//! bubblewrap + seccomp backend (docs/policy.md, Linux). Ported in design from Codex's
//! `linux-sandbox` (Apache-2.0) and Anthropic's sandbox-runtime.
//!
//! [`prepare`] makes the placeholders the policy needs and returns
//! `bwrap <namespaces> <mounts> -- <exe> __sandbox [helper args]`. Inside, the helper calls
//! [`enter`]: in an isolated exec it first starts the proxy bridge and the `tcp.open` control
//! server and forks, the parent staying to serve them; then it restores `SIGTERM`, denies TCP
//! binding with Landlock where the policy asks, installs the seccomp filters, and returns so the
//! helper execs the command or performs the file operation.
//!
//! The sandbox stays in the node's process group (no `--new-session`), so the node's `killpg`
//! reaches the command. bubblewrap forwards no signal, so [`prepare`] has it ignore `SIGTERM`
//! and `SIGINT`, which would otherwise kill it and, through `--die-with-parent`, `SIGKILL` the
//! command; the helper restores both before it execs the command. The
//! node already made bubblewrap a session leader with no controlling terminal, and seccomp
//! refuses `TIOCSTI`, so sharing the session gives the command no terminal to type into.

mod bridge;
mod mounts;
mod netns;
mod seccomp;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crate::error::{Error, Result};
use crate::helper::{self, Job, JobOp};
use crate::policy::{Default, HostRules, Network, Policy, ResolvedPolicy, RuleSet};
use crate::protocol::{Mechanism, SandboxInfo, SandboxStatus};
use crate::sandbox::placeholders::Placeholders;
use crate::sandbox::{Endpoint, Plan, Prepared};

pub use netns::NetnsControl;

/// The oldest bubblewrap with `--disable-userns`.
const MIN_BWRAP: (u32, u32) = (0, 8);

/// What `prepare` tells the helper on its command line, beside the job on stdin.
#[derive(Debug, Default, PartialEq, Eq)]
struct HelperArgs {
    /// The HTTP and SOCKS5 proxy sockets to bridge `127.0.0.1:3128` and `:1080` to.
    bridge: Option<(PathBuf, PathBuf)>,
    /// The helper's end of the `tcp.open` control socket.
    control: Option<RawFd>,
}

impl HelperArgs {
    fn to_args(&self) -> Vec<OsString> {
        let mut args = Vec::new();
        if let Some((http, socks)) = &self.bridge {
            args.extend(["--http".into(), http.into(), "--socks".into(), socks.into()]);
        }
        if let Some(fd) = self.control {
            args.extend(["--control".into(), fd.to_string().into()]);
        }
        args
    }

    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<HelperArgs> {
        let bad = |what: &str| Error::invalid_params(format!("bad helper arguments: {what}"));
        let mut parsed = HelperArgs::default();
        let (mut http, mut socks) = (None, None);
        let mut args = args.into_iter();
        while let Some(flag) = args.next() {
            let value = args.next().ok_or_else(|| bad("a flag without a value"))?;
            match flag.to_str() {
                Some("--http") => http = Some(PathBuf::from(value)),
                Some("--socks") => socks = Some(PathBuf::from(value)),
                Some("--control") => {
                    let fd = value.to_str().and_then(|v| v.parse().ok());
                    parsed.control = Some(fd.ok_or_else(|| bad("--control is not an fd"))?);
                }
                _ => return Err(bad("an unknown flag")),
            }
        }
        parsed.bridge = match (http, socks) {
            (Some(http), Some(socks)) => Some((http, socks)),
            (None, None) => None,
            _ => return Err(bad("--http and --socks go together")),
        };
        Ok(parsed)
    }
}

/// The bubblewrap binary this node uses.
#[derive(Clone, Debug)]
struct Bwrap {
    path: PathBuf,
    version: String,
    /// A setuid bubblewrap refuses `--disable-userns`; seccomp still refuses new namespaces.
    setuid: bool,
}

impl Bwrap {
    fn get() -> Result<Bwrap> {
        static BWRAP: OnceLock<std::result::Result<Bwrap, String>> = OnceLock::new();
        BWRAP
            .get_or_init(Bwrap::find)
            .clone()
            .map_err(Error::sandbox_unavailable)
    }

    fn find() -> std::result::Result<Bwrap, String> {
        let path = std::env::var_os("PATH")
            .into_iter()
            .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
            .chain([PathBuf::from("/usr/bin")])
            .map(|dir| dir.join("bwrap"))
            .find(|path| path.is_file())
            .ok_or("bubblewrap (bwrap) is not installed; install bubblewrap 0.8 or later")?;
        let output = Command::new(&path)
            .arg("--version")
            .stdin(Stdio::null())
            .output()
            .map_err(|err| format!("cannot run {}: {err}", path.display()))?;
        let text = String::from_utf8_lossy(&output.stdout);
        let version = text.trim().trim_start_matches("bubblewrap ").to_string();
        let mut numbers = version.split('.').map(|n| n.parse::<u32>().ok());
        let parsed = (numbers.next().flatten(), numbers.next().flatten());
        match parsed {
            (Some(major), Some(minor)) if (major, minor) >= MIN_BWRAP => {}
            _ => {
                return Err(format!(
                    "bubblewrap {version:?} at {} is too old; 0.8 or later is needed",
                    path.display()
                ));
            }
        }
        let setuid = std::fs::metadata(&path)
            .map(|meta| meta.permissions().mode() & 0o4000 != 0)
            .unwrap_or(false);
        Ok(Bwrap {
            path,
            version,
            setuid,
        })
    }
}

/// `(isolated, local_bind, unix_sockets)`.
fn network(policy: &ResolvedPolicy) -> (bool, bool, bool) {
    match policy.network() {
        Network::Host {
            local_bind,
            unix_sockets,
        } => (false, *local_bind, *unix_sockets),
        Network::Isolated {
            local_bind,
            unix_sockets,
            ..
        } => (true, *local_bind, *unix_sockets),
    }
}

fn unix_socket(endpoint: &Endpoint) -> Result<PathBuf> {
    match endpoint {
        Endpoint::Unix(path) => Ok(path.clone()),
        Endpoint::Tcp(addr) => Err(Error::sandbox_unavailable(format!(
            "an isolated Linux sandbox reaches its proxies over Unix sockets, not {addr}"
        ))),
    }
}

pub fn prepare(plan: &Plan, job: &Job) -> Result<Prepared> {
    let bwrap = Bwrap::get()?;
    let policy = plan.policy;
    let placeholders = Placeholders::create(
        &policy.state_dir().join("placeholders"),
        &mounts::missing_denies(policy),
        |path| policy.can_write(path),
    )
    .map_err(|err| Error::sandbox_unavailable(format!("cannot make a placeholder: {err}")))?;

    let is_exec = matches!(job.op, JobOp::Exec { .. });
    let (isolated, local_bind, _) = network(policy);
    let mut args = HelperArgs::default();
    let mut extra = vec![plan.exe.to_path_buf()];
    if let (Some(net), true) = (&plan.net, is_exec && isolated) {
        let (http, socks) = (unix_socket(&net.http)?, unix_socket(&net.socks)?);
        extra.extend([http.clone(), socks.clone()]);
        args.bridge = Some((http, socks));
    }
    let (netns, control) = if is_exec && isolated && local_bind {
        let (netns, control) = netns::pair()?;
        args.control = Some(control.as_raw_fd());
        (Some(netns), Some(control))
    } else {
        (None, None)
    };
    let mounts = mounts::Mounts::new(policy, placeholders.held(), &extra)?;

    let mut command = Command::new(&bwrap.path);
    command.args(["--unshare-user"]);
    if !bwrap.setuid {
        command.arg("--disable-userns");
    }
    command.args([
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--clearenv",
    ]);
    // A file operation never needs the network.
    if isolated || !is_exec {
        command.arg("--unshare-net");
    }
    command
        .args(mounts.args())
        .arg("--")
        .arg(plan.exe)
        .arg("__sandbox")
        .args(args.to_args());
    // SAFETY: the closure runs in the forked child before exec and only calls signal and fcntl,
    // which are async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            for signal in [libc::SIGTERM, libc::SIGINT] {
                if libc::signal(signal, libc::SIG_IGN) == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if let Some(control) = &control {
                let fd = control.as_raw_fd();
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(Prepared {
        command,
        placeholders,
        netns,
    })
}

/// How `localBind: false` is enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BindDenial {
    None,
    /// Landlock (ABI 4, Linux 6.7) refuses TCP `bind`; Unix sockets keep `bind` and `listen`.
    Landlock,
    /// seccomp refuses `bind` and `listen` for every socket family.
    Seccomp,
}

impl BindDenial {
    fn plan(local_bind: bool, unix_sockets: bool, landlock_abi: u32) -> BindDenial {
        match (local_bind, unix_sockets) {
            (true, _) => BindDenial::None,
            // Nothing else needs bind; seccomp refuses UDP and listen too.
            (false, false) => BindDenial::Seccomp,
            (false, true) if landlock_abi >= 4 => BindDenial::Landlock,
            (false, true) => BindDenial::Seccomp,
        }
    }
}

/// Run by the helper inside the sandbox before it execs the command or performs the file
/// operation. In an isolated exec the calling process forks: the parent serves the bridge and
/// the control socket until the command exits, and exits as it did; the child returns.
pub fn enter(policy: &ResolvedPolicy) -> Result<()> {
    let args = HelperArgs::parse(std::env::args_os().skip(2))?;
    // SAFETY: prepare passed this descriptor to the helper for exactly this use, and nothing else
    // in this process owns it.
    let control = args.control.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    if let Some(control) = &control {
        set_cloexec(control.as_raw_fd())?;
    }
    if args.bridge.is_some() || control.is_some() {
        let bridge = match args.bridge {
            Some((http, socks)) => Some(bridge::Bridge::bind(http, socks).map_err(|err| {
                Error::sandbox_unavailable(format!("cannot start the proxy bridge: {err}"))
            })?),
            None => None,
        };
        // SAFETY: the helper has started no thread, so the child may run any code.
        match unsafe { libc::fork() } {
            -1 => return Err(std::io::Error::last_os_error().into()),
            0 => drop((bridge, control)),
            child => supervise(child, bridge, control),
        }
    }
    // SAFETY: restoring the default action has no memory effects.
    unsafe { libc::signal(libc::SIGTERM, libc::SIG_DFL) };
    let (isolated, local_bind, unix_sockets) = network(policy);
    let denial = BindDenial::plan(local_bind, unix_sockets, landlock_abi());
    if denial == BindDenial::Landlock {
        deny_tcp_bind()?;
    }
    seccomp::apply(seccomp::NetRules {
        isolated,
        unix_sockets,
        deny_bind: denial == BindDenial::Seccomp,
    })
}

fn set_cloexec(fd: RawFd) -> Result<()> {
    // SAFETY: fcntl on an fd number has no memory effects.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    // SAFETY: as above.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// The helper's parent half in an isolated exec. Never returns.
fn supervise(child: libc::pid_t, bridge: Option<bridge::Bridge>, control: Option<OwnedFd>) -> ! {
    // SAFETY: plain calls on descriptor numbers and process attributes. The status pipe on fd 3
    // belongs to the child now; this process never returns to the code that owns its File.
    // Not dumpable: the command, as the same user, could otherwise write this unfiltered
    // process's memory through /proc.
    unsafe {
        libc::close(helper::STATUS_FD);
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        for fd in 0..3 {
            libc::dup2(null, fd);
        }
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    if let Some(bridge) = bridge {
        bridge.spawn();
    }
    if let Some(control) = control {
        std::thread::spawn(move || netns::serve(control));
    }
    let mut status = 0;
    loop {
        // SAFETY: waitpid writes the status into a valid int.
        let rc = unsafe { libc::waitpid(child, &mut status, 0) };
        if rc == child {
            break;
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            std::process::exit(helper::EXIT_EXEC_FAILED);
        }
    }
    netns::finish_serving();
    if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        // SAFETY: dying by the command's signal, so the sandbox reports what the command did.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
        }
        std::process::exit(128 + signal);
    }
    std::process::exit(libc::WEXITSTATUS(status))
}

/// The Landlock ABI version of the running kernel, 0 without Landlock.
fn landlock_abi() -> u32 {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    // SAFETY: with a null attribute and size 0, this flag only asks for the ABI version.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    u32::try_from(abi).unwrap_or(0)
}

/// A Landlock ruleset that handles TCP bind and grants no port.
fn deny_tcp_bind() -> Result<()> {
    use landlock::{
        AccessNet, CompatLevel, Compatible as _, Ruleset, RulesetAttr as _, RulesetStatus,
    };
    let refused = |err: landlock::RulesetError| {
        Error::sandbox_unavailable(format!("Landlock refused the bind ruleset: {err}"))
    };
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessNet::BindTcp)
        .and_then(|ruleset| ruleset.create())
        .and_then(|ruleset| ruleset.restrict_self())
        .map_err(refused)?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(Error::sandbox_unavailable(format!(
            "Landlock enforced the bind ruleset {:?}",
            status.ruleset
        )));
    }
    Ok(())
}

/// What this node leaves unenforced, one sentence each (policy.md, What each platform requires).
fn gaps(landlock_abi: u32) -> Vec<String> {
    let mut gaps = vec![
        "with localBind false, a UDP socket that sends before binding gets an ephemeral port and \
         receives replies on it",
        "a command killed by a signal is reported as exiting with 128 plus the signal number",
        "32-bit x86 and x32 programs cannot run in the sandbox",
        "connecting to an existing Unix socket needs only that the socket be readable, not its \
         directory writable",
    ];
    if landlock_abi >= 4 {
        gaps.push(
            "with localBind false and unixSockets true, TCP bind is refused, but a TCP socket can \
             listen on an ephemeral port without bind, and UDP sockets can bind any port",
        );
    } else {
        gaps.push(
            "with localBind false and unixSockets true, Unix sockets cannot bind or listen either \
             (Landlock ABI 4, Linux 6.7, is needed to tell them apart)",
        );
    }
    gaps.into_iter().map(str::to_string).collect()
}

pub fn probe() -> SandboxInfo {
    let status = match Bwrap::get().and_then(|bwrap| run_true(&bwrap)) {
        Ok(()) => SandboxStatus::Available,
        Err(err) => SandboxStatus::Unavailable {
            reason: err.message,
        },
    };
    let gaps = match status {
        SandboxStatus::Available => gaps(landlock_abi()),
        SandboxStatus::Unavailable { .. } => Vec::new(),
    };
    SandboxInfo {
        mechanism: Mechanism::Bubblewrap {
            version: Bwrap::get().ok().map(|bwrap| bwrap.version),
        },
        status,
        baseline_read: super::baseline_read(),
        gaps,
    }
}

/// Runs `true` through the helper in an isolated sandbox that can read only the baseline, so
/// availability means a real command got through bubblewrap and seccomp.
fn run_true(bwrap: &Bwrap) -> Result<()> {
    let program = ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .find(|path| Path::new(path).exists())
        .ok_or_else(|| {
            Error::sandbox_unavailable("there is no `true` program to test the sandbox with")
        })?;
    let policy = Policy {
        read: RuleSet {
            default: Default::Deny,
            allow: super::baseline_read()
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            deny: Vec::new(),
        },
        write: RuleSet {
            default: Default::Deny,
            allow: Vec::new(),
            deny: Vec::new(),
        },
        network: Network::Isolated {
            egress: HostRules {
                default: Default::Deny,
                allow: Vec::new(),
                deny: Vec::new(),
            },
            ports: None,
            local_bind: false,
            unix_sockets: false,
        },
    };
    let policy =
        ResolvedPolicy::resolve(&policy, Path::new("/nonexistent/happy-supervisor-probe"))?;
    let job = Job {
        policy: policy.clone(),
        op: JobOp::Exec {
            argv: crate::protocol::Argv::try_from(vec![program.to_string()])?,
            cwd: crate::protocol::AbsPath::try_from("/")?,
            env: BTreeMap::new(),
        },
    };
    let exe = helper::exe()?;
    let plan = Plan {
        policy: &policy,
        net: None,
        exe: &exe,
    };
    let Prepared { mut command, .. } = prepare(&plan, &job)?;
    let (mut status_reader, status_writer) = std::io::pipe()?;
    let status_fd = status_writer.as_raw_fd();
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: install_status_fd is async-signal-safe and runs in the forked child only.
    unsafe {
        command.pre_exec(move || helper::install_status_fd(status_fd));
    }
    let mut child = command.spawn()?;
    drop(command);
    drop(status_writer);
    let _ = child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(&helper::encode_job(&job));
    let mut status = Vec::new();
    status_reader.read_to_end(&mut status)?;
    let mut stderr = String::new();
    let _ = child
        .stderr
        .take()
        .expect("stderr is piped")
        .read_to_string(&mut stderr);
    let exit = child.wait()?;
    helper::parse_exec_status(&status)?;
    if !exit.success() {
        return Err(Error::sandbox_unavailable(diagnose(bwrap, &stderr)));
    }
    Ok(())
}

/// Why bubblewrap could not run `true`, and what to do about it.
fn diagnose(bwrap: &Bwrap, stderr: &str) -> String {
    let sysctl = |name: &str| {
        std::fs::read_to_string(format!("/proc/sys/{name}"))
            .map(|value| value.trim().to_string())
            .ok()
    };
    let first_line = stderr.lines().next().unwrap_or("no message").trim();
    let userns_denied = ["namespace", "uid map", "Operation not permitted"]
        .iter()
        .any(|needle| stderr.contains(needle));
    if !userns_denied {
        return format!(
            "a sandboxed `true` failed under bubblewrap {} at {}: {first_line}",
            bwrap.version,
            bwrap.path.display()
        );
    }
    if sysctl("kernel/apparmor_restrict_unprivileged_userns").as_deref() == Some("1") {
        return format!(
            "AppArmor restricts unprivileged user namespaces (Ubuntu 24.04 and later): install \
             an AppArmor profile that allows {} to use them, or set \
             kernel.apparmor_restrict_unprivileged_userns=0 ({first_line})",
            bwrap.path.display()
        );
    }
    if sysctl("kernel/unprivileged_userns_clone").as_deref() == Some("0") {
        return format!(
            "unprivileged user namespaces are disabled: set kernel.unprivileged_userns_clone=1 \
             or make {} setuid ({first_line})",
            bwrap.path.display()
        );
    }
    if sysctl("user/max_user_namespaces").as_deref() == Some("0") {
        return format!(
            "user namespaces are disabled: set user.max_user_namespaces above 0 ({first_line})"
        );
    }
    format!("bubblewrap cannot create the sandbox's namespaces: {first_line}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_args_round_trip() {
        let both = HelperArgs {
            bridge: Some(("/s/http.sock".into(), "/s/socks.sock".into())),
            control: Some(11),
        };
        let args = both.to_args();
        assert_eq!(
            args,
            [
                "--http",
                "/s/http.sock",
                "--socks",
                "/s/socks.sock",
                "--control",
                "11"
            ]
        );
        assert_eq!(HelperArgs::parse(args).unwrap(), both);
        assert_eq!(HelperArgs::parse([]).unwrap(), HelperArgs::default());
        assert_eq!(
            HelperArgs::parse(["--http".into(), "/a".into()])
                .unwrap_err()
                .message,
            "bad helper arguments: --http and --socks go together"
        );
    }

    #[test]
    fn bind_denial_by_kernel() {
        use BindDenial::*;
        let table = [
            ((true, true, 6), None),
            ((true, false, 1), None),
            ((false, false, 6), Seccomp),
            ((false, true, 6), Landlock),
            ((false, true, 4), Landlock),
            ((false, true, 3), Seccomp),
            ((false, true, 0), Seccomp),
        ];
        for ((local_bind, unix_sockets, abi), expected) in table {
            assert_eq!(
                BindDenial::plan(local_bind, unix_sockets, abi),
                expected,
                "{local_bind} {unix_sockets} {abi}"
            );
        }
    }
}
