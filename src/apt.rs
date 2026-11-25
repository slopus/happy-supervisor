//! Installing packages with apt for a system command that runs as `happy-system`, which is not
//! root (policy.md, Installing with apt). The supervisor, which is, runs `apt-get install` for
//! it, with package names only: no apt options, no files, no versions or releases, no removals,
//! and none of the caller's environment. So the command chooses which packages from the
//! repositories the administrator configured get installed, and nothing else that runs as root.
//!
//! Each such command gets its own socket ([`AptGate`]), which serves only processes of the
//! command's session, as `happy-system`, and only until the command exits. The `apt` and
//! `apt-get` the command finds first in `PATH` are links to a copy of this binary
//! ([`shim_main`]), which forward `install` there, print what `apt-get` prints, and exit as it
//! did.
//!
//! The shim sends the request as JSON and closes its side for writing. The supervisor answers
//! with frames, a kind byte and a big-endian `u32` length, then the payload: [`OUTPUT`] chunks,
//! then one [`EXITED`] (a big-endian `i32`) or [`REFUSED`] (a UTF-8 message).

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::system_account::root_dir;

/// The environment variable that names the command's socket.
pub const SOCKET_ENV: &str = "HAPPY_APT_SOCKET";
/// The names the shim answers to.
const SHIM_NAMES: [&str; 2] = ["apt", "apt-get"];
/// apt's exit code for an error.
const APT_FAILED: u8 = 100;
const MAX_REQUEST: usize = 64 << 10;
const MAX_PACKAGES: usize = 256;
const MAX_FRAME: usize = 64 << 10;
/// Connections one socket answers at once, and all of them together; more are closed
/// unanswered.
const MAX_CONNECTIONS: usize = 4;
const MAX_ALL_CONNECTIONS: usize = 16;
/// How long the supervisor waits for the whole request.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long, after `apt-get` exits, the supervisor still sends output that something it started
/// writes; later output is dropped.
const DRAIN_AFTER_EXIT: Duration = Duration::from_secs(2);
/// How long the supervisor waits for the shim to take output, before it stops sending it and
/// lets `apt-get` finish without it.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Where `apt-get` and `apt-cache` run: a fixed environment, none of the caller's.
const APT_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// Frame kinds.
pub const OUTPUT: u8 = 0;
pub const EXITED: u8 = 1;
pub const REFUSED: u8 = 2;

/// What the shim asks for: `{"do": "install", "packages": [...]}` or `{"do": "update"}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "do",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Request {
    Install {
        packages: Vec<String>,
        #[serde(default)]
        no_install_recommends: bool,
    },
    /// `apt-get update` from the sources the administrator configured, with nothing else.
    Update {},
}

/// A request the supervisor checked, which it runs as root.
#[derive(Debug, PartialEq, Eq)]
pub enum Apt {
    Install {
        packages: Vec<PackageName>,
        no_install_recommends: bool,
    },
    Update,
}

impl Apt {
    /// `apt-get`'s arguments.
    fn args(&self) -> Vec<&str> {
        match self {
            Apt::Install {
                packages,
                no_install_recommends,
            } => ["install", "-y", "-q", "--no-remove"]
                .into_iter()
                .chain(no_install_recommends.then_some("--no-install-recommends"))
                .chain(packages.iter().map(PackageName::as_str))
                .collect(),
            Apt::Update => vec!["update", "-q"],
        }
    }
}

/// How a request ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    Exited(i32),
    Refused(String),
}

/// A Debian package name, as `apt-get install` takes it without reading it as anything else: a
/// trailing `-` means remove, `=`, `/` and `:` pick a version, release or architecture, and a
/// name ending in `.deb` or holding `/` is a file. A trailing `+` means install, so `g++` stays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageName(String);

impl PackageName {
    pub fn parse(name: &str) -> Result<PackageName, String> {
        let bytes = name.as_bytes();
        let valid = bytes.len() >= 2
            && bytes.len() <= 128
            && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(b))
            && !name.ends_with('-')
            && !name.ends_with(".deb");
        if valid {
            Ok(PackageName(name.to_owned()))
        } else {
            Err(format!("{name:?} is not a package name"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Request {
    /// The supervisor's own check, whatever the shim did: each package a [`PackageName`].
    pub fn check(&self) -> Result<Apt, String> {
        match self {
            Request::Install {
                packages,
                no_install_recommends,
            } => {
                if packages.is_empty() || packages.len() > MAX_PACKAGES {
                    return Err(format!("name 1 to {MAX_PACKAGES} packages"));
                }
                Ok(Apt::Install {
                    packages: packages
                        .iter()
                        .map(|name| PackageName::parse(name))
                        .collect::<Result<_, _>>()?,
                    no_install_recommends: *no_install_recommends,
                })
            }
            Request::Update {} => Ok(Apt::Update),
        }
    }
}

/// The shim's command line, `apt-get [-y] [-q] install [--no-install-recommends] <package>...`
/// or a bare `apt-get update`, or the same with `apt`, as a request. Anything else is refused,
/// with what is allowed.
pub fn parse_command_line(args: &[String]) -> Result<Request, String> {
    if args.iter().find(|arg| !arg.starts_with('-')) == Some(&"update".to_owned()) {
        return match args {
            [_] => Ok(Request::Update {}),
            _ => Err(format!(
                "update takes no options or arguments: {}",
                args.join(" ")
            )),
        };
    }
    let mut install = None;
    let mut no_install_recommends = false;
    for arg in args {
        if arg == "--no-install-recommends" {
            no_install_recommends = true;
            continue;
        }
        let harmless = matches!(arg.as_str(), "--yes" | "--assume-yes" | "--quiet")
            || (arg.len() > 1
                && arg.starts_with('-')
                && !arg.starts_with("--")
                && arg[1..].chars().all(|c| c == 'y' || c == 'q'));
        if harmless {
            continue;
        }
        if arg.starts_with('-') {
            return Err(format!("the option {arg} is not allowed"));
        }
        match &mut install {
            None if arg == "install" => install = Some(Vec::new()),
            None => return Err(format!("only install and update are allowed, not {arg}")),
            Some(names) => names.push(PackageName::parse(arg)?.0),
        }
    }
    match install {
        Some(packages) if !packages.is_empty() => Ok(Request::Install {
            packages,
            no_install_recommends,
        }),
        _ => Err("name the packages to install".to_owned()),
    }
}

const USAGE: &str = "system commands run as happy-system, not root, and may only install \
                     packages by name from this machine's repositories: apt-get install [-y] \
                     [-q] [--no-install-recommends] <package>..., or apt-get update";

/// `apt` or `apt-get` in a system command: when the program name in `args` is one, forwards the
/// command line to the supervisor and returns `apt-get`'s exit code. `None` otherwise.
pub fn shim_main(mut args: impl Iterator<Item = std::ffi::OsString>) -> Option<ExitCode> {
    let argv0 = args.next()?;
    let name = Path::new(&argv0).file_name()?.to_str()?;
    if !SHIM_NAMES.contains(&name) {
        return None;
    }
    let args: Vec<String> = args.map(|arg| arg.to_string_lossy().into_owned()).collect();
    let fail = |why: &str| {
        eprintln!("{name}: {why}; {USAGE}");
        Some(ExitCode::from(APT_FAILED))
    };
    let request = match parse_command_line(&args) {
        Ok(request) => request,
        Err(why) => return fail(&why),
    };
    let Some(socket) = std::env::var_os(SOCKET_ENV) else {
        return fail("this is not a system command");
    };
    match forward(Path::new(&socket), &request) {
        Ok(Reply::Exited(code)) => Some(ExitCode::from(code.clamp(0, 255) as u8)),
        Ok(Reply::Refused(why)) => fail(&why),
        Err(err) => fail(&format!(
            "the supervisor did not answer ({err}); only a running system command may install"
        )),
    }
}

/// Sends `request`, prints the output, and returns how it ended.
fn forward(socket: &Path, request: &Request) -> std::io::Result<Reply> {
    let mut stream = UnixStream::connect(socket)?;
    let body = serde_json::to_vec(request).expect("a request serializes");
    stream.write_all(&body)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut stdout = std::io::stdout().lock();
    loop {
        let mut head = [0u8; 5];
        stream.read_exact(&mut head)?;
        let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        if len > MAX_FRAME {
            return Err(std::io::Error::other("a frame is too long"));
        }
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload)?;
        match head[0] {
            OUTPUT => {
                // Output that cannot be printed is lost; apt-get goes on.
                let _ = stdout.write_all(&payload).and_then(|()| stdout.flush());
            }
            EXITED => {
                let code = <[u8; 4]>::try_from(payload.as_slice())
                    .map_err(|_| std::io::Error::other("a bad exit frame"))?;
                return Ok(Reply::Exited(i32::from_be_bytes(code)));
            }
            REFUSED => {
                return Ok(Reply::Refused(
                    String::from_utf8_lossy(&payload).into_owned(),
                ));
            }
            kind => return Err(std::io::Error::other(format!("a frame of kind {kind}"))),
        }
    }
}

fn frame(stream: &mut UnixStream, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut bytes = Vec::with_capacity(5 + payload.len());
    bytes.push(kind);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    stream.write_all(&bytes)
}

/// Where the shims are: a copy of this binary and the `apt` and `apt-get` links to it, all
/// root's. A copy, because the account may not be able to reach the binary where it is.
pub const SHIM_DIR: &str = "/opt/happy-system/bin";
/// Where the commands' sockets are: root's, `0711`, so the account can reach a socket it is
/// given but not list or create any.
const SOCKET_DIR: &str = "/opt/happy-system/apt";
const SHIM_BINARY: &str = "happy-supervisor";

/// Makes [`SHIM_DIR`] hold this binary, copying it again when its size or time changed. Needs
/// root.
fn install_shims() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    static ONE: Mutex<()> = Mutex::new(());
    let _one = ONE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    root_dir(Path::new(SHIM_DIR), 0o755)?;
    let exe = crate::helper::exe()?;
    let source = std::fs::metadata(&exe)?;
    let copy = Path::new(SHIM_DIR).join(SHIM_BINARY);
    let current = std::fs::symlink_metadata(&copy).ok();
    let fresh = current.is_some_and(|copy| {
        copy.is_file()
            && copy.len() == source.len()
            && copy.modified().ok() == source.modified().ok()
    });
    if !fresh {
        // Unique to this process, in a directory only root writes.
        let partial = Path::new(SHIM_DIR).join(format!(".partial-{}", std::process::id()));
        let _ = std::fs::remove_file(&partial);
        let copied = std::fs::copy(&exe, &partial)
            .and_then(|_| {
                std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o755))
            })
            .and_then(|()| {
                std::fs::File::options()
                    .write(true)
                    .open(&partial)?
                    .set_modified(source.modified()?)
            })
            .and_then(|()| std::fs::rename(&partial, &copy));
        if let Err(err) = copied {
            let _ = std::fs::remove_file(&partial);
            return Err(err.into());
        }
    }
    for name in SHIM_NAMES {
        let link = Path::new(SHIM_DIR).join(name);
        if std::fs::read_link(&link).is_ok_and(|target| target == Path::new(SHIM_BINARY)) {
            continue;
        }
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(SHIM_BINARY, &link)?;
    }
    Ok(())
}

/// One system command's socket. It serves from [`AptGate::serve`] until it is dropped, which the
/// command's exec does as soon as the command exits, before its output ends: from then on
/// nothing the command left running can install, and a request not yet running is refused.
pub struct AptGate {
    path: PathBuf,
    listener: Option<std::os::unix::net::UnixListener>,
    task: Option<tokio::task::AbortHandle>,
    shared: Arc<Shared>,
}

struct Shared {
    uid: u32,
    /// `false` once the gate is dropped. Held from the last check until `apt-get` started.
    open: Mutex<bool>,
    /// Whether system access still runs as this account, read again just before `apt-get`
    /// starts, so `system disable` stops what it has not started yet.
    enabled: Box<dyn Fn() -> bool + Send + Sync>,
    connections: AtomicUsize,
}

/// One of a socket's [`MAX_CONNECTIONS`], given back when dropped.
struct Slot(Arc<Shared>);

/// Connections being answered, of every socket.
static ALL_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

impl Slot {
    fn take(shared: &Arc<Shared>) -> Option<Slot> {
        let mine = shared.connections.fetch_add(1, Ordering::AcqRel);
        let all = ALL_CONNECTIONS.fetch_add(1, Ordering::AcqRel);
        // Built first, so dropping it gives both back.
        let slot = Slot(shared.clone());
        (mine < MAX_CONNECTIONS && all < MAX_ALL_CONNECTIONS).then_some(slot)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::AcqRel);
        ALL_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One `apt-get` at a time: apt and dpkg take locks anyway, and a second would fail on them.
static APT: Mutex<()> = Mutex::new(());

impl AptGate {
    /// A socket that only `uid` (and root) may connect to, with the shims it needs, for as long
    /// as `enabled` says system access still runs as `uid`. Blocking; needs root.
    pub fn open(uid: u32, enabled: impl Fn() -> bool + Send + Sync + 'static) -> Result<AptGate> {
        use std::os::unix::fs::PermissionsExt as _;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        install_shims()?;
        root_dir(Path::new(SOCKET_DIR), 0o711)?;
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(SOCKET_DIR).join(format!("{}-{n}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        // From here on, dropping the gate removes the socket.
        let gate = AptGate {
            path,
            listener: Some(listener),
            task: None,
            shared: Arc::new(Shared {
                uid,
                open: Mutex::new(true),
                enabled: Box::new(enabled),
                connections: AtomicUsize::new(0),
            }),
        };
        std::fs::set_permissions(&gate.path, std::fs::Permissions::from_mode(0o600))?;
        std::os::unix::fs::chown(&gate.path, Some(uid), None)?;
        if let Some(listener) = &gate.listener {
            listener.set_nonblocking(true)?;
        }
        Ok(gate)
    }

    /// Points the command's shims at this socket, and puts them first in its `PATH`.
    pub fn apply_env(&self, env: &mut BTreeMap<String, String>) {
        env.insert(
            SOCKET_ENV.to_owned(),
            self.path.to_string_lossy().into_owned(),
        );
        let path = match env.get("PATH").map(String::as_str) {
            Some(rest) if !rest.is_empty() => format!("{SHIM_DIR}:{rest}"),
            _ => SHIM_DIR.to_owned(),
        };
        env.insert("PATH".to_owned(), path);
    }

    /// Serves the command whose session `session` leads: its process ID.
    pub fn serve(&mut self, session: u32, runtime: &tokio::runtime::Handle) {
        let Some(listener) = self.listener.take() else {
            return;
        };
        let shared = self.shared.clone();
        let task = runtime.spawn(async move {
            let Ok(listener) = tokio::net::UnixListener::from_std(listener) else {
                return;
            };
            while let Ok((stream, _)) = listener.accept().await {
                let Some(slot) = Slot::take(&shared) else {
                    continue;
                };
                let peer = stream.peer_cred().ok();
                let Ok(stream) = stream.into_std() else {
                    continue;
                };
                tokio::task::spawn_blocking(move || answer(stream, peer, &slot.0, session));
            }
        });
        self.task = Some(task.abort_handle());
    }
}

impl Drop for AptGate {
    fn drop(&mut self) {
        *self
            .shared
            .open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
        if let Some(task) = &self.task {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Whether `peer` is a process of the command's session, as the account.
fn in_session(peer: Option<tokio::net::unix::UCred>, uid: u32, session: u32) -> bool {
    peer.is_some_and(|peer| {
        peer.uid() == uid
            && peer.pid().is_some_and(|pid| {
                nix::unistd::getsid(Some(nix::unistd::Pid::from_raw(pid)))
                    .is_ok_and(|sid| sid.as_raw() as u32 == session)
            })
    })
}

/// Reads the request, checks who asks and what for, then runs `apt-get`, sending the output,
/// and replies.
fn answer(
    mut stream: UnixStream,
    peer: Option<tokio::net::unix::UCred>,
    shared: &Shared,
    session: u32,
) {
    // The whole request first, so a refusal is read rather than reset.
    let Ok(body) = read_request(&mut stream) else {
        return;
    };
    let checked = if !in_session(peer, shared.uid, session) {
        Err("only the system command's own processes may install".to_owned())
    } else if body.len() > MAX_REQUEST {
        Err("the request is too long".to_owned())
    } else {
        serde_json::from_slice::<Request>(&body)
            .map_err(|err| format!("bad request: {err}"))
            .and_then(|request| request.check())
            .and_then(|apt| {
                if let Apt::Install { packages, .. } = &apt {
                    packages.iter().try_for_each(known)?;
                }
                Ok(apt)
            })
    };
    let reply = match checked {
        Ok(apt) => {
            let still = || {
                leader_runs(session)
                    && in_session(peer, shared.uid, session)
                    && shared.enabled.as_ref()()
            };
            run(&apt, &mut stream, &shared.open, still)
        }
        Err(why) => Reply::Refused(why),
    };
    let _ = match reply {
        Reply::Exited(code) => frame(&mut stream, EXITED, &code.to_be_bytes()),
        Reply::Refused(why) => frame(&mut stream, REFUSED, why.as_bytes()),
    };
}

/// The request, at most [`MAX_REQUEST`] and one byte, within [`READ_TIMEOUT`] in all.
fn read_request(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let deadline = std::time::Instant::now() + READ_TIMEOUT;
    stream.set_nonblocking(false)?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let mut body = Vec::new();
    let mut chunk = [0u8; 4096];
    while body.len() <= MAX_REQUEST {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        stream.set_read_timeout(Some(left))?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(body)
}

/// Whether the process that leads `session`, the command, still runs: not yet a zombie. The
/// exec reaps it only after dropping the gate, so its ID is not anyone else's meanwhile.
fn leader_runs(session: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{session}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.trim_start().chars().next())
            .is_some_and(|state| !matches!(state, 'Z' | 'X' | 'x'))
    })
}

/// Refuses a name that is not exactly a package in apt's lists, so `apt-get`, which takes a
/// package's own name first, does not read it as a pattern of the packages in those lists.
fn known(name: &PackageName) -> std::result::Result<(), String> {
    let output = std::process::Command::new("/usr/bin/apt-cache")
        .args(["pkgnames", name.as_str()])
        .env_clear()
        .env("PATH", APT_PATH)
        .env("LANG", "C.UTF-8")
        .current_dir("/")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|err| format!("cannot run /usr/bin/apt-cache: {err}"))?;
    if output.status.success()
        && output
            .stdout
            .split(|byte| *byte == b'\n')
            .any(|line| line == name.as_str().as_bytes())
    {
        Ok(())
    } else {
        Err(format!(
            "{} is not a package in this machine's apt lists",
            name.as_str()
        ))
    }
}

/// `apt-get` with `apt`'s arguments (`install -y --no-remove`, or `update`) and a fixed
/// environment, its output sent on `stream` while the shim takes it. It starts only if the gate
/// is still `open` and `still` holds.
fn run(apt: &Apt, stream: &mut UnixStream, open: &Mutex<bool>, still: impl Fn() -> bool) -> Reply {
    use std::process::{Command, Stdio};
    let args = apt.args();
    let _one = APT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let (output, input) = match std::io::pipe() {
        Ok(pipe) => pipe,
        Err(err) => return Reply::Refused(format!("cannot run apt-get: {err}")),
    };
    let spawned = {
        let open = open.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if !*open || !still() {
            return Reply::Refused("the system command exited, or system access ended".to_owned());
        }
        tracing::info!("system access: apt-get {}", args.join(" "));
        let mut command = Command::new("/usr/bin/apt-get");
        command
            .args(&args)
            .env_clear()
            .env("PATH", APT_PATH)
            .env("HOME", "/root")
            .env("LANG", "C.UTF-8")
            .env("DEBIAN_FRONTEND", "noninteractive")
            .current_dir("/")
            .stdin(Stdio::null());
        match input.try_clone() {
            Ok(stderr) => command.stdout(input).stderr(stderr).spawn(),
            Err(err) => Err(err),
        }
        // `command` drops here with its copies of the pipe's input.
    };
    let mut child = match spawned {
        Ok(child) => child,
        Err(err) => return Reply::Refused(format!("cannot run /usr/bin/apt-get: {err}")),
    };
    match forward_output(output, stream, || child.wait()) {
        Ok(status) => Reply::Exited(status.code().unwrap_or(APT_FAILED as i32)),
        Err(err) => Reply::Refused(format!("waiting for apt-get failed: {err}")),
    }
}

/// Sends what arrives on `output` to the shim as [`OUTPUT`] frames, until `wait` returns and then
/// for [`DRAIN_AFTER_EXIT`] at most, so something `apt-get` started that keeps the pipe open
/// holds up neither the reply nor the next install. A thread reads the pipe to its end, dropping
/// what the shim does not take, so no writer ever waits on it.
fn forward_output<T>(
    mut output: std::io::PipeReader,
    stream: &UnixStream,
    wait: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let sink = Arc::new(Mutex::new(stream.try_clone().ok()));
    let (done, ended) = std::sync::mpsc::channel::<()>();
    let reader = {
        let sink = sink.clone();
        move || {
            let mut chunk = [0u8; 16 << 10];
            loop {
                let n = match output.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                };
                let mut sink = sink.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(stream) = sink.as_mut()
                    && frame(stream, OUTPUT, &chunk[..n]).is_err()
                {
                    *sink = None;
                }
            }
            drop(done);
        }
    };
    let read = std::thread::Builder::new()
        .name("apt-output".to_owned())
        .spawn(reader);
    let waited = wait();
    if read.is_ok() {
        let _ = ended.recv_timeout(DRAIN_AFTER_EXIT);
    }
    // The reply comes next, so no output may follow it.
    *sink.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    waited
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn package_names_are_names_only() {
        for name in ["hello", "g++", "libc6", "python3.12", "0ad", "lib32z1-dev"] {
            assert_eq!(PackageName::parse(name).map(|p| p.0), Ok(name.to_owned()));
        }
        for bad in [
            "-o",
            "APT::Update::Pre-Invoke::=id",
            "./hello.deb",
            "/tmp/hello.deb",
            "hello.deb",
            "hello=2.10-3",
            "hello/noble",
            "hello:amd64",
            "hello-",
            "coreutils-",
            "--reinstall",
            "Hello",
            "h*",
        ] {
            assert_eq!(
                PackageName::parse(bad),
                Err(format!("{bad:?} is not a package name")),
                "{bad}"
            );
        }
        assert!(PackageName::parse("h").is_err());
        assert!(PackageName::parse(&"a".repeat(129)).is_err());
    }

    #[test]
    fn the_supervisor_checks_the_request_whatever_the_shim_sent() {
        let request: Request =
            serde_json::from_str(r#"{"do": "install", "packages": ["hello", "coreutils-"]}"#)
                .unwrap();
        assert_eq!(
            request.check(),
            Err("\"coreutils-\" is not a package name".to_owned())
        );
        let none = Request::Install {
            packages: vec![],
            no_install_recommends: false,
        };
        assert_eq!(none.check(), Err("name 1 to 256 packages".to_owned()));
        let hello: Request = serde_json::from_str(
            r#"{"do": "install", "packages": ["hello"], "noInstallRecommends": true}"#,
        )
        .unwrap();
        let checked = hello.check().unwrap();
        assert_eq!(
            checked.args(),
            [
                "install",
                "-y",
                "-q",
                "--no-remove",
                "--no-install-recommends",
                "hello"
            ]
        );
        let update: Request = serde_json::from_str(r#"{"do": "update"}"#).unwrap();
        assert_eq!(update.check().unwrap().args(), ["update", "-q"]);
        for bad in [
            r#"{"do": "install", "packages": [], "options": ["-o"]}"#,
            r#"{"do": "update", "options": ["-o", "APT::Update::Pre-Invoke::=id"]}"#,
            r#"{"do": "update", "packages": ["foo"]}"#,
            r#"{"do": "upgrade"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn nothing_installs_once_the_gate_closed_or_system_access_ended() {
        let hello = Apt::Install {
            packages: vec![PackageName::parse("hello").unwrap()],
            no_install_recommends: false,
        };
        let ended = Reply::Refused("the system command exited, or system access ended".to_owned());
        let (mut stream, _shim) = UnixStream::pair().unwrap();
        let closed = Mutex::new(false);
        let spawned = std::cell::Cell::new(false);
        let still = || {
            spawned.set(true);
            true
        };
        assert_eq!(run(&hello, &mut stream, &closed, still), ended);
        assert!(!spawned.get(), "a closed gate does not even check");
        let open = Mutex::new(true);
        assert_eq!(run(&Apt::Update, &mut stream, &open, || false), ended);
    }

    #[test]
    fn output_after_the_exit_waits_a_little_then_is_dropped() {
        let (supervisor, mut shim) = UnixStream::pair().unwrap();
        let (output, mut input) = std::io::pipe().unwrap();
        // Something apt-get started, which keeps the pipe open.
        let keeper = input.try_clone().unwrap();
        input.write_all(b"done\n").unwrap();
        drop(input);
        let started = std::time::Instant::now();
        assert_eq!(forward_output(output, &supervisor, || Ok(7)).unwrap(), 7);
        assert!(started.elapsed() >= DRAIN_AFTER_EXIT);
        let mut keeper = keeper;
        keeper.write_all(b"late\n").unwrap();
        drop((supervisor, keeper));
        let mut bytes = Vec::new();
        shim.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, [0, 0, 0, 0, 5, b'd', b'o', b'n', b'e', b'\n']);
    }

    #[test]
    fn frames_are_a_kind_a_length_and_the_payload() {
        let (mut supervisor, mut shim) = UnixStream::pair().unwrap();
        frame(&mut supervisor, REFUSED, b"no").unwrap();
        frame(&mut supervisor, EXITED, &7i32.to_be_bytes()).unwrap();
        drop(supervisor);
        let mut bytes = Vec::new();
        shim.read_to_end(&mut bytes).unwrap();
        assert_eq!(
            bytes,
            [2, 0, 0, 0, 2, b'n', b'o', 1, 0, 0, 0, 4, 0, 0, 0, 7]
        );
    }

    #[test]
    fn the_shim_takes_install_with_its_harmless_options_and_a_bare_update_only() {
        let hello = Request::Install {
            packages: vec!["hello".to_owned(), "figlet".to_owned()],
            no_install_recommends: false,
        };
        for line in [
            "install hello figlet",
            "install -y hello figlet",
            "-yq install hello figlet",
            "install --yes --quiet hello figlet",
        ] {
            assert_eq!(parse_command_line(&args(line)), Ok(hello.clone()), "{line}");
        }
        assert_eq!(
            parse_command_line(&args("install -y --no-install-recommends hello figlet")),
            Ok(Request::Install {
                packages: vec!["hello".to_owned(), "figlet".to_owned()],
                no_install_recommends: true,
            })
        );
        assert_eq!(parse_command_line(&args("update")), Ok(Request::Update {}));
        for (line, why) in [
            (
                "update foo",
                "update takes no options or arguments: update foo",
            ),
            (
                "update -o APT::Update::Pre-Invoke::=id",
                "update takes no options or arguments: update -o APT::Update::Pre-Invoke::=id",
            ),
            (
                "-q update",
                "update takes no options or arguments: -q update",
            ),
            (
                "upgrade",
                "only install and update are allowed, not upgrade",
            ),
            (
                "remove hello",
                "only install and update are allowed, not remove",
            ),
            ("install", "name the packages to install"),
            (
                "-o APT::Update::Pre-Invoke::=id install hello",
                "the option -o is not allowed",
            ),
            (
                "install --reinstall hello",
                "the option --reinstall is not allowed",
            ),
            ("install -f", "the option -f is not allowed"),
            (
                "install ./hello.deb",
                "\"./hello.deb\" is not a package name",
            ),
            ("install hello-", "\"hello-\" is not a package name"),
        ] {
            assert_eq!(
                parse_command_line(&args(line)),
                Err(why.to_owned()),
                "{line}"
            );
        }
    }
}
