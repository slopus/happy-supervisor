//! Installing packages with apt for a system command that runs as `happy-system`, which is not
//! root (policy.md, System access). The supervisor, which is, runs `apt-get install` for it, with
//! package names only: no apt options, no files, no versions or releases, no removals, and none
//! of the caller's environment. So the command chooses which packages from the repositories the
//! administrator configured get installed, and nothing else that runs as root.
//!
//! Each such command gets its own socket, which exists only while the command runs and which only
//! processes of its session, as `happy-system`, may use. The `apt` and `apt-get` the command finds
//! first in `PATH` are links to this binary ([`shim_main`]), which forward `install` there with
//! their standard output and error, and exit as `apt-get` did.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind, Result};

/// The environment variable that names the command's socket.
pub const SOCKET_ENV: &str = "HAPPY_APT_SOCKET";
/// The names the shim answers to.
const SHIM_NAMES: [&str; 2] = ["apt", "apt-get"];
/// apt's exit code for an error.
const APT_FAILED: u8 = 100;
const MAX_REQUEST: usize = 64 << 10;
const MAX_PACKAGES: usize = 256;

/// What the shim asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub install: Vec<String>,
    #[serde(default)]
    pub no_install_recommends: bool,
}

/// What the supervisor answers, after `apt-get` wrote its output to the shim's.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    /// The packages, each a [`PackageName`]: the supervisor's own check, whatever the shim did.
    pub fn packages(&self) -> Result<Vec<PackageName>, String> {
        if self.install.is_empty() || self.install.len() > MAX_PACKAGES {
            return Err(format!("name 1 to {MAX_PACKAGES} packages"));
        }
        self.install
            .iter()
            .map(|name| PackageName::parse(name))
            .collect()
    }
}

/// The shim's command line, `apt-get [-y] [-q] install [--no-install-recommends] <package>...`
/// or the same with `apt`, as a request. Anything else is refused, with what is allowed.
pub fn parse_command_line(args: &[String]) -> Result<Request, String> {
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
            None => return Err(format!("only install is allowed, not {arg}")),
            Some(names) => names.push(PackageName::parse(arg)?.0),
        }
    }
    match install {
        Some(names) if !names.is_empty() => Ok(Request {
            install: names,
            no_install_recommends,
        }),
        _ => Err("name the packages to install".to_owned()),
    }
}

const USAGE: &str = "system commands run as happy-system, not root, and may only install \
                     packages by name from this machine's repositories: apt-get install [-y] \
                     [-q] [--no-install-recommends] <package>...";

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

/// Sends `request` with this process's standard output and error, and waits for the reply.
fn forward(socket: &Path, request: &Request) -> std::io::Result<Reply> {
    use std::os::fd::AsFd as _;
    let mut stream = std::os::unix::net::UnixStream::connect(socket)?;
    let fds = [
        std::io::stdout().as_fd().try_clone_to_owned()?,
        std::io::stderr().as_fd().try_clone_to_owned()?,
    ];
    let body = serde_json::to_vec(request).expect("a request serializes");
    crate::helper::send_fds(stream.as_fd(), &body, &fds)?;
    drop(fds);
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply)?;
    serde_json::from_slice(&reply).map_err(std::io::Error::other)
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
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
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
        let partial = Path::new(SHIM_DIR).join(".happy-supervisor.partial");
        let _ = std::fs::remove_file(&partial);
        std::fs::copy(&exe, &partial)?;
        std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o755))?;
        std::fs::File::options()
            .write(true)
            .open(&partial)?
            .set_modified(source.modified()?)?;
        std::fs::rename(&partial, &copy)?;
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

/// Creates `dir` or makes sure of it: a directory, root's, with `mode`.
fn root_dir(dir: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    std::fs::create_dir_all(dir)?;
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(Error::new(
            ErrorKind::Io,
            format!("{} is not a directory", dir.display()),
        ));
    }
    if meta.uid() != 0 {
        std::os::unix::fs::chown(dir, Some(0), Some(0))?;
    }
    if meta.mode() & 0o7777 != mode {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// One system command's socket. Dropping it, which its exec does at the exit, closes it and
/// removes it, so nothing the command left running can install.
pub struct AptGate {
    path: PathBuf,
    listener: Option<std::os::unix::net::UnixListener>,
    task: Option<tokio::task::AbortHandle>,
    uid: u32,
}

/// One `apt-get` at a time: dpkg takes a lock anyway, and a second would fail on it.
static APT: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl AptGate {
    /// A socket that only `uid` (and root) may connect to, with the shims it needs. Blocking;
    /// needs root.
    pub fn open(uid: u32) -> Result<AptGate> {
        use std::os::unix::fs::PermissionsExt as _;
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        install_shims()?;
        root_dir(Path::new(SOCKET_DIR), 0o711)?;
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = Path::new(SOCKET_DIR).join(format!("{}-{n}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        std::os::unix::fs::chown(&path, Some(uid), None)?;
        listener.set_nonblocking(true)?;
        Ok(AptGate {
            path,
            listener: Some(listener),
            task: None,
            uid,
        })
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
        let uid = self.uid;
        let task = runtime.spawn(async move {
            let Ok(listener) = tokio::net::UnixListener::from_std(listener) else {
                return;
            };
            while let Ok((stream, _)) = listener.accept().await {
                let peer = stream.peer_cred().ok();
                let Ok(stream) = stream.into_std() else {
                    continue;
                };
                tokio::task::spawn_blocking(move || answer(stream, peer, uid, session));
            }
        });
        self.task = Some(task.abort_handle());
    }
}

impl Drop for AptGate {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Checks who asks, then runs the install and replies.
fn answer(
    mut stream: std::os::unix::net::UnixStream,
    peer: Option<tokio::net::unix::UCred>,
    uid: u32,
    session: u32,
) {
    use std::os::fd::AsFd as _;
    let _ = stream.set_nonblocking(false);
    let in_session = peer.is_some_and(|peer| {
        peer.uid() == uid
            && peer.pid().is_some_and(|pid| {
                nix::unistd::getsid(Some(nix::unistd::Pid::from_raw(pid)))
                    .is_ok_and(|sid| sid.as_raw() as u32 == session)
            })
    });
    let reply = if !in_session {
        Reply::Refused("only the system command's own processes may install".to_owned())
    } else {
        match crate::helper::recv_fds(stream.as_fd(), MAX_REQUEST, 2) {
            Ok((body, fds)) => match serde_json::from_slice::<Request>(&body)
                .map_err(|err| format!("bad request: {err}"))
                .and_then(|request| Ok((request.packages()?, request.no_install_recommends)))
            {
                Ok((packages, no_recommends)) => install(&packages, no_recommends, fds),
                Err(why) => Reply::Refused(why),
            },
            Err(err) => Reply::Refused(format!("bad request: {err}")),
        }
    };
    let _ = stream.write_all(&serde_json::to_vec(&reply).expect("a reply serializes"));
}

/// `apt-get install -y --no-remove` with a fixed environment, its output on `fds` (standard
/// output, then error).
fn install(packages: &[PackageName], no_recommends: bool, fds: Vec<std::os::fd::OwnedFd>) -> Reply {
    use std::process::{Command, Stdio};
    let mut fds = fds.into_iter();
    let (Some(stdout), Some(stderr)) = (fds.next(), fds.next()) else {
        return Reply::Refused("bad request: send standard output and error".to_owned());
    };
    let names: Vec<&str> = packages.iter().map(PackageName::as_str).collect();
    tracing::info!("system access: apt-get install {}", names.join(" "));
    let _one = APT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let status = Command::new("/usr/bin/apt-get")
        .args(["install", "-y", "-q", "--no-remove"])
        .args(no_recommends.then_some("--no-install-recommends"))
        .args(&names)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C.UTF-8")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status();
    match status {
        Ok(status) => Reply::Exited(status.code().unwrap_or(APT_FAILED as i32)),
        Err(err) => Reply::Refused(format!("cannot run /usr/bin/apt-get: {err}")),
    }
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
    fn the_supervisor_checks_the_names_whatever_the_shim_sent() {
        let request: Request =
            serde_json::from_str(r#"{"install": ["hello", "coreutils-"]}"#).unwrap();
        assert_eq!(
            request.packages(),
            Err("\"coreutils-\" is not a package name".to_owned())
        );
        let none = Request {
            install: vec![],
            no_install_recommends: false,
        };
        assert_eq!(none.packages(), Err("name 1 to 256 packages".to_owned()));
        assert!(serde_json::from_str::<Request>(r#"{"install": [], "options": ["-o"]}"#).is_err());
    }

    #[test]
    fn the_shim_takes_install_and_its_harmless_options_only() {
        let hello = Request {
            install: vec!["hello".to_owned(), "figlet".to_owned()],
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
            Ok(Request {
                no_install_recommends: true,
                ..hello
            })
        );
        for (line, why) in [
            ("update", "only install is allowed, not update"),
            ("remove hello", "only install is allowed, not remove"),
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
