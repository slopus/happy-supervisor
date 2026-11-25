//! Who the supervisor runs as, and the workload user its work runs as (architecture.md,
//! Identity). With a workload user, every command, file operation and watch runs with that
//! user's uid, gid and supplementary groups, never the supervisor's.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::{Error, ErrorKind, Result};
use crate::protocol::{IdentityInfo, SystemInfo};
use crate::state::{StateDir, SystemAccess};

/// The supervisor's user and, with `--workload-user`, the user its work runs as. Resolved once
/// at startup.
#[derive(Debug)]
pub struct Identity {
    supervisor_user: String,
    root: bool,
    workload: Option<Arc<Workload>>,
    temp_dir: Option<String>,
    /// The state directory whose `private/system` enables system access. `None` refuses it.
    state: Option<StateDir>,
}

impl Identity {
    /// [`Identity::resolve`] with the workload user `state` names, and system access as `state`
    /// enables it.
    pub fn open(state: &StateDir) -> Result<Identity> {
        let mut identity = Identity::resolve(state.workload_user()?.as_deref())?;
        identity.state = Some(state.clone());
        Ok(identity)
    }

    /// The supervisor's own user, and the workload user named, if any. The node refuses to
    /// start when that user does not exist, is root, or cannot be switched to because the
    /// supervisor is not root, and on Linux when the supervisor is root and names none.
    pub fn resolve(workload_user: Option<&str>) -> Result<Identity> {
        let (supervisor_user, root) = current();
        if cfg!(target_os = "linux") && root && workload_user.is_none() {
            return Err(Error::invalid_params(ROOT_NEEDS_WORKLOAD_USER));
        }
        let workload = match workload_user {
            None => None,
            Some(name) => Some(Arc::new(Workload::resolve(name, &supervisor_user, root)?)),
        };
        let temp_dir = temp_dir(workload.as_deref());
        Ok(Identity {
            supervisor_user,
            root,
            workload,
            temp_dir,
            state: None,
        })
    }

    /// The account `{"mode": "system"}` work runs as, read from `private/system` on every call,
    /// so `system disable` takes effect on the next request. A refusal is `permission_denied`
    /// and says why.
    pub fn system(&self) -> Result<System> {
        if cfg!(windows) {
            return Err(denied("system access is not supported on Windows"));
        }
        if !self.root {
            return Err(denied(format!(
                "system access needs a supervisor running as root (a sudo install); this one \
                 runs as {:?}",
                self.supervisor_user
            )));
        }
        let access = match &self.state {
            Some(state) => state.system()?,
            None => None,
        };
        let access = access.ok_or_else(|| {
            denied(
                "system access is not enabled on this node; an administrator enables it with \
                 `sudo happy-supervisor system enable`",
            )
        })?;
        System::resolve(access, &self.supervisor_user)
    }

    pub fn workload(&self) -> Option<&Arc<Workload>> {
        self.workload.as_ref()
    }

    /// The work user's own temp directory, NodeInfo `identity.tempDir`: on macOS its
    /// `DARWIN_USER_TEMP_DIR`, where the developer tools' shims cache their lookups whatever
    /// `TMPDIR` says. `None` elsewhere, or when it could not be read.
    pub fn temp_dir(&self) -> Option<&str> {
        self.temp_dir.as_deref()
    }

    /// What NodeInfo `defaultEnv` says differently with a workload user: its `HOME` and `USER`.
    pub fn workload_env(&self) -> Vec<(String, String)> {
        #[cfg(unix)]
        return self
            .workload
            .iter()
            .flat_map(|workload| {
                [
                    ("HOME".to_string(), workload.home().to_string()),
                    ("USER".to_string(), workload.name().to_string()),
                ]
            })
            .collect();
        #[cfg(windows)]
        Vec::new()
    }

    /// NodeInfo `identity`.
    pub fn info(&self) -> IdentityInfo {
        IdentityInfo {
            supervisor_user: self.supervisor_user.clone(),
            workload_user: self.workload.as_ref().map(|w| w.name().to_owned()),
            root: self.root,
            temp_dir: self.temp_dir.clone(),
            system: self
                .system()
                .ok()
                .map(|system| SystemInfo { user: system.user }),
        }
    }
}

fn denied(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::PermissionDenied, message)
}

/// The account that installs system-wide software, as `private/system` names it (policy.md,
/// System access).
#[derive(Debug)]
pub struct System {
    user: String,
    /// The user the work runs as. `None` is root, which the supervisor is.
    account: Option<Arc<Workload>>,
    home: String,
    path: Vec<String>,
}

impl System {
    #[cfg(unix)]
    fn resolve(access: SystemAccess, supervisor_user: &str) -> Result<System> {
        let user = nix::unistd::User::from_name(&access.user)
            .map_err(|err| {
                Error::new(
                    ErrorKind::Io,
                    format!("cannot look up the system user {:?}: {err}", access.user),
                )
            })?
            .ok_or_else(|| {
                denied(format!(
                    "system access runs as {:?}, which no longer exists; an administrator runs \
                     `sudo happy-supervisor system enable` again",
                    access.user
                ))
            })?;
        let account = if user.uid.is_root() {
            None
        } else {
            Some(Arc::new(Workload::resolve(
                &user.name,
                supervisor_user,
                true,
            )?))
        };
        Ok(System {
            home: user.dir.to_string_lossy().into_owned(),
            user: access.user,
            account,
            path: access.path,
        })
    }

    #[cfg(windows)]
    fn resolve(_access: SystemAccess, _supervisor_user: &str) -> Result<System> {
        Err(denied("system access is not supported on Windows"))
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    /// The user to run as; `None` runs as the supervisor, which is root.
    pub fn account(&self) -> Option<&Arc<Workload>> {
        self.account.as_ref()
    }

    /// Gives a command the account's environment (api.md, Access): its `HOME`, `USER` and
    /// `LOGNAME`, on macOS its `TMPDIR`, and the recorded directories first in `PATH`, ahead of
    /// any other copy of them, so package managers use the account's caches and Homebrew's tools.
    pub fn apply_env(&self, env: &mut BTreeMap<String, String>) {
        env.insert("HOME".to_owned(), self.home.clone());
        for key in ["USER", "LOGNAME"] {
            env.insert(key.to_owned(), self.user.clone());
        }
        if let Some(temp) = temp_dir(self.account.as_deref()) {
            env.insert("TMPDIR".to_owned(), temp);
        }
        if self.path.is_empty() {
            return;
        }
        let rest = env.get("PATH").map_or("", String::as_str);
        let entries: Vec<&str> = self
            .path
            .iter()
            .map(String::as_str)
            .chain(
                rest.split(':')
                    .filter(|entry| !entry.is_empty() && !self.path.iter().any(|dir| dir == entry)),
            )
            .collect();
        let joined = entries.join(":");
        env.insert("PATH".to_owned(), joined);
    }
}

/// `happy-supervisor system enable`: records the account system access runs as, `user` or
/// else root on Linux, where `apt-get` and `npm -g` need it, and on macOS Homebrew's owner,
/// with Homebrew's directories for `PATH`: `brew` refuses to run as root, and Homebrew's
/// `npm -g` installs into its prefix. Root on a Mac without Homebrew. Needs root.
pub fn enable_system(state: &StateDir, user: Option<String>) -> Result<SystemAccess> {
    let (supervisor_user, root) = current();
    if cfg!(windows) || !root {
        return Err(denied(format!(
            "enabling system access needs root (sudo) on Linux or macOS; this runs as \
             {supervisor_user:?}"
        )));
    }
    let homebrew = if cfg!(target_os = "macos") {
        homebrew(HOMEBREW)
    } else {
        None
    };
    let user = match user {
        Some(user) => user,
        None => user_name(homebrew.as_ref().map_or(0, |brew| brew.owner))?,
    };
    let access = SystemAccess {
        user,
        path: homebrew.map(|brew| brew.path).unwrap_or_default(),
    };
    System::resolve(access.clone(), &supervisor_user)?;
    state.store_system(Some(&access))?;
    if let Err(err) = state.system() {
        state.store_system(None)?;
        return Err(err);
    }
    Ok(access)
}

/// Homebrew's repository and prefix: Apple silicon's, then Intel's.
const HOMEBREW: &[(&str, &str)] = &[
    ("/opt/homebrew", "/opt/homebrew"),
    ("/usr/local/Homebrew", "/usr/local"),
];

/// An installed Homebrew: who owns it, and its `bin` and `sbin`.
#[derive(Debug, PartialEq, Eq)]
struct Homebrew {
    owner: u32,
    path: Vec<String>,
}

/// The first of `candidates` whose repository holds `bin/brew`.
fn homebrew(candidates: &[(&str, &str)]) -> Option<Homebrew> {
    #[cfg(unix)]
    for (repository, prefix) in candidates {
        use std::os::unix::fs::MetadataExt as _;
        let repository = std::path::Path::new(repository);
        if !repository.join("bin/brew").is_file() {
            continue;
        }
        let owner = std::fs::metadata(repository).ok()?.uid();
        return Some(Homebrew {
            owner,
            path: vec![format!("{prefix}/bin"), format!("{prefix}/sbin")],
        });
    }
    let _ = candidates;
    None
}

/// The name of `uid`.
fn user_name(uid: u32) -> Result<String> {
    #[cfg(unix)]
    return nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|user| user.name)
        .ok_or_else(|| Error::invalid_params(format!("uid {uid} has no user name; pass --user")));
    #[cfg(windows)]
    Err(denied(format!("no user names on Windows (uid {uid})")))
}

/// `DARWIN_USER_TEMP_DIR` of the work user, as `getconf` run as that user prints it (the OS
/// derives it from the uid and creates it), without its trailing separator.
#[cfg(target_os = "macos")]
fn temp_dir(workload: Option<&Workload>) -> Option<String> {
    use std::process::{Command, Stdio};

    let mut command = Command::new("/usr/bin/getconf");
    command
        .arg("DARWIN_USER_TEMP_DIR")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    run_as(&mut command, workload, None).ok()?;
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_temp_dir(std::str::from_utf8(&output.stdout).ok()?)
}

#[cfg(not(target_os = "macos"))]
fn temp_dir(_workload: Option<&Workload>) -> Option<String> {
    None
}

/// One absolute path on one line, without its trailing separator.
#[cfg(any(target_os = "macos", all(test, unix)))]
fn parse_temp_dir(out: &str) -> Option<String> {
    let line = out.strip_suffix('\n').unwrap_or(out);
    let path = line.trim_end_matches('/');
    let normal = path
        .split('/')
        .skip(1)
        .all(|c| !matches!(c, "" | "." | ".."));
    (path.starts_with('/') && normal && !path.contains(['\n', '\0'])).then(|| path.to_owned())
}

/// On Linux, work never runs as root (SECURITY.md).
const ROOT_NEEDS_WORKLOAD_USER: &str = "on Linux a supervisor running as root needs \
     --workload-user, the unprivileged user its commands and file operations run as: see \
     docs/install.md (https://github.com/slopus/happy-supervisor/blob/main/docs/install.md)";

/// Makes `command` run as `workload`, when there is one ([`Workload::apply`]).
pub(crate) fn run_as(
    command: &mut std::process::Command,
    workload: Option<&Workload>,
    cwd: Option<&std::path::Path>,
) -> std::io::Result<()> {
    match workload {
        #[cfg(unix)]
        Some(workload) => workload.apply(command, cwd),
        #[cfg(windows)]
        Some(workload) => match *workload {},
        None => {
            let _ = (command, cwd);
            Ok(())
        }
    }
}

/// The supervisor's user name (its uid when it has none) and whether it is root.
#[cfg(unix)]
fn current() -> (String, bool) {
    let uid = nix::unistd::geteuid();
    let name = nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map_or_else(|| uid.to_string(), |user| user.name);
    (name, uid.is_root())
}

/// The account name, and whether the process token is elevated (an administrator's).
#[cfg(windows)]
fn current() -> (String, bool) {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let name = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_owned());
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; OpenProcessToken writes one handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return (name, false);
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut written = 0u32;
    // SAFETY: `elevation` is a TOKEN_ELEVATION of the size passed, and `token` is open.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut written,
        )
    };
    // SAFETY: `token` was opened above and is closed once.
    unsafe { CloseHandle(token) };
    (name, ok != 0 && elevation.TokenIsElevated != 0)
}

/// The user every command, file operation and watch runs as.
#[cfg(unix)]
#[derive(Debug)]
pub struct Workload {
    name: String,
    home: String,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

/// Windows has no workload user yet: [`Identity::resolve`] refuses one.
#[cfg(windows)]
#[derive(Debug)]
pub enum Workload {}

#[cfg(windows)]
impl Workload {
    fn resolve(name: &str, _supervisor_user: &str, _root: bool) -> Result<Workload> {
        Err(Error::invalid_params(format!(
            "a workload user ({name:?}) is not supported on Windows yet; run the supervisor as \
             the account commands should run as"
        )))
    }

    pub fn name(&self) -> &str {
        match *self {}
    }
}

#[cfg(unix)]
impl Workload {
    fn resolve(name: &str, supervisor_user: &str, root: bool) -> Result<Workload> {
        let user = nix::unistd::User::from_name(name)
            .map_err(|err| {
                Error::new(
                    ErrorKind::Io,
                    format!("cannot look up the workload user {name:?}: {err}"),
                )
            })?
            .ok_or_else(|| {
                Error::invalid_params(format!("the workload user {name:?} does not exist"))
            })?;
        if user.uid.is_root() {
            return Err(Error::invalid_params(format!(
                "the workload user {name:?} is root (uid 0); it must be an unprivileged user"
            )));
        }
        if !root {
            return Err(Error::invalid_params(format!(
                "running work as the workload user {name:?} needs a supervisor running as root; \
                 this one runs as {supervisor_user:?}"
            )));
        }
        let groups = group_list(&user.name, user.gid.as_raw())?;
        Ok(Workload {
            home: user.dir.to_string_lossy().into_owned(),
            name: user.name,
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            groups,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The home directory in the user database.
    pub fn home(&self) -> &str {
        &self.home
    }

    pub(crate) fn uid(&self) -> libc::uid_t {
        self.uid
    }

    /// Creates or truncates the file log at `path` as this user, in the helper
    /// ([`crate::helper::OPEN_LOG_ARG`]), which hands back the log and its directory, so the OS
    /// checks it as this user and the supervisor never resolves the path itself.
    pub(crate) fn create_log(
        &self,
        path: &crate::protocol::AbsPath,
    ) -> Result<(crate::exec::log::Place, std::fs::File)> {
        use std::io::Write as _;
        use std::os::fd::AsFd as _;
        use std::process::Stdio;

        let (ours, theirs) = std::os::unix::net::UnixDatagram::pair()?;
        let mut command = std::process::Command::new(crate::helper::exe()?);
        command
            .args([crate::helper::HELPER_ARG, crate::helper::OPEN_LOG_ARG])
            .stdin(Stdio::piped())
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(theirs)))
            .stderr(Stdio::piped());
        self.apply(&mut command, None)?;
        let mut child = command.spawn()?;
        drop(command);
        let mut stdin = child.stdin.take().expect("stdin is piped");
        // A helper that dies early closes its stdin; its exit then says why.
        let _ = stdin.write_all(&crate::helper::encode_frame(path));
        drop(stdin);
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(Error::new(
                ErrorKind::Io,
                format!(
                    "the log helper exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            ));
        }
        let (frame, fds) = crate::helper::recv_fds(ours.as_fd(), 64 << 10, 2)?;
        let reply: std::result::Result<(), Error> = crate::helper::read_frame(&mut &frame[..])?;
        reply?;
        let [dir, file]: [std::os::fd::OwnedFd; 2] = fds
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Io, "the log helper sent no descriptors"))?;
        let name = path
            .as_path()
            .file_name()
            .unwrap_or_default()
            .to_os_string();
        Ok((
            crate::exec::log::Place::from_parts(dir, name),
            std::fs::File::from(file),
        ))
    }

    /// Makes `command`'s child this user before it execs: its supplementary groups, gid and uid,
    /// then `cwd` (or `/`), so the OS checks the working directory as this user. Do not also
    /// set `current_dir`, which the child would enter as the supervisor.
    pub(crate) fn apply(
        &self,
        command: &mut std::process::Command,
        cwd: Option<&std::path::Path>,
    ) -> std::io::Result<()> {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::process::CommandExt as _;

        let cwd = std::ffi::CString::new(cwd.map_or(&b"/"[..], |cwd| cwd.as_os_str().as_bytes()))?;
        let groups = self.groups.clone();
        let (uid, gid) = (self.uid, self.gid);
        // SAFETY: the closure runs in the forked child before exec and only calls setgroups,
        // setgid, setuid and chdir, which are async-signal-safe, on memory allocated before the
        // fork.
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(groups.len() as _, groups.as_ptr()) < 0
                    || libc::setgid(gid) < 0
                    || libc::setuid(uid) < 0
                    || libc::chdir(cwd.as_ptr()) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
}

/// The user's groups, its primary group first.
#[cfg(target_os = "linux")]
fn group_list(name: &str, gid: libc::gid_t) -> Result<Vec<libc::gid_t>> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| Error::invalid_params(format!("the user name {name:?} contains NUL")))?;
    let groups =
        nix::unistd::getgrouplist(&c_name, nix::unistd::Gid::from_raw(gid)).map_err(|err| {
            Error::new(
                ErrorKind::Io,
                format!("cannot list the groups of {name:?}: {err}"),
            )
        })?;
    Ok(groups.into_iter().map(|gid| gid.as_raw()).collect())
}

/// `NGROUPS_MAX` in macOS's `<sys/syslimits.h>`: `setgroups` takes at most this many.
#[cfg(target_os = "macos")]
const MACOS_NGROUPS_MAX: usize = 16;

/// The user's groups, its primary group first, at most [`MACOS_NGROUPS_MAX`].
#[cfg(target_os = "macos")]
fn group_list(name: &str, gid: libc::gid_t) -> Result<Vec<libc::gid_t>> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| Error::invalid_params(format!("the user name {name:?} contains NUL")))?;
    let mut groups = vec![0 as libc::c_int; 64];
    loop {
        let mut count = groups.len() as libc::c_int;
        // SAFETY: `groups` holds `count` ints, and getgrouplist writes at most that many.
        let rc = unsafe {
            libc::getgrouplist(
                c_name.as_ptr(),
                gid as libc::c_int,
                groups.as_mut_ptr(),
                &mut count,
            )
        };
        if rc == 0 {
            groups.truncate(count as usize);
            break;
        }
        if groups.len() >= 4096 {
            return Err(Error::invalid_params(format!(
                "{name:?} is in more than 4096 groups"
            )));
        }
        groups.resize(groups.len() * 2, 0);
    }
    let mut groups: Vec<libc::gid_t> = groups.into_iter().map(|g| g as libc::gid_t).collect();
    groups.dedup();
    groups.truncate(MACOS_NGROUPS_MAX);
    Ok(groups)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_missing_or_root_workload_user_is_refused() {
        assert_eq!(
            Identity::resolve(Some("hs-no-such-user"))
                .unwrap_err()
                .to_string(),
            r#"the workload user "hs-no-such-user" does not exist"#
        );
        assert_eq!(
            Identity::resolve(Some("root")).unwrap_err().to_string(),
            r#"the workload user "root" is root (uid 0); it must be an unprivileged user"#
        );
    }

    #[test]
    fn without_a_workload_user_the_supervisor_is_described() {
        let identity = Identity::resolve(None).unwrap();
        let uid = nix::unistd::geteuid();
        let info = identity.info();
        assert_eq!(info.workload_user, None);
        assert_eq!(info.root, uid.is_root());
        let name = nix::unistd::User::from_uid(uid).unwrap().unwrap().name;
        assert_eq!(info.supervisor_user, name);
    }

    #[test]
    fn a_temp_dir_is_one_normalized_absolute_path() {
        assert_eq!(
            parse_temp_dir("/var/folders/6p/y937xtys6_716zvck3p0g3hw0000cj/T/\n").as_deref(),
            Some("/var/folders/6p/y937xtys6_716zvck3p0g3hw0000cj/T")
        );
        assert_eq!(parse_temp_dir("/tmp").as_deref(), Some("/tmp"));
        for bad in ["", "\n", "/", "T/", "/var/../tmp/", "/var//T/", "/a\n/b\n"] {
            assert_eq!(parse_temp_dir(bad), None, "{bad:?}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn on_macos_the_temp_dir_is_the_user_temp_dir() {
        let dir = Identity::resolve(None)
            .unwrap()
            .temp_dir()
            .unwrap()
            .to_owned();
        assert!(dir.starts_with("/var/folders/") || dir.starts_with("/private/var/folders/"));
        assert!(dir.ends_with("/T"), "{dir}");
    }

    #[test]
    fn homebrew_is_the_first_repository_with_brew() {
        let tmp = tempfile::tempdir().unwrap();
        let repository = tmp.path().join("Homebrew");
        std::fs::create_dir_all(repository.join("bin")).unwrap();
        std::fs::write(repository.join("bin/brew"), "").unwrap();
        let repository = repository.to_str().unwrap();
        assert_eq!(
            homebrew(&[("/hs-no-such-dir", "/a"), (repository, "/usr/local")]),
            Some(Homebrew {
                owner: nix::unistd::geteuid().as_raw(),
                path: vec!["/usr/local/bin".to_string(), "/usr/local/sbin".to_string()],
            })
        );
        assert_eq!(homebrew(&[("/hs-no-such-dir", "/a")]), None);
    }

    #[test]
    fn a_system_command_gets_the_accounts_environment() {
        let system = System {
            user: "admin".to_string(),
            account: None,
            home: "/Users/admin".to_string(),
            path: vec![
                "/opt/homebrew/bin".to_string(),
                "/opt/homebrew/sbin".to_string(),
            ],
        };
        let mut env = BTreeMap::from([
            (
                "PATH".to_string(),
                "/usr/local/bin:/opt/homebrew/sbin:/usr/bin".to_string(),
            ),
            ("HOME".to_string(), "/home/happy-workload".to_string()),
            ("LANG".to_string(), "C.UTF-8".to_string()),
        ]);
        system.apply_env(&mut env);
        let temp = env.remove("TMPDIR");
        assert_eq!(cfg!(target_os = "macos"), temp.is_some(), "{temp:?}");
        assert_eq!(
            env,
            BTreeMap::from([
                (
                    "PATH".to_string(),
                    "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin".to_string()
                ),
                ("HOME".to_string(), "/Users/admin".to_string()),
                ("USER".to_string(), "admin".to_string()),
                ("LOGNAME".to_string(), "admin".to_string()),
                ("LANG".to_string(), "C.UTF-8".to_string()),
            ])
        );
        let mut empty = BTreeMap::new();
        system.apply_env(&mut empty);
        assert_eq!(empty["PATH"], "/opt/homebrew/bin:/opt/homebrew/sbin");
    }

    #[test]
    fn a_supervisor_that_is_not_root_refuses_system_access() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let (me, _) = current();
        let err = Identity::resolve(None).unwrap().system().unwrap_err();
        assert_eq!(err.kind, ErrorKind::PermissionDenied);
        assert_eq!(
            err.message,
            format!(
                "system access needs a supervisor running as root (a sudo install); this one \
                 runs as {me:?}"
            )
        );
    }

    #[test]
    fn a_supervisor_that_is_not_root_cannot_switch_users() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let (me, _) = current();
        assert_eq!(
            Identity::resolve(Some("nobody")).unwrap_err().to_string(),
            format!(
                "running work as the workload user \"nobody\" needs a supervisor running as \
                 root; this one runs as {me:?}"
            )
        );
    }
}
