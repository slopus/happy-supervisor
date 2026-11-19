//! Who the supervisor runs as, and the workload user its work runs as (architecture.md,
//! Identity). With a workload user, every command, file operation and watch runs with that
//! user's uid, gid and supplementary groups, never the supervisor's.

use std::sync::Arc;

#[cfg(unix)]
use crate::error::ErrorKind;
use crate::error::{Error, Result};
use crate::protocol::IdentityInfo;

/// The supervisor's user and, with `--workload-user`, the user its work runs as. Resolved once
/// at startup.
#[derive(Debug)]
pub struct Identity {
    supervisor_user: String,
    root: bool,
    workload: Option<Arc<Workload>>,
}

impl Identity {
    /// The supervisor's own user, and the workload user named, if any. The node refuses to
    /// start when that user does not exist, is root, or cannot be switched to because the
    /// supervisor is not root.
    pub fn resolve(workload_user: Option<&str>) -> Result<Identity> {
        let (supervisor_user, root) = current();
        let workload = match workload_user {
            None => None,
            Some(name) => Some(Arc::new(Workload::resolve(name, &supervisor_user, root)?)),
        };
        Ok(Identity {
            supervisor_user,
            root,
            workload,
        })
    }

    pub fn workload(&self) -> Option<&Arc<Workload>> {
        self.workload.as_ref()
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
        }
    }
}

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
