//! `happy-system`, the account system access runs as on Linux unless an administrator names
//! another (policy.md, System access). `system enable` creates it with an npm prefix it owns, so
//! `npm install -g` works without root while the account cannot read the supervisor's private
//! state. `install.sh --uninstall` removes the same account, prefix, profile script and deny
//! entry by these names.

use std::path::Path;

use crate::error::{Error, ErrorKind, Result};

pub const USER: &str = "happy-system";
/// npm's global prefix for the account. Not under `/usr/local`, whose `bin`, `lib` and Python
/// directories root searches first: owning them would let the account run code as root.
pub const PREFIX: &str = "/opt/happy-system/npm";
pub const PREFIX_BIN: &str = "/opt/happy-system/npm/bin";
const PROFILE: &str = "/etc/profile.d/happy-system.sh";
/// The prefix's parent, root's, which the account may not change.
const DIR: &str = "/opt/happy-system";
/// Where cron and at look for users they refuse.
const DENY: [&str; 2] = ["/etc/cron.deny", "/etc/at.deny"];

/// Appended, not prepended, so a program the account installs never shadows one of the system's
/// for another user; root's `PATH` does not get it at all.
const PROFILE_SCRIPT: &str = "\
# Installed by happy-supervisor: programs happy-system installs with npm install -g, on the PATH
# of every user but root.
if [ \"$(id -u)\" -ne 0 ]; then
  case \":$PATH:\" in
    *:/opt/happy-system/npm/bin:*) ;;
    *) PATH=\"$PATH:/opt/happy-system/npm/bin\" ;;
  esac
fi
";

/// Creates the account if it is missing, then makes sure of its prefix, its `~/.npmrc`, the
/// profile script and its line in `/etc/cron.deny`. Idempotent; needs root.
pub fn provision() -> Result<()> {
    if lookup()?.is_none() {
        create()?;
    }
    let user = lookup()?.ok_or_else(|| io(format!("{USER} was not created")))?;
    unprivileged(&user)?;
    let (uid, gid) = (user.uid.as_raw(), user.gid.as_raw());
    root_dir(Path::new(DIR))?;
    std::fs::create_dir_all(PREFIX).map_err(|err| io(format!("cannot create {PREFIX}: {err}")))?;
    std::os::unix::fs::chown(PREFIX, Some(uid), Some(gid))
        .map_err(|err| io(format!("cannot give {PREFIX} to {USER}: {err}")))?;
    let npmrc = user.dir.join(".npmrc");
    write_as(&npmrc, &format!("prefix={PREFIX}\n"), uid, gid)
        .map_err(|err| io(format!("cannot write {}: {err}", npmrc.display())))?;
    write(Path::new(PROFILE), PROFILE_SCRIPT)?;
    DENY.iter().try_for_each(|path| deny(Path::new(path)))
}

/// Refuses an existing account that is root, in root's group, or in any group but its own: one
/// this did not create, whose rights system access would hand out.
fn unprivileged(user: &nix::unistd::User) -> Result<()> {
    let name = std::ffi::CString::new(USER).expect("no NUL in the name");
    let groups = nix::unistd::getgrouplist(&name, user.gid)
        .map_err(|err| io(format!("cannot list {USER}'s groups: {err}")))?;
    if user.uid.is_root() || user.gid.as_raw() == 0 || groups.iter().any(|g| *g != user.gid) {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "{USER} exists with more rights than its own: uid {}, groups {groups:?}; remove \
                 it, or name another account with --user",
                user.uid
            ),
        ));
    }
    Ok(())
}

/// Creates `dir` or makes sure of it: a directory, root's, that no one else may write, under
/// parents that only root may write either.
fn root_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    std::fs::create_dir_all(dir)
        .and_then(|()| std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)))
        .map_err(|err| io(format!("cannot create {}: {err}", dir.display())))?;
    for path in dir.ancestors() {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|err| io(format!("cannot read {}: {err}", path.display())))?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "{} must be a directory that only root may write",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Kills every process of the account, and those it starts meanwhile. Linux; needs root.
pub fn kill_processes() -> Result<()> {
    let Some(user) = lookup()? else {
        return Ok(());
    };
    let uid = user.uid.as_raw();
    for _ in 0..50 {
        let pids = processes_of(uid)?;
        if pids.is_empty() {
            return Ok(());
        }
        for pid in pids {
            kill_if_uid(pid, uid);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err(io(format!("{USER} keeps starting processes")))
}

fn lookup() -> Result<Option<nix::unistd::User>> {
    nix::unistd::User::from_name(USER).map_err(|err| io(format!("cannot look up {USER}: {err}")))
}

fn create() -> Result<()> {
    use std::process::Command;
    let home = format!("/home/{USER}");
    let shell = ["/usr/sbin/nologin", "/sbin/nologin"]
        .into_iter()
        .find(|shell| Path::new(shell).exists())
        .unwrap_or("/bin/false");
    let created = match Command::new("useradd")
        .args([
            "--system",
            "--create-home",
            "--home-dir",
            &home,
            "--shell",
            shell,
            USER,
        ])
        .status()
    {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Command::new("adduser")
            .args(["-S", "-D", "-h", &home, "-s", shell, USER])
            .status(),
        status => status,
    };
    match created {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(io(format!("creating {USER} failed: {status}"))),
        Err(err) => Err(io(format!(
            "cannot create {USER}: neither useradd nor adduser runs: {err}"
        ))),
    }
}

/// Writes `contents` to `path`, mode 0644, unless it already holds them.
fn write(path: &Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    if std::fs::read_to_string(path).is_ok_and(|current| current == contents) {
        return Ok(());
    }
    std::fs::write(path, contents)
        .and_then(|()| std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)))
        .map_err(|err| io(format!("cannot write {}: {err}", path.display())))
}

/// Writes `contents` to `path`, in a directory the account owns, as a new file of the account's
/// that replaces whatever `path` is. Never through a link the account put there, which would
/// have root write, and give the account, any file it points at.
fn write_as(path: &Path, contents: &str, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let partial = path.with_extension("happy-supervisor");
    let create = || {
        std::fs::File::options()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o644)
            .open(&partial)
    };
    let mut file = match create() {
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(&partial)?;
            create()?
        }
        file => file?,
    };
    let written = std::os::unix::fs::fchown(&file, Some(uid), Some(gid))
        .and_then(|()| file.write_all(contents.as_bytes()))
        .and_then(|()| std::fs::rename(&partial, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    written
}

/// Names the account in the deny file at `path`, so it cannot leave cron or at jobs that
/// outlive `system disable`.
fn deny(path: &Path) -> Result<()> {
    let current = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(io(format!("cannot read {}: {err}", path.display()))),
    };
    if current.lines().any(|line| line.trim() == USER) {
        return Ok(());
    }
    let mut text = current;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(USER);
    text.push('\n');
    write(path, &text)
}

/// Kills `pid` if it still has `uid`. Through a pidfd, which holds on to the process, so a
/// process that took the ID of one that exited meanwhile is not killed; a kernel without pidfds
/// (before 5.3) gets a plain `kill`.
fn kill_if_uid(pid: i32, uid: u32) {
    // SAFETY: pidfd_open takes a pid and flags, and returns a new descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        return;
    }
    // SAFETY: the descriptor was just opened, and nothing else owns it.
    let fd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd as i32) };
    let still = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .is_ok_and(|status| status_has_uid(&status, uid));
    if still {
        use std::os::fd::AsRawFd as _;
        // SAFETY: pidfd_send_signal takes the open pidfd, a signal, a null siginfo and flags.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
    }
}

/// The processes whose real, effective, saved or filesystem uid is `uid`.
fn processes_of(uid: u32) -> Result<Vec<i32>> {
    let entries =
        std::fs::read_dir("/proc").map_err(|err| io(format!("cannot list /proc: {err}")))?;
    Ok(entries
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/status"))
                .is_ok_and(|status| status_has_uid(&status, uid))
        })
        .collect())
}

fn status_has_uid(status: &str, uid: u32) -> bool {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .is_some_and(|ids| ids.split_whitespace().any(|id| id.parse() == Ok(uid)))
}

fn io(message: String) -> Error {
    Error::new(ErrorKind::Io, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_process_is_killed_only_while_it_has_the_uid() {
        use std::os::unix::process::ExitStatusExt as _;
        let uid = nix::unistd::getuid().as_raw();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        kill_if_uid(pid, uid.wrapping_add(1));
        assert_eq!(child.try_wait().unwrap(), None);
        kill_if_uid(pid, uid);
        assert_eq!(child.wait().unwrap().signal(), Some(9));
    }

    #[test]
    fn the_prefix_directory_must_be_roots_alone() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mine = dir.path().join("happy-system");
        let err = root_dir(&mine).unwrap_err();
        assert_eq!(err.kind, ErrorKind::PermissionDenied);
        assert_eq!(
            err.message,
            format!(
                "{} must be a directory that only root may write",
                mine.display()
            )
        );
    }

    #[test]
    fn the_npmrc_replaces_a_link_instead_of_writing_through_it() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, "root's\n").unwrap();
        let npmrc = dir.path().join(".npmrc");
        std::os::unix::fs::symlink(&target, &npmrc).unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(".npmrc.happy-supervisor")).unwrap();
        let (uid, gid) = (
            nix::unistd::getuid().as_raw(),
            nix::unistd::getgid().as_raw(),
        );
        write_as(&npmrc, "prefix=/opt/happy-system/npm\n", uid, gid).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "root's\n");
        assert!(std::fs::symlink_metadata(&npmrc).unwrap().is_file());
        assert_eq!(
            std::fs::read_to_string(&npmrc).unwrap(),
            "prefix=/opt/happy-system/npm\n"
        );
        assert!(!dir.path().join(".npmrc.happy-supervisor").exists());
    }

    #[test]
    fn a_process_is_the_accounts_by_any_of_its_uids() {
        let status = "Name:\tsleep\nUid:\t0\t999\t0\t0\nGid:\t0\t0\t0\t0\n";
        assert!(status_has_uid(status, 999));
        assert!(status_has_uid(status, 0));
        assert!(!status_has_uid(status, 998));
        assert!(!status_has_uid("Name:\tx\n", 0));
    }

    #[test]
    fn this_process_is_found_by_its_uid() {
        let me = nix::unistd::getuid().as_raw();
        assert!(
            processes_of(me)
                .unwrap()
                .contains(&(std::process::id() as i32))
        );
    }
}
