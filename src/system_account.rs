//! `happy-system`, the account system access ran as on Linux before 0.2.13, with an npm prefix
//! it owned and apt behind a socket. System access now runs as root (policy.md, System access);
//! this removes what 0.2.12 and earlier set up for that account: the account, its home, its
//! processes, its npm prefix, the profile script that put the prefix on `PATH`, and its lines in
//! the cron and at deny files. `install.sh --uninstall` removes the same by these names.

use std::path::Path;

use crate::error::{Error, ErrorKind, Result};

pub const USER: &str = "happy-system";
/// The account's npm prefix, in [`DIR`]; its `bin` was on `PATH`.
pub const PREFIX_BIN: &str = "/opt/happy-system/npm/bin";
const DIR: &str = "/opt/happy-system";
const PROFILE: &str = "/etc/profile.d/happy-system.sh";
/// The deny files the account was added to, so it could not schedule jobs.
const DENY: [&str; 2] = ["/etc/cron.deny", "/etc/at.deny"];

/// Removes the account and everything set up for it, if it is there. Idempotent; needs root.
/// Refuses, changing nothing, an account that is root or in root's group: not one 0.2.12 made.
pub fn remove() -> Result<()> {
    if let Some(user) = lookup()? {
        if user.uid.is_root() || user.gid.as_raw() == 0 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "{USER} is root's or in root's group; it was not made by happy-supervisor, so it stays"
                ),
            ));
        }
        kill_processes(user.uid.as_raw())?;
        delete_account()?;
    }
    remove_path(Path::new(DIR))?;
    remove_path(Path::new(PROFILE))?;
    for deny in DENY {
        undeny(Path::new(deny))?;
    }
    Ok(())
}

fn delete_account() -> Result<()> {
    use std::process::Command;
    let deleted = match Command::new("userdel").args(["--remove", USER]).status() {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Command::new("deluser")
            .args(["--remove-home", USER])
            .status(),
        status => status,
    };
    match deleted {
        Ok(status) if status.success() => {}
        Ok(status) => return Err(io(format!("removing {USER} failed: {status}"))),
        Err(err) => {
            return Err(io(format!(
                "cannot remove {USER}: neither userdel nor deluser runs: {err}"
            )));
        }
    }
    // `userdel --remove` leaves a home it did not find in passwd, and BusyBox's deluser may too.
    remove_path(&Path::new("/home").join(USER))
}

fn remove_path(path: &Path) -> Result<()> {
    let removed = match std::fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => Err(err),
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
    };
    removed.map_err(|err| io(format!("cannot remove {}: {err}", path.display())))
}

/// Drops the account's line from the deny file at `path`, leaving every other line as it was.
fn undeny(path: &Path) -> Result<()> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(io(format!("cannot read {}: {err}", path.display()))),
    };
    let Some(kept) = without_account(&text) else {
        return Ok(());
    };
    std::fs::write(path, kept).map_err(|err| io(format!("cannot write {}: {err}", path.display())))
}

/// `text` without its lines naming the account, or `None` when it names none.
fn without_account(text: &str) -> Option<String> {
    if !text.lines().any(|line| line.trim() == USER) {
        return None;
    }
    Some(
        text.lines()
            .filter(|line| line.trim() != USER)
            .flat_map(|line| [line, "\n"])
            .collect(),
    )
}

/// Kills every process of `uid`, and those it starts meanwhile. Linux; needs root.
fn kill_processes(uid: u32) -> Result<()> {
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
    fn only_the_accounts_line_leaves_a_deny_file() {
        assert_eq!(without_account("nobody\n"), None);
        assert_eq!(
            without_account("nobody\nhappy-system\nalice").as_deref(),
            Some("nobody\nalice\n")
        );
        assert_eq!(without_account("happy-system\n").as_deref(), Some(""));
        let dir = tempfile::tempdir().unwrap();
        let deny = dir.path().join("cron.deny");
        undeny(&deny).unwrap();
        assert!(!deny.exists(), "a missing file stays missing");
        std::fs::write(&deny, "happy-system\nbob\n").unwrap();
        undeny(&deny).unwrap();
        assert_eq!(std::fs::read_to_string(&deny).unwrap(), "bob\n");
    }

    #[test]
    fn a_path_is_removed_whatever_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("opt");
        std::fs::create_dir_all(tree.join("npm/bin")).unwrap();
        std::fs::write(tree.join("npm/bin/cowsay"), "").unwrap();
        remove_path(&tree).unwrap();
        assert!(!tree.exists());
        remove_path(&tree).unwrap();
        let link = dir.path().join("profile");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        remove_path(&link).unwrap();
        assert!(
            !link.exists() && dir.path().exists(),
            "the link, not what it points at"
        );
    }

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
