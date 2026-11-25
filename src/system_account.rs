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
const CRON_DENY: &str = "/etc/cron.deny";

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
    let (uid, gid) = (user.uid.as_raw(), user.gid.as_raw());
    std::fs::create_dir_all(PREFIX).map_err(|err| io(format!("cannot create {PREFIX}: {err}")))?;
    std::os::unix::fs::chown(PREFIX, Some(uid), Some(gid))
        .map_err(|err| io(format!("cannot give {PREFIX} to {USER}: {err}")))?;
    let npmrc = user.dir.join(".npmrc");
    write(&npmrc, &format!("prefix={PREFIX}\n"))?;
    std::os::unix::fs::chown(&npmrc, Some(uid), Some(gid))
        .map_err(|err| io(format!("cannot give {} to {USER}: {err}", npmrc.display())))?;
    write(Path::new(PROFILE), PROFILE_SCRIPT)?;
    deny_cron()
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
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
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

/// Keeps the account from leaving cron jobs that outlive `system disable`.
fn deny_cron() -> Result<()> {
    let current = match std::fs::read_to_string(CRON_DENY) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(io(format!("cannot read {CRON_DENY}: {err}"))),
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
    write(Path::new(CRON_DENY), &text)
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
