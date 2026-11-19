//! Linux `memoryBytes` and `processes` limits: a cgroup v2 child per command, under the cgroup
//! the service manager delegated to the supervisor (systemd `Delegate=yes`, docs/install.md).
//! Owned by the exec track.

use std::fs;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::protocol::Limits;

/// Where cgroup v2 is mounted.
const ROOT: &str = "/sys/fs/cgroup";
/// The leaf the supervisor moves itself into: a cgroup that holds processes cannot enable
/// controllers for its children.
const SUPERVISOR: &str = "supervisor";
/// The prefix of a command's cgroup.
const EXEC: &str = "exec-";

/// The supervisor's delegated cgroup, once it holds no process and passes its controllers on.
#[derive(Debug)]
struct Delegated {
    dir: PathBuf,
    memory: bool,
    pids: bool,
    next: AtomicU64,
    /// Command cgroups that still held a process the command left behind when it exited.
    stale: Mutex<Vec<PathBuf>>,
}

static DELEGATED: OnceLock<Option<Delegated>> = OnceLock::new();

/// Takes over the supervisor's cgroup if it was delegated. Call it once at startup, before the
/// supervisor starts any process: a cgroup it shares with another process is not its to manage.
/// Without the call, or without delegation, `memoryBytes` and `processes` are not enforced.
pub fn init() {
    DELEGATED.get_or_init(|| match delegate() {
        Ok(delegated) => Some(delegated),
        Err(reason) => {
            tracing::info!("limits.memoryBytes and limits.processes are not enforced: {reason}");
            None
        }
    });
}

/// Whether `memoryBytes` and `processes` are enforced.
pub(crate) fn support() -> (bool, bool) {
    match DELEGATED.get() {
        Some(Some(delegated)) => (delegated.memory, delegated.pids),
        _ => (false, false),
    }
}

fn delegate() -> Result<Delegated, String> {
    let own = fs::read_to_string("/proc/self/cgroup").map_err(|err| err.to_string())?;
    let path = own
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or("the supervisor is not in a cgroup v2 hierarchy")?;
    let dir = Path::new(ROOT).join(path.trim_start_matches('/'));
    let read =
        |name: &str| fs::read_to_string(dir.join(name)).map_err(|err| format!("{}: {err}", name));
    let available = read("cgroup.controllers")?;
    let available: Vec<&str> = available.split_whitespace().collect();
    if !available.contains(&"memory") && !available.contains(&"pids") {
        return Err(format!(
            "{} has neither the memory nor the pids controller",
            dir.display()
        ));
    }
    let pid = std::process::id().to_string();
    // The supervisor's own init, as PID 1 of a container, moves to the leaf with it.
    let init = crate::init::pid().map(|pid| pid.to_string());
    let others = read("cgroup.procs")?
        .lines()
        .filter(|line| *line != pid && Some(*line) != init.as_deref())
        .count();
    if others > 0 {
        return Err(format!(
            "{} holds {others} other processes, so it was not delegated to the supervisor alone",
            dir.display()
        ));
    }
    let leaf = dir.join(SUPERVISOR);
    match fs::create_dir(&leaf) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(format!("cannot create {}: {err}", leaf.display())),
    }
    let moved = init
        .iter()
        .chain([&pid])
        .try_for_each(|pid| fs::write(leaf.join("cgroup.procs"), pid));
    if let Err(err) = moved {
        let _ = fs::remove_dir(&leaf);
        return Err(format!("cannot move into {}: {err}", leaf.display()));
    }
    let enable = |controller: &str| {
        available.contains(&controller)
            && fs::write(dir.join("cgroup.subtree_control"), format!("+{controller}")).is_ok()
    };
    let (memory, pids) = (enable("memory"), enable("pids"));
    if !memory && !pids {
        return Err(format!(
            "cannot enable the memory or pids controller in {}",
            dir.display()
        ));
    }
    let delegated = Delegated {
        dir,
        memory,
        pids,
        next: AtomicU64::new(0),
        stale: Mutex::new(Vec::new()),
    };
    // Commands of a previous supervisor in this cgroup, which a restart did not end.
    if let Ok(entries) = fs::read_dir(&delegated.dir) {
        let leftovers = entries
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(EXEC))
            .map(|entry| entry.path());
        lock(&delegated.stale).extend(leftovers);
    }
    Ok(delegated)
}

/// One command's cgroup, with its limits. Dropping it removes the cgroup, or, while a process
/// the command left behind is still in it, retries with the next command.
#[derive(Debug)]
pub(crate) struct Cgroup {
    dir: PathBuf,
    /// `cgroup.procs`, open for writing: a process joins by writing `0` to it.
    procs: OwnedFd,
}

impl Cgroup {
    /// A cgroup for `limits`, or `None` when they set neither `memoryBytes` nor `processes`.
    /// The caller refused those limits already if this node does not enforce them.
    pub(crate) fn create(limits: &Limits) -> io::Result<Option<Cgroup>> {
        if limits.memory_bytes.is_none() && limits.processes.is_none() {
            return Ok(None);
        }
        let Some(Some(delegated)) = DELEGATED.get() else {
            return Ok(None);
        };
        lock(&delegated.stale).retain(|dir| fs::remove_dir(dir).is_err());
        let n = delegated.next.fetch_add(1, Ordering::Relaxed);
        let dir = delegated
            .dir
            .join(format!("{EXEC}{}-{n}", std::process::id()));
        fs::create_dir(&dir)?;
        let procs = fs::OpenOptions::new()
            .write(true)
            .open(dir.join("cgroup.procs"));
        let cgroup = Cgroup {
            procs: match procs {
                Ok(file) => file.into(),
                Err(err) => {
                    let _ = fs::remove_dir(&dir);
                    return Err(err);
                }
            },
            dir,
        };
        if let Some(bytes) = limits.memory_bytes {
            cgroup.set("memory.max", &bytes.to_string())?;
            // Swap would let the tree run on past the limit, only slower.
            match cgroup.set("memory.swap.max", "0") {
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                other => other?,
            }
            // Over the limit, the kernel kills the whole tree, not one process of it.
            cgroup.set("memory.oom.group", "1")?;
        }
        if let Some(processes) = limits.processes {
            cgroup.set("pids.max", &processes.to_string())?;
        }
        Ok(Some(cgroup))
    }

    fn set(&self, name: &str, value: &str) -> io::Result<()> {
        fs::write(self.dir.join(name), value)
            .map_err(|err| io::Error::new(err.kind(), format!("{name}: {err}")))
    }

    /// The descriptor a process writes `0` to, to join. The sandbox helper joins through it
    /// just before it execs the command, so bubblewrap and the helper stay outside.
    pub(crate) fn procs(&self) -> BorrowedFd<'_> {
        self.procs.as_fd()
    }

    /// Makes the child join before it execs. Register it before the child drops privileges:
    /// the workload user may not write to the supervisor's cgroups.
    pub(crate) fn join(&self, command: &mut Command) {
        let fd = self.procs.as_raw_fd();
        // SAFETY: the closure runs in the forked child and only calls write, which is
        // async-signal-safe, on a descriptor this cgroup keeps open until the spawn returns.
        unsafe {
            command.pre_exec(move || join(fd));
        }
    }

    /// Whether the kernel killed the tree for going over `memory.max`.
    pub(crate) fn out_of_memory(&self) -> bool {
        let Ok(events) = fs::read_to_string(self.dir.join("memory.events")) else {
            return false;
        };
        let count = |key: &str| {
            events
                .lines()
                .filter_map(|line| line.split_once(' '))
                .find(|(name, _)| *name == key)
                .and_then(|(_, n)| n.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };
        // `oom` counts this cgroup's own limit only; `oom_kill` also counts a system-wide OOM.
        count("oom") > 0 && count("oom_kill") > 0
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        if fs::remove_dir(&self.dir).is_err()
            && let Some(Some(delegated)) = DELEGATED.get()
        {
            lock(&delegated.stale).push(self.dir.clone());
        }
    }
}

/// Moves the calling process into the cgroup whose `cgroup.procs` is open as `fd`.
/// Async-signal-safe.
pub(crate) fn join(fd: std::os::fd::RawFd) -> io::Result<()> {
    // SAFETY: write reads one byte from a static buffer.
    if unsafe { libc::write(fd, b"0".as_ptr().cast(), 1) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_init_nothing_is_enforced_and_no_cgroup_is_made() {
        let limits = Limits {
            memory_bytes: std::num::NonZeroU64::new(1 << 20),
            processes: std::num::NonZeroU32::new(4),
            cpu_seconds: None,
        };
        assert_eq!(support(), (false, false));
        assert!(Cgroup::create(&limits).unwrap().is_none());
    }
}
