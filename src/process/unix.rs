//! Unix process groups (`setsid`, `killpg`). Owned by the exec track.

use std::io;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Child, Command};
use std::sync::OnceLock;
use std::sync::mpsc;

use crate::protocol::{ExitStatus, KillSignal, LimitSupport, Limits};

/// A command for the spawner, and where its child goes.
type SpawnJob = (Command, mpsc::SyncSender<io::Result<Child>>);

/// Starts `command` on the spawner, a thread that lives as long as the supervisor, and drops it
/// there. Linux sends a child's parent-death signal (`PR_SET_PDEATHSIG`, which bubblewrap's
/// `--die-with-parent` sets) when the thread that forked it exits, not the process. A command
/// started from a tokio blocking thread was killed when that thread exited, 10 s after it was
/// last used, however long the command was meant to run.
pub(crate) fn spawn(command: Command) -> io::Result<Child> {
    static SPAWNER: OnceLock<Option<mpsc::Sender<SpawnJob>>> = OnceLock::new();
    let gone = || io::Error::other("the supervisor's spawner thread is not running");
    let spawner = SPAWNER.get_or_init(|| {
        let (jobs, queue) = mpsc::channel::<SpawnJob>();
        std::thread::Builder::new()
            .name("spawner".into())
            .spawn(move || {
                for (mut command, reply) in queue {
                    let child = command.spawn();
                    // The parent's ends of the child's stdio (a terminal's slave) close here.
                    drop(command);
                    let _ = reply.send(child);
                }
            })
            .ok()
            .map(|_| jobs)
    });
    let (reply, child) = mpsc::sync_channel(1);
    spawner
        .as_ref()
        .ok_or_else(gone)?
        .send((command, reply))
        .map_err(|_| gone())?;
    child.recv().map_err(|_| gone())?
}

/// Makes the child the leader of a new session and process group, before anything else runs
/// in it (the sandbox helper included).
pub(crate) fn isolate(command: &mut Command) {
    // SAFETY: the closure runs in the forked child and only calls setsid, which is
    // async-signal-safe and touches no memory.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Gives the command SIGINT's default action, which an ignored SIGINT in the supervisor (a
/// background job of a shell) would otherwise pass on, so `interrupt` reaches it.
pub(crate) fn default_interrupt(command: &mut Command) {
    // SAFETY: the closure runs in the forked child and only calls signal, which is
    // async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            Ok(())
        });
    }
}

/// The `exec.start` limits Unix enforces. `cpuSeconds` is `RLIMIT_CPU`, which every process the
/// command starts inherits and counts for itself. On Linux, `memoryBytes` and `processes` are a
/// cgroup of the command's own ([`super::cgroups`]), when the supervisor's cgroup was delegated to
/// it. macOS has neither: `RLIMIT_NPROC` counts every process of the user, not of the tree.
pub(crate) fn limit_support() -> LimitSupport {
    #[cfg(target_os = "linux")]
    let (memory_bytes, processes) = super::cgroups::support();
    #[cfg(not(target_os = "linux"))]
    let (memory_bytes, processes) = (false, false);
    LimitSupport {
        memory_bytes,
        processes,
        cpu_seconds: true,
    }
}

/// Applies `limits` to the child before it execs: at `cpuSeconds` of CPU time a process gets
/// `SIGXCPU`, and a second later `SIGKILL` if it survived that.
pub(crate) fn limit(command: &mut Command, limits: &Limits) {
    let Some(seconds) = limits.cpu_seconds else {
        return;
    };
    let seconds = seconds.get() as libc::rlim_t;
    let cpu = libc::rlimit {
        rlim_cur: seconds,
        rlim_max: seconds.saturating_add(1),
    };
    // SAFETY: the closure runs in the forked child and only calls setrlimit, which is
    // async-signal-safe, on a value copied into it.
    unsafe {
        command.pre_exec(move || {
            if libc::setrlimit(libc::RLIMIT_CPU, &cpu) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// The process group a child leads.
#[derive(Debug)]
pub(crate) struct Tree {
    pgid: libc::pid_t,
}

impl Tree {
    pub(crate) fn adopt(child: &Child) -> io::Result<Tree> {
        Ok(Tree {
            pgid: child.id() as libc::pid_t,
        })
    }

    /// Signals every process in the group. A group that is already gone is not an error.
    pub(crate) fn signal(&self, signal: KillSignal) -> io::Result<()> {
        let signal = match signal {
            KillSignal::Interrupt => libc::SIGINT,
            KillSignal::Terminate => libc::SIGTERM,
            KillSignal::Kill => libc::SIGKILL,
        };
        // SAFETY: killpg has no memory effects.
        if unsafe { libc::killpg(self.pgid, signal) } < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                return Err(err);
            }
        }
        Ok(())
    }
}

/// Blocks until `child` exits, without reaping it. Until it is reaped its pid, which is also
/// the group's id, cannot be reused, so the caller can stop signalling the group first.
pub(crate) fn wait_exit(child: &Child) -> io::Result<()> {
    loop {
        // SAFETY: an all-zero siginfo_t is valid, and waitid only writes into it.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid siginfo_t for the duration of the call.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

pub(crate) fn exit_status(status: std::process::ExitStatus) -> ExitStatus {
    match (status.code(), status.signal()) {
        (Some(code), _) => ExitStatus::Exited { code },
        (None, Some(signal)) => ExitStatus::Signaled { signal },
        (None, None) => ExitStatus::Exited { code: -1 },
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
    use std::time::Duration;

    use super::*;

    /// `sleep 30`, killed when the thread that forked it exits, as bubblewrap's
    /// `--die-with-parent` has it.
    fn dies_with_its_parent_thread() -> Command {
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        // SAFETY: the closure runs in the forked child before exec and only calls prctl, which is
        // async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
    }

    /// Starts `start`'s command on a thread that exits at once, then gives the kernel a moment.
    fn started_on_a_passing_thread(start: fn(Command) -> io::Result<Child>) -> Child {
        let child = std::thread::spawn(move || start(dies_with_its_parent_thread()))
            .join()
            .unwrap()
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        child
    }

    #[test]
    fn a_command_outlives_the_thread_that_asked_for_it() {
        let mut direct = started_on_a_passing_thread(|mut command| command.spawn());
        assert_eq!(
            direct.wait().unwrap().signal(),
            Some(libc::SIGKILL),
            "the kernel kills a child whose forking thread exits"
        );
        let mut spawned = started_on_a_passing_thread(spawn);
        assert_eq!(spawned.try_wait().unwrap(), None);
        spawned.kill().unwrap();
        assert_eq!(spawned.wait().unwrap().signal(), Some(libc::SIGKILL));
    }
}
