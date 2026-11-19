//! Unix process groups (`setsid`, `killpg`). Owned by the exec track.

use std::io;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Child, Command};

use crate::protocol::{ExitStatus, KillSignal, LimitSupport, Limits};

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

/// The `exec.start` limits Unix enforces: `cpuSeconds` only, as `RLIMIT_CPU`, which every process
/// the command starts inherits and counts for itself. The tree-wide memory and process limits
/// need cgroups (Linux) or are not available (macOS).
pub(crate) fn limit_support() -> LimitSupport {
    LimitSupport {
        memory_bytes: false,
        processes: false,
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
