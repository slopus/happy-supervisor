//! The supervisor as PID 1, a container's entry point (docs/install.md, Containers).
//!
//! A process whose parent exits is reparented to PID 1, which must reap it. bubblewrap's own
//! init, PID 1 of the sandbox, outlives the bubblewrap the supervisor waits for by a moment, so
//! every sandboxed command leaves one such orphan, and a command's background processes may
//! leave more. On a host the system's init reaps them. When the supervisor is PID 1 itself,
//! [`reap_as_pid1`] keeps a small init in front of it, as `docker run --init` would. The
//! supervisor cannot reap them itself: a child of one of its threads that exited is reparented
//! to its main thread too, and reaping that would take an exit status `exec` waits for.

use std::sync::atomic::{AtomicI32, Ordering};

/// The init's PID, when [`reap_as_pid1`] started one: always 1.
static INIT: AtomicI32 = AtomicI32::new(0);

/// The signals the init passes on to the supervisor.
const FORWARDED: [libc::c_int; 6] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

/// When this process is PID 1, forks. The parent stays PID 1: it passes [`FORWARDED`] signals on
/// to the child, reaps every process reparented to it, and exits as the child does, with 128
/// plus the signal when a signal ended it. The child returns and runs the supervisor. As any
/// other PID it does nothing. Call it before any thread exists.
pub fn reap_as_pid1() {
    // SAFETY: getpid has no memory effects.
    if unsafe { libc::getpid() } != 1 {
        return;
    }
    // SAFETY: the sigset_t values are initialized by sigemptyset before use, and
    // pthread_sigmask only reads `set` and writes `old`. There is one thread, so blocking here
    // keeps the signals pending for sigwait in the parent; the child restores the mask.
    let (set, old) = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for signal in FORWARDED.into_iter().chain([libc::SIGCHLD]) {
            libc::sigaddset(&mut set, signal);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
        (set, old)
    };
    // SAFETY: there is one thread, so the child may run any code.
    match unsafe { libc::fork() } {
        -1 => {
            eprintln!(
                "happy-supervisor: running as PID 1 without an init, which cannot fork ({}); \
                 processes the sandbox leaves behind stay zombies",
                std::io::Error::last_os_error()
            );
            // SAFETY: restores the mask read above.
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
        }
        0 => {
            INIT.store(1, Ordering::Relaxed);
            // SAFETY: restores the mask read above.
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
        }
        child => init(child, &set),
    }
}

/// PID 1, when this process runs under the init [`reap_as_pid1`] started.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn pid() -> Option<u32> {
    match INIT.load(Ordering::Relaxed) {
        0 => None,
        pid => Some(pid as u32),
    }
}

/// The init's loop. Never returns.
fn init(child: libc::pid_t, set: &libc::sigset_t) -> ! {
    loop {
        let mut signal = 0;
        // SAFETY: `set` is a valid sigset_t and sigwait writes one int.
        if unsafe { libc::sigwait(set, &mut signal) } != 0 {
            continue;
        }
        if signal != libc::SIGCHLD {
            // SAFETY: kill has no memory effects.
            unsafe { libc::kill(child, signal) };
            continue;
        }
        loop {
            let mut status = 0;
            // SAFETY: waitpid writes the status into a valid int.
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid <= 0 {
                break;
            }
            if pid == child {
                std::process::exit(exit_code(status));
            }
        }
    }
}

/// The code a shell would report for a child's wait status.
fn exit_code(status: libc::c_int) -> i32 {
    if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        libc::WEXITSTATUS(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_the_shell_s() {
        let code = |script: &str| {
            let status = std::process::Command::new("/bin/sh")
                .args(["-c", script])
                .status()
                .unwrap();
            exit_code(std::os::unix::process::ExitStatusExt::into_raw(status))
        };
        assert_eq!(code("exit 0"), 0);
        assert_eq!(code("exit 3"), 3);
        assert_eq!(code("kill -TERM $$"), 128 + libc::SIGTERM);
    }

    #[test]
    fn a_process_that_is_not_pid_1_has_no_init() {
        reap_as_pid1();
        assert_eq!(pid(), None);
    }
}
