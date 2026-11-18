//! Windows Job Objects with `KILL_ON_JOB_CLOSE`. Owned by the exec track.

use std::io;
use std::os::windows::io::AsRawHandle as _;
use std::process::{Child, Command};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{INFINITE, WaitForSingleObject};

use crate::protocol::{ExitStatus, KillSignal};

/// The exit code of processes ended by `exec.kill` or a timeout.
const KILLED_EXIT_CODE: u32 = 1;

/// Nothing to do before spawning: the Job Object is attached right after.
pub(crate) fn isolate(_command: &mut Command) {}

/// A Job Object holding the child and everything it starts. Closing it kills them all, so a
/// supervisor that dies takes its commands with it.
#[derive(Debug)]
pub(crate) struct Tree {
    job: HANDLE,
}

// SAFETY: a job handle is a kernel handle, usable from any thread.
unsafe impl Send for Tree {}
// SAFETY: as above; the job functions used here are thread-safe.
unsafe impl Sync for Tree {}

impl Tree {
    /// Puts `child` into a new Job Object. A process the child starts before this returns
    /// escapes the job; spawning suspended would close that gap, but std cannot resume the
    /// main thread on stable Rust.
    pub(crate) fn adopt(child: &Child) -> io::Result<Tree> {
        // SAFETY: null attributes and name create an anonymous job with default security.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let tree = Tree { job };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` is a valid JOBOBJECT_EXTENDED_LIMIT_INFORMATION of the size passed.
        let set = unsafe {
            SetInformationJobObject(
                tree.job,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if set == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both handles are open; the child's stays open while `child` lives.
        if unsafe { AssignProcessToJobObject(tree.job, child.as_raw_handle() as HANDLE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(tree)
    }

    /// Ends every process in the job. Windows has no gentle signal for a tree, so `terminate`
    /// and `kill` both use `TerminateJobObject`.
    pub(crate) fn signal(&self, _signal: KillSignal) -> io::Result<()> {
        // SAFETY: the job handle is open until drop.
        if unsafe { TerminateJobObject(self.job, KILLED_EXIT_CODE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        // SAFETY: the handle is open and owned by this Tree alone.
        unsafe { CloseHandle(self.job) };
    }
}

/// Blocks until `child` exits. The process handle stays open, so the job can still be
/// signalled safely until the caller records the exit.
pub(crate) fn wait_exit(child: &Child) -> io::Result<()> {
    // SAFETY: the child's process handle is open while `child` lives.
    if unsafe { WaitForSingleObject(child.as_raw_handle() as HANDLE, INFINITE) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn exit_status(status: std::process::ExitStatus) -> ExitStatus {
    ExitStatus::Exited {
        code: status.code().unwrap_or(-1),
    }
}
