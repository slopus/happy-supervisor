//! Windows Job Objects with `KILL_ON_JOB_CLOSE`. Owned by the exec track.

use std::io;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle, RawHandle};
use std::os::windows::process::CommandExt as _;
use std::process::{Child, Command};

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_TIME,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, INFINITE, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
    WaitForSingleObject,
};

use crate::protocol::{ExitStatus, KillSignal, LimitSupport, Limits};

/// The exit code of processes ended by `exec.kill` or a timeout.
const KILLED_EXIT_CODE: u32 = 1;

/// Starts `command` and drops it. Windows has no parent-death signal, so any thread may start a
/// command; Unix starts them on a thread of their own (`unix::spawn`).
pub(crate) fn spawn(mut command: Command) -> io::Result<Child> {
    command.spawn()
}

/// Creates the child suspended, so it cannot start anything before [`Tree::adopt`] puts it in
/// its Job Object and lets it run.
pub(crate) fn isolate(command: &mut Command) {
    command.creation_flags(CREATE_SUSPENDED);
}

/// A Job Object holding the child and everything it starts. Closing it kills them all, so a
/// supervisor that dies takes its commands with it.
#[derive(Debug)]
pub(crate) struct Tree {
    job: OwnedHandle,
}

impl Tree {
    /// Puts `child`, spawned suspended by [`isolate`], into a new Job Object with `limits`, then
    /// resumes it. On an error the child is still suspended, and the caller kills it.
    pub(crate) fn adopt(child: &Child, limits: &Limits) -> io::Result<Tree> {
        // SAFETY: null attributes and name create an anonymous job with default security.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `job` is a freshly created handle that nothing else owns.
        let tree = Tree {
            job: unsafe { OwnedHandle::from_raw_handle(job as RawHandle) },
        };
        let limits = job_limits(limits);
        // SAFETY: `limits` is a valid JOBOBJECT_EXTENDED_LIMIT_INFORMATION of the size passed.
        let set = unsafe {
            SetInformationJobObject(
                tree.handle(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if set == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both handles are open; the child's stays open while `child` lives.
        if unsafe { AssignProcessToJobObject(tree.handle(), child.as_raw_handle() as HANDLE) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        resume(child.id())?;
        Ok(tree)
    }

    /// Ends every process in the job. Windows has no gentle signal for a tree, so `terminate`
    /// and `kill` both use `TerminateJobObject`.
    pub(crate) fn signal(&self, signal: KillSignal) -> io::Result<()> {
        if signal == KillSignal::Interrupt {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows commands cannot be interrupted yet",
            ));
        }
        // SAFETY: the job handle is open while `self` lives.
        if unsafe { TerminateJobObject(self.handle(), KILLED_EXIT_CODE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn handle(&self) -> HANDLE {
        self.job.as_raw_handle() as HANDLE
    }
}

/// The `exec.start` limits a Job Object enforces: all of them.
pub(crate) fn limit_support() -> LimitSupport {
    LimitSupport {
        memory_bytes: true,
        processes: true,
        cpu_seconds: true,
    }
}

/// `KILL_ON_JOB_CLOSE` and `limits`: the memory committed by the whole job, the processes in it
/// at once, and each process's user-mode CPU time.
pub(crate) fn job_limits(limits: &Limits) -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if let Some(bytes) = limits.memory_bytes {
        flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        info.JobMemoryLimit = usize::try_from(bytes.get()).unwrap_or(usize::MAX);
    }
    if let Some(processes) = limits.processes {
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit = processes.get();
    }
    if let Some(seconds) = limits.cpu_seconds {
        flags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
        // In 100-nanosecond units.
        info.BasicLimitInformation.PerProcessUserTimeLimit =
            i64::try_from(seconds.get().saturating_mul(10_000_000)).unwrap_or(i64::MAX);
    }
    info.BasicLimitInformation.LimitFlags = flags;
    info
}

/// Resumes the threads of process `pid`. A process created suspended has exactly one, its
/// main thread, which std does not expose on stable Rust, so it is found by a thread snapshot.
fn resume(pid: u32) -> io::Result<()> {
    // SAFETY: the snapshot call takes no pointers; the process id is ignored for threads.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `snapshot` is a valid handle that nothing else owns.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot as RawHandle) };
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut resumed = 0;
    // SAFETY: `entry` is a THREADENTRY32 with `dwSize` set, as Thread32First requires.
    let mut more = unsafe { Thread32First(snapshot.as_raw_handle() as HANDLE, &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: OpenThread takes no pointers.
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if thread.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `thread` is a fresh handle that nothing else owns.
            let thread = unsafe { OwnedHandle::from_raw_handle(thread as RawHandle) };
            // SAFETY: the handle is open and has THREAD_SUSPEND_RESUME access.
            if unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) } == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            resumed += 1;
        }
        // SAFETY: as for Thread32First.
        more = unsafe { Thread32Next(snapshot.as_raw_handle() as HANDLE, &mut entry) } != 0;
    }
    if resumed == 0 {
        return Err(io::Error::other(format!(
            "process {pid} has no thread to resume"
        )));
    }
    Ok(())
}

/// Hands the write end of an exec's status pipe to `child`, the sandbox helper, still
/// suspended: the handle is duplicated into it and closed here. Returns the preamble to write
/// to its stdin before the job, which tells the helper the handle's value there.
pub(crate) fn status_preamble(child: &Child, writer: std::io::PipeWriter) -> io::Result<[u8; 12]> {
    use std::os::windows::io::IntoRawHandle as _;
    use windows_sys::Win32::Foundation::{
        DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut theirs: HANDLE = std::ptr::null_mut();
    // SAFETY: our pipe handle is open, and closed by the call whatever it returns; the child's
    // process handle is open while `child` lives.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            writer.into_raw_handle() as HANDLE,
            child.as_raw_handle() as HANDLE,
            &mut theirs,
            0,
            0,
            DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut preamble = [0u8; 12];
    preamble[..4].copy_from_slice(crate::helper::STATUS_MAGIC);
    preamble[4..].copy_from_slice(&(theirs as u64).to_le_bytes());
    Ok(preamble)
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
