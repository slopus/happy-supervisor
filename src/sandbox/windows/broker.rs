//! The broker: `<exe> __sandbox` as the supervisor's account (module docs, step 1).

use std::fs::File;
use std::io::{self, Read, Write as _};
use std::os::windows::io::{AsHandle as _, AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_SERVICE_ALREADY_RUNNING, HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithLogonW,
    GetCurrentProcess, GetExitCodeProcess, INFINITE, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
};

use super::acl::{self, Access};
use super::install::{self, Install};
use super::lease::Lease;
use super::token::{self, TokenSpec};
use super::win::{check, owned, wide};
use crate::error::{Error, ErrorKind, Result};
use crate::helper::{EXIT_BAD_JOB, EXIT_EXEC_FAILED, Job, JobOp, STATUS_MAGIC};
use crate::policy::{Network, ResolvedPolicy};
use crate::wire::{from_cbor, to_cbor};

/// What the broker hands the runner, framed like a job on the runner's stdin.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RunnerJob {
    pub op: JobOp,
    pub token: TokenSpec,
    /// The exec status pipe's handle in the runner, or 0.
    pub status: u64,
}

pub(super) fn write_frame<T: Serialize>(out: &mut impl io::Write, value: &T) -> io::Result<()> {
    let cbor = to_cbor(value);
    out.write_all(&(cbor.len() as u32).to_be_bytes())?;
    out.write_all(&cbor)
}

pub(super) fn read_frame<T: serde::de::DeserializeOwned>(input: &mut impl Read) -> Result<T> {
    let mut len = [0u8; 4];
    input.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > crate::helper::MAX_JOB_BYTES {
        return Err(Error::too_large(format!("frame is {len} bytes")));
    }
    let mut cbor = vec![0u8; len];
    input.read_exact(&mut cbor)?;
    from_cbor(&cbor).map_err(|err| Error::invalid_params(format!("bad frame: {err}")))
}

/// Stdin as an unbuffered File, so the bytes after the job stay for the command.
pub(super) fn raw_stdin() -> io::Result<File> {
    Ok(File::from(
        std::io::stdin().as_handle().try_clone_to_owned()?,
    ))
}

pub(super) fn main(placeholders: &[PathBuf]) -> ! {
    let (job, status, stdin) = match read_input() {
        Ok(input) => input,
        Err(err) => {
            eprintln!("happy-supervisor __sandbox: {err}");
            std::process::exit(EXIT_BAD_JOB)
        }
    };
    match run(&job, placeholders, status, stdin) {
        Ok(code) => std::process::exit(code as i32),
        Err((err, status)) => report(&job.op, status, err),
    }
}

/// A failure before the runner took over: the status pipe for an exec, the reply for a file
/// operation, as the Unix helper does.
pub(super) fn report(op: &JobOp, status: Option<File>, err: Error) -> ! {
    match op {
        JobOp::Exec { .. } => {
            match status {
                Some(mut pipe) => {
                    let _ = pipe.write_all(&to_cbor(&err));
                }
                None => eprintln!("happy-supervisor __sandbox: {err}"),
            }
            std::process::exit(EXIT_EXEC_FAILED)
        }
        JobOp::Fs(_) => {
            let mut stdout = std::io::stdout().lock();
            let frame = crate::helper::encode_fs_reply(Err(err));
            let written = stdout.write_all(&frame).and_then(|()| stdout.flush());
            std::process::exit(if written.is_ok() { 0 } else { 1 })
        }
    }
}

fn read_input() -> Result<(Job, Option<File>, File)> {
    let mut stdin = raw_stdin()?;
    let mut head = [0u8; 4];
    stdin.read_exact(&mut head)?;
    let status = if &head == STATUS_MAGIC {
        let mut handle = [0u8; 8];
        stdin.read_exact(&mut handle)?;
        // SAFETY: the parent duplicated this handle into us and nothing else owns it.
        let status = unsafe { File::from_raw_handle(u64::from_le_bytes(handle) as HANDLE) };
        stdin.read_exact(&mut head)?;
        Some(status)
    } else {
        None
    };
    let job = crate::helper::read_job(&mut (&head[..]).chain(&mut stdin))?;
    Ok((job, status, stdin))
}

type Failed = (Error, Option<File>);

fn run(
    job: &Job,
    placeholders: &[PathBuf],
    status: Option<File>,
    stdin: File,
) -> std::result::Result<u32, Failed> {
    let unavailable = |err: io::Error| Error::sandbox_unavailable(err.to_string());
    let install = match Install::load() {
        Ok(install) => install,
        Err(err) => return Err((unavailable(err), status)),
    };
    let mut lease = match Lease::acquire(&install, &install::dir()) {
        Ok(lease) => lease,
        Err(err) => return Err((unavailable(err), status)),
    };
    let result = confine_and_launch(&install, &mut lease, job, placeholders, status, stdin);
    // The runner and the command have exited (or never started): nothing uses the ACEs now.
    let revoked = lease.revoke_all();
    match (result, revoked) {
        (Ok(code), Ok(())) => Ok(code),
        (Ok(code), Err(err)) => {
            eprintln!("happy-supervisor __sandbox: cannot revoke the sandbox's ACEs: {err}");
            Ok(code)
        }
        (Err(failed), _) => Err(failed),
    }
}

fn confine_and_launch(
    install: &Install,
    lease: &mut Lease,
    job: &Job,
    placeholders: &[PathBuf],
    status: Option<File>,
    stdin: File,
) -> std::result::Result<u32, Failed> {
    let prepared = (|| -> Result<(String, TokenSpec)> {
        let password = lease
            .slot
            .password()
            .map_err(|err| Error::sandbox_unavailable(err.to_string()))?;
        let spec = token_spec(install, &lease.slot.group_sid, &job.policy);
        let account = token::logon(&lease.slot.account, &password)
            .map_err(|err| Error::sandbox_unavailable(err.to_string()))?;
        let check = token::impersonation(&token::restricted(&account, &spec)?)?;
        let exe = std::env::current_exe()?;
        let mut targets = super::targets(job.policy.layers(), placeholders);
        targets.push((
            exe,
            Access {
                read: true,
                write: false,
            },
        ));
        for (path, want) in targets {
            let has = acl::access(&path, check.as_raw_handle() as HANDLE)?;
            let aces = acl::aces(want, has);
            if aces.is_empty() {
                continue;
            }
            lease.record(&path)?;
            acl::add(&path, &lease.group, &aces).map_err(|err| cannot_enforce(&path, err))?;
        }
        Ok((password, spec))
    })();
    let (password, spec) = match prepared {
        Ok(prepared) => prepared,
        Err(err) => return Err((err, status)),
    };
    let runner = match launch(&lease.slot.account, &password, job, spec, status.as_ref()) {
        Ok(runner) => runner,
        Err(err) => return Err((err, status)),
    };
    // The runner holds its own copy now; it reports, or closes it when the command started.
    drop(status);
    runner.wait(stdin)
}

fn cannot_enforce(path: &Path, err: io::Error) -> Error {
    Error::new(
        ErrorKind::SandboxUnavailable,
        format!("cannot enforce the policy at {}: {err}", path.display()),
    )
}

/// The runner's token: writes restricted when the policy denies them by default, and the
/// network groups the policy does not want made deny-only.
fn token_spec(install: &Install, slot_group: &str, policy: &ResolvedPolicy) -> TokenSpec {
    let groups = &install.groups;
    let (isolated, local_bind) = match policy.network() {
        Network::Host { local_bind, .. } => (false, *local_bind),
        Network::Isolated { local_bind, .. } => (true, *local_bind),
    };
    let mut enabled = Vec::new();
    let mut disabled = Vec::new();
    for (sid, on) in [
        (&groups.isolated, isolated),
        (&groups.no_listen, !local_bind),
        (&groups.loopback, isolated && local_bind),
    ] {
        if on {
            enabled.push(sid.clone());
        } else {
            disabled.push(sid.clone());
        }
    }
    TokenSpec::new(
        policy.write_default() == crate::policy::Default::Deny,
        slot_group,
        enabled,
        disabled,
    )
}

struct Runner {
    process: OwnedHandle,
    /// Kills the runner and the command when the broker goes, however it goes.
    _job: OwnedHandle,
    stdin: File,
    op: JobOp,
    token: TokenSpec,
    status: u64,
}

fn launch(
    account: &str,
    password: &str,
    job: &Job,
    token: TokenSpec,
    status: Option<&File>,
) -> Result<Runner> {
    let exe = std::env::current_exe()?;
    let (stdin_reader, stdin_writer) = std::io::pipe()?;
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: stdin_reader.as_raw_handle() as HANDLE,
        hStdOutput: std::io::stdout().as_raw_handle() as HANDLE,
        hStdError: std::io::stderr().as_raw_handle() as HANDLE,
        ..Default::default()
    };
    let mut command_line = wide(format!(
        "\"{}\" {} {}",
        exe.display(),
        super::HELPER_ARG,
        super::RUNNER_ARG
    ));
    let system = std::env::var_os("SystemRoot")
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)
        .join("System32");
    let mut info = PROCESS_INFORMATION::default();
    // The secondary logon service sometimes refuses a call while it serves another
    // (ERROR_SERVICE_ALREADY_RUNNING, seen with concurrent brokers); those take milliseconds.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        // SAFETY: every string is NUL-terminated and lives across the call; the std handles
        // are open in this process, and the call copies them into the runner.
        let started = check(unsafe {
            CreateProcessWithLogonW(
                wide(account).as_ptr(),
                wide(".").as_ptr(),
                wide(password).as_ptr(),
                0,
                wide(&exe).as_ptr(),
                command_line.as_mut_ptr(),
                CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                std::ptr::null(),
                wide(&system).as_ptr(),
                &startup,
                &mut info,
            )
        });
        match started {
            Ok(()) => break,
            Err(err)
                if err.raw_os_error() == Some(ERROR_SERVICE_ALREADY_RUNNING as i32)
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => {
                return Err(Error::sandbox_unavailable(format!(
                    "cannot start the sandbox runner as {account}: {err}"
                )));
            }
        }
    }
    drop(stdin_reader);
    // SAFETY: fresh handles from CreateProcessWithLogonW.
    let (process, thread) = unsafe { (owned(info.hProcess), owned(info.hThread)) };
    let started = (|| -> io::Result<(OwnedHandle, u64)> {
        let job = kill_on_close_job()?;
        // SAFETY: both handles are open.
        check(unsafe {
            AssignProcessToJobObject(
                job.as_raw_handle() as HANDLE,
                process.as_raw_handle() as HANDLE,
            )
        })?;
        let status = match status {
            Some(pipe) => give(pipe, &process)?,
            None => 0,
        };
        // SAFETY: the runner's main thread, created suspended.
        if unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        Ok((job, status))
    })();
    let (job_object, status) = match started {
        Ok(started) => started,
        Err(err) => {
            // SAFETY: the process handle is open.
            unsafe {
                windows_sys::Win32::System::Threading::TerminateProcess(
                    process.as_raw_handle() as HANDLE,
                    1,
                )
            };
            return Err(err.into());
        }
    };
    Ok(Runner {
        process,
        _job: job_object,
        stdin: File::from(OwnedHandle::from(stdin_writer)),
        op: job.op.clone(),
        token,
        status,
    })
}

impl Runner {
    /// Sends the runner its job, then the rest of our stdin, and waits for it.
    fn wait(self, mut stdin: File) -> std::result::Result<u32, Failed> {
        let Runner {
            process,
            _job,
            stdin: mut to_runner,
            op,
            token,
            status,
        } = self;
        let job = RunnerJob { op, token, status };
        if write_frame(&mut to_runner, &job).is_ok() {
            // Detached: it ends at our stdin's EOF, or with the process.
            std::thread::spawn(move || {
                let _ = io::copy(&mut stdin, &mut to_runner);
            });
        }
        let handle = process.as_raw_handle() as HANDLE;
        // SAFETY: the process handle is open.
        unsafe { WaitForSingleObject(handle, INFINITE) };
        let mut code = 0u32;
        // SAFETY: as above.
        if unsafe { GetExitCodeProcess(handle, &mut code) } == 0 {
            return Err((io::Error::last_os_error().into(), None));
        }
        Ok(code)
    }
}

fn kill_on_close_job() -> io::Result<OwnedHandle> {
    // SAFETY: null attributes and name: an anonymous job.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh handle.
    let job = unsafe { owned(job) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: `limits` is the structure the class names, of the size passed.
    check(unsafe {
        SetInformationJobObject(
            job.as_raw_handle() as HANDLE,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    })?;
    Ok(job)
}

/// Duplicates `pipe` into `process`; returns its value there.
fn give(pipe: &File, process: &OwnedHandle) -> io::Result<u64> {
    let mut theirs: HANDLE = std::ptr::null_mut();
    // SAFETY: both handles are open; the copy is not inheritable.
    check(unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            pipe.as_raw_handle() as HANDLE,
            process.as_raw_handle() as HANDLE,
            &mut theirs,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    })?;
    Ok(theirs as u64)
}
