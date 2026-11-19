//! The sandbox helper, `happy-supervisor __sandbox` (docs/architecture.md, The sandbox helper).
//!
//! The parent writes one [`Job`] to the helper's stdin with [`encode_job`]. The helper reads
//! exactly that frame, confines itself (Linux) or is already confined (macOS, by
//! `sandbox-exec`), and then either execs the command or performs one file operation.
//!
//! For an exec job the parent passes the write end of a close-on-exec pipe as fd
//! [`STATUS_FD`] (see [`install_status_fd`]). If the helper cannot confine itself or exec the
//! command, it writes the [`Error`] as CBOR there and exits 127. A successful exec closes the
//! pipe with nothing written. [`parse_exec_status`] reads the result.
//!
//! For a file job the helper writes one frame, `{"ok": FsResponse}` or `{"err": Error}`, to stdout
//! and exits 0. [`parse_fs_reply`] reads it. Jobs and replies are framed the same way: a 4-byte
//! big-endian length, then CBOR.

use std::collections::BTreeMap;
use std::io::Read;
#[cfg(unix)]
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::wire::{from_cbor, to_cbor};

use crate::error::{Error, ErrorKind, Result};
use crate::fs::{FsRequest, FsResponse};
use crate::policy::ResolvedPolicy;
use crate::protocol::{AbsPath, Argv};

/// Bigger than any valid job: a 16 MiB `fs.write` plus a full policy.
pub const MAX_JOB_BYTES: usize = 32 << 20;

/// The helper's fd for the exec status pipe.
pub const STATUS_FD: i32 = 3;

/// Windows: what precedes the job on the helper's stdin when the parent passes a status pipe,
/// followed by the pipe's handle in the helper as a little-endian u64. A frame's first byte is
/// at most 0x02, so it cannot be mistaken for a frame.
pub const STATUS_MAGIC: &[u8; 4] = b"HSS1";

/// The exit code of a helper that could not read its job.
pub const EXIT_BAD_JOB: i32 = 125;
/// The exit code of a helper that could not confine itself or exec the command.
pub const EXIT_EXEC_FAILED: i32 = 127;

/// One sandboxed operation. The policy is resolved by the parent, so the parent and the
/// helper act on the same canonical grants and the same `hidden` state directory (which lives
/// in [`ResolvedPolicy::hidden`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub policy: ResolvedPolicy,
    pub op: JobOp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JobOp {
    /// `env` is the whole environment. `cwd` is entered after confinement, so the OS checks it.
    Exec {
        argv: Argv,
        cwd: AbsPath,
        env: BTreeMap<String, String>,
    },
    Fs(FsRequest),
}

/// The frame the parent writes to the helper's stdin.
pub fn encode_job(job: &Job) -> Vec<u8> {
    encode_frame(job)
}

fn encode_frame<T: Serialize>(value: &T) -> Vec<u8> {
    let cbor = to_cbor(value);
    let mut frame = Vec::with_capacity(4 + cbor.len());
    frame.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
    frame.extend_from_slice(&cbor);
    frame
}

/// Reads exactly one frame from `reader`. Pass an unbuffered reader, or bytes past the frame are
/// consumed too.
pub fn read_job(reader: &mut impl Read) -> Result<Job> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_JOB_BYTES {
        return Err(Error::too_large(format!(
            "job is {len} bytes, at most {MAX_JOB_BYTES} are allowed"
        )));
    }
    let mut cbor = vec![0u8; len];
    reader.read_exact(&mut cbor)?;
    from_cbor(&cbor).map_err(|err| Error::invalid_params(format!("bad job: {err}")))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FsReply {
    Ok(FsResponse),
    Err(Error),
}

/// Parses the helper's stdout after a file job.
pub fn parse_fs_reply(stdout: &[u8]) -> Result<FsResponse> {
    if stdout.is_empty() {
        return Err(Error::new(
            ErrorKind::Io,
            "sandbox helper exited without a reply",
        ));
    }
    let reply = stdout
        .split_first_chunk::<4>()
        .filter(|(len, rest)| u32::from_be_bytes(**len) as usize == rest.len())
        .ok_or_else(|| "the frame length does not match".to_string())
        .and_then(|(_, cbor)| from_cbor::<FsReply>(cbor));
    match reply {
        Ok(FsReply::Ok(response)) => Ok(response),
        Ok(FsReply::Err(err)) => Err(err),
        Err(err) => Err(Error::new(
            ErrorKind::Io,
            format!("sandbox helper sent a bad reply: {err}"),
        )),
    }
}

/// Parses what the helper wrote to the status pipe before it closed. Empty means the command
/// was exec'd.
pub fn parse_exec_status(status: &[u8]) -> Result<()> {
    if status.is_empty() {
        return Ok(());
    }
    match from_cbor::<Error>(status) {
        Ok(err) => Err(err),
        Err(err) => Err(Error::new(
            ErrorKind::Io,
            format!("sandbox helper sent a bad status: {err}"),
        )),
    }
}

/// Makes `fd`, the write end of the status pipe, the child's [`STATUS_FD`] without
/// close-on-exec, so it survives into the helper.
///
/// # Safety
///
/// Call it only inside a `pre_exec` closure, in the forked child. It replaces whatever the
/// child had open as fd 3. It is async-signal-safe.
#[cfg(unix)]
pub unsafe fn install_status_fd(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    if fd == STATUS_FD {
        // SAFETY: fcntl on an fd number has no memory effects.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        // SAFETY: as above.
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    // SAFETY: dup2 on fd numbers has no memory effects; the caller accepts losing fd 3.
    } else if unsafe { libc::dup2(fd, STATUS_FD) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

static EXE: OnceLock<PathBuf> = OnceLock::new();

/// Uses `path` as the helper binary instead of the current executable. Integration tests call
/// it with `env!("CARGO_BIN_EXE_happy-supervisor")`, because their own executable is the test
/// harness. Only the first call has an effect.
pub fn set_exe(path: PathBuf) {
    let _ = EXE.set(path);
}

/// The binary to run as `<exe> __sandbox`.
pub fn exe() -> Result<PathBuf> {
    match EXE.get() {
        Some(path) => Ok(path.clone()),
        None => Ok(std::env::current_exe()?),
    }
}

/// The entry point of `happy-supervisor __sandbox`. `main.rs` calls it before starting any
/// runtime or thread.
pub fn main() -> ! {
    #[cfg(windows)]
    crate::sandbox::windows::helper_main();
    #[cfg(unix)]
    unix_main()
}

#[cfg(unix)]
fn unix_main() -> ! {
    let Job { policy, op } = match read_stdin_job() {
        Ok(job) => job,
        Err(err) => {
            eprintln!("happy-supervisor __sandbox: {err}");
            std::process::exit(EXIT_BAD_JOB)
        }
    };
    match op {
        JobOp::Exec { argv, cwd, env } => run_exec(&policy, &argv, &cwd, &env),
        JobOp::Fs(request) => run_fs(&policy, &request),
    }
}

#[cfg(unix)]
fn read_stdin_job() -> Result<Job> {
    use std::os::fd::AsFd as _;
    // A duplicate of fd 0 as a File: unbuffered, unlike `Stdin`, so the bytes after the frame
    // stay in the pipe for the command.
    let fd = std::io::stdin().as_fd().try_clone_to_owned()?;
    read_job(&mut std::fs::File::from(fd))
}

#[cfg(unix)]
/// Confines this process. On macOS `sandbox-exec` already did.
fn confine(policy: &ResolvedPolicy) -> Result<()> {
    #[cfg(target_os = "linux")]
    return crate::sandbox::enter(policy);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
        Ok(())
    }
}

#[cfg(unix)]
fn run_exec(
    policy: &ResolvedPolicy,
    argv: &Argv,
    cwd: &AbsPath,
    env: &BTreeMap<String, String>,
) -> ! {
    let status = take_status_pipe();
    let err = match confine(policy) {
        Err(err) => err,
        Ok(()) => exec(argv, cwd, env),
    };
    match status {
        Some(mut pipe) => {
            let _ = pipe.write_all(&to_cbor(&err));
        }
        None => eprintln!("happy-supervisor __sandbox: {err}"),
    }
    std::process::exit(EXIT_EXEC_FAILED)
}

#[cfg(unix)]
fn exec(argv: &Argv, cwd: &AbsPath, env: &BTreeMap<String, String>) -> Error {
    use std::os::unix::process::CommandExt as _;
    // After confining: on Linux the helper's other half, which keeps SIGINT ignored, has forked.
    // SAFETY: restoring the default action has no memory effects.
    unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
    // With `tty` the parent made the terminal this process's stdout and stderr, and kept stdin
    // for the job; the command gets the terminal as stdin too.
    // SAFETY: isatty and dup2 act on descriptor numbers only.
    unsafe {
        if libc::isatty(1) == 1 && libc::dup2(1, 0) < 0 {
            return Error::from(std::io::Error::last_os_error());
        }
    }
    let err = std::process::Command::new(argv.program())
        .args(argv.args())
        .current_dir(cwd.as_path())
        .env_clear()
        .envs(env)
        .exec();
    Error::from(err)
}

/// Takes fd 3 if the parent installed it, marked close-on-exec so a successful exec closes it.
#[cfg(unix)]
fn take_status_pipe() -> Option<std::fs::File> {
    use std::os::fd::{FromRawFd as _, OwnedFd};
    // SAFETY: fcntl on an fd number has no memory effects; on a closed fd it fails with EBADF.
    let flags = unsafe { libc::fcntl(STATUS_FD, libc::F_GETFD) };
    // SAFETY: as above.
    if flags < 0 || unsafe { libc::fcntl(STATUS_FD, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return None;
    }
    // SAFETY: fd 3 is open, and nothing else in this fresh process owns it.
    Some(std::fs::File::from(unsafe {
        OwnedFd::from_raw_fd(STATUS_FD)
    }))
}

/// The frame a file job's helper writes to stdout, which [`parse_fs_reply`] reads.
pub fn encode_fs_reply(result: Result<FsResponse>) -> Vec<u8> {
    encode_frame(&match result {
        Ok(response) => FsReply::Ok(response),
        Err(err) => FsReply::Err(err),
    })
}

#[cfg(unix)]
fn run_fs(policy: &ResolvedPolicy, request: &FsRequest) -> ! {
    let frame = encode_fs_reply(confine(policy).and_then(|()| crate::fs::perform(request)));
    let mut stdout = std::io::stdout().lock();
    let written = stdout.write_all(&frame).and_then(|()| stdout.flush());
    std::process::exit(if written.is_ok() { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Bytes, FileKind, FsPathParams, FsReadResult, FsStat};

    fn job() -> Job {
        let policy = crate::policy::allow_list([] as [&str; 0], [] as [&str; 0], false, true);
        Job {
            policy: ResolvedPolicy::resolve(&policy, std::path::Path::new("/nonexistent-state"))
                .unwrap(),
            op: JobOp::Exec {
                argv: Argv::try_from(vec!["/bin/echo".to_string(), "hi".to_string()]).unwrap(),
                cwd: AbsPath::try_from(if cfg!(windows) { r"C:\" } else { "/" }).unwrap(),
                env: BTreeMap::from([("PATH".to_string(), "/bin".to_string())]),
            },
        }
    }

    #[test]
    fn frame_is_length_then_cbor_and_reading_stops_at_its_end() {
        let job = job();
        let frame = encode_job(&job);
        let cbor = to_cbor(&job);
        assert_eq!(frame[..4], (cbor.len() as u32).to_be_bytes());
        assert_eq!(frame[4..], cbor[..]);

        let mut stream = std::io::Cursor::new([frame, b"stdin of the command".to_vec()].concat());
        assert_eq!(read_job(&mut stream).unwrap(), job);
        let mut rest = String::new();
        stream.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "stdin of the command");
    }

    #[test]
    fn bad_frames_are_rejected() {
        let huge = ((MAX_JOB_BYTES + 1) as u32).to_be_bytes();
        let err = read_job(&mut &huge[..]).unwrap_err();
        assert_eq!(err.kind, ErrorKind::TooLarge);

        let truncated = [0, 0, 0, 10, 0xa0];
        assert_eq!(
            read_job(&mut &truncated[..]).unwrap_err().kind,
            ErrorKind::Io
        );

        let garbage = [&1u32.to_be_bytes()[..], &[0xa0]].concat();
        assert_eq!(
            read_job(&mut &garbage[..]).unwrap_err().kind,
            ErrorKind::InvalidParams
        );
    }

    #[test]
    fn fs_job_shape() {
        let path = if cfg!(windows) { r"C:\x" } else { "/x" };
        let request = FsRequest::Stat(FsPathParams {
            path: AbsPath::try_from(path).unwrap(),
        });
        assert_eq!(
            crate::testkit::json(crate::wire::to_value(&JobOp::Fs(request))),
            serde_json::json!({ "fs": { "stat": { "path": path } } })
        );
    }

    fn framed(literal: serde_json::Value) -> Vec<u8> {
        let cbor = to_cbor(&crate::testkit::cbor(literal));
        [&(cbor.len() as u32).to_be_bytes()[..], &cbor].concat()
    }

    #[test]
    fn fs_replies() {
        let stat = serde_json::json!({ "ok": { "stat": { "kind": "file", "size": 3, "modifiedMs": 5, "readonly": true } } });
        assert_eq!(
            parse_fs_reply(&framed(stat)).unwrap(),
            FsResponse::Stat(FsStat {
                kind: FileKind::File,
                size: 3,
                modified_ms: 5,
                readonly: true,
            })
        );
        let read = serde_json::json!({ "ok": { "read": { "data": "h'6869'", "size": 2 } } });
        assert_eq!(
            parse_fs_reply(&framed(read)).unwrap(),
            FsResponse::Read(FsReadResult {
                data: Bytes(b"hi".to_vec()),
                size: 2,
            })
        );
        assert_eq!(
            parse_fs_reply(&framed(serde_json::json!({ "ok": "done" }))).unwrap(),
            FsResponse::Done
        );
        let denied = serde_json::json!({ "err": { "kind": "permission_denied", "message": "no" } });
        assert_eq!(
            parse_fs_reply(&framed(denied)).unwrap_err(),
            Error::new(ErrorKind::PermissionDenied, "no")
        );
        assert_eq!(
            parse_fs_reply(b"").unwrap_err(),
            Error::new(ErrorKind::Io, "sandbox helper exited without a reply")
        );
        assert_eq!(
            parse_fs_reply(&[0, 0, 0, 9, 0xa0]).unwrap_err(),
            Error::new(
                ErrorKind::Io,
                "sandbox helper sent a bad reply: the frame length does not match"
            )
        );
    }

    #[test]
    fn exec_status() {
        assert_eq!(parse_exec_status(b""), Ok(()));
        let not_found = Error::new(ErrorKind::NotFound, "No such file or directory");
        assert_eq!(parse_exec_status(&to_cbor(&not_found)), Err(not_found));
        assert_eq!(parse_exec_status(b"\xff").unwrap_err().kind, ErrorKind::Io);
    }
}
