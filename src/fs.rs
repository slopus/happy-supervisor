//! File operations (`fs.*`). Owned by the files track; the scaffold froze the types and
//! signatures.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind, Result};
use crate::helper::{Job, JobOp};
use crate::identity::Workload;
use crate::policy::{Confinement, ResolvedPolicy};
use crate::protocol::{
    AbsPath, Bytes, DirEntry, Empty, FileId, FileKind, FsListResult, FsMkdirParams, FsPathParams,
    FsReadParams, FsReadResult, FsRemoveParams, FsRenameParams, FsStat, FsWriteParams,
    MAX_FS_DATA_BYTES, MAX_LIST_ENTRIES, Value, WriteMode,
};

/// One file operation without its `access`. Travels to the sandbox helper inside a
/// [`Job`](crate::helper::Job).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FsRequest {
    Stat(FsPathParams),
    List(FsPathParams),
    Read(FsReadParams),
    Write(FsWriteParams),
    Mkdir(FsMkdirParams),
    Remove(FsRemoveParams),
    Rename(FsRenameParams),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FsResponse {
    Stat(FsStat),
    List(FsListResult),
    Read(FsReadResult),
    /// `{}`, the result of `fs.write`, `fs.mkdir`, `fs.remove` and `fs.rename`.
    Done,
}

impl FsResponse {
    /// The reply body of the request this answers.
    pub fn into_value(self) -> Value {
        match self {
            FsResponse::Stat(stat) => crate::wire::to_value(&stat),
            FsResponse::List(list) => crate::wire::to_value(&list),
            FsResponse::Read(read) => crate::wire::to_value(&read),
            FsResponse::Done => crate::wire::to_value(&Empty {}),
        }
    }
}

/// Runs a file request with this process's rights. Called in-process for raw access (on a
/// blocking thread) and inside the sandbox helper for sandboxed access.
pub fn perform(request: &FsRequest) -> Result<FsResponse> {
    match request {
        FsRequest::Stat(params) => stat(params.path.as_path()).map(FsResponse::Stat),
        FsRequest::List(params) => list(params.path.as_path()).map(FsResponse::List),
        FsRequest::Read(params) => read(params).map(FsResponse::Read),
        FsRequest::Write(params) => write(params).map(|()| FsResponse::Done),
        FsRequest::Mkdir(params) => mkdir(params).map(|()| FsResponse::Done),
        FsRequest::Remove(params) => remove(params).map(|()| FsResponse::Done),
        FsRequest::Rename(params) => rename(params).map(|()| FsResponse::Done),
    }
}

/// Runs a file request under its confinement: raw in-process, sandboxed through the helper.
pub async fn handle(request: FsRequest, confinement: Confinement) -> Result<FsResponse> {
    handle_as(request, confinement, None).await
}

/// [`handle`], as `workload` when there is one: a raw request then runs in the helper too, as
/// that user and unconfined (`__sandbox fs`).
pub async fn handle_as(
    request: FsRequest,
    confinement: Confinement,
    workload: Option<Arc<Workload>>,
) -> Result<FsResponse> {
    match (confinement, workload) {
        (Confinement::Raw, None) => tokio::task::spawn_blocking(move || perform(&request))
            .await
            .map_err(|err| Error::new(ErrorKind::Io, format!("file operation failed: {err}")))?,
        (Confinement::Raw, Some(workload)) => {
            let mut command = std::process::Command::new(crate::helper::exe()?);
            command.args([crate::helper::HELPER_ARG, crate::helper::UNCONFINED_FS_ARG]);
            crate::identity::run_as(&mut command, Some(&*workload), None)?;
            run_helper(command, &crate::helper::encode_fs_job(&request)).await
        }
        (Confinement::Sandboxed(policy), workload) => sandboxed(request, policy, workload).await,
    }
}

async fn sandboxed(
    request: FsRequest,
    policy: ResolvedPolicy,
    workload: Option<Arc<Workload>>,
) -> Result<FsResponse> {
    // The sandbox shows a path the policy hides as missing (bubblewrap) or lets metadata through
    // (Seatbelt), so the policy decides first and every platform answers permission_denied.
    // A rename acts on its two paths' directory entries, so their last components are not
    // followed; every other request acts on what its path resolves to.
    let checks: Vec<(&AbsPath, bool, bool)> = match &request {
        FsRequest::Stat(params) | FsRequest::List(params) => vec![(&params.path, false, true)],
        FsRequest::Read(params) => vec![(&params.path, false, true)],
        FsRequest::Write(params) => vec![(&params.path, true, true)],
        FsRequest::Mkdir(params) => vec![(&params.path, true, true)],
        FsRequest::Remove(params) => vec![(&params.path, true, true)],
        FsRequest::Rename(params) => vec![(&params.from, true, false), (&params.to, true, false)],
    };
    let checks: Vec<(String, PathBuf, bool, bool)> = checks
        .into_iter()
        .map(|(path, writes, follow)| {
            let shown = path.as_str().to_string();
            (shown, path.as_path().to_path_buf(), writes, follow)
        })
        .collect();
    let check = policy.clone();
    let denied = tokio::task::spawn_blocking(move || {
        checks
            .into_iter()
            .find_map(|(shown, target, writes, follow)| {
                let target = match (follow, target.parent(), target.file_name()) {
                    (false, Some(parent), Some(name)) => {
                        crate::policy::resolve_path(parent).join(name)
                    }
                    _ => crate::policy::resolve_path(&target),
                };
                if !check.can_read(&target) {
                    Some((shown, "readable"))
                } else if writes && !check.can_write(&target) {
                    Some((shown, "writable"))
                } else {
                    None
                }
            })
    })
    .await
    .map_err(|err| Error::new(ErrorKind::Io, format!("policy check failed: {err}")))?;
    if let Some((shown, what)) = denied {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("{shown}: not {what} by the policy"),
        ));
    }

    let job = Job {
        policy,
        op: JobOp::Fs(request),
    };
    let exe = crate::helper::exe()?;
    let plan = crate::sandbox::Plan {
        policy: &job.policy,
        net: None,
        exe: &exe,
        #[cfg(target_os = "linux")]
        cgroup: None,
    };
    let mut prepared = crate::sandbox::prepare(&plan, &job)?;
    crate::identity::run_as(&mut prepared.command, workload.as_deref(), None)?;
    let frame = crate::helper::encode_job(&job);
    let reply = run_helper(prepared.command, &frame).await;
    drop(prepared.placeholders);
    reply
}

/// Runs a helper with `frame` on its stdin and reads the one reply it writes to stdout.
async fn run_helper(command: std::process::Command, frame: &[u8]) -> Result<FsResponse> {
    let mut command = tokio::process::Command::from(command);
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    // A helper that dies before reading its job closes the pipe; its output says why.
    let _ = tokio::io::AsyncWriteExt::write_all(&mut stdin, frame).await;
    drop(stdin);
    let output = child.wait_with_output().await?;
    if output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::new(
            ErrorKind::Io,
            format!(
                "sandbox helper exited with {} without a reply: {}",
                output.status,
                stderr.trim()
            ),
        ));
    }
    crate::helper::parse_fs_reply(&output.stdout)
}

/// An io error with the path it happened on in its message.
fn at(path: &Path) -> impl Fn(std::io::Error) -> Error + '_ {
    move |err| {
        let err = Error::from(err);
        Error::new(err.kind, format!("{}: {}", path.display(), err.message))
    }
}

fn stat(path: &Path) -> Result<FsStat> {
    let meta = std::fs::metadata(path).map_err(at(path))?;
    let modified_ms = match meta
        .modified()
        .map_err(at(path))?
        .duration_since(UNIX_EPOCH)
    {
        Ok(after) => after.as_millis() as i64,
        Err(before) => -(before.duration().as_millis() as i64),
    };
    Ok(FsStat {
        kind: kind_of(meta.file_type()),
        size: meta.len(),
        modified_ms,
        readonly: meta.permissions().readonly(),
    })
}

fn kind_of(file_type: std::fs::FileType) -> FileKind {
    if file_type.is_symlink() {
        FileKind::Symlink
    } else if file_type.is_dir() {
        FileKind::Directory
    } else if file_type.is_file() {
        FileKind::File
    } else {
        FileKind::Other
    }
}

fn list(path: &Path) -> Result<FsListResult> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(path).map_err(at(path))? {
        let entry = entry.map_err(at(path))?;
        if entries.len() == MAX_LIST_ENTRIES {
            return Err(Error::too_large(format!(
                "{} has more than {MAX_LIST_ENTRIES} entries",
                path.display()
            )));
        }
        // `DirEntry::metadata` does not follow symlinks. An entry removed since `read_dir`
        // saw it is left out.
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        entries.push(DirEntry {
            name: entry.file_name().to_string_lossy().into_owned(),
            kind: kind_of(meta.file_type()),
            size: meta.len(),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(FsListResult { entries })
}

fn read(params: &FsReadParams) -> Result<FsReadResult> {
    let path = params.path.as_path();
    let max = MAX_FS_DATA_BYTES as u64;
    if let Some(length) = params.length
        && length > max
    {
        return Err(Error::too_large(format!(
            "length {length} is more than {max} bytes"
        )));
    }
    let mut file = match &params.beneath {
        Some(root) => open_beneath(root.as_path(), path)?,
        None => File::open(path).map_err(at(path))?,
    };
    let meta = file.metadata().map_err(at(path))?;
    let id = file_id(&file, &meta).map_err(at(path))?;
    if params.file.as_ref().is_some_and(|want| *want != id) {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("{} is no longer the file read before", path.display()),
        ));
    }
    let size = meta.len();
    file.seek(SeekFrom::Start(params.offset))
        .map_err(at(path))?;
    // Without a length, read to the end, but one byte past the cap shows the rest is too long.
    // Files such as /proc's report size 0, so the size cannot decide that.
    let limit = params.length.unwrap_or(max + 1);
    let mut data = Vec::new();
    file.take(limit).read_to_end(&mut data).map_err(at(path))?;
    if data.len() as u64 > max {
        return Err(Error::too_large(format!(
            "{} has more than {max} bytes after offset {}; pass a length",
            path.display(),
            params.offset
        )));
    }
    Ok(FsReadResult {
        data: Bytes::new(data),
        size,
        file: Some(id),
    })
}

/// Opens the regular file `path` names beneath `root`, through no symlink below `root`. What
/// is read is what the name led to as it was opened, however the tree changes afterwards.
fn open_beneath(root: &Path, path: &Path) -> Result<File> {
    let relative = path.strip_prefix(root).map_err(|_| {
        Error::invalid_params(format!(
            "{} is not beneath {}",
            path.display(),
            root.display()
        ))
    })?;
    let mut names = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => names.push(name),
            Component::CurDir => {}
            _ => {
                return Err(Error::invalid_params(format!(
                    "{} has `..` beneath {}",
                    path.display(),
                    root.display()
                )));
            }
        }
    }
    let file = open_names(root, &names, path)?;
    if !file.metadata().map_err(at(path))?.is_file() {
        return Err(Error::invalid_params(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(file)
}

fn through_a_symlink(path: &Path) -> Error {
    Error::new(
        ErrorKind::PermissionDenied,
        format!("{} is or passes through a symbolic link", path.display()),
    )
}

/// Opens `root`, then each of `names` inside the directory before it, never following a
/// symlink. Without `..` this confines the walk as `openat2`'s `RESOLVE_BENEATH |
/// RESOLVE_NO_SYMLINKS` would, on every Unix and kernel.
#[cfg(unix)]
fn open_names(root: &Path, names: &[&std::ffi::OsStr], path: &Path) -> Result<File> {
    use nix::fcntl::{AtFlags, OFlag, openat};
    use nix::sys::stat::{Mode, SFlag, fstatat};
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut fd: OwnedFd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(root)
        .map_err(at(path))?
        .into();
    for (i, name) in names.iter().enumerate() {
        let shape = if i + 1 == names.len() {
            // A FIFO opens at once instead of waiting for a writer, and is then refused.
            OFlag::O_NONBLOCK | OFlag::O_NOCTTY
        } else {
            OFlag::O_DIRECTORY
        };
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | shape;
        fd = match openat(&fd, *name, flags, Mode::empty()) {
            Ok(next) => next,
            Err(errno) => {
                // Systems differ in what a symlink fails with (ELOOP, EMLINK, ENOTDIR).
                let is_link = fstatat(&fd, *name, AtFlags::AT_SYMLINK_NOFOLLOW).is_ok_and(|st| {
                    SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT == SFlag::S_IFLNK
                });
                return Err(match errno {
                    _ if is_link => through_a_symlink(path),
                    nix::errno::Errno::ENOTDIR => Error::new(
                        ErrorKind::NotFound,
                        format!("{}: {}", path.display(), errno.desc()),
                    ),
                    _ => at(path)(errno.into()),
                });
            }
        };
    }
    Ok(File::from(fd))
}

/// Windows has no `openat`, so the file is opened by its whole path, not followed if it is a
/// link itself, and then its handle's real path must be exactly `root`'s real path and
/// `names`: a link or junction anywhere on the way makes them differ.
#[cfg(windows)]
fn open_names(root: &Path, names: &[&std::ffi::OsStr], path: &Path) -> Result<File> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    // Backup semantics opens a directory too, which is then refused as not a regular file.
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)
        .map_err(at(path))?;
    let mut expected = final_path(&root).map_err(at(path))?;
    for name in names {
        expected.push('\\');
        expected.push_str(&name.to_string_lossy());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(at(path))?;
    let attributes = file.metadata().map_err(at(path))?.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || final_path(&file).map_err(at(path))?.to_lowercase() != expected.to_lowercase()
    {
        return Err(through_a_symlink(path));
    }
    Ok(file)
}

/// The path an open handle really has, with every link on the way resolved.
#[cfg(windows)]
fn final_path(file: &File) -> std::io::Result<String> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW,
    };

    let mut buffer = vec![0u16; 512];
    loop {
        // SAFETY: the handle is open for the call, and the buffer holds `buffer.len()` UTF-16
        // units.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED,
            )
        } as usize;
        if len == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if len < buffer.len() {
            return Ok(String::from_utf16_lossy(&buffer[..len]));
        }
        // Too small: `len` is the size needed, with the terminating NUL.
        buffer.resize(len, 0);
    }
}

/// Which file `file` is and the state it is in: two reads that report the same ID read the
/// same file, unchanged in size and times.
#[cfg(unix)]
fn file_id(_file: &File, meta: &std::fs::Metadata) -> std::io::Result<FileId> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(FileId(format!(
        "{:x}:{:x}:{:x}:{}.{}:{}.{}",
        meta.dev(),
        meta.ino(),
        meta.size(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec()
    )))
}

#[cfg(windows)]
fn file_id(file: &File, _meta: &std::fs::Metadata) -> std::io::Result<FileId> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    // SAFETY: all-zero is a valid BY_HANDLE_FILE_INFORMATION, a plain C struct.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open for the call, and `info` is a writable struct of the type
    // the call fills.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let time = |t: windows_sys::Win32::Foundation::FILETIME| {
        (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
    };
    Ok(FileId(format!(
        "{:x}:{:x}{:08x}:{:x}{:08x}:{}:{}",
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
        info.nFileSizeHigh,
        info.nFileSizeLow,
        time(info.ftLastWriteTime),
        time(info.ftCreationTime)
    )))
}

fn write(params: &FsWriteParams) -> Result<()> {
    let path = params.path.as_path();
    let data = params.data.as_slice();
    if data.len() > MAX_FS_DATA_BYTES {
        return Err(Error::too_large(format!(
            "{} bytes is more than {MAX_FS_DATA_BYTES}",
            data.len()
        )));
    }
    match params.mode {
        WriteMode::Create => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(at(path))?;
            file.write_all(data).map_err(at(path))
        }
        WriteMode::Append => {
            let mut file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .map_err(at(path))?;
            file.write_all(data).map_err(at(path))
        }
        WriteMode::Overwrite => overwrite(path, data),
    }
}

/// Writes a temp file beside the target and renames it over, keeping the target's
/// permissions. When the directory refuses the temp file but the target itself is writable
/// (a policy that grants only the file), it truncates and writes the target in place.
fn overwrite(path: &Path, data: &[u8]) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => Some(meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(at(path)(err)),
    };
    let target = match meta {
        Some(meta) if meta.is_symlink() => match std::fs::canonicalize(path) {
            Ok(target) => target,
            // A dangling link: `open` creates its target, as a plain overwrite would.
            Err(_) => return in_place(path, data),
        },
        _ => path.to_path_buf(),
    };
    // Opening the target for writing first refuses what an in-place write would refuse: a
    // read-only file, or a directory.
    let existing = match OpenOptions::new().write(true).open(&target) {
        Ok(file) => Some(file),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(at(path)(err)),
    };
    let (temp_path, mut temp) = match create_temp_beside(&target) {
        Ok(temp) => temp,
        // bubblewrap denies writing with a read-only mount: EROFS.
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
            ) && existing.is_some() =>
        {
            let mut file = existing.expect("checked above");
            file.set_len(0).map_err(at(path))?;
            return file.write_all(data).map_err(at(path));
        }
        Err(err) => return Err(at(path)(err)),
    };
    let result = (|| {
        temp.write_all(data)?;
        if let Some(file) = existing {
            temp.set_permissions(file.metadata()?.permissions())?;
        }
        drop(temp);
        std::fs::rename(&temp_path, &target)
    })();
    if let Err(err) = result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(at(path)(err));
    }
    Ok(())
}

fn in_place(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(at(path))?;
    file.write_all(data).map_err(at(path))
}

fn create_temp_beside(target: &Path) -> std::io::Result<(PathBuf, File)> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = target.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the path has no file name",
        )
    })?;
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(
        ".happy-{}-{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let temp_path = target.with_file_name(temp_name);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    Ok((temp_path, file))
}

fn mkdir(params: &FsMkdirParams) -> Result<()> {
    let path = params.path.as_path();
    if params.recursive {
        std::fs::create_dir_all(path).map_err(at(path))
    } else {
        std::fs::create_dir(path).map_err(at(path))
    }
}

fn remove(params: &FsRemoveParams) -> Result<()> {
    let path = params.path.as_path();
    let file_type = std::fs::symlink_metadata(path)
        .map_err(at(path))?
        .file_type();
    if file_type.is_dir() {
        // `remove_dir_all` removes symlinks inside the tree without following them.
        if params.recursive {
            std::fs::remove_dir_all(path).map_err(at(path))
        } else {
            std::fs::remove_dir(path).map_err(at(path))
        }
    } else {
        remove_link_or_file(path, file_type).map_err(at(path))
    }
}

fn rename(params: &FsRenameParams) -> Result<()> {
    let (from, to) = (params.from.as_path(), params.to.as_path());
    std::fs::rename(from, to).map_err(|err| {
        let err = Error::from(err);
        Error::new(
            err.kind,
            format!("{} -> {}: {}", from.display(), to.display(), err.message),
        )
    })
}

#[cfg(windows)]
fn remove_link_or_file(path: &Path, file_type: std::fs::FileType) -> std::io::Result<()> {
    use std::os::windows::fs::FileTypeExt as _;
    if file_type.is_symlink_dir() {
        std::fs::remove_dir(path)
    } else {
        std::fs::remove_file(path)
    }
}

#[cfg(not(windows))]
fn remove_link_or_file(path: &Path, _file_type: std::fs::FileType) -> std::io::Result<()> {
    std::fs::remove_file(path)
}
