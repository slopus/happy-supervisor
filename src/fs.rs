//! File operations (`fs.*`). Owned by the files track; the scaffold froze the types and
//! signatures.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind, Result};
use crate::helper::{Job, JobOp};
use crate::policy::{Confinement, ResolvedPolicy};
use crate::protocol::{
    Bytes, DirEntry, Empty, FileKind, FsListResult, FsMkdirParams, FsPathParams, FsReadParams,
    FsReadResult, FsRemoveParams, FsStat, FsWriteParams, MAX_FS_DATA_BYTES, MAX_LIST_ENTRIES,
    Value, WriteMode,
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FsResponse {
    Stat(FsStat),
    List(FsListResult),
    Read(FsReadResult),
    /// `{}`, the result of `fs.write`, `fs.mkdir` and `fs.remove`.
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
    }
}

/// Runs a file request under its confinement: raw in-process, sandboxed through the helper.
pub async fn handle(request: FsRequest, confinement: Confinement) -> Result<FsResponse> {
    match confinement {
        Confinement::Raw => tokio::task::spawn_blocking(move || perform(&request))
            .await
            .map_err(|err| Error::new(ErrorKind::Io, format!("file operation failed: {err}")))?,
        Confinement::Sandboxed(policy) => sandboxed(request, policy).await,
    }
}

async fn sandboxed(request: FsRequest, policy: ResolvedPolicy) -> Result<FsResponse> {
    // Landlock governs opening, not metadata, so the helper could stat any path.
    if let FsRequest::Stat(params) = &request {
        let path = params.path.as_path().to_path_buf();
        let policy = policy.clone();
        let readable = tokio::task::spawn_blocking(move || {
            policy.can_read(&crate::policy::resolve_path(&path))
        })
        .await
        .map_err(|err| Error::new(ErrorKind::Io, format!("policy check failed: {err}")))?;
        if !readable {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!("{}: not readable by the policy", params.path.as_str()),
            ));
        }
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
    };
    let prepared = crate::sandbox::prepare(&plan, &job)?;
    let mut command = tokio::process::Command::from(prepared.command);
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    // A helper that dies before reading its job closes the pipe; its output says why.
    let _ = tokio::io::AsyncWriteExt::write_all(&mut stdin, &crate::helper::encode_job(&job)).await;
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
    let mut file = File::open(path).map_err(at(path))?;
    let size = file.metadata().map_err(at(path))?.len();
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
    })
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
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied && existing.is_some() => {
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
