//! `fs.*` with raw access, through `fs::perform` and `fs::handle` as dispatch calls them. Tests
//! that assert OS error messages or Unix permissions run on Unix only.
// The helpers serve the Unix-only tests too.
#![cfg_attr(windows, allow(dead_code, unused_imports))]

use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use happy_supervisor::fs::{self, FsRequest, FsResponse};
use happy_supervisor::policy::Confinement;
use happy_supervisor::protocol::{
    AbsPath, Bytes, DirEntry, FileId, FileKind, FsListResult, FsMkdirParams, FsPathParams,
    FsReadParams, FsReadResult, FsRemoveParams, FsRenameParams, FsStat, FsWriteParams, WriteMode,
};
use happy_supervisor::{Error, ErrorKind};

const MIB: usize = 1 << 20;

/// A canonical temp dir, so paths in messages match what the OS reports (macOS `/var` is
/// `/private/var`).
fn tempdir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    (tmp, root)
}

fn abs(path: &Path) -> AbsPath {
    AbsPath::try_from(path.to_str().unwrap()).unwrap()
}

fn stat(path: &Path) -> Result<FsStat, Error> {
    match fs::perform(&FsRequest::Stat(FsPathParams { path: abs(path) }))? {
        FsResponse::Stat(stat) => Ok(stat),
        other => panic!("stat answered {other:?}"),
    }
}

fn list(path: &Path) -> Result<Vec<DirEntry>, Error> {
    match fs::perform(&FsRequest::List(FsPathParams { path: abs(path) }))? {
        FsResponse::List(FsListResult { entries }) => Ok(entries),
        other => panic!("list answered {other:?}"),
    }
}

fn read(path: &Path, offset: u64, length: Option<u64>) -> Result<(Vec<u8>, u64), Error> {
    let request = FsRequest::Read(FsReadParams {
        path: abs(path),
        offset,
        length,
        beneath: None,
        file: None,
    });
    match fs::perform(&request)? {
        FsResponse::Read(FsReadResult { data, size, .. }) => Ok((data.into_vec(), size)),
        other => panic!("read answered {other:?}"),
    }
}

fn write(path: &Path, data: &[u8], mode: WriteMode) -> Result<FsResponse, Error> {
    fs::perform(&FsRequest::Write(FsWriteParams {
        path: abs(path),
        data: Bytes::new(data.to_vec()),
        mode,
    }))
}

fn mkdir(path: &Path, recursive: bool) -> Result<FsResponse, Error> {
    fs::perform(&FsRequest::Mkdir(FsMkdirParams {
        path: abs(path),
        recursive,
    }))
}

fn remove(path: &Path, recursive: bool) -> Result<FsResponse, Error> {
    fs::perform(&FsRequest::Remove(FsRemoveParams {
        path: abs(path),
        recursive,
    }))
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[cfg(unix)]
fn not_found(path: &Path) -> Error {
    Error::new(
        ErrorKind::NotFound,
        format!("{}: No such file or directory (os error 2)", path.display()),
    )
}

#[cfg(unix)]
fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
#[test]
fn stat_reports_kind_size_mtime_and_readonly() {
    let (_tmp, root) = tempdir();
    let file = root.join("a.txt");
    std::fs::write(&file, b"hello").unwrap();
    let mtime = UNIX_EPOCH + Duration::from_millis(1_763_496_000_123);
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(mtime)
        .unwrap();

    assert_eq!(
        stat(&file),
        Ok(FsStat {
            kind: FileKind::File,
            size: 5,
            modified_ms: 1_763_496_000_123,
            readonly: false,
        })
    );

    let mut readonly = std::fs::metadata(&file).unwrap().permissions();
    readonly.set_readonly(true);
    std::fs::set_permissions(&file, readonly).unwrap();
    assert!(stat(&file).unwrap().readonly);

    assert_eq!(stat(&root).unwrap().kind, FileKind::Directory);
    assert_eq!(stat(&root.join("nope")), Err(not_found(&root.join("nope"))));
}

#[cfg(unix)]
#[test]
fn stat_follows_symlinks() {
    let (_tmp, root) = tempdir();
    std::fs::write(root.join("target"), b"1234567").unwrap();
    std::os::unix::fs::symlink("target", root.join("link")).unwrap();
    std::os::unix::fs::symlink("missing", root.join("dangling")).unwrap();

    let linked = stat(&root.join("link")).unwrap();
    assert_eq!((linked.kind, linked.size), (FileKind::File, 7));
    assert_eq!(
        stat(&root.join("dangling")).unwrap_err().kind,
        ErrorKind::NotFound
    );
}

#[cfg(unix)]
#[test]
fn list_is_sorted_and_does_not_follow_symlinks() {
    let (_tmp, root) = tempdir();
    std::fs::write(root.join("b.txt"), b"abc").unwrap();
    std::fs::create_dir(root.join("a")).unwrap();
    std::os::unix::fs::symlink("b.txt", root.join("c")).unwrap();
    std::os::unix::fs::symlink("a", root.join("D")).unwrap();

    let entries = list(&root).unwrap();
    let shape: Vec<(&str, FileKind)> = entries.iter().map(|e| (&e.name[..], e.kind)).collect();
    assert_eq!(
        shape,
        [
            ("D", FileKind::Symlink),
            ("a", FileKind::Directory),
            ("b.txt", FileKind::File),
            ("c", FileKind::Symlink),
        ]
    );
    // A symlink's size is its target's length.
    assert_eq!(
        (entries[0].size, entries[2].size, entries[3].size),
        (1, 3, 5)
    );

    assert_eq!(list(&root.join("a")), Ok(vec![]));
    assert_eq!(list(&root.join("nope")), Err(not_found(&root.join("nope"))));
    assert_eq!(list(&root.join("b.txt")).unwrap_err().kind, ErrorKind::Io);
}

#[test]
fn list_refuses_more_than_10_000_entries() {
    let (_tmp, root) = tempdir();
    for i in 0..10_000 {
        std::fs::write(root.join(format!("f{i:05}")), b"").unwrap();
    }
    let entries = list(&root).unwrap();
    assert_eq!(entries.len(), 10_000);
    assert_eq!(entries[0].name, "f00000");
    assert_eq!(entries[9_999].name, "f09999");

    std::fs::write(root.join("one-more"), b"").unwrap();
    assert_eq!(
        list(&root),
        Err(Error::too_large(format!(
            "{} has more than 10000 entries",
            root.display()
        )))
    );
}

#[cfg(unix)]
#[test]
fn read_slices_and_reports_the_whole_size() {
    let (_tmp, root) = tempdir();
    let file = root.join("f");
    std::fs::write(&file, b"0123456789").unwrap();

    assert_eq!(read(&file, 0, None), Ok((b"0123456789".to_vec(), 10)));
    assert_eq!(read(&file, 3, Some(4)), Ok((b"3456".to_vec(), 10)));
    assert_eq!(read(&file, 7, None), Ok((b"789".to_vec(), 10)));
    assert_eq!(read(&file, 8, Some(100)), Ok((b"89".to_vec(), 10)));
    assert_eq!(read(&file, 50, None), Ok((vec![], 10)));
    assert_eq!(read(&file, 0, Some(0)), Ok((vec![], 10)));
    assert_eq!(
        read(&root.join("nope"), 0, None),
        Err(not_found(&root.join("nope")))
    );
}

#[test]
fn read_is_capped_at_16_mib_per_call() {
    let (_tmp, root) = tempdir();
    let file = root.join("big");
    std::fs::File::create(&file)
        .unwrap()
        .set_len(16 * MIB as u64 + 1)
        .unwrap();

    assert_eq!(
        read(&file, 0, Some(16 * MIB as u64 + 1)),
        Err(Error::too_large(
            "length 16777217 is more than 16777216 bytes"
        ))
    );
    assert_eq!(
        read(&file, 0, None),
        Err(Error::too_large(format!(
            "{} has more than 16777216 bytes after offset 0; pass a length",
            file.display()
        )))
    );
    let (data, size) = read(&file, 1, None).unwrap();
    assert_eq!((data.len(), size), (16 * MIB, 16 * MIB as u64 + 1));
    let (data, _) = read(&file, 0, Some(16 * MIB as u64)).unwrap();
    assert_eq!(data.len(), 16 * MIB);
}

#[cfg(target_os = "linux")]
#[test]
fn read_without_length_reads_files_that_report_size_zero() {
    let (data, size) = read(Path::new("/proc/self/status"), 0, None).unwrap();
    assert_eq!(size, 0);
    assert!(
        data.starts_with(b"Name:"),
        "{:?}",
        String::from_utf8_lossy(&data)
    );
}

#[cfg(unix)]
#[test]
fn write_create_refuses_an_existing_path() {
    let (_tmp, root) = tempdir();
    let file = root.join("new.txt");
    assert_eq!(
        write(&file, b"first", WriteMode::Create),
        Ok(FsResponse::Done)
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"first");

    let err = write(&file, b"second", WriteMode::Create).unwrap_err();
    assert_eq!(
        err,
        Error::new(
            ErrorKind::AlreadyExists,
            format!("{}: File exists (os error 17)", file.display())
        )
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"first");
}

#[test]
fn write_append_creates_then_appends() {
    let (_tmp, root) = tempdir();
    let file = root.join("log");
    write(&file, b"one\n", WriteMode::Append).unwrap();
    write(&file, b"two\n", WriteMode::Append).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"one\ntwo\n");
}

#[test]
fn write_overwrite_replaces_and_leaves_no_temp_file() {
    let (_tmp, root) = tempdir();
    let file = root.join("f.txt");
    write(&file, b"a long first version", WriteMode::Overwrite).unwrap();
    write(&file, b"short", WriteMode::Overwrite).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"short");
    assert_eq!(names(&root), ["f.txt"]);

    write(&file, b"", WriteMode::Overwrite).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"");
}

#[cfg(unix)]
#[test]
fn write_overwrite_keeps_the_targets_permissions() {
    let (_tmp, root) = tempdir();
    let file = root.join("script.sh");
    std::fs::write(&file, b"old").unwrap();
    set_mode(&file, 0o751);
    write(&file, b"new", WriteMode::Overwrite).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"new");
    assert_eq!(mode(&file), 0o751);
}

#[cfg(unix)]
#[test]
fn write_overwrite_through_a_symlink_replaces_the_target() {
    let (_tmp, root) = tempdir();
    std::fs::create_dir(root.join("real")).unwrap();
    std::fs::write(root.join("real/f"), b"old").unwrap();
    std::os::unix::fs::symlink("real/f", root.join("link")).unwrap();

    write(&root.join("link"), b"new", WriteMode::Overwrite).unwrap();
    assert_eq!(std::fs::read(root.join("real/f")).unwrap(), b"new");
    assert!(
        std::fs::symlink_metadata(root.join("link"))
            .unwrap()
            .is_symlink()
    );
    assert_eq!(names(&root.join("real")), ["f"]);
}

#[cfg(unix)]
#[test]
fn write_overwrite_falls_back_to_in_place_when_the_directory_is_not_writable() {
    use std::os::unix::fs::MetadataExt as _;
    if is_root() {
        eprintln!("skipped: root ignores directory permissions");
        return;
    }
    let (_tmp, root) = tempdir();
    let dir = root.join("locked");
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"old contents").unwrap();
    let inode = std::fs::metadata(&file).unwrap().ino();
    set_mode(&dir, 0o555);

    let result = write(&file, b"new", WriteMode::Overwrite);
    let missing = write(&dir.join("g"), b"x", WriteMode::Overwrite);
    set_mode(&dir, 0o755);

    assert_eq!(result, Ok(FsResponse::Done));
    assert_eq!(std::fs::read(&file).unwrap(), b"new");
    assert_eq!(std::fs::metadata(&file).unwrap().ino(), inode);
    assert_eq!(missing.unwrap_err().kind, ErrorKind::PermissionDenied);
    assert_eq!(names(&dir), ["f"]);
}

#[cfg(unix)]
#[test]
fn write_overwrite_refuses_a_read_only_file() {
    if is_root() {
        eprintln!("skipped: root may write read-only files");
        return;
    }
    let (_tmp, root) = tempdir();
    let file = root.join("ro");
    std::fs::write(&file, b"keep").unwrap();
    set_mode(&file, 0o444);
    let err = write(&file, b"new", WriteMode::Overwrite).unwrap_err();
    assert_eq!(err.kind, ErrorKind::PermissionDenied);
    assert_eq!(std::fs::read(&file).unwrap(), b"keep");
    assert_eq!(names(&root), ["ro"]);
}

#[test]
fn write_never_creates_the_parent() {
    let (_tmp, root) = tempdir();
    let file = root.join("missing/f");
    for mode in [WriteMode::Create, WriteMode::Overwrite, WriteMode::Append] {
        let err = write(&file, b"x", mode).unwrap_err();
        assert_eq!(err.kind, ErrorKind::NotFound, "{mode:?}: {err}");
    }
    assert_eq!(names(&root), [] as [&str; 0]);
}

#[cfg(unix)]
#[test]
fn write_refuses_a_directory_and_more_than_16_mib() {
    let (_tmp, root) = tempdir();
    let err = write(&root, b"x", WriteMode::Overwrite).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Io, "{err}");

    let big = vec![0u8; 16 * MIB + 1];
    assert_eq!(
        write(&root.join("big"), &big, WriteMode::Create),
        Err(Error::too_large("16777217 bytes is more than 16777216"))
    );
    assert_eq!(names(&root), [] as [&str; 0]);
    write(&root.join("max"), &big[1..], WriteMode::Create).unwrap();
    assert_eq!(std::fs::metadata(root.join("max")).unwrap().len(), 16 << 20);
}

#[cfg(unix)]
#[test]
fn mkdir_plain_and_recursive() {
    let (_tmp, root) = tempdir();
    let dir = root.join("d");
    assert_eq!(mkdir(&dir, false), Ok(FsResponse::Done));
    assert!(dir.is_dir());
    assert_eq!(
        mkdir(&dir, false).unwrap_err().kind,
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        mkdir(&root.join("x/y"), false),
        Err(not_found(&root.join("x/y")))
    );

    let deep = root.join("a/b/c");
    assert_eq!(mkdir(&deep, true), Ok(FsResponse::Done));
    assert!(deep.is_dir());
    assert_eq!(mkdir(&deep, true), Ok(FsResponse::Done));

    std::fs::write(root.join("file"), b"").unwrap();
    assert_eq!(
        mkdir(&root.join("file"), true).unwrap_err().kind,
        ErrorKind::AlreadyExists
    );
}

#[cfg(unix)]
#[test]
fn remove_file_and_empty_directory() {
    let (_tmp, root) = tempdir();
    std::fs::write(root.join("f"), b"").unwrap();
    std::fs::create_dir(root.join("empty")).unwrap();
    std::fs::create_dir(root.join("full")).unwrap();
    std::fs::write(root.join("full/x"), b"").unwrap();

    assert_eq!(remove(&root.join("f"), false), Ok(FsResponse::Done));
    assert_eq!(remove(&root.join("empty"), false), Ok(FsResponse::Done));
    let err = remove(&root.join("full"), false).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Io);
    assert!(
        err.message.starts_with(&format!(
            "{}: Directory not empty",
            root.join("full").display()
        )),
        "{err}"
    );
    assert_eq!(names(&root), ["full"]);
    assert_eq!(
        remove(&root.join("f"), false),
        Err(not_found(&root.join("f")))
    );
}

#[cfg(unix)]
#[test]
fn remove_symlink_removes_the_link_only() {
    let (_tmp, root) = tempdir();
    std::fs::create_dir(root.join("dir")).unwrap();
    std::fs::write(root.join("dir/keep"), b"").unwrap();
    std::os::unix::fs::symlink("dir", root.join("link")).unwrap();

    assert_eq!(remove(&root.join("link"), true), Ok(FsResponse::Done));
    assert_eq!(names(&root), ["dir"]);
    assert_eq!(names(&root.join("dir")), ["keep"]);
}

#[cfg(unix)]
#[test]
fn remove_recursive_does_not_follow_symlinks_out_of_the_tree() {
    let (_tmp, root) = tempdir();
    let outside = root.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("precious"), b"keep me").unwrap();
    let tree = root.join("tree");
    std::fs::create_dir_all(tree.join("sub/deeper")).unwrap();
    std::fs::write(tree.join("sub/deeper/f"), b"").unwrap();
    std::os::unix::fs::symlink(&outside, tree.join("sub/escape")).unwrap();
    std::os::unix::fs::symlink(outside.join("precious"), tree.join("file-link")).unwrap();

    assert_eq!(remove(&tree, true), Ok(FsResponse::Done));
    assert_eq!(names(&root), ["outside"]);
    assert_eq!(std::fs::read(outside.join("precious")).unwrap(), b"keep me");
}

#[tokio::test]
async fn handle_runs_raw_requests() {
    let (_tmp, root) = tempdir();
    let file = root.join("f");
    let write = FsRequest::Write(FsWriteParams {
        path: abs(&file),
        data: Bytes::new(b"via handle".to_vec()),
        mode: WriteMode::Create,
    });
    assert_eq!(
        fs::handle(write, Confinement::Raw).await,
        Ok(FsResponse::Done)
    );
    let read = FsRequest::Read(FsReadParams {
        path: abs(&file),
        offset: 4,
        length: None,
        beneath: None,
        file: None,
    });
    match fs::handle(read, Confinement::Raw).await {
        Ok(FsResponse::Read(FsReadResult { data, size, .. })) => {
            assert_eq!((data.into_vec(), size), (b"handle".to_vec(), 10))
        }
        other => panic!("read answered {other:?}"),
    }
}

fn rename(from: &Path, to: &Path) -> Result<FsResponse, Error> {
    fs::perform(&FsRequest::Rename(FsRenameParams {
        from: abs(from),
        to: abs(to),
    }))
}

#[test]
fn rename_moves_and_replaces_a_file() {
    let (_tmp, root) = tempdir();
    std::fs::write(root.join("a"), b"new").unwrap();
    std::fs::write(root.join("b"), b"old").unwrap();
    std::fs::create_dir(root.join("dir")).unwrap();

    assert_eq!(
        rename(&root.join("a"), &root.join("b")),
        Ok(FsResponse::Done)
    );
    assert_eq!(std::fs::read(root.join("b")).unwrap(), b"new");
    assert!(!root.join("a").exists());
    assert_eq!(
        rename(&root.join("dir"), &root.join("moved")),
        Ok(FsResponse::Done)
    );
    assert!(root.join("moved").is_dir());

    let err = rename(&root.join("a"), &root.join("c")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::NotFound);
    assert!(
        err.message.starts_with(&format!(
            "{} -> {}: ",
            root.join("a").display(),
            root.join("c").display()
        )),
        "{}",
        err.message
    );
}

// `fs.read` with `root` and `file`: the control plane's check of a path and its read are
// separate calls, and what runs on the node can swap the path between them.

/// `ws/src/notes.txt` (9 bytes) inside the workspace, `secret` (7 bytes) and `outside/secret`
/// beside it.
fn workspace() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let (tmp, base) = tempdir();
    let ws = base.join("ws");
    std::fs::create_dir_all(ws.join("src")).unwrap();
    std::fs::create_dir(base.join("outside")).unwrap();
    std::fs::write(ws.join("src/notes.txt"), b"workspace").unwrap();
    std::fs::write(base.join("secret"), b"hunter2").unwrap();
    std::fs::write(base.join("outside/secret"), b"hunter2").unwrap();
    (tmp, base, ws)
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

// The Windows runner is an administrator, who may create symlinks.
#[cfg(windows)]
fn symlink(target: &Path, link: &Path) {
    if target.is_dir() {
        std::os::windows::fs::symlink_dir(target, link).unwrap();
    } else {
        std::os::windows::fs::symlink_file(target, link).unwrap();
    }
}

fn read_in(
    root: &Path,
    path: &Path,
    offset: u64,
    length: Option<u64>,
    file: Option<FileId>,
) -> Result<FsReadResult, Error> {
    let request = FsRequest::Read(FsReadParams {
        path: abs(path),
        offset,
        length,
        beneath: Some(abs(root)),
        file,
    });
    match fs::perform(&request)? {
        FsResponse::Read(read) => Ok(read),
        other => panic!("read answered {other:?}"),
    }
}

fn through_a_symlink(path: &Path) -> Error {
    Error::new(
        ErrorKind::PermissionDenied,
        format!("{} is or passes through a symbolic link", path.display()),
    )
}

#[tokio::test]
async fn read_beneath_root_refuses_a_file_swapped_for_a_symlink_after_the_check() {
    let (_tmp, base, ws) = workspace();
    let notes = ws.join("src/notes.txt");
    // The check the control plane makes first: no component is a symlink.
    let mut at = ws.clone();
    for part in ["src", "notes.txt"] {
        let entry = list(&at)
            .unwrap()
            .into_iter()
            .find(|e| e.name == part)
            .unwrap();
        assert_eq!(
            entry.kind,
            if part == "src" {
                FileKind::Directory
            } else {
                FileKind::File
            }
        );
        at = at.join(part);
    }
    std::fs::remove_file(&notes).unwrap();
    symlink(&base.join("secret"), &notes);

    assert_eq!(read(&notes, 0, None).unwrap().0, b"hunter2");
    assert_eq!(
        read_in(&ws, &notes, 0, None, None),
        Err(through_a_symlink(&notes))
    );
}

#[test]
fn read_beneath_root_refuses_a_symlink_in_a_middle_component() {
    let (_tmp, base, ws) = workspace();
    symlink(&base.join("outside"), &ws.join("link"));
    let secret = ws.join("link/secret");
    assert_eq!(read(&secret, 0, None).unwrap().0, b"hunter2");
    assert_eq!(
        read_in(&ws, &secret, 0, None, None),
        Err(through_a_symlink(&secret))
    );
}

#[test]
fn read_beneath_root_refuses_dot_dot_and_paths_outside_it() {
    let (_tmp, base, ws) = workspace();
    // Joined as text: `PathBuf::push` drops `..` from a Windows verbatim (`\\?\`) path.
    let sep = std::path::MAIN_SEPARATOR;
    let up = PathBuf::from(format!("{}{sep}src{sep}..{sep}..{sep}secret", ws.display()));
    assert_eq!(
        read_in(&ws, &up, 0, None, None),
        Err(Error::invalid_params(format!(
            "{} has `..` beneath {}",
            up.display(),
            ws.display()
        )))
    );
    let outside = base.join("secret");
    assert_eq!(
        read_in(&ws, &outside, 0, None, None),
        Err(Error::invalid_params(format!(
            "{} is not beneath {}",
            outside.display(),
            ws.display()
        )))
    );
}

#[test]
fn read_beneath_root_reads_regular_files_only() {
    let (_tmp, _base, ws) = workspace();
    let notes = ws.join("src/notes.txt");
    let read = read_in(&ws, &notes, 4, Some(3), None).unwrap();
    assert_eq!((read.data.into_vec(), read.size), (b"spa".to_vec(), 9));
    assert!(read.file.is_some());
    for path in [&ws, &ws.join("src")] {
        assert_eq!(
            read_in(&ws, path, 0, None, None),
            Err(Error::invalid_params(format!(
                "{} is not a regular file",
                path.display()
            )))
        );
    }
    for missing in [ws.join("src/gone"), ws.join("src/notes.txt/inside")] {
        assert_eq!(
            read_in(&ws, &missing, 0, None, None).map_err(|e| e.kind),
            Err(ErrorKind::NotFound),
            "{}",
            missing.display()
        );
    }
}

#[cfg(unix)]
#[test]
fn read_beneath_root_refuses_a_fifo_without_waiting_for_a_writer() {
    let (_tmp, _base, ws) = workspace();
    let fifo = ws.join("fifo");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
    assert_eq!(
        read_in(&ws, &fifo, 0, None, None),
        Err(Error::invalid_params(format!(
            "{} is not a regular file",
            fifo.display()
        )))
    );
}

#[test]
fn ranged_read_with_file_refuses_a_same_size_swap() {
    let (_tmp, base, ws) = workspace();
    let notes = ws.join("src/notes.txt");
    let first = read_in(&ws, &notes, 0, Some(4), None).unwrap();
    assert_eq!(first.data.into_vec(), b"work");
    let file = first.file.unwrap();
    let again = read_in(&ws, &notes, 4, None, Some(file.clone())).unwrap();
    assert_eq!(
        (again.data.into_vec(), again.file),
        (b"space".to_vec(), Some(file.clone()))
    );

    // Same size, swapped in by rename between two ranges.
    std::fs::write(base.join("swap"), b"SECRET!!!").unwrap();
    std::fs::rename(base.join("swap"), &notes).unwrap();
    assert_eq!(
        read_in(&ws, &notes, 4, None, None).unwrap().data.into_vec(),
        b"ET!!!"
    );
    assert_eq!(
        read_in(&ws, &notes, 4, None, Some(file)),
        Err(Error::new(
            ErrorKind::NotFound,
            format!("{} is no longer the file read before", notes.display())
        ))
    );
}

#[cfg(unix)]
#[test]
fn ranged_read_with_file_refuses_a_rewrite_in_place_with_the_old_mtime() {
    let (_tmp, _base, ws) = workspace();
    let notes = ws.join("src/notes.txt");
    let file = read_in(&ws, &notes, 0, Some(4), None)
        .unwrap()
        .file
        .unwrap();
    let modified = std::fs::metadata(&notes).unwrap().modified().unwrap();
    // Past the kernel's coarse clock tick, so the change time moves.
    std::thread::sleep(Duration::from_millis(20));
    let rewritten = std::fs::OpenOptions::new()
        .write(true)
        .open(&notes)
        .unwrap();
    std::io::Write::write_all(&mut &rewritten, b"WORKSPACE").unwrap();
    rewritten.set_modified(modified).unwrap();
    drop(rewritten);
    assert_eq!(
        std::fs::metadata(&notes).unwrap().modified().unwrap(),
        modified
    );
    assert_eq!(
        read_in(&ws, &notes, 4, None, Some(file)).map_err(|e| e.kind),
        Err(ErrorKind::NotFound)
    );
}

#[test]
fn read_without_root_checks_file_too() {
    let (_tmp, base, ws) = workspace();
    let notes = ws.join("src/notes.txt");
    let request = |file| {
        FsRequest::Read(FsReadParams {
            path: abs(&notes),
            offset: 0,
            length: None,
            beneath: None,
            file,
        })
    };
    let Ok(FsResponse::Read(FsReadResult {
        file: Some(file), ..
    })) = fs::perform(&request(None))
    else {
        panic!("read reports no file");
    };
    std::fs::rename(base.join("secret"), &notes).unwrap();
    assert_eq!(
        fs::perform(&request(Some(file))).map_err(|e| e.kind),
        Err(ErrorKind::NotFound)
    );
}
