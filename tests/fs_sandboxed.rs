//! `fs.*` under a sandbox, through the helper binary.
#![cfg(unix)]

use std::path::{Path, PathBuf};

use happy_supervisor::fs::{self, FsRequest, FsResponse};
use happy_supervisor::policy::{Confinement, ResolvedPolicy, allow_list};
use happy_supervisor::protocol::{
    AbsPath, Bytes, DirEntry, FileKind, FsListResult, FsMkdirParams, FsPathParams, FsReadParams,
    FsReadResult, FsRemoveParams, FsWriteParams, WriteMode,
};
use happy_supervisor::{Error, ErrorKind, helper, sandbox};

/// A tree with `granted/` (read), `granted/out/` (write), `granted/.state/` (the hidden state
/// directory) and `secret/` (not granted).
struct Tree {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Tree {
    fn new() -> Tree {
        helper::set_exe(env!("CARGO_BIN_EXE_happy-supervisor").into());
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for dir in ["granted/out", "granted/.state", "secret"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("granted/readme"), b"public").unwrap();
        std::fs::write(root.join("granted/out/result"), b"old result").unwrap();
        std::fs::write(root.join("granted/.state/credentials.json"), b"{}").unwrap();
        std::fs::write(root.join("secret/key"), b"hunter2").unwrap();
        Tree { _tmp: tmp, root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// Reads `granted` (and the system paths the helper needs) and writes `write`.
    fn confinement(&self, write: &[&str]) -> Confinement {
        let mut read = sandbox::baseline_read();
        read.push(self.path("granted").to_str().unwrap().to_string());
        let write: Vec<String> = write
            .iter()
            .map(|rel| self.path(rel).to_str().unwrap().to_string())
            .collect();
        let policy = allow_list(read, write, false, false);
        Confinement::Sandboxed(
            ResolvedPolicy::resolve(&policy, &self.path("granted/.state")).unwrap(),
        )
    }
}

fn abs(path: &Path) -> AbsPath {
    AbsPath::try_from(path.to_str().unwrap()).unwrap()
}

/// Linux and macOS always enforce sandboxes, so a missing one fails the test.
fn require_sandbox() {
    // The probe runs the helper too; without this it runs the test harness instead.
    helper::set_exe(env!("CARGO_BIN_EXE_happy-supervisor").into());
    if let Err(err) = sandbox::probe().require_available() {
        panic!("this node cannot run sandboxed requests: {err}");
    }
}

async fn stat(tree: &Tree, rel: &str) -> Result<FsResponse, Error> {
    let request = FsRequest::Stat(FsPathParams {
        path: abs(&tree.path(rel)),
    });
    fs::handle(request, tree.confinement(&[])).await
}

async fn read(tree: &Tree, rel: &str) -> Result<Vec<u8>, Error> {
    let request = FsRequest::Read(FsReadParams {
        path: abs(&tree.path(rel)),
        offset: 0,
        length: None,
    });
    match fs::handle(request, tree.confinement(&[])).await? {
        FsResponse::Read(FsReadResult { data, .. }) => Ok(data.into_vec()),
        other => panic!("read answered {other:?}"),
    }
}

async fn write(tree: &Tree, rel: &str, grant: &[&str], data: &[u8]) -> Result<FsResponse, Error> {
    let request = FsRequest::Write(FsWriteParams {
        path: abs(&tree.path(rel)),
        data: Bytes::new(data.to_vec()),
        mode: WriteMode::Overwrite,
    });
    fs::handle(request, tree.confinement(grant)).await
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn stat_outside_the_policy_is_refused_before_the_helper_runs() {
    let tree = Tree::new();
    for rel in [
        "secret/key",
        "secret/missing",
        "granted/.state/credentials.json",
    ] {
        assert_eq!(
            stat(&tree, rel).await,
            Err(Error::new(
                ErrorKind::PermissionDenied,
                format!("{}: not readable by the policy", tree.path(rel).display())
            )),
            "{rel}"
        );
    }
}

#[tokio::test]
async fn stat_checks_where_a_symlink_really_points() {
    let tree = Tree::new();
    std::os::unix::fs::symlink(tree.path("secret/key"), tree.path("granted/sneaky")).unwrap();
    assert_eq!(
        stat(&tree, "granted/sneaky").await.unwrap_err().kind,
        ErrorKind::PermissionDenied
    );
}

#[tokio::test]
async fn sandboxed_reads_see_only_the_policy() {
    require_sandbox();
    let tree = Tree::new();
    assert_eq!(read(&tree, "granted/readme").await, Ok(b"public".to_vec()));
    assert_eq!(
        read(&tree, "secret/key").await.unwrap_err().kind,
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        read(&tree, "granted/.state/credentials.json")
            .await
            .unwrap_err()
            .kind,
        ErrorKind::PermissionDenied
    );
    let FsResponse::Stat(stat) = stat(&tree, "granted/readme").await.unwrap() else {
        panic!("stat answered something else");
    };
    assert_eq!((stat.kind, stat.size), (FileKind::File, 6));

    let secret = FsRequest::List(FsPathParams {
        path: abs(&tree.path("secret")),
    });
    assert_eq!(
        fs::handle(secret, tree.confinement(&[]))
            .await
            .unwrap_err()
            .kind,
        ErrorKind::PermissionDenied
    );

    let list = FsRequest::List(FsPathParams {
        path: abs(&tree.path("granted/out")),
    });
    assert_eq!(
        fs::handle(list, tree.confinement(&[])).await,
        Ok(FsResponse::List(FsListResult {
            entries: vec![DirEntry {
                name: "result".to_string(),
                kind: FileKind::File,
                size: 10,
            }]
        }))
    );
}

#[tokio::test]
async fn sandboxed_writes_need_a_write_grant() {
    require_sandbox();
    let tree = Tree::new();
    assert_eq!(
        write(&tree, "granted/readme", &[], b"defaced")
            .await
            .unwrap_err()
            .kind,
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        std::fs::read(tree.path("granted/readme")).unwrap(),
        b"public"
    );

    assert_eq!(
        write(&tree, "granted/out/result", &["granted/out"], b"new").await,
        Ok(FsResponse::Done)
    );
    assert_eq!(
        std::fs::read(tree.path("granted/out/result")).unwrap(),
        b"new"
    );
    assert_eq!(names(&tree.path("granted/out")), ["result"]);

    let mkdir = FsRequest::Mkdir(FsMkdirParams {
        path: abs(&tree.path("granted/out/a/b")),
        recursive: true,
    });
    let confinement = tree.confinement(&["granted/out"]);
    assert_eq!(
        fs::handle(mkdir, confinement.clone()).await,
        Ok(FsResponse::Done)
    );
    let remove = FsRequest::Remove(FsRemoveParams {
        path: abs(&tree.path("granted/out/a")),
        recursive: true,
    });
    assert_eq!(fs::handle(remove, confinement).await, Ok(FsResponse::Done));
    assert_eq!(names(&tree.path("granted/out")), ["result"]);
}

#[tokio::test]
async fn overwrite_with_only_the_file_granted_writes_in_place() {
    require_sandbox();
    let tree = Tree::new();
    assert_eq!(
        write(
            &tree,
            "granted/out/result",
            &["granted/out/result"],
            b"in place"
        )
        .await,
        Ok(FsResponse::Done)
    );
    assert_eq!(
        std::fs::read(tree.path("granted/out/result")).unwrap(),
        b"in place"
    );
    assert_eq!(names(&tree.path("granted/out")), ["result"]);
}
