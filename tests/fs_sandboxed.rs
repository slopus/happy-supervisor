//! `fs.*` under a sandbox, through the helper binary.
#![cfg(unix)]

use std::path::{Path, PathBuf};

use happy_supervisor::fs::{self, FsRequest, FsResponse};
use happy_supervisor::policy::{Confinement, ResolvedPolicy, allow_list};
use happy_supervisor::protocol::{
    AbsPath, Bytes, DirEntry, FileKind, FsListResult, FsMkdirParams, FsPathParams, FsReadParams,
    FsReadResult, FsRemoveParams, FsRenameParams, FsWriteParams, WriteMode,
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
        beneath: None,
        file: None,
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

async fn rename(tree: &Tree, from: &str, to: &str, write: &[&str]) -> Result<FsResponse, Error> {
    let request = FsRequest::Rename(FsRenameParams {
        from: abs(&tree.path(from)),
        to: abs(&tree.path(to)),
    });
    fs::handle(request, tree.confinement(write)).await
}

#[tokio::test]
async fn sandboxed_renames_need_both_paths_writable() {
    require_sandbox();
    let tree = Tree::new();
    std::fs::write(tree.path("granted/out/new"), b"new result").unwrap();
    assert_eq!(
        rename(
            &tree,
            "granted/out/new",
            "granted/out/result",
            &["granted/out"]
        )
        .await,
        Ok(FsResponse::Done)
    );
    assert_eq!(
        std::fs::read(tree.path("granted/out/result")).unwrap(),
        b"new result"
    );
    assert!(!tree.path("granted/out/new").exists());

    let out = tree.path("granted/out/result");
    let readme = tree.path("granted/readme");
    assert_eq!(
        rename(
            &tree,
            "granted/out/result",
            "granted/moved",
            &["granted/out"]
        )
        .await,
        Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "{}: not writable by the policy",
                tree.path("granted/moved").display()
            )
        ))
    );
    assert_eq!(
        rename(
            &tree,
            "granted/readme",
            "granted/out/readme",
            &["granted/out"]
        )
        .await,
        Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("{}: not writable by the policy", readme.display())
        ))
    );
    assert!(out.exists() && readme.exists());
}

#[tokio::test]
async fn a_sandboxed_rename_moves_a_symlink_not_its_target() {
    require_sandbox();
    let tree = Tree::new();
    std::os::unix::fs::symlink(tree.path("secret/key"), tree.path("granted/out/link")).unwrap();
    assert_eq!(
        rename(
            &tree,
            "granted/out/link",
            "granted/out/moved",
            &["granted/out"]
        )
        .await,
        Ok(FsResponse::Done)
    );
    assert_eq!(
        std::fs::read_link(tree.path("granted/out/moved")).unwrap(),
        tree.path("secret/key")
    );
    assert_eq!(std::fs::read(tree.path("secret/key")).unwrap(), b"hunter2");
}

/// A file operation never gets a command proxy, so an isolated policy is no network at all, and
/// the operation still runs (the cluster sends isolated policies with every restricted call).
#[tokio::test]
async fn an_isolated_policy_still_reads_and_writes_files() {
    use happy_supervisor::policy::{Default, HostRules, Network};

    require_sandbox();
    let tree = Tree::new();
    let mut read = sandbox::baseline_read();
    read.push(tree.path("granted").to_str().unwrap().to_string());
    let mut policy = allow_list(
        read,
        [tree.path("granted/out").to_str().unwrap().to_string()],
        false,
        false,
    );
    policy.network = Network::Isolated {
        egress: HostRules {
            default: Default::Deny,
            allow: vec![],
            deny: vec![],
        },
        ports: Some(vec![]),
        local_bind: false,
        unix_sockets: false,
    };
    let confinement = || {
        Confinement::Sandboxed(
            ResolvedPolicy::resolve(&policy, &tree.path("granted/.state")).unwrap(),
        )
    };
    let request = FsRequest::Read(FsReadParams {
        path: abs(&tree.path("granted/readme")),
        offset: 0,
        length: None,
        beneath: None,
        file: None,
    });
    match fs::handle(request, confinement()).await.unwrap() {
        FsResponse::Read(FsReadResult { data, .. }) => assert_eq!(data.into_vec(), b"public"),
        other => panic!("read answered {other:?}"),
    }
    let request = FsRequest::Write(FsWriteParams {
        path: abs(&tree.path("granted/out/result")),
        data: Bytes::new(b"new".to_vec()),
        mode: WriteMode::Overwrite,
    });
    fs::handle(request, confinement()).await.unwrap();
    assert_eq!(
        std::fs::read(tree.path("granted/out/result")).unwrap(),
        b"new"
    );
}

/// `root` and `file` reach the helper: a symlink inside the granted tree is refused beneath
/// `root`, and a file swapped between two ranges is refused by `file`.
#[tokio::test]
async fn sandboxed_reads_beneath_root_refuse_symlinks_and_swaps() {
    require_sandbox();
    let tree = Tree::new();
    std::os::unix::fs::symlink(tree.path("granted/readme"), tree.path("granted/link")).unwrap();
    let read = |rel: &str, offset, file| {
        let request = FsRequest::Read(FsReadParams {
            path: abs(&tree.path(rel)),
            offset,
            length: Some(3),
            beneath: Some(abs(&tree.path("granted"))),
            file,
        });
        fs::handle(request, tree.confinement(&[]))
    };
    let link = tree.path("granted/link");
    assert_eq!(
        read("granted/link", 0, None).await,
        Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("{} is or passes through a symbolic link", link.display())
        ))
    );
    let Ok(FsResponse::Read(FsReadResult {
        data,
        file: Some(file),
        ..
    })) = read("granted/readme", 0, None).await
    else {
        panic!("the read reports no file");
    };
    assert_eq!(data.into_vec(), b"pub");
    std::fs::write(tree.path("swap"), b"PUBLIC").unwrap();
    std::fs::rename(tree.path("swap"), tree.path("granted/readme")).unwrap();
    assert_eq!(
        read("granted/readme", 3, Some(file))
            .await
            .map_err(|e| e.kind),
        Err(ErrorKind::NotFound)
    );
}
