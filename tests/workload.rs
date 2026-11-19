//! `--workload-user` (identity.rs): every command and file operation runs as that user. The
//! node needs root to switch users, so most of this runs only as root; CI runs it with sudo.
#![cfg(unix)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use happy_supervisor::protocol::{
    AbsPath, Access, Bytes, Event, ExecOutput, ExitStatus, FsWriteParams, NodeInfo, WatchEvent,
    WatchEventBody, WithAccess, WriteMode,
};
use happy_supervisor::{Controller, ErrorKind};
use serde_json::{Value as Json, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

const BIN: &str = env!("CARGO_BIN_EXE_happy-supervisor");
const TOKEN: &str = "tok_workload_test";
const WAIT: Duration = Duration::from_secs(30);
const USER: &str = "nobody";

fn root() -> bool {
    nix::unistd::geteuid().is_root()
}

fn id(args: &[&str]) -> String {
    let output = std::process::Command::new("id")
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// A world-traversable copy of the supervisor, so the workload user can run it as the helper
/// wherever the build lives, and a state directory beside it.
struct Install {
    dir: tempfile::TempDir,
}

impl Install {
    fn new() -> Install {
        // Not the default temporary directory: root's on macOS is private to root.
        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::copy(BIN, dir.path().join("happy-supervisor")).unwrap();
        std::fs::write(dir.path().join("token"), format!("{TOKEN}\n")).unwrap();
        Install { dir }
    }

    fn path(&self, rel: &str) -> PathBuf {
        std::fs::canonicalize(self.dir.path()).unwrap().join(rel)
    }

    fn serve(&self, user: &str) -> Child {
        Command::new(self.path("happy-supervisor"))
            .args(["serve", "--listen", "127.0.0.1:0", "--token-file"])
            .arg(self.path("token"))
            .arg("--state-dir")
            .arg(self.path("state"))
            .args(["--workload-user", user])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }
}

#[tokio::test]
async fn a_node_that_cannot_switch_to_its_workload_user_does_not_start() {
    let install = Install::new();
    for (user, expected) in [
        (
            "hs-no-such-user",
            r#"happy-supervisor: the workload user "hs-no-such-user" does not exist"#.to_string(),
        ),
        (
            "root",
            r#"happy-supervisor: the workload user "root" is root (uid 0); it must be an unprivileged user"#
                .to_string(),
        ),
        (
            USER,
            format!(
                "happy-supervisor: running work as the workload user {USER:?} needs a \
                 supervisor running as root; this one runs as {:?}",
                id(&["-un"])
            ),
        ),
    ] {
        if user == USER && root() {
            continue;
        }
        let output = install.serve(user).wait_with_output().await.unwrap();
        assert!(!output.status.success(), "{user}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr.trim(), expected, "{user}");
    }
}

struct Node {
    install: Install,
    ctl: Controller,
    _child: Child,
}

impl Node {
    async fn start() -> Node {
        let install = Install::new();
        let mut child = install.serve(USER);
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        let line = tokio::time::timeout(WAIT, lines.next_line())
            .await
            .expect("serve printed nothing")
            .unwrap()
            .expect("serve exited before listening");
        let addr = line.strip_prefix("listening ").unwrap().to_string();
        let ctl = Controller::connect(&format!("ws://{addr}"), TOKEN)
            .await
            .unwrap();
        Node {
            install,
            ctl,
            _child: child,
        }
    }

    /// A directory anyone may write, owned by root.
    fn shared(&self) -> PathBuf {
        let dir = self.install.path("shared");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        dir
    }

    /// A directory only root may enter, holding `secret`.
    fn private(&self) -> PathBuf {
        let dir = self.install.path("root-only");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(dir.join("secret"), b"root's").unwrap();
        dir
    }

    /// Runs `script` with `sh -c` and returns its exit and output.
    async fn sh(
        &self,
        exec_id: &str,
        script: &str,
        access: Json,
        tty: bool,
    ) -> (ExitStatus, String) {
        let mut events = self.ctl.events();
        let mut params = json!({ "execId": exec_id, "argv": ["/bin/sh", "-c", script],
                                 "cwd": "/", "env": { "PATH": "/usr/bin:/bin" }, "access": access });
        if tty {
            params["tty"] = json!({ "rows": 24, "cols": 80 });
        }
        let _: Json = self.ctl.command("exec.start", params).await.unwrap();
        let mut output = Vec::new();
        loop {
            match tokio::time::timeout(WAIT, events.next()).await.unwrap() {
                Some(Event::ExecOutput(ExecOutput {
                    exec_id: id, data, ..
                })) if id.as_str() == exec_id => output.extend(data.0),
                Some(Event::ExecExit(exit)) if exit.exec_id.as_str() == exec_id => {
                    let text = String::from_utf8(output).unwrap().replace("\r\n", "\n");
                    return (exit.exit, text);
                }
                Some(_) => {}
                None => panic!("the events ended"),
            }
        }
    }
}

fn raw() -> Json {
    json!({ "mode": "raw" })
}

fn sandboxed(network: Json) -> Json {
    json!({ "mode": "sandboxed", "policy": {
        "filesystem": {
            "read": { "default": "allow", "allow": [], "deny": [] },
            "write": { "default": "deny", "allow": [], "deny": [] },
        },
        "network": network } })
}

fn host() -> Json {
    json!({ "mode": "host", "localBind": false, "unixSockets": false })
}

fn isolated() -> Json {
    json!({ "mode": "isolated", "egress": { "default": "deny", "allow": [], "deny": [] },
            "ports": null, "localBind": false, "unixSockets": false })
}

fn abs(path: &Path) -> AbsPath {
    AbsPath::try_from(path.to_str().unwrap()).unwrap()
}

#[tokio::test]
async fn commands_and_file_operations_run_as_the_workload_user() {
    if !root() {
        eprintln!("skipped: switching to a workload user needs root");
        return;
    }
    let node = Node::start().await;
    let uid = id(&["-u", USER]);
    let groups = id(&["-G", USER]);

    let info: NodeInfo = node.ctl.command("node.info", ()).await.unwrap();
    assert_eq!(info.identity.supervisor_user, id(&["-un"]));
    assert_eq!(info.identity.workload_user.as_deref(), Some(USER));
    assert!(info.identity.root);
    assert_eq!(info.default_env["USER"], USER);

    let ids = "id -u; id -G";
    let expected = format!("{uid}\n{groups}\n");
    assert_eq!(
        node.sh("raw", ids, raw(), false).await,
        (ExitStatus::Exited { code: 0 }, expected.clone())
    );
    let owns_its_terminal = "id -u; test -O \"$(tty)\" && echo owns its terminal";
    assert_eq!(
        node.sh("tty", owns_its_terminal, raw(), true).await,
        (
            ExitStatus::Exited { code: 0 },
            format!("{uid}\nowns its terminal\n")
        )
    );
    let mut cases = vec![("sandboxed", sandboxed(host()))];
    if cfg!(target_os = "linux") {
        // bubblewrap runs as the workload user; its helper reaches the proxy sockets by
        // descriptor.
        cases.push(("isolated", sandboxed(isolated())));
    }
    for (exec_id, access) in cases {
        assert_eq!(
            node.sh(exec_id, ids, access, false).await,
            (ExitStatus::Exited { code: 0 }, expected.clone()),
            "{exec_id}"
        );
    }

    let private = node.private();
    let secret = private.join("secret");
    let (exit, _) = node
        .sh("denied", &format!("cat {}", secret.display()), raw(), false)
        .await;
    assert_eq!(exit, ExitStatus::Exited { code: 1 });
    let cwd = node
        .ctl
        .call(
            "exec.start",
            happy_supervisor::wire::to_value(&json!({ "execId": "cwd", "argv": ["/bin/pwd"],
                "cwd": private.to_str().unwrap(), "env": {}, "access": raw() })),
        )
        .await
        .unwrap_err();
    assert_eq!(cwd.kind, ErrorKind::PermissionDenied, "{}", cwd.message);

    for access in [raw(), sandboxed(host())] {
        let read = node
            .ctl
            .call(
                "fs.read",
                happy_supervisor::wire::to_value(
                    &json!({ "path": secret.to_str().unwrap(), "access": access }),
                ),
            )
            .await
            .unwrap_err();
        assert_eq!(read.kind, ErrorKind::PermissionDenied, "{}", read.message);
    }
    let written = node.shared().join("written");
    let write = WithAccess {
        params: FsWriteParams {
            path: abs(&written),
            data: Bytes(b"as nobody".to_vec()),
            mode: WriteMode::Create,
        },
        access: Access::Raw {},
    };
    let _: Json = node.ctl.command("fs.write", &write).await.unwrap();
    let meta = std::fs::metadata(&written).unwrap();
    // macOS's `id` prints nobody as -2.
    assert_eq!(meta.uid(), uid.parse::<i64>().unwrap() as u32);
    let into_root_only = WithAccess {
        params: FsWriteParams {
            path: abs(&private.join("planted")),
            ..write.params.clone()
        },
        access: Access::Raw {},
    };
    let err = node
        .ctl
        .command::<_, Json>("fs.write", &into_root_only)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PermissionDenied, "{}", err.message);
    assert!(!private.join("planted").exists());

    // Watches run as the workload user too: it cannot watch what it cannot read.
    let watch = |watch_id: &str, path: &Path| {
        happy_supervisor::wire::to_value(&json!({ "watchId": watch_id,
            "path": path.to_str().unwrap(), "recursive": true, "access": raw() }))
    };
    let err = node
        .ctl
        .call("watch.start", watch("private", &private))
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PermissionDenied, "{}", err.message);
    let shared = node.shared();
    let mut events = node.ctl.events();
    node.ctl
        .call("watch.start", watch("shared", &shared))
        .await
        .unwrap();
    let made = format!("mkdir {0}/dir && touch {0}/dir/file", shared.display());
    let (exit, _) = node.sh("make", &made, raw(), false).await;
    assert_eq!(exit, ExitStatus::Exited { code: 0 });
    let expected = [shared.join("dir"), shared.join("dir/file")].map(|p| p.display().to_string());
    let mut seen = Vec::new();
    while !expected.iter().all(|path| seen.contains(path)) {
        match tokio::time::timeout(WAIT, events.next()).await.unwrap() {
            Some(Event::WatchEvent(WatchEvent {
                watch_id,
                body: WatchEventBody::Changes { changes },
            })) if watch_id.as_str() == "shared" => {
                seen.extend(changes.into_iter().map(|change| change.path));
            }
            Some(_) => {}
            None => panic!("the events ended"),
        }
    }
    assert!(seen.iter().all(|path| expected.contains(path)), "{seen:?}");
}
