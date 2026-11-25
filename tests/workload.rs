//! `--workload-user` (identity.rs): every command and file operation runs as that user. The
//! node needs root to switch users, so most of this runs only as root; CI runs it with sudo.
#![cfg(unix)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use happy_supervisor::protocol::{
    AbsPath, Access, Bytes, Event, ExecOutput, ExitStatus, FsReadResult, FsWriteParams, NodeInfo,
    WatchEvent, WatchEventBody, WithAccess, WriteMode,
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
        // Copied by `cp`, not std::fs::copy: a process this test forks for another test while the
        // copy is open for writing inherits that descriptor until it execs, and executing the
        // copy meanwhile fails with ETXTBSY ("Text file busy"). Only `cp` ever holds it here.
        let copied = std::process::Command::new("cp")
            .arg(BIN)
            .arg(dir.path().join("happy-supervisor"))
            .status()
            .unwrap();
        assert!(copied.success());
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
        let env = json!({ "PATH": "/usr/bin:/bin" });
        self.sh_in(exec_id, script, access, tty, env).await
    }

    /// [`Node::sh`] with `env`.
    async fn sh_in(
        &self,
        exec_id: &str,
        script: &str,
        access: Json,
        tty: bool,
        env: Json,
    ) -> (ExitStatus, String) {
        let mut events = self.ctl.events();
        let mut params = json!({ "execId": exec_id, "argv": ["/bin/sh", "-c", script],
                                 "cwd": "/", "env": env, "access": access });
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

    // The workload user creates a file log, and a rewrite keeps it its own.
    let start_logged = |exec_id: &str, path: &Path| {
        happy_supervisor::wire::to_value(&json!({ "execId": exec_id,
            "argv": ["/bin/sh", "-c", "printf 0123456789abcdefghijklmnopqrstuvwxyz"], "cwd": "/",
            "env": {}, "access": raw(),
            "log": { "kind": "file", "path": path.to_str().unwrap(), "limitBytes": 16 } }))
    };
    let err = node
        .ctl
        .call(
            "exec.start",
            start_logged("log-denied", &private.join("x.log")),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PermissionDenied, "{}", err.message);
    assert!(!private.join("x.log").exists());
    let log = node.shared().join("out.log");
    let mut events = node.ctl.events();
    node.ctl
        .call("exec.start", start_logged("logged", &log))
        .await
        .unwrap();
    loop {
        match tokio::time::timeout(WAIT, events.next()).await.unwrap() {
            Some(Event::ExecExit(exit)) if exit.exec_id.as_str() == "logged" => break,
            Some(_) => {}
            None => panic!("the events ended"),
        }
    }
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        "0123[happy-supervisor: 24 bytes omitted]\nstuvwxyz"
    );
    assert_eq!(
        std::fs::metadata(&log).unwrap().uid(),
        uid.parse::<i64>().unwrap() as u32
    );

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
    // FSEvents may also report the root, whose modification time the mkdir changed.
    let root = shared.display().to_string();
    assert!(
        seen.iter()
            .all(|path| expected.contains(path) || *path == root),
        "{seen:?}"
    );
}

fn system() -> Json {
    json!({ "mode": "system" })
}

impl Install {
    /// `happy-supervisor system <args>` on this install's state directory: its output.
    fn system(&self, args: &[&str]) -> String {
        let output = std::process::Command::new(self.path("happy-supervisor"))
            .arg("system")
            .args(args)
            .arg("--state-dir")
            .arg(self.path("state"))
            .output()
            .unwrap();
        let text =
            String::from_utf8(output.stdout).unwrap() + &String::from_utf8(output.stderr).unwrap();
        assert!(output.status.success(), "{text}");
        text
    }
}

impl Node {
    /// The error `exec.start` replies to a system `id -u`.
    async fn system_refused(&self, exec_id: &str) -> happy_supervisor::Error {
        self.ctl
            .call(
                "exec.start",
                happy_supervisor::wire::to_value(&json!({ "execId": exec_id,
                    "argv": ["/usr/bin/id", "-u"], "cwd": "/", "env": {}, "access": system() })),
            )
            .await
            .unwrap_err()
    }
}

#[test]
fn the_system_commands_need_the_services_state_and_root_to_enable() {
    let install = Install::new();
    let run = |args: &[&str]| {
        let output = std::process::Command::new(install.path("happy-supervisor"))
            .arg("system")
            .args(args)
            .output()
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        (output.status.code(), stderr.trim().to_string())
    };
    let missing = install.path("missing");
    assert_eq!(
        run(&["status", "--state-dir", missing.to_str().unwrap()]),
        (
            Some(1),
            format!(
                "happy-supervisor: no supervisor state at {}: pass the service's --state-dir",
                missing.display()
            )
        )
    );
    assert_eq!(run(&["status"]).0, Some(2));
    if root() {
        return;
    }
    std::fs::create_dir_all(install.path("state/private")).unwrap();
    assert_eq!(
        run(&[
            "enable",
            "--state-dir",
            install.path("state").to_str().unwrap()
        ]),
        (
            Some(1),
            format!(
                "happy-supervisor: enabling system access needs root (sudo) on Linux or macOS; \
                 this runs as {:?}",
                id(&["-un"])
            )
        )
    );
}

#[tokio::test]
async fn system_access_runs_as_the_enabled_account_only_while_enabled() {
    if !root() {
        eprintln!("skipped: system access needs a supervisor running as root");
        return;
    }
    let node = Node::start().await;
    let not_enabled = "system access is not enabled on this node; an administrator enables it \
                       with `sudo happy-supervisor system enable`";

    let info: NodeInfo = node.ctl.command("node.info", ()).await.unwrap();
    assert_eq!(info.identity.system, None);
    let err = node.system_refused("before").await;
    assert_eq!(
        (err.kind, err.message.as_str()),
        (ErrorKind::PermissionDenied, not_enabled)
    );
    assert_eq!(node.install.system(&["status"]), "system access disabled\n");

    assert_eq!(
        node.install.system(&["enable", "--user", "root"]),
        "system access enabled: it runs as root\n"
    );
    let info: NodeInfo = node.ctl.command("node.info", ()).await.unwrap();
    assert_eq!(
        info.identity.system,
        Some(happy_supervisor::protocol::SystemInfo {
            user: "root".to_string()
        })
    );
    let home = nix::unistd::User::from_name("root").unwrap().unwrap().dir;
    assert_eq!(
        node.sh(
            "system",
            "id -u; echo $HOME $USER $LOGNAME",
            system(),
            false
        )
        .await,
        (
            ExitStatus::Exited { code: 0 },
            format!("0\n{} root root\n", home.display())
        )
    );
    assert_eq!(
        node.sh("raw", "id -u", raw(), false).await,
        (
            ExitStatus::Exited { code: 0 },
            format!("{}\n", id(&["-u", USER]))
        )
    );
    let secret = node.private().join("secret");
    let read: FsReadResult = node
        .ctl
        .command(
            "fs.read",
            json!({ "path": secret.to_str().unwrap(), "access": system() }),
        )
        .await
        .unwrap();
    assert_eq!(read.data.0, b"root's");
    let planted = secret.with_file_name("planted");
    let write = WithAccess {
        params: FsWriteParams {
            path: abs(&planted),
            data: Bytes(b"as root".to_vec()),
            mode: WriteMode::Create,
        },
        access: Access::System {},
    };
    let _: Json = node.ctl.command("fs.write", &write).await.unwrap();
    assert_eq!(std::fs::metadata(&planted).unwrap().uid(), 0);

    let state = node.install.path("state/private/system");
    std::fs::write(
        &state,
        r#"{ "user": "root", "path": ["/hs/bin", "/usr/bin"] }"#,
    )
    .unwrap();
    assert_eq!(
        node.sh("path", "echo $PATH", system(), false).await,
        (
            ExitStatus::Exited { code: 0 },
            "/hs/bin:/usr/bin:/bin\n".to_string()
        )
    );
    std::fs::write(&state, r#"{ "user": "hs-no-such-user", "path": [] }"#).unwrap();
    let err = node.system_refused("gone").await;
    assert_eq!(
        (err.kind, err.message.as_str()),
        (
            ErrorKind::PermissionDenied,
            "system access runs as \"hs-no-such-user\", which no longer exists; an administrator \
             runs `sudo happy-supervisor system enable` again"
        )
    );

    let alias = node.install.path("alias");
    std::os::unix::fs::symlink(node.install.path(""), &alias).unwrap();
    let nobody = nix::unistd::User::from_name(USER).unwrap().unwrap();
    std::os::unix::fs::lchown(&alias, Some(nobody.uid.as_raw()), None).unwrap();
    let output = std::process::Command::new(node.install.path("happy-supervisor"))
        .args(["system", "status", "--state-dir"])
        .arg(alias.join("state"))
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        format!(
            "happy-supervisor: system access stays refused: {} is a symlink or another user's, \
             or others may write it",
            alias.display()
        )
    );

    assert_eq!(
        node.install.system(&["disable"]),
        "system access disabled\n"
    );
    let err = node.system_refused("after").await;
    assert_eq!(
        (err.kind, err.message.as_str()),
        (ErrorKind::PermissionDenied, not_enabled)
    );
    let info: NodeInfo = node.ctl.command("node.info", ()).await.unwrap();
    assert_eq!(info.identity.system, None);
}

/// The installs system access is for, run for real: CI runs it as root on throwaway machines
/// (`--ignored`). `HS_TEST_PATH` adds the directory of the runner's `npm` to `PATH`.
#[tokio::test]
#[ignore = "installs packages system-wide"]
async fn system_access_installs_packages() {
    assert!(root(), "system access needs a supervisor running as root");
    let node = Node::start().await;
    let info: NodeInfo = node.ctl.command("node.info", ()).await.unwrap();
    let mut env = json!(info.default_env);
    if let Ok(extra) = std::env::var("HS_TEST_PATH") {
        env["PATH"] = json!(format!("{}:{extra}", env["PATH"].as_str().unwrap()));
    }
    env["DEBIAN_FRONTEND"] = json!("noninteractive");
    env["HOMEBREW_NO_AUTO_UPDATE"] = json!("1");
    env["HOMEBREW_NO_INSTALL_CLEANUP"] = json!("1");
    let (installs, account) = if cfg!(target_os = "linux") {
        (
            ["apt-get install -y hello", "npm install -g cowsay"],
            "root".to_string(),
        )
    } else {
        (
            ["brew install hello", "npm install -g cowsay"],
            std::env::var("SUDO_USER").unwrap(),
        )
    };
    let check = "hello && cowsay installed";

    for (n, install) in installs.iter().enumerate() {
        let (exit, output) = node
            .sh_in(&format!("raw-{n}"), install, raw(), false, env.clone())
            .await;
        eprintln!("raw `{install}`: {exit:?}\n{output}");
        assert_ne!(exit, ExitStatus::Exited { code: 0 }, "raw `{install}`");
        let err = node
            .ctl
            .call(
                "exec.start",
                happy_supervisor::wire::to_value(&json!({ "execId": format!("off-{n}"),
                    "argv": ["/bin/sh", "-c", install], "cwd": "/", "env": env,
                    "access": system() })),
            )
            .await
            .unwrap_err();
        eprintln!(
            "system `{install}` before enabling: {:?} {}",
            err.kind, err.message
        );
        assert_eq!(err.kind, ErrorKind::PermissionDenied);
    }

    let enabled = node.install.system(&["enable"]);
    eprintln!("{enabled}");
    assert_eq!(
        enabled,
        format!("system access enabled: it runs as {account}\n")
    );
    for (n, install) in installs.iter().enumerate() {
        let (exit, output) = node
            .sh_in(
                &format!("system-{n}"),
                install,
                system(),
                false,
                env.clone(),
            )
            .await;
        eprintln!("system `{install}`: {exit:?}\n{output}");
        assert_eq!(exit, ExitStatus::Exited { code: 0 }, "system `{install}`");
    }
    let (exit, output) = node.sh_in("check", check, system(), false, env).await;
    eprintln!("system `{check}`: {exit:?}\n{output}");
    assert_eq!(exit, ExitStatus::Exited { code: 0 });
    assert!(output.starts_with("Hello, world!\n"), "{output}");
    assert!(output.contains("< installed >"), "{output}");
}
