//! `happy-supervisor serve --listen` driven by `Controller` (docs/serve.md).

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use happy_supervisor::protocol::NodeInfo;
use happy_supervisor::{Controller, ErrorKind};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

const BIN: &str = env!("CARGO_BIN_EXE_happy-supervisor");
const TOKEN: &str = "tok_serve_test";
const WAIT: Duration = Duration::from_secs(30);

struct Served {
    child: Child,
    /// `127.0.0.1:41234` or `unix:/…`.
    addr: String,
    dir: tempfile::TempDir,
}

impl Served {
    async fn start(listen: &str) -> Served {
        let dir = tempfile::tempdir().unwrap();
        Served::start_in(dir, listen).await
    }

    async fn start_in(dir: tempfile::TempDir, listen: &str) -> Served {
        let token = dir.path().join("token");
        std::fs::write(&token, format!("{TOKEN}\n")).unwrap();
        let mut child = serve(dir.path(), listen);
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        let line = tokio::time::timeout(WAIT, lines.next_line())
            .await
            .expect("serve printed nothing")
            .unwrap()
            .expect("serve exited before listening");
        let addr = line.strip_prefix("listening ").unwrap().to_string();
        Served { child, addr, dir }
    }

    fn url(&self) -> String {
        match self.addr.strip_prefix("unix:") {
            Some(_) => self.addr.clone(),
            None => format!("ws://{}", self.addr),
        }
    }

    async fn connect(&self) -> Controller {
        Controller::connect(&self.url(), TOKEN).await.unwrap()
    }
}

fn serve(state: &Path, listen: &str) -> Child {
    Command::new(BIN)
        .args(["serve", "--listen", listen, "--token-file"])
        .arg(state.join("token"))
        .arg("--state-dir")
        .arg(state)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

#[tokio::test]
async fn a_controller_drives_a_listening_node() {
    let served = Served::start("127.0.0.1:0").await;
    assert!(served.addr.starts_with("127.0.0.1:"), "{}", served.addr);
    let ctl = served.connect().await;
    let info: NodeInfo = ctl.command("node.info", ()).await.unwrap();
    let id = std::fs::read_to_string(served.dir.path().join("private/installation-id")).unwrap();
    assert_eq!(info.installation_id, id.trim());

    let unknown = ctl
        .call("node.nope", happy_supervisor::protocol::Value::Null)
        .await
        .unwrap_err();
    assert_eq!(unknown.kind, ErrorKind::UnknownKind);
}

#[tokio::test]
async fn a_wrong_token_is_refused_before_the_upgrade() {
    let served = Served::start("127.0.0.1:0").await;
    let err = Controller::connect(&served.url(), "tok_wrong")
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::PermissionDenied);
    assert_eq!(
        err.message,
        format!("{}/ refused the token (401 Unauthorized)", served.url())
    );
}

#[cfg(unix)]
#[tokio::test]
async fn commands_and_events_flow_over_a_unix_socket() {
    use happy_supervisor::protocol::{Event, ExecOutput, ExitStatus};
    use std::path::PathBuf;

    let dir = tempfile::tempdir().unwrap();
    let socket: PathBuf = dir.path().join("node.sock");
    let served = Served::start_in(dir, &format!("unix:{}", socket.display())).await;
    assert_eq!(served.addr, format!("unix:{}", socket.display()));
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    let ctl = served.connect().await;
    let mut events = ctl.events();
    let started: serde_json::Value = ctl
        .command(
            "exec.start",
            serde_json::json!({ "execId": "hi", "argv": ["/bin/sh", "-c", "echo hello"],
                                "cwd": "/", "env": {}, "access": { "mode": "raw" } }),
        )
        .await
        .unwrap();
    assert_eq!(started["execId"], "hi");
    let mut stdout = Vec::new();
    let exit = loop {
        match tokio::time::timeout(WAIT, events.next()).await.unwrap() {
            Some(Event::ExecOutput(ExecOutput { data, .. })) => stdout.extend(data.0),
            Some(Event::ExecExit(exit)) => break exit,
            Some(_) => {}
            None => panic!("the events ended"),
        }
    };
    assert_eq!(exit.exit, ExitStatus::Exited { code: 0 });
    assert_eq!(stdout, b"hello\n");
}

#[cfg(unix)]
#[tokio::test]
async fn a_new_controller_takes_over_and_starts_a_new_session() {
    let served = Served::start("127.0.0.1:0").await;
    let first = served.connect().await;
    let first_session = first.session().unwrap();
    let _: serde_json::Value = first
        .command(
            "exec.start",
            serde_json::json!({ "execId": "long", "argv": ["/bin/sleep", "30"],
                                "cwd": "/", "env": {}, "access": { "mode": "raw" } }),
        )
        .await
        .unwrap();

    let second = served.connect().await;
    let second_session = second.session().unwrap();
    assert_ne!(first_session, second_session);
    let list: serde_json::Value = second
        .command("exec.list", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(list["execs"][0]["execId"], "long");
    // The replaced controller stops rather than taking the node back.
    let replaced = first
        .call("node.info", happy_supervisor::protocol::Value::Null)
        .await
        .unwrap_err();
    assert_eq!(replaced.kind, ErrorKind::Io);
    let again: serde_json::Value = second
        .command("exec.list", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(again["execs"][0]["execId"], "long");
    let _: serde_json::Value = second
        .command(
            "exec.kill",
            serde_json::json!({ "execId": "long", "signal": "kill" }),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn two_nodes_cannot_share_a_state_directory() {
    let mut served = Served::start("127.0.0.1:0").await;
    let second = serve(served.dir.path(), "127.0.0.1:0")
        .wait_with_output()
        .await
        .unwrap();
    assert!(!second.status.success());
    assert!(served.child.try_wait().unwrap().is_none());
}
