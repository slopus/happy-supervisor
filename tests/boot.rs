//! The supervisor's side of happy-supervisor-boot's channel (boot.md, The channel): the real
//! binary, run by this test as boot runs it, against `testing::ControlPlane`.
#![cfg(unix)]

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use happy_supervisor::protocol::{BootState, BootStatus, Event, NodeInfo};
use happy_supervisor::testing::ControlPlane;
use happy_supervisor::testkit::{cbor, json};
use happy_supervisor::{ErrorKind, protocol};
use serde_json::{Value as Json, json};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const BIN: &str = env!("CARGO_BIN_EXE_happy-supervisor");
const WAIT: Duration = Duration::from_secs(30);

async fn joined(cp: &ControlPlane, state: &Path) {
    let joined = Command::new(BIN)
        .args(["join", "--url", &cp.join_url(), "--state-dir"])
        .arg(state)
        .env("HAPPY_JOIN_TOKEN", cp.issue_join_token())
        .output()
        .await
        .unwrap();
    assert!(joined.status.success(), "join failed: {joined:?}");
}

fn run(state: &Path, boot: bool) -> Command {
    let mut command = Command::new(BIN);
    command
        .arg("run")
        .arg("--state-dir")
        .arg(state)
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    if boot {
        command
            .env("HAPPY_SUPERVISOR_BOOT", std::process::id().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
    } else {
        command.stdin(Stdio::null()).stdout(Stdio::null());
    }
    command
}

async fn call(cp: &ControlPlane, kind: &str, body: Json) -> Result<Json, happy_supervisor::Error> {
    tokio::time::timeout(WAIT, cp.command(kind, cbor(body)))
        .await
        .unwrap_or_else(|_| panic!("no reply to {kind}"))
        .map(json)
}

async fn line(lines: &mut Lines<BufReader<ChildStdout>>) -> String {
    tokio::time::timeout(WAIT, lines.next_line())
        .await
        .expect("a line from the supervisor")
        .unwrap()
        .expect("stdout is open")
}

async fn send(stdin: &mut ChildStdin, status: &Json) {
    let line = format!("{}\n", json!({ "status": status }));
    stdin.write_all(line.as_bytes()).await.unwrap();
}

async fn boot_event(cp: &ControlPlane) -> BootStatus {
    loop {
        let event = tokio::time::timeout(WAIT, cp.next_event())
            .await
            .expect("a node.boot")
            .unwrap();
        if let Event::NodeBoot(status) = event {
            return status;
        }
    }
}

async fn exits(child: &mut Child) -> std::process::ExitStatus {
    tokio::time::timeout(WAIT, child.wait())
        .await
        .expect("the supervisor exits")
        .unwrap()
}

#[tokio::test]
async fn under_boot_the_supervisor_reports_its_status_forwards_upgrades_and_stops_with_stdin() {
    let cp = ControlPlane::start().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    joined(&cp, &state).await;
    let mut child = run(&state, true).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap()).lines();

    let idle = json!({ "bootVersion": "0.1.0", "running": "0.2.9", "previous": "0.2.8",
                       "target": null, "state": "idle", "restarts": 0 });
    send(&mut stdin, &idle).await;
    // Once its session opened, it says so, once.
    assert_eq!(line(&mut stdout).await, r#"{"connected":{}}"#);

    let info: NodeInfo =
        serde_json::from_value(call(&cp, "node.info", json!({})).await.unwrap()).unwrap();
    assert_eq!(
        info.boot,
        Some(BootStatus {
            boot_version: "0.1.0".into(),
            running: Some("0.2.9".into()),
            previous: Some("0.2.8".into()),
            target: None,
            state: BootState::Idle,
            error: None,
            restarts: 0,
            last_exit: None,
        })
    );

    assert_eq!(
        call(&cp, "node.upgrade", json!({ "version": "0.3.0" }))
            .await
            .unwrap(),
        json!({})
    );
    assert_eq!(
        line(&mut stdout).await,
        r#"{"upgrade":{"version":"0.3.0"}}"#
    );
    let bad = call(&cp, "node.upgrade", json!({ "version": "../0.3.0" }))
        .await
        .unwrap_err();
    assert_eq!(bad.kind, ErrorKind::InvalidParams);

    // Each status boot sends from now on reaches the control plane as `node.boot`.
    let downloading = json!({ "bootVersion": "0.1.0", "running": "0.2.9", "previous": "0.2.8",
                              "target": "0.3.0", "state": "downloading", "restarts": 0 });
    send(&mut stdin, &downloading).await;
    let status = boot_event(&cp).await;
    assert_eq!(
        (status.target.as_deref(), status.state),
        (Some("0.3.0"), protocol::BootState::Downloading)
    );

    // The end of stdin is boot asking it to stop.
    drop(stdin);
    assert!(exits(&mut child).await.success());
}

#[tokio::test]
async fn without_boot_the_supervisor_refuses_to_change_its_version() {
    let cp = ControlPlane::start().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    joined(&cp, &state).await;
    let mut child = run(&state, false).spawn().unwrap();
    loop {
        let event = tokio::time::timeout(WAIT, cp.next_event())
            .await
            .unwrap()
            .unwrap();
        if matches!(event, Event::NodeReady(_)) {
            break;
        }
    }
    let info: NodeInfo =
        serde_json::from_value(call(&cp, "node.info", json!({})).await.unwrap()).unwrap();
    assert_eq!(info.boot, None);
    let refused = call(&cp, "node.upgrade", json!({ "version": "0.3.0" }))
        .await
        .unwrap_err();
    assert_eq!(refused.kind, ErrorKind::PermissionDenied);
    assert_eq!(
        refused.message,
        "this node was not started by happy-supervisor-boot, so it cannot change its version; \
         install it again with the installer"
    );
    child.start_kill().unwrap();
    exits(&mut child).await;
}
