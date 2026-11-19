//! `exec.start` `limits` (api.md), raw and sandboxed, through a `serve` node.

use std::process::Stdio;
use std::time::{Duration, Instant};

use happy_supervisor::Controller;
use happy_supervisor::protocol::{Event, ExecOutput, ExitStatus, NodeInfo};
use serde_json::{Value as Json, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

const BIN: &str = env!("CARGO_BIN_EXE_happy-supervisor");
const TOKEN: &str = "tok_limits_test";
const WAIT: Duration = Duration::from_secs(60);

struct Node {
    ctl: Controller,
    _child: Child,
    _dir: tempfile::TempDir,
}

impl Node {
    async fn start() -> Node {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("token"), format!("{TOKEN}\n")).unwrap();
        let mut child = Command::new(BIN)
            .args(["serve", "--listen", "127.0.0.1:0", "--token-file"])
            .arg(dir.path().join("token"))
            .arg("--state-dir")
            .arg(dir.path().join("state"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let line = tokio::time::timeout(WAIT, BufReader::new(stdout).lines().next_line())
            .await
            .unwrap()
            .unwrap()
            .expect("serve exited before listening");
        let addr = line.strip_prefix("listening ").unwrap().to_string();
        let ctl = Controller::connect(&format!("ws://{addr}"), TOKEN)
            .await
            .unwrap();
        Node {
            ctl,
            _child: child,
            _dir: dir,
        }
    }

    /// Runs `argv` with `limits` and returns its exit, its output, and how long it ran.
    async fn run(
        &self,
        exec_id: &str,
        argv: &[&str],
        access: &Json,
        limits: Json,
    ) -> (ExitStatus, String, Duration) {
        let mut events = self.ctl.events();
        let started = Instant::now();
        let params = json!({ "execId": exec_id, "argv": argv, "cwd": cwd(), "env": env(),
                             "access": access, "limits": limits });
        let _: Json = self.ctl.command("exec.start", params).await.unwrap();
        let mut output = Vec::new();
        loop {
            match tokio::time::timeout(WAIT, events.next()).await.unwrap() {
                Some(Event::ExecOutput(ExecOutput {
                    exec_id: id, data, ..
                })) if id.as_str() == exec_id => output.extend(data.0),
                Some(Event::ExecExit(exit)) if exit.exec_id.as_str() == exec_id => {
                    let output = String::from_utf8_lossy(&output).replace("\r\n", "\n");
                    return (exit.exit, output, started.elapsed());
                }
                Some(_) => {}
                None => panic!("the events ended"),
            }
        }
    }
}

fn cwd() -> &'static str {
    if cfg!(windows) { r"C:\" } else { "/" }
}

fn env() -> Json {
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap();
        json!({ "PATH": format!(r"{root}\System32"), "SystemRoot": root,
                "PATHEXT": ".COM;.EXE;.BAT;.CMD" })
    } else {
        json!({ "PATH": "/usr/bin:/bin" })
    }
}

fn raw() -> Json {
    json!({ "mode": "raw" })
}

fn sandboxed() -> Json {
    json!({ "mode": "sandboxed", "policy": {
        "filesystem": {
            "read": { "default": "allow", "allow": [], "deny": [] },
            "write": { "default": "deny", "allow": [], "deny": [] },
        },
        "network": { "mode": "host", "localBind": false, "unixSockets": false } } })
}

/// A command that spins on the CPU for minutes.
fn spin() -> Vec<&'static str> {
    if cfg!(windows) {
        vec!["cmd", "/c", "for /L %i in (1,1,2000000000) do @rem"]
    } else {
        vec!["/bin/sh", "-c", "while :; do :; done"]
    }
}

#[tokio::test]
async fn node_info_says_which_limits_are_enforced() {
    let node = Node::start().await;
    let info: NodeInfo = node.ctl.command("node.info", ()).await.unwrap();
    let windows = cfg!(windows);
    assert_eq!(
        (
            info.limits.memory_bytes,
            info.limits.processes,
            info.limits.cpu_seconds
        ),
        (windows, windows, true)
    );
}

#[tokio::test]
async fn cpu_seconds_ends_a_process_that_spins() {
    let node = Node::start().await;
    for (label, access) in [("raw", raw()), ("sandboxed", sandboxed())] {
        let (exit, _, ran) = node
            .run(label, &spin(), &access, json!({ "cpuSeconds": 1 }))
            .await;
        let expected = if cfg!(windows) {
            // A Job Object ends a process over its time limit with STATUS_QUOTA_EXCEEDED.
            ExitStatus::Exited {
                code: 0xC000_0044_u32 as i32,
            }
        } else if cfg!(target_os = "linux") && label == "sandboxed" {
            // bubblewrap reports a signal as 128 plus its number (policy.md, Linux gaps).
            ExitStatus::Exited { code: 128 + 24 }
        } else {
            ExitStatus::Signaled { signal: 24 }
        };
        assert_eq!(exit, expected, "{label}");
        assert!(ran < Duration::from_secs(20), "{label} ran {ran:?}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_limit_this_node_cannot_enforce_is_refused() {
    let node = Node::start().await;
    let params = |limits: Json| {
        happy_supervisor::wire::to_value(&json!({ "execId": "x", "argv": ["/bin/true"],
            "cwd": "/", "env": {}, "access": raw(), "limits": limits }))
    };
    let err = node
        .ctl
        .call(
            "exec.start",
            params(json!({ "memoryBytes": 1u64 << 30, "processes": 8 })),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind, happy_supervisor::ErrorKind::SandboxUnavailable);
    assert_eq!(
        err.message,
        "this node cannot enforce limits.memoryBytes or limits.processes (NodeInfo limits)"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn processes_caps_the_tree() {
    let node = Node::start().await;
    let nested = ["cmd", "/c", "cmd", "/c", "echo", "nested"];
    for (label, access) in [("raw", raw()), ("sandboxed", sandboxed())] {
        let (exit, output, _) = node
            .run(label, &nested, &access, json!({ "processes": 2 }))
            .await;
        assert_eq!(
            (exit, output.trim()),
            (ExitStatus::Exited { code: 0 }, "nested"),
            "{label}"
        );
        let (exit, output, _) = node
            .run(
                &format!("{label}-1"),
                &nested,
                &access,
                json!({ "processes": 1 }),
            )
            .await;
        assert_ne!(exit, ExitStatus::Exited { code: 0 }, "{label}: {output}");
        assert!(!output.contains("nested"), "{label}: {output}");
    }
}
