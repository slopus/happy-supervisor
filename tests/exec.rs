//! `ExecManager` driven as the dispatcher drives it, with its events read off the wire by a
//! control-plane session.
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use happy_supervisor::exec::ExecManager;
use happy_supervisor::link::{Incoming, ManualClock, NodeIdentity, Role, Session};
use happy_supervisor::policy::{Confinement, Policy, ResolvedPolicy};
use happy_supervisor::protocol::{
    ByteRange, Event, ExecExit, ExecId, ExecLogParams, ExecStartParams, ExecState, ExecSummary,
    ExecWriteParams, ExitStatus, KillSignal, NodeInfo, Stream,
};
use happy_supervisor::{Error, ErrorKind};
use serde_json::{Value, json};

struct Node {
    exec: ExecManager,
    node: Session,
    cp: Session,
    clock: Arc<ManualClock>,
    events: Vec<Event>,
}

impl Node {
    fn new() -> Node {
        let clock = ManualClock::new(1_763_496_000_000);
        let identity = NodeIdentity {
            node_id: "n_1".to_string(),
            installation_id: "tz4a98xxat96iws9zmbrgj3a".to_string(),
        };
        let (mut node, outbox) = Session::new(Role::Node(identity), clock.clone());
        let role = Role::ControlPlane {
            resume_window_ms: 60_000,
        };
        let (mut cp, _) = Session::new(role, clock.clone());
        node.connected();
        cp.connected();
        let mut this = Node {
            exec: ExecManager::new(outbox),
            node,
            cp,
            clock,
            events: Vec::new(),
        };
        this.pump();
        this.node.ready(info(), vec![], vec![]).unwrap();
        this.pump();
        this.events.clear();
        this
    }

    /// Moves frames both ways until both sides are idle, acking as time passes.
    fn pump(&mut self) {
        let mut ticked = false;
        loop {
            let mut moved = false;
            while let Some(text) = self.node.poll_transmit() {
                self.cp.receive(&text);
                moved = true;
            }
            while let Some(text) = self.cp.poll_transmit() {
                self.node.receive(&text);
                moved = true;
            }
            if moved {
                ticked = false;
            } else if ticked {
                break;
            } else {
                self.clock.advance(200);
                self.cp.tick();
                self.node.tick();
                ticked = true;
            }
        }
        while let Some(incoming) = self.cp.poll_incoming() {
            if let Incoming::Message { kind, body, .. } = incoming {
                self.events
                    .push(Event::parse(&kind, body).unwrap().unwrap());
            }
        }
    }

    async fn start(&self, params: Value) -> Result<u32, Error> {
        self.start_with(params, Confinement::Raw).await
    }

    async fn start_with(&self, params: Value, confinement: Confinement) -> Result<u32, Error> {
        let params: ExecStartParams = serde_json::from_value(params).unwrap();
        Ok(self.exec.start(params, confinement, None).await?.pid)
    }

    /// Waits for the process's `exec.exit`.
    async fn exit(&mut self, exec_id: &str) -> ExecExit {
        for _ in 0..1000 {
            self.pump();
            let exit = self.events.iter().find_map(|event| match event {
                Event::ExecExit(exit) if exit.exec_id.as_str() == exec_id => Some(exit.clone()),
                _ => None,
            });
            if let Some(exit) = exit {
                return exit;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{exec_id} did not exit");
    }

    /// The streamed output of one stream of a process.
    fn streamed(&self, exec_id: &str, stream: Stream) -> String {
        let bytes: Vec<u8> = self
            .events
            .iter()
            .filter_map(|event| match event {
                Event::ExecOutput(out)
                    if out.exec_id.as_str() == exec_id && out.stream == stream =>
                {
                    Some(out.data.as_slice().to_vec())
                }
                _ => None,
            })
            .flatten()
            .collect();
        String::from_utf8(bytes).unwrap()
    }

    /// The events of one process, output chunks as `output`.
    fn kinds(&self, exec_id: &str) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|event| match event {
                Event::ExecOutput(e) if e.exec_id.as_str() == exec_id => Some("output".into()),
                Event::ExecTimedOut(e) if e.exec_id.as_str() == exec_id => {
                    Some(format!("timedOut {:?} {}", e.action, e.log_bytes))
                }
                Event::ExecExit(e) if e.exec_id.as_str() == exec_id => {
                    Some(format!("exit {:?} {}", e.exit, e.log_bytes))
                }
                _ => None,
            })
            .collect()
    }

    async fn log(&self, exec_id: &str, offset: u64, length: Option<u64>) -> Result<Read, Error> {
        let params = ExecLogParams {
            exec_id: id(exec_id),
            offset,
            length,
        };
        let result = self.exec.log(params).await?;
        Ok(Read {
            data: String::from_utf8(result.data.into_vec()).unwrap(),
            offset: result.offset,
            total: result.total_bytes,
            retained: result
                .retained
                .iter()
                .map(|ByteRange { start, end }| (*start, *end))
                .collect(),
        })
    }

    async fn write(&self, exec_id: &str, data: &[u8], eof: bool) -> Result<(), Error> {
        let params = ExecWriteParams {
            exec_id: id(exec_id),
            data: happy_supervisor::protocol::Bytes::new(data.to_vec()),
            eof,
        };
        self.exec.write(params).await
    }

    fn summary(&self, exec_id: &str) -> Option<ExecSummary> {
        self.exec
            .list()
            .into_iter()
            .find(|s| s.exec_id.as_str() == exec_id)
    }
}

#[derive(Debug, PartialEq)]
struct Read {
    data: String,
    offset: u64,
    total: u64,
    retained: Vec<(u64, u64)>,
}

fn id(text: &str) -> ExecId {
    ExecId::try_from(text).unwrap()
}

fn sh(exec_id: &str, script: &str) -> Value {
    json!({ "execId": exec_id, "argv": ["/bin/sh", "-c", script], "cwd": "/", "env": {} })
}

fn info() -> NodeInfo {
    serde_json::from_value(json!({
        "installationId": "tz4a98xxat96iws9zmbrgj3a", "name": "box", "hostname": "box",
        "supervisorVersion": "0.1.0",
        "os": { "family": "linux", "name": null, "version": null, "kernelVersion": null, "arch": "x86_64" },
        "cpu": { "model": null, "physicalCores": null, "logicalCores": 1 },
        "memory": { "totalBytes": 1, "swapTotalBytes": 0 },
        "disks": [], "gpus": [],
        "sandbox": { "mechanism": "none", "available": false, "reason": "test", "landlockAbi": null, "baselineRead": [] },
        "defaultEnv": {}, "collectedAtMs": 0
    }))
    .unwrap()
}

const ALPHABET: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCD";

#[tokio::test]
async fn output_streams_and_the_exit_code_arrives_last() {
    let mut node = Node::new();
    node.start(sh("e", "echo out; echo err >&2; exit 3"))
        .await
        .unwrap();
    let exit = node.exit("e").await;
    assert_eq!(exit.exit, ExitStatus::Exited { code: 3 });
    assert_eq!(exit.log_bytes, 8);
    assert_eq!(node.streamed("e", Stream::Stdout), "out\n");
    assert_eq!(node.streamed("e", Stream::Stderr), "err\n");
    assert_eq!(node.kinds("e").last().unwrap(), "exit Exited { code: 3 } 8");
    let log = node.log("e", 0, None).await.unwrap().data;
    assert!(log == "out\nerr\n" || log == "err\nout\n", "{log:?}");
    assert_eq!(
        node.summary("e"),
        Some(ExecSummary {
            exec_id: id("e"),
            state: ExecState::Exited {
                exit: ExitStatus::Exited { code: 3 }
            },
            log_bytes: 8,
        })
    );
}

#[tokio::test]
async fn a_signal_ends_a_process_as_signaled() {
    let mut node = Node::new();
    node.start(sh("s", "kill -9 $$")).await.unwrap();
    assert_eq!(
        node.exit("s").await.exit,
        ExitStatus::Signaled { signal: 9 }
    );
}

#[tokio::test]
async fn the_environment_is_exactly_env_and_bare_names_use_its_path() {
    let mut node = Node::new();
    let params = json!({
        "execId": "env", "argv": ["env"], "cwd": "/",
        "env": { "PATH": "/nonexistent:/usr/bin:/bin", "ONLY": "this" }
    });
    node.start(params).await.unwrap();
    node.exit("env").await;
    assert_eq!(
        node.streamed("env", Stream::Stdout),
        "ONLY=this\nPATH=/nonexistent:/usr/bin:/bin\n"
    );
    assert!(std::env::var_os("PATH").is_some());

    let pwd = json!({ "execId": "pwd", "argv": ["/bin/pwd"], "cwd": "/usr", "env": {} });
    node.start(pwd).await.unwrap();
    node.exit("pwd").await;
    assert_eq!(node.streamed("pwd", Stream::Stdout), "/usr\n");
}

#[tokio::test]
async fn stdin_round_trips_until_eof() {
    let mut node = Node::new();
    let params = json!({
        "execId": "cat", "argv": ["cat"], "cwd": "/", "env": { "PATH": "/bin:/usr/bin" },
        "stdin": true
    });
    node.start(params).await.unwrap();
    node.write("cat", b"hello ", false).await.unwrap();
    node.write("cat", b"world", true).await.unwrap();
    assert_eq!(
        node.write("cat", b"late", false).await.unwrap_err().kind,
        ErrorKind::InvalidParams
    );
    assert_eq!(node.exit("cat").await.exit, ExitStatus::Exited { code: 0 });
    assert_eq!(node.streamed("cat", Stream::Stdout), "hello world");

    node.start(sh("closed", "cat; sleep 30")).await.unwrap();
    let err = node.write("closed", b"x", false).await.unwrap_err();
    assert_eq!(err, Error::invalid_params("closed has no open stdin"));
    let err = node
        .write("closed", &vec![0; (1 << 20) + 1], false)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::TooLarge);
    assert_eq!(
        node.write("nobody", b"x", false).await.unwrap_err().kind,
        ErrorKind::NotFound
    );
    node.exec.kill(&id("closed"), KillSignal::Kill).unwrap();
    node.exit("closed").await;
}

fn is_gone(pid: u32) -> bool {
    // SAFETY: kill with signal 0 only checks for the process.
    let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
    let zombie = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .is_ok_and(|stat| stat.rsplit(')').next().unwrap_or("").starts_with(" Z"));
    !alive || zombie
}

#[tokio::test]
async fn kill_reaches_grandchildren() {
    let mut node = Node::new();
    node.start(sh("tree", "sleep 300 & echo $!; wait"))
        .await
        .unwrap();
    let mut grandchild = String::new();
    while !grandchild.ends_with('\n') {
        tokio::time::sleep(Duration::from_millis(10)).await;
        node.pump();
        grandchild = node.streamed("tree", Stream::Stdout);
    }
    let grandchild: u32 = grandchild.trim().parse().unwrap();
    assert!(!is_gone(grandchild));

    node.exec.kill(&id("tree"), KillSignal::Terminate).unwrap();
    assert_eq!(
        node.exit("tree").await.exit,
        ExitStatus::Signaled { signal: 15 }
    );
    for _ in 0..100 {
        if is_gone(grandchild) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(is_gone(grandchild), "grandchild {grandchild} survived");

    node.exec.kill(&id("tree"), KillSignal::Kill).unwrap();
    assert_eq!(
        node.exec
            .kill(&id("nobody"), KillSignal::Kill)
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn shutdown_kills_every_running_command() {
    let mut node = Node::new();
    node.start(sh("a", "sleep 300")).await.unwrap();
    node.start(sh("b", "sleep 300")).await.unwrap();
    node.exec.shutdown().await;
    assert_eq!(
        node.exit("a").await.exit,
        ExitStatus::Signaled { signal: 9 }
    );
    assert_eq!(
        node.exit("b").await.exit,
        ExitStatus::Signaled { signal: 9 }
    );
}

#[tokio::test]
async fn a_kill_timeout_kills_the_tree_and_exits_timed_out() {
    let mut node = Node::new();
    let mut params = sh("slow", "echo started; sleep 300");
    params["timeout"] = json!({ "ms": 300, "action": { "kind": "kill" } });
    node.start(params).await.unwrap();
    node.exit("slow").await;
    assert_eq!(
        node.kinds("slow"),
        ["output", "timedOut Kill 8", "exit TimedOut 8"]
    );
}

#[tokio::test]
async fn a_background_timeout_stops_streaming_and_keeps_logging() {
    let mut node = Node::new();
    let mut params = sh("bg", "echo before; sleep 1; echo after");
    params["timeout"] = json!({ "ms": 300, "action": { "kind": "background" } });
    node.start(params).await.unwrap();
    while node.kinds("bg").len() < 2 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        node.pump();
    }
    assert_eq!(node.summary("bg").unwrap().state, ExecState::Running);
    node.exit("bg").await;
    assert_eq!(
        node.kinds("bg"),
        [
            "output",
            "timedOut Background 7",
            "exit Exited { code: 0 } 13"
        ]
    );
    assert_eq!(node.streamed("bg", Stream::Stdout), "before\n");
    assert_eq!(
        node.log("bg", 0, None).await.unwrap().data,
        "before\nafter\n"
    );
}

#[tokio::test]
async fn a_memory_log_keeps_head_and_tail_and_reads_stop_at_the_gap() {
    let mut node = Node::new();
    let mut params = sh("m", &format!("printf {ALPHABET}"));
    params["log"] = json!({ "kind": "memory", "limitBytes": 16 });
    node.start(params).await.unwrap();
    assert_eq!(node.exit("m").await.log_bytes, 40);
    assert_eq!(node.streamed("m", Stream::Stdout), ALPHABET);
    assert_eq!(
        node.log("m", 0, None).await.unwrap(),
        Read {
            data: "0123".into(),
            offset: 0,
            total: 40,
            retained: vec![(0, 4), (32, 40)],
        }
    );
    let tail = node.log("m", 4, None).await.unwrap();
    assert_eq!((tail.data.as_str(), tail.offset), ("wxyzABCD", 32));
    let middle = node.log("m", 2, Some(100)).await.unwrap();
    assert_eq!((middle.data.as_str(), middle.offset), ("23", 2));
    let short = node.log("m", 35, Some(2)).await.unwrap();
    assert_eq!((short.data.as_str(), short.offset), ("zA", 35));
    assert_eq!(
        node.log("m", 0, Some((1 << 20) + 1))
            .await
            .unwrap_err()
            .kind,
        ErrorKind::TooLarge
    );
}

#[tokio::test]
async fn a_file_log_is_truncated_then_compacted_with_a_marker_line() {
    let mut node = Node::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.log");
    std::fs::write(&path, "stale contents from an earlier run").unwrap();
    let mut params = sh("f", &format!("printf {ALPHABET}"));
    params["log"] = json!({ "kind": "file", "path": path, "limitBytes": 16 });
    node.start(params).await.unwrap();
    node.exit("f").await;
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "0123[happy-supervisor: 28 bytes omitted]\nwxyzABCD"
    );
    assert_eq!(
        node.log("f", 30, None).await.unwrap(),
        Read {
            data: "wxyzABCD".into(),
            offset: 32,
            total: 40,
            retained: vec![(0, 4), (32, 40)],
        }
    );

    let mut params = sh("nodir", "true");
    params["log"] = json!({ "kind": "file", "path": dir.path().join("missing/m.log") });
    let err = node.start(params).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::NotFound);
    assert!(!dir.path().join("missing").exists());
}

#[tokio::test]
async fn output_chunks_are_at_most_64_kib() {
    let mut node = Node::new();
    node.start(sh("big", "head -c 300000 /dev/zero"))
        .await
        .unwrap();
    assert_eq!(node.exit("big").await.log_bytes, 300_000);
    let sizes: Vec<usize> = node
        .events
        .iter()
        .filter_map(|e| match e {
            Event::ExecOutput(out) => Some(out.data.as_slice().len()),
            _ => None,
        })
        .collect();
    assert!(sizes.iter().all(|&n| n <= 65536), "{sizes:?}");
    assert_eq!(sizes.iter().sum::<usize>(), 300_000);
}

#[tokio::test]
async fn a_failed_start_keeps_its_id_and_sends_no_exit() {
    let mut node = Node::new();
    let missing = json!({ "execId": "x", "argv": ["/nonexistent/prog"], "cwd": "/", "env": {} });
    assert_eq!(
        node.start(missing.clone()).await.unwrap_err().kind,
        ErrorKind::NotFound
    );
    let bare = json!({ "execId": "y", "argv": ["prog"], "cwd": "/", "env": { "PATH": "/bin" } });
    assert_eq!(
        node.start(bare).await.unwrap_err(),
        Error::not_found("prog is not in PATH \"/bin\"")
    );
    let mut nowhere = sh("z", "true");
    nowhere["cwd"] = json!("/nonexistent");
    assert_eq!(
        node.start(nowhere).await.unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        node.start(missing).await.unwrap_err().kind,
        ErrorKind::AlreadyExists
    );
    node.start(sh("ok", "true")).await.unwrap();
    node.exit("ok").await;
    assert_eq!(node.kinds("x"), [] as [String; 0]);
    let listed: Vec<String> = node
        .exec
        .list()
        .iter()
        .map(|s| s.exec_id.to_string())
        .collect();
    assert_eq!(listed, ["ok"]);
    assert_eq!(node.log("x", 0, None).await.unwrap().total, 0);
}

#[tokio::test]
async fn a_running_id_cannot_start_again() {
    let mut node = Node::new();
    node.start(sh("dup", "sleep 300")).await.unwrap();
    assert_eq!(
        node.start(sh("dup", "true")).await.unwrap_err(),
        Error::new(ErrorKind::AlreadyExists, "dup is already in use")
    );
    node.exec.kill(&id("dup"), KillSignal::Kill).unwrap();
    node.exit("dup").await;
}

#[tokio::test]
async fn only_the_256_most_recent_exits_are_kept() {
    let mut node = Node::new();
    for n in 0..257 {
        let exec_id = format!("r{n}");
        node.start(sh(&exec_id, "true")).await.unwrap();
        node.exit(&exec_id).await;
    }
    let listed = node.exec.list();
    assert_eq!(listed.len(), 256);
    assert_eq!(listed[0].exec_id.as_str(), "r1");
    assert_eq!(
        node.log("r0", 0, None).await.unwrap_err().kind,
        ErrorKind::NotFound
    );
    node.start(sh("r0", "true")).await.unwrap();
    node.exit("r0").await;
}

#[tokio::test]
async fn a_sandboxed_command_runs_through_the_helper() {
    happy_supervisor::helper::set_exe(env!("CARGO_BIN_EXE_happy-supervisor").into());
    let sandbox = happy_supervisor::sandbox::probe();
    if let Err(err) = sandbox.require_available() {
        if cfg!(target_os = "linux") {
            panic!("Linux must sandbox: {err}");
        }
        eprintln!("skipped: the sandbox is unavailable here: {}", err.message);
        return;
    }
    let mut node = Node::new();
    let state = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let work_path = work.path().to_str().unwrap().to_string();
    let mut read = sandbox.baseline_read.clone();
    read.push("/nonexistent-grant".to_string());
    let policy = Policy::new(read, vec![work_path.clone()], false, false).unwrap();
    let confinement = || Confinement::Sandboxed(ResolvedPolicy::resolve(&policy, state.path()));

    let mut params = sh("sb", "echo inside; cat");
    params["cwd"] = json!(work_path);
    params["stdin"] = json!(true);
    params["log"] = json!({ "kind": "file", "path": format!("{work_path}/sb.log") });
    let params: ExecStartParams = serde_json::from_value(params).unwrap();
    let started = node.exec.start(params, confinement(), None).await.unwrap();
    assert_eq!(started.ignored_paths, ["/nonexistent-grant"]);
    node.write("sb", b"from stdin", true).await.unwrap();
    assert_eq!(node.exit("sb").await.exit, ExitStatus::Exited { code: 0 });
    assert_eq!(node.streamed("sb", Stream::Stdout), "inside\nfrom stdin");
    assert_eq!(
        std::fs::read_to_string(work.path().join("sb.log")).unwrap(),
        "inside\nfrom stdin"
    );

    let outside = tempfile::tempdir().unwrap();
    let denied = outside.path().join("denied");
    let mut write = sh("sbw", &format!("echo x > {}", denied.display()));
    write["cwd"] = json!(work_path);
    node.start_with(write, confinement()).await.unwrap();
    assert_ne!(node.exit("sbw").await.exit, ExitStatus::Exited { code: 0 });
    assert!(!denied.exists());

    let missing =
        json!({ "execId": "sbx", "argv": ["/nonexistent/prog"], "cwd": work_path, "env": {} });
    let err = node.start_with(missing, confinement()).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::NotFound);

    let mut outside = sh("sbo", "true");
    outside["log"] = json!({ "kind": "file", "path": state.path().join("x.log") });
    let err = node.start_with(outside, confinement()).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::PermissionDenied);
    assert!(!state.path().join("x.log").exists());
}
