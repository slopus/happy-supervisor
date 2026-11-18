//! The real binary against `testing::ControlPlane`: `happy-supervisor join`, then
//! `happy-supervisor run` as a child process, driven over the link.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use happy_supervisor::protocol::{
    Bytes, Event, ExecExit, ExitStatus, ProxyBody, ProxyEnd, ProxyMessage, ProxyResponse, Stream,
};
use happy_supervisor::testing::{ControlPlane, Options};
use happy_supervisor::testkit::{cbor, json};
use serde_json::{Value as Json, json};
use tokio::process::{Child, Command};

const BIN: &str = env!("CARGO_BIN_EXE_happy-supervisor");
const WAIT: Duration = Duration::from_secs(30);

/// A joined node running against its own control plane.
struct Node {
    cp: ControlPlane,
    dir: tempfile::TempDir,
    node_id: String,
    child: Option<Child>,
    /// Events read while waiting for another one, oldest first.
    seen: Vec<Event>,
}

impl Node {
    async fn start() -> Node {
        Node::start_with(Options::default()).await
    }

    async fn start_with(options: Options) -> Node {
        let cp = ControlPlane::start_with(options).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let token = cp.issue_join_token();
        let joined = join(&cp, &token, &dir.path().join("state")).await;
        assert!(joined.status.success(), "join failed: {joined:?}");
        let node_id = cp.joins()[0].node_id.clone();
        let mut node = Node {
            cp,
            dir,
            node_id,
            child: None,
            seen: Vec::new(),
        };
        node.run();
        let ready = node.event(|e| matches!(e, Event::NodeReady(_))).await;
        let Event::NodeReady(ready) = ready else {
            unreachable!()
        };
        assert_eq!(ready.previous_session, None);
        node
    }

    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    /// Starts `happy-supervisor run`, its log going to `run.log`.
    fn run(&mut self) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.path().join("run.log"))
            .unwrap();
        let child = Command::new(BIN)
            .arg("run")
            .arg("--state-dir")
            .arg(self.state())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        self.child = Some(child);
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("run.log")).unwrap_or_default()
    }

    async fn call(&self, kind: &str, body: Json) -> Result<Json, happy_supervisor::Error> {
        let reply = tokio::time::timeout(WAIT, self.cp.command(kind, cbor(body)))
            .await
            .unwrap_or_else(|_| panic!("no reply to {kind}; node log:\n{}", self.log()));
        reply.map(json)
    }

    async fn ok(&self, kind: &str, body: Json) -> Json {
        self.call(kind, body)
            .await
            .unwrap_or_else(|err| panic!("{kind} failed: {err}"))
    }

    /// The first event, seen before or arriving now, that `wanted` accepts.
    async fn event(&mut self, wanted: impl Fn(&Event) -> bool) -> Event {
        if let Some(at) = self.seen.iter().position(&wanted) {
            return self.seen.remove(at);
        }
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let event = tokio::time::timeout_at(deadline, self.cp.next_event())
                .await
                .unwrap_or_else(|_| panic!("no such event; node log:\n{}", self.log()))
                .unwrap();
            if wanted(&event) {
                return event;
            }
            self.seen.push(event);
        }
    }

    /// Waits for `exec_id`'s exit and returns it with the process's streamed stdout and stderr.
    async fn exit(&mut self, exec_id: &str) -> (ExecExit, String, String) {
        let event = self
            .event(|e| matches!(e, Event::ExecExit(x) if x.exec_id.as_str() == exec_id))
            .await;
        let Event::ExecExit(exit) = event else {
            unreachable!()
        };
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        self.seen.retain(|e| match e {
            Event::ExecOutput(out) if out.exec_id.as_str() == exec_id => {
                assert_eq!(out.dropped_bytes, 0, "{exec_id} dropped output");
                match out.stream {
                    Stream::Stdout => stdout.extend_from_slice(out.data.as_slice()),
                    Stream::Stderr => stderr.extend_from_slice(out.data.as_slice()),
                }
                false
            }
            _ => true,
        });
        let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
        (exit, text(stdout), text(stderr))
    }

    async fn wait_exit_code(&mut self) -> Option<i32> {
        let child = self.child.as_mut().unwrap();
        let status = tokio::time::timeout(WAIT, child.wait())
            .await
            .expect("run did not exit")
            .unwrap();
        self.child = None;
        status.code()
    }

    fn baseline_read(&self) -> Vec<String> {
        self.cp.joins()[0].info.sandbox.baseline_read.clone()
    }

    /// A sandboxed `access` reading the baseline plus `read`, writing `write`.
    fn sandboxed(&self, read: &[&Path], write: &[&Path]) -> Json {
        let mut reads = self.baseline_read();
        reads.extend(read.iter().map(|p| path(p)));
        json!({ "mode": "sandboxed", "policy": {
            "read": reads, "write": write.iter().map(|p| path(p)).collect::<Vec<_>>(),
            "localBind": false, "unixSockets": false } })
    }
}

async fn join(cp: &ControlPlane, token: &str, state: &Path) -> std::process::Output {
    Command::new(BIN)
        .args(["join", "--url", &cp.join_url(), "--token", token])
        .args(["--name", "e2e-node", "--state-dir"])
        .arg(state)
        .output()
        .await
        .unwrap()
}

/// The canonical path as a policy string. macOS temp dirs sit behind the `/var` symlink.
fn path(p: &Path) -> String {
    std::fs::canonicalize(p)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

fn sh(exec_id: &str, script: &str, cwd: &Path, access: Json) -> Json {
    json!({ "execId": exec_id, "argv": ["/bin/sh", "-c", script], "cwd": path(cwd),
            "env": { "PATH": "/usr/bin:/bin" }, "access": access })
}

fn raw() -> Json {
    json!({ "mode": "raw" })
}

fn hex(data: &[u8]) -> String {
    let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
    format!("h'{hex}'")
}

#[tokio::test]
async fn join_takes_a_one_time_token_and_stores_owner_only_credentials() {
    let node = Node::start().await;
    let record = &node.cp.joins()[0];
    assert_eq!(record.name, "e2e-node");
    let private = node.state().join("private");
    let installation_id = std::fs::read_to_string(private.join("installation-id")).unwrap();
    assert_eq!(record.installation_id, installation_id);
    assert_eq!(record.info.installation_id, installation_id);

    let credentials = private.join("credentials.json");
    let stored: Json = serde_json::from_slice(&std::fs::read(&credentials).unwrap()).unwrap();
    assert_eq!(
        stored,
        json!({ "endpoint": node.cp.endpoint(), "nodeId": record.node_id,
                "nodeToken": record.node_token, "name": "e2e-node" })
    );
    assert_ne!(node.cp.endpoint(), node.cp.join_url());
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&credentials), 0o600);
    assert_eq!(mode(&private), 0o700);

    let again = join(&node.cp, &record.join_token, &node.dir.path().join("other")).await;
    assert_eq!(again.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(
        stderr.contains("the join token is invalid, expired or spent (401 Unauthorized): unknown or spent join token"),
        "{stderr}"
    );
    assert!(
        !node
            .dir
            .path()
            .join("other/private/credentials.json")
            .exists()
    );
    assert_eq!(node.cp.joins().len(), 1);
}

#[tokio::test]
async fn node_info_is_collected_fresh() {
    let node = Node::start().await;
    let info = node.ok("node.info", json!({})).await;
    assert_eq!(info["name"], "e2e-node");
    assert_eq!(info["installationId"], node.cp.joins()[0].installation_id);
    assert_eq!(info["supervisorVersion"], env!("CARGO_PKG_VERSION"));
    let unknown = node.call("node.nope", json!({})).await.unwrap_err();
    assert_eq!(unknown.message, "unknown message kind `node.nope`");
}

#[tokio::test]
async fn a_sandboxed_command_writes_only_where_its_policy_allows() {
    let mut node = Node::start().await;
    let work = tempfile::tempdir().unwrap();
    let out = work.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let missing = work.path().join("missing");
    let mut access = node.sandboxed(&[work.path()], &[&out]);
    access["policy"]["write"]
        .as_array_mut()
        .unwrap()
        .push(json!(format!("{}/missing", path(work.path()))));
    let script = "echo ok > out/ok.txt && echo written; \
                  (echo bad > denied.txt) 2>/dev/null || echo refused";
    let started = node
        .ok("exec.start", sh("sbx", script, work.path(), access))
        .await;
    assert_eq!(
        started["ignoredPaths"],
        json!([format!("{}/missing", path(work.path()))])
    );
    let (exit, stdout, _) = node.exit("sbx").await;
    assert_eq!(exit.exit, ExitStatus::Exited { code: 0 });
    assert_eq!(stdout, "written\nrefused\n");
    assert_eq!(std::fs::read_to_string(out.join("ok.txt")).unwrap(), "ok\n");
    assert!(!work.path().join("denied.txt").exists());
    assert!(!missing.exists());
}

#[tokio::test]
async fn a_raw_command_reads_its_stdin() {
    let mut node = Node::start().await;
    let mut start = sh("cat", "cat; echo done >&2", Path::new("/"), raw());
    start["stdin"] = json!(true);
    node.ok("exec.start", start).await;
    node.ok(
        "exec.write",
        json!({ "execId": "cat", "data": hex(b"hello "), "eof": false }),
    )
    .await;
    node.ok(
        "exec.write",
        json!({ "execId": "cat", "data": hex(b"world\n"), "eof": true }),
    )
    .await;
    let (exit, stdout, stderr) = node.exit("cat").await;
    assert_eq!(exit.exit, ExitStatus::Exited { code: 0 });
    assert_eq!(
        (stdout.as_str(), stderr.as_str()),
        ("hello world\n", "done\n")
    );
}

#[tokio::test]
async fn timeouts_kill_or_move_to_the_background() {
    let mut node = Node::start().await;
    let mut kill = sh("k", "sleep 30", Path::new("/"), raw());
    kill["timeout"] = json!({ "ms": 300, "action": { "kind": "kill" } });
    node.ok("exec.start", kill).await;
    let (exit, _, _) = node.exit("k").await;
    assert_eq!(exit.exit, ExitStatus::TimedOut);

    let mut background = sh("b", "echo early; sleep 1; echo late", Path::new("/"), raw());
    background["timeout"] = json!({ "ms": 300, "action": { "kind": "background" } });
    node.ok("exec.start", background).await;
    node.event(|e| matches!(e, Event::ExecTimedOut(t) if t.exec_id.as_str() == "b"))
        .await;
    let (exit, stdout, _) = node.exit("b").await;
    assert_eq!(exit.exit, ExitStatus::Exited { code: 0 });
    assert_eq!(stdout, "early\n");
    let log = node
        .ok("exec.log", json!({ "execId": "b", "offset": 0 }))
        .await;
    assert_eq!(log["data"], hex(b"early\nlate\n"));
    assert_eq!(log["totalBytes"], 11);
}

/// The control plane answers a command's HTTPS request to a listed host itself, adding a
/// header, and the command sees that response.
#[tokio::test]
async fn the_proxy_sends_listed_hosts_through_the_control_plane() {
    let mut node = Node::start().await;
    let work = tempfile::tempdir().unwrap();
    let sandboxed = node.sandboxed(&[work.path()], &[]);
    for (exec_id, access) in [("raw-curl", raw()), ("sbx-curl", sandboxed)] {
        let mut start = json!({ "execId": exec_id,
            "argv": ["curl", "-sS", "-i", "--max-time", "20", "https://api.example.test/hello?x=1"],
            "cwd": path(work.path()), "env": { "PATH": "/usr/bin:/bin" }, "access": access });
        start["proxy"] = json!({ "token": "pt_e2e", "hosts": ["api.example.test"] });
        node.ok("exec.start", start).await;

        let request = node
            .event(|e| matches!(e, Event::Proxy(ProxyMessage::Request(_))))
            .await;
        let Event::Proxy(ProxyMessage::Request(request)) = request else {
            unreachable!()
        };
        assert_eq!(request.exec_id.as_str(), exec_id);
        assert_eq!(request.token.as_str(), "pt_e2e");
        assert_eq!(
            (request.method.as_str(), request.host.as_str(), request.port),
            ("GET", "api.example.test", 443)
        );
        assert_eq!(request.path, "/hello?x=1");
        assert!(
            !request
                .headers
                .iter()
                .any(|(name, _)| name == "proxy-authorization")
        );
        let stream_id = request.stream_id;
        let body = b"from the control plane\n";
        node.cp.send_proxy(ProxyMessage::Response(ProxyResponse {
            stream_id,
            status: 200,
            headers: vec![
                (
                    "content-type".to_string(),
                    Bytes::new(b"text/plain".to_vec()),
                ),
                ("content-length".to_string(), Bytes::new(b"23".to_vec())),
                (
                    "x-injected".to_string(),
                    Bytes::new(b"by-the-control-plane".to_vec()),
                ),
            ],
        }));
        node.cp.send_proxy(ProxyMessage::Body(ProxyBody {
            stream_id,
            data: Bytes::new(body.to_vec()),
        }));
        node.cp
            .send_proxy(ProxyMessage::End(ProxyEnd { stream_id }));

        let (exit, stdout, stderr) = node.exit(exec_id).await;
        assert_eq!(
            exit.exit,
            ExitStatus::Exited { code: 0 },
            "{exec_id}: {stderr}"
        );
        assert!(stdout.starts_with("HTTP/1.1 200"), "{exec_id}: {stdout}");
        assert!(
            stdout
                .to_ascii_lowercase()
                .contains("x-injected: by-the-control-plane"),
            "{exec_id}: {stdout}"
        );
        assert!(
            stdout.ends_with("\r\n\r\nfrom the control plane\n"),
            "{exec_id}: {stdout}"
        );
    }
}

/// Output keeps flowing while the connection drops twice, once with acks stalled so the node
/// resends what the control plane already had. The stream arrives whole and once.
#[tokio::test]
async fn a_dropped_connection_resumes_without_loss_or_duplicates() {
    let mut node = Node::start().await;
    let session = node.cp.session();
    let script = "i=0; while [ $i -lt 300 ]; do echo line-$i; i=$((i+1)); sleep 0.01; done";
    node.ok("exec.start", sh("stream", script, Path::new("/"), raw()))
        .await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    node.cp.stall_acks(true);
    tokio::time::sleep(Duration::from_millis(400)).await;
    node.cp.drop_connection();
    let lists: Vec<_> = (0..20).map(|_| node.call("exec.list", json!({}))).collect();
    for listed in futures_util::future::join_all(lists).await {
        assert_eq!(listed.unwrap()["execs"][0]["execId"], "stream");
    }
    node.cp.stall_acks(false);
    tokio::time::sleep(Duration::from_millis(300)).await;
    node.cp.drop_connection();

    let (exit, stdout, _) = node.exit("stream").await;
    assert_eq!(exit.exit, ExitStatus::Exited { code: 0 });
    let expected: String = (0..300).map(|i| format!("line-{i}\n")).collect();
    assert_eq!(stdout, expected);
    assert_eq!(node.cp.session(), session);
    assert!(!node.seen.iter().any(|e| matches!(e, Event::NodeReady(_))));
    assert_eq!(node.cp.stray_replies(), 0);
}

#[tokio::test]
async fn a_forgotten_session_gets_node_ready_with_the_previous_one() {
    let mut node = Node::start().await;
    node.ok("exec.start", sh("keep", "sleep 30", Path::new("/"), raw()))
        .await;
    let first = node.cp.session().unwrap();
    node.cp.forget_session();
    let ready = node.event(|e| matches!(e, Event::NodeReady(_))).await;
    let Event::NodeReady(ready) = ready else {
        unreachable!()
    };
    assert_eq!(ready.previous_session, Some(first));
    assert_eq!(ready.execs.len(), 1);
    assert_eq!(ready.execs[0].exec_id.as_str(), "keep");
    assert_ne!(node.cp.session(), Some(first));
    node.ok("exec.kill", json!({ "execId": "keep", "signal": "kill" }))
        .await;
}

#[tokio::test]
async fn a_revoked_node_exits_3_and_stays_out() {
    let mut node = Node::start().await;
    let node_id = node.node_id.clone();
    node.cp.revoke(&node_id);
    assert_eq!(node.wait_exit_code().await, Some(3));
    node.run();
    assert_eq!(node.wait_exit_code().await, Some(3));
    assert!(
        node.log()
            .contains("refused this node's credential (401 Unauthorized)")
    );
}

#[tokio::test]
async fn sigterm_ends_the_session_and_exits_0() {
    let mut node = Node::start().await;
    let pid = node.child.as_ref().unwrap().id().unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    assert_eq!(node.wait_exit_code().await, Some(0));
}

/// The same traffic with and without deflate. Prints the byte counts.
#[tokio::test]
async fn deflate_shrinks_the_link_and_plain_v1_still_works() {
    let mut counts = Vec::new();
    for deflate in [true, false] {
        let mut node = Node::start_with(Options {
            deflate,
            ..Options::default()
        })
        .await;
        for _ in 0..5 {
            node.ok("node.info", json!({})).await;
        }
        node.ok(
            "exec.start",
            sh("seq", "seq 1 20000", Path::new("/"), raw()),
        )
        .await;
        let (_, stdout, _) = node.exit("seq").await;
        assert_eq!(stdout.lines().count(), 20000);
        let received = node.cp.received();
        let sent = node.cp.sent();
        println!(
            "deflate={deflate}: node -> control plane {} frames, {} bytes on the wire for {} \
             bytes of CBOR (ratio {:.3}); control plane -> node {} frames, {} wire / {} CBOR",
            received.frames,
            received.wire_bytes,
            received.cbor_bytes,
            received.wire_bytes as f64 / received.cbor_bytes as f64,
            sent.frames,
            sent.wire_bytes,
            sent.cbor_bytes,
        );
        if deflate {
            // Every frame carries the one-byte prefix; the NodeInfo replies shrink.
            assert!(
                received.wire_bytes * 10 < received.cbor_bytes * 6,
                "{received:?}"
            );
        } else {
            assert_eq!(received.wire_bytes, received.cbor_bytes);
            assert_eq!(sent.wire_bytes, sent.cbor_bytes);
        }
        counts.push(received.cbor_bytes);
    }
    assert!(counts.iter().all(|&c| c > 100_000), "{counts:?}");
}
