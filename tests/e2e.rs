//! The real binary against `testing::ControlPlane`: `happy-supervisor join`, then
//! `happy-supervisor run` as a child process, driven over the link.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use happy_supervisor::protocol::{
    Bytes, Event, ExecExit, ExitStatus, ProxyBody, ProxyEnd, ProxyMessage, ProxyResponse, Stream,
};
use happy_supervisor::testing::{ControlPlane, Options, Traffic};
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
    single_lane: bool,
    deflate_level: u32,
    child: Option<Child>,
    /// Events read while waiting for another one, oldest first.
    seen: Vec<Event>,
}

impl Node {
    async fn start() -> Node {
        Node::start_with(Options::default()).await
    }

    async fn start_with(options: Options) -> Node {
        Node::start_full(options, false).await
    }

    /// A node that sends everything through one lane, as a link without lanes would.
    async fn start_single_lane() -> Node {
        Node::start_full(Options::default(), true).await
    }

    async fn start_full(options: Options, single_lane: bool) -> Node {
        let mut node = Node::spawn(options, single_lane).await;
        let ready = node.event(|e| matches!(e, Event::NodeReady(_))).await;
        let Event::NodeReady(ready) = ready else {
            unreachable!()
        };
        assert_eq!(ready.previous_session, None);
        node
    }

    /// Joins and starts `run`, without waiting for it to connect.
    async fn spawn(options: Options, single_lane: bool) -> Node {
        let deflate_level = options.deflate_level;
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
            single_lane,
            deflate_level,
            child: None,
            seen: Vec::new(),
        };
        node.run();
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
        let mut command = Command::new(BIN);
        if self.single_lane {
            command.env(happy_supervisor::client::SINGLE_LANE_ENV, "1");
        }
        command.env(
            happy_supervisor::ws::DEFLATE_LEVEL_ENV,
            self.deflate_level.to_string(),
        );
        let child = command
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
    assert_eq!(info["sandbox"]["available"], true, "{}", info["sandbox"]);
    let gaps = info["sandbox"]["gaps"].to_string();
    let expected = if cfg!(target_os = "macos") {
        "the metadata (not the listing or contents) of every directory above a grant is readable"
    } else {
        "a TCP socket can listen on an ephemeral port without bind"
    };
    assert!(gaps.contains(expected), "{gaps}");
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

/// What the control plane received between two readings.
fn since(before: Traffic, after: Traffic) -> Traffic {
    Traffic {
        frames: after.frames - before.frames,
        frame_bytes: after.frame_bytes - before.frame_bytes,
        wire_bytes: after.wire_bytes - before.wire_bytes,
    }
}

fn report(what: &str, t: Traffic) {
    println!(
        "{what}: {} frames, {} bytes as frames, {} bytes on the wire (ratio {:.3}; {:.1} -> {:.1} bytes per frame)",
        t.frames,
        t.frame_bytes,
        t.wire_bytes,
        t.wire_bytes as f64 / t.frame_bytes as f64,
        t.frame_bytes as f64 / t.frames as f64,
        t.wire_bytes as f64 / t.frames as f64,
    );
}

/// permessage-deflate is offered, accepted, and shrinks small frames and large ones, at
/// DEFLATE levels 1 and 6. Prints the byte counts against the raw frame sizes.
#[tokio::test]
async fn the_link_is_compressed_with_permessage_deflate() {
    for level in [1, 2, 6] {
        let mut node = Node::start_with(Options {
            deflate_level: level,
            ..Options::default()
        })
        .await;
        assert_eq!(
            node.cp.offered_extensions().as_deref(),
            Some(happy_supervisor::ws::DEFLATE_OFFER)
        );
        let accepted = node.cp.accepted_extensions().unwrap();
        assert_eq!(accepted, "permessage-deflate; client_max_window_bits=15");
        assert!(node.log().contains(&accepted), "{}", node.log());

        // Build output, one line per write: a run of small frames.
        let before = node.cp.received();
        let script = "i=0; while [ $i -lt 3000 ]; do \
            echo \"   Compiling crate-$i v0.1.$i (/home/me/repo/crates/crate-$i)\"; i=$((i+1)); done";
        node.ok("exec.start", sh("build", script, Path::new("/"), raw()))
            .await;
        let (_, stdout, _) = node.exit("build").await;
        assert_eq!(stdout.lines().count(), 3000);
        let build = since(before, node.cp.received());
        report(
            &format!("level {level}, build output, node -> control plane"),
            build,
        );

        let before = node.cp.received();
        for _ in 0..5 {
            node.ok("node.info", json!({})).await;
        }
        let info = since(before, node.cp.received());
        report(
            &format!("level {level}, 5 node.info replies, node -> control plane"),
            info,
        );
        report(
            &format!("level {level}, everything, control plane -> node"),
            node.cp.sent(),
        );

        assert!(build.wire_bytes * 10 < build.frame_bytes * 3, "{build:?}");
        assert!(info.wire_bytes * 10 < info.frame_bytes * 3, "{info:?}");
    }
}

#[tokio::test]
async fn a_control_plane_that_declines_compression_is_refused() {
    let node = Node::spawn(
        Options {
            deflate: false,
            ..Options::default()
        },
        false,
    )
    .await;
    let deadline = tokio::time::Instant::now() + WAIT;
    while !node.log().contains("did not accept permessage-deflate") {
        assert!(tokio::time::Instant::now() < deadline, "{}", node.log());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(node.cp.accepted_extensions(), None);
    assert_eq!(node.cp.session(), None);
}

/// 100 tiny commands while 16 MiB reads keep the link busy, with lanes and through one lane.
/// Prints both p99s. It measures time, so it runs alone: CI runs it in a step of its own, in
/// release. The control plane gets its own threads so that decoding the reads does not delay the
/// tiny commands on its side.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "timing: run alone with --ignored"]
async fn tiny_commands_stay_fast_beside_a_16_mib_read() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big");
    // Incompressible, so the reads keep the link busy.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let data: Vec<u8> = (0..16 << 20)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    std::fs::write(&big, &data).unwrap();
    let mut p99s = Vec::new();
    for single_lane in [false, true] {
        let node = if single_lane {
            Node::start_single_lane().await
        } else {
            Node::start().await
        };
        let stop = std::sync::atomic::AtomicBool::new(false);
        // Three reads in flight keep the node's side of the link busy. Four would pass the
        // 64 MiB budget of its outgoing queue and lose the session.
        let reader = || async {
            let mut reads = 0;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                // The reply stays CBOR: turning 16 MiB into a JSON literal would stall this task.
                let params = cbor(json!({ "path": path(&big), "access": raw() }));
                let read = node
                    .cp
                    .command("fs.read", params)
                    .await
                    .unwrap_or_else(|err| panic!("fs.read: {err}; node log:\n{}", node.log()));
                let size = read
                    .as_map()
                    .unwrap()
                    .iter()
                    .find(|(k, _)| k.as_text() == Some("size"));
                assert_eq!(size.unwrap().1.as_integer(), Some((16 << 20).into()));
                reads += 1;
            }
            reads
        };
        let bulk = async {
            let (a, b, c) = tokio::join!(reader(), reader(), reader());
            a + b + c
        };
        let tiny = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let mut latencies = Vec::new();
            for _ in 0..100 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                let started = std::time::Instant::now();
                node.ok(
                    "fs.stat",
                    json!({ "path": path(dir.path()), "access": raw() }),
                )
                .await;
                latencies.push(started.elapsed());
            }
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
            latencies
        };
        let (reads, mut latencies) = tokio::join!(bulk, tiny);
        latencies.sort();
        let (p50, p99) = (latencies[49], latencies[98]);
        println!(
            "{}: fs.stat p50 {:.1} ms, p99 {:.1} ms, max {:.1} ms beside {reads} reads of 16 MiB",
            if single_lane { "one lane" } else { "lanes" },
            p50.as_secs_f64() * 1000.0,
            p99.as_secs_f64() * 1000.0,
            latencies[99].as_secs_f64() * 1000.0,
        );
        assert!(reads >= 1);
        p99s.push(p99);
    }
    assert!(p99s[0] < Duration::from_millis(50), "{p99s:?}");
    assert!(p99s[0] * 10 < p99s[1], "{p99s:?}");
}

#[tokio::test]
async fn files_are_read_written_and_listed_raw_and_sandboxed() {
    let node = Node::start().await;
    let work = tempfile::tempdir().unwrap();
    let (open, closed) = (work.path().join("open"), work.path().join("closed"));
    std::fs::create_dir(&open).unwrap();
    std::fs::create_dir(&closed).unwrap();
    std::fs::write(closed.join("secret.txt"), "secret").unwrap();
    let file = |dir: &Path, name: &str| format!("{}/{name}", path(dir));

    for (label, access) in [("raw", raw()), ("sandboxed", node.sandboxed(&[], &[&open]))] {
        let target = file(&open, &format!("{label}.txt"));
        let written = json!({ "path": target, "access": access, "data": hex(b"hello\n"),
                              "mode": "create" });
        node.ok("fs.write", written.clone()).await;
        let again = node.call("fs.write", written).await.unwrap_err();
        assert_eq!(
            again.kind,
            happy_supervisor::ErrorKind::AlreadyExists,
            "{label}"
        );
        node.ok(
            "fs.write",
            json!({ "path": target, "access": access, "data": hex(b"world\n"), "mode": "append" }),
        )
        .await;
        let read = node
            .ok(
                "fs.read",
                json!({ "path": target, "access": access, "offset": 6 }),
            )
            .await;
        assert_eq!(
            read,
            json!({ "data": hex(b"world\n"), "size": 12 }),
            "{label}"
        );
        let stat = node
            .ok("fs.stat", json!({ "path": target, "access": access }))
            .await;
        assert_eq!(
            (stat["kind"].clone(), stat["size"].clone()),
            (json!("file"), json!(12))
        );
    }
    let listed = node
        .ok("fs.list", json!({ "path": path(&open), "access": raw() }))
        .await;
    let names: Vec<&str> = listed["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["raw.txt", "sandboxed.txt"]);

    let sandboxed = node.sandboxed(&[], &[&open]);
    let denied = node
        .call(
            "fs.read",
            json!({ "path": file(&closed, "secret.txt"), "access": sandboxed }),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.kind, happy_supervisor::ErrorKind::PermissionDenied);
    let denied = node
        .call(
            "fs.write",
            json!({ "path": file(&closed, "new.txt"), "access": sandboxed,
                    "data": hex(b"x"), "mode": "create" }),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.kind, happy_supervisor::ErrorKind::PermissionDenied);
    assert!(!closed.join("new.txt").exists());
    let secret = node
        .ok(
            "fs.read",
            json!({ "path": file(&closed, "secret.txt"), "access": raw() }),
        )
        .await;
    assert_eq!(secret["data"], hex(b"secret"));
}

#[tokio::test]
async fn a_watch_reports_a_new_file() {
    let mut node = Node::start().await;
    let work = tempfile::tempdir().unwrap();
    let dir = path(work.path());
    node.ok(
        "watch.start",
        json!({ "watchId": "w-1", "path": dir, "recursive": true,
                "access": node.sandboxed(&[work.path()], &[]) }),
    )
    .await;
    std::fs::write(work.path().join("new.txt"), "x").unwrap();
    let created = format!("{dir}/new.txt");
    let event = node
        .event(|e| match e {
            Event::WatchEvent(w) => match &w.body {
                happy_supervisor::protocol::WatchEventBody::Changes { changes } => {
                    changes.iter().any(|c| c.path == created)
                }
                _ => false,
            },
            _ => false,
        })
        .await;
    let Event::WatchEvent(event) = event else {
        unreachable!()
    };
    assert_eq!(event.watch_id.as_str(), "w-1");
    let listed = node.ok("watch.stop", json!({ "watchId": "w-1" })).await;
    assert_eq!(listed, json!({}));
}
