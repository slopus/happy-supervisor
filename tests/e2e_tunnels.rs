//! TCP tunnels through the real binary: `happy-supervisor run` against `testing::ControlPlane`,
//! reaching servers that a raw command started on the node's loopback (docs/tunnels.md).
#![cfg(unix)]

use std::process::Stdio;
use std::time::{Duration, Instant};

use happy_supervisor::ErrorKind;
use happy_supervisor::protocol::{
    Bytes, Event, ExecOutput, StreamId, TcpCredit, TcpData, TcpEnd, TcpMessage, TcpReset,
};
use happy_supervisor::testing::{ControlPlane, Options};
use happy_supervisor::testkit::{cbor, json};
use serde_json::{Value as Json, json};
use tokio::process::{Child, Command};

const BIN: &str = env!("CARGO_BIN_EXE_happy-supervisor");
const WAIT: Duration = Duration::from_secs(60);
const WINDOW: u64 = 1 << 20;
const CHUNK: usize = 64 << 10;

/// `echo` writes back what it reads, `trailer` reads to EOF and then reports the count, `sink`
/// never reads. Each prints its port, then serves connections until killed, and prints `reset`
/// when a client resets one.
const SERVER: &str = r#"
import os, socket, sys, threading
mode = sys.argv[1]
threading.Timer(300, lambda: os._exit(0)).start()
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(128)
print(listener.getsockname()[1], flush=True)
def serve(conn):
    try:
        if mode == "sink":
            threading.Event().wait()
        count = 0
        while True:
            data = conn.recv(65536)
            if not data:
                break
            count += len(data)
            if mode == "echo":
                conn.sendall(data)
        if mode == "trailer":
            conn.sendall(b"trailer after %d bytes" % count)
        conn.shutdown(socket.SHUT_WR)
        conn.close()
    except ConnectionResetError:
        print("reset", flush=True)
while True:
    conn, _ = listener.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
"#;

/// A joined node running against its own control plane.
struct Node {
    cp: ControlPlane,
    dir: tempfile::TempDir,
    _child: Child,
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
        let state = dir.path().join("state");
        let joined = Command::new(BIN)
            .args(["join", "--url", &cp.join_url()])
            .env("HAPPY_JOIN_TOKEN", cp.issue_join_token())
            .args(["--name", "tunnel-node", "--state-dir"])
            .arg(&state)
            .output()
            .await
            .unwrap();
        assert!(joined.status.success(), "join failed: {joined:?}");
        let log = std::fs::File::create(dir.path().join("run.log")).unwrap();
        let child = Command::new(BIN)
            .env(
                happy_supervisor::ws::DEFLATE_LEVEL_ENV,
                options.deflate_level.to_string(),
            )
            .arg("run")
            .arg("--state-dir")
            .arg(&state)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut node = Node {
            cp,
            dir,
            _child: child,
            seen: Vec::new(),
        };
        node.event(|e| matches!(e, Event::NodeReady(_))).await;
        node
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

    async fn next_event(&self) -> Event {
        tokio::time::timeout(WAIT, self.cp.next_event())
            .await
            .unwrap_or_else(|_| panic!("no event for {WAIT:?}; node log:\n{}", self.log()))
            .unwrap()
    }

    /// The first event, seen before or arriving now, that `wanted` accepts.
    async fn event(&mut self, wanted: impl Fn(&Event) -> bool) -> Event {
        if let Some(at) = self.seen.iter().position(&wanted) {
            return self.seen.remove(at);
        }
        loop {
            let event = self.next_event().await;
            if wanted(&event) {
                return event;
            }
            self.seen.push(event);
        }
    }

    /// Starts [`SERVER`] in `mode` as a raw command and returns its port.
    async fn server(&mut self, exec_id: &str, mode: &str) -> u16 {
        self.ok(
            "exec.start",
            json!({ "execId": exec_id, "argv": ["/usr/bin/env", "python3", "-c", SERVER, mode],
                    "cwd": "/", "env": { "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin" },
                    "access": { "mode": "raw" } }),
        )
        .await;
        let line = self.stdout_line(exec_id).await;
        line.parse()
            .unwrap_or_else(|_| panic!("{exec_id} printed {line:?}"))
    }

    async fn stdout_line(&mut self, exec_id: &str) -> String {
        let event = self
            .event(|e| matches!(e, Event::ExecOutput(o) if o.exec_id.as_str() == exec_id))
            .await;
        let Event::ExecOutput(ExecOutput { data, .. }) = event else {
            unreachable!()
        };
        String::from_utf8(data.0).unwrap().trim().to_string()
    }

    async fn kill(&self, exec_id: &str) {
        self.ok("exec.kill", json!({ "execId": exec_id, "signal": "kill" }))
            .await;
    }

    async fn open(&self, port: u16) -> StreamId {
        let id = StreamId::generate();
        self.ok("tcp.open", open_body(id, port)).await;
        id
    }

    /// Carries every pipe to completion as the control plane's end: sends each one's bytes in
    /// 64 KiB pieces, one piece per pipe in turn, within the windows the node credits, then
    /// `tcp.end`; credits what the node sends; returns once the node ended every pipe.
    /// `progress` sees the bytes received so far after each piece.
    async fn carry(&mut self, pipes: &mut [Pipe], mut progress: impl FnMut(&ControlPlane, usize)) {
        loop {
            let mut sent_some = true;
            while sent_some {
                sent_some = false;
                for pipe in pipes.iter_mut() {
                    sent_some |= pipe.send_one(&self.cp);
                }
            }
            if pipes.iter().all(|p| p.ended && p.end_sent) {
                return;
            }
            match self.next_event().await {
                Event::Tcp(message) => {
                    let pipe = pipes
                        .iter_mut()
                        .find(|p| p.id == message.stream_id())
                        .unwrap_or_else(|| panic!("a message for no pipe: {message:?}"));
                    pipe.receive(&self.cp, message);
                    progress(&self.cp, pipes.iter().map(|p| p.received.len()).sum());
                }
                other => self.seen.push(other),
            }
        }
    }
}

fn open_body(id: StreamId, port: u16) -> Json {
    json!({ "streamId": hex(id.0.as_bytes()), "host": "127.0.0.1", "port": port })
}

fn hex(data: &[u8]) -> String {
    let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
    format!("h'{hex}'")
}

/// The control plane's end of one tunnel.
struct Pipe {
    id: StreamId,
    outgoing: Vec<u8>,
    sent: usize,
    /// How much more the node accepts before crediting.
    window: u64,
    credited: u64,
    end_sent: bool,
    received: Vec<u8>,
    ended: bool,
}

impl Pipe {
    fn new(id: StreamId, outgoing: Vec<u8>) -> Pipe {
        Pipe {
            id,
            outgoing,
            sent: 0,
            window: WINDOW,
            credited: 0,
            end_sent: false,
            received: Vec::new(),
            ended: false,
        }
    }

    fn send_one(&mut self, cp: &ControlPlane) -> bool {
        let n = (self.outgoing.len() - self.sent)
            .min(CHUNK)
            .min(self.window as usize);
        if n > 0 {
            cp.send_tcp(TcpMessage::Data(TcpData {
                stream_id: self.id,
                data: Bytes::new(self.outgoing[self.sent..self.sent + n].to_vec()),
            }));
            self.sent += n;
            self.window -= n as u64;
            return true;
        }
        if self.sent == self.outgoing.len() && !self.end_sent {
            cp.send_tcp(TcpMessage::End(TcpEnd { stream_id: self.id }));
            self.end_sent = true;
            return true;
        }
        false
    }

    fn receive(&mut self, cp: &ControlPlane, message: TcpMessage) {
        match message {
            TcpMessage::Data(TcpData { data, .. }) => {
                cp.send_tcp(TcpMessage::Credit(TcpCredit {
                    stream_id: self.id,
                    bytes: data.0.len() as u64,
                }));
                self.received.extend_from_slice(&data.0);
            }
            TcpMessage::Credit(TcpCredit { bytes, .. }) => {
                self.window += bytes;
                self.credited += bytes;
            }
            TcpMessage::End(_) => self.ended = true,
            TcpMessage::Reset(TcpReset { reason, .. }) => panic!("{} was reset: {reason}", self.id),
        }
    }
}

/// Bytes that do not compress, different for every `seed`.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[tokio::test]
async fn eight_concurrent_tunnels_echo_every_byte_in_order() {
    let mut node = Node::start().await;
    let port = node.server("echo", "echo").await;
    let mut pipes = Vec::new();
    for seed in 0..8 {
        pipes.push(Pipe::new(node.open(port).await, noise(seed, 4 << 20)));
    }
    node.carry(&mut pipes, |_, _| {}).await;
    for pipe in &pipes {
        assert_eq!(pipe.received.len(), pipe.outgoing.len());
        assert!(
            pipe.received == pipe.outgoing,
            "{} echoed out of order",
            pipe.id
        );
    }
    node.kill("echo").await;
}

#[tokio::test]
async fn a_half_closed_tunnel_still_receives_the_servers_last_bytes() {
    let mut node = Node::start().await;
    let port = node.server("trailer", "trailer").await;
    let id = node.open(port).await;
    let mut pipes = [Pipe::new(id, b"twelve bytes".to_vec())];
    node.carry(&mut pipes, |_, _| {}).await;
    assert_eq!(pipes[0].received, b"trailer after 12 bytes");
    node.kill("trailer").await;
}

#[tokio::test]
async fn a_closed_port_is_connection_refused() {
    let node = Node::start().await;
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let err = node
        .call("tcp.open", open_body(StreamId::generate(), port))
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::ConnectionRefused);
    let err = node
        .call(
            "tcp.open",
            json!({ "streamId": hex(StreamId::generate().0.as_bytes()), "host": "10.0.0.1", "port": 80 }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidParams);
}

#[tokio::test]
async fn an_exec_id_routes_to_that_process_if_it_may_bind() {
    let mut node = Node::start().await;
    let port = node.server("srv", "echo").await;
    let id = StreamId::generate();
    let mut body = open_body(id, port);
    body["execId"] = json!("srv");
    assert_eq!(node.ok("tcp.open", body).await, json!({}));

    let mut body = open_body(StreamId::generate(), port);
    body["execId"] = json!("nope");
    let err = node.call("tcp.open", body).await.unwrap_err();
    assert_eq!(
        (err.kind, err.message.as_str()),
        (ErrorKind::NotFound, "nope is not running")
    );

    let no_bind = json!({ "mode": "sandboxed", "policy": {
        "filesystem": {
            "read": { "default": "deny", "allow": ["/"], "deny": [] },
            "write": { "default": "deny", "allow": [], "deny": [] }
        },
        "network": { "mode": "host", "localBind": false, "unixSockets": false } } });
    node.ok(
        "exec.start",
        json!({ "execId": "confined", "argv": ["/bin/sleep", "30"], "cwd": "/", "env": {},
                "access": no_bind }),
    )
    .await;
    let mut body = open_body(StreamId::generate(), port);
    body["execId"] = json!("confined");
    let err = node.call("tcp.open", body).await.unwrap_err();
    assert_eq!(
        (err.kind, err.message.as_str()),
        (
            ErrorKind::PermissionDenied,
            "confined's policy does not allow localBind"
        )
    );
    node.kill("confined").await;
    node.kill("srv").await;
}

/// A local server that stops reading holds the node to one window of the control plane's
/// bytes: the node credits only what it wrote, and the session carries on.
#[tokio::test]
async fn a_server_that_stops_reading_holds_the_tunnel_at_one_window() {
    let mut node = Node::start().await;
    let session = node.cp.session();
    let port = node.server("sink", "sink").await;
    let id = node.open(port).await;
    let mut pipe = Pipe::new(id, noise(1, 64 << 20));
    loop {
        while pipe.send_one(&node.cp) {}
        match tokio::time::timeout(Duration::from_secs(1), node.cp.next_event()).await {
            Ok(event) => match event.unwrap() {
                Event::Tcp(message) => pipe.receive(&node.cp, message),
                other => node.seen.push(other),
            },
            Err(_) => break,
        }
    }
    assert!(
        pipe.sent < pipe.outgoing.len(),
        "the server's socket buffers filled"
    );
    assert_eq!(pipe.sent as u64 - pipe.credited, WINDOW);
    assert_eq!(pipe.window, 0);
    assert_eq!(
        node.ok("exec.list", json!({})).await["execs"][0]["execId"],
        "sink"
    );
    assert_eq!(node.cp.session(), session);
    node.kill("sink").await;
}

#[tokio::test]
async fn tunnels_survive_a_dropped_connection_intact() {
    let mut node = Node::start().await;
    let session = node.cp.session();
    let port = node.server("echo", "echo").await;
    let mut pipes = Vec::new();
    for seed in 0..2 {
        pipes.push(Pipe::new(node.open(port).await, noise(seed, 4 << 20)));
    }
    let mut dropped = 0;
    node.carry(&mut pipes, |cp, received| {
        if dropped < 2 && received > (dropped + 1) * (2 << 20) {
            cp.drop_connection();
            dropped += 1;
        }
    })
    .await;
    assert_eq!(dropped, 2);
    for pipe in &pipes {
        assert!(
            pipe.received == pipe.outgoing,
            "{} lost or reordered bytes",
            pipe.id
        );
    }
    assert_eq!(node.cp.session(), session);
    assert!(!node.seen.iter().any(|e| matches!(e, Event::NodeReady(_))));
    node.kill("echo").await;
}

#[tokio::test]
async fn a_lost_session_resets_every_tunnel() {
    let mut node = Node::start().await;
    let port = node.server("echo", "echo").await;
    let id = node.open(port).await;
    let mut pipe = Pipe::new(id, b"ping".to_vec());
    pipe.send_one(&node.cp);
    while pipe.received.len() < 4 {
        match node.next_event().await {
            Event::Tcp(message) => pipe.receive(&node.cp, message),
            other => node.seen.push(other),
        }
    }
    assert_eq!(pipe.received, b"ping");

    node.cp.forget_session();
    node.event(|e| matches!(e, Event::NodeReady(_))).await;
    assert_eq!(node.stdout_line("echo").await, "reset");
    node.ok("tcp.open", open_body(id, port)).await;
    node.kill("echo").await;
}

/// What a dev server serves, as plaintext: this repository's sources, tests, docs and lockfile,
/// repeated to `len` bytes.
fn plaintext(len: usize) -> Vec<u8> {
    fn walk(dir: &std::path::Path, out: &mut Vec<u8>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.extend(std::fs::read(&path).unwrap());
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut corpus = Vec::new();
    for dir in ["src", "tests", "docs"] {
        walk(&root.join(dir), &mut corpus);
    }
    for file in ["Cargo.toml", "Cargo.lock"] {
        corpus.extend(std::fs::read(root.join(file)).unwrap());
    }
    corpus.iter().copied().cycle().take(len).collect()
}

/// One tunnel echoing plaintext, then random bytes as the worst case, at DEFLATE levels 1 and 6.
/// Prints the throughput and the bytes on the wire against the frames' own size.
#[tokio::test]
async fn throughput_of_one_tunnel() {
    let payloads = [
        ("plaintext (sources, docs, lockfile)", plaintext(16 << 20)),
        ("random bytes (worst case)", noise(7, 16 << 20)),
    ];
    for (what, data) in &payloads {
        for level in [1, 2, 6] {
            let mut node = Node::start_with(Options {
                deflate_level: level,
                ..Options::default()
            })
            .await;
            let port = node.server("echo", "echo").await;
            let mut pipes = [Pipe::new(node.open(port).await, data.clone())];
            let (sent, received) = (node.cp.sent(), node.cp.received());
            let started = Instant::now();
            node.carry(&mut pipes, |_, _| {}).await;
            let elapsed = started.elapsed().as_secs_f64();
            assert!(pipes[0].received == pipes[0].outgoing);
            let (sent_now, received_now) = (node.cp.sent(), node.cp.received());
            let ratio = |wire: u64, frames: u64| wire as f64 / frames as f64;
            println!(
                "tunnel, {what}, level {level}: {:.1} MiB/s each way ({} MiB echoed in {elapsed:.2} s); \
                 to the node {} wire / {} frame bytes ({:.3}), from the node {} / {} ({:.3})",
                (data.len() >> 20) as f64 / elapsed,
                data.len() >> 20,
                sent_now.wire_bytes - sent.wire_bytes,
                sent_now.frame_bytes - sent.frame_bytes,
                ratio(
                    sent_now.wire_bytes - sent.wire_bytes,
                    sent_now.frame_bytes - sent.frame_bytes
                ),
                received_now.wire_bytes - received.wire_bytes,
                received_now.frame_bytes - received.frame_bytes,
                ratio(
                    received_now.wire_bytes - received.wire_bytes,
                    received_now.frame_bytes - received.frame_bytes
                ),
            );
            node.kill("echo").await;
        }
    }
}
