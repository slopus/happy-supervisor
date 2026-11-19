//! TCP tunnels in-process, against real local servers, with the test playing the control
//! plane's end of each stream (docs/tunnels.md).

use std::time::Duration;

use happy_supervisor::ErrorKind;
use happy_supervisor::exec::TunnelRoute;
use happy_supervisor::protocol::{
    Bytes, LoopbackHost, ProxyMessage, StreamId, TcpCredit, TcpData, TcpEnd, TcpMessage,
    TcpOpenParams, TcpReset,
};
use happy_supervisor::proxy::{NodeCa, ProxyManager};
use happy_supervisor::streams::Upstream;
use happy_supervisor::tunnel::TunnelManager;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const WINDOW: usize = 1 << 20;

struct Channel(mpsc::UnboundedSender<TcpMessage>);

impl Upstream for Channel {
    fn proxy(&self, message: ProxyMessage) {
        panic!("a tunnel sent {message:?}");
    }

    fn tcp(&self, message: TcpMessage) {
        let _ = self.0.send(message);
    }
}

/// The node's tunnels and the control plane's end of their streams.
struct Harness {
    tunnels: TunnelManager,
    from_node: mpsc::UnboundedReceiver<TcpMessage>,
    _dir: tempfile::TempDir,
}

impl Harness {
    fn start() -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let (private, public) = (dir.path().join("private"), dir.path().join("public"));
        std::fs::create_dir(&private).unwrap();
        std::fs::create_dir(&public).unwrap();
        let (tx, from_node) = mpsc::unbounded_channel();
        let proxy = ProxyManager::new(
            Channel(tx),
            NodeCa::load_or_create(&private, &public).unwrap(),
        );
        Harness {
            tunnels: TunnelManager::new(&proxy),
            from_node,
            _dir: dir,
        }
    }

    async fn open(&self, port: u16) -> StreamId {
        let id = StreamId::generate();
        self.tunnels
            .open(params(id, LoopbackHost::V4, port), TunnelRoute::Loopback)
            .await
            .unwrap();
        id
    }

    async fn next(&mut self) -> TcpMessage {
        tokio::time::timeout(Duration::from_secs(20), self.from_node.recv())
            .await
            .expect("the node sent nothing for 20 s")
            .unwrap()
    }

    fn send(&self, message: TcpMessage) {
        self.tunnels.on_event(message);
    }

    fn data(&self, id: StreamId, data: &[u8]) {
        self.send(TcpMessage::Data(TcpData {
            stream_id: id,
            data: Bytes(data.to_vec()),
        }));
    }

    fn end(&self, id: StreamId) {
        self.send(TcpMessage::End(TcpEnd { stream_id: id }));
    }

    /// Reads the node's bytes up to `tcp.end`, crediting them, and skipping credit for ours.
    async fn read_to_end(&mut self, id: StreamId) -> Vec<u8> {
        let mut received = Vec::new();
        loop {
            match self.next().await {
                TcpMessage::Data(TcpData { stream_id, data }) if stream_id == id => {
                    self.send(TcpMessage::Credit(TcpCredit {
                        stream_id: id,
                        bytes: data.0.len() as u64,
                    }));
                    received.extend_from_slice(&data.0);
                }
                TcpMessage::Credit(_) => {}
                TcpMessage::End(TcpEnd { stream_id }) if stream_id == id => return received,
                other => panic!("expected the bytes of {id}, got {other:?}"),
            }
        }
    }
}

fn params(id: StreamId, host: LoopbackHost, port: u16) -> TcpOpenParams {
    TcpOpenParams {
        stream_id: id,
        host,
        port,
        exec_id: None,
    }
}

/// A server that reads everything, then writes `prefix` and what it read, then closes.
async fn echo_after_eof(prefix: &'static [u8]) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut read = Vec::new();
        tcp.read_to_end(&mut read).await.unwrap();
        tcp.write_all(prefix).await.unwrap();
        tcp.write_all(&read).await.unwrap();
        read
    });
    (port, server)
}

async fn accept_one() -> (u16, tokio::task::JoinHandle<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (
        port,
        tokio::spawn(async move { listener.accept().await.unwrap().0 }),
    )
}

#[tokio::test]
async fn bytes_cross_in_both_directions_and_each_end_is_a_half_close() {
    let mut h = Harness::start();
    let (port, server) = echo_after_eof(b"you sent: ").await;
    let id = h.open(port).await;
    h.data(id, b"hello ");
    h.data(id, b"tunnel");
    h.end(id);
    assert_eq!(h.read_to_end(id).await, b"you sent: hello tunnel");
    assert_eq!(server.await.unwrap(), b"hello tunnel");
}

#[tokio::test]
async fn data_is_credited_once_written_to_the_local_socket() {
    let mut h = Harness::start();
    let (port, server) = accept_one().await;
    let id = h.open(port).await;
    let mut local = server.await.unwrap();
    h.data(id, b"0123456789");
    let mut got = [0; 10];
    local.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"0123456789");
    assert_eq!(
        h.next().await,
        TcpMessage::Credit(TcpCredit {
            stream_id: id,
            bytes: 10
        })
    );
}

#[tokio::test]
async fn data_sent_right_behind_the_open_is_buffered_until_connected() {
    let mut h = Harness::start();
    let (port, server) = echo_after_eof(b"").await;
    let id = StreamId::generate();
    let tunnels = h.tunnels.clone();
    let open = tunnels.open(params(id, LoopbackHost::V4, port), TunnelRoute::Loopback);
    tokio::pin!(open);
    let opened = futures_util::poll!(&mut open);
    h.data(id, b"early");
    h.end(id);
    assert!(opened.is_pending(), "the data arrived while connecting");
    open.await.unwrap();
    assert_eq!(h.read_to_end(id).await, b"early");
    assert_eq!(server.await.unwrap(), b"early");
}

#[tokio::test]
async fn localhost_reaches_an_ipv4_only_server() {
    let mut h = Harness::start();
    let (port, server) = echo_after_eof(b"v4").await;
    let id = StreamId::generate();
    h.tunnels
        .open(
            params(id, LoopbackHost::Localhost, port),
            TunnelRoute::Loopback,
        )
        .await
        .unwrap();
    h.end(id);
    assert_eq!(h.read_to_end(id).await, b"v4");
    server.await.unwrap();
}

#[tokio::test]
async fn a_closed_port_is_connection_refused_and_leaves_no_stream() {
    let h = Harness::start();
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let id = StreamId::generate();
    let err = h
        .tunnels
        .open(params(id, LoopbackHost::V4, port), TunnelRoute::Loopback)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::ConnectionRefused);
    assert_eq!(
        err.message,
        format!("127.0.0.1:{port} refused the connection")
    );
    let (port, _server) = accept_one().await;
    h.tunnels
        .open(params(id, LoopbackHost::V4, port), TunnelRoute::Loopback)
        .await
        .expect("the failed open left nothing behind");
}

#[tokio::test]
async fn an_id_in_use_is_already_exists() {
    let h = Harness::start();
    let (port, _server) = accept_one().await;
    let id = h.open(port).await;
    let err = h
        .tunnels
        .open(params(id, LoopbackHost::V4, port), TunnelRoute::Loopback)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AlreadyExists);
}

#[tokio::test]
async fn a_reset_from_the_control_plane_resets_the_local_connection() {
    let h = Harness::start();
    let (port, server) = accept_one().await;
    let id = h.open(port).await;
    let mut local = server.await.unwrap();
    h.send(TcpMessage::Reset(TcpReset {
        stream_id: id,
        reason: "client went away".into(),
    }));
    let mut buf = [0; 1];
    let err = local.read(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn a_local_reset_sends_tcp_reset() {
    let mut h = Harness::start();
    let (port, server) = accept_one().await;
    let id = h.open(port).await;
    let local = server.await.unwrap();
    #[allow(deprecated)]
    local.set_linger(Some(Duration::ZERO)).unwrap();
    drop(local);
    match h.next().await {
        TcpMessage::Reset(TcpReset { stream_id, reason }) => {
            assert_eq!(stream_id, id);
            assert!(
                reason.starts_with("reading the local socket failed: "),
                "{reason}"
            );
        }
        other => panic!("expected tcp.reset, got {other:?}"),
    }
}

#[tokio::test]
async fn the_node_stops_reading_when_the_window_is_empty() {
    let mut h = Harness::start();
    let (port, server) = accept_one().await;
    let id = h.open(port).await;
    let mut local = server.await.unwrap();
    let upload: Vec<u8> = (0..3 * WINDOW).map(|i| (i % 251) as u8).collect();
    let writer = {
        let upload = upload.clone();
        tokio::spawn(async move {
            local.write_all(&upload).await.unwrap();
            local.shutdown().await.unwrap();
            local
        })
    };
    let mut received = Vec::new();
    while received.len() < WINDOW {
        match h.next().await {
            TcpMessage::Data(data) => received.extend_from_slice(&data.data.0),
            other => panic!("expected tcp.data, got {other:?}"),
        }
    }
    assert_eq!(
        received.len(),
        WINDOW,
        "exactly one window before any credit"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        h.from_node.try_recv().is_err(),
        "the node paused without credit"
    );

    h.send(TcpMessage::Credit(TcpCredit {
        stream_id: id,
        bytes: WINDOW as u64,
    }));
    received.extend(h.read_to_end(id).await);
    assert!(received == upload, "every byte, in order");
    writer.await.unwrap();
}

#[tokio::test]
async fn a_lost_session_resets_every_tunnel() {
    let h = Harness::start();
    let (port, server) = accept_one().await;
    h.open(port).await;
    let mut local = server.await.unwrap();
    h.tunnels.session_lost();
    let mut buf = [0; 1];
    let err = local.read(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
}
