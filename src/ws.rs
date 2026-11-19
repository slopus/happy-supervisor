//! The WebSocket under the link (api.md, Connection and Compression), on [`yawc`]: the node's
//! upgrade, which offers the subprotocol and permessage-deflate and reads back what the control
//! plane chose, and a [`Socket`] that writes one frame at a time while it keeps reading.
//!
//! Compression is RFC 7692 permessage-deflate with context takeover, done by yawc. Each
//! direction is one DEFLATE stream per connection, so a new connection starts fresh. Nothing
//! above this module sees it.

use std::future::poll_fn;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::Sink;
use http::{HeaderValue, Request, StatusCode, header};
use http_body_util::Empty;
use tokio::io::{AsyncRead, AsyncWrite};
use yawc::frame::OpCode;
use yawc::{HttpStream, Options, WebSocket, WebSocketError};

use crate::protocol::MAX_FRAME_BYTES;

#[cfg(feature = "node")]
mod dial;
#[cfg(feature = "node")]
pub use dial::{Dialed, accept, dial};

/// The one link subprotocol. The control plane must select it.
pub const SUBPROTOCOL: &str = "happy-supervisor.v1";

/// The node's `Sec-WebSocket-Extensions` offer.
pub const DEFLATE_OFFER: &str = "permessage-deflate; client_max_window_bits";

/// The DEFLATE level of what this side sends. Measured with zlib-rs on the e2e traffic, level 2
/// compresses small frames as well as the default 6 and plaintext nearly as well, at 1.6 times its
/// speed. Level 1 is faster still but sends a fifth more on small frames and expands random bytes
/// by 5 % (docs/architecture.md, The link).
pub const DEFLATE_LEVEL: u32 = 2;

/// With the `testing` feature, the node compresses at the level in this variable instead, to
/// measure levels against each other.
#[cfg(feature = "testing")]
pub const DEFLATE_LEVEL_ENV: &str = "HAPPY_SUPERVISOR_DEFLATE_LEVEL";

/// The level the node compresses at: [`DEFLATE_LEVEL`], or with the `testing` feature the
/// [`DEFLATE_LEVEL_ENV`] override.
pub fn node_level() -> u32 {
    #[cfg(feature = "testing")]
    if let Some(level) = std::env::var(DEFLATE_LEVEL_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return level;
    }
    DEFLATE_LEVEL
}

/// yawc's settings for one side of a link connection: frames up to the frame limit, before and
/// after inflating, and, with `deflate`, permessage-deflate with context takeover. As a server
/// it answers the node's bare `client_max_window_bits` with 15, the full 32 KiB window; yawc
/// would otherwise pick 9, too small for one message to compress against the last.
pub fn options(deflate: bool, level: u32) -> Options {
    let options = Options::default()
        .with_max_payload_read(MAX_FRAME_BYTES)
        .with_max_read_buffer(MAX_FRAME_BYTES)
        .with_no_delay();
    if deflate {
        options
            .with_compression_level(yawc::CompressionLevel::new(level))
            .with_client_max_window_bits(15)
    } else {
        options.without_compression()
    }
}

/// Why [`upgrade`] refused a request: the status to answer, and a line for the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused {
    pub status: StatusCode,
    pub reason: &'static str,
}

/// Accepts a link WebSocket (api.md, Connecting): checks that the request offers
/// `happy-supervisor.v1` and permessage-deflate, and answers with both, compressing at `level`.
/// Authentication is the caller's, before this. Returns the response to send, and the socket
/// once the client has switched protocols.
pub fn upgrade<B>(
    request: &mut Request<B>,
    level: u32,
) -> Result<(http::Response<Empty<Bytes>>, Upgrading), Refused> {
    let refuse = |reason| Refused {
        status: StatusCode::BAD_REQUEST,
        reason,
    };
    let offered = |name, wanted: &dyn Fn(&str) -> bool| {
        request
            .headers()
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|item| wanted(item.trim()))
    };
    if !offered(header::SEC_WEBSOCKET_PROTOCOL, &|p| p == SUBPROTOCOL) {
        return Err(refuse("offer happy-supervisor.v1"));
    }
    if !offered(header::SEC_WEBSOCKET_EXTENSIONS, &|e| {
        e.starts_with("permessage-deflate")
    }) {
        return Err(refuse("permessage-deflate is required"));
    }
    let (response, upgrading) = WebSocket::upgrade_with_options(request, options(true, level))
        .map_err(|_| refuse("not a WebSocket upgrade"))?;
    let (mut parts, body) = response.into_parts();
    parts.headers.insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(SUBPROTOCOL),
    );
    let extensions = parts
        .headers
        .get(header::SEC_WEBSOCKET_EXTENSIONS)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    Ok((
        http::Response::from_parts(parts, body),
        Upgrading {
            upgrading,
            extensions,
        },
    ))
}

/// An accepted upgrade, until the client switches protocols.
pub struct Upgrading {
    upgrading: yawc::UpgradeFut,
    extensions: Option<String>,
}

impl Upgrading {
    pub async fn socket(self) -> Result<Socket, WebSocketError> {
        Ok(Socket::new(self.upgrading.await?, self.extensions))
    }
}

/// An open link WebSocket.
pub struct Socket<S = HttpStream> {
    ws: WebSocket<S>,
    /// The last frame was flushed and the socket can take another.
    writable: bool,
    /// The agreed `Sec-WebSocket-Extensions`, or `None` for an uncompressed connection.
    extensions: Option<String>,
    /// Which direction [`Socket::next`] polls first this time.
    read_first: bool,
    /// The code of the close frame the peer sent.
    peer_close: Option<u16>,
}

/// Each side pings a quiet connection this often, and drops one that stays silent for
/// [`DEAD_AFTER`] (api.md, Connecting).
pub const PING_EVERY: std::time::Duration = std::time::Duration::from_secs(15);
pub const DEAD_AFTER: std::time::Duration = std::time::Duration::from_secs(45);

/// The close code a listening node closes a connection with when a newer one takes over
/// (serve.md). A client that gets it does not redial.
pub const CLOSE_REPLACED: u16 = 4001;

/// What [`Socket::next`] waited for.
pub enum Event {
    /// The socket can take another frame.
    Writable,
    /// A binary message.
    Binary(Bytes),
    /// A text message, which the link refuses.
    Text,
    /// A ping or pong. Pings are answered by yawc.
    Control,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Socket<S> {
    /// `ws`, set up with `extensions` as agreed on the upgrade.
    pub fn new(ws: WebSocket<S>, extensions: Option<String>) -> Socket<S> {
        Socket {
            ws,
            writable: false,
            extensions,
            read_first: false,
            peer_close: None,
        }
    }

    /// The code of the close frame that ended the connection, if the peer sent one.
    pub fn peer_close_code(&self) -> Option<u16> {
        self.peer_close
    }

    /// The agreed `Sec-WebSocket-Extensions`, `None` when the connection is uncompressed.
    pub fn extensions(&self) -> Option<&str> {
        self.extensions.as_deref()
    }

    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// Writes one binary message. Only after [`Event::Writable`]; the next one comes once it
    /// is flushed.
    pub fn send(&mut self, payload: Vec<u8>) -> Result<(), WebSocketError> {
        self.start(yawc::Frame::binary(payload))
    }

    /// Writes a ping, like [`send`](Socket::send).
    pub fn ping(&mut self) -> Result<(), WebSocketError> {
        self.start(yawc::Frame::ping(Bytes::new()))
    }

    fn start(&mut self, frame: yawc::Frame) -> Result<(), WebSocketError> {
        debug_assert!(self.writable, "a frame is still being written");
        self.writable = false;
        std::pin::Pin::new(&mut self.ws).start_send(frame)
    }

    /// Waits for the socket to become writable or for a message, whichever comes first.
    /// `Err` is a closed or failed connection.
    pub async fn next(&mut self) -> Result<Event, WebSocketError> {
        poll_fn(|cx| self.poll_next(cx)).await
    }

    /// Polls both directions every time, starting with the one that did not go first last time,
    /// so a busy writer never stops the reader and a busy reader never stops the writer.
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, WebSocketError>> {
        self.read_first = !self.read_first;
        if self.read_first {
            if let Poll::Ready(read) = self.poll_read(cx) {
                return Poll::Ready(read);
            }
            self.poll_writable(cx)
        } else {
            if let Poll::Ready(writable) = self.poll_writable(cx) {
                return Poll::Ready(writable);
            }
            self.poll_read(cx)
        }
    }

    fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, WebSocketError>> {
        if self.writable {
            return Poll::Pending;
        }
        let mut ws = std::pin::Pin::new(&mut self.ws);
        if let Poll::Ready(flushed) = ws.as_mut().poll_flush(cx) {
            flushed?;
            if let Poll::Ready(ready) = ws.poll_ready(cx) {
                ready?;
                self.writable = true;
                return Poll::Ready(Ok(Event::Writable));
            }
        }
        Poll::Pending
    }

    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, WebSocketError>> {
        match self.ws.poll_next_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(frame)) => Poll::Ready(Ok(match frame.opcode() {
                OpCode::Binary => Event::Binary(frame.into_payload()),
                OpCode::Text => Event::Text,
                OpCode::Close => {
                    self.peer_close = frame.close_code().map(u16::from);
                    return Poll::Ready(Err(WebSocketError::ConnectionClosed));
                }
                _ => Event::Control,
            })),
        }
    }

    /// Sends a close frame with `code` and `reason`, waiting at most a second.
    pub async fn close_with(mut self, code: u16, reason: &str) {
        let close = async {
            let mut ws = std::pin::Pin::new(&mut self.ws);
            poll_fn(|cx| ws.as_mut().poll_ready(cx)).await?;
            ws.as_mut().start_send(yawc::Frame::close(
                yawc::close::CloseCode::from(code),
                reason.as_bytes(),
            ))?;
            poll_fn(|cx| ws.as_mut().poll_flush(cx)).await
        };
        let _ = tokio::time::timeout(Duration::from_secs(1), close).await;
    }

    /// Sends a close frame, waiting at most a second.
    pub async fn close(mut self) {
        let close = async {
            let mut ws = std::pin::Pin::new(&mut self.ws);
            poll_fn(|cx| ws.as_mut().poll_close(cx)).await
        };
        let _ = tokio::time::timeout(Duration::from_secs(1), close).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yawc::Role;

    use crate::link::{ManualClock, NodeIdentity, Session};
    use crate::protocol::{Bytes as Data, Event as LinkEvent, ProxyBody, ProxyMessage, StreamId};

    /// Moves frames between `session` and `socket` the way the drivers do: one frame written
    /// at a time, and the socket read while it is written. Returns once `done` holds.
    async fn drive<S: AsyncRead + AsyncWrite + Unpin>(
        session: &mut Session,
        socket: &mut Socket<S>,
        mut done: impl FnMut(&mut Session) -> bool,
    ) {
        loop {
            if done(session) {
                return;
            }
            if socket.is_writable()
                && let Some(frame) = session.poll_transmit()
            {
                socket.send(frame).unwrap();
                continue;
            }
            tokio::select! {
                event = socket.next() => match event.unwrap() {
                    Event::Binary(payload) => session.receive(&payload),
                    Event::Writable | Event::Control => {}
                    Event::Text => panic!("text"),
                },
                _ = session.changed() => {}
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => session.tick(),
            }
        }
    }

    /// Both sides flood each other through 4 KiB of buffer. A driver that stopped reading
    /// while it wrote would deadlock here.
    #[tokio::test]
    async fn both_sides_flooding_a_tiny_buffer_never_deadlock() {
        let (a, b) = tokio::io::duplex(4096);
        let offer = "permessage-deflate";
        let mut node_ws = Socket::new(
            WebSocket::from_stream_with_extensions(a, Role::Client, Some(offer), options(true, 1))
                .unwrap(),
            Some(offer.to_string()),
        );
        let mut cp_ws = Socket::new(
            WebSocket::from_stream_with_extensions(b, Role::Server, Some(offer), options(true, 1))
                .unwrap(),
            Some(offer.to_string()),
        );
        let clock = ManualClock::new(1_763_496_000_000);
        let identity = NodeIdentity {
            node_id: "n_1".to_string(),
            installation_id: "tz4a98xxat96iws9zmbrgj3a".to_string(),
        };
        let (mut node, node_out) = Session::new(crate::link::Role::Node(identity), clock.clone());
        let role = crate::link::Role::ControlPlane {
            resume_window_ms: 1000,
        };
        let (mut cp, cp_out) = Session::new(role, clock);
        node.connected();
        cp.connected();

        const CHUNKS: usize = 64;
        let flood = |out: &crate::link::Outbox, seed: u8| {
            for n in 0..CHUNKS {
                // Incompressible, so the buffer fills.
                let data = (0..60_000u32)
                    .map(|i| (i.wrapping_mul(2_654_435_761) >> (n % 7 + seed as usize)) as u8)
                    .collect();
                out.proxy(ProxyMessage::Body(ProxyBody {
                    stream_id: StreamId(uuid::Uuid::from_u128(seed as u128)),
                    data: Data(data),
                }));
            }
        };
        let received = |session: &mut Session, count: &mut usize| {
            while let Some(incoming) = session.poll_incoming() {
                if let crate::link::Incoming::Message { kind, body, .. } = incoming
                    && let Some(Ok(LinkEvent::Proxy(_))) = LinkEvent::parse(&kind, body)
                {
                    *count += 1;
                }
            }
            *count == CHUNKS
        };
        let info: crate::protocol::NodeInfo = crate::wire::from_value(crate::testkit::cbor(
            serde_json::json!({
                "installationId": "tz4a98xxat96iws9zmbrgj3a", "name": "box", "hostname": "box",
                "supervisorVersion": "0.1.0",
                "os": { "family": "linux", "name": null, "version": null, "kernelVersion": null, "arch": "x86_64" },
                "cpu": { "model": null, "physicalCores": null, "logicalCores": 1 },
                "memory": { "totalBytes": 1, "swapTotalBytes": 0 },
                "disks": [], "gpus": [],
                "sandbox": { "mechanism": "none", "available": false, "reason": "test", "baselineRead": [] },
                "defaultEnv": {}, "collectedAtMs": 0
            }),
        ))
        .unwrap();
        let (mut at_node, mut at_cp) = (0, 0);
        let (node_done, cp_done) = (std::cell::Cell::new(false), std::cell::Cell::new(false));
        let (mut node_flooded, mut cp_flooded) = (false, false);
        let both_done = async {
            while !(node_done.get() && cp_done.get()) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        };
        let flooded = async {
            tokio::select! {
                _ = drive(&mut node, &mut node_ws, |s| {
                    if !node_flooded && s.needs_ready() {
                        s.ready(info.clone(), vec![], vec![]).unwrap();
                        flood(&node_out, 1);
                        node_flooded = true;
                    }
                    node_done.set(received(s, &mut at_node));
                    false
                }) => {}
                _ = drive(&mut cp, &mut cp_ws, |s| {
                    if !cp_flooded && s.session().is_some() {
                        flood(&cp_out, 2);
                        cp_flooded = true;
                    }
                    cp_done.set(received(s, &mut at_cp));
                    false
                }) => {}
                _ = both_done => {}
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(20), flooded)
            .await
            .expect("the two sides deadlocked");
    }

    #[test]
    fn an_upgrade_needs_the_subprotocol_and_deflate() {
        let request = |protocol: &str, extensions: &str| {
            Request::get("/")
                .header(header::CONNECTION, "upgrade")
                .header(header::UPGRADE, "websocket")
                .header(header::SEC_WEBSOCKET_VERSION, "13")
                .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
                .header(header::SEC_WEBSOCKET_PROTOCOL, protocol)
                .header(header::SEC_WEBSOCKET_EXTENSIONS, extensions)
                .body(())
                .unwrap()
        };
        let refused = |reason| {
            Err::<(), _>(Refused {
                status: StatusCode::BAD_REQUEST,
                reason,
            })
        };
        let deflate = "permessage-deflate; client_max_window_bits";
        let mut other = request("chat", deflate);
        assert_eq!(
            upgrade(&mut other, 2).map(|_| ()),
            refused("offer happy-supervisor.v1")
        );
        let mut plain = request("x, happy-supervisor.v1", "");
        assert_eq!(
            upgrade(&mut plain, 2).map(|_| ()),
            refused("permessage-deflate is required")
        );
        let mut good = request("x, happy-supervisor.v1", deflate);
        let (response, _) = upgrade(&mut good, 2).unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        let header = |name| response.headers().get(name).unwrap().to_str().unwrap();
        assert_eq!(
            header(header::SEC_WEBSOCKET_PROTOCOL),
            "happy-supervisor.v1"
        );
        assert_eq!(
            header(header::SEC_WEBSOCKET_EXTENSIONS),
            "permessage-deflate; client_max_window_bits=15"
        );
    }

    #[cfg(feature = "node")]
    #[test]
    fn the_accept_key_is_rfc_6455s() {
        assert_eq!(
            accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
