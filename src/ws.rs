//! The WebSocket under the link (api.md, Connection and Compression), on [`yawc`]: the node's
//! upgrade, which offers the subprotocol and permessage-deflate and reads back what the control
//! plane chose, and a [`Socket`] that writes one frame at a time while it keeps reading.
//!
//! Compression is RFC 7692 permessage-deflate with context takeover, done by yawc. Each
//! direction is one DEFLATE stream per connection, so a new connection starts fresh. Nothing
//! above this module sees it.

use std::future::poll_fn;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use futures_util::Sink;
use http::{HeaderValue, Request, StatusCode, header};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use sha1::{Digest as _, Sha1};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use url::Url;
use yawc::frame::OpCode;
use yawc::{HttpStream, Options, Role, WebSocket, WebSocketError};

use crate::protocol::MAX_FRAME_BYTES;

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

/// How a dial ended.
pub enum Dialed {
    Open(Box<Socket>),
    /// The upgrade was answered `401` or `403`.
    Refused(StatusCode),
}

/// Opens the link WebSocket to `endpoint` with `token` as a bearer credential: `wss://`, or
/// `ws://` for tests and local listeners, or `unix:PATH` for a local listener's socket (serve.md).
/// `Err` describes a failure worth retrying.
pub async fn dial(endpoint: &Url, token: &str) -> Result<Dialed, String> {
    let (io, host_header, target) = connect(endpoint).await?;
    let key = base64::engine::general_purpose::STANDARD.encode(uuid::Uuid::now_v7().as_bytes());
    let bearer = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| "the token is not a valid header value".to_string())?;
    let request = Request::get(target)
        .header(header::HOST, host_header)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header(header::SEC_WEBSOCKET_KEY, &key)
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .header(header::SEC_WEBSOCKET_PROTOCOL, SUBPROTOCOL)
        .header(header::SEC_WEBSOCKET_EXTENSIONS, DEFLATE_OFFER)
        .header(header::AUTHORIZATION, bearer)
        .body(Empty::<Bytes>::new())
        .map_err(|err| format!("bad request: {err}"))?;

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|err| format!("HTTP: {err}"))?;
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let mut response = sender
        .send_request(request)
        .await
        .map_err(|err| format!("HTTP: {err}"))?;
    let status = response.status();
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return Ok(Dialed::Refused(status));
    }
    if status != StatusCode::SWITCHING_PROTOCOLS {
        return Err(format!("the upgrade was answered {status}"));
    }
    let headers = response.headers();
    if headers
        .get(header::SEC_WEBSOCKET_ACCEPT)
        .map(|v| v.as_bytes())
        != Some(accept(&key).as_bytes())
    {
        return Err("the upgrade answered a wrong Sec-WebSocket-Accept".to_string());
    }
    let protocol = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok());
    if protocol != Some(SUBPROTOCOL) {
        return Err(format!(
            "the server selected subprotocol {protocol:?}, not {SUBPROTOCOL}"
        ));
    }
    let extensions = headers
        .get(header::SEC_WEBSOCKET_EXTENSIONS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if extensions.split(';').next().map(str::trim) != Some("permessage-deflate") {
        return Err(format!(
            "the server did not accept permessage-deflate (Sec-WebSocket-Extensions: {extensions:?})"
        ));
    }
    let upgraded = hyper::upgrade::on(&mut response)
        .await
        .map_err(|err| format!("upgrade: {err}"))?;
    let ws = WebSocket::from_stream_with_extensions(
        HttpStream::from(TokioIo::new(upgraded)),
        Role::Client,
        Some(&extensions),
        options(true, node_level()),
    )
    .map_err(|err| format!("WebSocket: {err}"))?;
    Ok(Dialed::Open(Box::new(Socket::new(ws, Some(extensions)))))
}

/// The stream to `endpoint`, its `Host` header and the request target.
async fn connect(endpoint: &Url) -> Result<(Box<dyn Io>, String, String), String> {
    #[cfg(unix)]
    if endpoint.scheme() == "unix" {
        let unix = tokio::net::UnixStream::connect(endpoint.path())
            .await
            .map_err(|err| format!("connecting to {}: {err}", endpoint.path()))?;
        return Ok((Box::new(unix), "localhost".to_string(), "/".to_string()));
    }
    let host = endpoint
        .host_str()
        .ok_or_else(|| format!("{endpoint} has no host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = endpoint
        .port_or_known_default()
        .ok_or_else(|| format!("{endpoint} has no port"))?;
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|err| format!("connecting: {err}"))?;
    let _ = tcp.set_nodelay(true);
    let io: Box<dyn Io> = match endpoint.scheme() {
        "wss" => {
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|err| format!("bad host {host}: {err}"))?;
            let tls = tokio_rustls::TlsConnector::from(tls_config()?)
                .connect(name, tcp)
                .await
                .map_err(|err| format!("TLS: {err}"))?;
            Box::new(tls)
        }
        _ => Box::new(tcp),
    };
    let host_header = match endpoint.port() {
        Some(port) => format!("{}:{port}", endpoint.host_str().unwrap_or_default()),
        None => endpoint.host_str().unwrap_or_default().to_string(),
    };
    Ok((
        io,
        host_header,
        endpoint[url::Position::BeforePath..].to_string(),
    ))
}

/// `Sec-WebSocket-Accept` for `key` (RFC 6455, 4.2.2).
pub fn accept(key: &str) -> String {
    let mut sha = Sha1::new();
    sha.update(key.as_bytes());
    sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(sha.finalize())
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// TLS trusting the platform's store (api.md, Joining).
fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            let native = rustls_native_certs::load_native_certs();
            let (added, _) = roots.add_parsable_certificates(native.certs);
            if added == 0 {
                return Err(format!(
                    "no trusted certificates in the platform store: {:?}",
                    native.errors
                ));
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|err| format!("TLS: {err}"))?
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Ok(Arc::new(config))
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
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
                "sandbox": { "mechanism": "none", "available": false, "reason": "test", "landlockAbi": null, "baselineRead": [] },
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
    fn the_accept_key_is_rfc_6455s() {
        assert_eq!(
            accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
