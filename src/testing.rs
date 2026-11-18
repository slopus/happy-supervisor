//! An in-process control plane for tests (docs/architecture.md, Testing), behind the `testing`
//! feature. Owned by the transport track; the scaffold froze the API below. It speaks the link
//! protocol through [`link::Session`](crate::link::Session) with
//! [`Role::ControlPlane`](crate::link::Role::ControlPlane): one session, for one node at a time.
//!
//! The fault hooks only move or drop frames and call the session. Every protocol rule stays in
//! `link`.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::serve::{IncomingStream, Listener};
use axum::{Json, Router};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use crate::error::{Error, ErrorKind, Result};
use crate::link::{Clock, Incoming, Outbox, Role, Session, SystemClock};
use crate::protocol::{
    ByeReason, Event, Frame, JoinError, JoinRequest, JoinResponse, MsgId, NodeInfo, ProxyMessage,
    SessionId, TcpMessage, Value,
};
use crate::wire::from_cbor;
use crate::ws::{SUBPROTOCOL, Socket};

const JOIN_PATH: &str = "/api/nodes/join";
const CONNECT_PATH: &str = "/nodes/connect";
const PING_EVERY: Duration = Duration::from_secs(15);

/// api.md's join endpoint and the WebSocket endpoint it hands out, served by axum on
/// `127.0.0.1:0`.
pub struct ControlPlane {
    addr: SocketAddr,
    shared: Arc<Shared>,
    control: mpsc::UnboundedSender<Control>,
    events: tokio::sync::Mutex<mpsc::UnboundedReceiver<Event>>,
    opened: watch::Receiver<Option<SessionId>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// How the control plane is set up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// Accept the node's permessage-deflate offer. A control plane that declines it is refused
    /// by the node (api.md, Compression); `false` exists to test that.
    pub deflate: bool,
    /// The DEFLATE level of what the control plane sends.
    pub deflate_level: u32,
    /// The `resumeWindowMs` of `welcome`.
    pub resume_window_ms: u64,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            deflate: true,
            deflate_level: crate::ws::DEFLATE_LEVEL,
            resume_window_ms: 300_000,
        }
    }
}

/// One accepted join.
#[derive(Clone, Debug, PartialEq)]
pub struct JoinRecord {
    pub join_token: String,
    pub installation_id: String,
    pub name: String,
    pub info: NodeInfo,
    pub node_id: String,
    pub node_token: String,
}

/// Frames in one direction since the control plane started: their count, their bytes as frames
/// (ID and CBOR body, before compression), and the bytes their WebSocket connections carried
/// over TCP, upgrade requests and WebSocket framing included.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub frames: u64,
    pub frame_bytes: u64,
    pub wire_bytes: u64,
}

struct Shared {
    port: u16,
    options: Options,
    join_tokens: Mutex<HashSet<String>>,
    joins: Mutex<Vec<JoinRecord>>,
    revoked: Mutex<HashSet<String>>,
    /// Frames and their bytes, by direction. Wire bytes come from `meters`.
    received: Mutex<(u64, u64)>,
    sent: Mutex<(u64, u64)>,
    /// The TCP byte counts of every WebSocket connection so far.
    meters: Mutex<Vec<Meter>>,
    /// The node's last `Sec-WebSocket-Extensions` offer, and this side's answer.
    offered: Mutex<Option<String>>,
    accepted: Mutex<Option<String>>,
    stray_replies: AtomicUsize,
    sockets: mpsc::UnboundedSender<Box<Socket>>,
}

enum Control {
    Command {
        kind: String,
        body: Value,
        reply: oneshot::Sender<Result<Value>>,
    },
    Proxy(ProxyMessage),
    Tcp(TcpMessage),
    DropConnection,
    StallAcks(bool),
    Forget,
    ResumeWindow(u64),
    Revoke,
}

impl ControlPlane {
    pub async fn start() -> Result<ControlPlane> {
        ControlPlane::start_with(Options::default()).await
    }

    pub async fn start_with(options: Options) -> Result<ControlPlane> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let listener = Metered(listener);
        let (sockets_tx, sockets_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            port: addr.port(),
            options,
            join_tokens: Mutex::default(),
            joins: Mutex::default(),
            revoked: Mutex::default(),
            received: Mutex::default(),
            sent: Mutex::default(),
            meters: Mutex::default(),
            offered: Mutex::default(),
            accepted: Mutex::default(),
            stray_replies: AtomicUsize::new(0),
            sockets: sockets_tx,
        });
        let app = Router::new()
            .route(JOIN_PATH, post(join))
            .route(CONNECT_PATH, get(connect))
            .with_state(shared.clone());
        let server = tokio::spawn(async move {
            let app = app.into_make_service_with_connect_info::<Meter>();
            if let Err(err) = axum::serve(listener, app).await {
                tracing::error!("the test control plane stopped serving: {err}");
            }
        });

        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let role = Role::ControlPlane {
            resume_window_ms: options.resume_window_ms,
        };
        let (session, outbox) = Session::new(role, clock.clone());
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let (opened_tx, opened_rx) = watch::channel(None);
        let actor = Actor {
            shared: shared.clone(),
            session,
            outbox,
            clock,
            socket: None,
            stall_acks: false,
            pending: HashMap::new(),
            events: events_tx,
            opened: opened_tx,
        };
        let actor = tokio::spawn(actor.run(sockets_rx, control_rx));
        Ok(ControlPlane {
            addr,
            shared,
            control: control_tx,
            events: tokio::sync::Mutex::new(events_rx),
            opened: opened_rx,
            tasks: vec![server, actor],
        })
    }

    /// `http://127.0.0.1:<port>/…/join`, for `join --url`.
    pub fn join_url(&self) -> String {
        format!("http://{}{JOIN_PATH}", self.addr)
    }

    /// The `ws://127.0.0.1:<port>/…` endpoint that joins answer with.
    pub fn endpoint(&self) -> String {
        endpoint(self.shared.port)
    }

    /// A fresh single-use join token.
    pub fn issue_join_token(&self) -> String {
        let token = format!("jt_{}", cuid2::create_id());
        lock(&self.shared.join_tokens).insert(token.clone());
        token
    }

    pub fn joins(&self) -> Vec<JoinRecord> {
        lock(&self.shared.joins).clone()
    }

    /// Sends a command to the connected node, waiting for it to connect first, and waits for
    /// the reply. An `error` reply becomes the `Err`, and so does losing the session first.
    pub async fn command(&self, kind: &str, body: Value) -> Result<Value> {
        let mut opened = self.opened.clone();
        opened
            .wait_for(Option::is_some)
            .await
            .map_err(|_| stopped())?;
        let (reply, replied) = oneshot::channel();
        self.send(Control::Command {
            kind: kind.to_string(),
            body,
            reply,
        });
        replied.await.map_err(|_| stopped())?
    }

    /// The next event from the node, `node.ready` and `proxy.*` stream messages
    /// ([`Event::Proxy`]) included.
    pub async fn next_event(&self) -> Result<Event> {
        self.events.lock().await.recv().await.ok_or_else(stopped)
    }

    /// Sends a `proxy.*` stream message to the connected node, as the control plane's side of a
    /// stream (proxy.md).
    pub fn send_proxy(&self, message: ProxyMessage) {
        self.send(Control::Proxy(message));
    }

    /// Sends a `tcp.*` stream message to the connected node, as the control plane's end of a
    /// tunnel (tunnels.md).
    pub fn send_tcp(&self, message: TcpMessage) {
        self.send(Control::Tcp(message));
    }

    /// Closes the current WebSocket without `bye`. The session survives.
    pub fn drop_connection(&self) {
        self.send(Control::DropConnection);
    }

    /// While stalled, received messages are processed but no `ack` is sent.
    pub fn stall_acks(&self, stalled: bool) {
        self.send(Control::StallAcks(stalled));
    }

    /// Forgets the node's session, so its next `hello` gets `resumed: false`.
    pub fn forget_session(&self) {
        self.send(Control::Forget);
    }

    pub fn set_resume_window_ms(&self, ms: u64) {
        self.send(Control::ResumeWindow(ms));
    }

    /// Sends `bye` with `revoked`, and answers later upgrades with this node's token with `401`.
    pub fn revoke(&self, node_id: &str) {
        let joins = lock(&self.shared.joins);
        let mut revoked = lock(&self.shared.revoked);
        for join in joins.iter().filter(|j| j.node_id == node_id) {
            revoked.insert(join.node_token.clone());
        }
        self.send(Control::Revoke);
    }

    /// The current session, once a `hello` was answered. `None` again after it is lost.
    pub fn session(&self) -> Option<SessionId> {
        *self.opened.borrow()
    }

    /// Frames received from the node.
    pub fn received(&self) -> Traffic {
        let (frames, frame_bytes) = *lock(&self.shared.received);
        let wire_bytes = lock(&self.shared.meters)
            .iter()
            .map(|m| m.0.read.load(Ordering::SeqCst))
            .sum();
        Traffic {
            frames,
            frame_bytes,
            wire_bytes,
        }
    }

    /// Frames sent to the node.
    pub fn sent(&self) -> Traffic {
        let (frames, frame_bytes) = *lock(&self.shared.sent);
        let wire_bytes = lock(&self.shared.meters)
            .iter()
            .map(|m| m.0.written.load(Ordering::SeqCst))
            .sum();
        Traffic {
            frames,
            frame_bytes,
            wire_bytes,
        }
    }

    /// The `Sec-WebSocket-Extensions` the node offered on its last upgrade.
    pub fn offered_extensions(&self) -> Option<String> {
        lock(&self.shared.offered).clone()
    }

    /// The `Sec-WebSocket-Extensions` this side answered on the last upgrade, `None` when it
    /// declined compression.
    pub fn accepted_extensions(&self) -> Option<String> {
        lock(&self.shared.accepted).clone()
    }

    /// Replies whose `to` was no command waiting for one: a command the node handled twice, or
    /// answered after its session was lost.
    pub fn stray_replies(&self) -> usize {
        self.shared.stray_replies.load(Ordering::SeqCst)
    }

    fn send(&self, control: Control) {
        let _ = self.control.send(control);
    }
}

impl Drop for ControlPlane {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn endpoint(port: u16) -> String {
    format!("ws://127.0.0.1:{port}{CONNECT_PATH}")
}

fn stopped() -> Error {
    Error::new(ErrorKind::Io, "the test control plane stopped")
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn join(
    State(shared): State<Arc<Shared>>,
    Json(request): Json<JoinRequest>,
) -> std::result::Result<Json<JoinResponse>, (StatusCode, Json<JoinError>)> {
    if !lock(&shared.join_tokens).remove(&request.join_token) {
        let error = JoinError {
            error: "unknown or spent join token".to_string(),
        };
        return Err((StatusCode::UNAUTHORIZED, Json(error)));
    }
    let response = JoinResponse {
        node_id: format!("n_{}", cuid2::create_id()),
        node_token: format!("nt_{}", cuid2::create_id()),
        endpoint: endpoint(shared.port),
    };
    lock(&shared.joins).push(JoinRecord {
        join_token: request.join_token,
        installation_id: request.installation_id,
        name: request.name,
        info: request.info,
        node_id: response.node_id.clone(),
        node_token: response.node_token.clone(),
    });
    Ok(Json(response))
}

async fn connect(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(meter): ConnectInfo<Meter>,
    headers: HeaderMap,
    upgrade: yawc::IncomingUpgrade,
) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let known = token.is_some_and(|token| {
        lock(&shared.joins).iter().any(|j| j.node_token == token)
            && !lock(&shared.revoked).contains(token)
    });
    if !known {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let offers_link = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|p| p.trim() == SUBPROTOCOL));
    if !offers_link {
        return (StatusCode::BAD_REQUEST, "offer happy-supervisor.v1").into_response();
    }
    *lock(&shared.offered) = headers
        .get(header::SEC_WEBSOCKET_EXTENSIONS)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let (mut response, upgraded) = match upgrade.upgrade(crate::ws::options(
        shared.options.deflate,
        shared.options.deflate_level,
    )) {
        Ok(upgrade) => upgrade,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };
    response.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(SUBPROTOCOL),
    );
    let extensions = response
        .headers()
        .get(header::SEC_WEBSOCKET_EXTENSIONS)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    *lock(&shared.accepted) = extensions.clone();
    tokio::spawn(async move {
        match upgraded.await {
            Ok(ws) => {
                lock(&shared.meters).push(meter);
                let _ = shared.sockets.send(Box::new(Socket::new(ws, extensions)));
            }
            Err(err) => tracing::warn!("the test control plane's upgrade failed: {err}"),
        }
    });
    response.map(axum::body::Body::new)
}

/// A TCP listener whose connections count the bytes they carry.
struct Metered(TcpListener);

#[derive(Default)]
struct Counters {
    read: AtomicU64,
    written: AtomicU64,
}

/// One connection's byte counts, handed to handlers as its connect info.
#[derive(Clone)]
struct Meter(Arc<Counters>);

struct MeteredStream {
    io: TcpStream,
    meter: Meter,
}

impl Listener for Metered {
    type Io = MeteredStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (MeteredStream, SocketAddr) {
        loop {
            match self.0.accept().await {
                Ok((io, addr)) => {
                    let _ = io.set_nodelay(true);
                    let meter = Meter(Arc::default());
                    return (MeteredStream { io, meter }, addr);
                }
                Err(err) => {
                    tracing::warn!("the test control plane failed to accept: {err}");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

impl Connected<IncomingStream<'_, Metered>> for Meter {
    fn connect_info(stream: IncomingStream<'_, Metered>) -> Meter {
        stream.io().meter.clone()
    }
}

impl AsyncRead for MeteredStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.io).poll_read(cx, buf);
        let read = (buf.filled().len() - before) as u64;
        self.meter.0.read.fetch_add(read, Ordering::SeqCst);
        polled
    }
}

impl AsyncWrite for MeteredStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = polled {
            self.meter.0.written.fetch_add(n as u64, Ordering::SeqCst);
        }
        polled
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.io).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = polled {
            self.meter.0.written.fetch_add(n as u64, Ordering::SeqCst);
        }
        polled
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Owns the session and the current WebSocket. Runs until the control plane is dropped.
struct Actor {
    shared: Arc<Shared>,
    session: Session,
    outbox: Outbox,
    clock: Arc<dyn Clock>,
    socket: Option<Connection>,
    stall_acks: bool,
    pending: HashMap<MsgId, oneshot::Sender<Result<Value>>>,
    events: mpsc::UnboundedSender<Event>,
    opened: watch::Sender<Option<SessionId>>,
}

struct Connection {
    socket: Socket,
    last_frame: Instant,
}

enum Wake {
    Socket(Option<Box<Socket>>),
    Event(std::result::Result<crate::ws::Event, yawc::WebSocketError>),
    Control(Option<Control>),
    Changed,
    Tick,
    Ping,
    Dead,
}

impl Actor {
    async fn run(
        mut self,
        mut sockets: mpsc::UnboundedReceiver<Box<Socket>>,
        mut control: mpsc::UnboundedReceiver<Control>,
    ) {
        let mut ping = tokio::time::interval_at(Instant::now() + PING_EVERY, PING_EVERY);
        let mut ping_due = false;
        loop {
            while let Some(incoming) = self.session.poll_incoming() {
                self.incoming(incoming);
            }
            match &mut self.socket {
                // Nothing reaches a peer while there is no connection.
                None => while self.session.poll_transmit().is_some() {},
                Some(conn) if conn.socket.is_writable() => {
                    if let Some(frame) = self.session.poll_transmit() {
                        if self.stall_acks && is_ack(&frame) {
                            continue;
                        }
                        let mut sent = lock(&self.shared.sent);
                        sent.0 += 1;
                        sent.1 += frame.len() as u64;
                        drop(sent);
                        if conn.socket.send(frame).is_err() {
                            self.disconnect();
                        }
                        continue;
                    }
                    if ping_due {
                        ping_due = false;
                        if conn.socket.ping().is_err() {
                            self.disconnect();
                        }
                        continue;
                    }
                    if self.session.is_closing() {
                        if let Some(conn) = self.socket.take() {
                            conn.socket.close().await;
                        }
                        self.session.disconnected();
                        continue;
                    }
                }
                Some(_) => {}
            }

            let deadline = self.session.deadline().map(|at| {
                let wait = at.saturating_sub(self.clock.now_ms());
                Instant::now() + Duration::from_millis(wait)
            });
            let last_frame = self.socket.as_ref().map(|c| c.last_frame);
            let socket = &mut self.socket;
            let event = async {
                match socket {
                    Some(conn) => conn.socket.next().await,
                    None => std::future::pending().await,
                }
            };
            let wake = tokio::select! {
                socket = sockets.recv() => Wake::Socket(socket),
                event = event => Wake::Event(event),
                c = control.recv() => Wake::Control(c),
                _ = self.session.changed() => Wake::Changed,
                _ = sleep_until(deadline) => Wake::Tick,
                _ = ping.tick() => Wake::Ping,
                _ = sleep_until(last_frame.map(|t| t + crate::client::DEAD_AFTER)) => Wake::Dead,
            };
            match wake {
                Wake::Socket(None) | Wake::Control(None) => return,
                Wake::Socket(Some(socket)) => {
                    self.disconnect();
                    self.socket = Some(Connection {
                        socket: *socket,
                        last_frame: Instant::now(),
                    });
                    self.session.connected();
                }
                Wake::Event(event) => self.event(event),
                Wake::Control(Some(c)) => self.control(c),
                Wake::Changed => {}
                Wake::Tick => self.session.tick(),
                Wake::Ping => ping_due = self.socket.is_some(),
                Wake::Dead => self.disconnect(),
            }
        }
    }

    fn event(&mut self, event: std::result::Result<crate::ws::Event, yawc::WebSocketError>) {
        use crate::ws::Event;
        let Some(conn) = &mut self.socket else {
            return;
        };
        match event {
            Ok(Event::Writable) => return,
            Err(_) => return self.disconnect(),
            Ok(_) => conn.last_frame = Instant::now(),
        }
        match event {
            Ok(Event::Binary(payload)) => {
                let mut received = lock(&self.shared.received);
                received.0 += 1;
                received.1 += payload.len() as u64;
                drop(received);
                self.session.receive(&payload);
            }
            Ok(Event::Text) => self.session.reject("a text frame"),
            _ => {}
        }
    }

    fn incoming(&mut self, incoming: Incoming) {
        match incoming {
            Incoming::Opened { session, .. } => {
                self.opened.send_replace(Some(session));
            }
            Incoming::Message { id, kind, body } => match Event::parse(&kind, body) {
                Some(Ok(event)) => {
                    let _ = self.events.send(event);
                }
                Some(Err(err)) => tracing::warn!("the node sent a bad {kind}: {err}"),
                None => self.outbox.reply(
                    id,
                    Err(Error::new(
                        ErrorKind::UnknownKind,
                        format!("unknown message kind `{kind}`"),
                    )),
                ),
            },
            Incoming::Reply { to, result } => match self.pending.remove(&to) {
                Some(waiting) => {
                    let _ = waiting.send(result);
                }
                None => {
                    self.shared.stray_replies.fetch_add(1, Ordering::SeqCst);
                }
            },
            Incoming::Lost { session, reason } => {
                tracing::info!(%session, "the test control plane lost the session: {reason:?}");
                for (_, waiting) in self.pending.drain() {
                    let _ = waiting.send(Err(Error::new(
                        ErrorKind::Io,
                        "the session was lost before the reply",
                    )));
                }
                self.opened.send_replace(None);
            }
        }
    }

    fn control(&mut self, control: Control) {
        match control {
            Control::Command { kind, body, reply } => {
                let id = self.outbox.command(&kind, &body);
                self.pending.insert(id, reply);
            }
            Control::Proxy(message) => self.outbox.proxy(message),
            Control::Tcp(message) => self.outbox.tcp(message),
            Control::DropConnection => self.disconnect(),
            Control::StallAcks(stalled) => self.stall_acks = stalled,
            Control::Forget => self.session.forget(),
            Control::ResumeWindow(ms) => self.session.set_resume_window_ms(ms),
            Control::Revoke => self
                .session
                .bye(ByeReason::Revoked, Some("revoked by the test".to_string())),
        }
    }

    /// Drops the current WebSocket, if any, without a close frame.
    fn disconnect(&mut self) {
        if self.socket.take().is_some() {
            self.session.disconnected();
        }
    }
}

fn is_ack(frame: &[u8]) -> bool {
    crate::wire::split(frame)
        .ok()
        .and_then(|(_, body)| from_cbor::<Frame>(body).ok())
        .is_some_and(|frame| matches!(frame, Frame::Ack(_)))
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
