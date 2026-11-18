//! An in-process control plane for tests (docs/architecture.md, Testing), behind the `testing`
//! feature. Owned by the transport track; the scaffold froze the API below. It speaks the link
//! protocol through [`link::Session`](crate::link::Session) with
//! [`Role::ControlPlane`](crate::link::Role::ControlPlane): one session, for one node at a time.
//!
//! The fault hooks only move or drop frames and call the session. Every protocol rule stays in
//! `link`.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use crate::error::{Error, ErrorKind, Result};
use crate::link::{Clock, Incoming, Outbox, Role, Session, SystemClock};
use crate::protocol::{
    ByeReason, Event, Frame, JoinError, JoinRequest, JoinResponse, MAX_FRAME_BYTES, MsgId,
    NodeInfo, ProxyMessage, SessionId, Value,
};
use crate::wire::{Wire, from_cbor};

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
    /// Select `happy-supervisor.v1.deflate` when the node offers it. Otherwise
    /// `happy-supervisor.v1`.
    pub deflate: bool,
    /// The `resumeWindowMs` of `welcome`.
    pub resume_window_ms: u64,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            deflate: true,
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

/// Frames in one direction since the control plane started: their count, their size on the
/// wire, and their size as CBOR before compression.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub frames: u64,
    pub wire_bytes: u64,
    pub cbor_bytes: u64,
}

impl Traffic {
    fn add(&mut self, wire: Wire, payload: &[u8]) {
        self.frames += 1;
        self.wire_bytes += payload.len() as u64;
        self.cbor_bytes += wire.decode(payload).map_or(0, |cbor| cbor.len() as u64);
    }
}

struct Shared {
    port: u16,
    options: Options,
    join_tokens: Mutex<HashSet<String>>,
    joins: Mutex<Vec<JoinRecord>>,
    revoked: Mutex<HashSet<String>>,
    received: Mutex<Traffic>,
    sent: Mutex<Traffic>,
    stray_replies: AtomicUsize,
    sockets: mpsc::UnboundedSender<(WebSocket, Wire)>,
}

enum Control {
    Command {
        kind: String,
        body: Value,
        reply: oneshot::Sender<Result<Value>>,
    },
    Proxy(ProxyMessage),
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
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let (sockets_tx, sockets_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            port: addr.port(),
            options,
            join_tokens: Mutex::default(),
            joins: Mutex::default(),
            revoked: Mutex::default(),
            received: Mutex::default(),
            sent: Mutex::default(),
            stray_replies: AtomicUsize::new(0),
            sockets: sockets_tx,
        });
        let app = Router::new()
            .route(JOIN_PATH, post(join))
            .route(CONNECT_PATH, get(connect))
            .with_state(shared.clone());
        let server = tokio::spawn(async move {
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
        *lock(&self.shared.received)
    }

    /// Frames sent to the node.
    pub fn sent(&self) -> Traffic {
        *lock(&self.shared.sent)
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
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
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
    let offered: &[&str] = if shared.options.deflate {
        &Wire::OFFERED
    } else {
        &[crate::wire::SUBPROTOCOL_PLAIN]
    };
    let upgrade = upgrade
        .protocols(offered.iter().copied())
        .max_message_size(MAX_FRAME_BYTES + 1)
        .max_frame_size(MAX_FRAME_BYTES + 1);
    let wire = upgrade
        .selected_protocol()
        .and_then(|v| v.to_str().ok())
        .and_then(Wire::from_subprotocol)
        .unwrap_or(Wire::Plain);
    upgrade.on_upgrade(move |socket| async move {
        let _ = shared.sockets.send((socket, wire));
    })
}

/// Owns the session and the current WebSocket. Runs until the control plane is dropped.
struct Actor {
    shared: Arc<Shared>,
    session: Session,
    outbox: Outbox,
    clock: Arc<dyn Clock>,
    socket: Option<Socket>,
    stall_acks: bool,
    pending: HashMap<MsgId, oneshot::Sender<Result<Value>>>,
    events: mpsc::UnboundedSender<Event>,
    opened: watch::Sender<Option<SessionId>>,
}

struct Socket {
    sink: SplitSink<WebSocket, Message>,
    stream: SplitStream<WebSocket>,
    wire: Wire,
    last_frame: Instant,
}

enum Wake {
    Socket(Option<(WebSocket, Wire)>),
    Frame(Option<std::result::Result<Message, axum::Error>>),
    Control(Option<Control>),
    Changed,
    Tick,
    Ping,
    Dead,
}

impl Actor {
    async fn run(
        mut self,
        mut sockets: mpsc::UnboundedReceiver<(WebSocket, Wire)>,
        mut control: mpsc::UnboundedReceiver<Control>,
    ) {
        let mut ping = tokio::time::interval_at(Instant::now() + PING_EVERY, PING_EVERY);
        loop {
            self.drain().await;
            let deadline = self.session.deadline().map(|at| {
                let wait = at.saturating_sub(self.clock.now_ms());
                Instant::now() + Duration::from_millis(wait)
            });
            let last_frame = self.socket.as_ref().map(|s| s.last_frame);
            let socket = &mut self.socket;
            let frame = async {
                match socket {
                    Some(socket) => socket.stream.next().await,
                    None => std::future::pending().await,
                }
            };
            let wake = tokio::select! {
                socket = sockets.recv() => Wake::Socket(socket),
                frame = frame => Wake::Frame(frame),
                c = control.recv() => Wake::Control(c),
                _ = self.session.changed() => Wake::Changed,
                _ = sleep_until(deadline) => Wake::Tick,
                _ = ping.tick() => Wake::Ping,
                _ = sleep_until(last_frame.map(|t| t + crate::client::DEAD_AFTER)) => Wake::Dead,
            };
            match wake {
                Wake::Socket(None) | Wake::Control(None) => return,
                Wake::Socket(Some((ws, wire))) => {
                    self.disconnect();
                    let (sink, stream) = ws.split();
                    self.socket = Some(Socket {
                        sink,
                        stream,
                        wire,
                        last_frame: Instant::now(),
                    });
                    self.session.connected(wire);
                }
                Wake::Frame(frame) => self.frame(frame),
                Wake::Control(Some(c)) => self.control(c),
                Wake::Changed => {}
                Wake::Tick => self.session.tick(),
                Wake::Ping => {
                    if let Some(socket) = &mut self.socket
                        && socket
                            .sink
                            .send(Message::Ping(Vec::new().into()))
                            .await
                            .is_err()
                    {
                        self.disconnect();
                    }
                }
                Wake::Dead => self.disconnect(),
            }
        }
    }

    /// Writes what the session has to send and routes what it delivered, until nothing moves.
    async fn drain(&mut self) {
        loop {
            let mut moved = false;
            while let Some(payload) = self.session.poll_transmit() {
                moved = true;
                let Some(socket) = &mut self.socket else {
                    continue;
                };
                let wire = socket.wire;
                if self.stall_acks && is_ack(wire, &payload) {
                    continue;
                }
                lock(&self.shared.sent).add(wire, &payload);
                if socket
                    .sink
                    .send(Message::Binary(payload.into()))
                    .await
                    .is_err()
                {
                    self.disconnect();
                }
            }
            while let Some(incoming) = self.session.poll_incoming() {
                moved = true;
                self.incoming(incoming);
            }
            if !moved {
                break;
            }
        }
        if self.socket.is_some() && self.session.is_closing() {
            if let Some(mut socket) = self.socket.take() {
                let _ = socket.sink.close().await;
            }
            self.session.disconnected();
        }
    }

    fn frame(&mut self, frame: Option<std::result::Result<Message, axum::Error>>) {
        let Some(socket) = &mut self.socket else {
            return;
        };
        socket.last_frame = Instant::now();
        match frame {
            Some(Ok(Message::Binary(payload))) => {
                lock(&self.shared.received).add(socket.wire, &payload);
                self.session.receive(&payload);
            }
            Some(Ok(Message::Text(_))) => self.session.reject("a text frame"),
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => self.disconnect(),
            Some(Ok(_)) => {}
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

fn is_ack(wire: Wire, payload: &[u8]) -> bool {
    wire.decode(payload)
        .ok()
        .and_then(|cbor| from_cbor::<Frame>(&cbor).ok())
        .is_some_and(|frame| matches!(frame, Frame::Ack(_)))
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
