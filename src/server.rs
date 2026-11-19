//! The control plane's side of the link (api.md, Control-plane library): a
//! [`Session`] in the control-plane role for one node, over whichever of its WebSockets is the
//! latest. The program accepts the sockets ([`crate::ws::upgrade`]) or dials them
//! ([`Controller`](crate::Controller)); every link rule stays in [`crate::link`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use crate::error::{Error, ErrorKind, Result};
use crate::link::{Clock, Incoming, LostReason, Outbox, Role, Session, SystemClock};
use crate::protocol::{ByeReason, Event, Hello, MsgId, ProxyMessage, SessionId, TcpMessage, Value};
use crate::ws::{CLOSE_REPLACED, DEAD_AFTER, PING_EVERY, Socket};

/// How long a dropped session stays resumable unless the program says otherwise.
pub const RESUME_WINDOW_MS: u64 = 300_000;

/// One node's link, as the control plane. Lives across connections and sessions until it is
/// dropped or [closed](ControlPlaneLink::close). Cheap to share behind an `Arc`.
pub struct ControlPlaneLink {
    control: mpsc::UnboundedSender<Control>,
    opened: watch::Receiver<Option<SessionId>>,
    subscribers: Subscribers,
    task: tokio::task::JoinHandle<()>,
}

/// What [`LinkEvents::next`] reports, in the order it happened.
#[derive(Clone, Debug)]
pub enum LinkEvent {
    /// A session opened (`resumed: false`, a new session) or resumed on a new connection.
    Opened {
        session: SessionId,
        resumed: bool,
        hello: Box<Hello>,
    },
    /// An event from the node: `exec.*`, `watch.event`, `net.denied`, `net.bindDenied`,
    /// `node.ready`, or a `proxy.*` or `tcp.*` stream message.
    Event(Event),
    /// The session cannot be resumed. Commands it carried were failed.
    Lost {
        session: SessionId,
        reason: LostReason,
    },
    /// The connection ended. `replaced` when the node closed it for a newer one (serve.md).
    /// The session stays resumable until its window passes.
    Disconnected { replaced: bool },
}

type Subscribers = Arc<Mutex<Vec<mpsc::UnboundedSender<LinkEvent>>>>;

/// The link's events from the moment [`ControlPlaneLink::events`] was called.
pub struct LinkEvents {
    events: mpsc::UnboundedReceiver<LinkEvent>,
}

impl LinkEvents {
    /// The next event; `None` once the link is gone.
    pub async fn next(&mut self) -> Option<LinkEvent> {
        self.events.recv().await
    }
}

enum Control {
    Attach(Box<Socket>),
    Command {
        kind: String,
        body: Value,
        reply: oneshot::Sender<CallResult<Value>>,
    },
    Proxy(ProxyMessage),
    Tcp(TcpMessage),
    Bye(ByeReason, Option<String>),
}

impl ControlPlaneLink {
    /// A link with no connection yet, keeping a dropped session resumable for
    /// `resume_window_ms`. Needs a Tokio runtime.
    pub fn new(resume_window_ms: u64) -> ControlPlaneLink {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let (session, outbox) =
            Session::new(Role::ControlPlane { resume_window_ms }, clock.clone());
        let (control, control_rx) = mpsc::unbounded_channel();
        let (opened_tx, opened) = watch::channel(None);
        let subscribers = Subscribers::default();
        let actor = Actor {
            session,
            outbox,
            clock,
            socket: None,
            pending: HashMap::new(),
            subscribers: subscribers.clone(),
            opened: opened_tx,
        };
        ControlPlaneLink {
            control,
            opened,
            subscribers,
            task: tokio::spawn(actor.run(control_rx)),
        }
    }

    /// Makes `socket` the node's connection, dropping the current one. The node's `hello` on
    /// it opens or resumes the session.
    pub fn attach(&self, socket: Socket) {
        let _ = self.control.send(Control::Attach(Box::new(socket)));
    }

    /// Sends a command and waits for its reply, as `R`. [`CallError`] says whether the node
    /// answered with an error or the command may not have run.
    pub async fn command<P, R>(&self, kind: &str, params: P) -> CallResult<R>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let reply = self.call(kind, crate::wire::to_value(&params)).await?;
        crate::wire::from_value(reply)
            .map_err(|err| CallError::BadReply(format!("the {kind} reply did not parse: {err}")))
    }

    /// [`ControlPlaneLink::command`] with an untyped body and result.
    pub async fn call(&self, kind: &str, body: Value) -> CallResult<Value> {
        let (reply, replied) = oneshot::channel();
        self.control
            .send(Control::Command {
                kind: kind.to_string(),
                body,
                reply,
            })
            .map_err(|_| CallError::Closed)?;
        replied.await.map_err(|_| CallError::Closed)?
    }

    /// Every event from now on.
    pub fn events(&self) -> LinkEvents {
        let (tx, events) = mpsc::unbounded_channel();
        lock(&self.subscribers).push(tx);
        LinkEvents { events }
    }

    /// Sends a `proxy.*` stream message, as the control plane's side of a stream (proxy.md).
    pub fn send_proxy(&self, message: ProxyMessage) {
        let _ = self.control.send(Control::Proxy(message));
    }

    /// Sends a `tcp.*` stream message, as the control plane's end of a tunnel (tunnels.md).
    pub fn send_tcp(&self, message: TcpMessage) {
        let _ = self.control.send(Control::Tcp(message));
    }

    /// Ends the session with `bye` (api.md, Ending a session); `revoked` makes the node exit.
    pub fn bye(&self, reason: ByeReason, message: Option<String>) {
        let _ = self.control.send(Control::Bye(reason, message));
    }

    /// The open session, `None` while there is none.
    pub fn session(&self) -> Option<SessionId> {
        *self.opened.borrow()
    }

    /// Waits until a session is open, at most `timeout`.
    pub async fn opened(&self, timeout: Duration) -> Result<SessionId> {
        let mut opened = self.opened.clone();
        match tokio::time::timeout(timeout, opened.wait_for(Option::is_some)).await {
            Ok(Ok(session)) => Ok(session.expect("waited for Some")),
            Ok(Err(_)) => Err(gone()),
            Err(_) => Err(Error::new(ErrorKind::TimedOut, "no session is open")),
        }
    }

    /// Stops the link: the connection drops without `bye`, and waiting commands fail.
    pub fn close(&self) {
        self.task.abort();
    }
}

impl Drop for ControlPlaneLink {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub type CallResult<T> = std::result::Result<T, CallError>;

/// Why a command has no result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallError {
    /// The node ran it and replied with this error.
    Node(Error),
    /// No session was open. The command was not sent.
    NoSession,
    /// The session was lost before the reply. The command may or may not have run.
    Lost,
    /// The link was closed or dropped. The command may or may not have run.
    Closed,
    /// The node replied, but not with the type asked for.
    BadReply(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Node(err) => write!(f, "{err}"),
            CallError::NoSession => f.write_str("no session is open"),
            CallError::Lost => f.write_str("the session was lost before the reply"),
            CallError::Closed => f.write_str("the link to the node is gone"),
            CallError::BadReply(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for CallError {}

/// The node's error as it is; the link's own failures as `io`.
impl From<CallError> for Error {
    fn from(err: CallError) -> Error {
        match err {
            CallError::Node(err) => err,
            other => Error::new(ErrorKind::Io, other.to_string()),
        }
    }
}

fn gone() -> Error {
    Error::new(ErrorKind::Io, "the link to the node is gone")
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Owns the session and the current WebSocket.
struct Actor {
    session: Session,
    outbox: Outbox,
    clock: Arc<dyn Clock>,
    socket: Option<Connection>,
    pending: HashMap<MsgId, oneshot::Sender<CallResult<Value>>>,
    subscribers: Subscribers,
    opened: watch::Sender<Option<SessionId>>,
}

struct Connection {
    socket: Socket,
    last_frame: Instant,
    ping_due: bool,
}

enum Wake {
    Event(std::result::Result<crate::ws::Event, yawc::WebSocketError>),
    Control(Option<Control>),
    Changed,
    Tick,
    Ping,
    Dead,
}

impl Actor {
    async fn run(mut self, mut control: mpsc::UnboundedReceiver<Control>) {
        let mut ping = tokio::time::interval_at(Instant::now() + PING_EVERY, PING_EVERY);
        loop {
            while let Some(incoming) = self.session.poll_incoming() {
                self.incoming(incoming);
            }
            match &mut self.socket {
                // Nothing reaches a peer while there is no connection.
                None => while self.session.poll_transmit().is_some() {},
                Some(conn) if conn.socket.is_writable() => {
                    let sent = if let Some(frame) = self.session.poll_transmit() {
                        Some(conn.socket.send(frame))
                    } else if conn.ping_due {
                        conn.ping_due = false;
                        Some(conn.socket.ping())
                    } else {
                        None
                    };
                    match sent {
                        Some(Ok(())) => continue,
                        Some(Err(_)) => {
                            self.disconnect(false);
                            continue;
                        }
                        None if self.session.is_closing() => {
                            if let Some(conn) = self.socket.take() {
                                conn.socket.close().await;
                                self.session.disconnected();
                                self.publish(LinkEvent::Disconnected { replaced: false });
                            }
                            continue;
                        }
                        None => {}
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
                event = event => Wake::Event(event),
                c = control.recv() => Wake::Control(c),
                _ = self.session.changed() => Wake::Changed,
                _ = sleep_until(deadline) => Wake::Tick,
                _ = ping.tick() => Wake::Ping,
                _ = sleep_until(last_frame.map(|t| t + DEAD_AFTER)) => Wake::Dead,
            };
            match wake {
                Wake::Control(None) => return,
                Wake::Event(event) => self.event(event),
                Wake::Control(Some(c)) => self.control(c),
                Wake::Changed => {}
                Wake::Tick => self.session.tick(),
                Wake::Ping => {
                    if let Some(conn) = &mut self.socket {
                        conn.ping_due = true;
                    }
                }
                Wake::Dead => self.disconnect(false),
            }
        }
    }

    fn event(&mut self, event: std::result::Result<crate::ws::Event, yawc::WebSocketError>) {
        use crate::ws::Event;
        let Some(conn) = &mut self.socket else {
            return;
        };
        match event {
            Ok(Event::Writable) => {}
            Err(_) => {
                let replaced = conn.socket.peer_close_code() == Some(CLOSE_REPLACED);
                self.disconnect(replaced);
            }
            Ok(event) => {
                conn.last_frame = Instant::now();
                match event {
                    Event::Binary(payload) => self.session.receive(&payload),
                    Event::Text => self.session.reject("a text frame"),
                    _ => {}
                }
            }
        }
    }

    fn control(&mut self, control: Control) {
        match control {
            Control::Attach(socket) => {
                self.disconnect(false);
                self.socket = Some(Connection {
                    socket: *socket,
                    last_frame: Instant::now(),
                    ping_due: false,
                });
                self.session.connected();
            }
            Control::Command { kind, body, reply } => {
                if self.session.session().is_none() {
                    let _ = reply.send(Err(CallError::NoSession));
                    return;
                }
                let id = self.outbox.command(&kind, &body);
                self.pending.insert(id, reply);
            }
            Control::Proxy(message) => self.outbox.proxy(message),
            Control::Tcp(message) => self.outbox.tcp(message),
            Control::Bye(reason, message) => self.session.bye(reason, message),
        }
    }

    fn incoming(&mut self, incoming: Incoming) {
        match incoming {
            Incoming::Opened {
                session,
                resumed,
                hello,
            } => {
                self.opened.send_replace(Some(session));
                if let Some(hello) = hello {
                    self.publish(LinkEvent::Opened {
                        session,
                        resumed,
                        hello: Box::new(hello),
                    });
                }
            }
            Incoming::Message { id, kind, body } => match Event::parse(&kind, body) {
                Some(Ok(event)) => self.publish(LinkEvent::Event(event)),
                Some(Err(err)) => tracing::warn!("the node sent a bad {kind}: {err}"),
                None => self.outbox.reply(
                    id,
                    Err(Error::new(
                        ErrorKind::UnknownKind,
                        format!("unknown message kind `{kind}`"),
                    )),
                ),
            },
            Incoming::Reply { to, result } => {
                if let Some(waiting) = self.pending.remove(&to) {
                    let _ = waiting.send(result.map_err(CallError::Node));
                }
            }
            Incoming::Lost { session, reason } => {
                tracing::info!(%session, "the session was lost: {reason:?}");
                for (_, waiting) in self.pending.drain() {
                    let _ = waiting.send(Err(CallError::Lost));
                }
                self.opened.send_replace(None);
                self.publish(LinkEvent::Lost { session, reason });
            }
        }
    }

    fn publish(&self, event: LinkEvent) {
        lock(&self.subscribers).retain(|tx| tx.send(event.clone()).is_ok());
    }

    /// Drops the current WebSocket, if any, without a close frame.
    fn disconnect(&mut self, replaced: bool) {
        if self.socket.take().is_some() {
            self.session.disconnected();
            self.publish(LinkEvent::Disconnected { replaced });
        }
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
