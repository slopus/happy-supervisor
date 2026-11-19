//! The control-plane side of the link for Rust programs and tests (docs/serve.md, The Rust
//! client): a [`link::Session`](crate::link::Session) in the control-plane role over a real
//! WebSocket to a `serve` node, redialing and resuming when the connection drops.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use url::Url;

use crate::error::{Error, ErrorKind, Result};
use crate::link::{Clock, Incoming, Outbox, Role, Session, SystemClock};
use crate::protocol::{Event, MsgId, ProxyMessage, SessionId, TcpMessage, Value};
use crate::ws::{Dialed, Socket};

const PING_EVERY: Duration = Duration::from_secs(15);
const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const REDIAL_MIN: Duration = Duration::from_millis(100);
const REDIAL_MAX: Duration = Duration::from_secs(5);
/// How long a session the node may resume stays known here.
const RESUME_WINDOW_MS: u64 = 300_000;

/// A connection to one node. Dropping it closes the connection; the node keeps its processes
/// and loses the session once the resume window passes.
pub struct Controller {
    control: mpsc::UnboundedSender<Control>,
    opened: watch::Receiver<Option<SessionId>>,
    subscribers: Subscribers,
    task: tokio::task::JoinHandle<()>,
}

type Subscribers = Arc<Mutex<Vec<mpsc::UnboundedSender<Event>>>>;

/// The node's events from the moment [`Controller::events`] was called.
pub struct Events {
    events: mpsc::UnboundedReceiver<Event>,
}

impl Events {
    /// The next event; `None` once the controller is gone.
    pub async fn next(&mut self) -> Option<Event> {
        self.events.recv().await
    }
}

enum Control {
    Command {
        kind: String,
        body: Value,
        reply: oneshot::Sender<Result<Value>>,
    },
    Proxy(ProxyMessage),
    Tcp(TcpMessage),
}

impl Controller {
    /// Connects to a node's listener (`ws://IP:PORT`, `unix:PATH`) with its token, and returns
    /// once the session is open.
    pub async fn connect(url: &str, token: &str) -> Result<Controller> {
        let url = Url::parse(url)
            .map_err(|err| Error::invalid_params(format!("bad node URL {url:?}: {err}")))?;
        let socket = dial(&url, token).await?;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let role = Role::ControlPlane {
            resume_window_ms: RESUME_WINDOW_MS,
        };
        let (session, outbox) = Session::new(role, clock.clone());
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let (opened_tx, mut opened) = watch::channel(None);
        let subscribers = Subscribers::default();
        let actor = Actor {
            url,
            token: token.to_string(),
            session,
            outbox,
            clock,
            pending: HashMap::new(),
            subscribers: subscribers.clone(),
            opened: opened_tx,
        };
        let task = tokio::spawn(actor.run(socket, control_rx));
        let waited = tokio::time::timeout(OPEN_TIMEOUT, opened.wait_for(Option::is_some))
            .await
            .map(|opened| opened.map(|_| ()));
        match waited {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return Err(gone()),
            Err(_) => {
                task.abort();
                return Err(Error::new(
                    ErrorKind::TimedOut,
                    "the node did not open a session",
                ));
            }
        }
        Ok(Controller {
            control: control_tx,
            opened,
            subscribers,
            task,
        })
    }

    /// Sends a command and waits for its reply, as `R`. An `error` reply is the `Err`, and so
    /// is losing the session first.
    pub async fn command<P, R>(&self, kind: &str, params: P) -> Result<R>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let reply = self.call(kind, crate::wire::to_value(&params)).await?;
        crate::wire::from_value(reply).map_err(|err| {
            Error::new(
                ErrorKind::Io,
                format!("the {kind} reply did not parse: {err}"),
            )
        })
    }

    /// [`Controller::command`] with an untyped body and result.
    pub async fn call(&self, kind: &str, body: Value) -> Result<Value> {
        let mut opened = self.opened.clone();
        let reopened = tokio::time::timeout(OPEN_TIMEOUT, opened.wait_for(Option::is_some));
        match reopened.await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return Err(gone()),
            Err(_) => return Err(Error::new(ErrorKind::TimedOut, "no session is open")),
        }
        let (reply, replied) = oneshot::channel();
        self.control
            .send(Control::Command {
                kind: kind.to_string(),
                body,
                reply,
            })
            .map_err(|_| gone())?;
        replied.await.map_err(|_| gone())?
    }

    /// Every event the node sends from now on: `exec.output`, `exec.exit`, `watch.event`,
    /// `net.denied`, `node.ready`, and the `proxy.*` and `tcp.*` stream messages.
    pub fn events(&self) -> Events {
        let (tx, events) = mpsc::unbounded_channel();
        lock(&self.subscribers).push(tx);
        Events { events }
    }

    /// Sends a `proxy.*` stream message, as the control plane's side of a stream (proxy.md).
    pub fn send_proxy(&self, message: ProxyMessage) {
        let _ = self.control.send(Control::Proxy(message));
    }

    /// Sends a `tcp.*` stream message, as the control plane's end of a tunnel (tunnels.md).
    pub fn send_tcp(&self, message: TcpMessage) {
        let _ = self.control.send(Control::Tcp(message));
    }

    /// The open session, `None` while there is none.
    pub fn session(&self) -> Option<SessionId> {
        *self.opened.borrow()
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn gone() -> Error {
    Error::new(ErrorKind::Io, "the connection to the node is gone")
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn dial(url: &Url, token: &str) -> Result<Socket> {
    match crate::ws::dial(url, token).await {
        Ok(Dialed::Open(socket)) => Ok(*socket),
        Ok(Dialed::Refused(status)) => Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("{url} refused the token ({status})"),
        )),
        Err(err) => Err(Error::new(
            ErrorKind::Io,
            format!("connecting to {url}: {err}"),
        )),
    }
}

/// Owns the session and the WebSocket.
struct Actor {
    url: Url,
    token: String,
    session: Session,
    outbox: Outbox,
    clock: Arc<dyn Clock>,
    pending: HashMap<MsgId, oneshot::Sender<Result<Value>>>,
    subscribers: Subscribers,
    opened: watch::Sender<Option<SessionId>>,
}

/// How a connection ended.
enum Ended {
    /// The controller was dropped.
    Dropped,
    /// The node closed it for a newer connection, which now has the node.
    Replaced,
    Redial,
}

impl Actor {
    async fn run(mut self, mut socket: Socket, mut control: mpsc::UnboundedReceiver<Control>) {
        let mut delay = REDIAL_MIN;
        loop {
            self.session.connected();
            let ended = self.connection(socket, &mut control).await;
            self.session.disconnected();
            match ended {
                Ended::Dropped => return,
                Ended::Replaced => {
                    tracing::info!("another connection took over the node");
                    self.fail_pending("another connection took over the node");
                    return;
                }
                Ended::Redial => {}
            }
            socket = loop {
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(REDIAL_MAX);
                match dial(&self.url, &self.token).await {
                    Ok(socket) => break socket,
                    Err(err) if err.kind == ErrorKind::PermissionDenied => {
                        tracing::warn!("{err}");
                        self.fail_pending(&err.message);
                        return;
                    }
                    Err(err) => tracing::debug!("{err}"),
                }
            };
            delay = REDIAL_MIN;
        }
    }

    async fn connection(
        &mut self,
        mut socket: Socket,
        control: &mut mpsc::UnboundedReceiver<Control>,
    ) -> Ended {
        let mut ping = tokio::time::interval_at(Instant::now() + PING_EVERY, PING_EVERY);
        let mut ping_due = false;
        let mut last_frame = Instant::now();
        loop {
            while let Some(incoming) = self.session.poll_incoming() {
                self.incoming(incoming);
            }
            if socket.is_writable() {
                let sent = if let Some(frame) = self.session.poll_transmit() {
                    Some(socket.send(frame))
                } else if ping_due {
                    ping_due = false;
                    Some(socket.ping())
                } else {
                    None
                };
                match sent {
                    Some(Ok(())) => continue,
                    Some(Err(_)) => return Ended::Redial,
                    None if self.session.is_closing() => {
                        socket.close().await;
                        return Ended::Redial;
                    }
                    None => {}
                }
            }
            let deadline = self.session.deadline().map(|at| {
                let wait = at.saturating_sub(self.clock.now_ms());
                Instant::now() + Duration::from_millis(wait)
            });
            tokio::select! {
                event = socket.next() => match event {
                    Ok(crate::ws::Event::Writable) => {}
                    Ok(event) => {
                        last_frame = Instant::now();
                        match event {
                            crate::ws::Event::Binary(payload) => self.session.receive(&payload),
                            crate::ws::Event::Text => self.session.reject("a text frame"),
                            _ => {}
                        }
                    }
                    Err(_) if socket.peer_close_code() == Some(crate::ws::CLOSE_REPLACED) => {
                        return Ended::Replaced;
                    }
                    Err(_) => return Ended::Redial,
                },
                c = control.recv() => match c {
                    Some(c) => self.control(c),
                    None => {
                        socket.close().await;
                        return Ended::Dropped;
                    }
                },
                _ = self.session.changed() => {}
                _ = sleep_until(deadline) => self.session.tick(),
                _ = ping.tick() => ping_due = true,
                _ = tokio::time::sleep_until(last_frame + crate::client::DEAD_AFTER) => {
                    return Ended::Redial;
                }
            }
        }
    }

    fn control(&mut self, control: Control) {
        match control {
            Control::Command { kind, body, reply } => {
                if self.session.session().is_none() {
                    let _ = reply.send(Err(Error::new(ErrorKind::Io, "no session is open")));
                    return;
                }
                let id = self.outbox.command(&kind, &body);
                self.pending.insert(id, reply);
            }
            Control::Proxy(message) => self.outbox.proxy(message),
            Control::Tcp(message) => self.outbox.tcp(message),
        }
    }

    fn incoming(&mut self, incoming: Incoming) {
        match incoming {
            Incoming::Opened { session, .. } => {
                self.opened.send_replace(Some(session));
            }
            Incoming::Message { id, kind, body } => match Event::parse(&kind, body) {
                Some(Ok(event)) => {
                    lock(&self.subscribers).retain(|tx| tx.send(event.clone()).is_ok());
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
            Incoming::Reply { to, result } => {
                if let Some(waiting) = self.pending.remove(&to) {
                    let _ = waiting.send(result);
                }
            }
            Incoming::Lost { session, reason } => {
                tracing::info!(%session, "the session was lost: {reason:?}");
                self.fail_pending("the session was lost before the reply");
                self.opened.send_replace(None);
            }
        }
    }

    fn fail_pending(&mut self, why: &str) {
        for (_, waiting) in self.pending.drain() {
            let _ = waiting.send(Err(Error::new(ErrorKind::Io, why)));
        }
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
