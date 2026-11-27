//! The connection to the control plane (docs/api.md, Connection). Owned by the transport
//! track; the scaffold froze the signature.
//!
//! One [`Session`] lives for the whole run, across connections. The driver moves frames between
//! it and the WebSocket and follows docs/architecture.md's driver loop. Every protocol rule is in
//! [`link`](crate::link); nothing here decides what is resent, acked or lost.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::dispatch::{Node, dispatch};
use crate::error::{Error, ErrorKind, Result};
use crate::link::{
    Clock, Incoming, Lane, LostReason, NodeIdentity, Outbox, Role, Session, SystemClock, lane_of,
};
use crate::protocol::{ByeReason, MsgId, SessionId, Value};
use crate::state::StateDir;
use crate::ws::{DEAD_AFTER, Dialed, Event, PING_EVERY, Socket};

pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// A connection up this long resets the backoff.
pub const STABLE_AFTER: Duration = Duration::from_secs(60);
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a failed `node.ready` collection waits before it is tried again.
const READY_RETRY: Duration = Duration::from_secs(1);

/// With the `testing` feature, setting this variable makes the node send every message through
/// one lane, as a link without lanes would, to measure what lanes are worth.
#[cfg(feature = "testing")]
pub const SINGLE_LANE_ENV: &str = "HAPPY_SUPERVISOR_SINGLE_LANE";

/// Why [`run`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunExit {
    /// The control plane refused the credential with `401` or `403`, or sent `bye` with
    /// `revoked`. The CLI exits `3`.
    Revoked,
    /// The supervisor was asked to stop (Ctrl-C or SIGTERM).
    Interrupted,
}

/// Connects to the stored endpoint and serves the control plane, redialing until revoked or
/// interrupted. Drives one [`link::Session`](crate::link::Session) across every connection.
/// Re-reads the credentials before each dial, so a `node.update` takes effect.
pub async fn run(state: StateDir) -> Result<RunExit> {
    run_until(state, shutdown_signal()).await
}

/// [`run`], stopping when `stop` resolves instead of on a signal. Stopping sends `bye` with
/// `shutdown` on a live connection and kills every running command.
pub async fn run_until(
    state: StateDir,
    stop: impl Future<Output = ()> + Send + 'static,
) -> Result<RunExit> {
    let (credentials, installation_id) = {
        let state = state.clone();
        blocking(move || Ok((state.credentials()?, state.installation_id()?))).await?
    };
    let credentials = credentials.ok_or_else(|| {
        Error::new(
            ErrorKind::Io,
            "this node has not joined a control plane; run `happy-supervisor join` first",
        )
    })?;
    let identity = NodeIdentity {
        node_id: credentials.node_id,
        installation_id,
    };
    let _lock = {
        let state = state.clone();
        blocking(move || state.lock()).await?
    };
    drive(state, identity, Source::Dial, stop).await
}

/// Serves the control planes that connect to a listener (serve.md): each socket from `sockets`
/// takes over from the one before it. The installation ID is the node ID. Returns when `stop`
/// resolves or `sockets` closes. The caller holds the state directory's lock.
pub async fn serve_until(
    state: StateDir,
    sockets: mpsc::UnboundedReceiver<Box<Socket>>,
    stop: impl Future<Output = ()> + Send + 'static,
) -> Result<RunExit> {
    let installation_id = {
        let state = state.clone();
        blocking(move || state.installation_id()).await?
    };
    let identity = NodeIdentity {
        node_id: installation_id.clone(),
        installation_id,
    };
    drive(state, identity, Source::Listen(sockets, None), stop).await
}

/// Where connections come from.
enum Source {
    /// Dial the stored endpoint, redialing with backoff.
    Dial,
    /// Accepted connections, and one that arrived while another was served.
    Listen(mpsc::UnboundedReceiver<Box<Socket>>, Option<Box<Socket>>),
}

async fn drive(
    state: StateDir,
    identity: NodeIdentity,
    source: Source,
    stop: impl Future<Output = ()> + Send + 'static,
) -> Result<RunExit> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    #[allow(unused_mut)]
    let (mut session, outbox) = Session::new(Role::Node(identity), clock.clone());
    #[cfg(feature = "testing")]
    if std::env::var_os(SINGLE_LANE_ENV).is_some() {
        tracing::warn!("{SINGLE_LANE_ENV} is set: sending through a single lane");
        session.set_single_lane(true);
    }
    let node = {
        let (state, outbox) = (state.clone(), outbox.clone());
        Arc::new(blocking(move || Node::open(state, outbox)).await?)
    };

    let (stop_tx, stop_rx) = watch::channel(false);
    let stopper = tokio::spawn(async move {
        stop.await;
        let _ = stop_tx.send(true);
    });
    // Each status boot reports from now on is a `node.boot`; `node.ready` carries the current.
    let boot = crate::boot::statuses().map(|mut statuses| {
        let outbox = outbox.clone();
        tokio::spawn(async move {
            while statuses.changed().await.is_ok() {
                let status = statuses.borrow_and_update().clone();
                if let Some(status) = status {
                    outbox.node_boot(status);
                }
            }
        })
    });
    let (to_handlers, from_driver) = mpsc::unbounded_channel();
    let handlers = tokio::spawn(serve(node.clone(), outbox, from_driver));
    let mut driver = Driver {
        state,
        source,
        session,
        node: node.clone(),
        clock,
        handlers: to_handlers,
        stop: stop_rx,
        ready: None,
    };
    let exit = driver.run().await;
    if let Some(boot) = boot {
        boot.abort();
    }
    handlers.abort();
    stopper.abort();
    node.shutdown().await;
    exit
}

/// Resolves on Ctrl-C or SIGTERM, or when happy-supervisor-boot closes stdin (boot.md,
/// Running).
pub async fn shutdown_signal() {
    tokio::select! {
        () = signal() => {}
        () = crate::boot::closed() => {}
    }
}

async fn signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(err) => {
                tracing::warn!("cannot watch for SIGTERM: {err}");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

type Handler = Pin<Box<dyn Future<Output = Option<Lane>> + Send>>;
type Received = (MsgId, String, Value);

/// Runs every received message through `dispatch` and queues the replies. Each handler is a
/// task of its own, so handlers run in parallel and replies may come back in any order (api.md,
/// Commands and replies), except that the messages of one process, watch or stream are handled
/// one at a time, in delivery order (api.md, Lanes).
async fn serve(node: Arc<Node>, outbox: Outbox, mut messages: mpsc::UnboundedReceiver<Received>) {
    let mut running: FuturesUnordered<Handler> = FuturesUnordered::new();
    // Entities with a handler running, and their messages waiting behind it.
    let mut busy: HashMap<Lane, VecDeque<Received>> = HashMap::new();
    let start = |lane: Option<Lane>, (id, kind, body): Received| -> Handler {
        let (node, outbox) = (node.clone(), outbox.clone());
        let handler = tokio::spawn(async move {
            if let Some(result) = dispatch(&node, &kind, body).await {
                outbox.reply(id, result);
            }
        });
        Box::pin(async move {
            if let Err(err) = handler.await {
                tracing::error!("a handler failed: {err}");
            }
            lane
        })
    };
    loop {
        tokio::select! {
            message = messages.recv() => {
                let Some(message) = message else { return };
                let lane = match lane_of(&message.1, &message.2) {
                    lane @ (Lane::Exec(_) | Lane::Watch(_) | Lane::Stream(_)) => lane,
                    Lane::Control | Lane::Own => {
                        running.push(start(None, message));
                        continue;
                    }
                };
                match busy.get_mut(&lane) {
                    Some(waiting) => waiting.push_back(message),
                    None => {
                        busy.insert(lane.clone(), VecDeque::new());
                        running.push(start(Some(lane), message));
                    }
                }
            }
            Some(lane) = running.next(), if !running.is_empty() => {
                let Some(lane) = lane else { continue };
                match busy.get_mut(&lane).and_then(VecDeque::pop_front) {
                    Some(next) => running.push(start(Some(lane), next)),
                    None => {
                        busy.remove(&lane);
                    }
                }
            }
        }
    }
}

struct Driver {
    state: StateDir,
    source: Source,
    session: Session,
    node: Arc<Node>,
    clock: Arc<dyn Clock>,
    handlers: mpsc::UnboundedSender<Received>,
    stop: watch::Receiver<bool>,
    /// The `node.ready` collection in progress, and the session it is for.
    ready: Option<(SessionId, tokio::task::JoinHandle<Result<Ready>>)>,
}

type Ready = (
    crate::protocol::NodeInfo,
    Vec<crate::protocol::ExecSummary>,
    Vec<crate::protocol::WatchId>,
);

/// How one connection ended.
enum Ended {
    Revoked,
    Stopped,
    /// Redial. `up` is how long the connection was open.
    Retry {
        up: Duration,
    },
}

impl Driver {
    async fn run(&mut self) -> Result<RunExit> {
        let mut backoff = BACKOFF_MIN;
        loop {
            let ended = match self.source {
                Source::Dial => self.connection().await?,
                Source::Listen(..) => match self.accepted().await {
                    // A client that says `revoked` revokes nothing here: wait for the next.
                    Ended::Revoked | Ended::Retry { .. } => continue,
                    Ended::Stopped => return Ok(RunExit::Interrupted),
                },
            };
            match ended {
                Ended::Revoked => return Ok(RunExit::Revoked),
                Ended::Stopped => return Ok(RunExit::Interrupted),
                Ended::Retry { up } => {
                    if up >= STABLE_AFTER {
                        backoff = BACKOFF_MIN;
                    }
                }
            }
            let delay = jitter(backoff);
            backoff = (backoff * 2).min(BACKOFF_MAX);
            tracing::info!("reconnecting in {} ms", delay.as_millis());
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = self.stop.wait_for(|stopped| *stopped) => return Ok(RunExit::Interrupted),
            }
        }
    }

    /// Dials once and serves the connection until it ends. `Err` is a stored credential that
    /// can never work, such as an endpoint that is not `wss://`.
    async fn connection(&mut self) -> Result<Ended> {
        let state = self.state.clone();
        let credentials = blocking(move || state.credentials())
            .await?
            .ok_or_else(|| Error::new(ErrorKind::Io, "the stored credentials are gone"))?;
        let endpoint = crate::enroll::check_url(&credentials.endpoint, "wss", "ws")?;
        let dial = tokio::time::timeout(
            DIAL_TIMEOUT,
            crate::ws::dial(&endpoint, &credentials.node_token),
        );
        let dialed = tokio::select! {
            dialed = dial => dialed,
            _ = self.stop.wait_for(|stopped| *stopped) => return Ok(Ended::Stopped),
        };
        let retry = Ok(Ended::Retry { up: Duration::ZERO });
        let socket = match dialed {
            Err(_) => {
                tracing::warn!("connecting to {endpoint} timed out");
                return retry;
            }
            Ok(Ok(Dialed::Refused(status))) => {
                tracing::error!("{endpoint} refused this node's credential ({status})");
                return Ok(Ended::Revoked);
            }
            Ok(Err(err)) => {
                tracing::warn!("connecting to {endpoint} failed: {err}");
                return retry;
            }
            Ok(Ok(Dialed::Open(socket))) => socket,
        };
        tracing::info!(
            "connected to {endpoint} ({}; {})",
            crate::ws::SUBPROTOCOL,
            socket.extensions().unwrap_or("uncompressed")
        );

        Ok(self.connected(*socket).await)
    }

    /// Waits for the next accepted connection and serves it.
    async fn accepted(&mut self) -> Ended {
        let Source::Listen(sockets, waiting) = &mut self.source else {
            return Ended::Stopped;
        };
        let socket = match waiting.take() {
            Some(socket) => socket,
            None => tokio::select! {
                socket = sockets.recv() => match socket {
                    Some(socket) => socket,
                    None => return Ended::Stopped,
                },
                _ = self.stop.wait_for(|stopped| *stopped) => return Ended::Stopped,
            },
        };
        tracing::info!("a control plane connected");
        self.connected(*socket).await
    }

    async fn connected(&mut self, socket: Socket) -> Ended {
        let opened = Instant::now();
        self.session.connected();
        let ended = self.serve_connection(socket).await;
        self.session.disconnected();
        match ended {
            Served::Revoked => Ended::Revoked,
            Served::Stopped => Ended::Stopped,
            Served::Closed => Ended::Retry {
                up: opened.elapsed(),
            },
        }
    }

    /// Moves frames until the connection ends. One frame is written at a time, and the socket
    /// is read while it is written, so neither side can block the other with a full buffer.
    async fn serve_connection(&mut self, mut socket: Socket) -> Served {
        let mut ping = tokio::time::interval_at(Instant::now() + PING_EVERY, PING_EVERY);
        let mut ping_due = false;
        let mut last_frame = Instant::now();
        let mut revoked = false;
        let mut stopping = false;
        loop {
            while let Some(incoming) = self.session.poll_incoming() {
                revoked |= self.handle(incoming);
            }
            if self.ready.is_none() && self.session.needs_ready() {
                self.collect_ready(Duration::ZERO);
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
                    Some(Err(err)) => {
                        tracing::warn!("writing to the control plane failed: {err}");
                        return Served::Closed;
                    }
                    None if self.session.is_closing() => {
                        socket.close().await;
                        return if revoked {
                            Served::Revoked
                        } else if stopping {
                            Served::Stopped
                        } else {
                            Served::Closed
                        };
                    }
                    None => {}
                }
            }

            let deadline = self.session.deadline().map(|at| {
                let wait = at.saturating_sub(self.clock.now_ms());
                Instant::now() + Duration::from_millis(wait)
            });
            let ready_slot = &mut self.ready;
            let ready = async {
                match ready_slot {
                    Some((_, task)) => task.await,
                    None => std::future::pending().await,
                }
            };
            let takeover = async {
                match &mut self.source {
                    Source::Listen(sockets, _) => sockets.recv().await,
                    Source::Dial => std::future::pending().await,
                }
            };
            let wake = tokio::select! {
                event = socket.next() => Wake::Socket(event),
                Some(next) = takeover => Wake::Takeover(next),
                _ = self.session.changed() => Wake::Changed,
                _ = sleep_until(deadline) => Wake::Tick,
                _ = ping.tick() => Wake::Ping,
                _ = tokio::time::sleep_until(last_frame + DEAD_AFTER) => Wake::Dead,
                collected = ready => Wake::Ready(Box::new(collected)),
                _ = self.stop.wait_for(|stopped| *stopped), if !stopping => Wake::Stop,
            };
            match wake {
                Wake::Socket(Ok(Event::Writable)) => {}
                Wake::Socket(Ok(event)) => {
                    last_frame = Instant::now();
                    match event {
                        Event::Binary(payload) => self.session.receive(&payload),
                        Event::Text => self.session.reject("a text frame"),
                        Event::Writable | Event::Control => {}
                    }
                }
                Wake::Socket(Err(err)) => {
                    tracing::warn!("the connection to the control plane ended: {err}");
                    return Served::Closed;
                }
                Wake::Takeover(next) => {
                    tracing::info!("a new connection takes over from the current one");
                    if let Source::Listen(_, waiting) = &mut self.source {
                        *waiting = Some(next);
                    }
                    socket
                        .close_with(crate::ws::CLOSE_REPLACED, "replaced by a newer connection")
                        .await;
                    return Served::Closed;
                }
                Wake::Changed => {}
                Wake::Tick => self.session.tick(),
                Wake::Ping => ping_due = true,
                Wake::Dead => {
                    tracing::warn!(
                        "no frame from the control plane for {} s; redialing",
                        DEAD_AFTER.as_secs()
                    );
                    return Served::Closed;
                }
                Wake::Ready(collected) => self.ready_collected(*collected),
                Wake::Stop => {
                    stopping = true;
                    self.session.bye(ByeReason::Shutdown, None);
                    if !self.session.is_closing() {
                        return Served::Stopped;
                    }
                }
            }
        }
    }

    /// Routes one thing the session delivered. True when the control plane revoked the node.
    fn handle(&mut self, incoming: Incoming) -> bool {
        match incoming {
            Incoming::Opened {
                session, resumed, ..
            } => {
                tracing::info!(%session, resumed, "session open");
                // What makes a version boot started healthy (boot.md, Running).
                crate::boot::connected();
                false
            }
            Incoming::Message { id, kind, body } => {
                let _ = self.handlers.send((id, kind, body));
                false
            }
            Incoming::Reply { to, .. } => {
                tracing::debug!(%to, "ignored a reply to a command this node never sent");
                false
            }
            Incoming::Lost { session, reason } => {
                tracing::warn!(%session, "session lost: {reason:?}");
                self.node.session_lost();
                if let Some((_, task)) = self.ready.take() {
                    task.abort();
                }
                matches!(
                    reason,
                    LostReason::PeerBye(ref bye) if bye.reason == ByeReason::Revoked
                )
            }
        }
    }

    /// Starts collecting `node.ready`'s state for the waiting session, after `delay`.
    fn collect_ready(&mut self, delay: Duration) {
        let Some(session) = self.session.session() else {
            return;
        };
        let node = self.node.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            node.ready_state().await
        });
        self.ready = Some((session, task));
    }

    fn ready_collected(
        &mut self,
        collected: std::result::Result<Result<Ready>, tokio::task::JoinError>,
    ) {
        let Some((for_session, _)) = self.ready.take() else {
            return;
        };
        match collected {
            Ok(Ok((info, execs, watches))) => {
                // A collection for a session lost meanwhile is stale; collect again.
                if self.session.session() == Some(for_session)
                    && self.session.needs_ready()
                    && let Err(err) = self.session.ready(info, execs, watches)
                {
                    tracing::warn!("node.ready: {err}");
                }
            }
            Ok(Err(err)) => {
                tracing::warn!("collecting node.ready failed: {err}");
                self.collect_ready(READY_RETRY);
            }
            Err(err) => tracing::warn!("collecting node.ready failed: {err}"),
        }
    }
}

enum Served {
    Revoked,
    Stopped,
    Closed,
}

/// What woke the connection loop.
enum Wake {
    Socket(std::result::Result<Event, yawc::WebSocketError>),
    /// A listener accepted another connection, which replaces this one.
    Takeover(Box<Socket>),
    Changed,
    Tick,
    Ping,
    Dead,
    Ready(Box<std::result::Result<Result<Ready>, tokio::task::JoinError>>),
    Stop,
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// `delay` ±20 %.
fn jitter(delay: Duration) -> Duration {
    // The low 62 bits of a UUIDv7 are random.
    let random = (uuid::Uuid::now_v7().as_u128() & 0xffff) as f64 / f64::from(u16::MAX);
    delay.mul_f64(0.8 + 0.4 * random)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| Error::new(ErrorKind::Io, format!("a blocking task failed: {err}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_within_a_fifth() {
        for _ in 0..1000 {
            let d = jitter(Duration::from_secs(10));
            assert!(
                d >= Duration::from_secs(8) && d <= Duration::from_secs(12),
                "{d:?}"
            );
        }
    }
}
