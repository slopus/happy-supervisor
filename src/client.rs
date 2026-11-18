//! The connection to the control plane (docs/api.md, Connection). Owned by the transport
//! track; the scaffold froze the signature.
//!
//! One [`Session`] lives for the whole run, across connections. The driver moves frames between
//! it and the WebSocket and follows docs/architecture.md's driver loop. Every protocol rule is in
//! [`link`](crate::link); nothing here decides what is resent, acked or lost.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::FuturesUnordered;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode, header};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self, Message};

use crate::dispatch::{Node, dispatch};
use crate::error::{Error, ErrorKind, Result};
use crate::link::{Clock, Incoming, LostReason, NodeIdentity, Outbox, Role, Session, SystemClock};
use crate::protocol::{ByeReason, MAX_FRAME_BYTES, MsgId, SessionId, Value};
use crate::state::StateDir;
use crate::wire::Wire;

pub const PING_EVERY: Duration = Duration::from_secs(15);
pub const DEAD_AFTER: Duration = Duration::from_secs(45);
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// A connection up this long resets the backoff.
pub const STABLE_AFTER: Duration = Duration::from_secs(60);
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a failed `node.ready` collection waits before it is tried again.
const READY_RETRY: Duration = Duration::from_secs(1);

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
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let (session, outbox) = Session::new(Role::Node(identity), clock.clone());
    let node = {
        let (state, outbox) = (state.clone(), outbox.clone());
        Arc::new(blocking(move || Node::open(state, outbox)).await?)
    };

    let (stop_tx, stop_rx) = watch::channel(false);
    let stopper = tokio::spawn(async move {
        stop.await;
        let _ = stop_tx.send(true);
    });
    let (to_handlers, from_driver) = mpsc::unbounded_channel();
    let handlers = tokio::spawn(serve(node.clone(), outbox, from_driver));
    let mut driver = Driver {
        state,
        session,
        node: node.clone(),
        clock,
        handlers: to_handlers,
        stop: stop_rx,
        ready: None,
    };
    let exit = driver.run().await;
    handlers.abort();
    stopper.abort();
    node.shutdown().await;
    exit
}

async fn shutdown_signal() {
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

/// Runs every received message through `dispatch` and queues the replies. Messages start in
/// arrival order (ID order) on this one task, and then run concurrently, so replies may come
/// back in any order (api.md, Commands and replies).
async fn serve(
    node: Arc<Node>,
    outbox: Outbox,
    mut messages: mpsc::UnboundedReceiver<(MsgId, String, Value)>,
) {
    let mut running = FuturesUnordered::new();
    loop {
        tokio::select! {
            message = messages.recv() => {
                let Some((id, kind, body)) = message else { return };
                let node = node.clone();
                running.push(async move { (id, dispatch(&node, &kind, body).await) });
            }
            Some((id, result)) = running.next(), if !running.is_empty() => {
                if let Some(result) = result {
                    outbox.reply(id, result);
                }
            }
        }
    }
}

struct Driver {
    state: StateDir,
    session: Session,
    node: Arc<Node>,
    clock: Arc<dyn Clock>,
    handlers: mpsc::UnboundedSender<(MsgId, String, Value)>,
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
            match self.connection().await? {
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
        let mut request = endpoint
            .as_str()
            .into_client_request()
            .map_err(|err| Error::invalid_params(format!("bad endpoint {endpoint}: {err}")))?;
        let bearer = HeaderValue::from_str(&format!("Bearer {}", credentials.node_token))
            .map_err(|_| Error::invalid_params("the node token is not a valid header value"))?;
        request.headers_mut().insert(header::AUTHORIZATION, bearer);
        request.headers_mut().insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(&Wire::OFFERED.join(", ")).expect("subprotocols are ASCII"),
        );
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_FRAME_BYTES + 1))
            .max_frame_size(Some(MAX_FRAME_BYTES + 1));
        let dial = tokio::time::timeout(
            DIAL_TIMEOUT,
            tokio_tungstenite::connect_async_with_config(request, Some(config), true),
        );
        let dialed = tokio::select! {
            dialed = dial => dialed,
            _ = self.stop.wait_for(|stopped| *stopped) => return Ok(Ended::Stopped),
        };
        let retry = Ok(Ended::Retry { up: Duration::ZERO });
        let (socket, response) = match dialed {
            Err(_) => {
                tracing::warn!("connecting to {endpoint} timed out");
                return retry;
            }
            Ok(Err(tungstenite::Error::Http(response)))
                if matches!(
                    response.status(),
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                ) =>
            {
                tracing::error!(
                    "{endpoint} refused this node's credential ({})",
                    response.status()
                );
                return Ok(Ended::Revoked);
            }
            Ok(Err(err)) => {
                tracing::warn!("connecting to {endpoint} failed: {err}");
                return retry;
            }
            Ok(Ok(dialed)) => dialed,
        };
        let wire = response
            .headers()
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .and_then(|v| v.to_str().ok())
            .and_then(Wire::from_subprotocol);
        let Some(wire) = wire else {
            tracing::warn!("{endpoint} chose neither link subprotocol; closing");
            let (mut sink, _) = socket.split();
            let _ = sink.close().await;
            return retry;
        };
        tracing::info!("connected to {endpoint} ({})", wire.subprotocol());

        let opened = Instant::now();
        self.session.connected(wire);
        let ended = self.serve_connection(socket).await;
        self.session.disconnected();
        Ok(match ended {
            Served::Revoked => Ended::Revoked,
            Served::Stopped => Ended::Stopped,
            Served::Closed => Ended::Retry {
                up: opened.elapsed(),
            },
        })
    }

    async fn serve_connection<S>(&mut self, socket: S) -> Served
    where
        S: futures_util::Stream<Item = tungstenite::Result<Message>>
            + futures_util::Sink<Message, Error = tungstenite::Error>
            + Unpin,
    {
        let (mut sink, mut stream) = socket.split();
        let mut ping = tokio::time::interval_at(Instant::now() + PING_EVERY, PING_EVERY);
        let mut last_frame = Instant::now();
        let mut revoked = false;
        let mut stopping = false;
        loop {
            // Drain until nothing moves: handling incoming can queue frames, and the reverse.
            loop {
                let mut moved = false;
                while let Some(payload) = self.session.poll_transmit() {
                    moved = true;
                    if let Err(err) = sink.feed(Message::Binary(payload.into())).await {
                        tracing::warn!("writing to the control plane failed: {err}");
                        return Served::Closed;
                    }
                }
                while let Some(incoming) = self.session.poll_incoming() {
                    moved = true;
                    revoked |= self.handle(incoming);
                }
                if self.ready.is_none() && self.session.needs_ready() {
                    self.collect_ready(Duration::ZERO);
                }
                if !moved {
                    break;
                }
            }
            if let Err(err) = sink.flush().await {
                tracing::warn!("writing to the control plane failed: {err}");
                return Served::Closed;
            }
            if self.session.is_closing() {
                let _ = sink.close().await;
                return if revoked {
                    Served::Revoked
                } else if stopping {
                    Served::Stopped
                } else {
                    Served::Closed
                };
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
            let wake = tokio::select! {
                frame = stream.next() => Wake::Frame(frame),
                _ = self.session.changed() => Wake::Changed,
                _ = sleep_until(deadline) => Wake::Tick,
                _ = ping.tick() => Wake::Ping,
                _ = tokio::time::sleep_until(last_frame + DEAD_AFTER) => Wake::Dead,
                collected = ready => Wake::Ready(Box::new(collected)),
                _ = self.stop.wait_for(|stopped| *stopped), if !stopping => Wake::Stop,
            };
            match wake {
                Wake::Frame(frame) => {
                    last_frame = Instant::now();
                    match frame {
                        Some(Ok(Message::Binary(payload))) => self.session.receive(&payload),
                        Some(Ok(Message::Text(_))) => self.session.reject("a text frame"),
                        Some(Ok(Message::Close(_))) | None => return Served::Closed,
                        Some(Ok(_)) => {}
                        Some(Err(err)) => {
                            tracing::warn!("reading from the control plane failed: {err}");
                            return Served::Closed;
                        }
                    }
                }
                Wake::Changed => {}
                Wake::Tick => self.session.tick(),
                Wake::Ping => {
                    if sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                        return Served::Closed;
                    }
                }
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
    Frame(Option<tungstenite::Result<Message>>),
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
