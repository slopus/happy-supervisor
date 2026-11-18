//! The link protocol (docs/api.md, Link protocol) as a sans-IO state machine.
//!
//! A [`Session`] holds no socket and starts no task. Its driver (the node's `client`, or the test
//! control plane) owns the WebSocket and feeds the session what happens to it:
//! [`connected`](Session::connected) with the negotiated [`Wire`],
//! [`receive`](Session::receive) for each binary frame,
//! [`disconnected`](Session::disconnected), and [`tick`](Session::tick) at
//! [`deadline`](Session::deadline). After each call it drains
//! [`poll_transmit`](Session::poll_transmit) into the socket and
//! [`poll_incoming`](Session::poll_incoming) into its handlers, and closes the socket once
//! [`is_closing`](Session::is_closing) is set and nothing is left to transmit. It also waits on
//! [`changed`](Session::changed), which fires after each [`Outbox`] call.
//!
//! One `Session` lives as long as its peer relationship, across connections and sessions. The
//! node has one. The control plane has one per node. [`Role`] is the only difference.
//!
//! Sending goes through [`Outbox`], a cloneable handle that exec, watch and the driver use from
//! any task. Each message gets its UUIDv7 and its CBOR frame when it is queued, and the same
//! bytes are resent after a reconnect. Compression, when the connection uses it, is applied per
//! transmission.
//!
//! Messages queued while no session is live wait in the queue and go out once one is. On the
//! node a new session goes live only after [`Session::ready`], whose `node.ready` takes an ID
//! reserved before anything else was queued, so it is always the session's first message.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::Serialize;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::protocol::{
    ACK_DELAY_MS, ACK_EVERY_MSGS, Ack, Bye, ByeReason, Bytes, Change, DROPPABLE_QUEUE_BYTES,
    ExecExit, ExecId, ExecOutput, ExecSummary, ExecTimedOut, ExitStatus, Frame, Hello, MsgId,
    NodeInfo, NodeReady, Outcome, REPLY_KIND, RETAINED_QUEUE_BYTES, Reply, SessionId, Stream,
    TimeoutAction, True, WatchEvent, WatchEventBody, WatchId, Welcome,
};
use crate::wire::{Value, Wire, from_cbor, from_value, to_cbor};

/// Milliseconds since the Unix epoch. Message IDs carry it, and every timer reads it.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    }
}

/// A clock that moves only when told to, for tests.
#[derive(Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(now_ms: u64) -> Arc<ManualClock> {
        Arc::new(ManualClock(AtomicU64::new(now_ms)))
    }

    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// Dials, sends `hello`, and sends `node.ready` first in each new session.
    Node(NodeIdentity),
    /// Answers `hello` with `welcome`, chooses session IDs, and keeps a dropped session for
    /// `resume_window_ms`.
    ControlPlane { resume_window_ms: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeIdentity {
    pub node_id: String,
    pub installation_id: String,
}

/// Queue budgets (api.md, Event delivery).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// For `exec.output` and `watch.event` changes. Past it they are dropped and accounted.
    pub droppable_bytes: usize,
    /// For everything else. Past it the session is lost with `queue_overflow`.
    pub retained_bytes: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            droppable_bytes: DROPPABLE_QUEUE_BYTES,
            retained_bytes: RETAINED_QUEUE_BYTES,
        }
    }
}

/// What the session hands its driver.
#[derive(Clone, Debug, PartialEq)]
pub enum Incoming {
    /// A handshake finished. `hello` is the node's, on the control plane. On the node, check
    /// [`Session::needs_ready`] next.
    Opened {
        session: SessionId,
        resumed: bool,
        hello: Option<Hello>,
    },
    /// A message to handle: a command, or an event. Delivered once per session, in ID order.
    Message {
        id: MsgId,
        kind: String,
        body: Value,
    },
    Reply {
        to: MsgId,
        result: Result<Value>,
    },
    /// The session cannot be recovered. Its queue was discarded, and commands it carried will
    /// never be answered.
    Lost {
        session: SessionId,
        reason: LostReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LostReason {
    /// The `hello`/`welcome` exchange started a new session instead.
    NotResumed,
    /// The connection stayed down longer than the resume window.
    WindowElapsed,
    /// The peer sent `bye`.
    PeerBye(Bye),
    /// This side sent `bye`.
    SentBye(ByeReason),
    /// Messages that must not be dropped passed [`Limits::retained_bytes`].
    QueueOverflow,
    /// The peer sent something invalid. This side sent `bye` with `protocol_error`.
    ProtocolError(String),
    /// The control plane forgot the session ([`Session::forget`]), as a restart would.
    Forgotten,
}

/// The driver's end of a session.
pub struct Session {
    shared: Arc<Shared>,
}

/// The sending end of a session. Cheap to clone, usable from any task.
#[derive(Clone)]
pub struct Outbox {
    shared: Arc<Shared>,
}

struct Shared {
    state: Mutex<State>,
    changed: tokio::sync::Notify,
    clock: Arc<dyn Clock>,
}

impl Shared {
    /// Locks the state and records the time of the call.
    fn lock(&self) -> MutexGuard<'_, State> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.now = self.clock.now_ms();
        state
    }
}

/// The state locked by an [`Outbox`] call. Wakes the driver when dropped.
struct OutboxGuard<'a> {
    state: MutexGuard<'a, State>,
    changed: &'a tokio::sync::Notify,
}

impl Drop for OutboxGuard<'_> {
    fn drop(&mut self) {
        self.changed.notify_one();
    }
}

impl std::ops::Deref for OutboxGuard<'_> {
    type Target = State;

    fn deref(&self) -> &State {
        &self.state
    }
}

impl std::ops::DerefMut for OutboxGuard<'_> {
    fn deref_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

enum Conn {
    /// No connection. `since` is when the last one dropped, for the resume window.
    Down {
        since: Option<u64>,
    },
    /// Connected, `hello`/`welcome` not yet exchanged.
    Handshake,
    Open,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Class {
    Droppable,
    Retained,
    /// A watch's `overflow: true` marker. Retained.
    Overflow(WatchId),
}

struct Queued {
    id: MsgId,
    /// The CBOR frame. Budgets count its length.
    cbor: Vec<u8>,
    class: Class,
}

struct State {
    /// The clock reading of the call in progress.
    now: u64,
    node: Option<NodeIdentity>,
    resume_window_ms: Option<u64>,
    limits: Limits,
    ids: IdGen,
    conn: Conn,
    wire: Wire,
    closing: bool,

    session: Option<SessionId>,
    /// Queued messages may be transmitted. On the node, only after `node.ready` is queued.
    live: bool,
    /// The node's reserved `node.ready` ID while a new session is not yet live.
    ready_id: Option<MsgId>,
    /// The node's last lost session, for `node.ready`.
    previous: Option<SessionId>,

    queue: VecDeque<Queued>,
    /// `queue[..sent]` was written on the current connection.
    sent: usize,
    droppable_bytes: usize,
    retained_bytes: usize,
    dropped: HashMap<(ExecId, Stream), u64>,
    /// Watches whose overflow marker is queued and not yet transmitted.
    overflowed: HashSet<WatchId>,

    /// The latest message received from the peer in this session.
    cursor: Option<MsgId>,
    /// The cursor last told to the peer, by `ack` or handshake.
    acked: Option<MsgId>,
    unacked: u32,
    unacked_since: Option<u64>,
    duplicate: bool,

    /// Handshake, ack and bye frames, as CBOR, sent before queued messages.
    control: VecDeque<Vec<u8>>,
    incoming: VecDeque<Incoming>,
}

impl Session {
    pub fn new(role: Role, clock: Arc<dyn Clock>) -> (Session, Outbox) {
        let seed = Uuid::now_v7().as_u128() as u64;
        Session::with_options(role, clock, Limits::default(), seed)
    }

    /// A session with explicit budgets and ID randomness, for tests.
    pub fn with_options(
        role: Role,
        clock: Arc<dyn Clock>,
        limits: Limits,
        seed: u64,
    ) -> (Session, Outbox) {
        let (node, resume_window_ms) = match role {
            Role::Node(identity) => (Some(identity), None),
            Role::ControlPlane { resume_window_ms } => (None, Some(resume_window_ms)),
        };
        let mut ids = IdGen::new(seed);
        let ready_id = node.as_ref().map(|_| MsgId(ids.next(clock.now_ms())));
        let state = State {
            now: 0,
            node,
            resume_window_ms,
            limits,
            ids,
            conn: Conn::Down { since: None },
            wire: Wire::Plain,
            closing: false,
            session: None,
            live: false,
            ready_id,
            previous: None,
            queue: VecDeque::new(),
            sent: 0,
            droppable_bytes: 0,
            retained_bytes: 0,
            dropped: HashMap::new(),
            overflowed: HashSet::new(),
            cursor: None,
            acked: None,
            unacked: 0,
            unacked_since: None,
            duplicate: false,
            control: VecDeque::new(),
            incoming: VecDeque::new(),
        };
        let shared = Arc::new(Shared {
            state: Mutex::new(state),
            changed: tokio::sync::Notify::new(),
            clock,
        });
        (
            Session {
                shared: shared.clone(),
            },
            Outbox { shared },
        )
    }

    pub fn outbox(&self) -> Outbox {
        Outbox {
            shared: self.shared.clone(),
        }
    }

    /// A WebSocket is up, speaking `wire`. The node queues its `hello`; the control plane waits
    /// for one.
    pub fn connected(&mut self, wire: Wire) {
        let mut s = self.shared.lock();
        let now = s.now;
        s.expire(now);
        s.conn = Conn::Handshake;
        s.wire = wire;
        s.sent = 0;
        s.closing = false;
        s.control.clear();
        if let Some(node) = s.node.clone() {
            let hello = Frame::Hello(Hello {
                session: s.session,
                cursor: s.cursor,
                node_id: node.node_id,
                installation_id: node.installation_id,
                version: crate::VERSION.to_string(),
            });
            s.handshake_sent(hello);
        }
    }

    /// The WebSocket is gone.
    pub fn disconnected(&mut self) {
        let mut s = self.shared.lock();
        let since = s.session.map(|_| s.now);
        s.conn = Conn::Down { since };
        s.sent = 0;
        s.closing = false;
        s.control.clear();
    }

    /// Feeds the payload of one received binary frame.
    pub fn receive(&mut self, payload: &[u8]) {
        let mut s = self.shared.lock();
        let frame = s
            .wire
            .decode(payload)
            .and_then(|cbor| from_cbor::<Frame>(&cbor));
        match frame {
            Ok(frame) => s.receive(frame),
            Err(err) => s.protocol_error(format!("bad frame: {err}")),
        }
    }

    /// Runs the timers that are due: the ack delay and the resume window.
    pub fn tick(&mut self) {
        let mut s = self.shared.lock();
        let now = s.now;
        s.expire(now);
        if s.unacked_since.is_some_and(|t| now >= t + ACK_DELAY_MS) {
            s.ack_now();
        }
    }

    /// When [`tick`](Session::tick) next has work, in [`Clock`] milliseconds.
    pub fn deadline(&self) -> Option<u64> {
        let s = self.shared.lock();
        let ack = match s.conn {
            Conn::Open => s.unacked_since.map(|t| t + ACK_DELAY_MS),
            _ => None,
        };
        let expiry = match (&s.conn, s.session, s.resume_window_ms) {
            (Conn::Down { since: Some(t) }, Some(_), Some(window)) => Some(t + window),
            _ => None,
        };
        [ack, expiry].into_iter().flatten().min()
    }

    /// The payload of the next binary frame to write on the current connection.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        let mut s = self.shared.lock();
        let wire = s.wire;
        if let Some(frame) = s.control.pop_front() {
            return Some(wire.encode(&frame));
        }
        if !s.transmittable() {
            return None;
        }
        let index = s.sent;
        s.sent += 1;
        let queued = &s.queue[index];
        let payload = wire.encode(&queued.cbor);
        if let Class::Overflow(watch_id) = queued.class.clone() {
            s.overflowed.remove(&watch_id);
        }
        Some(payload)
    }

    pub fn poll_incoming(&mut self) -> Option<Incoming> {
        self.shared.lock().incoming.pop_front()
    }

    /// Resolves after an [`Outbox`] call, which may have left something to transmit or deliver.
    /// It can resolve with nothing new; the driver then drains and waits again.
    pub async fn changed(&self) {
        self.shared.changed.notified().await;
    }

    /// This side sent or received `bye`. Close the socket once `poll_transmit` is empty.
    pub fn is_closing(&self) -> bool {
        self.shared.lock().closing
    }

    pub fn session(&self) -> Option<SessionId> {
        self.shared.lock().session
    }

    /// The node has a new session that waits for [`Session::ready`].
    pub fn needs_ready(&self) -> bool {
        let s = self.shared.lock();
        s.node.is_some() && s.session.is_some() && !s.live
    }

    /// Queues `node.ready` as the new session's first message and lets the queue flow.
    pub fn ready(
        &mut self,
        info: NodeInfo,
        execs: Vec<ExecSummary>,
        watches: Vec<WatchId>,
    ) -> Result<()> {
        let mut s = self.shared.lock();
        let (true, Some(id)) = (
            s.node.is_some() && s.session.is_some() && !s.live,
            s.ready_id,
        ) else {
            return Err(Error::invalid_params(
                "no new session is waiting for node.ready",
            ));
        };
        let body = NodeReady {
            info,
            previous_session: s.previous,
            execs,
            watches,
        };
        let cbor = msg_cbor(id, "node.ready", &to_cbor(&body));
        s.retained_bytes += cbor.len();
        s.queue.push_front(Queued {
            id,
            cbor,
            class: Class::Retained,
        });
        s.ready_id = None;
        s.live = true;
        s.check_retained();
        Ok(())
    }

    /// Ends the session on purpose with `bye`.
    pub fn bye(&mut self, reason: ByeReason, message: Option<String>) {
        let mut s = self.shared.lock();
        s.lose(LostReason::SentBye(reason), Some(Bye { reason, message }));
    }

    /// Control plane: drops the session as a restart would, so the next `hello` gets
    /// `resumed: false`. A current connection closes without `bye`.
    pub fn forget(&mut self) {
        let mut s = self.shared.lock();
        s.lose(LostReason::Forgotten, None);
        if !matches!(s.conn, Conn::Down { .. }) {
            s.closing = true;
        }
    }

    /// Control plane: the `resumeWindowMs` of later `welcome`s.
    pub fn set_resume_window_ms(&mut self, ms: u64) {
        self.shared.lock().resume_window_ms = Some(ms);
    }
}

impl Outbox {
    fn lock(&self) -> OutboxGuard<'_> {
        OutboxGuard {
            state: self.shared.lock(),
            changed: &self.shared.changed,
        }
    }

    /// Queues a command. Its reply arrives as [`Incoming::Reply`] with this ID in `to`.
    pub fn command<T: Serialize + ?Sized>(&self, kind: &str, body: &T) -> MsgId {
        self.lock().enqueue(kind, body, Class::Retained)
    }

    /// Queues the reply to the command `to`.
    pub fn reply(&self, to: MsgId, result: Result<Value>) {
        let reply = Reply {
            to,
            outcome: Outcome::from(result),
        };
        self.lock().enqueue(REPLY_KIND, &reply, Class::Retained);
    }

    /// Queues one chunk of output, at most
    /// [`MAX_OUTPUT_CHUNK_BYTES`](crate::protocol::MAX_OUTPUT_CHUNK_BYTES). If the droppable
    /// budget is full it is dropped, and its size goes into the stream's next `droppedBytes`.
    pub fn exec_output(&self, exec_id: ExecId, stream: Stream, data: Vec<u8>) {
        let mut s = self.lock();
        let key = (exec_id, stream);
        let output = ExecOutput {
            exec_id: key.0.clone(),
            stream,
            dropped_bytes: s.dropped.get(&key).copied().unwrap_or(0),
            data: Bytes(data),
        };
        let body = to_cbor(&output);
        if s.fits_droppable("exec.output", &body) {
            s.dropped.remove(&key);
            s.enqueue_cbor("exec.output", &body, Class::Droppable);
        } else {
            *s.dropped.entry(key).or_default() += output.data.0.len() as u64;
        }
    }

    /// Queues that a timeout elapsed, after a chunk carrying any dropped output count. After a
    /// `background` action, send no more output for the process.
    pub fn exec_timed_out(&self, exec_id: ExecId, action: TimeoutAction, log_bytes: u64) {
        let mut s = self.lock();
        s.flush_dropped(&exec_id);
        let event = ExecTimedOut {
            exec_id,
            action,
            log_bytes,
        };
        s.enqueue("exec.timedOut", &event, Class::Retained);
    }

    /// Queues a process's exit, after a chunk carrying any dropped output count.
    pub fn exec_exit(&self, exec_id: ExecId, exit: ExitStatus, log_bytes: u64) {
        let mut s = self.lock();
        s.flush_dropped(&exec_id);
        let event = ExecExit {
            exec_id,
            exit,
            log_bytes,
        };
        s.enqueue("exec.exit", &event, Class::Retained);
    }

    /// Queues a batch of at most
    /// [`MAX_CHANGES_PER_EVENT`](crate::protocol::MAX_CHANGES_PER_EVENT) changes. If the
    /// droppable budget is full, `overflow: true` is queued instead. Until that marker is
    /// transmitted, further changes of the watch are discarded, since the rescan it asks for
    /// covers them.
    pub fn watch_changes(&self, watch_id: WatchId, changes: Vec<Change>) {
        let mut s = self.lock();
        if changes.is_empty() || s.overflowed.contains(&watch_id) {
            return;
        }
        let event = WatchEvent {
            watch_id,
            body: WatchEventBody::Changes { changes },
        };
        let body = to_cbor(&event);
        if s.fits_droppable("watch.event", &body) {
            s.enqueue_cbor("watch.event", &body, Class::Droppable);
        } else {
            s.overflow(event.watch_id);
        }
    }

    /// Queues `overflow: true`, for a watch whose OS queue overflowed.
    pub fn watch_overflow(&self, watch_id: WatchId) {
        let mut s = self.lock();
        if !s.overflowed.contains(&watch_id) {
            s.overflow(watch_id);
        }
    }
}

impl State {
    fn transmittable(&self) -> bool {
        matches!(self.conn, Conn::Open)
            && self.live
            && !self.closing
            && self.sent < self.queue.len()
    }

    fn handshake_sent(&mut self, frame: Frame) {
        self.control.push_back(frame_cbor(&frame));
        self.acked = self.cursor;
        self.unacked = 0;
        self.unacked_since = None;
        self.duplicate = false;
    }

    fn receive(&mut self, frame: Frame) {
        match (&self.conn, frame) {
            (Conn::Handshake, Frame::Hello(hello)) if self.node.is_none() => self.on_hello(hello),
            (Conn::Handshake, Frame::Welcome(welcome)) if self.node.is_some() => {
                self.on_welcome(welcome)
            }
            (Conn::Open, Frame::Msg(msg)) => self.on_msg(msg.id, msg.kind, msg.body),
            (Conn::Open, Frame::Ack(Ack { cursor })) => self.confirmed(Some(cursor)),
            (Conn::Handshake | Conn::Open, Frame::Bye(bye)) => {
                self.lose(LostReason::PeerBye(bye), None);
                self.closing = true;
            }
            (Conn::Down { .. }, _) => {}
            (_, frame) => {
                let t = match frame {
                    Frame::Hello(_) => "hello",
                    Frame::Welcome(_) => "welcome",
                    Frame::Msg(_) => "msg",
                    Frame::Ack(_) => "ack",
                    Frame::Bye(_) => "bye",
                };
                self.protocol_error(format!("unexpected `{t}` frame"));
            }
        }
    }

    fn on_hello(&mut self, hello: Hello) {
        let resumed = hello.session.is_some() && hello.session == self.session;
        if resumed {
            self.confirmed(hello.cursor);
        } else {
            if self.session.is_some() {
                self.lose(LostReason::NotResumed, None);
            }
            self.session = Some(SessionId(self.ids.next(self.now)));
            self.cursor = None;
            self.live = true;
        }
        let session = self.session.expect("set above");
        self.conn = Conn::Open;
        self.sent = 0;
        let welcome = Frame::Welcome(Welcome {
            session,
            resumed,
            cursor: if resumed { self.cursor } else { None },
            resume_window_ms: self.resume_window_ms.unwrap_or(0),
        });
        self.handshake_sent(welcome);
        self.incoming.push_back(Incoming::Opened {
            session,
            resumed,
            hello: Some(hello),
        });
    }

    fn on_welcome(&mut self, welcome: Welcome) {
        self.resume_window_ms = Some(welcome.resume_window_ms);
        if welcome.resumed {
            if self.session != Some(welcome.session) {
                return self.protocol_error(format!(
                    "welcome resumed session {}, which this node did not ask for",
                    welcome.session
                ));
            }
            self.confirmed(welcome.cursor);
        } else {
            if self.session.is_some() {
                self.lose(LostReason::NotResumed, None);
            }
            self.session = Some(welcome.session);
            self.cursor = None;
            self.acked = None;
        }
        self.conn = Conn::Open;
        self.sent = 0;
        self.incoming.push_back(Incoming::Opened {
            session: welcome.session,
            resumed: welcome.resumed,
            hello: None,
        });
    }

    fn on_msg(&mut self, id: MsgId, kind: String, body: Value) {
        if self.cursor.is_some_and(|cursor| id <= cursor) {
            self.duplicate = true;
            self.unacked_since.get_or_insert(self.now);
            return;
        }
        let incoming = if kind == REPLY_KIND {
            match from_value::<Reply>(body) {
                Ok(reply) => Incoming::Reply {
                    to: reply.to,
                    result: reply.outcome.into(),
                },
                Err(err) => return self.protocol_error(format!("bad reply: {err}")),
            }
        } else {
            Incoming::Message { id, kind, body }
        };
        self.cursor = Some(id);
        self.unacked += 1;
        self.unacked_since.get_or_insert(self.now);
        self.incoming.push_back(incoming);
        if self.unacked >= ACK_EVERY_MSGS {
            self.ack_now();
        }
    }

    /// The peer confirmed everything up to `cursor`.
    fn confirmed(&mut self, cursor: Option<MsgId>) {
        let Some(cursor) = cursor else { return };
        while self.queue.front().is_some_and(|q| q.id <= cursor) {
            let queued = self.queue.pop_front().expect("checked");
            self.sent = self.sent.saturating_sub(1);
            match queued.class {
                Class::Droppable => self.droppable_bytes -= queued.cbor.len(),
                Class::Retained => self.retained_bytes -= queued.cbor.len(),
                Class::Overflow(watch_id) => {
                    self.retained_bytes -= queued.cbor.len();
                    self.overflowed.remove(&watch_id);
                }
            }
        }
    }

    fn ack_now(&mut self) {
        if !matches!(self.conn, Conn::Open) {
            return;
        }
        if let Some(cursor) = self.cursor
            && (self.acked != Some(cursor) || self.duplicate)
        {
            self.control
                .push_back(frame_cbor(&Frame::Ack(Ack { cursor })));
            self.acked = Some(cursor);
        }
        self.unacked = 0;
        self.unacked_since = None;
        self.duplicate = false;
    }

    fn expire(&mut self, now: u64) {
        if let (Conn::Down { since: Some(t) }, Some(_), Some(window)) =
            (&self.conn, self.session, self.resume_window_ms)
            && now >= t + window
        {
            self.lose(LostReason::WindowElapsed, None);
            self.conn = Conn::Down { since: None };
        }
    }

    fn protocol_error(&mut self, message: String) {
        let bye = Bye {
            reason: ByeReason::ProtocolError,
            message: Some(message.clone()),
        };
        self.lose(LostReason::ProtocolError(message), Some(bye));
    }

    /// Discards the session and its queue. With `bye`, tells the peer and closes.
    fn lose(&mut self, reason: LostReason, bye: Option<Bye>) {
        if let Some(bye) = bye
            && !matches!(self.conn, Conn::Down { .. })
        {
            self.control.push_back(frame_cbor(&Frame::Bye(bye)));
            self.closing = true;
        }
        self.queue.clear();
        self.sent = 0;
        self.droppable_bytes = 0;
        self.retained_bytes = 0;
        self.dropped.clear();
        self.overflowed.clear();
        self.cursor = None;
        self.acked = None;
        self.unacked = 0;
        self.unacked_since = None;
        self.duplicate = false;
        self.live = false;
        if self.node.is_some() {
            self.ready_id = Some(MsgId(self.ids.next(self.now)));
        }
        if let Some(session) = self.session.take() {
            if self.node.is_some() {
                self.previous = Some(session);
            }
            self.incoming.push_back(Incoming::Lost { session, reason });
        }
    }

    fn fits_droppable(&self, kind: &str, body: &[u8]) -> bool {
        self.droppable_bytes + msg_cbor_len(kind, body) <= self.limits.droppable_bytes
    }

    fn enqueue<T: Serialize + ?Sized>(&mut self, kind: &str, body: &T, class: Class) -> MsgId {
        self.enqueue_cbor(kind, &to_cbor(body), class)
    }

    fn enqueue_cbor(&mut self, kind: &str, body: &[u8], class: Class) -> MsgId {
        let id = MsgId(self.ids.next(self.now));
        let cbor = msg_cbor(id, kind, body);
        match class {
            Class::Droppable => self.droppable_bytes += cbor.len(),
            Class::Retained | Class::Overflow(_) => self.retained_bytes += cbor.len(),
        }
        self.queue.push_back(Queued { id, cbor, class });
        self.check_retained();
        id
    }

    fn check_retained(&mut self) {
        if self.retained_bytes > self.limits.retained_bytes {
            let bye = Bye {
                reason: ByeReason::QueueOverflow,
                message: None,
            };
            self.lose(LostReason::QueueOverflow, Some(bye));
        }
    }

    fn flush_dropped(&mut self, exec_id: &ExecId) {
        for stream in [Stream::Stdout, Stream::Stderr] {
            if let Some(dropped_bytes) = self.dropped.remove(&(exec_id.clone(), stream)) {
                let output = ExecOutput {
                    exec_id: exec_id.clone(),
                    stream,
                    data: Bytes::default(),
                    dropped_bytes,
                };
                self.enqueue("exec.output", &output, Class::Retained);
            }
        }
    }

    fn overflow(&mut self, watch_id: WatchId) {
        let event = WatchEvent {
            watch_id: watch_id.clone(),
            body: WatchEventBody::Overflow { overflow: True },
        };
        self.overflowed.insert(watch_id.clone());
        self.enqueue("watch.event", &event, Class::Overflow(watch_id));
    }
}

fn frame_cbor(frame: &Frame) -> Vec<u8> {
    to_cbor(frame)
}

/// The start of a `msg` frame, up to its `body` value: a 4-entry map with `t`, `id`, `kind` and
/// `body` keys. CBOR items concatenate, so appending the body's own encoding completes it.
fn msg_prefix(id: MsgId, kind: &str) -> Vec<u8> {
    let mut out = vec![0xa4];
    for item in [&Value::from("t"), &Value::from("msg"), &Value::from("id")] {
        out.extend(to_cbor(item));
    }
    out.extend(to_cbor(&id));
    out.extend(to_cbor("kind"));
    out.extend(to_cbor(kind));
    out.extend(to_cbor("body"));
    out
}

fn msg_cbor(id: MsgId, kind: &str, body: &[u8]) -> Vec<u8> {
    let mut out = msg_prefix(id, kind);
    out.extend_from_slice(body);
    out
}

/// The length `msg_cbor` will produce, before an ID is spent on a message that may not fit.
/// Every ID encodes to the same 17 bytes.
fn msg_cbor_len(kind: &str, body: &[u8]) -> usize {
    msg_prefix(MsgId(Uuid::nil()), kind).len() + body.len()
}

/// UUIDv7 generation with the RFC 9562 monotonic random method: within one millisecond, or when
/// the clock steps back, the 74 random bits of the previous ID are incremented.
struct IdGen {
    last: u128,
    rng: u64,
}

const RAND_BITS: u32 = 74;
const RAND_B_MASK: u128 = (1 << 62) - 1;

impl IdGen {
    fn new(seed: u64) -> IdGen {
        IdGen { last: 0, rng: seed }
    }

    fn next(&mut self, now: u64) -> Uuid {
        let ms = now & ((1 << 48) - 1);
        let last_ms = (self.last >> 80) as u64;
        let (ms, random) = if self.last == 0 || ms > last_ms {
            (ms, self.random())
        } else {
            let incremented = random_bits(self.last) + 1;
            if incremented >> RAND_BITS == 0 {
                (last_ms, incremented)
            } else {
                (last_ms + 1, self.random())
            }
        };
        self.last = compose(ms, random);
        Uuid::from_u128(self.last)
    }

    /// 74 random bits with the top one clear, leaving room to increment.
    fn random(&mut self) -> u128 {
        let high = self.splitmix() as u128;
        let low = self.splitmix() as u128;
        ((high << 64) | low) & ((1 << (RAND_BITS - 1)) - 1)
    }

    fn splitmix(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn compose(ms: u64, random: u128) -> u128 {
    ((ms as u128) << 80)
        | (0x7 << 76)
        | ((random >> 62) << 64)
        | (0b10 << 62)
        | (random & RAND_B_MASK)
}

fn random_bits(uuid: u128) -> u128 {
    (((uuid >> 64) & 0xfff) << 62) | (uuid & RAND_B_MASK)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value as Json, json};

    use super::*;
    use crate::error::ErrorKind;
    use crate::protocol::{ChangeKind, ExecState};
    use crate::testkit::cbor;

    const T0: u64 = 1_763_496_000_000;
    const S1: &str = "0193a3b4-0000-7000-8000-000000000001";
    const S2: &str = "0193a3b4-0000-7000-8000-000000000002";
    const C1: &str = "0193a3b4-7c2e-7aa1-9f00-3c1d2e4f5a6b";

    fn sid(text: &str) -> SessionId {
        SessionId(Uuid::parse_str(text).unwrap())
    }

    fn exec(id: &str) -> ExecId {
        ExecId::try_from(id).unwrap()
    }

    fn watch(id: &str) -> WatchId {
        WatchId::try_from(id).unwrap()
    }

    fn info() -> NodeInfo {
        from_value(cbor(json!({
            "installationId": "tz4a98xxat96iws9zmbrgj3a", "name": "box", "hostname": "box",
            "supervisorVersion": "0.1.0",
            "os": { "family": "linux", "name": null, "version": null, "kernelVersion": null, "arch": "x86_64" },
            "cpu": { "model": null, "physicalCores": null, "logicalCores": 1 },
            "memory": { "totalBytes": 1, "swapTotalBytes": 0 },
            "disks": [], "gpus": [],
            "sandbox": { "mechanism": "none", "available": false, "reason": "test", "landlockAbi": null, "baselineRead": [] },
            "defaultEnv": {}, "collectedAtMs": 0
        })))
        .unwrap()
    }

    fn node_session(limits: Limits) -> (Session, Outbox, Arc<ManualClock>) {
        let clock = ManualClock::new(T0);
        let identity = NodeIdentity {
            node_id: "n_1".to_string(),
            installation_id: "tz4a98xxat96iws9zmbrgj3a".to_string(),
        };
        let (session, outbox) =
            Session::with_options(Role::Node(identity), clock.clone(), limits, 7);
        (session, outbox, clock)
    }

    /// The `u'…'` test literal of a UUID.
    fn u(id: &str) -> String {
        format!("u'{id}'")
    }

    /// The CBOR frame a JSON test literal stands for.
    fn frame(literal: Json) -> Vec<u8> {
        to_cbor(&cbor(literal))
    }

    /// The node's `hello`; an absent session or cursor is omitted, as on the wire.
    fn hello(session: Option<&str>, cursor: Option<&str>) -> Json {
        let mut hello = json!({ "t": "hello", "nodeId": "n_1",
                "installationId": "tz4a98xxat96iws9zmbrgj3a", "version": crate::VERSION });
        if let Some(session) = session {
            hello["session"] = json!(u(session));
        }
        if let Some(cursor) = cursor {
            hello["cursor"] = json!(u(cursor));
        }
        hello
    }

    fn welcome(session: &str, resumed: bool, cursor: Option<&str>) -> Vec<u8> {
        frame(
            json!({ "t": "welcome", "session": u(session), "resumed": resumed, "cursor": cursor.map(u), "resumeWindowMs": 1000 }),
        )
    }

    fn literal(payload: &[u8]) -> Json {
        crate::testkit::json(from_cbor(payload).unwrap())
    }

    fn drain(session: &mut Session) -> Vec<Json> {
        std::iter::from_fn(|| session.poll_transmit())
            .map(|payload| literal(&payload))
            .collect()
    }

    fn incoming(session: &mut Session) -> Vec<Incoming> {
        std::iter::from_fn(|| session.poll_incoming()).collect()
    }

    /// The bare UUID text of a `u'…'` literal.
    fn bare(literal: &Json) -> String {
        let text = literal.as_str().unwrap();
        text.strip_prefix("u'")
            .unwrap()
            .strip_suffix('\'')
            .unwrap()
            .to_string()
    }

    fn id_of(frame: &Json) -> String {
        bare(&frame["id"])
    }

    fn ack(cursor: &str) -> Vec<u8> {
        frame(json!({ "t": "ack", "cursor": u(cursor) }))
    }

    fn exit_body(id: &str, log_bytes: u64) -> Json {
        json!({ "execId": id, "exit": { "kind": "exited", "code": 0 }, "logBytes": log_bytes })
    }

    /// A node in session S1 with `node.ready` sent and confirmed.
    fn open_node(limits: Limits) -> (Session, Outbox, Arc<ManualClock>) {
        let (mut session, outbox, clock) = node_session(limits);
        session.connected(Wire::Plain);
        session.receive(&welcome(S1, false, None));
        session.ready(info(), vec![], vec![]).unwrap();
        let frames = drain(&mut session);
        session.receive(&ack(&id_of(&frames[1])));
        incoming(&mut session);
        (session, outbox, clock)
    }

    #[test]
    fn a_new_session_opens_with_hello_and_node_ready_comes_first() {
        let (mut session, outbox, _clock) = node_session(Limits::default());
        session.connected(Wire::Plain);
        assert_eq!(drain(&mut session), [hello(None, None)]);
        outbox.exec_exit(exec("early"), ExitStatus::Exited { code: 0 }, 5);
        assert_eq!(drain(&mut session), [] as [Json; 0]);

        session.receive(&welcome(S1, false, None));
        assert_eq!(
            incoming(&mut session),
            [Incoming::Opened {
                session: sid(S1),
                resumed: false,
                hello: None,
            }]
        );
        assert!(session.needs_ready());
        assert_eq!(drain(&mut session), [] as [Json; 0]);

        let execs = vec![ExecSummary {
            exec_id: exec("early"),
            state: ExecState::Exited {
                exit: ExitStatus::Exited { code: 0 },
            },
            log_bytes: 5,
        }];
        session.ready(info(), execs, vec![watch("w-1")]).unwrap();
        assert!(!session.needs_ready());
        let frames = drain(&mut session);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0]["kind"], "node.ready");
        assert_eq!(frames[0]["body"]["previousSession"], Json::Null);
        assert_eq!(
            frames[0]["body"]["execs"],
            json!([{ "execId": "early", "state": "exited", "exit": { "kind": "exited", "code": 0 }, "logBytes": 5 }])
        );
        assert_eq!(frames[0]["body"]["watches"], json!(["w-1"]));
        assert_eq!(frames[1]["kind"], "exec.exit");
        assert_eq!(frames[1]["body"], exit_body("early", 5));
        assert!(id_of(&frames[0]) < id_of(&frames[1]));
        assert_eq!(
            session.ready(info(), vec![], vec![]),
            Err(Error::invalid_params(
                "no new session is waiting for node.ready"
            ))
        );
    }

    #[test]
    fn resume_resends_exactly_the_unconfirmed_tail() {
        let (mut session, outbox, _clock) = open_node(Limits::default());
        for id in ["e1", "e2", "e3"] {
            outbox.exec_exit(exec(id), ExitStatus::Exited { code: 0 }, 1);
        }
        let payloads: Vec<Vec<u8>> = std::iter::from_fn(|| session.poll_transmit()).collect();
        let ids: Vec<String> = payloads.iter().map(|p| id_of(&literal(p))).collect();
        session.receive(&ack(&ids[0]));

        session.disconnected();
        outbox.exec_exit(exec("e4"), ExitStatus::Exited { code: 0 }, 1);
        assert_eq!(session.poll_transmit(), None);

        session.connected(Wire::Plain);
        assert_eq!(drain(&mut session), [hello(Some(S1), None)]);
        session.receive(&welcome(S1, true, Some(&ids[1])));
        assert_eq!(
            incoming(&mut session),
            [Incoming::Opened {
                session: sid(S1),
                resumed: true,
                hello: None,
            }]
        );
        let resent: Vec<Vec<u8>> = std::iter::from_fn(|| session.poll_transmit()).collect();
        assert_eq!(resent.len(), 2);
        assert_eq!(resent[0], payloads[2]);
        let e4 = literal(&resent[1]);
        assert_eq!(e4["body"], exit_body("e4", 1));
        assert!(id_of(&e4) > ids[2]);
    }

    #[test]
    fn the_cursor_is_acked_after_200_ms_once_and_again_for_a_duplicate() {
        let (mut session, _outbox, clock) = open_node(Limits::default());
        let msg = frame(json!({ "t": "msg", "id": u(C1), "kind": "exec.list", "body": {} }));
        session.receive(&msg);
        assert_eq!(
            incoming(&mut session),
            [Incoming::Message {
                id: MsgId(Uuid::parse_str(C1).unwrap()),
                kind: "exec.list".to_string(),
                body: cbor(json!({})),
            }]
        );
        assert_eq!(session.deadline(), Some(T0 + 200));
        clock.advance(199);
        session.tick();
        assert_eq!(drain(&mut session), [] as [Json; 0]);
        clock.advance(1);
        session.tick();
        assert_eq!(
            drain(&mut session),
            [json!({ "t": "ack", "cursor": u(C1) })]
        );
        assert_eq!(session.deadline(), None);

        session.receive(&msg);
        assert_eq!(incoming(&mut session), []);
        clock.advance(200);
        session.tick();
        assert_eq!(
            drain(&mut session),
            [json!({ "t": "ack", "cursor": u(C1) })]
        );
        clock.advance(200);
        session.tick();
        assert_eq!(drain(&mut session), [] as [Json; 0]);
    }

    #[test]
    fn the_64th_message_is_acked_at_once() {
        let (mut session, _outbox, _clock) = open_node(Limits::default());
        let id = |n: u32| format!("0193a3b4-0000-7000-8000-{n:012x}");
        for n in 1..=63 {
            session.receive(&frame(
                json!({ "t": "msg", "id": u(&id(n)), "kind": "exec.list", "body": {} }),
            ));
        }
        assert_eq!(drain(&mut session), [] as [Json; 0]);
        session.receive(&frame(
            json!({ "t": "msg", "id": u(&id(64)), "kind": "x", "body": {} }),
        ));
        assert_eq!(
            drain(&mut session),
            [json!({ "t": "ack", "cursor": u(&id(64)) })]
        );
        assert_eq!(incoming(&mut session).len(), 64);
    }

    #[test]
    fn a_session_not_resumed_discards_its_queue() {
        let (mut session, outbox, _clock) = open_node(Limits::default());
        outbox.exec_exit(exec("e1"), ExitStatus::Exited { code: 0 }, 1);
        assert_eq!(drain(&mut session).len(), 1);
        session.disconnected();
        outbox.exec_exit(exec("e2"), ExitStatus::Exited { code: 0 }, 1);

        session.connected(Wire::Plain);
        drain(&mut session);
        session.receive(&welcome(S2, false, None));
        assert_eq!(
            incoming(&mut session),
            [
                Incoming::Lost {
                    session: sid(S1),
                    reason: LostReason::NotResumed,
                },
                Incoming::Opened {
                    session: sid(S2),
                    resumed: false,
                    hello: None,
                },
            ]
        );
        session.ready(info(), vec![], vec![]).unwrap();
        let frames = drain(&mut session);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["kind"], "node.ready");
        assert_eq!(frames[0]["body"]["previousSession"], u(S1));
    }

    #[test]
    fn a_session_down_past_its_window_is_lost() {
        let (mut session, _outbox, clock) = open_node(Limits::default());
        session.disconnected();
        assert_eq!(session.deadline(), Some(T0 + 1000));
        clock.advance(999);
        session.tick();
        assert_eq!(incoming(&mut session), []);
        clock.advance(1);
        session.tick();
        assert_eq!(
            incoming(&mut session),
            [Incoming::Lost {
                session: sid(S1),
                reason: LostReason::WindowElapsed,
            }]
        );
        assert_eq!(session.deadline(), None);
        session.connected(Wire::Plain);
        assert_eq!(drain(&mut session), [hello(None, None)]);
    }

    #[test]
    fn too_many_unconfirmed_messages_lose_the_session() {
        let limits = Limits {
            droppable_bytes: 1 << 20,
            retained_bytes: 1000,
        };
        let (mut session, outbox, _clock) = open_node(limits);
        outbox.exec_exit(exec("e"), ExitStatus::Exited { code: 0 }, 1);
        let one = session.poll_transmit().unwrap().len();
        let mut sent = 1;
        while incoming(&mut session).is_empty() {
            outbox.exec_exit(exec("e"), ExitStatus::Exited { code: 0 }, 1);
            sent += 1;
            assert!(sent < 100);
        }
        assert_eq!(sent, 1000 / one + 1);
        let frames = drain(&mut session);
        assert_eq!(
            frames.last(),
            Some(&json!({ "t": "bye", "reason": "queue_overflow" }))
        );
        assert!(session.is_closing());
        assert_eq!(session.session(), None);
    }

    #[test]
    fn dropped_output_is_counted_on_the_next_chunk_and_before_the_exit() {
        let limits = Limits {
            droppable_bytes: 300,
            retained_bytes: 1 << 20,
        };
        let (mut session, outbox, _clock) = open_node(limits);
        outbox.exec_output(exec("e"), Stream::Stdout, vec![b'a'; 100]);
        let first = drain(&mut session);
        assert_eq!(first[0]["body"]["droppedBytes"], 0);
        outbox.exec_output(exec("e"), Stream::Stdout, vec![b'b'; 100]);
        assert_eq!(drain(&mut session), [] as [Json; 0]);
        session.receive(&ack(&id_of(&first[0])));
        outbox.exec_output(exec("e"), Stream::Stdout, b"tail".to_vec());
        let tail = drain(&mut session);
        assert_eq!(
            tail[0]["body"],
            json!({ "execId": "e", "stream": "stdout", "data": "h'7461696c'", "droppedBytes": 100 })
        );

        outbox.exec_output(exec("e"), Stream::Stderr, vec![b'c'; 200]);
        outbox.exec_exit(exec("e"), ExitStatus::Signaled { signal: 9 }, 304);
        let frames = drain(&mut session);
        assert_eq!(
            frames.iter().map(|f| f["body"].clone()).collect::<Vec<_>>(),
            [
                json!({ "execId": "e", "stream": "stderr", "data": "h''", "droppedBytes": 200 }),
                json!({ "execId": "e", "exit": { "kind": "signaled", "signal": 9 }, "logBytes": 304 }),
            ]
        );
    }

    #[test]
    fn dropped_changes_become_one_overflow_marker() {
        let limits = Limits {
            droppable_bytes: 300,
            retained_bytes: 1 << 20,
        };
        let (mut session, outbox, _clock) = open_node(limits);
        let change = |path: &str| Change {
            kind: ChangeKind::Modified,
            path: path.to_string(),
        };
        session.disconnected();
        outbox.exec_output(exec("e"), Stream::Stdout, vec![b'a'; 200]);
        outbox.watch_changes(watch("w"), vec![change("/a")]);
        outbox.watch_changes(watch("w"), vec![change("/b")]);
        outbox.watch_overflow(watch("w"));
        outbox.watch_changes(watch("v"), vec![]);

        session.connected(Wire::Plain);
        drain(&mut session);
        session.receive(&welcome(S1, true, None));
        let frames = drain(&mut session);
        assert_eq!(
            frames.iter().map(|f| f["kind"].clone()).collect::<Vec<_>>(),
            ["exec.output", "watch.event"]
        );
        assert_eq!(
            frames[1]["body"],
            json!({ "watchId": "w", "overflow": true })
        );

        session.receive(&ack(&id_of(&frames[1])));
        outbox.watch_changes(watch("w"), vec![change("/c")]);
        assert_eq!(
            drain(&mut session)[0]["body"],
            json!({ "watchId": "w", "changes": [ { "kind": "modified", "path": "/c" } ] })
        );
    }

    #[test]
    fn replies_and_commands_are_messages() {
        let (mut session, outbox, _clock) = open_node(Limits::default());
        let to = MsgId(Uuid::parse_str(C1).unwrap());
        outbox.reply(to, Ok(cbor(json!({ "execs": [] }))));
        outbox.reply(to, Err(Error::not_found("no exec `x`")));
        let id = outbox.command("node.ping", &cbor(json!({ "n": 1 })));
        let frames = drain(&mut session);
        assert_eq!(
            frames
                .iter()
                .map(|f| (f["kind"].clone(), f["body"].clone()))
                .collect::<Vec<_>>(),
            [
                (
                    json!("reply"),
                    json!({ "to": u(C1), "ok": { "execs": [] } })
                ),
                (
                    json!("reply"),
                    json!({ "to": u(C1), "error": { "kind": "not_found", "message": "no exec `x`" } })
                ),
                (json!("node.ping"), json!({ "n": 1 })),
            ]
        );
        assert_eq!(id_of(&frames[2]), id.to_string());

        session.receive(
            &frame(json!({ "t": "msg", "id": u(C1), "kind": "reply", "body": { "to": u(&id.to_string()), "error": { "kind": "unknown_kind", "message": "?" } } })),
        );
        assert_eq!(
            incoming(&mut session),
            [Incoming::Reply {
                to: id,
                result: Err(Error::new(ErrorKind::UnknownKind, "?")),
            }]
        );
    }

    #[test]
    fn bye_and_protocol_errors_end_the_session() {
        let (mut session, _outbox, _clock) = open_node(Limits::default());
        session.receive(&frame(
            json!({ "t": "bye", "reason": "revoked", "message": "node removed by admin" }),
        ));
        assert_eq!(
            incoming(&mut session),
            [Incoming::Lost {
                session: sid(S1),
                reason: LostReason::PeerBye(Bye {
                    reason: ByeReason::Revoked,
                    message: Some("node removed by admin".to_string()),
                }),
            }]
        );
        assert!(session.is_closing());
        assert_eq!(drain(&mut session), [] as [Json; 0]);

        let (mut session, _outbox, _clock) = open_node(Limits::default());
        session.receive(&welcome(S1, true, None));
        assert_eq!(
            drain(&mut session),
            [
                json!({ "t": "bye", "reason": "protocol_error", "message": "unexpected `welcome` frame" })
            ]
        );
        assert_eq!(
            incoming(&mut session),
            [Incoming::Lost {
                session: sid(S1),
                reason: LostReason::ProtocolError("unexpected `welcome` frame".to_string()),
            }]
        );

        let (mut session, _outbox, _clock) = node_session(Limits::default());
        session.connected(Wire::Plain);
        drain(&mut session);
        session.receive(b"not cbor");
        let bye = drain(&mut session);
        assert_eq!(bye[0]["reason"], "protocol_error");
        assert!(
            bye[0]["message"]
                .as_str()
                .unwrap()
                .starts_with("bad frame: ")
        );
    }

    #[test]
    fn the_control_plane_resumes_within_the_window_and_starts_over_after_it() {
        let clock = ManualClock::new(T0);
        let role = Role::ControlPlane {
            resume_window_ms: 1000,
        };
        let (mut cp, outbox) = Session::with_options(role, clock.clone(), Limits::default(), 9);
        cp.connected(Wire::Plain);
        assert_eq!(drain(&mut cp), [] as [Json; 0]);
        cp.receive(&frame(hello(None, None)));
        let frames = drain(&mut cp);
        let s = bare(&frames[0]["session"]);
        assert_eq!(
            frames,
            [json!({ "t": "welcome", "session": u(&s), "resumed": false, "resumeWindowMs": 1000 })]
        );
        let Some(Incoming::Opened {
            resumed: false,
            hello: Some(hello_frame),
            ..
        }) = cp.poll_incoming()
        else {
            panic!("not opened");
        };
        assert_eq!(hello_frame.node_id, "n_1");

        outbox.command("exec.list", &cbor(json!({})));
        let command = cp.poll_transmit().unwrap();
        cp.disconnected();
        clock.advance(999);
        cp.connected(Wire::Plain);
        cp.receive(&frame(hello(Some(&s), None)));
        let resent: Vec<Vec<u8>> = std::iter::from_fn(|| cp.poll_transmit()).collect();
        assert_eq!(
            literal(&resent[0]),
            json!({ "t": "welcome", "session": u(&s), "resumed": true, "resumeWindowMs": 1000 })
        );
        assert_eq!(resent[1..], [command]);
        incoming(&mut cp);

        cp.disconnected();
        clock.advance(1000);
        cp.connected(Wire::Plain);
        cp.receive(&frame(hello(Some(&s), None)));
        let events = incoming(&mut cp);
        assert_eq!(
            events[0],
            Incoming::Lost {
                session: sid(&s),
                reason: LostReason::WindowElapsed,
            }
        );
        let Incoming::Opened {
            session: next,
            resumed: false,
            ..
        } = events[1]
        else {
            panic!("not opened");
        };
        assert_ne!(next, sid(&s));
        let frames = drain(&mut cp);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["resumed"], false);

        cp.forget();
        assert!(cp.is_closing());
        assert_eq!(
            incoming(&mut cp),
            [Incoming::Lost {
                session: next,
                reason: LostReason::Forgotten,
            }]
        );
    }

    #[test]
    fn a_node_and_a_control_plane_talk_through_two_sessions() {
        let clock = ManualClock::new(T0);
        let identity = NodeIdentity {
            node_id: "n_1".to_string(),
            installation_id: "tz4a98xxat96iws9zmbrgj3a".to_string(),
        };
        let (mut node, node_out) =
            Session::with_options(Role::Node(identity), clock.clone(), Limits::default(), 1);
        let role = Role::ControlPlane {
            resume_window_ms: 1000,
        };
        let (mut cp, cp_out) = Session::with_options(role, clock.clone(), Limits::default(), 2);
        let pump = |node: &mut Session, cp: &mut Session| loop {
            let mut moved = false;
            while let Some(text) = node.poll_transmit() {
                cp.receive(&text);
                moved = true;
            }
            while let Some(text) = cp.poll_transmit() {
                node.receive(&text);
                moved = true;
            }
            if !moved {
                break;
            }
        };
        node.connected(Wire::Plain);
        cp.connected(Wire::Plain);
        pump(&mut node, &mut cp);
        assert!(node.needs_ready());
        node.ready(info(), vec![], vec![]).unwrap();
        let command = cp_out.command("exec.list", &cbor(json!({})));
        pump(&mut node, &mut cp);

        let at_node = incoming(&mut node);
        let Incoming::Message { id, kind, .. } = &at_node[1] else {
            panic!("no command at the node: {at_node:?}");
        };
        assert_eq!((*id, kind.as_str()), (command, "exec.list"));
        node_out.reply(*id, Ok(cbor(json!({ "execs": [] }))));
        pump(&mut node, &mut cp);

        let at_cp = incoming(&mut cp);
        assert!(matches!(&at_cp[1], Incoming::Message { kind, .. } if kind == "node.ready"));
        assert_eq!(
            at_cp[2],
            Incoming::Reply {
                to: command,
                result: Ok(cbor(json!({ "execs": [] }))),
            }
        );
        assert_eq!(node.session(), cp.session());

        clock.advance(200);
        node.tick();
        cp.tick();
        pump(&mut node, &mut cp);
        node.disconnected();
        cp.disconnected();
        node.connected(Wire::Plain);
        cp.connected(Wire::Plain);
        pump(&mut node, &mut cp);
        assert_eq!(node.poll_transmit(), None);
        assert!(matches!(
            incoming(&mut cp)[..],
            [Incoming::Opened { resumed: true, .. }]
        ));
    }

    #[tokio::test]
    async fn an_outbox_on_another_task_wakes_the_driver() {
        let (mut session, outbox, _clock) = open_node(Limits::default());
        let producer = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            outbox.exec_exit(exec("late"), ExitStatus::Exited { code: 0 }, 2);
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), session.changed())
            .await
            .unwrap();
        assert_eq!(drain(&mut session)[0]["body"], exit_body("late", 2));
        producer.await.unwrap();
    }

    #[test]
    fn ids_are_monotonic_uuid_v7() {
        let mut ids = IdGen::new(3);
        let a = ids.next(T0);
        let b = ids.next(T0);
        let c = ids.next(T0 - 5);
        for id in [a, b, c] {
            assert_eq!(id.get_version_num(), 7);
            assert_eq!(id.get_timestamp().unwrap().to_unix(), (T0 / 1000, 0));
        }
        assert!(a < b && b < c);
        assert_eq!(b.as_u128(), a.as_u128() + 1);

        ids.last = compose(T0, (1 << RAND_BITS) - 1);
        let rolled = ids.next(T0);
        assert_eq!(rolled.as_u128() >> 80, (T0 + 1) as u128);
        assert_eq!(rolled.get_version_num(), 7);
        assert!(ids.next(T0 + 10).as_u128() >> 80 == (T0 + 10) as u128);
    }
}
