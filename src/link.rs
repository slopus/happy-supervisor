//! The link protocol (docs/api.md, Link protocol) as a sans-IO state machine.
//!
//! A [`Session`] holds no socket and starts no task. Its driver (the node's `client`, or the test
//! control plane) owns the WebSocket and feeds the session what happens to it:
//! [`connected`](Session::connected), [`receive`](Session::receive) for each binary message,
//! [`disconnected`](Session::disconnected), and [`tick`](Session::tick) at
//! [`deadline`](Session::deadline). Whenever the socket can take a frame and
//! [`wants_transmit`](Session::wants_transmit) is set, it writes one
//! [`poll_transmit`](Session::poll_transmit), and it drains
//! [`poll_incoming`](Session::poll_incoming) into its handlers. It closes the socket once
//! [`is_closing`](Session::is_closing) is set and nothing is left to transmit. It also waits on
//! [`changed`](Session::changed), which fires after each [`Outbox`] call.
//!
//! One `Session` lives as long as its peer relationship, across connections and sessions. The
//! node has one. The control plane has one per node. [`Role`] is the only difference.
//!
//! Sending goes through [`Outbox`], a cloneable handle that exec, watch and the driver use from
//! any task. A message waits in its lane ([`Lane`]) until the scheduler picks it, and gets its
//! frame ID only then, as it is written. A body over 64 KiB goes as a run of parts. Written data
//! frames are kept, byte for byte, until confirmed, and resent first after a resume.
//!
//! Messages queued while no session is live wait in their lanes and go out once one is. On the
//! node a new session goes live only after [`Session::ready`], whose `node.ready` goes to the
//! front of the control lane, so it is always the session's first message.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::Serialize;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::protocol::{
    ACK_DELAY_MS, ACK_EVERY_MSGS, Ack, Bye, ByeReason, Bytes, Change, DROPPABLE_QUEUE_BYTES, Event,
    ExecExit, ExecId, ExecOutput, ExecSummary, ExecTimedOut, ExitStatus, Frame, Hello,
    MAX_MESSAGE_BYTES, MAX_PART_BYTES, MAX_PARTIAL_BYTES, MsgId, NetDenied, NodeInfo, NodeReady,
    Outcome, Part, ProxyMessage, REPLY_KIND, RETAINED_QUEUE_BYTES, Reply, SessionId, Stream,
    TcpMessage, TimeoutAction, True, WatchEvent, WatchEventBody, WatchId, Welcome,
};
use crate::wire::{Value, from_cbor, from_value, msg_head, to_cbor, to_value};

/// The deficit round robin quantum: what each busy lane may write per round.
pub const QUANTUM_BYTES: usize = 64 << 10;

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

/// Queue budgets (api.md, Event delivery) and reassembly bounds (api.md, Lanes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// For `exec.output` and `watch.event` changes. Past it they are dropped and accounted.
    pub droppable_bytes: usize,
    /// For everything else. Past it the session is lost with `queue_overflow`.
    pub retained_bytes: usize,
    /// The largest message reassembled from parts. Past it is a protocol error.
    pub message_bytes: usize,
    /// Incomplete messages held. Past it the session is lost with `queue_overflow`.
    pub partial_bytes: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            droppable_bytes: DROPPABLE_QUEUE_BYTES,
            retained_bytes: RETAINED_QUEUE_BYTES,
            message_bytes: MAX_MESSAGE_BYTES,
            partial_bytes: MAX_PARTIAL_BYTES,
        }
    }
}

/// The lane a message travels in (api.md, Lanes). Messages of one lane are written in order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Lane {
    /// `node.*` commands, their replies, and `node.ready`. Written before every other lane.
    Control,
    Exec(String),
    Watch(String),
    Stream(Uuid),
    /// A lane of its own: `msg:<id>` for a command without an entity, `reply:<commandId>` for
    /// its reply.
    Own,
}

impl std::fmt::Display for Lane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Lane::Control => f.write_str("control"),
            Lane::Exec(id) => write!(f, "exec:{id}"),
            Lane::Watch(id) => write!(f, "watch:{id}"),
            Lane::Stream(id) => write!(f, "stream:{id}"),
            Lane::Own => f.write_str("own"),
        }
    }
}

/// The lane of a message that is not a reply, from its kind and its (text-keyed) body. A reply
/// travels in its command's lane, or in one of its own.
pub fn lane_of(kind: &str, body: &Value) -> Lane {
    let field = |name: &str| {
        body.as_map()?
            .iter()
            .find(|(key, _)| key.as_text() == Some(name))
            .map(|(_, value)| value)
    };
    let family = kind.split('.').next().unwrap_or_default();
    match family {
        "node" => Lane::Control,
        "exec" | "net" => match field("execId") {
            Some(Value::Text(id)) => Lane::Exec(id.clone()),
            _ => Lane::Own,
        },
        "watch" => match field("watchId") {
            Some(Value::Text(id)) => Lane::Watch(id.clone()),
            _ => Lane::Own,
        },
        "proxy" | "tcp" => match field("streamId") {
            Some(Value::Bytes(id)) => Uuid::from_slice(id).map_or(Lane::Own, Lane::Stream),
            _ => Lane::Own,
        },
        _ => Lane::Own,
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
    /// A message to handle: a command, or an event. Delivered once per session, when it is
    /// complete. Messages of one lane are delivered in order.
    Message {
        id: MsgId,
        kind: String,
        body: Value,
    },
    /// The reply to a command; `to` is the ID [`Outbox::command`] returned.
    Reply { to: MsgId, result: Result<Value> },
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
    /// Messages that must not be dropped passed [`Limits::retained_bytes`], or incomplete
    /// messages from the peer passed [`Limits::partial_bytes`].
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

/// A message waiting in its lane.
struct Outgoing {
    /// The `msg` frame's CBOR body. Budgets count its length.
    body: Vec<u8>,
    class: Class,
    /// How much of `body` went out as parts, and the ID of the first part.
    written: usize,
    of: Option<MsgId>,
    /// For a command, the ID [`Outbox::command`] returned, which its reply is delivered under.
    ticket: Option<MsgId>,
}

/// The key of a lane queue. Every [`Lane::Own`] message gets a key of its own.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum LaneKey {
    Entity(Lane),
    Own(u64),
    /// Every message, in the order queued ([`Session::set_single_lane`]).
    Single,
}

#[derive(Default)]
struct LaneQueue {
    messages: VecDeque<Outgoing>,
    deficit: usize,
}

/// A written data frame, kept until the peer confirms it.
struct Kept {
    id: MsgId,
    frame: Vec<u8>,
    /// The budget this frame's share of its message releases once confirmed.
    release: (Class, usize),
}

struct State {
    /// The clock reading of the call in progress.
    now: u64,
    node: Option<NodeIdentity>,
    resume_window_ms: Option<u64>,
    limits: Limits,
    ids: IdGen,
    conn: Conn,
    closing: bool,

    session: Option<SessionId>,
    /// Lanes may be written. On the node, only after `node.ready` is queued.
    live: bool,
    /// The node's last lost session, for `node.ready`.
    previous: Option<SessionId>,

    control_lane: VecDeque<Outgoing>,
    lanes: HashMap<LaneKey, LaneQueue>,
    /// The lanes with queued messages, in round robin order.
    ring: VecDeque<LaneKey>,
    next_own: u64,
    single_lane: bool,
    /// Written data frames not yet confirmed, in ID order.
    kept: VecDeque<Kept>,
    /// `kept[..resent]` was written on the current connection.
    resent: usize,
    droppable_bytes: usize,
    retained_bytes: usize,
    dropped: HashMap<(ExecId, Stream), u64>,
    /// Watches whose overflow marker is queued and not yet written.
    overflowed: HashSet<WatchId>,
    /// Written commands: message ID to the ID their reply is delivered under.
    commands: HashMap<MsgId, MsgId>,
    /// Received commands not yet replied to, and their lanes.
    reply_lanes: HashMap<MsgId, Lane>,

    /// The latest data frame received from the peer in this session.
    cursor: Option<MsgId>,
    /// The cursor last told to the peer, by `ack` or handshake.
    acked: Option<MsgId>,
    unacked: u32,
    unacked_since: Option<u64>,
    duplicate: bool,
    /// Messages arriving as parts, by the ID of their first part.
    partials: HashMap<MsgId, Vec<u8>>,
    partial_bytes: usize,

    /// Handshake, ack and bye bodies, written before any lane. They get their IDs as written.
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
        let state = State {
            now: 0,
            node,
            resume_window_ms,
            limits,
            ids: IdGen::new(seed),
            conn: Conn::Down { since: None },
            closing: false,
            session: None,
            live: false,
            previous: None,
            control_lane: VecDeque::new(),
            lanes: HashMap::new(),
            ring: VecDeque::new(),
            next_own: 0,
            single_lane: false,
            kept: VecDeque::new(),
            resent: 0,
            droppable_bytes: 0,
            retained_bytes: 0,
            dropped: HashMap::new(),
            overflowed: HashSet::new(),
            commands: HashMap::new(),
            reply_lanes: HashMap::new(),
            cursor: None,
            acked: None,
            unacked: 0,
            unacked_since: None,
            duplicate: false,
            partials: HashMap::new(),
            partial_bytes: 0,
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

    /// Puts every message, control lane included, into one lane in the order queued, as a link
    /// without lanes would. For measuring what lanes are worth; messages already queued keep
    /// their lanes.
    pub fn set_single_lane(&mut self, single: bool) {
        self.shared.lock().single_lane = single;
    }

    /// A WebSocket is up. The node queues its `hello`; the control plane waits for one.
    pub fn connected(&mut self) {
        let mut s = self.shared.lock();
        let now = s.now;
        s.expire(now);
        s.conn = Conn::Handshake;
        s.resent = 0;
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
        s.resent = 0;
        s.closing = false;
        s.control.clear();
    }

    /// Feeds one received binary message: a frame ID, then the body. A data frame at or below
    /// the cursor is a resent duplicate and is dropped without decoding its body.
    pub fn receive(&mut self, payload: &[u8]) {
        let mut s = self.shared.lock();
        let (id, body) = match crate::wire::split(payload) {
            Ok((id, body)) => (MsgId(id), body),
            Err(err) => return s.protocol_error(format!("bad frame: {err}")),
        };
        if matches!(s.conn, Conn::Open) && s.cursor.is_some_and(|cursor| id <= cursor) {
            s.duplicate = true;
            let now = s.now;
            s.unacked_since.get_or_insert(now);
            return;
        }
        match from_cbor::<Frame>(body) {
            Ok(frame) => s.receive(id, frame),
            Err(err) => s.protocol_error(format!("bad frame: {err}")),
        }
    }

    /// The peer broke the protocol outside any frame's contents, such as with a text frame:
    /// sends `bye` with `protocol_error` and loses the session.
    pub fn reject(&mut self, why: &str) {
        self.shared.lock().protocol_error(why.to_string());
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

    /// [`poll_transmit`](Session::poll_transmit) has a frame.
    pub fn wants_transmit(&self) -> bool {
        let s = self.shared.lock();
        !s.control.is_empty()
            || (s.writable()
                && (s.resent < s.kept.len() || !s.control_lane.is_empty() || !s.ring.is_empty()))
    }

    /// The next frame to write on the current connection, chosen now: a handshake, ack or bye
    /// frame, then a kept frame to resend, then the control lane, then the other lanes in deficit
    /// round robin. Call it when the socket can take a frame, not ahead of time.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        let mut s = self.shared.lock();
        if let Some(body) = s.control.pop_front() {
            let id = s.next_id();
            return Some(crate::wire::frame(id.0, &body));
        }
        if !s.writable() {
            return None;
        }
        if s.resent < s.kept.len() {
            s.resent += 1;
            return Some(s.kept[s.resent - 1].frame.clone());
        }
        if let Some(out) = s.control_lane.pop_front() {
            let (frame, rest) = s.write(out);
            if let Some(rest) = rest {
                s.control_lane.push_front(rest);
            }
            return Some(frame);
        }
        s.write_lanes()
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

    /// Queues `node.ready` as the new session's first message and lets the lanes flow.
    pub fn ready(
        &mut self,
        info: NodeInfo,
        execs: Vec<ExecSummary>,
        watches: Vec<WatchId>,
    ) -> Result<()> {
        let mut s = self.shared.lock();
        if !(s.node.is_some() && s.session.is_some() && !s.live) {
            return Err(Error::invalid_params(
                "no new session is waiting for node.ready",
            ));
        }
        let body = NodeReady {
            info,
            previous_session: s.previous,
            execs,
            watches,
        };
        let body = msg_body("node.ready", &to_cbor(&body));
        s.retained_bytes += body.len();
        let ready = Outgoing {
            body,
            class: Class::Retained,
            written: 0,
            of: None,
            ticket: None,
        };
        if s.single_lane {
            s.push(LaneKey::Single, ready, true);
        } else {
            s.control_lane.push_front(ready);
        }
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

    /// Queues a command in the lane [`lane_of`] gives it. Its reply arrives as
    /// [`Incoming::Reply`] with the returned ID in `to`.
    pub fn command<T: Serialize + ?Sized>(&self, kind: &str, body: &T) -> MsgId {
        let body = to_value(body);
        let lane = lane_of(kind, &body);
        let body = msg_body(kind, &to_cbor(&body));
        let mut s = self.lock();
        let ticket = s.next_id();
        s.enqueue(lane, body, Class::Retained, Some(ticket));
        ticket
    }

    /// Queues the reply to the received command `to`, in that command's lane, or in a lane of
    /// its own. A command of a lost session gets no reply.
    pub fn reply(&self, to: MsgId, result: Result<Value>) {
        let reply = Reply {
            to,
            outcome: Outcome::from(result),
        };
        let body = msg_body(REPLY_KIND, &to_cbor(&reply));
        let mut s = self.lock();
        let Some(lane) = s.reply_lanes.remove(&to) else {
            tracing::debug!(%to, "dropped the reply to a command of a lost session");
            return;
        };
        s.enqueue(lane, body, Class::Retained, None);
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
            let lane = Lane::Exec(key.0.to_string());
            s.enqueue(lane, msg_body("exec.output", &body), Class::Droppable, None);
        } else {
            *s.dropped.entry(key).or_default() += output.data.0.len() as u64;
        }
    }

    /// Queues that a timeout elapsed, after a chunk carrying any dropped output count. After a
    /// `background` action, send no more output for the process.
    pub fn exec_timed_out(&self, exec_id: ExecId, action: TimeoutAction, log_bytes: u64) {
        let mut s = self.lock();
        s.flush_dropped(&exec_id);
        let lane = Lane::Exec(exec_id.to_string());
        let event = ExecTimedOut {
            exec_id,
            action,
            log_bytes,
        };
        s.enqueue(
            lane,
            msg_body("exec.timedOut", &to_cbor(&event)),
            Class::Retained,
            None,
        );
    }

    /// Queues a process's exit, after a chunk carrying any dropped output count.
    pub fn exec_exit(&self, exec_id: ExecId, exit: ExitStatus, log_bytes: u64) {
        let mut s = self.lock();
        s.flush_dropped(&exec_id);
        let lane = Lane::Exec(exec_id.to_string());
        let event = ExecExit {
            exec_id,
            exit,
            log_bytes,
        };
        s.enqueue(
            lane,
            msg_body("exec.exit", &to_cbor(&event)),
            Class::Retained,
            None,
        );
    }

    /// Queues a batch of at most
    /// [`MAX_CHANGES_PER_EVENT`](crate::protocol::MAX_CHANGES_PER_EVENT) changes. If the
    /// droppable budget is full, `overflow: true` is queued instead. Until that marker is
    /// written, further changes of the watch are discarded, since the rescan it asks for
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
            let lane = Lane::Watch(event.watch_id.to_string());
            s.enqueue(lane, msg_body("watch.event", &body), Class::Droppable, None);
        } else {
            s.overflow(event.watch_id);
        }
    }

    /// Queues a `net.denied` in its process's lane. The command proxy rate-limits them.
    pub fn net_denied(&self, event: NetDenied) {
        let lane = Lane::Exec(event.exec_id.to_string());
        let body = msg_body("net.denied", &to_cbor(&event));
        self.lock().enqueue(lane, body, Class::Retained, None);
    }

    /// Queues `overflow: true`, for a watch whose OS queue overflowed.
    pub fn watch_overflow(&self, watch_id: WatchId) {
        let mut s = self.lock();
        if !s.overflowed.contains(&watch_id) {
            s.overflow(watch_id);
        }
    }

    /// Queues a `tcp.*` stream message (tunnels.md) in its stream's lane. Never dropped, like
    /// proxy messages.
    pub fn tcp(&self, message: TcpMessage) {
        let kind = message.kind();
        let lane = Lane::Stream(message.stream_id().0);
        let body = match &message {
            TcpMessage::Data(body) => to_cbor(body),
            TcpMessage::End(body) => to_cbor(body),
            TcpMessage::Reset(body) => to_cbor(body),
            TcpMessage::Credit(body) => to_cbor(body),
        };
        let body = msg_body(kind, &body);
        self.lock().enqueue(lane, body, Class::Retained, None);
    }

    /// Queues a `proxy.*` stream message (proxy.md) in its stream's lane. Never dropped: the
    /// stream's flow-control window, not the queue, bounds how much is in flight.
    pub fn proxy(&self, message: ProxyMessage) {
        let kind = message.kind();
        let lane = Lane::Stream(message.stream_id().0);
        let body = match &message {
            ProxyMessage::Request(body) => to_cbor(body),
            ProxyMessage::Response(body) => to_cbor(body),
            ProxyMessage::Body(body) => to_cbor(body),
            ProxyMessage::End(body) => to_cbor(body),
            ProxyMessage::Reset(body) => to_cbor(body),
            ProxyMessage::Credit(body) => to_cbor(body),
        };
        let body = msg_body(kind, &body);
        self.lock().enqueue(lane, body, Class::Retained, None);
    }
}

impl State {
    fn next_id(&mut self) -> MsgId {
        MsgId(self.ids.next(self.now))
    }

    /// Lanes and kept frames may be written.
    fn writable(&self) -> bool {
        matches!(self.conn, Conn::Open) && self.live && !self.closing
    }

    fn handshake_sent(&mut self, frame: Frame) {
        self.control.push_back(to_cbor(&frame));
        self.acked = self.cursor;
        self.unacked = 0;
        self.unacked_since = None;
        self.duplicate = false;
    }

    /// Writes the next frame of `out`: the whole message, or its next part. Returns the frame,
    /// and what is left of `out` to write.
    fn write(&mut self, mut out: Outgoing) -> (Vec<u8>, Option<Outgoing>) {
        let id = self.next_id();
        let total = out.body.len();
        let first = out.of.is_none();
        let start = out.written;
        let (frame, done) = if first && total <= MAX_PART_BYTES {
            out.written = total;
            (crate::wire::frame(id.0, &out.body), true)
        } else {
            let of = *out.of.get_or_insert(id);
            let end = (start + MAX_PART_BYTES).min(total);
            let part = Frame::Part(Part {
                of,
                last: end == total,
                data: Bytes(out.body[start..end].to_vec()),
            });
            out.written = end;
            (crate::wire::frame(id.0, &to_cbor(&part)), end == total)
        };
        if first {
            if let Some(ticket) = out.ticket {
                self.commands.insert(id, ticket);
            }
            if let Class::Overflow(watch_id) = &out.class {
                self.overflowed.remove(watch_id);
            }
        }
        self.kept.push_back(Kept {
            id,
            frame: frame.clone(),
            release: (out.class.clone(), out.written - start),
        });
        self.resent = self.kept.len();
        (frame, (!done).then_some(out))
    }

    /// The next frame from the lanes, in deficit round robin.
    fn write_lanes(&mut self) -> Option<Vec<u8>> {
        loop {
            let key = self.ring.front()?.clone();
            let lane = self.lanes.get_mut(&key).expect("ring lanes are queued");
            let front = lane.messages.front().expect("queued lanes are not empty");
            let cost = (front.body.len() - front.written).min(MAX_PART_BYTES);
            if lane.deficit < cost {
                lane.deficit += QUANTUM_BYTES;
                self.ring.rotate_left(1);
                continue;
            }
            lane.deficit -= cost;
            let out = lane.messages.pop_front().expect("checked");
            let (frame, rest) = self.write(out);
            let lane = self.lanes.get_mut(&key).expect("still queued");
            if let Some(rest) = rest {
                lane.messages.push_front(rest);
            }
            if lane.messages.is_empty() {
                self.lanes.remove(&key);
                self.ring.pop_front();
            }
            return Some(frame);
        }
    }

    fn push(&mut self, key: LaneKey, out: Outgoing, front: bool) {
        let ring = &mut self.ring;
        let lane = self.lanes.entry(key.clone()).or_insert_with(|| {
            ring.push_back(key);
            LaneQueue::default()
        });
        if front {
            lane.messages.push_front(out);
        } else {
            lane.messages.push_back(out);
        }
    }

    fn receive(&mut self, id: MsgId, frame: Frame) {
        match (&self.conn, frame) {
            (Conn::Handshake, Frame::Hello(hello)) if self.node.is_none() => self.on_hello(hello),
            (Conn::Handshake, Frame::Welcome(welcome)) if self.node.is_some() => {
                self.on_welcome(welcome)
            }
            (Conn::Open, Frame::Msg(msg)) => {
                self.accepted(id);
                self.deliver(id, msg.kind, msg.body);
                self.ack_if_due();
            }
            (Conn::Open, Frame::Part(part)) => {
                self.accepted(id);
                self.on_part(id, part);
                self.ack_if_due();
            }
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
                    Frame::Part(_) => "part",
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
        self.resent = 0;
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
        self.resent = 0;
        self.incoming.push_back(Incoming::Opened {
            session: welcome.session,
            resumed: welcome.resumed,
            hello: None,
        });
    }

    /// A data frame above the cursor arrived.
    fn accepted(&mut self, id: MsgId) {
        self.cursor = Some(id);
        self.unacked += 1;
        self.unacked_since.get_or_insert(self.now);
    }

    fn ack_if_due(&mut self) {
        if self.unacked >= ACK_EVERY_MSGS {
            self.ack_now();
        }
    }

    fn on_part(&mut self, id: MsgId, part: Part) {
        let partial = if part.of == id {
            self.partials.entry(part.of).or_default()
        } else {
            match self.partials.get_mut(&part.of) {
                Some(partial) => partial,
                None => {
                    return self.protocol_error(format!(
                        "a part of message {}, whose first part never came",
                        part.of
                    ));
                }
            }
        };
        if partial.len() + part.data.0.len() > self.limits.message_bytes {
            return self.protocol_error(format!(
                "message {} is over {} bytes",
                part.of, self.limits.message_bytes
            ));
        }
        partial.extend_from_slice(&part.data.0);
        self.partial_bytes += part.data.0.len();
        if self.partial_bytes > self.limits.partial_bytes {
            let bye = Bye {
                reason: ByeReason::QueueOverflow,
                message: Some(format!(
                    "over {} bytes of incomplete messages",
                    self.limits.partial_bytes
                )),
            };
            return self.lose(LostReason::QueueOverflow, Some(bye));
        }
        if !part.last {
            return;
        }
        let body = self.partials.remove(&part.of).expect("appended above");
        self.partial_bytes -= body.len();
        match from_cbor::<Frame>(&body) {
            Ok(Frame::Msg(msg)) => self.deliver(part.of, msg.kind, msg.body),
            Ok(_) => self.protocol_error(format!("message {} is not a `msg`", part.of)),
            Err(err) => self.protocol_error(format!("bad message {}: {err}", part.of)),
        }
    }

    fn deliver(&mut self, id: MsgId, kind: String, body: Value) {
        let incoming = if kind == REPLY_KIND {
            match from_value::<Reply>(body) {
                Ok(reply) => Incoming::Reply {
                    to: self.commands.remove(&reply.to).unwrap_or(reply.to),
                    result: reply.outcome.into(),
                },
                Err(err) => return self.protocol_error(format!("bad reply: {err}")),
            }
        } else {
            if !Event::is_event(&kind) {
                self.reply_lanes.insert(id, lane_of(&kind, &body));
            }
            Incoming::Message { id, kind, body }
        };
        self.incoming.push_back(incoming);
    }

    /// The peer confirmed everything up to `cursor`.
    fn confirmed(&mut self, cursor: Option<MsgId>) {
        let Some(cursor) = cursor else { return };
        while self.kept.front().is_some_and(|k| k.id <= cursor) {
            let kept = self.kept.pop_front().expect("checked");
            self.resent = self.resent.saturating_sub(1);
            match kept.release {
                (Class::Droppable, len) => self.droppable_bytes -= len,
                (Class::Retained, len) => self.retained_bytes -= len,
                (Class::Overflow(watch_id), len) => {
                    self.retained_bytes -= len;
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
            self.control.push_back(to_cbor(&Frame::Ack(Ack { cursor })));
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

    /// Discards the session, its lanes and kept frames. With `bye`, tells the peer and closes.
    fn lose(&mut self, reason: LostReason, bye: Option<Bye>) {
        if let Some(bye) = bye
            && !matches!(self.conn, Conn::Down { .. })
        {
            self.control.push_back(to_cbor(&Frame::Bye(bye)));
            self.closing = true;
        }
        self.control_lane.clear();
        self.lanes.clear();
        self.ring.clear();
        self.kept.clear();
        self.resent = 0;
        self.droppable_bytes = 0;
        self.retained_bytes = 0;
        self.dropped.clear();
        self.overflowed.clear();
        self.commands.clear();
        self.reply_lanes.clear();
        self.partials.clear();
        self.partial_bytes = 0;
        self.cursor = None;
        self.acked = None;
        self.unacked = 0;
        self.unacked_since = None;
        self.duplicate = false;
        self.live = false;
        if let Some(session) = self.session.take() {
            if self.node.is_some() {
                self.previous = Some(session);
            }
            self.incoming.push_back(Incoming::Lost { session, reason });
        }
    }

    fn fits_droppable(&self, kind: &str, body: &[u8]) -> bool {
        self.droppable_bytes + msg_head(kind).len() + body.len() <= self.limits.droppable_bytes
    }

    /// Queues the `msg` body `body` in `lane`.
    fn enqueue(&mut self, lane: Lane, body: Vec<u8>, class: Class, ticket: Option<MsgId>) {
        match class {
            Class::Droppable => self.droppable_bytes += body.len(),
            Class::Retained | Class::Overflow(_) => self.retained_bytes += body.len(),
        }
        let out = Outgoing {
            body,
            class,
            written: 0,
            of: None,
            ticket,
        };
        let key = match lane {
            _ if self.single_lane => LaneKey::Single,
            Lane::Control => {
                self.control_lane.push_back(out);
                return self.check_retained();
            }
            Lane::Own => {
                self.next_own += 1;
                LaneKey::Own(self.next_own)
            }
            entity => LaneKey::Entity(entity),
        };
        self.push(key, out, false);
        self.check_retained();
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
                let lane = Lane::Exec(exec_id.to_string());
                self.enqueue(
                    lane,
                    msg_body("exec.output", &to_cbor(&output)),
                    Class::Retained,
                    None,
                );
            }
        }
    }

    fn overflow(&mut self, watch_id: WatchId) {
        let event = WatchEvent {
            watch_id: watch_id.clone(),
            body: WatchEventBody::Overflow { overflow: True },
        };
        self.overflowed.insert(watch_id.clone());
        let lane = Lane::Watch(watch_id.to_string());
        self.enqueue(
            lane,
            msg_body("watch.event", &to_cbor(&event)),
            Class::Overflow(watch_id),
            None,
        );
    }
}

/// A `msg` frame's body: `kind`, then `body`, already encoded.
fn msg_body(kind: &str, body: &[u8]) -> Vec<u8> {
    let mut out = msg_head(kind);
    out.extend_from_slice(body);
    out
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
    use std::sync::atomic::AtomicU64;

    use serde_json::{Value as Json, json};

    use super::*;
    use crate::error::ErrorKind;
    use crate::protocol::{ChangeKind, ExecState, ProxyBody, ProxyEnd, StreamId};
    use crate::testkit::cbor;
    use crate::wire::split;

    const T0: u64 = 1_763_496_000_000;
    const S1: &str = "0193a3b4-0000-7000-8000-000000000001";
    const S2: &str = "0193a3b4-0000-7000-8000-000000000002";
    const C1: &str = "0193a3b4-7c2e-7aa1-9f00-3c1d2e4f5a6b";

    fn sid(text: &str) -> SessionId {
        SessionId(Uuid::parse_str(text).unwrap())
    }

    fn mid(text: &str) -> MsgId {
        MsgId(Uuid::parse_str(text).unwrap())
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
            "sandbox": { "mechanism": "none", "available": false, "reason": "test", "baselineRead": [] },
            "identity": { "supervisorUser": "me", "workloadUser": null, "root": false },
            "limits": { "memoryBytes": false, "processes": false, "cpuSeconds": true },
            "defaultEnv": {}, "collectedAtMs": 0
        })))
        .unwrap()
    }

    fn identity() -> NodeIdentity {
        NodeIdentity {
            node_id: "n_1".to_string(),
            installation_id: "tz4a98xxat96iws9zmbrgj3a".to_string(),
        }
    }

    fn node_session(limits: Limits) -> (Session, Outbox, Arc<ManualClock>) {
        let clock = ManualClock::new(T0);
        let (session, outbox) =
            Session::with_options(Role::Node(identity()), clock.clone(), limits, 7);
        (session, outbox, clock)
    }

    /// The `u'…'` test literal of a UUID.
    fn u(id: &str) -> String {
        format!("u'{id}'")
    }

    /// A frame ID above every earlier one, for frames the test plays the peer of.
    fn peer_id() -> String {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        format!("0193a3b5-0000-7000-8000-{n:012x}")
    }

    /// The frame with ID `id` and the body a JSON test literal stands for.
    fn frame_with(id: &str, body: Json) -> Vec<u8> {
        crate::wire::frame(Uuid::parse_str(id).unwrap(), &to_cbor(&cbor(body)))
    }

    fn frame(body: Json) -> Vec<u8> {
        frame_with(&peer_id(), body)
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

    /// A frame as its JSON test literal, with the prefix shown as `id`.
    fn literal(payload: &[u8]) -> Json {
        let (id, body) = split(payload).unwrap();
        let mut json = crate::testkit::json(from_cbor(body).unwrap());
        json["id"] = json!(u(&id.to_string()));
        json
    }

    /// The literal without its `id`, for frames whose ID the test does not know.
    fn bare_literal(payload: &[u8]) -> Json {
        let mut json = literal(payload);
        json.as_object_mut().unwrap().remove("id");
        json
    }

    fn drain_raw(session: &mut Session) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| session.poll_transmit()).collect()
    }

    fn drain(session: &mut Session) -> Vec<Json> {
        drain_raw(session).iter().map(|p| literal(p)).collect()
    }

    fn drain_bare(session: &mut Session) -> Vec<Json> {
        drain_raw(session).iter().map(|p| bare_literal(p)).collect()
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
        session.connected();
        session.receive(&welcome(S1, false, None));
        session.ready(info(), vec![], vec![]).unwrap();
        let frames = drain(&mut session);
        session.receive(&ack(&id_of(&frames[1])));
        incoming(&mut session);
        (session, outbox, clock)
    }

    /// The node receives the command `kind` with ID `id`, so it can reply.
    fn command_at(session: &mut Session, id: &str, kind: &str, body: Json) {
        session.receive(&frame_with(
            id,
            json!({ "t": "msg", "kind": kind, "body": body }),
        ));
        assert!(matches!(incoming(session)[..], [Incoming::Message { .. }]));
    }

    /// A node and a control plane, both open in one session with `node.ready` delivered.
    fn pair() -> (Session, Outbox, Session, Outbox, Arc<ManualClock>) {
        let clock = ManualClock::new(T0);
        let (mut node, node_out) =
            Session::with_options(Role::Node(identity()), clock.clone(), Limits::default(), 1);
        let role = Role::ControlPlane {
            resume_window_ms: 1000,
        };
        let (mut cp, cp_out) = Session::with_options(role, clock.clone(), Limits::default(), 2);
        node.connected();
        cp.connected();
        pump(&mut node, &mut cp);
        node.ready(info(), vec![], vec![]).unwrap();
        pump(&mut node, &mut cp);
        incoming(&mut node);
        incoming(&mut cp);
        (node, node_out, cp, cp_out, clock)
    }

    fn pump(node: &mut Session, cp: &mut Session) {
        loop {
            let mut moved = false;
            while let Some(frame) = node.poll_transmit() {
                cp.receive(&frame);
                moved = true;
            }
            while let Some(frame) = cp.poll_transmit() {
                node.receive(&frame);
                moved = true;
            }
            if !moved {
                break;
            }
        }
    }

    #[test]
    fn lanes_come_from_the_kind_and_the_entity() {
        let stream = "0193a3b4-0000-7000-8000-0000000000aa";
        let rows = [
            ("node.info", json!({}), "control"),
            ("node.update", json!({ "endpoint": "wss://x" }), "control"),
            ("node.ready", json!({}), "control"),
            ("exec.start", json!({ "execId": "build-1" }), "exec:build-1"),
            ("exec.write", json!({ "execId": "build-1" }), "exec:build-1"),
            ("exec.output", json!({ "execId": "b" }), "exec:b"),
            ("exec.log", json!({ "execId": "b" }), "exec:b"),
            ("exec.list", json!({}), "own"),
            ("watch.start", json!({ "watchId": "w-1" }), "watch:w-1"),
            ("watch.event", json!({ "watchId": "w-1" }), "watch:w-1"),
            (
                "proxy.body",
                json!({ "streamId": u(stream) }),
                "stream:0193a3b4-0000-7000-8000-0000000000aa",
            ),
            (
                "tcp.open",
                json!({ "streamId": u(stream) }),
                "stream:0193a3b4-0000-7000-8000-0000000000aa",
            ),
            ("tcp.data", json!({ "streamId": "h'00'" }), "own"),
            ("fs.read", json!({ "path": "/a" }), "own"),
            ("fs.write", json!({ "path": "/a" }), "own"),
            ("future.kind", json!({ "execId": "b" }), "own"),
        ];
        for (kind, body, lane) in rows {
            assert_eq!(lane_of(kind, &cbor(body)).to_string(), lane, "{kind}");
        }
    }

    #[test]
    fn a_new_session_opens_with_hello_and_node_ready_comes_first() {
        let (mut session, outbox, _clock) = node_session(Limits::default());
        session.connected();
        assert_eq!(drain_bare(&mut session), [hello(None, None)]);
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
        assert!(!session.wants_transmit());
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
        assert!(session.wants_transmit());
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
    fn frames_get_their_ids_as_they_are_written() {
        let (mut session, outbox, clock) = open_node(Limits::default());
        outbox.exec_exit(exec("a"), ExitStatus::Exited { code: 0 }, 1);
        clock.advance(5000);
        outbox.exec_exit(exec("b"), ExitStatus::Exited { code: 0 }, 1);
        clock.advance(5000);
        let frames = drain(&mut session);
        let stamp = |f: &Json| {
            Uuid::parse_str(&id_of(f))
                .unwrap()
                .get_timestamp()
                .unwrap()
                .to_unix()
                .0
        };
        assert_eq!(stamp(&frames[0]), (T0 + 10_000) / 1000);
        assert_eq!(stamp(&frames[1]), (T0 + 10_000) / 1000);
        assert!(id_of(&frames[0]) < id_of(&frames[1]));
    }

    #[test]
    fn resume_resends_exactly_the_unconfirmed_tail() {
        let (mut session, outbox, _clock) = open_node(Limits::default());
        for id in ["e1", "e2", "e3"] {
            outbox.exec_exit(exec(id), ExitStatus::Exited { code: 0 }, 1);
        }
        let payloads = drain_raw(&mut session);
        let ids: Vec<String> = payloads.iter().map(|p| id_of(&literal(p))).collect();
        session.receive(&ack(&ids[0]));

        session.disconnected();
        outbox.exec_exit(exec("e4"), ExitStatus::Exited { code: 0 }, 1);
        assert_eq!(session.poll_transmit(), None);

        session.connected();
        assert_eq!(drain_bare(&mut session), [hello(Some(S1), None)]);
        session.receive(&welcome(S1, true, Some(&ids[1])));
        assert_eq!(
            incoming(&mut session),
            [Incoming::Opened {
                session: sid(S1),
                resumed: true,
                hello: None,
            }]
        );
        let resent = drain_raw(&mut session);
        assert_eq!(resent.len(), 2);
        assert_eq!(resent[0], payloads[2]);
        let e4 = literal(&resent[1]);
        assert_eq!(e4["body"], exit_body("e4", 1));
        assert!(id_of(&e4) > ids[2]);
    }

    #[test]
    fn the_cursor_is_acked_after_200_ms_once_and_again_for_a_duplicate() {
        let (mut session, _outbox, clock) = open_node(Limits::default());
        let msg = frame_with(C1, json!({ "t": "msg", "kind": "exec.list", "body": {} }));
        session.receive(&msg);
        assert_eq!(
            incoming(&mut session),
            [Incoming::Message {
                id: mid(C1),
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
            drain_bare(&mut session),
            [json!({ "t": "ack", "cursor": u(C1) })]
        );
        assert_eq!(session.deadline(), None);

        session.receive(&msg);
        assert_eq!(incoming(&mut session), []);
        clock.advance(200);
        session.tick();
        assert_eq!(
            drain_bare(&mut session),
            [json!({ "t": "ack", "cursor": u(C1) })]
        );
        clock.advance(200);
        session.tick();
        assert_eq!(drain(&mut session), [] as [Json; 0]);
    }

    #[test]
    fn a_duplicate_is_dropped_without_decoding_its_body() {
        let (mut session, _outbox, clock) = open_node(Limits::default());
        session.receive(&frame_with(
            C1,
            json!({ "t": "msg", "kind": "exec.list", "body": {} }),
        ));
        incoming(&mut session);
        // The same ID with a body that is not CBOR: a resend is never decoded.
        let garbage = [Uuid::parse_str(C1).unwrap().as_bytes(), &b"\xff\xff"[..]].concat();
        session.receive(&garbage);
        assert_eq!(incoming(&mut session), []);
        assert!(!session.is_closing());
        clock.advance(200);
        session.tick();
        assert_eq!(
            drain_bare(&mut session),
            [json!({ "t": "ack", "cursor": u(C1) })]
        );
        // Above the cursor it is decoded, and refused.
        session.receive(
            &[
                Uuid::parse_str(&peer_id()).unwrap().as_bytes(),
                &b"\xff\xff"[..],
            ]
            .concat(),
        );
        assert!(session.is_closing());
    }

    #[test]
    fn the_64th_message_is_acked_at_once() {
        let (mut session, _outbox, _clock) = open_node(Limits::default());
        let id = |n: u32| format!("0193a3b4-0000-7000-8000-{n:012x}");
        for n in 1..=63 {
            session.receive(&frame_with(
                &id(n),
                json!({ "t": "msg", "kind": "exec.list", "body": {} }),
            ));
        }
        assert_eq!(drain(&mut session), [] as [Json; 0]);
        session.receive(&frame_with(
            &id(64),
            json!({ "t": "msg", "kind": "x", "body": {} }),
        ));
        assert_eq!(
            drain_bare(&mut session),
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

        session.connected();
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
        session.connected();
        assert_eq!(drain_bare(&mut session), [hello(None, None)]);
    }

    #[test]
    fn too_many_unconfirmed_messages_lose_the_session() {
        let limits = Limits {
            retained_bytes: 1000,
            ..Limits::default()
        };
        let (mut session, outbox, _clock) = open_node(limits);
        outbox.exec_exit(exec("e"), ExitStatus::Exited { code: 0 }, 1);
        let one = session.poll_transmit().unwrap().len() - crate::wire::PREFIX_BYTES;
        let mut sent = 1;
        while incoming(&mut session).is_empty() {
            outbox.exec_exit(exec("e"), ExitStatus::Exited { code: 0 }, 1);
            sent += 1;
            assert!(sent < 100);
        }
        assert_eq!(sent, 1000 / one + 1);
        let frames = drain_bare(&mut session);
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
            ..Limits::default()
        };
        let (mut session, outbox, _clock) = open_node(limits);
        outbox.exec_output(exec("e"), Stream::Stdout, vec![b'a'; 150]);
        let first = drain(&mut session);
        assert_eq!(first[0]["body"]["droppedBytes"], 0);
        outbox.exec_output(exec("e"), Stream::Stdout, vec![b'b'; 150]);
        assert_eq!(drain(&mut session), [] as [Json; 0]);
        session.receive(&ack(&id_of(&first[0])));
        outbox.exec_output(exec("e"), Stream::Stdout, b"tail".to_vec());
        let tail = drain(&mut session);
        assert_eq!(
            tail[0]["body"],
            json!({ "execId": "e", "stream": "stdout", "data": "h'7461696c'", "droppedBytes": 150 })
        );

        outbox.exec_output(exec("e"), Stream::Stderr, vec![b'c'; 260]);
        outbox.exec_exit(exec("e"), ExitStatus::Signaled { signal: 9 }, 304);
        let frames = drain(&mut session);
        assert_eq!(
            frames.iter().map(|f| f["body"].clone()).collect::<Vec<_>>(),
            [
                json!({ "execId": "e", "stream": "stderr", "data": "h''", "droppedBytes": 260 }),
                json!({ "execId": "e", "exit": { "kind": "signaled", "signal": 9 }, "logBytes": 304 }),
            ]
        );
    }

    #[test]
    fn dropped_changes_become_one_overflow_marker() {
        let limits = Limits {
            droppable_bytes: 300,
            ..Limits::default()
        };
        let (mut session, outbox, _clock) = open_node(limits);
        let change = |path: &str| Change {
            kind: ChangeKind::Modified,
            path: path.to_string(),
        };
        session.disconnected();
        outbox.exec_output(exec("e"), Stream::Stdout, vec![b'a'; 250]);
        outbox.watch_changes(watch("w"), vec![change("/a")]);
        outbox.watch_changes(watch("w"), vec![change("/b")]);
        outbox.watch_overflow(watch("w"));
        outbox.watch_changes(watch("v"), vec![]);

        session.connected();
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
    fn proxy_messages_are_never_dropped() {
        let limits = Limits {
            droppable_bytes: 300,
            ..Limits::default()
        };
        let (mut session, outbox, _clock) = open_node(limits);
        let stream = StreamId(Uuid::parse_str(S2).unwrap());
        outbox.exec_output(exec("e"), Stream::Stdout, vec![b'a'; 200]);
        outbox.proxy(ProxyMessage::Body(ProxyBody {
            stream_id: stream,
            data: Bytes(vec![b'b'; 1000]),
        }));
        outbox.proxy(ProxyMessage::End(ProxyEnd { stream_id: stream }));
        let frames = drain(&mut session);
        assert_eq!(
            frames.iter().map(|f| f["kind"].clone()).collect::<Vec<_>>(),
            ["exec.output", "proxy.body", "proxy.end"]
        );
        assert_eq!(frames[2]["body"], json!({ "streamId": u(S2) }));
    }

    #[test]
    fn replies_go_in_their_commands_lane_and_commands_get_theirs_back() {
        let (mut session, outbox, _clock) = open_node(Limits::default());
        command_at(&mut session, C1, "exec.list", json!({}));
        outbox.reply(mid(C1), Ok(cbor(json!({ "execs": [] }))));
        // A second reply, or one to a command never received, has no lane and is dropped.
        outbox.reply(mid(C1), Err(Error::not_found("no exec `x`")));
        let ticket = outbox.command("node.ping", &cbor(json!({ "n": 1 })));
        let frames = drain(&mut session);
        assert_eq!(
            frames
                .iter()
                .map(|f| (f["kind"].clone(), f["body"].clone()))
                .collect::<Vec<_>>(),
            [
                (json!("node.ping"), json!({ "n": 1 })),
                (
                    json!("reply"),
                    json!({ "to": u(C1), "ok": { "execs": [] } })
                ),
            ]
        );
        assert_ne!(id_of(&frames[0]), ticket.to_string());

        session.receive(&frame(
            json!({ "t": "msg", "kind": "reply", "body": { "to": frames[0]["id"], "error": { "kind": "unknown_kind", "message": "?" } } }),
        ));
        assert_eq!(
            incoming(&mut session),
            [Incoming::Reply {
                to: ticket,
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
            drain_bare(&mut session),
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
        session.connected();
        drain(&mut session);
        session.receive(
            &[
                Uuid::parse_str(&peer_id()).unwrap().as_bytes(),
                &b"not cbor"[..],
            ]
            .concat(),
        );
        let bye = drain_bare(&mut session);
        assert_eq!(bye[0]["reason"], "protocol_error");
        assert!(
            bye[0]["message"]
                .as_str()
                .unwrap()
                .starts_with("bad frame: ")
        );

        let (mut session, _outbox, _clock) = node_session(Limits::default());
        session.connected();
        drain(&mut session);
        session.receive(b"short");
        assert_eq!(
            drain_bare(&mut session),
            [
                json!({ "t": "bye", "reason": "protocol_error", "message": "bad frame: frame of 5 bytes has no room for its ID" })
            ]
        );

        let (mut session, _outbox, _clock) = open_node(Limits::default());
        session.reject("a text frame");
        assert_eq!(
            drain_bare(&mut session),
            [json!({ "t": "bye", "reason": "protocol_error", "message": "a text frame" })]
        );
        assert!(session.is_closing());
    }

    #[test]
    fn the_control_plane_resumes_within_the_window_and_starts_over_after_it() {
        let clock = ManualClock::new(T0);
        let role = Role::ControlPlane {
            resume_window_ms: 1000,
        };
        let (mut cp, outbox) = Session::with_options(role, clock.clone(), Limits::default(), 9);
        cp.connected();
        assert_eq!(drain(&mut cp), [] as [Json; 0]);
        cp.receive(&frame(hello(None, None)));
        let frames = drain_bare(&mut cp);
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
        cp.connected();
        cp.receive(&frame(hello(Some(&s), None)));
        let resent = drain_raw(&mut cp);
        assert_eq!(
            bare_literal(&resent[0]),
            json!({ "t": "welcome", "session": u(&s), "resumed": true, "resumeWindowMs": 1000 })
        );
        assert_eq!(resent[1..], [command]);
        incoming(&mut cp);

        cp.disconnected();
        clock.advance(1000);
        cp.connected();
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
        let (mut node, node_out, mut cp, cp_out, clock) = pair();
        let command = cp_out.command("exec.list", &cbor(json!({})));
        pump(&mut node, &mut cp);

        let at_node = incoming(&mut node);
        let Incoming::Message { id, kind, .. } = &at_node[0] else {
            panic!("no command at the node: {at_node:?}");
        };
        assert_eq!(kind, "exec.list");
        node_out.reply(*id, Ok(cbor(json!({ "execs": [] }))));
        pump(&mut node, &mut cp);

        assert_eq!(
            incoming(&mut cp),
            [Incoming::Reply {
                to: command,
                result: Ok(cbor(json!({ "execs": [] }))),
            }]
        );
        assert_eq!(node.session(), cp.session());

        clock.advance(200);
        node.tick();
        cp.tick();
        pump(&mut node, &mut cp);
        node.disconnected();
        cp.disconnected();
        node.connected();
        cp.connected();
        pump(&mut node, &mut cp);
        assert_eq!(node.poll_transmit(), None);
        assert!(matches!(
            incoming(&mut cp)[..],
            [Incoming::Opened { resumed: true, .. }]
        ));
    }

    /// The `(t, lane)` of each frame the node writes: `msg` frames by kind and body, parts by
    /// the message they belong to.
    fn written(session: &mut Session) -> Vec<(String, String)> {
        drain(session)
            .iter()
            .map(|f| {
                let t = f["t"].as_str().unwrap().to_string();
                let what = match t.as_str() {
                    "part" => format!(
                        "{}{}",
                        bare(&f["of"]),
                        if f["last"] == true { " last" } else { "" }
                    ),
                    _ => format!(
                        "{} {}",
                        f["kind"].as_str().unwrap(),
                        if f["body"]["to"].is_string() {
                            bare(&f["body"]["to"])
                        } else {
                            String::new()
                        }
                    ),
                };
                (t, what)
            })
            .collect()
    }

    #[test]
    fn a_small_reply_waits_at_most_one_part_of_a_large_one() {
        let (mut node, node_out, mut cp, cp_out, _clock) = pair();
        let big = cp_out.command("fs.read", &cbor(json!({ "path": "/big" })));
        let small = cp_out.command("fs.stat", &cbor(json!({ "path": "/small" })));
        pump(&mut node, &mut cp);
        let commands: Vec<MsgId> = incoming(&mut node)
            .into_iter()
            .map(|i| match i {
                Incoming::Message { id, .. } => id,
                other => panic!("{other:?}"),
            })
            .collect();
        let data = vec![7u8; 1 << 20];
        node_out.reply(
            commands[0],
            Ok(cbor(
                json!({ "data": format!("h'{}'", "07".repeat(1 << 20)) }),
            )),
        );
        node_out.reply(commands[1], Ok(cbor(json!({ "size": 200 }))));

        let frames = drain_raw(&mut node);
        let literals: Vec<Json> = frames.iter().map(|f| literal(f)).collect();
        let of = id_of(&literals[0]);
        let shape: Vec<String> = literals
            .iter()
            .map(|f| match f["t"].as_str().unwrap() {
                "part" => {
                    assert_eq!(bare(&f["of"]), of);
                    if f["last"] == true {
                        "last part".to_string()
                    } else {
                        "part".to_string()
                    }
                }
                _ => format!("reply to {}", bare(&f["body"]["to"])),
            })
            .collect();
        let mut expected = vec!["part".to_string(), format!("reply to {}", commands[1])];
        expected.extend(std::iter::repeat_n("part".to_string(), 15));
        expected.push("last part".to_string());
        assert_eq!(shape, expected);
        assert!(frames.iter().all(|f| f.len() <= MAX_PART_BYTES + 64));
        assert_eq!(literals[0]["id"], literals[0]["of"]);

        for frame in &frames {
            cp.receive(frame);
        }
        let at_cp = incoming(&mut cp);
        assert_eq!(
            at_cp[0],
            Incoming::Reply {
                to: small,
                result: Ok(cbor(json!({ "size": 200 }))),
            }
        );
        let Incoming::Reply {
            to,
            result: Ok(body),
        } = &at_cp[1]
        else {
            panic!("{:?}", at_cp[1]);
        };
        assert_eq!(*to, big);
        assert_eq!(
            crate::testkit::json(body.clone())["data"],
            format!("h'{}'", "07".repeat(data.len()))
        );
    }

    #[test]
    fn busy_lanes_take_turns_of_64_kib() {
        let (mut session, outbox, _clock) = open_node(Limits::default());
        for id in ["a", "b", "c"] {
            for _ in 0..4 {
                outbox.exec_output(exec(id), Stream::Stdout, vec![b'x'; 60_000]);
            }
        }
        outbox.exec_exit(exec("d"), ExitStatus::Exited { code: 0 }, 1);
        let lanes: Vec<String> = drain(&mut session)
            .iter()
            .map(|f| f["body"]["execId"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            lanes,
            [
                "a", "b", "c", "d", "a", "b", "c", "a", "b", "c", "a", "b", "c"
            ]
        );
    }

    #[test]
    fn a_lane_keeps_its_order_and_parts_stay_together() {
        let (mut node, node_out, mut cp, _cp_out, _clock) = pair();
        node_out.exec_output(exec("e"), Stream::Stdout, vec![1; 100]);
        node_out.proxy(ProxyMessage::Body(ProxyBody {
            stream_id: StreamId(Uuid::parse_str(S2).unwrap()),
            data: Bytes(vec![2; 200_000]),
        }));
        node_out.exec_output(exec("e"), Stream::Stdout, vec![3; 50_000]);
        node_out.exec_output(exec("e"), Stream::Stdout, vec![4; 10]);
        node_out.exec_exit(exec("e"), ExitStatus::Exited { code: 0 }, 50_110);
        let shape = written(&mut node);
        let parts: Vec<usize> = shape
            .iter()
            .enumerate()
            .filter(|(_, (t, _))| t == "part")
            .map(|(i, _)| i)
            .collect();
        assert_eq!(parts.len(), 4);
        // Every frame is delivered at the control plane in each lane's order.
        node.disconnected();
        node.connected();
        cp.disconnected();
        cp.connected();
        pump(&mut node, &mut cp);
        let at_cp: Vec<(String, Json)> = incoming(&mut cp)
            .into_iter()
            .filter_map(|i| match i {
                Incoming::Message { kind, body, .. } => Some((kind, crate::testkit::json(body))),
                _ => None,
            })
            .collect();
        let exec_events: Vec<Json> = at_cp
            .iter()
            .filter(|(k, _)| k.starts_with("exec."))
            .map(|(k, b)| match k.as_str() {
                "exec.output" => json!(b["data"].as_str().unwrap().len()),
                _ => json!(k),
            })
            .collect();
        assert_eq!(
            exec_events,
            [json!(203), json!(100_003), json!(23), json!("exec.exit")]
        );
        assert_eq!(at_cp.iter().filter(|(k, _)| k == "proxy.body").count(), 1);
    }

    #[test]
    fn a_message_cut_by_a_reconnect_is_resent_from_the_unconfirmed_part() {
        let (mut node, node_out, mut cp, _cp_out, _clock) = pair();
        node_out.proxy(ProxyMessage::Body(ProxyBody {
            stream_id: StreamId(Uuid::parse_str(S2).unwrap()),
            data: Bytes(vec![9; 300_000]),
        }));
        let first = node.poll_transmit().unwrap();
        let second = node.poll_transmit().unwrap();
        let third = node.poll_transmit().unwrap();
        cp.receive(&first);
        cp.receive(&second);
        // The third is lost with the connection; the control plane confirmed the second.
        cp.tick();
        let second_id = id_of(&literal(&second));
        node.receive(&ack(&second_id));
        node.disconnected();
        cp.disconnected();

        node.connected();
        cp.connected();
        let hello = node.poll_transmit().unwrap();
        cp.receive(&hello);
        let welcome = cp.poll_transmit().unwrap();
        node.receive(&welcome);
        let resent = node.poll_transmit().unwrap();
        assert_eq!(resent, third);
        cp.receive(&resent);
        pump(&mut node, &mut cp);
        let messages: Vec<Incoming> = incoming(&mut cp)
            .into_iter()
            .filter(|i| matches!(i, Incoming::Message { .. }))
            .collect();
        let [Incoming::Message { id, kind, body }] = &messages[..] else {
            panic!("{messages:?}");
        };
        assert_eq!(kind, "proxy.body");
        assert_eq!(id.to_string(), id_of(&literal(&first)));
        let ProxyMessage::Body(body) = ProxyMessage::parse(kind, body.clone()).unwrap() else {
            panic!()
        };
        assert_eq!(body.data.0, vec![9; 300_000]);
    }

    #[test]
    fn reassembly_is_bounded() {
        let limits = Limits {
            message_bytes: 100,
            partial_bytes: 150,
            ..Limits::default()
        };
        let clock = ManualClock::new(T0);
        let (mut session, _outbox) =
            Session::with_options(Role::Node(identity()), clock, limits, 7);
        let open = |session: &mut Session| {
            session.connected();
            drain(session);
            session.receive(&welcome(S1, false, None));
            session.ready(info(), vec![], vec![]).unwrap();
            drain(session);
            incoming(session);
        };
        let part = |id: &str, of: &str, last: bool, len: usize| {
            frame_with(
                id,
                json!({ "t": "part", "of": u(of), "last": last, "data": format!("h'{}'", "00".repeat(len)) }),
            )
        };
        open(&mut session);
        let a = peer_id();
        session.receive(&part(&a, &a, false, 60));
        session.receive(&part(&peer_id(), &a, false, 41));
        assert_eq!(
            drain_bare(&mut session),
            [
                json!({ "t": "bye", "reason": "protocol_error", "message": format!("message {a} is over 100 bytes") })
            ]
        );

        session.disconnected();
        open(&mut session);
        let (a, b, c) = (peer_id(), peer_id(), peer_id());
        session.receive(&part(&a, &a, false, 60));
        session.receive(&part(&b, &b, false, 60));
        assert_eq!(drain(&mut session), [] as [Json; 0]);
        session.receive(&part(&c, &c, false, 31));
        assert_eq!(
            drain_bare(&mut session),
            [
                json!({ "t": "bye", "reason": "queue_overflow", "message": "over 150 bytes of incomplete messages" })
            ]
        );
        assert!(matches!(
            incoming(&mut session)[..],
            [Incoming::Lost {
                reason: LostReason::QueueOverflow,
                ..
            }]
        ));

        session.disconnected();
        open(&mut session);
        let x = peer_id();
        session.receive(&part(&peer_id(), &x, true, 1));
        assert_eq!(
            drain_bare(&mut session)[0]["message"],
            format!("a part of message {x}, whose first part never came")
        );
    }

    #[test]
    fn incomplete_messages_survive_a_resume_and_go_with_a_lost_session() {
        let (mut node, node_out, mut cp, _cp_out, _clock) = pair();
        let stream = StreamId(Uuid::parse_str(S2).unwrap());
        node_out.proxy(ProxyMessage::Body(ProxyBody {
            stream_id: stream,
            data: Bytes(vec![5; 100_000]),
        }));
        let first = node.poll_transmit().unwrap();
        cp.receive(&first);
        cp.tick();
        node.disconnected();
        cp.disconnected();
        node.connected();
        cp.connected();
        pump(&mut node, &mut cp);
        assert_eq!(
            incoming(&mut cp)
                .iter()
                .filter(|i| matches!(i, Incoming::Message { kind, .. } if kind == "proxy.body"))
                .count(),
            1
        );

        node_out.proxy(ProxyMessage::Body(ProxyBody {
            stream_id: stream,
            data: Bytes(vec![6; 100_000]),
        }));
        cp.receive(&node.poll_transmit().unwrap());
        cp.forget();
        node.disconnected();
        cp.disconnected();
        node.connected();
        cp.connected();
        pump(&mut node, &mut cp);
        node.ready(info(), vec![], vec![]).unwrap();
        pump(&mut node, &mut cp);
        assert!(
            incoming(&mut cp)
                .iter()
                .all(|i| !matches!(i, Incoming::Message { kind, .. } if kind == "proxy.body"))
        );
    }

    #[test]
    fn a_single_lane_writes_in_queue_order() {
        let (mut session, outbox, _clock) = open_node(Limits::default());
        session.set_single_lane(true);
        command_at(&mut session, C1, "fs.read", json!({ "path": "/big" }));
        let other = peer_id();
        command_at(&mut session, &other, "fs.stat", json!({ "path": "/s" }));
        outbox.reply(
            mid(C1),
            Ok(cbor(
                json!({ "data": format!("h'{}'", "07".repeat(200_000)) }),
            )),
        );
        outbox.reply(mid(&other), Ok(cbor(json!({ "size": 1 }))));
        let shape: Vec<String> = written(&mut session).into_iter().map(|(t, _)| t).collect();
        assert_eq!(shape, ["part", "part", "part", "part", "msg"]);
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
