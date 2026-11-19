//! Everything on the wire: docs/api.md and docs/node-info.md as serde types: link frames, the
//! body of every message kind, the join exchange, and NodeInfo.
//!
//! Incoming values are parsed into these types at the dispatcher, so code past it can trust them:
//! IDs, argv and absolute paths are validated by their `TryFrom` impls, and policies by
//! [`Policy`]'s.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::error::Error;
pub use crate::policy::Policy;
pub use crate::wire::Value;

/// The largest WebSocket message, after decompression (api.md, Limits).
pub const MAX_FRAME_BYTES: usize = 1 << 20;
/// The most of a message's CBOR body one `part` carries, and the largest body sent as one `msg`.
pub const MAX_PART_BYTES: usize = 64 << 10;
/// The largest reassembled message.
pub const MAX_MESSAGE_BYTES: usize = 32 << 20;
/// The incomplete messages a receiver holds per session.
pub const MAX_PARTIAL_BYTES: usize = 64 << 20;
pub const MAX_FS_DATA_BYTES: usize = 16 << 20;
pub const MAX_EXEC_WRITE_BYTES: usize = 1 << 20;
pub const MAX_OUTPUT_CHUNK_BYTES: usize = 64 << 10;
pub const RETAINED_EXITED_EXECS: usize = 256;
pub const MAX_EXEC_LOG_READ_BYTES: u64 = 1 << 20;
pub const DEFAULT_MEMORY_LOG_BYTES: u64 = 1 << 20;
pub const MAX_MEMORY_LOG_BYTES: u64 = 16 << 20;
pub const MEMORY_LOG_BUDGET_BYTES: u64 = 256 << 20;
pub const DEFAULT_FILE_LOG_BYTES: u64 = 64 << 20;
pub const MAX_FILE_LOG_BYTES: u64 = 1 << 30;
pub const MAX_WATCHES: usize = 64;
pub const MAX_LIST_ENTRIES: usize = 10_000;
pub const MAX_PROXY_TOKEN_BYTES: usize = 4096;
pub const MAX_PROXY_HOSTS: usize = 256;
pub const MAX_PROXY_BODY_BYTES: usize = 64 << 10;
pub const MAX_TCP_DATA_BYTES: usize = 64 << 10;
/// Open proxy streams and tunnels together (proxy.md, tunnels.md).
pub const MAX_STREAMS: usize = 1024;
/// Each direction of a proxy stream or tunnel (proxy.md, Flow control).
pub const STREAM_WINDOW_BYTES: u64 = 1 << 20;
pub const TCP_CONNECT_TIMEOUT_MS: u64 = 10_000;
pub const MAX_CHANGES_PER_EVENT: usize = 256;
pub const ACK_DELAY_MS: u64 = 200;
pub const ACK_EVERY_MSGS: u32 = 64;
pub const DROPPABLE_QUEUE_BYTES: usize = 16 << 20;
pub const RETAINED_QUEUE_BYTES: usize = 64 << 20;

// ---------------------------------------------------------------------------------------------
// Link frames (api.md, Link protocol)

/// Reads a CBOR byte string and nothing else: a text string or an array of numbers is rejected,
/// where a generic byte buffer would take either.
fn byte_string<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    struct Visitor;

    impl serde::de::Visitor<'_> for Visitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a byte string")
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
            Ok(v)
        }
    }

    d.deserialize_byte_buf(Visitor)
}

/// Defines a UUID newtype carried as a 16-byte CBOR byte string.
macro_rules! uuid_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub Uuid);

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_bytes(self.0.as_bytes())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let bytes = byte_string(d)?;
                Uuid::from_slice(&bytes).map($name).map_err(|_| {
                    serde::de::Error::custom(format!(
                        "a UUID is 16 bytes, got {}",
                        bytes.len()
                    ))
                })
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

uuid_type!(
    /// A message ID: a UUIDv7, strictly increasing per sender within a session.
    MsgId
);
uuid_type!(
    /// A session ID: a UUIDv7 chosen by the control plane.
    SessionId
);

/// The body of one frame (api.md, Frame layout). The frame ID is the prefix before it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum Frame {
    Hello(Hello),
    Welcome(Welcome),
    Msg(Msg),
    Part(Part),
    Ack(Ack),
    Bye(Bye),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hello {
    /// The session to resume, or `None` for a new one.
    pub session: Option<SessionId>,
    pub cursor: Option<MsgId>,
    pub node_id: String,
    pub installation_id: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Welcome {
    pub session: SessionId,
    pub resumed: bool,
    /// The control plane's cursor. Always `None` when `resumed` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<MsgId>,
    pub resume_window_ms: u64,
}

/// A message. Its ID is the frame's.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Msg {
    pub kind: String,
    #[serde(default = "null")]
    pub body: Value,
}

fn null() -> Value {
    Value::Null
}

/// One piece of a message whose body is over [`MAX_PART_BYTES`] (api.md, Lanes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    /// The ID of the message's first part, which is the message's ID.
    pub of: MsgId,
    pub last: bool,
    /// The next piece of the `msg` frame's CBOR body.
    pub data: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    pub cursor: MsgId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bye {
    pub reason: ByeReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByeReason {
    Shutdown,
    Revoked,
    QueueOverflow,
    ProtocolError,
}

/// The message kind of a reply.
pub const REPLY_KIND: &str = "reply";

/// A reply's body: `{"to": …, "ok": …}` or `{"to": …, "error": {"kind", "message"}}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    pub to: MsgId,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Ok(Value),
    Error(Error),
}

impl From<crate::Result<Value>> for Outcome {
    fn from(result: crate::Result<Value>) -> Outcome {
        match result {
            Ok(value) => Outcome::Ok(value),
            Err(err) => Outcome::Error(err),
        }
    }
}

impl From<Outcome> for crate::Result<Value> {
    fn from(outcome: Outcome) -> crate::Result<Value> {
        match outcome {
            Outcome::Ok(value) => Ok(value),
            Outcome::Error(err) => Err(err),
        }
    }
}

/// The events the node sends, as `{"kind": …, "body": …}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body")]
pub enum Event {
    #[serde(rename = "node.ready")]
    NodeReady(Box<NodeReady>),
    #[serde(rename = "exec.output")]
    ExecOutput(ExecOutput),
    #[serde(rename = "exec.exit")]
    ExecExit(ExecExit),
    #[serde(rename = "exec.timedOut")]
    ExecTimedOut(ExecTimedOut),
    #[serde(rename = "watch.event")]
    WatchEvent(WatchEvent),
    #[serde(rename = "net.denied")]
    NetDenied(NetDenied),
    /// A `proxy.*` stream message (proxy.md), which carries its own `kind`.
    #[serde(untagged)]
    Proxy(ProxyMessage),
    /// A `tcp.*` stream message (tunnels.md), which carries its own `kind`.
    #[serde(untagged)]
    Tcp(TcpMessage),
}

impl Event {
    pub const KINDS: [&str; 6] = [
        "node.ready",
        "exec.output",
        "exec.exit",
        "exec.timedOut",
        "watch.event",
        "net.denied",
    ];

    /// Parses a received message as an event. `None` for a kind that is not an event.
    pub fn parse(kind: &str, body: Value) -> Option<Result<Event, String>> {
        if ProxyMessage::KINDS.contains(&kind) {
            return Some(ProxyMessage::parse(kind, body).map(Event::Proxy));
        }
        if TcpMessage::KINDS.contains(&kind) {
            return Some(TcpMessage::parse(kind, body).map(Event::Tcp));
        }
        if !Event::KINDS.contains(&kind) {
            return None;
        }
        Some(crate::wire::from_value(tagged(kind, body)))
    }

    /// Whether `kind` is an event, which gets no reply. Every other kind is a command, and one
    /// the receiver does not know gets `unknown_kind`.
    pub fn is_event(kind: &str) -> bool {
        Event::KINDS.contains(&kind)
            || ProxyMessage::KINDS.contains(&kind)
            || TcpMessage::KINDS.contains(&kind)
    }
}

/// `{"kind": kind, "body": body}`, the shape the event enums deserialize from.
fn tagged(kind: &str, body: Value) -> Value {
    Value::Map(vec![
        (Value::Text("kind".into()), Value::Text(kind.into())),
        (Value::Text("body".into()), body),
    ])
}

/// The commands the node serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommandKind {
    NodeInfo,
    NodeUpdate,
    ExecStart,
    ExecWrite,
    ExecResize,
    ExecKill,
    ExecList,
    ExecLog,
    FsStat,
    FsList,
    FsRead,
    FsWrite,
    FsMkdir,
    FsRemove,
    FsRename,
    WatchStart,
    WatchStop,
    TcpOpen,
}

impl CommandKind {
    pub const ALL: [CommandKind; 18] = [
        CommandKind::NodeInfo,
        CommandKind::NodeUpdate,
        CommandKind::ExecStart,
        CommandKind::ExecWrite,
        CommandKind::ExecResize,
        CommandKind::ExecKill,
        CommandKind::ExecList,
        CommandKind::ExecLog,
        CommandKind::FsStat,
        CommandKind::FsList,
        CommandKind::FsRead,
        CommandKind::FsWrite,
        CommandKind::FsMkdir,
        CommandKind::FsRemove,
        CommandKind::FsRename,
        CommandKind::WatchStart,
        CommandKind::WatchStop,
        CommandKind::TcpOpen,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            CommandKind::NodeInfo => "node.info",
            CommandKind::NodeUpdate => "node.update",
            CommandKind::ExecStart => "exec.start",
            CommandKind::ExecWrite => "exec.write",
            CommandKind::ExecResize => "exec.resize",
            CommandKind::ExecKill => "exec.kill",
            CommandKind::ExecList => "exec.list",
            CommandKind::ExecLog => "exec.log",
            CommandKind::FsStat => "fs.stat",
            CommandKind::FsList => "fs.list",
            CommandKind::FsRead => "fs.read",
            CommandKind::FsWrite => "fs.write",
            CommandKind::FsMkdir => "fs.mkdir",
            CommandKind::FsRemove => "fs.remove",
            CommandKind::FsRename => "fs.rename",
            CommandKind::WatchStart => "watch.start",
            CommandKind::WatchStop => "watch.stop",
            CommandKind::TcpOpen => "tcp.open",
        }
    }

    pub fn from_name(name: &str) -> Option<CommandKind> {
        CommandKind::ALL.into_iter().find(|k| k.as_str() == name)
    }
}

/// `{}` as params or result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

// ---------------------------------------------------------------------------------------------
// Joining (api.md, Joining and credentials)

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    pub join_token: String,
    pub installation_id: String,
    pub name: String,
    pub info: NodeInfo,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinResponse {
    pub node_id: String,
    pub node_token: String,
    /// The full WebSocket URL to connect to from now on.
    pub endpoint: String,
}

/// The body of a failed join, when the control plane sends one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinError {
    pub error: String,
}

// ---------------------------------------------------------------------------------------------
// Validated primitives

/// Defines a control-plane-chosen ID: 1 to 64 characters of `[A-Za-z0-9_.-]`.
macro_rules! id_type {
    ($name:ident, $what:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = Error;

            fn try_from(id: String) -> Result<Self, Error> {
                let valid = (1..=64).contains(&id.len())
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
                if valid {
                    Ok($name(id))
                } else {
                    Err(Error::invalid_params(format!(
                        "{} must be 1 to 64 characters of [A-Za-z0-9_.-], got {id:?}",
                        $what
                    )))
                }
            }
        }

        impl TryFrom<&str> for $name {
            type Error = Error;

            fn try_from(id: &str) -> Result<Self, Error> {
                $name::try_from(id.to_owned())
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_type!(ExecId, "execId");
id_type!(WatchId, "watchId");

/// An absolute path from the wire. Not canonicalized and not checked for existence.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AbsPath(String);

impl AbsPath {
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AbsPath {
    type Error = Error;

    fn try_from(path: String) -> Result<Self, Error> {
        if path.contains('\0') {
            return Err(Error::invalid_params(format!("path {path:?} contains NUL")));
        }
        if !Path::new(&path).is_absolute() {
            return Err(Error::invalid_params(format!(
                "path {path:?} is not absolute"
            )));
        }
        Ok(AbsPath(path))
    }
}

impl TryFrom<&str> for AbsPath {
    type Error = Error;

    fn try_from(path: &str) -> Result<Self, Error> {
        AbsPath::try_from(path.to_owned())
    }
}

impl From<AbsPath> for String {
    fn from(path: AbsPath) -> String {
        path.0
    }
}

/// A non-empty argv. `program()` is `argv[0]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<String>", into = "Vec<String>")]
pub struct Argv(Vec<String>);

impl Argv {
    pub fn program(&self) -> &str {
        &self.0[0]
    }

    pub fn args(&self) -> &[String] {
        &self.0[1..]
    }

    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

impl TryFrom<Vec<String>> for Argv {
    type Error = Error;

    fn try_from(argv: Vec<String>) -> Result<Self, Error> {
        match argv.first() {
            None => Err(Error::invalid_params("argv is empty")),
            Some(program) if program.is_empty() => Err(Error::invalid_params("argv[0] is empty")),
            Some(_) => Ok(Argv(argv)),
        }
    }
}

impl From<Argv> for Vec<String> {
    fn from(argv: Argv) -> Vec<String> {
        argv.0
    }
}

/// Bytes carried as a CBOR byte string: `data` fields and proxy header values.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    pub fn new(bytes: Vec<u8>) -> Bytes {
        Bytes(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bytes({} bytes)", self.0.len())
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        byte_string(d).map(Bytes)
    }
}

// ---------------------------------------------------------------------------------------------
// Access

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum Access {
    /// A struct variant, because serde's `deny_unknown_fields` skips unit variants, and
    /// `{"mode": "raw", "policy": …}` must not run raw with the policy silently dropped.
    Raw {},
    Sandboxed {
        policy: Policy,
    },
}

/// The params of a request that carries `access`: the operation's own fields plus `access`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WithAccess<T> {
    #[serde(flatten)]
    pub params: T,
    pub access: Access,
}

// ---------------------------------------------------------------------------------------------
// Node

/// `node.update`: a new token, a new endpoint, or both. Parsing rejects an update with neither.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "NodeUpdateWire")]
pub struct NodeUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeUpdateWire {
    #[serde(default)]
    node_token: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
}

impl TryFrom<NodeUpdateWire> for NodeUpdate {
    type Error = Error;

    fn try_from(wire: NodeUpdateWire) -> Result<NodeUpdate, Error> {
        if wire.node_token.is_none() && wire.endpoint.is_none() {
            return Err(Error::invalid_params(
                "node.update needs nodeToken, endpoint or both",
            ));
        }
        Ok(NodeUpdate {
            node_token: wire.node_token,
            endpoint: wire.endpoint,
        })
    }
}

/// `node.ready`, the node's first message in every new session.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeReady {
    pub info: NodeInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_session: Option<SessionId>,
    pub execs: Vec<ExecSummary>,
    pub watches: Vec<WatchId>,
}

// ---------------------------------------------------------------------------------------------
// Processes

/// `exec.start` params without `access`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecStartParams {
    pub exec_id: ExecId,
    pub argv: Argv,
    pub cwd: AbsPath,
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub stdin: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<Timeout>,
    #[serde(default)]
    pub log: LogSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxySpec>,
    /// A terminal of this size instead of pipes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<TtySize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TtySizeWire")]
pub struct TtySize {
    pub rows: u16,
    pub cols: u16,
}

#[derive(Deserialize)]
struct TtySizeWire {
    rows: u16,
    cols: u16,
}

impl TryFrom<TtySizeWire> for TtySize {
    type Error = String;

    fn try_from(wire: TtySizeWire) -> std::result::Result<TtySize, String> {
        if wire.rows == 0 || wire.cols == 0 {
            return Err(format!(
                "a terminal of {} rows and {} columns: both must be at least 1",
                wire.rows, wire.cols
            ));
        }
        Ok(TtySize {
            rows: wire.rows,
            cols: wire.cols,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecResizeParams {
    pub exec_id: ExecId,
    #[serde(flatten)]
    pub size: TtySize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timeout {
    pub ms: u64,
    #[serde(with = "tagged_action")]
    pub action: TimeoutAction,
}

/// What happens when a timeout elapses. `{"kind": …}` in `exec.start`, a bare string in
/// `exec.timedOut`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimeoutAction {
    /// Kill the tree; the exit is `timedOut`.
    Kill,
    /// Keep running, stop streaming `exec.output`, keep logging.
    Background,
}

mod tagged_action {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::TimeoutAction;

    #[derive(Serialize, Deserialize)]
    struct Tagged {
        kind: TimeoutAction,
    }

    pub fn serialize<S: Serializer>(action: &TimeoutAction, s: S) -> Result<S::Ok, S::Error> {
        Tagged { kind: *action }.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<TimeoutAction, D::Error> {
        Ok(Tagged::deserialize(d)?.kind)
    }
}

/// Where a process's combined output log lives (api.md, Output logs). `limit_bytes` is checked
/// against the per-kind maximum when parsed; [`LogSpec::limit_bytes`] applies the default.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    try_from = "LogSpecWire"
)]
pub enum LogSpec {
    Memory {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit_bytes: Option<u64>,
    },
    File {
        path: AbsPath,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit_bytes: Option<u64>,
    },
}

impl Default for LogSpec {
    fn default() -> LogSpec {
        LogSpec::Memory { limit_bytes: None }
    }
}

impl LogSpec {
    /// The size limit, with the default for its kind applied.
    pub fn limit_bytes(&self) -> u64 {
        match self {
            LogSpec::Memory { limit_bytes } => limit_bytes.unwrap_or(DEFAULT_MEMORY_LOG_BYTES),
            LogSpec::File { limit_bytes, .. } => limit_bytes.unwrap_or(DEFAULT_FILE_LOG_BYTES),
        }
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum LogSpecWire {
    Memory {
        #[serde(default)]
        limit_bytes: Option<u64>,
    },
    File {
        path: AbsPath,
        #[serde(default)]
        limit_bytes: Option<u64>,
    },
}

impl TryFrom<LogSpecWire> for LogSpec {
    type Error = Error;

    fn try_from(wire: LogSpecWire) -> Result<LogSpec, Error> {
        let (spec, max) = match wire {
            LogSpecWire::Memory { limit_bytes } => {
                (LogSpec::Memory { limit_bytes }, MAX_MEMORY_LOG_BYTES)
            }
            LogSpecWire::File { path, limit_bytes } => {
                (LogSpec::File { path, limit_bytes }, MAX_FILE_LOG_BYTES)
            }
        };
        match spec.limit_bytes() {
            0 => Err(Error::invalid_params("log limitBytes must be positive")),
            n if n > max => Err(Error::invalid_params(format!(
                "log limitBytes is {n}, at most {max} are allowed"
            ))),
            _ => Ok(spec),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecStartResult {
    pub exec_id: ExecId,
    pub pid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecWriteParams {
    pub exec_id: ExecId,
    pub data: Bytes,
    #[serde(default)]
    pub eof: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KillSignal {
    /// SIGINT, as Ctrl-C at a terminal.
    Interrupt,
    Terminate,
    Kill,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecKillParams {
    pub exec_id: ExecId,
    pub signal: KillSignal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecListResult {
    pub execs: Vec<ExecSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecSummary {
    pub exec_id: ExecId,
    #[serde(flatten)]
    pub state: ExecState,
    pub log_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum ExecState {
    Running,
    Exited { exit: ExitStatus },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ExitStatus {
    Exited { code: i32 },
    Signaled { signal: i32 },
    TimedOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecOutput {
    pub exec_id: ExecId,
    pub stream: Stream,
    pub data: Bytes,
    pub dropped_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecExit {
    pub exec_id: ExecId,
    pub exit: ExitStatus,
    pub log_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecTimedOut {
    pub exec_id: ExecId,
    pub action: TimeoutAction,
    pub log_bytes: u64,
}

/// A command proxy refused one of the process's connections (proxy.md, Egress proxy).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetDenied {
    pub exec_id: ExecId,
    pub host: String,
    pub port: u16,
    pub via: Via,
    pub reason: DenyReason,
    /// Refusals not reported since the last event, over the rate limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Via {
    Http,
    Socks5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DenyReason {
    Egress,
    Port,
    Address,
    Resolve,
    Credential,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecLogParams {
    pub exec_id: ExecId,
    #[serde(default)]
    pub offset: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecLogResult {
    pub data: Bytes,
    pub offset: u64,
    pub total_bytes: u64,
    pub retained: Vec<ByteRange>,
}

/// `[start, end)` in logical log offsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

// ---------------------------------------------------------------------------------------------
// The credential proxy (docs/proxy.md)

/// `exec.start`'s `proxy`: the hosts whose HTTP(S) requests go through the control plane, and the
/// token the node attaches to each.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ProxySpecWire")]
pub struct ProxySpec {
    pub token: ProxyToken,
    pub hosts: Vec<HostPattern>,
}

#[derive(Deserialize)]
struct ProxySpecWire {
    token: ProxyToken,
    hosts: Vec<HostPattern>,
}

impl TryFrom<ProxySpecWire> for ProxySpec {
    type Error = Error;

    fn try_from(wire: ProxySpecWire) -> Result<Self, Error> {
        if wire.hosts.len() > MAX_PROXY_HOSTS {
            return Err(Error::invalid_params(format!(
                "proxy hosts has {} entries, at most {MAX_PROXY_HOSTS} are allowed",
                wire.hosts.len()
            )));
        }
        Ok(ProxySpec {
            token: wire.token,
            hosts: wire.hosts,
        })
    }
}

/// The opaque proxy token: 1 to 4096 bytes. Never logged, so `Debug` hides it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProxyToken(String);

impl ProxyToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ProxyToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProxyToken(<redacted>)")
    }
}

impl TryFrom<String> for ProxyToken {
    type Error = Error;

    fn try_from(token: String) -> Result<Self, Error> {
        if (1..=MAX_PROXY_TOKEN_BYTES).contains(&token.len()) {
            Ok(ProxyToken(token))
        } else {
            Err(Error::invalid_params(format!(
                "a proxy token is 1 to {MAX_PROXY_TOKEN_BYTES} bytes, got {}",
                token.len()
            )))
        }
    }
}

impl TryFrom<&str> for ProxyToken {
    type Error = Error;

    fn try_from(token: &str) -> Result<Self, Error> {
        ProxyToken::try_from(token.to_owned())
    }
}

impl From<ProxyToken> for String {
    fn from(token: ProxyToken) -> String {
        token.0
    }
}

/// One `hosts` entry, lowercase and without a trailing dot.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum HostPattern {
    /// Exactly this name.
    Exact(String),
    /// `*.suffix`: every name under `suffix`, not `suffix` itself.
    Suffix(String),
}

impl HostPattern {
    /// Whether `host` (any case, a trailing dot allowed) is covered.
    pub fn matches(&self, host: &str) -> bool {
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        match self {
            HostPattern::Exact(name) => host == *name,
            HostPattern::Suffix(suffix) => host
                .strip_suffix(suffix.as_str())
                .is_some_and(|rest| rest.len() > 1 && rest.ends_with('.')),
        }
    }
}

impl TryFrom<String> for HostPattern {
    type Error = Error;

    fn try_from(pattern: String) -> Result<Self, Error> {
        let name = pattern
            .strip_suffix('.')
            .unwrap_or(&pattern)
            .to_ascii_lowercase();
        let (wildcard, name) = match name.strip_prefix("*.") {
            Some(suffix) => (true, suffix.to_owned()),
            None => (false, name),
        };
        let bad = |why: &str| Error::invalid_params(format!("proxy host {pattern:?} {why}"));
        if name.parse::<std::net::IpAddr>().is_ok() || name.starts_with('[') {
            return Err(bad("is an IP address, and only DNS names are allowed"));
        }
        let valid = (1..=253).contains(&name.len())
            && name.split('.').all(|label| {
                (1..=63).contains(&label.len())
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            });
        if !valid {
            return Err(bad("is not a DNS name or `*.` and a DNS name"));
        }
        Ok(if wildcard {
            HostPattern::Suffix(name)
        } else {
            HostPattern::Exact(name)
        })
    }
}

impl TryFrom<&str> for HostPattern {
    type Error = Error;

    fn try_from(pattern: &str) -> Result<Self, Error> {
        HostPattern::try_from(pattern.to_owned())
    }
}

impl From<HostPattern> for String {
    fn from(pattern: HostPattern) -> String {
        match pattern {
            HostPattern::Exact(name) => name,
            HostPattern::Suffix(suffix) => format!("*.{suffix}"),
        }
    }
}

uuid_type!(
    /// A proxy stream: a UUIDv7 the node chooses for each forwarded request.
    StreamId
);

impl StreamId {
    pub fn generate() -> StreamId {
        StreamId(Uuid::now_v7())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https,
}

/// A `[name, value]` pair: the name lowercase, the value bytes.
pub type Header = (String, Bytes);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyRequest {
    pub stream_id: StreamId,
    pub exec_id: ExecId,
    pub token: ProxyToken,
    pub method: String,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub headers: Vec<Header>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyResponse {
    pub stream_id: StreamId,
    pub status: u16,
    pub headers: Vec<Header>,
}

/// A piece of a request or response body, at most [`MAX_PROXY_BODY_BYTES`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyBody {
    pub stream_id: StreamId,
    pub data: Bytes,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyEnd {
    pub stream_id: StreamId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyReset {
    pub stream_id: StreamId,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyCredit {
    pub stream_id: StreamId,
    pub bytes: u64,
}

/// One `proxy.*` stream message, in either direction, as `{"kind": …, "body": …}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body")]
pub enum ProxyMessage {
    #[serde(rename = "proxy.request")]
    Request(ProxyRequest),
    #[serde(rename = "proxy.response")]
    Response(ProxyResponse),
    #[serde(rename = "proxy.body")]
    Body(ProxyBody),
    #[serde(rename = "proxy.end")]
    End(ProxyEnd),
    #[serde(rename = "proxy.reset")]
    Reset(ProxyReset),
    #[serde(rename = "proxy.credit")]
    Credit(ProxyCredit),
}

impl ProxyMessage {
    pub const KINDS: [&str; 6] = [
        "proxy.request",
        "proxy.response",
        "proxy.body",
        "proxy.end",
        "proxy.reset",
        "proxy.credit",
    ];

    pub fn kind(&self) -> &'static str {
        match self {
            ProxyMessage::Request(_) => "proxy.request",
            ProxyMessage::Response(_) => "proxy.response",
            ProxyMessage::Body(_) => "proxy.body",
            ProxyMessage::End(_) => "proxy.end",
            ProxyMessage::Reset(_) => "proxy.reset",
            ProxyMessage::Credit(_) => "proxy.credit",
        }
    }

    pub fn stream_id(&self) -> StreamId {
        match self {
            ProxyMessage::Request(m) => m.stream_id,
            ProxyMessage::Response(m) => m.stream_id,
            ProxyMessage::Body(m) => m.stream_id,
            ProxyMessage::End(m) => m.stream_id,
            ProxyMessage::Reset(m) => m.stream_id,
            ProxyMessage::Credit(m) => m.stream_id,
        }
    }

    /// Parses a received message of one of [`ProxyMessage::KINDS`] as a stream message.
    pub fn parse(kind: &str, body: Value) -> Result<ProxyMessage, String> {
        crate::wire::from_value(tagged(kind, body))
    }
}

// ---------------------------------------------------------------------------------------------
// TCP tunnels (docs/tunnels.md)

/// `tcp.open`'s params. The host is loopback by construction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "TcpOpenWire")]
pub struct TcpOpenParams {
    pub stream_id: StreamId,
    pub host: LoopbackHost,
    pub port: u16,
    /// Connect to the loopback as this running process sees it (tunnels.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_id: Option<ExecId>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcpOpenWire {
    stream_id: StreamId,
    host: LoopbackHost,
    port: u16,
    #[serde(default)]
    exec_id: Option<ExecId>,
}

impl TryFrom<TcpOpenWire> for TcpOpenParams {
    type Error = Error;

    fn try_from(wire: TcpOpenWire) -> Result<Self, Error> {
        if wire.port == 0 {
            return Err(Error::invalid_params("port must be 1 to 65535, got 0"));
        }
        Ok(TcpOpenParams {
            stream_id: wire.stream_id,
            host: wire.host,
            port: wire.port,
            exec_id: wire.exec_id,
        })
    }
}

/// The hosts a tunnel may reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum LoopbackHost {
    /// `127.0.0.1`.
    V4,
    /// `::1`.
    V6,
    /// `localhost`: `::1`, then `127.0.0.1`.
    Localhost,
}

impl LoopbackHost {
    /// The addresses to try, in order.
    pub fn addresses(self) -> &'static [std::net::IpAddr] {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        const V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        const V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        match self {
            LoopbackHost::V4 => &[V4],
            LoopbackHost::V6 => &[V6],
            LoopbackHost::Localhost => &[V6, V4],
        }
    }
}

impl TryFrom<String> for LoopbackHost {
    type Error = Error;

    fn try_from(host: String) -> Result<Self, Error> {
        match host.as_str() {
            "127.0.0.1" => Ok(LoopbackHost::V4),
            "::1" => Ok(LoopbackHost::V6),
            "localhost" => Ok(LoopbackHost::Localhost),
            _ => Err(Error::invalid_params(format!(
                "a tunnel reaches 127.0.0.1, ::1 or localhost, not {host:?}"
            ))),
        }
    }
}

impl From<LoopbackHost> for String {
    fn from(host: LoopbackHost) -> String {
        match host {
            LoopbackHost::V4 => "127.0.0.1",
            LoopbackHost::V6 => "::1",
            LoopbackHost::Localhost => "localhost",
        }
        .to_string()
    }
}

/// Bytes of a tunnel, at most [`MAX_TCP_DATA_BYTES`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpData {
    pub stream_id: StreamId,
    pub data: Bytes,
}

/// The sender's half-close.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpEnd {
    pub stream_id: StreamId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpReset {
    pub stream_id: StreamId,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpCredit {
    pub stream_id: StreamId,
    pub bytes: u64,
}

/// One `tcp.*` stream message, in either direction, as `{"kind": …, "body": …}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body")]
pub enum TcpMessage {
    #[serde(rename = "tcp.data")]
    Data(TcpData),
    #[serde(rename = "tcp.end")]
    End(TcpEnd),
    #[serde(rename = "tcp.reset")]
    Reset(TcpReset),
    #[serde(rename = "tcp.credit")]
    Credit(TcpCredit),
}

impl TcpMessage {
    pub const KINDS: [&str; 4] = ["tcp.data", "tcp.end", "tcp.reset", "tcp.credit"];

    pub fn kind(&self) -> &'static str {
        match self {
            TcpMessage::Data(_) => "tcp.data",
            TcpMessage::End(_) => "tcp.end",
            TcpMessage::Reset(_) => "tcp.reset",
            TcpMessage::Credit(_) => "tcp.credit",
        }
    }

    pub fn stream_id(&self) -> StreamId {
        match self {
            TcpMessage::Data(m) => m.stream_id,
            TcpMessage::End(m) => m.stream_id,
            TcpMessage::Reset(m) => m.stream_id,
            TcpMessage::Credit(m) => m.stream_id,
        }
    }

    /// Parses a received message of one of [`TcpMessage::KINDS`].
    pub fn parse(kind: &str, body: Value) -> Result<TcpMessage, String> {
        crate::wire::from_value(tagged(kind, body))
    }
}

// ---------------------------------------------------------------------------------------------
// Files

/// `fs.stat` and `fs.list` params without `access`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsPathParams {
    pub path: AbsPath,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsReadParams {
    pub path: AbsPath,
    #[serde(default)]
    pub offset: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteMode {
    Create,
    Overwrite,
    Append,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsWriteParams {
    pub path: AbsPath,
    pub data: Bytes,
    pub mode: WriteMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsMkdirParams {
    pub path: AbsPath,
    #[serde(default)]
    pub recursive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsRemoveParams {
    pub path: AbsPath,
    #[serde(default)]
    pub recursive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsRenameParams {
    pub from: AbsPath,
    pub to: AbsPath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FsStat {
    pub kind: FileKind,
    pub size: u64,
    pub modified_ms: i64,
    pub readonly: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub kind: FileKind,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsListResult {
    pub entries: Vec<DirEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsReadResult {
    pub data: Bytes,
    pub size: u64,
}

// ---------------------------------------------------------------------------------------------
// Watching

/// `watch.start` params without `access`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchStartParams {
    pub watch_id: WatchId,
    pub path: AbsPath,
    #[serde(default)]
    pub recursive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchStopParams {
    pub watch_id: WatchId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchEvent {
    pub watch_id: WatchId,
    #[serde(flatten)]
    pub body: WatchEventBody,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WatchEventBody {
    Changes { changes: Vec<Change> },
    Overflow { overflow: True },
}

/// The literal `true`, for `"overflow": true`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct True;

impl Serialize for True {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for True {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if bool::deserialize(d)? {
            Ok(True)
        } else {
            Err(serde::de::Error::custom("expected `true`"))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub kind: ChangeKind,
    pub path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Created,
    Modified,
    Removed,
    Renamed,
}

// ---------------------------------------------------------------------------------------------
// NodeInfo (docs/node-info.md)

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub installation_id: String,
    pub name: String,
    pub hostname: String,
    pub supervisor_version: String,
    pub os: OsInfo,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub disks: Vec<DiskInfo>,
    pub gpus: Vec<GpuInfo>,
    pub sandbox: SandboxInfo,
    pub identity: IdentityInfo,
    pub default_env: BTreeMap<String, String>,
    pub collected_at_ms: u64,
}

/// NodeInfo's `identity`: who the supervisor runs as, and who its work runs as.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInfo {
    pub supervisor_user: String,
    /// `--workload-user`: every command, file operation and watch runs as this user. `null`
    /// when they run as the supervisor's user.
    pub workload_user: Option<String>,
    /// The supervisor runs as root (Unix) or with an elevated administrator token (Windows).
    pub root: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OsInfo {
    pub family: OsFamily,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    pub arch: Arch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsFamily {
    Linux,
    Macos,
    Windows,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arch {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpuInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_cores: Option<u32>,
    pub logical_cores: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub swap_total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskInfo {
    pub mount_point: String,
    pub file_system: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub removable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuInfo {
    pub name: String,
    pub vendor: GpuVendor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GpuVendor {
    Nvidia,
    Amd,
    Intel,
    Apple,
    Other,
}

/// NodeInfo's `sandbox`. On the wire it is the flat object of node-info.md. In Rust the
/// availability and the bubblewrap version are sum types, so "available with a reason" or
/// "seatbelt with a bubblewrap version" cannot be built.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "SandboxInfoWire", try_from = "SandboxInfoWire")]
pub struct SandboxInfo {
    pub mechanism: Mechanism,
    pub status: SandboxStatus,
    pub baseline_read: Vec<String>,
    /// What the sandbox does not enforce here, one sentence each. Empty when unavailable.
    pub gaps: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mechanism {
    /// `version` is what `bwrap --version` printed.
    Bubblewrap {
        version: Option<String>,
    },
    Seatbelt,
    Windows,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SandboxStatus {
    Available,
    Unavailable { reason: String },
}

impl SandboxInfo {
    /// `Ok` when sandboxed requests can run here, else the `sandbox_unavailable` to answer.
    pub fn require_available(&self) -> crate::Result<()> {
        match &self.status {
            SandboxStatus::Available => Ok(()),
            SandboxStatus::Unavailable { reason } => Err(Error::sandbox_unavailable(reason)),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SandboxInfoWire {
    mechanism: MechanismName,
    available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    baseline_read: Vec<String>,
    #[serde(default)]
    gaps: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum MechanismName {
    Bubblewrap,
    Seatbelt,
    Windows,
    None,
}

impl From<SandboxInfo> for SandboxInfoWire {
    fn from(info: SandboxInfo) -> SandboxInfoWire {
        let (mechanism, version) = match info.mechanism {
            Mechanism::Bubblewrap { version } => (MechanismName::Bubblewrap, version),
            Mechanism::Seatbelt => (MechanismName::Seatbelt, None),
            Mechanism::Windows => (MechanismName::Windows, None),
            Mechanism::None => (MechanismName::None, None),
        };
        let (available, reason) = match info.status {
            SandboxStatus::Available => (true, None),
            SandboxStatus::Unavailable { reason } => (false, Some(reason)),
        };
        SandboxInfoWire {
            mechanism,
            available,
            reason,
            version,
            baseline_read: info.baseline_read,
            gaps: info.gaps,
        }
    }
}

impl TryFrom<SandboxInfoWire> for SandboxInfo {
    type Error = Error;

    fn try_from(wire: SandboxInfoWire) -> Result<SandboxInfo, Error> {
        let mechanism = match (wire.mechanism, wire.version) {
            (MechanismName::Bubblewrap, version) => Mechanism::Bubblewrap { version },
            (MechanismName::Seatbelt, None) => Mechanism::Seatbelt,
            (MechanismName::Windows, None) => Mechanism::Windows,
            (MechanismName::None, None) => Mechanism::None,
            (_, Some(_)) => {
                return Err(Error::invalid_params(
                    "version is set for a mechanism other than bubblewrap",
                ));
            }
        };
        let status = match (wire.available, wire.reason) {
            (true, None) => SandboxStatus::Available,
            (false, Some(reason)) => SandboxStatus::Unavailable { reason },
            (true, Some(_)) => {
                return Err(Error::invalid_params("an available sandbox has a reason"));
            }
            (false, None) => {
                return Err(Error::invalid_params(
                    "an unavailable sandbox has no reason",
                ));
            }
        };
        if matches!(mechanism, Mechanism::None) && status == SandboxStatus::Available {
            return Err(Error::invalid_params("mechanism none cannot be available"));
        }
        Ok(SandboxInfo {
            mechanism,
            status,
            baseline_read: wire.baseline_read,
            gaps: wire.gaps,
        })
    }
}

// The examples use Unix paths, which are not absolute on Windows.
#[cfg(all(test, unix))]
mod tests {
    use serde::de::DeserializeOwned;
    use serde_json::{Value as Json, json};

    use super::*;
    use crate::testkit::cbor;
    use crate::wire::{from_cbor, from_value, to_cbor};

    /// Parses the CBOR that `literal` stands for as `T`, checks that `T` encodes back to the
    /// same CBOR (nulls and omitted fields being equal), and returns it.
    fn round_trip<T: Serialize + DeserializeOwned>(literal: Json) -> T {
        let bytes = to_cbor(&cbor(literal.clone()));
        let parsed: T = from_cbor(&bytes).unwrap();
        let encoded = to_cbor(&parsed);
        let unregistered = crate::wire::text_keys(&encoded);
        assert!(
            unregistered.is_empty(),
            "field names missing from wire::REGISTRY: {unregistered:?}"
        );
        let again: Value = from_cbor(&encoded).unwrap();
        assert_eq!(canon(crate::testkit::json(again)), canon(literal));
        parsed
    }

    /// Drops null map entries, so a field written as `null` equals one that was omitted.
    fn canon(json: serde_json::Value) -> serde_json::Value {
        match json {
            serde_json::Value::Object(map) => serde_json::Value::Object(
                map.into_iter()
                    .filter(|(_, v)| !v.is_null())
                    .map(|(k, v)| (k, canon(v)))
                    .collect(),
            ),
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.into_iter().map(canon).collect())
            }
            other => other,
        }
    }

    fn parse<T: DeserializeOwned>(literal: Json) -> T {
        from_value(cbor(literal)).unwrap()
    }

    fn rejects<T: DeserializeOwned + std::fmt::Debug>(literal: Json) -> String {
        from_value::<T>(cbor(literal)).unwrap_err()
    }

    fn u(id: &str) -> String {
        format!("u'{id}'")
    }

    fn policy_json() -> Json {
        json!({
          "filesystem": {
            "read":  { "default": "deny", "allow": ["/usr", "/home/me/repo"], "deny": [] },
            "write": { "default": "deny", "allow": ["/home/me/repo"], "deny": ["/home/me/repo/.git/hooks"] }
          },
          "network": { "mode": "host", "localBind": false, "unixSockets": false }
        })
    }

    fn node_info_json() -> Json {
        json!({
          "installationId": "tz4a98xxat96iws9zmbrgj3a",
          "name": "build-box-3",
          "hostname": "build-box-3.lan",
          "supervisorVersion": "0.1.0",
          "os": {
            "family": "linux",
            "name": "Debian GNU/Linux",
            "version": "13",
            "kernelVersion": "6.12.115+deb13.1-amd64",
            "arch": "x86_64"
          },
          "cpu": { "model": "AMD EPYC 9654 96-Core Processor", "physicalCores": 24, "logicalCores": 48 },
          "memory": { "totalBytes": 134217728000u64, "swapTotalBytes": 0 },
          "disks": [
            { "mountPoint": "/", "fileSystem": "ext4", "totalBytes": 1000000000000u64, "availableBytes": 400000000000u64, "removable": false }
          ],
          "gpus": [
            { "name": "NVIDIA L4", "vendor": "nvidia", "memoryBytes": 24152899584u64, "driverVersion": "580.82.07" }
          ],
          "sandbox": {
            "mechanism": "bubblewrap",
            "version": "0.11.0",
            "available": true,
            "reason": null,
            "baselineRead": ["/usr", "/bin", "/lib", "/lib64", "/etc"],
            "gaps": [
              "a command killed by a signal is reported as exiting with 128 plus the signal number",
              "32-bit x86 and x32 programs cannot run in the sandbox"
            ]
          },
          "identity": { "supervisorUser": "root", "workloadUser": "happy-workload", "root": true },
          "defaultEnv": { "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/me", "USER": "me", "LANG": "C.UTF-8" },
          "collectedAtMs": 1763496000000u64
        })
    }

    #[test]
    fn api_md_kinds_are_all_modeled() {
        let doc = include_str!("../docs/api.md");
        let mut commands = Vec::new();
        for line in doc.lines() {
            let Some(name) = line.strip_prefix("### `").and_then(|l| l.split('`').next()) else {
                continue;
            };
            if line.ends_with("(event)") {
                assert!(Event::KINDS.contains(&name), "event {name} is not modeled");
            } else {
                commands.push(
                    CommandKind::from_name(name)
                        .unwrap_or_else(|| panic!("{name} is not a CommandKind")),
                );
            }
        }
        // tunnels.md defines the one command api.md does not.
        assert!(include_str!("../docs/tunnels.md").contains("`tcp.open` is a **command**"));
        commands.push(CommandKind::TcpOpen);
        assert_eq!(commands, CommandKind::ALL);
    }

    const ID_A: &str = "0193a3b4-7c2e-7aa1-9f00-3c1d2e4f5a6b";
    const ID_B: &str = "0193a3b5-0000-7000-8000-000000000001";

    fn id(text: &str) -> Uuid {
        Uuid::parse_str(text).unwrap()
    }

    #[test]
    fn link_frames() {
        let hello: Frame = round_trip(
            json!({ "t": "hello", "session": u(ID_A), "cursor": u(ID_B), "nodeId": "n_1", "installationId": "tz4a98xxat96iws9zmbrgj3a", "version": "0.1.0" }),
        );
        assert_eq!(
            hello,
            Frame::Hello(Hello {
                session: Some(SessionId(id(ID_A))),
                cursor: Some(MsgId(id(ID_B))),
                node_id: "n_1".to_string(),
                installation_id: "tz4a98xxat96iws9zmbrgj3a".to_string(),
                version: "0.1.0".to_string(),
            })
        );
        round_trip::<Frame>(
            json!({ "t": "hello", "session": null, "cursor": null, "nodeId": "n_1", "installationId": "x", "version": "0.1.0" }),
        );
        let welcome: Frame = round_trip(
            json!({ "t": "welcome", "session": u(ID_A), "resumed": true, "cursor": u(ID_B), "resumeWindowMs": 300000 }),
        );
        assert_eq!(
            welcome,
            Frame::Welcome(Welcome {
                session: SessionId(id(ID_A)),
                resumed: true,
                cursor: Some(MsgId(id(ID_B))),
                resume_window_ms: 300000,
            })
        );
        let msg: Frame = round_trip(
            json!({ "t": "msg", "kind": "exec.start", "body": { "execId": "build-1" } }),
        );
        assert_eq!(
            msg,
            Frame::Msg(Msg {
                kind: "exec.start".to_string(),
                body: cbor(json!({ "execId": "build-1" })),
            })
        );
        let part: Frame =
            round_trip(json!({ "t": "part", "of": u(ID_A), "last": false, "data": "h'a3'" }));
        assert_eq!(
            part,
            Frame::Part(Part {
                of: MsgId(id(ID_A)),
                last: false,
                data: Bytes(vec![0xa3]),
            })
        );
        let ack: Frame = round_trip(json!({ "t": "ack", "cursor": u(ID_A) }));
        assert_eq!(
            ack,
            Frame::Ack(Ack {
                cursor: MsgId(id(ID_A))
            })
        );
        let bye: Frame = round_trip(
            json!({ "t": "bye", "reason": "revoked", "message": "node removed by admin" }),
        );
        assert_eq!(
            bye,
            Frame::Bye(Bye {
                reason: ByeReason::Revoked,
                message: Some("node removed by admin".to_string()),
            })
        );
        for reason in ["shutdown", "queue_overflow", "protocol_error"] {
            round_trip::<Frame>(json!({ "t": "bye", "reason": reason }));
        }
        assert!(rejects::<Frame>(json!({ "t": "ping" })).contains("unknown variant `ping`"));
        assert!(
            rejects::<Frame>(json!({ "t": "ack", "cursor": "h'0102'" }))
                .contains("a UUID is 16 bytes, got 2")
        );
        assert!(
            rejects::<Frame>(json!({ "t": "ack", "cursor": ID_A }))
                .contains("invalid type: string")
        );
        let unknown_keys: Frame = parse(json!({ "t": "ack", "cursor": u(ID_A), "future": 1 }));
        assert_eq!(
            unknown_keys,
            Frame::Ack(Ack {
                cursor: MsgId(id(ID_A))
            })
        );
    }

    #[test]
    fn replies() {
        let ok: Reply = round_trip(json!({ "to": u(ID_A), "ok": { "size": 1 } }));
        assert_eq!(
            ok,
            Reply {
                to: MsgId(id(ID_A)),
                outcome: Outcome::Ok(cbor(json!({ "size": 1 }))),
            }
        );
        let err: Reply = round_trip(
            json!({ "to": u(ID_B), "error": { "kind": "permission_denied", "message": "…" } }),
        );
        assert_eq!(
            crate::Result::<Value>::from(err.outcome),
            Err(Error::new(crate::ErrorKind::PermissionDenied, "…"))
        );
    }

    #[test]
    fn join_exchange() {
        let request: JoinRequest = round_trip(
            json!({ "joinToken": "jt_1", "installationId": "tz4a98xxat96iws9zmbrgj3a", "name": "build-box-3", "info": node_info_json() }),
        );
        assert_eq!(request.name, "build-box-3");
        let response: JoinResponse = round_trip(
            json!({ "nodeId": "n_1", "nodeToken": "nt_1", "endpoint": "wss://edge-2.control.example.com/nodes/connect" }),
        );
        assert_eq!(
            response.endpoint,
            "wss://edge-2.control.example.com/nodes/connect"
        );
        let error: JoinError = round_trip(json!({ "error": "token spent" }));
        assert_eq!(error.error, "token spent");
    }

    #[test]
    fn node_ready_and_node_info() {
        let info: NodeInfo = round_trip(node_info_json());
        assert_eq!(
            info.sandbox.mechanism,
            Mechanism::Bubblewrap {
                version: Some("0.11.0".to_string())
            }
        );
        assert_eq!(info.sandbox.require_available(), Ok(()));
        assert_eq!(info.os.arch, Arch::X86_64);
        assert_eq!(info.gpus[0].vendor, GpuVendor::Nvidia);
        assert_eq!(
            info.identity,
            IdentityInfo {
                supervisor_user: "root".to_string(),
                workload_user: Some("happy-workload".to_string()),
                root: true
            }
        );

        let ready = json!({ "kind": "node.ready", "body": {
            "info": node_info_json(),
            "previousSession": u(ID_A),
            "execs": [ { "execId": "build-1", "state": "running", "logBytes": 1200 } ],
            "watches": [ "w-1" ]
        }});
        let Event::NodeReady(ready) = round_trip(ready) else {
            panic!("not node.ready");
        };
        assert_eq!(ready.previous_session, Some(SessionId(id(ID_A))));
        assert_eq!(
            ready.execs,
            [ExecSummary {
                exec_id: ExecId::try_from("build-1").unwrap(),
                state: ExecState::Running,
                log_bytes: 1200,
            }]
        );
        assert_eq!(ready.watches, [WatchId::try_from("w-1").unwrap()]);
    }

    #[test]
    fn events_parse_by_kind() {
        let event = Event::parse(
            "exec.output",
            cbor(
                json!({ "execId": "build-1", "stream": "stdout", "data": "h'6869'", "droppedBytes": 0 }),
            ),
        );
        assert_eq!(
            event.unwrap().unwrap(),
            Event::ExecOutput(ExecOutput {
                exec_id: ExecId::try_from("build-1").unwrap(),
                stream: Stream::Stdout,
                data: Bytes(b"hi".to_vec()),
                dropped_bytes: 0,
            })
        );
        assert!(Event::parse("exec.start", cbor(json!({}))).is_none());
        assert!(Event::parse("exec.exit", cbor(json!({}))).unwrap().is_err());
    }

    #[test]
    fn sandbox_info_shapes() {
        let mac: SandboxInfo = round_trip(
            json!({ "mechanism": "seatbelt", "available": false, "reason": "sandbox-exec is missing", "baselineRead": [], "gaps": [] }),
        );
        assert_eq!(
            mac.require_available(),
            Err(Error::sandbox_unavailable("sandbox-exec is missing"))
        );
        let windows: SandboxInfo = round_trip(
            json!({ "mechanism": "none", "available": false, "reason": "Windows has no sandbox backend", "baselineRead": [], "gaps": [] }),
        );
        assert_eq!(windows.mechanism, Mechanism::None);
        let bwrap: SandboxInfo = round_trip(
            json!({ "mechanism": "bubblewrap", "version": "0.11.0", "available": true, "reason": null, "baselineRead": ["/usr"], "gaps": [] }),
        );
        assert_eq!(
            bwrap.mechanism,
            Mechanism::Bubblewrap {
                version: Some("0.11.0".to_string())
            }
        );
        let restricted: SandboxInfo = round_trip(
            json!({ "mechanism": "windows", "available": false, "reason": "run happy-supervisor install-sandbox as an administrator", "baselineRead": [], "gaps": [] }),
        );
        assert_eq!(restricted.mechanism, Mechanism::Windows);
        assert!(rejects::<SandboxInfo>(json!({ "mechanism": "seatbelt", "version": "1", "available": true, "reason": null, "baselineRead": [] })).contains("version is set for a mechanism other than bubblewrap"));
        assert!(rejects::<SandboxInfo>(json!({ "mechanism": "bubblewrap", "available": true, "reason": "x", "baselineRead": [] })).contains("an available sandbox has a reason"));
        assert!(rejects::<SandboxInfo>(json!({ "mechanism": "bubblewrap", "available": false, "reason": null, "baselineRead": [] })).contains("an unavailable sandbox has no reason"));
        assert!(rejects::<SandboxInfo>(json!({ "mechanism": "none", "available": true, "reason": null, "baselineRead": [] })).contains("mechanism none cannot be available"));
    }

    #[test]
    fn access() {
        assert_eq!(
            round_trip::<Access>(json!({ "mode": "raw" })),
            Access::Raw {}
        );
        let Access::Sandboxed { policy } =
            round_trip(json!({ "mode": "sandboxed", "policy": policy_json() }))
        else {
            panic!("not sandboxed");
        };
        assert_eq!(
            policy.write.allow,
            [std::path::PathBuf::from("/home/me/repo")]
        );
        assert!(
            rejects::<Access>(json!({ "mode": "sandboxed" })).contains("missing field `policy`")
        );
        assert!(
            rejects::<Access>(json!({ "mode": "raw", "policy": policy_json() }))
                .contains("unknown field `policy`")
        );
        assert!(rejects::<Access>(json!({ "mode": "root" })).contains("unknown variant `root`"));
    }

    #[test]
    fn exec_start() {
        let params = json!({
          "execId": "build-1",
          "argv": ["/usr/bin/make", "-j8"],
          "cwd": "/home/me/repo",
          "env": { "PATH": "/usr/bin:/bin", "HOME": "/home/me" },
          "stdin": false,
          "timeout": { "ms": 600000, "action": { "kind": "background" } },
          "log": { "kind": "file", "path": "/home/me/repo/.logs/build-1.log", "limitBytes": 67108864 },
          "proxy": { "token": "pt_8f1c…", "hosts": ["api.github.com"] },
          "access": { "mode": "sandboxed", "policy": policy_json() }
        });
        let start: WithAccess<ExecStartParams> = round_trip(params);
        assert_eq!(
            start.params.proxy,
            Some(ProxySpec {
                token: ProxyToken::try_from("pt_8f1c…").unwrap(),
                hosts: vec![HostPattern::Exact("api.github.com".to_string())],
            })
        );
        assert_eq!(start.params.argv.program(), "/usr/bin/make");
        assert_eq!(start.params.argv.args(), ["-j8"]);
        assert_eq!(
            start.params.timeout,
            Some(Timeout {
                ms: 600000,
                action: TimeoutAction::Background
            })
        );
        assert_eq!(start.params.log.limit_bytes(), 67108864);

        let minimal: ExecStartParams =
            parse(json!({ "execId": "a", "argv": ["sh"], "cwd": "/", "env": {} }));
        assert_eq!(
            (minimal.stdin, minimal.timeout, &minimal.log),
            (false, None, &LogSpec::Memory { limit_bytes: None })
        );
        assert_eq!(minimal.log.limit_bytes(), 1 << 20);
        let kill: Timeout = round_trip(json!({ "ms": 5, "action": { "kind": "kill" } }));
        assert_eq!(kill.action, TimeoutAction::Kill);

        assert!(
            rejects::<ExecStartParams>(json!({ "execId": "a", "argv": [], "cwd": "/", "env": {} }))
                .contains("argv is empty")
        );
        assert!(
            rejects::<ExecStartParams>(
                json!({ "execId": "a", "argv": ["sh"], "cwd": "rel", "env": {} })
            )
            .contains(r#"path "rel" is not absolute"#)
        );
        assert!(
            rejects::<ExecStartParams>(
                json!({ "execId": "", "argv": ["sh"], "cwd": "/", "env": {} })
            )
            .contains("execId must be 1 to 64 characters")
        );
        assert!(
            rejects::<ExecStartParams>(
                json!({ "execId": "a".repeat(65), "argv": ["sh"], "cwd": "/", "env": {} })
            )
            .contains("execId must be 1 to 64 characters")
        );
        assert_eq!(ExecId::try_from("A-z_0.9").unwrap().as_str(), "A-z_0.9");

        let result: ExecStartResult = round_trip(json!({ "execId": "build-1", "pid": 4242 }));
        assert_eq!(result.pid, 4242);
    }

    #[test]
    fn proxy_specs() {
        let spec: ProxySpec = parse(json!({ "token": "pt_1",
            "hosts": ["api.github.com", "*.openai.com", "Registry.NPMJS.org."] }));
        assert_eq!(
            spec.hosts,
            [
                HostPattern::Exact("api.github.com".to_string()),
                HostPattern::Suffix("openai.com".to_string()),
                HostPattern::Exact("registry.npmjs.org".to_string()),
            ]
        );
        assert_eq!(format!("{:?}", spec.token), "ProxyToken(<redacted>)");
        assert_eq!(spec.token.as_str(), "pt_1");

        assert!(
            rejects::<ProxySpec>(json!({ "token": "", "hosts": [] }))
                .contains("a proxy token is 1 to 4096 bytes, got 0")
        );
        assert!(ProxyToken::try_from("x".repeat(4096)).is_ok());
        assert!(ProxyToken::try_from("x".repeat(4097)).is_err());
        let hosts: Vec<String> = (0..257).map(|i| format!("h{i}.example.com")).collect();
        assert!(
            rejects::<ProxySpec>(json!({ "token": "t", "hosts": hosts }))
                .contains("proxy hosts has 257 entries, at most 256 are allowed")
        );
        for bad in ["127.0.0.1", "::1", "[::1]", "*.10.0.0.1"] {
            assert!(
                HostPattern::try_from(bad)
                    .unwrap_err()
                    .message
                    .contains("is an IP address"),
                "{bad}"
            );
        }
        for bad in [
            "",
            "*",
            "*.",
            "a..b",
            "*.*.example.com",
            "ex ample.com",
            "a.com:443",
        ] {
            assert!(
                HostPattern::try_from(bad)
                    .unwrap_err()
                    .message
                    .contains("is not a DNS name"),
                "{bad}"
            );
        }
    }

    #[test]
    fn tunnel_messages() {
        let open: TcpOpenParams =
            round_trip(json!({ "streamId": u(ID_A), "host": "localhost", "port": 3000 }));
        assert_eq!(open.host.addresses().len(), 2);
        assert_eq!(open.exec_id, None);
        let routed: TcpOpenParams = round_trip(
            json!({ "streamId": u(ID_A), "host": "127.0.0.1", "port": 3000, "execId": "dev-server" }),
        );
        assert_eq!(
            routed.exec_id,
            Some(ExecId::try_from("dev-server").unwrap())
        );
        assert_eq!(
            parse::<TcpOpenParams>(json!({ "streamId": u(ID_A), "host": "::1", "port": 1 })).host,
            LoopbackHost::V6
        );
        assert!(
            rejects::<TcpOpenParams>(
                json!({ "streamId": u(ID_A), "host": "10.0.0.1", "port": 22 })
            )
            .contains(r#"a tunnel reaches 127.0.0.1, ::1 or localhost, not "10.0.0.1""#)
        );
        assert!(
            rejects::<TcpOpenParams>(
                json!({ "streamId": u(ID_A), "host": "127.0.0.1", "port": 0 })
            )
            .contains("port must be 1 to 65535, got 0")
        );
        let data: Event = round_trip(
            json!({ "kind": "tcp.data", "body": { "streamId": u(ID_A), "data": "h'0102'" } }),
        );
        assert!(matches!(data, Event::Tcp(TcpMessage::Data(_))));
        for (kind, body) in [
            ("tcp.end", json!({ "streamId": u(ID_A) })),
            (
                "tcp.reset",
                json!({ "streamId": u(ID_A), "reason": "peer reset" }),
            ),
            ("tcp.credit", json!({ "streamId": u(ID_A), "bytes": 65536 })),
        ] {
            let message: TcpMessage = round_trip(json!({ "kind": kind, "body": body }));
            assert_eq!(message.kind(), kind);
            assert_eq!(message.stream_id().to_string(), ID_A);
        }
    }

    #[test]
    fn host_patterns_match() {
        let exact = HostPattern::try_from("api.github.com").unwrap();
        assert!(exact.matches("api.github.com"));
        assert!(exact.matches("API.GitHub.com."));
        assert!(!exact.matches("x.api.github.com"));
        assert!(!exact.matches("github.com"));
        let suffix = HostPattern::try_from("*.openai.com").unwrap();
        assert!(suffix.matches("api.openai.com"));
        assert!(suffix.matches("a.b.OpenAI.com."));
        assert!(!suffix.matches("openai.com"));
        assert!(!suffix.matches("notopenai.com"));
        assert!(!suffix.matches(".openai.com"));
        assert_eq!(String::from(suffix), "*.openai.com");
    }

    #[test]
    fn proxy_messages() {
        let request = Event::parse(
            "proxy.request",
            cbor(json!({ "streamId": u(ID_A), "execId": "build-1", "token": "pt_8f1c",
              "method": "POST", "scheme": "https", "host": "api.openai.com", "port": 443,
              "path": "/v1/responses",
              "headers": [["content-type", "h'6170706c69636174696f6e2f6a736f6e'"], ["x-a", "h''"]] })),
        )
        .unwrap()
        .unwrap();
        let Event::Proxy(ProxyMessage::Request(request)) = request else {
            panic!("{request:?}");
        };
        assert_eq!(request.stream_id.to_string(), ID_A);
        assert_eq!((request.scheme, request.port), (Scheme::Https, 443));
        assert_eq!(
            request.headers,
            [
                (
                    "content-type".to_string(),
                    Bytes(b"application/json".to_vec())
                ),
                ("x-a".to_string(), Bytes(vec![])),
            ]
        );

        let response: ProxyMessage = round_trip(json!({ "kind": "proxy.response",
            "body": { "streamId": u(ID_A), "status": 200, "headers": [["content-type", "h'6869'"]] } }));
        assert_eq!(response.kind(), "proxy.response");
        let body: ProxyMessage = round_trip(
            json!({ "kind": "proxy.body", "body": { "streamId": u(ID_B), "data": "h'000102'" } }),
        );
        assert_eq!(body.stream_id().to_string(), ID_B);
        round_trip::<ProxyMessage>(json!({ "kind": "proxy.end", "body": { "streamId": u(ID_A) } }));
        round_trip::<ProxyMessage>(
            json!({ "kind": "proxy.reset", "body": { "streamId": u(ID_A), "reason": "upstream timeout" } }),
        );
        let credit: Event = round_trip(
            json!({ "kind": "proxy.credit", "body": { "streamId": u(ID_A), "bytes": 65536 } }),
        );
        assert_eq!(
            credit,
            Event::Proxy(ProxyMessage::Credit(ProxyCredit {
                stream_id: StreamId(Uuid::parse_str(ID_A).unwrap()),
                bytes: 65536,
            }))
        );

        assert!(
            Event::parse(
                "proxy.body",
                cbor(json!({ "streamId": u(ID_A), "data": "text" }))
            )
            .unwrap()
            .unwrap_err()
            .contains("invalid type: string")
        );
        assert!(Event::parse("proxy.stream", cbor(json!({}))).is_none());
        assert_eq!(StreamId::generate().0.get_version_num(), 7);
    }

    #[test]
    fn log_specs() {
        assert_eq!(
            round_trip::<LogSpec>(json!({ "kind": "memory", "limitBytes": 1048576 })).limit_bytes(),
            1048576
        );
        assert_eq!(
            round_trip::<LogSpec>(json!({ "kind": "memory" })),
            LogSpec::Memory { limit_bytes: None }
        );
        assert_eq!(
            round_trip::<LogSpec>(json!({ "kind": "file", "path": "/var/log/x.log" }))
                .limit_bytes(),
            64 << 20
        );
        assert!(
            rejects::<LogSpec>(json!({ "kind": "memory", "limitBytes": (16 << 20) + 1 }))
                .contains("log limitBytes is 16777217, at most 16777216 are allowed")
        );
        assert_eq!(
            round_trip::<LogSpec>(
                json!({ "kind": "file", "path": "/x", "limitBytes": 1u64 << 30 })
            )
            .limit_bytes(),
            1 << 30
        );
        assert!(
            rejects::<LogSpec>(
                json!({ "kind": "file", "path": "/x", "limitBytes": (1u64 << 30) + 1 })
            )
            .contains("at most 1073741824")
        );
        assert!(
            rejects::<LogSpec>(json!({ "kind": "memory", "limitBytes": 0 }))
                .contains("log limitBytes must be positive")
        );
        assert!(rejects::<LogSpec>(json!({ "kind": "file" })).contains("missing field `path`"));
        assert_eq!(
            parse::<LogSpec>(json!({ "kind": "memory", "path": "/x" })),
            LogSpec::Memory { limit_bytes: None }
        );
    }

    #[test]
    fn exec_methods_and_notifications() {
        let write: ExecWriteParams =
            round_trip(json!({ "execId": "e", "data": "h'000102'", "eof": false }));
        assert_eq!(write.data, Bytes(vec![0, 1, 2]));
        let empty: ExecWriteParams =
            round_trip(json!({ "execId": "e", "data": "h''", "eof": true }));
        assert_eq!(empty.data.0, b"");
        assert!(
            rejects::<ExecWriteParams>(json!({ "execId": "e", "data": "AAEC" }))
                .contains("invalid type: string")
        );
        assert!(
            rejects::<ExecWriteParams>(json!({ "execId": "e", "data": [0, 1, 2] }))
                .contains("invalid type: sequence")
        );

        let kill: ExecKillParams = round_trip(json!({ "execId": "e", "signal": "terminate" }));
        assert_eq!(kill.signal, KillSignal::Terminate);
        let interrupt: ExecKillParams = round_trip(json!({ "execId": "e", "signal": "interrupt" }));
        assert_eq!(interrupt.signal, KillSignal::Interrupt);
        let resize: ExecResizeParams =
            round_trip(json!({ "execId": "e", "rows": 50, "cols": 132 }));
        assert_eq!(
            resize.size,
            TtySize {
                rows: 50,
                cols: 132
            }
        );
        let tty: ExecStartParams = round_trip(json!({ "execId": "t", "argv": ["/bin/sh"],
            "cwd": "/", "env": {}, "stdin": false, "log": { "kind": "memory" },
            "tty": { "rows": 24, "cols": 80 } }));
        assert_eq!(tty.tty, Some(TtySize { rows: 24, cols: 80 }));
        assert_eq!(
            rejects::<ExecResizeParams>(json!({ "execId": "e", "rows": 0, "cols": 80 })),
            "a terminal of 0 rows and 80 columns: both must be at least 1"
        );

        let list: ExecListResult = round_trip(json!({ "execs": [
            { "execId": "a", "state": "running", "logBytes": 1200 },
            { "execId": "b", "state": "exited", "exit": { "kind": "exited", "code": 0 }, "logBytes": 0 },
            { "execId": "c", "state": "exited", "exit": { "kind": "signaled", "signal": 9 }, "logBytes": 1 },
            { "execId": "d", "state": "exited", "exit": { "kind": "timedOut" }, "logBytes": 2 }
        ]}));
        let exits: Vec<ExecState> = list.execs.into_iter().map(|s| s.state).collect();
        assert_eq!(
            exits,
            [
                ExecState::Running,
                ExecState::Exited {
                    exit: ExitStatus::Exited { code: 0 }
                },
                ExecState::Exited {
                    exit: ExitStatus::Signaled { signal: 9 }
                },
                ExecState::Exited {
                    exit: ExitStatus::TimedOut
                },
            ]
        );

        let exit: Event = round_trip(
            json!({ "kind": "exec.exit", "body": { "execId": "build-1", "exit": { "kind": "exited", "code": 0 }, "logBytes": 183022 } }),
        );
        assert_eq!(
            exit,
            Event::ExecExit(ExecExit {
                exec_id: ExecId::try_from("build-1").unwrap(),
                exit: ExitStatus::Exited { code: 0 },
                log_bytes: 183022
            })
        );
        let timed_out: Event = round_trip(
            json!({ "kind": "exec.timedOut", "body": { "execId": "build-1", "action": "background", "logBytes": 183022 } }),
        );
        assert_eq!(
            timed_out,
            Event::ExecTimedOut(ExecTimedOut {
                exec_id: ExecId::try_from("build-1").unwrap(),
                action: TimeoutAction::Background,
                log_bytes: 183022
            })
        );

        let denied: Event = round_trip(
            json!({ "kind": "net.denied", "body": { "execId": "e_1", "host": "evil.example", "port": 443, "via": "http", "reason": "egress" } }),
        );
        assert_eq!(
            denied,
            Event::NetDenied(NetDenied {
                exec_id: ExecId::try_from("e_1").unwrap(),
                host: "evil.example".to_string(),
                port: 443,
                via: Via::Http,
                reason: DenyReason::Egress,
                dropped: None,
            })
        );
        let counted: Event = round_trip(
            json!({ "kind": "net.denied", "body": { "execId": "e_1", "host": "10.0.0.1", "port": 22, "via": "socks5", "reason": "address", "dropped": 7 } }),
        );
        assert!(matches!(
            counted,
            Event::NetDenied(NetDenied {
                via: Via::Socks5,
                reason: DenyReason::Address,
                dropped: Some(7),
                ..
            })
        ));

        let log: ExecLogParams =
            round_trip(json!({ "execId": "build-1", "offset": 0, "length": 65536 }));
        assert_eq!(log.length, Some(65536));
        let defaults: ExecLogParams = parse(json!({ "execId": "build-1" }));
        assert_eq!((defaults.offset, defaults.length), (0, None));
        let read: ExecLogResult = round_trip(
            json!({ "data": "h'6869'", "offset": 0, "totalBytes": 183022, "retained": [ { "start": 0, "end": 16384 }, { "start": 120000, "end": 183022 } ] }),
        );
        assert_eq!(
            read.retained,
            [
                ByteRange {
                    start: 0,
                    end: 16384
                },
                ByteRange {
                    start: 120000,
                    end: 183022
                }
            ]
        );
    }

    #[test]
    fn files() {
        let stat: FsStat = round_trip(
            json!({ "kind": "file", "size": 1234, "modifiedMs": 1763496000000u64, "readonly": false }),
        );
        assert_eq!(stat.kind, FileKind::File);
        let list: FsListResult = round_trip(
            json!({ "entries": [ { "name": "src", "kind": "directory", "size": 4096 }, { "name": "l", "kind": "symlink", "size": 3 } ] }),
        );
        assert_eq!(list.entries[1].kind, FileKind::Symlink);
        let access = json!({ "mode": "raw" });
        let read: WithAccess<FsReadParams> =
            round_trip(json!({ "path": "/x", "access": access, "offset": 0, "length": 1048576 }));
        assert_eq!(read.params.length, Some(1048576));
        let read_defaults: FsReadParams = parse(json!({ "path": "/x" }));
        assert_eq!((read_defaults.offset, read_defaults.length), (0, None));
        let result: FsReadResult = round_trip(json!({ "data": "h'6869'", "size": 1234 }));
        assert_eq!(result.data.0, b"hi");
        for mode in ["create", "overwrite", "append"] {
            round_trip::<WithAccess<FsWriteParams>>(
                json!({ "path": "/x", "access": access, "data": "h''", "mode": mode }),
            );
        }
        let mkdir: WithAccess<FsMkdirParams> =
            round_trip(json!({ "path": "/x", "access": access, "recursive": false }));
        assert!(!mkdir.params.recursive);
        let remove: WithAccess<FsRemoveParams> =
            round_trip(json!({ "path": "/x", "access": access, "recursive": true }));
        assert!(remove.params.recursive);
        let rename: WithAccess<FsRenameParams> =
            round_trip(json!({ "from": "/x/a.txt", "to": "/x/b.txt", "access": access }));
        assert_eq!(
            (rename.params.from.as_str(), rename.params.to.as_str()),
            ("/x/a.txt", "/x/b.txt")
        );
        let stat_params: WithAccess<FsPathParams> =
            round_trip(json!({ "path": "/x", "access": access }));
        assert_eq!(stat_params.params.path.as_str(), "/x");
    }

    #[test]
    fn watching() {
        let start: WithAccess<WatchStartParams> = round_trip(
            json!({ "watchId": "w-1", "path": "/home/me/repo", "recursive": true, "access": { "mode": "sandboxed", "policy": policy_json() } }),
        );
        assert_eq!(start.params.watch_id.as_str(), "w-1");
        let stop: WatchStopParams = round_trip(json!({ "watchId": "w-1" }));
        assert_eq!(stop.watch_id.as_str(), "w-1");

        let changes: WatchEvent = round_trip(
            json!({ "watchId": "w-1", "changes": [ { "kind": "modified", "path": "/home/me/repo/src/main.rs" } ] }),
        );
        assert_eq!(
            changes.body,
            WatchEventBody::Changes {
                changes: vec![Change {
                    kind: ChangeKind::Modified,
                    path: "/home/me/repo/src/main.rs".to_string()
                }]
            }
        );
        let overflow: WatchEvent = round_trip(json!({ "watchId": "w-1", "overflow": true }));
        assert_eq!(overflow.body, WatchEventBody::Overflow { overflow: True });
        assert!(
            from_value::<WatchEvent>(cbor(json!({ "watchId": "w-1", "overflow": false }))).is_err()
        );
        for kind in ["created", "modified", "removed", "renamed"] {
            round_trip::<Change>(json!({ "kind": kind, "path": "/p" }));
        }
    }

    #[test]
    fn node_methods() {
        let both: NodeUpdate = round_trip(
            json!({ "nodeToken": "nt_2", "endpoint": "wss://edge-5.control.example.com/nodes/connect" }),
        );
        assert_eq!(both.node_token.as_deref(), Some("nt_2"));
        let token: NodeUpdate = round_trip(json!({ "nodeToken": "nt_3" }));
        assert_eq!(
            (token.node_token.as_deref(), token.endpoint),
            (Some("nt_3"), None)
        );
        assert!(
            rejects::<NodeUpdate>(json!({}))
                .contains("node.update needs nodeToken, endpoint or both")
        );
        assert_eq!(round_trip::<Empty>(json!({})), Empty {});
    }
}
