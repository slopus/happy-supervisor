//! Everything on the wire: docs/api.md and docs/node-info.md as serde types.
//!
//! Incoming values are parsed into these types at the dispatcher, so code past it can trust them:
//! IDs, argv and absolute paths are validated by their `TryFrom` impls, and policies by
//! [`Policy`]'s.

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::error::{Error, ErrorKind};
pub use crate::policy::Policy;

pub const MAX_FRAME_BYTES: usize = 32 << 20;
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
pub const MAX_CHANGES_PER_EVENT: usize = 256;
pub const EVENT_QUEUE_BYTES: usize = 16 << 20;

// ---------------------------------------------------------------------------------------------
// JSON-RPC envelope

/// The `"jsonrpc": "2.0"` member. Deserializes only from `"2.0"`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JsonRpcVersion;

impl Serialize for JsonRpcVersion {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str("2.0")
    }
}

impl<'de> Deserialize<'de> for JsonRpcVersion {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match String::deserialize(d)?.as_str() {
            "2.0" => Ok(JsonRpcVersion),
            other => Err(serde::de::Error::custom(format!(
                "unsupported jsonrpc version `{other}`"
            ))),
        }
    }
}

/// A request from the control plane. `params` stays raw until the dispatcher knows the method.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: JsonRpcVersion,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: JsonRpcVersion,
    pub id: Value,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Outcome {
    #[serde(rename = "result")]
    Result(Value),
    #[serde(rename = "error")]
    Error(RpcError),
}

impl Response {
    pub fn new(id: Value, result: crate::Result<Value>) -> Response {
        Response {
            jsonrpc: JsonRpcVersion,
            id,
            outcome: match result {
                Ok(value) => Outcome::Result(value),
                Err(err) => Outcome::Error(err.into()),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: RpcErrorData,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RpcErrorData {
    pub kind: ErrorKind,
}

impl From<Error> for RpcError {
    fn from(err: Error) -> RpcError {
        RpcError {
            code: err.kind.code(),
            message: err.message,
            data: RpcErrorData { kind: err.kind },
        }
    }
}

impl From<RpcError> for Error {
    fn from(err: RpcError) -> Error {
        Error::new(err.data.kind, err.message)
    }
}

/// An outgoing notification frame: `{"jsonrpc": "2.0", "method": …, "params": …}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NotificationFrame {
    pub jsonrpc: JsonRpcVersion,
    #[serde(flatten)]
    pub notification: Notification,
}

impl From<Notification> for NotificationFrame {
    fn from(notification: Notification) -> NotificationFrame {
        NotificationFrame {
            jsonrpc: JsonRpcVersion,
            notification,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum Notification {
    #[serde(rename = "node.hello")]
    Hello(Box<Hello>),
    #[serde(rename = "exec.output")]
    ExecOutput(ExecOutput),
    #[serde(rename = "exec.exit")]
    ExecExit(ExecExit),
    #[serde(rename = "exec.timedOut")]
    ExecTimedOut(ExecTimedOut),
    #[serde(rename = "watch.event")]
    WatchEvent(WatchEvent),
}

/// The request methods the node serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    NodeInfo,
    NodeRotateCredential,
    ExecStart,
    ExecWrite,
    ExecKill,
    ExecList,
    ExecLog,
    FsStat,
    FsList,
    FsRead,
    FsWrite,
    FsMkdir,
    FsRemove,
    WatchStart,
    WatchStop,
}

impl Method {
    pub const ALL: [Method; 15] = [
        Method::NodeInfo,
        Method::NodeRotateCredential,
        Method::ExecStart,
        Method::ExecWrite,
        Method::ExecKill,
        Method::ExecList,
        Method::ExecLog,
        Method::FsStat,
        Method::FsList,
        Method::FsRead,
        Method::FsWrite,
        Method::FsMkdir,
        Method::FsRemove,
        Method::WatchStart,
        Method::WatchStop,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Method::NodeInfo => "node.info",
            Method::NodeRotateCredential => "node.rotateCredential",
            Method::ExecStart => "exec.start",
            Method::ExecWrite => "exec.write",
            Method::ExecKill => "exec.kill",
            Method::ExecList => "exec.list",
            Method::ExecLog => "exec.log",
            Method::FsStat => "fs.stat",
            Method::FsList => "fs.list",
            Method::FsRead => "fs.read",
            Method::FsWrite => "fs.write",
            Method::FsMkdir => "fs.mkdir",
            Method::FsRemove => "fs.remove",
            Method::WatchStart => "watch.start",
            Method::WatchStop => "watch.stop",
        }
    }

    pub fn from_name(name: &str) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.as_str() == name)
    }
}

/// `{}` as params or result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

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

/// Bytes carried as standard padded base64 in `data` fields.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Base64Bytes(pub Vec<u8>);

impl std::fmt::Debug for Base64Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Base64Bytes({} bytes)", self.0.len())
    }
}

impl Serialize for Base64Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map(Base64Bytes)
            .map_err(|err| serde::de::Error::custom(format!("data is not base64: {err}")))
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
// Node methods

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateCredentialParams {
    pub node_token: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hello {
    pub node_id: String,
    pub installation_id: String,
    pub version: String,
    pub info: NodeInfo,
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    #[serde(deny_unknown_fields)]
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
    deny_unknown_fields,
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
    rename_all_fields = "camelCase",
    deny_unknown_fields
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
    pub ignored_paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecWriteParams {
    pub exec_id: ExecId,
    pub data: Base64Bytes,
    #[serde(default)]
    pub eof: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KillSignal {
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
    pub data: Base64Bytes,
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
    pub data: Base64Bytes,
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
    pub data: Base64Bytes,
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
    pub data: Base64Bytes,
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
    pub default_env: BTreeMap<String, String>,
    pub collected_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OsInfo {
    pub family: OsFamily,
    pub name: Option<String>,
    pub version: Option<String>,
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
    pub model: Option<String>,
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
    pub memory_bytes: Option<u64>,
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
/// availability and the Landlock ABI are sum types, so "available with a reason" or "seatbelt
/// with a Landlock ABI" cannot be built.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "SandboxInfoWire", try_from = "SandboxInfoWire")]
pub struct SandboxInfo {
    pub mechanism: Mechanism,
    pub status: SandboxStatus,
    pub baseline_read: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    Landlock { abi: Option<u32> },
    Seatbelt,
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SandboxInfoWire {
    mechanism: MechanismName,
    available: bool,
    reason: Option<String>,
    landlock_abi: Option<u32>,
    baseline_read: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum MechanismName {
    Landlock,
    Seatbelt,
    None,
}

impl From<SandboxInfo> for SandboxInfoWire {
    fn from(info: SandboxInfo) -> SandboxInfoWire {
        let (mechanism, landlock_abi) = match info.mechanism {
            Mechanism::Landlock { abi } => (MechanismName::Landlock, abi),
            Mechanism::Seatbelt => (MechanismName::Seatbelt, None),
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
            landlock_abi,
            baseline_read: info.baseline_read,
        }
    }
}

impl TryFrom<SandboxInfoWire> for SandboxInfo {
    type Error = Error;

    fn try_from(wire: SandboxInfoWire) -> Result<SandboxInfo, Error> {
        let mechanism = match (wire.mechanism, wire.landlock_abi) {
            (MechanismName::Landlock, abi) => Mechanism::Landlock { abi },
            (MechanismName::Seatbelt, None) => Mechanism::Seatbelt,
            (MechanismName::None, None) => Mechanism::None,
            (_, Some(_)) => {
                return Err(Error::invalid_params(
                    "landlockAbi is set for a non-landlock mechanism",
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
        })
    }
}

// The examples use Unix paths, which are not absolute on Windows.
#[cfg(all(test, unix))]
mod tests {
    use serde::de::DeserializeOwned;
    use serde_json::json;

    use super::*;

    /// Parses `json` as `T`, checks it serializes back to the same JSON, and returns it.
    fn round_trip<T: Serialize + DeserializeOwned>(json: Value) -> T {
        let parsed: T = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), json);
        parsed
    }

    fn rejects<T: DeserializeOwned + std::fmt::Debug>(json: Value) -> String {
        serde_json::from_value::<T>(json).unwrap_err().to_string()
    }

    fn policy_json() -> Value {
        json!({ "read": ["/usr", "/home/me/repo"], "write": ["/home/me/repo"], "localBind": false, "unixSockets": false })
    }

    fn node_info_json() -> Value {
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
            "mechanism": "landlock",
            "available": true,
            "reason": null,
            "landlockAbi": 6,
            "baselineRead": ["/usr", "/bin", "/lib", "/lib64", "/etc"]
          },
          "defaultEnv": { "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/me", "USER": "me", "LANG": "C.UTF-8" },
          "collectedAtMs": 1763496000000u64
        })
    }

    #[test]
    fn api_md_methods_are_all_modeled() {
        let doc = include_str!("../docs/api.md");
        let notifications = [
            "node.hello",
            "exec.output",
            "exec.exit",
            "exec.timedOut",
            "watch.event",
        ];
        let mut methods = Vec::new();
        for line in doc.lines() {
            let Some(name) = line.strip_prefix("### `").and_then(|l| l.split('`').next()) else {
                continue;
            };
            if line.ends_with("(notification)") {
                assert!(
                    notifications.contains(&name),
                    "notification {name} is not modeled"
                );
            } else {
                methods.push(
                    Method::from_name(name).unwrap_or_else(|| panic!("{name} is not a Method")),
                );
            }
        }
        assert_eq!(methods, Method::ALL);
    }

    #[test]
    fn envelope() {
        let request: Request = round_trip(
            json!({ "jsonrpc": "2.0", "id": 7, "method": "fs.read", "params": { "path": "/x" } }),
        );
        assert_eq!((request.id, request.method.as_str()), (json!(7), "fs.read"));
        let no_params: Request =
            serde_json::from_value(json!({ "jsonrpc": "2.0", "id": "a", "method": "exec.list" }))
                .unwrap();
        assert_eq!(no_params.params, Value::Null);
        assert!(
            rejects::<Request>(json!({ "jsonrpc": "1.0", "id": 1, "method": "x" }))
                .contains("unsupported jsonrpc version `1.0`")
        );

        let ok = Response::new(json!(7), Ok(json!({ "size": 1 })));
        assert_eq!(
            serde_json::to_value(&ok).unwrap(),
            json!({ "jsonrpc": "2.0", "id": 7, "result": { "size": 1 } })
        );
        let err = Response::new(json!(7), Err(Error::new(ErrorKind::PermissionDenied, "…")));
        let err_json = json!({ "jsonrpc": "2.0", "id": 7, "error": { "code": -32003, "message": "…", "data": { "kind": "permission_denied" } } });
        assert_eq!(serde_json::to_value(&err).unwrap(), err_json);
        assert_eq!(round_trip::<Response>(err_json), err);

        let frame: NotificationFrame = round_trip(
            json!({ "jsonrpc": "2.0", "method": "exec.output", "params": { "execId": "build-1", "stream": "stdout", "data": "aGk=", "droppedBytes": 0 } }),
        );
        assert_eq!(
            frame.notification,
            Notification::ExecOutput(ExecOutput {
                exec_id: ExecId::try_from("build-1").unwrap(),
                stream: Stream::Stdout,
                data: Base64Bytes(b"hi".to_vec()),
                dropped_bytes: 0,
            })
        );
    }

    #[test]
    fn hello_and_node_info() {
        let info: NodeInfo = round_trip(node_info_json());
        assert_eq!(info.sandbox.mechanism, Mechanism::Landlock { abi: Some(6) });
        assert_eq!(info.sandbox.require_available(), Ok(()));
        assert_eq!(info.os.arch, Arch::X86_64);
        assert_eq!(info.gpus[0].vendor, GpuVendor::Nvidia);

        let hello = json!({ "jsonrpc": "2.0", "method": "node.hello", "params": {
            "nodeId": "n_1",
            "installationId": "tz4a98xxat96iws9zmbrgj3a",
            "version": "0.1.0",
            "info": node_info_json(),
            "execs": [ { "execId": "build-1", "state": "running" } ],
            "watches": [ "w-1" ]
        }});
        let NotificationFrame {
            notification: Notification::Hello(hello),
            ..
        } = round_trip(hello)
        else {
            panic!("not a hello");
        };
        assert_eq!(
            hello.execs,
            [ExecSummary {
                exec_id: ExecId::try_from("build-1").unwrap(),
                state: ExecState::Running
            }]
        );
        assert_eq!(hello.watches, [WatchId::try_from("w-1").unwrap()]);
    }

    #[test]
    fn sandbox_info_shapes() {
        let mac: SandboxInfo = round_trip(
            json!({ "mechanism": "seatbelt", "available": false, "reason": "sandbox-exec is missing", "landlockAbi": null, "baselineRead": [] }),
        );
        assert_eq!(
            mac.require_available(),
            Err(Error::sandbox_unavailable("sandbox-exec is missing"))
        );
        let windows: SandboxInfo = round_trip(
            json!({ "mechanism": "none", "available": false, "reason": "Windows has no sandbox backend", "landlockAbi": null, "baselineRead": [] }),
        );
        assert_eq!(windows.mechanism, Mechanism::None);
        assert!(rejects::<SandboxInfo>(json!({ "mechanism": "seatbelt", "available": true, "reason": null, "landlockAbi": 3, "baselineRead": [] })).contains("landlockAbi is set for a non-landlock mechanism"));
        assert!(rejects::<SandboxInfo>(json!({ "mechanism": "landlock", "available": true, "reason": "x", "landlockAbi": 3, "baselineRead": [] })).contains("an available sandbox has a reason"));
        assert!(rejects::<SandboxInfo>(json!({ "mechanism": "landlock", "available": false, "reason": null, "landlockAbi": null, "baselineRead": [] })).contains("an unavailable sandbox has no reason"));
        assert!(rejects::<SandboxInfo>(json!({ "mechanism": "none", "available": true, "reason": null, "landlockAbi": null, "baselineRead": [] })).contains("mechanism none cannot be available"));
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
        assert_eq!(policy.write(), ["/home/me/repo"]);
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
          "access": { "mode": "sandboxed", "policy": policy_json() }
        });
        let start: WithAccess<ExecStartParams> = round_trip(params);
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
            serde_json::from_value(json!({ "execId": "a", "argv": ["sh"], "cwd": "/", "env": {} }))
                .unwrap();
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

        let result: ExecStartResult = round_trip(
            json!({ "execId": "build-1", "pid": 4242, "ignoredPaths": ["/home/me/.cache/nonexistent"] }),
        );
        assert_eq!(result.pid, 4242);
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
        assert!(
            rejects::<LogSpec>(json!({ "kind": "memory", "path": "/x" }))
                .contains("unknown field `path`")
        );
    }

    #[test]
    fn exec_methods_and_notifications() {
        let write: ExecWriteParams =
            round_trip(json!({ "execId": "e", "data": "AAEC", "eof": false }));
        assert_eq!(write.data, Base64Bytes(vec![0, 1, 2]));
        let empty: ExecWriteParams = round_trip(json!({ "execId": "e", "data": "", "eof": true }));
        assert_eq!(empty.data.0, b"");
        assert!(
            rejects::<ExecWriteParams>(json!({ "execId": "e", "data": "A" }))
                .contains("data is not base64")
        );
        assert!(
            rejects::<ExecWriteParams>(json!({ "execId": "e", "data": "AAE" }))
                .contains("data is not base64")
        );

        let kill: ExecKillParams = round_trip(json!({ "execId": "e", "signal": "terminate" }));
        assert_eq!(kill.signal, KillSignal::Terminate);

        let list: ExecListResult = round_trip(json!({ "execs": [
            { "execId": "a", "state": "running" },
            { "execId": "b", "state": "exited", "exit": { "kind": "exited", "code": 0 } },
            { "execId": "c", "state": "exited", "exit": { "kind": "signaled", "signal": 9 } },
            { "execId": "d", "state": "exited", "exit": { "kind": "timedOut" } }
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

        let exit: NotificationFrame = round_trip(
            json!({ "jsonrpc": "2.0", "method": "exec.exit", "params": { "execId": "build-1", "exit": { "kind": "exited", "code": 0 }, "logBytes": 183022 } }),
        );
        assert_eq!(
            exit.notification,
            Notification::ExecExit(ExecExit {
                exec_id: ExecId::try_from("build-1").unwrap(),
                exit: ExitStatus::Exited { code: 0 },
                log_bytes: 183022
            })
        );
        let timed_out: NotificationFrame = round_trip(
            json!({ "jsonrpc": "2.0", "method": "exec.timedOut", "params": { "execId": "build-1", "action": "background", "logBytes": 183022 } }),
        );
        assert_eq!(
            timed_out.notification,
            Notification::ExecTimedOut(ExecTimedOut {
                exec_id: ExecId::try_from("build-1").unwrap(),
                action: TimeoutAction::Background,
                log_bytes: 183022
            })
        );

        let log: ExecLogParams =
            round_trip(json!({ "execId": "build-1", "offset": 0, "length": 65536 }));
        assert_eq!(log.length, Some(65536));
        let defaults: ExecLogParams =
            serde_json::from_value(json!({ "execId": "build-1" })).unwrap();
        assert_eq!((defaults.offset, defaults.length), (0, None));
        let read: ExecLogResult = round_trip(
            json!({ "data": "aGk=", "offset": 0, "totalBytes": 183022, "retained": [ { "start": 0, "end": 16384 }, { "start": 120000, "end": 183022 } ] }),
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
        let read_defaults: FsReadParams = serde_json::from_value(json!({ "path": "/x" })).unwrap();
        assert_eq!((read_defaults.offset, read_defaults.length), (0, None));
        let result: FsReadResult = round_trip(json!({ "data": "aGk=", "size": 1234 }));
        assert_eq!(result.data.0, b"hi");
        for mode in ["create", "overwrite", "append"] {
            round_trip::<WithAccess<FsWriteParams>>(
                json!({ "path": "/x", "access": access, "data": "", "mode": mode }),
            );
        }
        let mkdir: WithAccess<FsMkdirParams> =
            round_trip(json!({ "path": "/x", "access": access, "recursive": false }));
        assert!(!mkdir.params.recursive);
        let remove: WithAccess<FsRemoveParams> =
            round_trip(json!({ "path": "/x", "access": access, "recursive": true }));
        assert!(remove.params.recursive);
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
            serde_json::from_value::<WatchEvent>(json!({ "watchId": "w-1", "overflow": false }))
                .is_err()
        );
        for kind in ["created", "modified", "removed", "renamed"] {
            round_trip::<Change>(json!({ "kind": kind, "path": "/p" }));
        }
    }

    #[test]
    fn node_methods() {
        let rotate: RotateCredentialParams = round_trip(json!({ "nodeToken": "nt_2" }));
        assert_eq!(rotate.node_token, "nt_2");
        assert_eq!(round_trip::<Empty>(json!({})), Empty {});
    }
}
