//! How frames become WebSocket payloads (api.md, Encoding and Compression): CBOR, and the
//! optional per-frame raw DEFLATE selected by the WebSocket subprotocol.

use std::borrow::Cow;
use std::io::{Read as _, Write as _};

use serde::Serialize;
use serde::de::DeserializeOwned;

pub use ciborium::Value;

use crate::protocol::MAX_FRAME_BYTES;

pub const SUBPROTOCOL_DEFLATE: &str = "happy-supervisor.v1.deflate";
pub const SUBPROTOCOL_PLAIN: &str = "happy-supervisor.v1";

/// Frames shorter than this are never compressed.
pub const COMPRESS_MIN_BYTES: usize = 256;

const UNCOMPRESSED: u8 = 0x00;
const DEFLATED: u8 = 0x01;

/// The negotiated payload format of one connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    /// `happy-supervisor.v1`: the payload is the CBOR frame.
    Plain,
    /// `happy-supervisor.v1.deflate`: a 1-byte prefix, then CBOR or raw DEFLATE of it.
    Deflate,
}

impl Wire {
    /// The subprotocols the node offers, in its order of preference.
    pub const OFFERED: [&str; 2] = [SUBPROTOCOL_DEFLATE, SUBPROTOCOL_PLAIN];

    pub fn subprotocol(self) -> &'static str {
        match self {
            Wire::Plain => SUBPROTOCOL_PLAIN,
            Wire::Deflate => SUBPROTOCOL_DEFLATE,
        }
    }

    pub fn from_subprotocol(name: &str) -> Option<Wire> {
        match name {
            SUBPROTOCOL_PLAIN => Some(Wire::Plain),
            SUBPROTOCOL_DEFLATE => Some(Wire::Deflate),
            _ => None,
        }
    }

    /// The payload carrying the CBOR frame `cbor`.
    pub fn encode(self, cbor: &[u8]) -> Vec<u8> {
        match self {
            Wire::Plain => cbor.to_vec(),
            Wire::Deflate => {
                if cbor.len() >= COMPRESS_MIN_BYTES {
                    let compressed = deflate(cbor);
                    if compressed.len() < cbor.len() {
                        return [&[DEFLATED][..], &compressed].concat();
                    }
                }
                [&[UNCOMPRESSED][..], cbor].concat()
            }
        }
    }

    /// The CBOR frame inside `payload`. Fails on a malformed payload, or one larger than the
    /// frame limit before or after inflating.
    pub fn decode(self, payload: &[u8]) -> Result<Cow<'_, [u8]>, String> {
        if payload.len() > MAX_FRAME_BYTES + 1 {
            return Err(format!(
                "frame of {} bytes is over the limit",
                payload.len()
            ));
        }
        match self {
            Wire::Plain => Ok(Cow::Borrowed(payload)),
            Wire::Deflate => match payload.split_first() {
                Some((&UNCOMPRESSED, cbor)) => Ok(Cow::Borrowed(cbor)),
                Some((&DEFLATED, compressed)) => inflate(compressed).map(Cow::Owned),
                Some((prefix, _)) => Err(format!("unknown frame prefix 0x{prefix:02x}")),
                None => Err("empty frame".to_string()),
            },
        }
    }
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data)
        .expect("writing to a Vec cannot fail");
    encoder.finish().expect("writing to a Vec cannot fail")
}

/// What a registry entry names (api.md, Encoding).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// A map key, anywhere.
    Key,
    /// A frame's `t` value.
    Frame,
    /// A `msg` frame's `kind` value.
    Kind,
}

/// The append-only registry of compact names (api.md, Encoding): on the wire each of these
/// names is the CBOR unsigned integer beside it. Never renumber or reuse an entry; a new name
/// gets the next number. 0 to 23 encode in one byte and go to the most frequent names.
pub const REGISTRY: &[(u64, &str, Role)] = &[
    (0, "t", Role::Key),
    (1, "id", Role::Key),
    (2, "kind", Role::Key),
    (3, "body", Role::Key),
    (4, "cursor", Role::Key),
    (5, "msg", Role::Frame),
    (6, "ack", Role::Frame),
    (7, "exec.output", Role::Kind),
    (8, "reply", Role::Kind),
    (9, "execId", Role::Key),
    (10, "stream", Role::Key),
    (11, "data", Role::Key),
    (12, "droppedBytes", Role::Key),
    (13, "to", Role::Key),
    (14, "ok", Role::Key),
    (15, "error", Role::Key),
    (16, "exec.exit", Role::Kind),
    (17, "exit", Role::Key),
    (18, "logBytes", Role::Key),
    (19, "code", Role::Key),
    (20, "watch.event", Role::Kind),
    (21, "watchId", Role::Key),
    (22, "changes", Role::Key),
    (23, "path", Role::Key),
    (24, "hello", Role::Frame),
    (25, "welcome", Role::Frame),
    (26, "bye", Role::Frame),
    (27, "proxy.body", Role::Kind),
    (28, "proxy.credit", Role::Kind),
    (29, "proxy.request", Role::Kind),
    (30, "proxy.response", Role::Kind),
    (31, "proxy.end", Role::Kind),
    (32, "proxy.reset", Role::Kind),
    (33, "node.ready", Role::Kind),
    (34, "exec.timedOut", Role::Kind),
    (35, "node.info", Role::Kind),
    (36, "node.update", Role::Kind),
    (37, "exec.start", Role::Kind),
    (38, "exec.write", Role::Kind),
    (39, "exec.kill", Role::Kind),
    (40, "exec.list", Role::Kind),
    (41, "exec.log", Role::Kind),
    (42, "fs.stat", Role::Kind),
    (43, "fs.list", Role::Kind),
    (44, "fs.read", Role::Kind),
    (45, "fs.write", Role::Kind),
    (46, "fs.mkdir", Role::Kind),
    (47, "fs.remove", Role::Kind),
    (48, "watch.start", Role::Kind),
    (49, "watch.stop", Role::Kind),
    (50, "streamId", Role::Key),
    (51, "bytes", Role::Key),
    (52, "message", Role::Key),
    (53, "session", Role::Key),
    (54, "resumed", Role::Key),
    (55, "resumeWindowMs", Role::Key),
    (56, "nodeId", Role::Key),
    (57, "installationId", Role::Key),
    (58, "version", Role::Key),
    (59, "reason", Role::Key),
    (60, "previousSession", Role::Key),
    (61, "signal", Role::Key),
    (62, "overflow", Role::Key),
    (63, "headers", Role::Key),
    (64, "status", Role::Key),
    (65, "method", Role::Key),
    (66, "scheme", Role::Key),
    (67, "host", Role::Key),
    (68, "port", Role::Key),
    (69, "token", Role::Key),
    (70, "hosts", Role::Key),
    (71, "proxy", Role::Key),
    (72, "argv", Role::Key),
    (73, "cwd", Role::Key),
    (74, "env", Role::Key),
    (75, "stdin", Role::Key),
    (76, "timeout", Role::Key),
    (77, "ms", Role::Key),
    (78, "action", Role::Key),
    (79, "log", Role::Key),
    (80, "limitBytes", Role::Key),
    (81, "access", Role::Key),
    (82, "mode", Role::Key),
    (83, "policy", Role::Key),
    (84, "read", Role::Key),
    (85, "write", Role::Key),
    (86, "localBind", Role::Key),
    (87, "unixSockets", Role::Key),
    (88, "eof", Role::Key),
    (89, "pid", Role::Key),
    (90, "ignoredPaths", Role::Key),
    (91, "execs", Role::Key),
    (92, "state", Role::Key),
    (93, "offset", Role::Key),
    (94, "length", Role::Key),
    (95, "totalBytes", Role::Key),
    (96, "retained", Role::Key),
    (97, "start", Role::Key),
    (98, "end", Role::Key),
    (99, "entries", Role::Key),
    (100, "name", Role::Key),
    (101, "size", Role::Key),
    (102, "modifiedMs", Role::Key),
    (103, "readonly", Role::Key),
    (104, "recursive", Role::Key),
    (105, "nodeToken", Role::Key),
    (106, "endpoint", Role::Key),
    (107, "info", Role::Key),
    (108, "watches", Role::Key),
    (109, "hostname", Role::Key),
    (110, "supervisorVersion", Role::Key),
    (111, "os", Role::Key),
    (112, "family", Role::Key),
    (113, "kernelVersion", Role::Key),
    (114, "arch", Role::Key),
    (115, "cpu", Role::Key),
    (116, "model", Role::Key),
    (117, "logicalCores", Role::Key),
    (118, "physicalCores", Role::Key),
    (119, "memory", Role::Key),
    (120, "swapTotalBytes", Role::Key),
    (121, "disks", Role::Key),
    (122, "mountPoint", Role::Key),
    (123, "fileSystem", Role::Key),
    (124, "availableBytes", Role::Key),
    (125, "removable", Role::Key),
    (126, "gpus", Role::Key),
    (127, "vendor", Role::Key),
    (128, "memoryBytes", Role::Key),
    (129, "driverVersion", Role::Key),
    (130, "sandbox", Role::Key),
    (131, "mechanism", Role::Key),
    (132, "available", Role::Key),
    (133, "landlockAbi", Role::Key),
    (134, "baselineRead", Role::Key),
    (135, "gaps", Role::Key),
    (136, "defaultEnv", Role::Key),
    (137, "collectedAtMs", Role::Key),
    (138, "joinToken", Role::Key),
];

struct Names {
    by_name: std::collections::HashMap<(&'static str, Role), u64>,
    by_number: std::collections::HashMap<u64, (&'static str, Role)>,
}

fn names() -> &'static Names {
    static NAMES: std::sync::OnceLock<Names> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| Names {
        by_name: REGISTRY
            .iter()
            .map(|&(n, name, role)| ((name, role), n))
            .collect(),
        by_number: REGISTRY
            .iter()
            .map(|&(n, name, role)| (n, (name, role)))
            .collect(),
    })
}

/// A text value of `role` as its registry number, when it has one.
fn compact_name(value: Value, role: Role) -> Value {
    match value {
        Value::Text(name) => match names().by_name.get(&(name.as_str(), role)) {
            Some(&n) => Value::Integer(n.into()),
            None => Value::Text(name),
        },
        other => other,
    }
}

/// A registry number of `role` back as its text. Text passes through.
fn expand_name(value: Value, role: Role) -> Result<Value, String> {
    let Value::Integer(n) = value else {
        return Ok(value);
    };
    let what = match role {
        Role::Key => "key",
        Role::Frame => "frame type",
        Role::Kind => "message kind",
    };
    let number = u64::try_from(n).map_err(|_| format!("unknown {what} {}", i128::from(n)))?;
    match names().by_number.get(&number) {
        Some(&(name, r)) if r == role => Ok(Value::Text(name.to_string())),
        _ => Err(format!("unknown {what} {number}")),
    }
}

fn is_text(value: &Value, text: &str) -> bool {
    value.as_text() == Some(text)
}

/// Replaces registered map keys by their numbers, and a frame's `t` and a `msg` frame's `kind`.
fn compact(value: Value) -> Value {
    match value {
        Value::Map(entries) => {
            let t = entries
                .iter()
                .find(|(k, _)| is_text(k, "t"))
                .and_then(|(_, v)| v.as_text().map(str::to_owned));
            let entries = entries
                .into_iter()
                .map(|(key, value)| {
                    let value = match key.as_text() {
                        Some("t") if t.is_some() => compact_name(value, Role::Frame),
                        Some("kind") if t.as_deref() == Some("msg") => {
                            compact_name(value, Role::Kind)
                        }
                        _ => compact(value),
                    };
                    (compact_name(key, Role::Key), value)
                })
                .collect();
            Value::Map(entries)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(compact).collect()),
        Value::Tag(tag, inner) => Value::Tag(tag, Box::new(compact(*inner))),
        other => other,
    }
}

/// The inverse of [`compact`]. A number the registry lacks is an error; text passes through.
fn expand(value: Value) -> Result<Value, String> {
    match value {
        Value::Map(entries) => {
            let mut expanded = Vec::with_capacity(entries.len());
            let mut kind = None;
            let mut is_msg = false;
            for (key, value) in entries {
                let key = expand_name(key, Role::Key)?;
                match key.as_text() {
                    Some("t") => {
                        let t = expand_name(value, Role::Frame)?;
                        is_msg = is_text(&t, "msg");
                        expanded.push((key, t));
                    }
                    Some("kind") => {
                        kind = Some(expanded.len());
                        expanded.push((key, value));
                    }
                    _ => expanded.push((key, expand(value)?)),
                }
            }
            if let Some(at) = kind {
                let value = std::mem::replace(&mut expanded[at].1, Value::Null);
                expanded[at].1 = if is_msg {
                    expand_name(value, Role::Kind)?
                } else {
                    expand(value)?
                };
            }
            Ok(Value::Map(expanded))
        }
        Value::Array(items) => items
            .into_iter()
            .map(expand)
            .collect::<Result<_, _>>()
            .map(Value::Array),
        Value::Tag(tag, inner) => Ok(Value::Tag(tag, Box::new(expand(*inner)?))),
        other => Ok(other),
    }
}

fn write(item: &(impl Serialize + ?Sized), out: &mut Vec<u8>) {
    ciborium::into_writer(item, out).expect("CBOR writes to a Vec");
}

/// The encoded start of a `msg` frame up to its `body` value: `t`, `id`, `kind` and the `body`
/// key, compacted as [`to_cbor`] would. CBOR items concatenate, so appending a body encoded by
/// [`to_cbor`] completes the frame without converting the body again.
pub fn msg_prefix(id: &crate::protocol::MsgId, kind: &str) -> Vec<u8> {
    let name = |text: &str, role| compact_name(Value::Text(text.to_string()), role);
    let mut out = vec![0xa4];
    write(&name("t", Role::Key), &mut out);
    write(&name("msg", Role::Frame), &mut out);
    write(&name("id", Role::Key), &mut out);
    write(id, &mut out);
    write(&name("kind", Role::Key), &mut out);
    write(&name(kind, Role::Kind), &mut out);
    write(&name("body", Role::Key), &mut out);
    out
}

/// Inflates at most one byte past the limit, so a small bomb cannot allocate more.
fn inflate(compressed: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(compressed)
        .take(MAX_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|err| format!("bad deflate data: {err}"))?;
    if out.len() > MAX_FRAME_BYTES {
        return Err(format!("frame inflates past {MAX_FRAME_BYTES} bytes"));
    }
    Ok(out)
}

/// Encodes a value as compact CBOR: registered names become their numbers ([`REGISTRY`]).
/// Every wire type serializes, so this cannot fail.
pub fn to_cbor<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    write(&compact(to_value(value)), &mut out);
    out
}

/// Decodes compact CBOR, turning registered numbers back into names first.
pub fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    let value: Value = ciborium::from_reader(bytes).map_err(|err| match err {
        ciborium::de::Error::Semantic(_, message) => message,
        ciborium::de::Error::Syntax(offset) => format!("bad CBOR at byte {offset}"),
        ciborium::de::Error::Io(_) => "the CBOR ends early".to_string(),
        ciborium::de::Error::RecursionLimitExceeded => "the CBOR nests too deep".to_string(),
    })?;
    from_value(expand(value)?)
}

/// A typed value as a dynamic CBOR value, for message bodies and results.
pub fn to_value<T: Serialize + ?Sized>(value: &T) -> Value {
    Value::serialized(value).expect("wire types serialize to CBOR")
}

pub fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, String> {
    value.deserialized().map_err(|err| match err {
        ciborium::value::Error::Custom(message) => message,
    })
}

/// The text map keys left in compact CBOR, outside free-form maps (`env`, `defaultEnv`): field
/// names missing from the registry.
#[cfg(test)]
pub(crate) fn text_keys(bytes: &[u8]) -> Vec<String> {
    fn walk(value: &Value, free_form: bool, out: &mut Vec<String>) {
        match value {
            Value::Map(entries) => {
                for (key, value) in entries {
                    let name = match key {
                        Value::Text(text) => {
                            if !free_form {
                                out.push(text.clone());
                            }
                            text.clone()
                        }
                        other => match expand_name(other.clone(), Role::Key) {
                            Ok(Value::Text(text)) => text,
                            _ => String::new(),
                        },
                    };
                    walk(value, matches!(name.as_str(), "env" | "defaultEnv"), out);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| walk(item, false, out)),
            _ => {}
        }
    }
    let value: Value = ciborium::from_reader(bytes).expect("CBOR");
    let mut out = Vec::new();
    walk(&value, false, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Ack, Bytes, ExecId, ExecOutput, Frame, Msg, MsgId, Stream};

    #[test]
    fn an_ack_frame_is_these_cbor_bytes() {
        let cursor = uuid::Uuid::parse_str("0193a3b4-7c2e-7aa1-9f00-3c1d2e4f5a6b").unwrap();
        let frame = Frame::Ack(Ack {
            cursor: MsgId(cursor),
        });
        let bytes = to_cbor(&frame);
        let expected: Vec<u8> = [
            // {0 (t): 6 (ack), 4 (cursor): 16 bytes}
            &[0xa2, 0x00, 0x06, 0x04, 0x50][..],
            &[0x01, 0x93, 0xa3, 0xb4, 0x7c, 0x2e, 0x7a, 0xa1],
            &[0x9f, 0x00, 0x3c, 0x1d, 0x2e, 0x4f, 0x5a, 0x6b],
        ]
        .concat();
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 21);
        assert_eq!(from_cbor::<Frame>(&expected).unwrap(), frame);
    }

    /// The hot frame: 16 bytes of output. Was 115 bytes with text keys and kinds.
    #[test]
    fn a_small_exec_output_frame_is_these_cbor_bytes() {
        let id = MsgId(uuid::Uuid::parse_str("0193a3b4-7c2e-7aa1-9f00-3c1d2e4f5a6b").unwrap());
        let output = ExecOutput {
            exec_id: ExecId::try_from("build-1").unwrap(),
            stream: Stream::Stdout,
            data: Bytes(b"0123456789abcdef".to_vec()),
            dropped_bytes: 0,
        };
        let bytes = [msg_prefix(&id, "exec.output"), to_cbor(&output)].concat();
        let expected: Vec<u8> = [
            // {0 (t): 5 (msg), 1 (id): 16 bytes, 2 (kind): 7 (exec.output), 3 (body): …}
            &[0xa4, 0x00, 0x05, 0x01, 0x50][..],
            &[0x01, 0x93, 0xa3, 0xb4, 0x7c, 0x2e, 0x7a, 0xa1],
            &[0x9f, 0x00, 0x3c, 0x1d, 0x2e, 0x4f, 0x5a, 0x6b],
            &[0x02, 0x07, 0x03],
            // {9 (execId): "build-1", 10 (stream): "stdout", 11 (data): 16 bytes, 12: 0}
            &[0xa4, 0x09, 0x67],
            b"build-1",
            &[0x0a, 0x66],
            b"stdout",
            &[0x0b, 0x50],
            b"0123456789abcdef",
            &[0x0c, 0x00],
        ]
        .concat();
        assert_eq!(bytes, expected);
        assert!(bytes.len() <= 64, "{} bytes", bytes.len());
        let frame: Frame = from_cbor(&bytes).unwrap();
        let Frame::Msg(msg) = frame else {
            panic!("{frame:?}")
        };
        assert_eq!((msg.id, msg.kind.as_str()), (id, "exec.output"));
        assert_eq!(from_value::<ExecOutput>(msg.body).unwrap(), output);
        let whole = Frame::Msg(Msg {
            id,
            kind: "exec.output".to_string(),
            body: to_value(&output),
        });
        assert_eq!(to_cbor(&whole), expected);
    }

    #[test]
    fn unregistered_text_passes_and_unknown_numbers_are_refused() {
        let future = Value::Map(vec![
            (Value::Text("t".into()), Value::Text("msg".into())),
            (
                Value::Text("kind".into()),
                Value::Text("exec.future".into()),
            ),
            (Value::Text("futureField".into()), Value::Integer(1.into())),
        ]);
        let bytes = to_cbor(&future);
        assert_eq!(&bytes[..3], &[0xa3, 0x00, 0x05]);
        assert_eq!(from_cbor::<Value>(&bytes).unwrap(), future);

        let refused = |entries: Vec<(Value, Value)>| {
            let mut bytes = Vec::new();
            ciborium::into_writer(&Value::Map(entries), &mut bytes).unwrap();
            from_cbor::<Value>(&bytes).unwrap_err()
        };
        let int = |n: u64| Value::Integer(n.into());
        assert_eq!(refused(vec![(int(9999), int(1))]), "unknown key 9999");
        assert_eq!(refused(vec![(int(5), int(1))]), "unknown key 5");
        assert_eq!(refused(vec![(int(0), int(7))]), "unknown frame type 7");
        assert_eq!(
            refused(vec![(int(0), int(5)), (int(2), int(9999))]),
            "unknown message kind 9999"
        );
        // A body's own `kind` is a value like any other.
        let change = Value::Map(vec![(
            Value::Text("kind".into()),
            Value::Text("reply".into()),
        )]);
        assert_eq!(
            to_cbor(&change),
            [0xa1, 0x02, 0x65, b'r', b'e', b'p', b'l', b'y']
        );
    }

    #[test]
    fn the_registry_is_unique_dense_and_matches_api_md() {
        let numbers: Vec<u64> = REGISTRY.iter().map(|e| e.0).collect();
        assert_eq!(numbers, (0..REGISTRY.len() as u64).collect::<Vec<_>>());
        let mut seen = std::collections::HashSet::new();
        for (_, name, _) in REGISTRY {
            assert!(seen.insert(*name), "{name} is registered twice");
        }
        let doc = include_str!("../docs/api.md");
        let rows: Vec<String> = doc
            .lines()
            .filter(|l| {
                l.starts_with("| ") && l.contains(" | `") && l[2..].starts_with(char::is_numeric)
            })
            .map(str::to_string)
            .collect();
        let expected: Vec<String> = REGISTRY
            .iter()
            .map(|(n, name, role)| {
                let role = match role {
                    Role::Key => "key",
                    Role::Frame => "frame",
                    Role::Kind => "kind",
                };
                format!("| {n} | `{name}` | {role} |")
            })
            .collect();
        assert_eq!(rows, expected);
    }

    #[test]
    fn plain_payloads_are_the_frame() {
        assert_eq!(Wire::Plain.encode(&[0xa0]), [0xa0]);
        assert_eq!(Wire::Plain.decode(&[0xa0]).unwrap().as_ref(), [0xa0]);
    }

    #[test]
    fn deflate_compresses_large_frames_only_when_smaller() {
        let small = vec![b'a'; COMPRESS_MIN_BYTES - 1];
        assert_eq!(Wire::Deflate.encode(&small), [&[0x00][..], &small].concat());

        let large: Vec<u8> = b"exec.output stdout chunk ".repeat(100);
        let payload = Wire::Deflate.encode(&large);
        assert_eq!(payload[0], 0x01);
        assert!(payload.len() < large.len() / 10, "{} bytes", payload.len());
        assert_eq!(Wire::Deflate.decode(&payload).unwrap().as_ref(), large);

        let incompressible: Vec<u8> = (0..300u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let payload = Wire::Deflate.encode(&incompressible);
        assert_eq!(payload, [&[0x00][..], &incompressible].concat());
        assert_eq!(
            Wire::Deflate.decode(&payload).unwrap().as_ref(),
            incompressible
        );
    }

    #[test]
    fn bad_deflate_payloads_are_rejected() {
        let bomb = [&[0x01][..], &deflate(&vec![0; MAX_FRAME_BYTES + 1])].concat();
        assert!(bomb.len() < 64 << 10);
        assert_eq!(
            Wire::Deflate.decode(&bomb),
            Err(format!("frame inflates past {MAX_FRAME_BYTES} bytes"))
        );
        let exact = [&[0x01][..], &deflate(&vec![0; MAX_FRAME_BYTES])].concat();
        assert_eq!(Wire::Deflate.decode(&exact).unwrap().len(), MAX_FRAME_BYTES);
        assert_eq!(
            Wire::Deflate.decode(&[0x02, 0xa0]),
            Err("unknown frame prefix 0x02".to_string())
        );
        assert_eq!(Wire::Deflate.decode(&[]), Err("empty frame".to_string()));
        assert!(
            Wire::Deflate
                .decode(&[0x01, 0xff, 0xff])
                .unwrap_err()
                .starts_with("bad deflate data: ")
        );
    }

    #[test]
    fn subprotocols() {
        assert_eq!(
            Wire::OFFERED.map(Wire::from_subprotocol),
            [Some(Wire::Deflate), Some(Wire::Plain)]
        );
        assert_eq!(Wire::from_subprotocol("happy-supervisor.v2"), None);
        assert_eq!(Wire::Deflate.subprotocol(), "happy-supervisor.v1.deflate");
    }
}
