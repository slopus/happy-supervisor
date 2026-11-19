//! How frames become WebSocket payloads (api.md, Encoding and Compression): CBOR, and the
//! optional per-frame raw DEFLATE selected by the WebSocket subprotocol.

//! How frames become WebSocket messages (api.md, Frame layout): a 16-byte frame ID, then a CBOR
//! body whose registered names are compacted to integers. Compression is the WebSocket's own
//! permessage-deflate ([`ws`](crate::ws)), so nothing here compresses.

use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

pub use ciborium::Value;

use crate::protocol::MAX_FRAME_BYTES;

/// The frame ID before every body.
pub const PREFIX_BYTES: usize = 16;

/// One frame: `id`, then `body`.
pub fn frame(id: Uuid, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREFIX_BYTES + body.len());
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(body);
    out
}

/// A received frame's ID and body. Fails on a frame too short for its ID or over the limit.
pub fn split(payload: &[u8]) -> Result<(Uuid, &[u8]), String> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(format!(
            "frame of {} bytes is over the limit",
            payload.len()
        ));
    }
    if payload.len() < PREFIX_BYTES {
        return Err(format!(
            "frame of {} bytes has no room for its ID",
            payload.len()
        ));
    }
    let (id, body) = payload.split_at(PREFIX_BYTES);
    let id: [u8; PREFIX_BYTES] = id.try_into().expect("split at the prefix length");
    Ok((Uuid::from_bytes(id), body))
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
    (1, "kind", Role::Key),
    (2, "body", Role::Key),
    (3, "cursor", Role::Key),
    (4, "msg", Role::Frame),
    (5, "ack", Role::Frame),
    (6, "part", Role::Frame),
    (7, "of", Role::Key),
    (8, "last", Role::Key),
    (9, "data", Role::Key),
    (10, "exec.output", Role::Kind),
    (11, "reply", Role::Kind),
    (12, "execId", Role::Key),
    (13, "stream", Role::Key),
    (14, "droppedBytes", Role::Key),
    (15, "to", Role::Key),
    (16, "ok", Role::Key),
    (17, "error", Role::Key),
    (18, "streamId", Role::Key),
    (19, "tcp.data", Role::Kind),
    (20, "proxy.body", Role::Kind),
    (21, "watch.event", Role::Kind),
    (22, "watchId", Role::Key),
    (23, "changes", Role::Key),
    (24, "exec.exit", Role::Kind),
    (25, "exit", Role::Key),
    (26, "logBytes", Role::Key),
    (27, "code", Role::Key),
    (28, "path", Role::Key),
    (29, "hello", Role::Frame),
    (30, "welcome", Role::Frame),
    (31, "bye", Role::Frame),
    (32, "proxy.credit", Role::Kind),
    (33, "proxy.request", Role::Kind),
    (34, "proxy.response", Role::Kind),
    (35, "proxy.end", Role::Kind),
    (36, "proxy.reset", Role::Kind),
    (37, "node.ready", Role::Kind),
    (38, "exec.timedOut", Role::Kind),
    (39, "node.info", Role::Kind),
    (40, "node.update", Role::Kind),
    (41, "exec.start", Role::Kind),
    (42, "exec.write", Role::Kind),
    (43, "exec.kill", Role::Kind),
    (44, "exec.list", Role::Kind),
    (45, "exec.log", Role::Kind),
    (46, "fs.stat", Role::Kind),
    (47, "fs.list", Role::Kind),
    (48, "fs.read", Role::Kind),
    (49, "fs.write", Role::Kind),
    (50, "fs.mkdir", Role::Kind),
    (51, "fs.remove", Role::Kind),
    (52, "watch.start", Role::Kind),
    (53, "watch.stop", Role::Kind),
    (54, "bytes", Role::Key),
    (55, "message", Role::Key),
    (56, "session", Role::Key),
    (57, "resumed", Role::Key),
    (58, "resumeWindowMs", Role::Key),
    (59, "nodeId", Role::Key),
    (60, "installationId", Role::Key),
    (61, "version", Role::Key),
    (62, "reason", Role::Key),
    (63, "previousSession", Role::Key),
    (64, "signal", Role::Key),
    (65, "overflow", Role::Key),
    (66, "headers", Role::Key),
    (67, "status", Role::Key),
    (68, "method", Role::Key),
    (69, "scheme", Role::Key),
    (70, "host", Role::Key),
    (71, "port", Role::Key),
    (72, "token", Role::Key),
    (73, "hosts", Role::Key),
    (74, "proxy", Role::Key),
    (75, "argv", Role::Key),
    (76, "cwd", Role::Key),
    (77, "env", Role::Key),
    (78, "stdin", Role::Key),
    (79, "timeout", Role::Key),
    (80, "ms", Role::Key),
    (81, "action", Role::Key),
    (82, "log", Role::Key),
    (83, "limitBytes", Role::Key),
    (84, "access", Role::Key),
    (85, "mode", Role::Key),
    (86, "policy", Role::Key),
    (87, "read", Role::Key),
    (88, "write", Role::Key),
    (89, "localBind", Role::Key),
    (90, "unixSockets", Role::Key),
    (91, "eof", Role::Key),
    (92, "pid", Role::Key),
    (93, "ignoredPaths", Role::Key),
    (94, "execs", Role::Key),
    (95, "state", Role::Key),
    (96, "offset", Role::Key),
    (97, "length", Role::Key),
    (98, "totalBytes", Role::Key),
    (99, "retained", Role::Key),
    (100, "start", Role::Key),
    (101, "end", Role::Key),
    (102, "entries", Role::Key),
    (103, "name", Role::Key),
    (104, "size", Role::Key),
    (105, "modifiedMs", Role::Key),
    (106, "readonly", Role::Key),
    (107, "recursive", Role::Key),
    (108, "nodeToken", Role::Key),
    (109, "endpoint", Role::Key),
    (110, "info", Role::Key),
    (111, "watches", Role::Key),
    (112, "hostname", Role::Key),
    (113, "supervisorVersion", Role::Key),
    (114, "os", Role::Key),
    (115, "family", Role::Key),
    (116, "kernelVersion", Role::Key),
    (117, "arch", Role::Key),
    (118, "cpu", Role::Key),
    (119, "model", Role::Key),
    (120, "logicalCores", Role::Key),
    (121, "physicalCores", Role::Key),
    (122, "memory", Role::Key),
    (123, "swapTotalBytes", Role::Key),
    (124, "disks", Role::Key),
    (125, "mountPoint", Role::Key),
    (126, "fileSystem", Role::Key),
    (127, "availableBytes", Role::Key),
    (128, "removable", Role::Key),
    (129, "gpus", Role::Key),
    (130, "vendor", Role::Key),
    (131, "memoryBytes", Role::Key),
    (132, "driverVersion", Role::Key),
    (133, "sandbox", Role::Key),
    (134, "mechanism", Role::Key),
    (135, "available", Role::Key),
    (136, "landlockAbi", Role::Key),
    (137, "baselineRead", Role::Key),
    (138, "gaps", Role::Key),
    (139, "defaultEnv", Role::Key),
    (140, "collectedAtMs", Role::Key),
    (141, "joinToken", Role::Key),
    (142, "tcp.credit", Role::Kind),
    (143, "tcp.open", Role::Kind),
    (144, "tcp.end", Role::Kind),
    (145, "tcp.reset", Role::Kind),
    (146, "filesystem", Role::Key),
    (147, "allow", Role::Key),
    (148, "deny", Role::Key),
    (149, "default", Role::Key),
    (150, "network", Role::Key),
    (151, "egress", Role::Key),
    (152, "ports", Role::Key),
    (153, "net.denied", Role::Kind),
    (154, "via", Role::Key),
    (155, "dropped", Role::Key),
    (156, "fs.rename", Role::Kind),
    (157, "from", Role::Key),
    (158, "tty", Role::Key),
    (159, "rows", Role::Key),
    (160, "cols", Role::Key),
    (161, "exec.resize", Role::Kind),
    (162, "identity", Role::Key),
    (163, "supervisorUser", Role::Key),
    (164, "workloadUser", Role::Key),
    (165, "root", Role::Key),
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

/// The encoded start of a `msg` frame's body up to its `body` value: `t`, `kind` and the
/// `body` key, compacted as [`to_cbor`] would. CBOR items concatenate, so appending a body
/// encoded by [`to_cbor`] completes the frame without converting the body again.
pub fn msg_head(kind: &str) -> Vec<u8> {
    let name = |text: &str, role| compact_name(Value::Text(text.to_string()), role);
    let mut out = vec![0xa3];
    write(&name("t", Role::Key), &mut out);
    write(&name("msg", Role::Frame), &mut out);
    write(&name("kind", Role::Key), &mut out);
    write(&name(kind, Role::Kind), &mut out);
    write(&name("body", Role::Key), &mut out);
    out
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
/// names missing from the registry. The protocol tests that use it run on Unix.
#[cfg(all(test, unix))]
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
    use crate::protocol::{Ack, Bytes, ExecId, ExecOutput, Frame, Msg, MsgId, Part, Stream};

    const ID: [u8; 16] = [
        0x01, 0x93, 0xa3, 0xb4, 0x7c, 0x2e, 0x7a, 0xa1, 0x9f, 0x00, 0x3c, 0x1d, 0x2e, 0x4f, 0x5a,
        0x6b,
    ];
    const CURSOR: [u8; 16] = [
        0x01, 0x93, 0xa3, 0xb4, 0x7c, 0x2e, 0x7a, 0xa0, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07,
    ];

    #[test]
    fn an_ack_frame_is_these_bytes() {
        let ack = Frame::Ack(Ack {
            cursor: MsgId(Uuid::from_bytes(CURSOR)),
        });
        let bytes = frame(Uuid::from_bytes(ID), &to_cbor(&ack));
        let expected: Vec<u8> = [
            // the frame ID, then {0 (t): 5 (ack), 3 (cursor): 16 bytes}
            &ID[..],
            &[0xa2, 0x00, 0x05, 0x03, 0x50],
            &CURSOR,
        ]
        .concat();
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 37);
        let (id, body) = split(&expected).unwrap();
        assert_eq!(id, Uuid::from_bytes(ID));
        assert_eq!(from_cbor::<Frame>(body).unwrap(), ack);
    }

    /// The hot frame: 16 bytes of output. Was 115 bytes with text keys, kinds and the ID inside.
    #[test]
    fn a_small_exec_output_frame_is_these_bytes() {
        let output = ExecOutput {
            exec_id: ExecId::try_from("build-1").unwrap(),
            stream: Stream::Stdout,
            data: Bytes(b"0123456789abcdef".to_vec()),
            dropped_bytes: 0,
        };
        let body = [msg_head("exec.output"), to_cbor(&output)].concat();
        let bytes = frame(Uuid::from_bytes(ID), &body);
        let expected: Vec<u8> = [
            &ID[..],
            // {0 (t): 4 (msg), 1 (kind): 10 (exec.output), 2 (body): …}
            &[0xa3, 0x00, 0x04, 0x01, 0x0a, 0x02],
            // {12 (execId): "build-1", 13 (stream): "stdout", 9 (data): 16 bytes, 14: 0}
            &[0xa4, 0x0c, 0x67],
            b"build-1",
            &[0x0d, 0x66],
            b"stdout",
            &[0x09, 0x50],
            b"0123456789abcdef",
            &[0x0e, 0x00],
        ]
        .concat();
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 60);
        let frame: Frame = from_cbor(split(&bytes).unwrap().1).unwrap();
        let Frame::Msg(msg) = frame else {
            panic!("{frame:?}")
        };
        assert_eq!(msg.kind, "exec.output");
        assert_eq!(from_value::<ExecOutput>(msg.body).unwrap(), output);
        let whole = Frame::Msg(Msg {
            kind: "exec.output".to_string(),
            body: to_value(&output),
        });
        assert_eq!(to_cbor(&whole), body);
    }

    #[test]
    fn a_part_frame_is_these_bytes() {
        let part = Frame::Part(Part {
            of: MsgId(Uuid::from_bytes(ID)),
            last: true,
            data: Bytes(vec![0xa3, 0x00]),
        });
        let bytes = frame(Uuid::from_bytes(CURSOR), &to_cbor(&part));
        let expected: Vec<u8> = [
            &CURSOR[..],
            // {0 (t): 6 (part), 7 (of): 16 bytes, 8 (last): true, 9 (data): 2 bytes}
            &[0xa4, 0x00, 0x06, 0x07, 0x50],
            &ID,
            &[0x08, 0xf5, 0x09, 0x42, 0xa3, 0x00],
        ]
        .concat();
        assert_eq!(bytes, expected);
        assert_eq!(from_cbor::<Frame>(split(&bytes).unwrap().1).unwrap(), part);
    }

    #[test]
    fn a_frame_needs_its_id_and_fits_the_limit() {
        assert_eq!(
            split(&[0; 15]),
            Err("frame of 15 bytes has no room for its ID".to_string())
        );
        assert_eq!(
            split(&vec![0; MAX_FRAME_BYTES + 1]),
            Err(format!(
                "frame of {} bytes is over the limit",
                MAX_FRAME_BYTES + 1
            ))
        );
        assert_eq!(
            split(&[7; 16]).unwrap(),
            (Uuid::from_bytes([7; 16]), &[][..])
        );
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
        assert_eq!(&bytes[..3], &[0xa3, 0x00, 0x04]);
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
            refused(vec![(int(0), int(4)), (int(1), int(9999))]),
            "unknown message kind 9999"
        );
        // A body's own `kind` is a value like any other.
        let change = Value::Map(vec![(
            Value::Text("kind".into()),
            Value::Text("reply".into()),
        )]);
        assert_eq!(
            to_cbor(&change),
            [0xa1, 0x01, 0x65, b'r', b'e', b'p', b'l', b'y']
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
}
