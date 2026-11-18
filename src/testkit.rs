//! Test literals for CBOR values, written as JSON the way api.md writes them: a string `h'…'`
//! (hex) is a byte string, and `u'…'` (a hyphenated UUID) is a 16-byte one.

use crate::wire::Value;

/// The CBOR value a JSON test literal stands for.
pub fn cbor(json: serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => Value::Integer(i.into()),
            (None, Some(u)) => Value::Integer(u.into()),
            (None, None) => Value::Float(n.as_f64().expect("a JSON number")),
        },
        serde_json::Value::String(s) => {
            if let Some(hex) = s.strip_prefix("h'").and_then(|r| r.strip_suffix('\'')) {
                Value::Bytes(from_hex(hex))
            } else if let Some(uuid) = s.strip_prefix("u'").and_then(|r| r.strip_suffix('\'')) {
                Value::Bytes(
                    uuid::Uuid::parse_str(uuid)
                        .expect("a UUID")
                        .as_bytes()
                        .to_vec(),
                )
            } else {
                Value::Text(s)
            }
        }
        serde_json::Value::Array(items) => Value::Array(items.into_iter().map(cbor).collect()),
        serde_json::Value::Object(map) => Value::Map(
            map.into_iter()
                .map(|(k, v)| (Value::Text(k), cbor(v)))
                .collect(),
        ),
    }
}

/// The JSON test literal for a CBOR value. A 16-byte string reads as `u'…'`.
pub fn json(value: Value) -> serde_json::Value {
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(b),
        Value::Integer(i) => {
            let i: i128 = i.into();
            serde_json::json!(i64::try_from(i).expect("test integers fit i64"))
        }
        Value::Float(f) => serde_json::json!(f),
        Value::Text(s) => serde_json::Value::String(s),
        Value::Bytes(b) if b.len() == 16 => serde_json::Value::String(format!(
            "u'{}'",
            uuid::Uuid::from_slice(&b).expect("16 bytes")
        )),
        Value::Bytes(b) => serde_json::Value::String(format!("h'{}'", to_hex(&b))),
        Value::Array(items) => serde_json::Value::Array(items.into_iter().map(json).collect()),
        Value::Map(entries) => serde_json::Value::Object(
            entries
                .into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k.into_text().expect("text keys"), json(v)))
                .collect(),
        ),
        other => panic!("no test literal for {other:?}"),
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}
