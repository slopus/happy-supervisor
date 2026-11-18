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

/// Encodes a value as CBOR. Every wire type serializes, so this cannot fail.
pub fn to_cbor<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("wire types serialize to CBOR");
    out
}

pub fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    ciborium::from_reader(bytes).map_err(|err| match err {
        ciborium::de::Error::Semantic(_, message) => message,
        ciborium::de::Error::Syntax(offset) => format!("bad CBOR at byte {offset}"),
        ciborium::de::Error::Io(_) => "the CBOR ends early".to_string(),
        ciborium::de::Error::RecursionLimitExceeded => "the CBOR nests too deep".to_string(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Ack, Frame, MsgId};

    #[test]
    fn an_ack_frame_is_these_cbor_bytes() {
        let cursor = uuid::Uuid::parse_str("0193a3b4-7c2e-7aa1-9f00-3c1d2e4f5a6b").unwrap();
        let frame = Frame::Ack(Ack {
            cursor: MsgId(cursor),
        });
        let bytes = to_cbor(&frame);
        let expected: Vec<u8> = [
            &[0xa2, 0x61, b't', 0x63, b'a', b'c', b'k'][..],
            &[0x66, b'c', b'u', b'r', b's', b'o', b'r', 0x50],
            &[0x01, 0x93, 0xa3, 0xb4, 0x7c, 0x2e, 0x7a, 0xa1],
            &[0x9f, 0x00, 0x3c, 0x1d, 0x2e, 0x4f, 0x5a, 0x6b],
        ]
        .concat();
        assert_eq!(bytes, expected);
        assert_eq!(from_cbor::<Frame>(&expected).unwrap(), frame);
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
