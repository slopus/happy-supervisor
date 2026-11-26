//! A release key of the tests' own, which signs as minisign does.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use blake2::{Blake2b512, Digest as _};
use ring::signature::{Ed25519KeyPair, KeyPair as _};

use crate::minisign::PublicKey;

pub struct Signer {
    pair: Ed25519KeyPair,
    id: [u8; 8],
}

impl Signer {
    pub fn new() -> Signer {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("a key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("a key");
        let id = pair.public_key().as_ref()[..8].try_into().expect("8 bytes");
        Signer { pair, id }
    }

    pub fn public(&self) -> PublicKey {
        let key = [b"Ed".as_slice(), &self.id, self.pair.public_key().as_ref()].concat();
        PublicKey::parse(&STANDARD.encode(key)).expect("the key parses")
    }

    /// A `.minisig` of `data` with the trusted comment `comment`, prehashed as minisign 0.12 signs.
    pub fn sign(&self, data: &[u8], comment: &str) -> String {
        let sig = self.pair.sign(&Blake2b512::digest(data));
        let global = self.pair.sign(&[sig.as_ref(), comment.as_bytes()].concat());
        let sig = [b"ED".as_slice(), &self.id, sig.as_ref()].concat();
        format!(
            "untrusted comment: test\n{}\ntrusted comment: {comment}\n{}\n",
            STANDARD.encode(sig),
            STANDARD.encode(global.as_ref())
        )
    }
}
