//! Verifying a minisign signature (https://jedisct1.github.io/minisign/), the format the release
//! key signs `SHA256SUMS` with: Ed25519 over the BLAKE2b-512 hash of the file (`ED`), or over
//! the file itself (`Ed`, minisign's legacy form), then Ed25519 over that signature and the
//! trusted comment, which is how the comment is bound to it.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use blake2::{Blake2b512, Digest as _};
use ring::signature::{ED25519, UnparsedPublicKey};

/// A minisign public key: its 8-byte key ID and the Ed25519 key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    id: [u8; 8],
    key: [u8; 32],
}

impl PublicKey {
    /// Parses the base64 line minisign prints, `RWQ…`.
    pub fn parse(text: &str) -> Result<PublicKey, String> {
        let bytes = STANDARD
            .decode(text.trim())
            .map_err(|err| format!("public key: {err}"))?;
        let [b'E', b'd', rest @ ..] = bytes.as_slice() else {
            return Err("public key: not an Ed25519 minisign key".to_owned());
        };
        let (id, key) = rest
            .split_first_chunk::<8>()
            .ok_or("public key: too short")?;
        let key: [u8; 32] = key.try_into().map_err(|_| "public key: wrong length")?;
        Ok(PublicKey { id: *id, key })
    }

    /// The key ID as minisign prints it, most significant byte first.
    pub fn id(&self) -> String {
        self.id.iter().rev().map(|b| format!("{b:02X}")).collect()
    }
}

/// Checks that `signature`, the text of a `.minisig` file, signs `data` under one of `keys`, and
/// returns its trusted comment.
pub fn verify(keys: &[PublicKey], data: &[u8], signature: &str) -> Result<String, String> {
    let mut lines = signature.lines();
    let mut line = || lines.next().ok_or("signature: truncated");
    let untrusted = line()?;
    if !untrusted.starts_with("untrusted comment:") {
        return Err("signature: no untrusted comment line".to_owned());
    }
    let sig = STANDARD
        .decode(line()?.trim())
        .map_err(|err| format!("signature: {err}"))?;
    let comment = line()?
        .strip_prefix("trusted comment: ")
        .ok_or("signature: no trusted comment line")?;
    let global = STANDARD
        .decode(line()?.trim())
        .map_err(|err| format!("signature: {err}"))?;
    if sig.len() != 74 || global.len() != 64 {
        return Err("signature: wrong length".to_owned());
    }
    let (algorithm, rest) = sig.split_at(2);
    let (id, sig) = rest.split_at(8);
    let key = keys
        .iter()
        .find(|key| key.id == id)
        .ok_or("signature: made with a key that is not the release key")?;
    let prehashed;
    let message = match algorithm {
        b"ED" => {
            prehashed = Blake2b512::digest(data);
            prehashed.as_slice()
        }
        b"Ed" => data,
        _ => return Err("signature: unknown algorithm".to_owned()),
    };
    let ed25519 = UnparsedPublicKey::new(&ED25519, key.key);
    ed25519
        .verify(message, sig)
        .map_err(|_| "signature: does not match the file")?;
    let signed_comment = [sig, comment.as_bytes()].concat();
    ed25519
        .verify(&signed_comment, &global)
        .map_err(|_| "signature: the trusted comment was changed")?;
    Ok(comment.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made with `minisign -G -W` and `minisign -S -t "happy-supervisor 1.2.3"` over DATA.
    const KEY: &str = "RWS5WLolakdXSintDYTbr9G6QxjMvNmC9SGAlzifmTQq3gJ5Df9qgzvu";
    const DATA: &[u8] = b"hello\n";
    const SIG: &str = "untrusted comment: signature from minisign secret key
RUS5WLolakdXSsduvq1gwgkKF7U1SZTlmu/UnxOYoEtZojJH5NpZ2y4QxOomf9RNo2MqsW5QHY+1x6ulUX1vOrLVLowaGieqbwc=
trusted comment: happy-supervisor 1.2.3
0R7VBjLRox/o4U6SHvdoBDKNb/MJn8trQHIvAiPu1V/9k5jjuM6cuMP4kr8bXE68xUzv4zVx8Mrl8q7B95fhCQ==
";

    fn key() -> PublicKey {
        PublicKey::parse(KEY).unwrap()
    }

    #[test]
    fn a_minisign_signature_verifies_and_yields_its_trusted_comment() {
        assert_eq!(key().id(), "4A57476A25BA58B9");
        assert_eq!(
            verify(&[key()], DATA, SIG).as_deref(),
            Ok("happy-supervisor 1.2.3")
        );
    }

    #[test]
    fn a_changed_file_comment_or_key_is_refused() {
        assert_eq!(
            verify(&[key()], b"hello!\n", SIG),
            Err("signature: does not match the file".to_owned())
        );
        let comment = SIG.replace("1.2.3", "1.2.4");
        assert_eq!(
            verify(&[key()], DATA, &comment),
            Err("signature: the trusted comment was changed".to_owned())
        );
        let release =
            PublicKey::parse("RWQ6QpJv09qdNGB9/hp7j8OjguWGLTtuvAO/d34LiFGJPzFtF2bkY1Lr").unwrap();
        assert_eq!(release.id(), "349DDAD36F92423A");
        assert_eq!(
            verify(&[release], DATA, SIG),
            Err("signature: made with a key that is not the release key".to_owned())
        );
        assert_eq!(
            verify(&[key()], DATA, "untrusted comment: x\n"),
            Err("signature: truncated".to_owned())
        );
    }
}
