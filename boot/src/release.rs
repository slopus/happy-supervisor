//! What makes a supervisor build one this boot may run: `SHA256SUMS` signed by the release key
//! with the trusted comment `happy-supervisor <version>`, which binds the list to the version
//! asked for, and a binary whose SHA-256 that list names (deploy/README.md, Releasing).

use std::io::Read as _;
use std::path::Path;

use crate::minisign::{self, PublicKey};

/// The release keys this boot trusts, compiled in: a build runs when any one of them signed it,
/// and never otherwise. The first is the release key the publish trigger signs with
/// (deploy/README.md, Google Cloud). An offline backup key goes after it (docs/boot.md, Release
/// keys), so the primary can be replaced without a new boot on every node.
pub const RELEASE_KEYS: &[&str] = &["RWQ6QpJv09qdNGB9/hp7j8OjguWGLTtuvAO/d34LiFGJPzFtF2bkY1Lr"];

/// [`RELEASE_KEYS`], parsed.
pub fn release_keys() -> Vec<PublicKey> {
    RELEASE_KEYS
        .iter()
        .map(|key| PublicKey::parse(key).expect("a release key parses"))
        .collect()
}

/// The release file of this platform's supervisor, as `release.yml` names it.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const FILE: &str = "happy-supervisor-linux-x86_64";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub const FILE: &str = "happy-supervisor-linux-aarch64";
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const FILE: &str = "happy-supervisor-macos-aarch64";
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub const FILE: &str = "happy-supervisor-macos-x86_64";
#[cfg(all(windows, target_arch = "x86_64"))]
pub const FILE: &str = "happy-supervisor-windows-x86_64.exe";

/// A release version, as the release pipeline accepts one (`^[0-9A-Za-z.+-]+$`), starting with a
/// letter or digit so it is never `.` or `..` as a directory name, and at most 64 bytes.
pub fn check_version(version: &str) -> Result<(), String> {
    let ok = version.len() <= 64
        && version.starts_with(|c: char| c.is_ascii_alphanumeric())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'));
    if ok {
        Ok(())
    } else {
        Err(format!("bad version {version:?}"))
    }
}

/// The SHA-256 of [`FILE`] that `sums`, signed by `signature` under one of `keys`, names for
/// release `version`.
pub fn expected(
    keys: &[PublicKey],
    version: &str,
    sums: &[u8],
    signature: &str,
) -> Result<[u8; 32], String> {
    let comment = minisign::verify(keys, sums, signature)
        .map_err(|err| format!("SHA256SUMS of {version}: {err}"))?;
    if comment != format!("happy-supervisor {version}") {
        return Err(format!(
            "SHA256SUMS of {version} is signed for another release ({comment:?})"
        ));
    }
    let sums = std::str::from_utf8(sums).map_err(|_| "SHA256SUMS is not text".to_owned())?;
    let hex = sums
        .lines()
        .find_map(|line| {
            let (hash, name) = line.split_once(char::is_whitespace)?;
            let name = name.trim_start();
            (name.strip_prefix('*').unwrap_or(name) == FILE).then_some(hash)
        })
        .ok_or_else(|| format!("release {version} has no {FILE}"))?;
    parse_hex(hex).ok_or_else(|| format!("SHA256SUMS of {version}: bad hash for {FILE}"))
}

fn parse_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The SHA-256 of the file at `path`.
pub fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0; 1 << 16];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        context.update(&buf[..n]);
    }
    Ok(context
        .finish()
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes"))
}

/// The SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes")
}

/// `hash` as lowercase hex, as `SHA256SUMS` writes it.
pub fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::Signer;

    #[test]
    fn the_release_key_and_file_name() {
        assert_eq!(release_keys()[0].id(), "349DDAD36F92423A");
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(FILE, "happy-supervisor-linux-x86_64");
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        assert_eq!(FILE, "happy-supervisor-macos-aarch64");
        #[cfg(all(windows, target_arch = "x86_64"))]
        assert_eq!(FILE, "happy-supervisor-windows-x86_64.exe");
    }

    #[test]
    fn a_build_signed_by_any_one_trusted_key_verifies() {
        let (primary, backup, stranger) = (Signer::new(), Signer::new(), Signer::new());
        let keys = [primary.public(), backup.public()];
        let sums = format!("{}  {FILE}\n", hex(&sha256(b"supervisor")));
        for signer in [&primary, &backup] {
            let sig = signer.sign(sums.as_bytes(), "happy-supervisor 1.0.0");
            assert_eq!(
                expected(&keys, "1.0.0", sums.as_bytes(), &sig),
                Ok(sha256(b"supervisor"))
            );
        }
        let sig = stranger.sign(sums.as_bytes(), "happy-supervisor 1.0.0");
        assert_eq!(
            expected(&keys, "1.0.0", sums.as_bytes(), &sig),
            Err(
                "SHA256SUMS of 1.0.0: signature: made with a key that is not the release key"
                    .to_owned()
            )
        );
        // Every compiled-in key parses, and no two share a key ID.
        let compiled = release_keys();
        assert_eq!(compiled.len(), RELEASE_KEYS.len());
        let mut ids: Vec<String> = compiled.iter().map(PublicKey::id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), RELEASE_KEYS.len());
    }

    #[test]
    fn versions() {
        for good in ["0.2.8", "0.2.0-linux.5", "1.0.0+build.2"] {
            assert_eq!(check_version(good), Ok(()));
        }
        for bad in ["", ".", "..", "../x", "a/b", "a b", "-1", &"9".repeat(65)] {
            assert_eq!(check_version(bad), Err(format!("bad version {bad:?}")));
        }
    }

    #[test]
    fn the_signed_list_names_this_platforms_hash_for_this_version_only() {
        let signer = Signer::new();
        let binary = b"supervisor";
        let sums = format!(
            "{}  {FILE}\n{}  happy-supervisor-other\n",
            hex(&sha256(binary)),
            hex(&sha256(b"other"))
        );
        let sig = signer.sign(sums.as_bytes(), "happy-supervisor 1.0.0");
        let keys = [signer.public()];
        assert_eq!(
            expected(&keys, "1.0.0", sums.as_bytes(), &sig),
            Ok(sha256(binary))
        );
        assert_eq!(
            expected(&keys, "1.0.1", sums.as_bytes(), &sig),
            Err(
                "SHA256SUMS of 1.0.1 is signed for another release (\"happy-supervisor 1.0.0\")"
                    .to_owned()
            )
        );
        assert_eq!(
            expected(&release_keys(), "1.0.0", sums.as_bytes(), &sig),
            Err(
                "SHA256SUMS of 1.0.0: signature: made with a key that is not the release key"
                    .to_owned()
            )
        );
        let other = "0000  happy-supervisor-other\n";
        let sig = signer.sign(other.as_bytes(), "happy-supervisor 1.0.0");
        assert_eq!(
            expected(&keys, "1.0.0", other.as_bytes(), &sig),
            Err(format!("release 1.0.0 has no {FILE}"))
        );
    }
}
