//! The boot directory (docs/boot.md, Files): the verified builds, each with the signed list it
//! was verified against, and which of them runs.
//!
//! ```text
//! <dir>/state.json                     {"current": "0.2.9", "previous": "0.2.8"}
//! <dir>/versions/<version>/<binary>    happy-supervisor, or happy-supervisor.exe
//! <dir>/versions/<version>/SHA256SUMS
//! <dir>/versions/<version>/SHA256SUMS.minisig
//! ```
//!
//! A build reaches `versions/` only verified, by a rename of a directory it was verified in. It is
//! verified again, from those files, before each start.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::minisign::PublicKey;
use crate::release;

/// The binary's name in its version directory.
pub const BINARY: &str = if cfg!(windows) {
    "happy-supervisor.exe"
} else {
    "happy-supervisor"
};
const SUMS: &str = "SHA256SUMS";
const SIG: &str = "SHA256SUMS.minisig";

/// Which build runs, and the one before it, kept to go back to.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub current: Option<String>,
    pub previous: Option<String>,
}

/// One build's files, as fetched and before they are verified.
pub struct Build<'a> {
    pub version: &'a str,
    pub sums: &'a [u8],
    pub signature: &'a str,
    pub binary: &'a [u8],
}

pub struct Store {
    dir: PathBuf,
    keys: Vec<PublicKey>,
}

impl Store {
    /// The boot directory at `dir`, created if missing, trusting builds that `keys` signed.
    pub fn open(dir: PathBuf, keys: Vec<PublicKey>) -> io::Result<Store> {
        fs::create_dir_all(dir.join("versions"))?;
        set_mode(&dir, 0o755)?;
        set_mode(&dir.join("versions"), 0o755)?;
        Ok(Store { dir, keys })
    }

    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }

    pub fn state(&self) -> io::Result<State> {
        match fs::read(self.dir.join("state.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(State::default()),
            Err(err) => Err(err),
        }
    }

    /// Replaces `state.json` atomically: a file beside it, then a rename.
    pub fn save(&self, state: &State) -> io::Result<()> {
        let temp = self.dir.join(".state.json.new");
        let mut file = fs::File::create(&temp)?;
        file.write_all(&serde_json::to_vec(state).expect("State serializes"))?;
        file.sync_all()?;
        fs::rename(temp, self.dir.join("state.json"))
    }

    fn version_dir(&self, version: &str) -> PathBuf {
        self.dir.join("versions").join(version)
    }

    /// The binary of `version`, verified now against its signed list: the path to start, or why
    /// it may not be started.
    pub fn verified(&self, version: &str) -> Result<PathBuf, String> {
        release::check_version(version)?;
        let dir = self.version_dir(version);
        let read = |name: &str| {
            fs::read(dir.join(name)).map_err(|err| format!("{version}: cannot read {name}: {err}"))
        };
        let sums = read(SUMS)?;
        let signature =
            String::from_utf8(read(SIG)?).map_err(|_| format!("{version}: {SIG} is not text"))?;
        let expected = release::expected(&self.keys, version, &sums, &signature)?;
        let binary = dir.join(BINARY);
        let actual = release::sha256_file(&binary)
            .map_err(|err| format!("{version}: cannot read {BINARY}: {err}"))?;
        if actual != expected {
            return Err(format!(
                "{version}: {BINARY} is not the signed build (SHA-256 {}, signed {})",
                release::hex(&actual),
                release::hex(&expected)
            ));
        }
        Ok(binary)
    }

    /// Verifies `build` and only then puts it in `versions/`, replacing a copy there that no
    /// longer verifies. Returns the binary's path.
    pub fn install(&self, build: &Build) -> Result<PathBuf, String> {
        let version = build.version;
        release::check_version(version)?;
        let expected = release::expected(&self.keys, version, build.sums, build.signature)?;
        if release::sha256(build.binary) != expected {
            return Err(format!(
                "{version}: the downloaded {} is not the signed build",
                release::FILE
            ));
        }
        if let Ok(path) = self.verified(version) {
            return Ok(path);
        }
        let io = |err: io::Error| format!("{version}: cannot store the build: {err}");
        let staging = self
            .dir
            .join("versions")
            .join(format!(".{version}.{}", std::process::id()));
        let _ = fs::remove_dir_all(&staging);
        fs::create_dir(&staging).map_err(io)?;
        set_mode(&staging, 0o755).map_err(io)?;
        let write = |name: &str, data: &[u8], mode: u32| -> io::Result<()> {
            let path = staging.join(name);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.write_all(data)?;
            file.sync_all()?;
            set_mode(&path, mode)
        };
        write(SUMS, build.sums, 0o644).map_err(io)?;
        write(SIG, build.signature.as_bytes(), 0o644).map_err(io)?;
        write(BINARY, build.binary, 0o755).map_err(io)?;
        let target = self.version_dir(version);
        let _ = fs::remove_dir_all(&target);
        fs::rename(&staging, &target).map_err(io)?;
        self.verified(version)
    }

    /// Verifies and stores the build of `version` that an installer downloaded into `from`:
    /// `SHA256SUMS`, `SHA256SUMS.minisig` and this platform's [`release::FILE`], as the release
    /// serves them. Nothing is downloaded. Returns the binary's path.
    pub fn install_from(&self, version: &str, from: &Path) -> Result<PathBuf, String> {
        let read = |name: &str| {
            fs::read(from.join(name)).map_err(|err| format!("{}: {err}", from.join(name).display()))
        };
        let sums = read(SUMS)?;
        let signature =
            String::from_utf8(read(SIG)?).map_err(|_| format!("{version}: {SIG} is not text"))?;
        let binary = read(release::FILE)?;
        self.install(&Build {
            version,
            sums: &sums,
            signature: &signature,
            binary: &binary,
        })
    }

    /// Removes every build but `keep`, and anything a stopped install left behind.
    pub fn prune(&self, keep: &[&str]) {
        let Ok(entries) = fs::read_dir(self.dir.join("versions")) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if !keep.iter().any(|keep| name == **keep) {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Sets a Unix mode whatever the umask: a workload user runs the binary as itself
/// (docs/boot.md, Files). Elsewhere the directory's ACL applies.
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release::{FILE, hex, sha256};
    use crate::testkit::Signer;

    fn signed(signer: &Signer, version: &str, binary: &[u8]) -> (String, String) {
        let sums = format!("{}  {FILE}\n", hex(&sha256(binary)));
        let sig = signer.sign(sums.as_bytes(), &format!("happy-supervisor {version}"));
        (sums, sig)
    }

    #[test]
    fn only_a_signed_build_is_stored_and_a_changed_one_is_refused_at_start() {
        let dir = tempfile::tempdir().unwrap();
        let signer = Signer::new();
        let store = Store::open(dir.path().join("boot"), vec![signer.public()]).unwrap();
        assert_eq!(store.state().unwrap(), State::default());

        let (sums, sig) = signed(&signer, "1.0.0", b"one");
        let bad = Build {
            version: "1.0.0",
            sums: sums.as_bytes(),
            signature: &sig,
            binary: b"two",
        };
        assert_eq!(
            store.install(&bad),
            Err(format!(
                "1.0.0: the downloaded {FILE} is not the signed build"
            ))
        );
        assert!(!dir.path().join("boot/versions/1.0.0").exists());

        let good = Build {
            binary: b"one",
            ..bad
        };
        let path = store.install(&good).unwrap();
        assert_eq!(path, dir.path().join("boot/versions/1.0.0").join(BINARY));
        assert_eq!(fs::read(&path).unwrap(), b"one");
        assert_eq!(store.verified("1.0.0"), Ok(path.clone()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o755);
            assert_eq!(mode(path.parent().unwrap()), 0o755);
            assert_eq!(mode(&path.with_file_name(SUMS)), 0o644);
            assert_eq!(mode(&dir.path().join("boot")), 0o755);
        }

        fs::write(&path, b"evil").unwrap();
        assert_eq!(
            store.verified("1.0.0"),
            Err(format!(
                "1.0.0: {BINARY} is not the signed build (SHA-256 {}, signed {})",
                hex(&sha256(b"evil")),
                hex(&sha256(b"one"))
            ))
        );
        // Installing again replaces the copy that no longer verifies.
        assert_eq!(store.install(&good), Ok(path.clone()));
        assert_eq!(fs::read(&path).unwrap(), b"one");

        // The OS's message differs by platform.
        let missing = store.verified("2.0.0").unwrap_err();
        assert!(
            missing.starts_with("2.0.0: cannot read SHA256SUMS: "),
            "{missing}"
        );

        let state = State {
            current: Some("1.0.0".into()),
            previous: None,
        };
        store.save(&state).unwrap();
        assert_eq!(store.state().unwrap(), state);
        assert_eq!(
            fs::read_to_string(dir.path().join("boot/state.json")).unwrap(),
            r#"{"current":"1.0.0","previous":null}"#
        );

        fs::create_dir(dir.path().join("boot/versions/0.9.0")).unwrap();
        fs::create_dir(dir.path().join("boot/versions/.2.0.0.77")).unwrap();
        store.prune(&["1.0.0"]);
        let mut left: Vec<_> = fs::read_dir(dir.path().join("boot/versions"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["1.0.0"]);
    }

    #[test]
    fn a_build_an_installer_downloaded_is_stored_only_when_it_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let signer = Signer::new();
        let store = Store::open(dir.path().join("boot"), vec![signer.public()]).unwrap();
        let from = dir.path().join("download");
        fs::create_dir(&from).unwrap();
        let (sums, sig) = signed(&signer, "1.0.0", b"one");
        fs::write(from.join(SUMS), &sums).unwrap();
        fs::write(from.join(SIG), &sig).unwrap();

        let missing = store.install_from("1.0.0", &from).unwrap_err();
        assert!(
            missing.starts_with(&format!("{}: ", from.join(FILE).display())),
            "{missing}"
        );
        fs::write(from.join(FILE), b"two").unwrap();
        assert_eq!(
            store.install_from("1.0.0", &from),
            Err(format!(
                "1.0.0: the downloaded {FILE} is not the signed build"
            ))
        );
        // Signed for 1.0.0, so never another version's.
        assert!(store.install_from("2.0.0", &from).is_err());
        assert!(!dir.path().join("boot/versions/1.0.0").exists());

        fs::write(from.join(FILE), b"one").unwrap();
        let path = store.install_from("1.0.0", &from).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");
        assert_eq!(store.verified("1.0.0"), Ok(path));
    }
}
