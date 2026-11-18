//! The state directory: installation ID and credentials (docs/architecture.md, State
//! directory). Owned by the transport track; the scaffold froze the signatures.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind, Result};

const INSTALLATION_ID: &str = "installation-id";
const CREDENTIALS: &str = "credentials.json";

#[derive(Clone, Debug)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// Opens `dir`, or the platform default, creating it and `private/` `0700` and `public/` if
    /// missing.
    pub fn open(dir: Option<PathBuf>) -> Result<StateDir> {
        let root = match dir {
            Some(dir) => dir,
            None => default_root()?,
        };
        let state = StateDir { root };
        create_dir(&state.root, 0o700)?;
        create_dir(&state.private_dir(), 0o700)?;
        create_dir(&state.public_dir(), 0o755)?;
        Ok(state)
    }

    /// A state directory at `root`, as is. For unit tests that need a `StateDir` without I/O.
    #[cfg(all(test, unix))]
    pub(crate) fn at(root: PathBuf) -> StateDir {
        StateDir { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `private/`: identity, credentials and the proxy CA key. Every job's `hidden` path.
    pub fn private_dir(&self) -> PathBuf {
        self.root.join("private")
    }

    /// `public/`: the CA bundle, which sandboxed commands with a proxy may read.
    pub fn public_dir(&self) -> PathBuf {
        self.root.join("public")
    }

    /// The cuid2 in `private/installation-id`, created on first use and never changed after.
    pub fn installation_id(&self) -> Result<String> {
        let path = self.private_dir().join(INSTALLATION_ID);
        if let Some(id) = read_installation_id(&path)? {
            return Ok(id);
        }
        let id = cuid2::create_id();
        let temp = write_temp(&self.private_dir(), id.as_bytes(), 0o600)?;
        // A link fails if the file exists, so two first starts agree on one ID.
        let linked = std::fs::hard_link(&temp, &path);
        let _ = std::fs::remove_file(&temp);
        match linked {
            Ok(()) => {
                sync_dir(&self.private_dir())?;
                Ok(id)
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                read_installation_id(&path)?
                    .ok_or_else(|| io_error(&path, "vanished while it was created"))
            }
            Err(err) => Err(io_error(&path, err)),
        }
    }

    /// The stored `private/credentials.json`, or `None` before the first join.
    pub fn credentials(&self) -> Result<Option<Credentials>> {
        let path = self.private_dir().join(CREDENTIALS);
        let text = match std::fs::read(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(io_error(&path, err)),
        };
        serde_json::from_slice(&text)
            .map(Some)
            .map_err(|err| io_error(&path, err))
    }

    /// Replaces `private/credentials.json` atomically and durably, owner-only.
    pub fn store_credentials(&self, credentials: &Credentials) -> Result<()> {
        let dir = self.private_dir();
        let path = dir.join(CREDENTIALS);
        let json = serde_json::to_vec_pretty(credentials).expect("credentials serialize");
        let temp = write_temp(&dir, &json, 0o600)?;
        if let Err(err) = std::fs::rename(&temp, &path) {
            let _ = std::fs::remove_file(&temp);
            return Err(io_error(&path, err));
        }
        sync_dir(&dir)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    /// The full WebSocket URL to connect to (api.md, Joining).
    pub endpoint: String,
    pub node_id: String,
    pub node_token: String,
    pub name: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("endpoint", &self.endpoint)
            .field("node_id", &self.node_id)
            .field("node_token", &"<redacted>")
            .field("name", &self.name)
            .finish()
    }
}

/// The platform default (docs/architecture.md, State directory).
fn default_root() -> Result<PathBuf> {
    let env = |name: &str| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let missing = |what: &str| {
        Error::new(
            ErrorKind::Io,
            format!("no default state directory: {what} is not set, pass --state-dir"),
        )
    };
    let base = if cfg!(target_os = "macos") {
        env("HOME")
            .ok_or_else(|| missing("HOME"))?
            .join("Library/Application Support")
    } else if cfg!(windows) {
        env("LOCALAPPDATA").ok_or_else(|| missing("LOCALAPPDATA"))?
    } else if is_root() {
        PathBuf::from("/var/lib")
    } else if let Some(state) = env("XDG_STATE_HOME") {
        state
    } else {
        env("HOME")
            .ok_or_else(|| missing("HOME"))?
            .join(".local/state")
    };
    Ok(base.join("happy-supervisor"))
}

#[cfg(unix)]
fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

/// Creates `dir` and its missing parents. On Unix the directories it creates get `mode`, and
/// `dir` itself is set to `mode` if it already existed with another one.
fn create_dir(dir: &Path, mode: u32) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        builder.mode(mode);
        builder.create(dir).map_err(|err| io_error(dir, err))?;
        let meta = std::fs::metadata(dir).map_err(|err| io_error(dir, err))?;
        if meta.permissions().mode() & 0o7777 != mode {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))
                .map_err(|err| io_error(dir, err))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        builder.create(dir).map_err(|err| io_error(dir, err))?;
    }
    Ok(())
}

fn read_installation_id(path: &Path) -> Result<Option<String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(io_error(path, err)),
    };
    let id = text.trim();
    let valid = id.len() == 24
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if !valid {
        return Err(io_error(path, format!("{id:?} is not a cuid2")));
    }
    Ok(Some(id.to_string()))
}

/// Writes `contents` to a new file in `dir`, created with `mode` on Unix, and syncs it.
fn write_temp(dir: &Path, contents: &[u8], mode: u32) -> Result<PathBuf> {
    let path = dir.join(format!(".tmp-{}", uuid::Uuid::now_v7()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let written = options.open(&path).and_then(|mut file| {
        file.write_all(contents)?;
        file.sync_all()
    });
    if let Err(err) = written {
        let _ = std::fs::remove_file(&path);
        return Err(io_error(&path, err));
    }
    Ok(path)
}

/// Makes a rename or link in `dir` durable. Windows has no directory sync; NTFS journals it.
fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|err| io_error(dir, err))?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn io_error(path: &Path, err: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, format!("{}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials(token: &str) -> Credentials {
        Credentials {
            endpoint: "wss://edge.example.com/nodes/connect".to_string(),
            node_id: "n_1".to_string(),
            node_token: token.to_string(),
            name: "box".to_string(),
        }
    }

    #[test]
    fn open_creates_the_two_parts() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("a/b/state");
        let state = StateDir::open(Some(root.clone())).unwrap();
        assert_eq!(state.private_dir(), root.join("private"));
        assert_eq!(state.public_dir(), root.join("public"));
        assert!(state.private_dir().is_dir() && state.public_dir().is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&root), 0o700);
            assert_eq!(mode(&state.private_dir()), 0o700);
            assert_eq!(mode(&state.public_dir()), 0o755);
            std::fs::set_permissions(state.private_dir(), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            StateDir::open(Some(root.clone())).unwrap();
            assert_eq!(mode(&state.private_dir()), 0o700);
        }
    }

    #[test]
    fn the_installation_id_is_made_once() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateDir::open(Some(tmp.path().to_path_buf())).unwrap();
        let id = state.installation_id().unwrap();
        assert_eq!(id.len(), 24);
        assert_eq!(state.installation_id().unwrap(), id);
        let reopened = StateDir::open(Some(tmp.path().to_path_buf())).unwrap();
        assert_eq!(reopened.installation_id().unwrap(), id);
        let path = state.private_dir().join("installation-id");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), id);
        assert_eq!(std::fs::read_dir(state.private_dir()).unwrap().count(), 1);

        std::fs::write(&path, "Not-A-Cuid\n").unwrap();
        let err = state.installation_id().unwrap_err();
        assert!(
            err.message
                .ends_with(r#"installation-id: "Not-A-Cuid" is not a cuid2"#)
        );
    }

    #[test]
    fn credentials_are_replaced_whole_and_owner_only() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateDir::open(Some(tmp.path().to_path_buf())).unwrap();
        assert_eq!(state.credentials().unwrap(), None);
        state.store_credentials(&credentials("nt_1")).unwrap();
        state.store_credentials(&credentials("nt_2")).unwrap();
        assert_eq!(state.credentials().unwrap(), Some(credentials("nt_2")));
        let path = state.private_dir().join("credentials.json");
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "endpoint": "wss://edge.example.com/nodes/connect",
                "nodeId": "n_1", "nodeToken": "nt_2", "name": "box" })
        );
        assert_eq!(std::fs::read_dir(state.private_dir()).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(
            format!("{:?}", credentials("nt_secret")),
            r#"Credentials { endpoint: "wss://edge.example.com/nodes/connect", node_id: "n_1", node_token: "<redacted>", name: "box" }"#
        );
    }
}
