//! The state directory: installation ID and credentials (docs/architecture.md, State
//! directory). Owned by the transport track; the scaffold froze the signatures.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind, Result};

const INSTALLATION_ID: &str = "installation-id";
const CREDENTIALS: &str = "credentials.json";
const WORKLOAD_USER: &str = "workload-user";
const SYSTEM: &str = "system";

/// A running node's hold on its state directory. Released on drop, or when the process ends.
#[derive(Debug)]
pub struct StateLock {
    _file: std::fs::File,
}

#[derive(Clone, Debug)]
pub struct StateDir {
    root: PathBuf,
    /// `--workload-user`, which overrides `private/workload-user`.
    workload_user: Option<String>,
}

impl StateDir {
    /// Opens `dir`, or the platform default, creating it and `private/` `0700` and `public/` if
    /// missing.
    pub fn open(dir: Option<PathBuf>) -> Result<StateDir> {
        let root = match dir {
            Some(dir) => dir,
            None => default_root()?,
        };
        let state = StateDir {
            root,
            workload_user: None,
        };
        create_dir(&state.root, 0o700)?;
        create_dir(&state.private_dir(), 0o700)?;
        create_dir(&state.public_dir(), 0o755)?;
        Ok(state)
    }

    /// The existing state directory at `root`, changing nothing: for the administrator's
    /// commands, which must not narrow a running node's `0711` root or create a directory the
    /// service does not use.
    pub fn existing(root: PathBuf) -> Result<StateDir> {
        let state = StateDir {
            root,
            workload_user: None,
        };
        if !state.private_dir().is_dir() {
            return Err(Error::not_found(format!(
                "no supervisor state at {}: pass the service's --state-dir",
                state.root.display()
            )));
        }
        Ok(state)
    }

    /// A state directory at `root`, as is. For unit tests that need a `StateDir` without I/O.
    #[cfg(all(test, unix))]
    pub(crate) fn at(root: PathBuf) -> StateDir {
        StateDir {
            root,
            workload_user: None,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Runs the node's work as `user` (`--workload-user`) instead of the one in
    /// `private/workload-user`.
    pub fn with_workload_user(mut self, user: Option<String>) -> StateDir {
        if user.is_some() {
            self.workload_user = user;
        }
        self
    }

    /// The user every command, file operation and watch runs as: `--workload-user`, else the
    /// first line of `private/workload-user`, which an installer writes. `None` runs them as
    /// the supervisor's user.
    pub fn workload_user(&self) -> Result<Option<String>> {
        if let Some(user) = &self.workload_user {
            return Ok(Some(user.clone()));
        }
        let path = self.private_dir().join(WORKLOAD_USER);
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(text
                .lines()
                .next()
                .map(str::trim)
                .filter(|user| !user.is_empty())
                .map(str::to_owned)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(io_error(&path, err)),
        }
    }

    /// Lets other users pass through the state directory (`0711`) to `public/`, which a
    /// workload user's commands read. `private/` stays `0700`.
    pub fn open_to_workload(&self) -> Result<()> {
        create_dir(&self.root, 0o711)
    }

    /// Takes the directory for one running node (`run` or `serve`) until the [`StateLock`] is
    /// dropped. A second one is refused.
    pub fn lock(&self) -> Result<StateLock> {
        let path = self.root.join("lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(StateLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("another happy-supervisor is using {}", self.root.display()),
            )),
            Err(std::fs::TryLockError::Error(err)) => Err(err.into()),
        }
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

    /// `private/system`, which `happy-supervisor system enable` writes: the account
    /// `{"mode": "system"}` work runs as. `None` when system access is not enabled.
    ///
    /// It authorizes work as root, so the state directory, `private/` and the file must each be
    /// the supervisor's user's own, not a symlink, and writable by no one else, and every
    /// directory above them root's or the supervisor's user's and writable by no one else (or
    /// sticky, as `/tmp`). Then no other user can replace any of it between this check and the
    /// read. Otherwise system access is refused.
    pub fn system(&self) -> Result<Option<SystemAccess>> {
        let path = self.private_dir().join(SYSTEM);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(io_error(&path, err)),
        }
        self.check_protected()?;
        let text = match std::fs::read(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(io_error(&path, err)),
        };
        serde_json::from_slice(&text)
            .map(Some)
            .map_err(|err| io_error(&path, err))
    }

    /// Refuses unless no other user can replace what [`StateDir::system`] reads: the state
    /// directory, `private/` and `private/system` (when it exists) must be the supervisor's
    /// user's own, no symlink, and writable by no one else. Every entry above them, on the path
    /// as given and as resolved, must be root's or the supervisor's user's, and a directory
    /// writable by no one else unless it is sticky (`/tmp`). `system enable` checks this before
    /// it writes.
    pub fn check_protected(&self) -> Result<()> {
        #[cfg(unix)]
        if let Some(path) = self.unprotected() {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "system access stays refused: {} is a symlink or another user's, or others \
                     may write it",
                    path.display()
                ),
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn unprotected(&self) -> Option<PathBuf> {
        use std::os::unix::fs::MetadataExt as _;
        let me = nix::unistd::geteuid().as_raw();
        let mut own = vec![self.root.clone(), self.private_dir()];
        let marker = self.private_dir().join(SYSTEM);
        if std::fs::symlink_metadata(&marker).is_ok() {
            own.push(marker);
        }
        let mine = |path: &Path| {
            std::fs::symlink_metadata(path).is_ok_and(|meta| {
                !meta.file_type().is_symlink() && meta.uid() == me && meta.mode() & 0o022 == 0
            })
        };
        if let Some(path) = own.into_iter().find(|path| !mine(path)) {
            return Some(path);
        }
        let held = |path: &Path| {
            std::fs::symlink_metadata(path).is_ok_and(|meta| {
                (meta.uid() == 0 || meta.uid() == me)
                    && (meta.file_type().is_symlink()
                        || meta.mode() & 0o022 == 0
                        || meta.mode() & 0o1000 != 0)
            })
        };
        let Ok(resolved) = std::fs::canonicalize(&self.root) else {
            return Some(self.root.clone());
        };
        [&self.root, &resolved]
            .into_iter()
            .flat_map(|root| root.ancestors().skip(1))
            .find(|path| !held(path))
            .map(Path::to_path_buf)
    }

    /// Enables system access with `access`, atomically and owner-only, or disables it.
    pub fn store_system(&self, access: Option<&SystemAccess>) -> Result<()> {
        let dir = self.private_dir();
        let path = dir.join(SYSTEM);
        match access {
            Some(access) => {
                let json = serde_json::to_vec_pretty(access).expect("system access serializes");
                let temp = write_temp(&dir, &json, 0o600)?;
                if let Err(err) = std::fs::rename(&temp, &path) {
                    let _ = std::fs::remove_file(&temp);
                    return Err(io_error(&path, err));
                }
            }
            None => match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) => return Err(io_error(&path, err)),
            },
        }
        sync_dir(&dir)
    }
}

/// `private/system`: who `{"mode": "system"}` work runs as (policy.md, System access).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemAccess {
    /// The account's user name, `root` included.
    pub user: String,
    /// Directories put at the front of a system command's `PATH`: Homebrew's `bin` and `sbin`.
    pub path: Vec<String>,
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

    #[test]
    fn one_node_at_a_time_holds_the_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateDir::open(Some(tmp.path().to_path_buf())).unwrap();
        let held = state.lock().unwrap();
        let err = state.lock().unwrap_err();
        assert_eq!(
            err,
            Error::new(
                ErrorKind::AlreadyExists,
                format!("another happy-supervisor is using {}", tmp.path().display())
            )
        );
        drop(held);
        assert!(state.lock().is_ok());
    }

    #[test]
    fn system_access_is_stored_and_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let state = StateDir::open(Some(tmp.path().to_path_buf())).unwrap();
        assert_eq!(state.system().unwrap(), None);
        let access = SystemAccess {
            user: "admin".to_string(),
            path: vec!["/opt/homebrew/bin".to_string()],
        };
        state.store_system(Some(&access)).unwrap();
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("private/system")).unwrap(),
            "{\n  \"user\": \"admin\",\n  \"path\": [\n    \"/opt/homebrew/bin\"\n  ]\n}"
        );
        assert_eq!(state.system().unwrap(), Some(access));
        state.store_system(None).unwrap();
        state.store_system(None).unwrap();
        assert_eq!(state.system().unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn system_access_others_can_write_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let state = StateDir::open(Some(tmp.path().to_path_buf())).unwrap();
        let access = SystemAccess {
            user: "root".to_string(),
            path: vec![],
        };
        state.store_system(Some(&access)).unwrap();
        let marker = tmp.path().join("private/system");
        let refused = |path: &Path| {
            Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "system access stays refused: {} is a symlink or another user's, or others \
                     may write it",
                    path.display()
                ),
            )
        };
        let mode = |path: &Path, mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        mode(&marker, 0o666);
        assert_eq!(state.system().unwrap_err(), refused(&marker));
        mode(&marker, 0o600);
        mode(&state.private_dir(), 0o770);
        assert_eq!(state.system().unwrap_err(), refused(&state.private_dir()));
        mode(&state.private_dir(), 0o700);
        std::fs::rename(&marker, tmp.path().join("real")).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("real"), &marker).unwrap();
        assert_eq!(state.system().unwrap_err(), refused(&marker));
        std::fs::remove_file(&marker).unwrap();
        assert_eq!(state.system().unwrap(), None);

        let shared = tmp.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let below = StateDir::open(Some(shared.join("state"))).unwrap();
        below.store_system(Some(&access)).unwrap();
        mode(&shared, 0o777);
        assert_eq!(below.system().unwrap_err(), refused(&shared));
        mode(&shared, 0o1777);
        assert_eq!(below.system().unwrap(), Some(access));
    }

    #[cfg(unix)]
    #[test]
    fn the_administrators_commands_change_nothing_and_need_the_state() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing");
        assert_eq!(
            StateDir::existing(missing.clone()).unwrap_err(),
            Error::not_found(format!(
                "no supervisor state at {}: pass the service's --state-dir",
                missing.display()
            ))
        );
        assert!(!missing.exists());
        let state = StateDir::open(Some(tmp.path().to_path_buf())).unwrap();
        state.open_to_workload().unwrap();
        StateDir::existing(tmp.path().to_path_buf()).unwrap();
        let mode = std::fs::metadata(tmp.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o711);
    }

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
