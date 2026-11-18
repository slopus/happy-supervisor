//! The state directory: installation ID and credentials (docs/architecture.md, State
//! directory). Owned by the transport track; the scaffold froze the signatures.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Clone, Debug)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// Opens `dir`, or the platform default, creating it `0700` if missing.
    pub fn open(dir: Option<PathBuf>) -> Result<StateDir> {
        let _ = dir;
        Err(Error::not_implemented("the state directory"))
    }

    /// A state directory at `root`, as is. For unit tests that need a `StateDir` without I/O.
    #[cfg(all(test, unix))]
    pub(crate) fn at(root: PathBuf) -> StateDir {
        StateDir { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The cuid2 in `installation-id`, created on first use and never changed after.
    pub fn installation_id(&self) -> Result<String> {
        Err(Error::not_implemented("the installation ID"))
    }

    /// The stored `credentials.json`, or `None` before the first join.
    pub fn credentials(&self) -> Result<Option<Credentials>> {
        Err(Error::not_implemented("credentials"))
    }

    /// Replaces `credentials.json` atomically and durably, owner-only.
    pub fn store_credentials(&self, credentials: &Credentials) -> Result<()> {
        let _ = credentials;
        Err(Error::not_implemented("credentials"))
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
