//! The credential proxy (docs/proxy.md): a per-command HTTP proxy that sends requests for
//! chosen hosts through the control plane as `proxy.*` streams. Owned by the proxy track; the
//! scaffold froze the signatures.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::link::Outbox;
use crate::protocol::{ExecId, ProxyMessage, ProxySpec};

/// Where streams go: the link in the supervisor, an in-memory control plane in tests. Called
/// with internal locks held, so it must not block or call back into the proxy.
pub trait Upstream: Send + Sync + 'static {
    fn send(&self, message: ProxyMessage);
}

impl Upstream for Outbox {
    fn send(&self, message: ProxyMessage) {
        self.proxy(message);
    }
}

/// The node's certificate authority and its `public/ca-bundle.pem`. Cheap to clone.
#[derive(Clone)]
pub struct NodeCa {
    bundle: PathBuf,
}

impl NodeCa {
    /// Loads the CA from `private_dir`, creating it on first start, and rewrites
    /// `public_dir/ca-bundle.pem` with the platform's roots followed by the CA. Blocking. Both
    /// directories must exist.
    pub fn load_or_create(private_dir: &Path, public_dir: &Path) -> Result<NodeCa> {
        let _ = private_dir;
        Ok(NodeCa {
            bundle: public_dir.join("ca-bundle.pem"),
        })
    }

    pub fn bundle_path(&self) -> &Path {
        &self.bundle
    }
}

/// Every command's proxy on this node, and the streams they share. Cheap to clone.
#[derive(Clone)]
pub struct ProxyManager {
    ca: NodeCa,
}

impl ProxyManager {
    pub fn new(upstream: impl Upstream, ca: NodeCa) -> ProxyManager {
        let _ = upstream;
        ProxyManager { ca }
    }

    /// `public/ca-bundle.pem`, which sandboxed commands with a proxy may read.
    pub fn ca_bundle(&self) -> &Path {
        self.ca.bundle_path()
    }

    /// Starts the command's proxy on a loopback port. It runs until the lease is dropped.
    pub async fn start_for_exec(&self, exec_id: ExecId, spec: ProxySpec) -> Result<ProxyLease> {
        let _ = (exec_id, spec);
        Err(Error::not_implemented("the credential proxy"))
    }

    /// A `proxy.*` message from the control plane. Never blocks.
    pub fn on_event(&self, message: ProxyMessage) {
        let _ = message;
    }

    /// The session was lost: every open stream ends (proxy.md, Limits and failure).
    pub fn session_lost(&self) {}
}

/// A running command's proxy. Dropping it stops the proxy and resets its open streams.
pub struct ProxyLease {
    env: Vec<(String, String)>,
    bundle: PathBuf,
}

impl ProxyLease {
    /// The variables to set in the command's environment, replacing any given.
    pub fn env(&self) -> &[(String, String)] {
        &self.env
    }

    pub fn ca_bundle(&self) -> &Path {
        &self.bundle
    }
}
