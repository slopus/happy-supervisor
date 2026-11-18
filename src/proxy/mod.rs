//! The credential proxy (docs/proxy.md): a per-command HTTP proxy that sends requests for
//! chosen hosts through the control plane as `proxy.*` streams. Owned by the proxy track; the
//! scaffold froze the signatures.

mod ca;
mod server;

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use base64::Engine;
use rustls::crypto::CryptoProvider;

use crate::protocol::{ExecId, ProxyMessage, ProxySpec};
use crate::streams::{Streams, Upstream};
pub use ca::NodeCa;
use server::{Proxy, Tasks};

use crate::error::{Error, ErrorKind, Result};

/// Every command's proxy on this node, and the streams they share. Cheap to clone.
#[derive(Clone)]
pub struct ProxyManager {
    streams: Arc<Streams>,
    ca: NodeCa,
}

impl ProxyManager {
    pub fn new(upstream: impl Upstream, ca: NodeCa) -> ProxyManager {
        ProxyManager {
            streams: Arc::new(Streams::new(Box::new(upstream))),
            ca,
        }
    }

    /// `public/ca-bundle.pem`, which sandboxed commands with a proxy may read.
    pub fn ca_bundle(&self) -> &Path {
        self.ca.bundle_path()
    }

    /// Starts the command's proxy on a loopback port. It runs until the lease is dropped.
    pub async fn start_for_exec(&self, exec_id: ExecId, spec: ProxySpec) -> Result<ProxyLease> {
        let mut secret = [0u8; 32];
        random_bytes(&mut secret)?;
        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
        let proxy = Arc::new(Proxy {
            exec_id: exec_id.clone(),
            token: spec.token,
            hosts: spec.hosts,
            credentials: format!("happy:{secret}"),
            streams: self.streams.clone(),
            ca: self.ca.clone(),
            tasks: Tasks::open(),
        });
        let port = server::listen(proxy.clone()).await?;
        let url = format!("http://happy:{secret}@127.0.0.1:{port}");
        let bundle = self.ca.bundle_path().to_path_buf();
        let bundle_text = bundle.to_string_lossy().into_owned();
        let env = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
            .into_iter()
            .map(|name| (name.to_owned(), url.clone()))
            .chain(
                [
                    "SSL_CERT_FILE",
                    "CURL_CA_BUNDLE",
                    "REQUESTS_CA_BUNDLE",
                    "NODE_EXTRA_CA_CERTS",
                    "GIT_SSL_CAINFO",
                ]
                .into_iter()
                .map(|name| (name.to_owned(), bundle_text.clone())),
            )
            .collect();
        Ok(ProxyLease { proxy, env, bundle })
    }

    /// A `proxy.*` message from the control plane. Never blocks.
    pub fn on_event(&self, message: ProxyMessage) {
        self.streams.on_proxy(message);
    }

    /// The session was lost: every open stream ends (proxy.md, Limits and failure).
    pub fn session_lost(&self) {
        self.streams.session_lost();
    }

    /// The node's stream table, which tunnels share.
    pub(crate) fn streams(&self) -> &Arc<Streams> {
        &self.streams
    }
}

/// A running command's proxy. Dropping it stops the proxy and resets its open streams.
pub struct ProxyLease {
    proxy: Arc<Proxy>,
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

impl Drop for ProxyLease {
    fn drop(&mut self) {
        self.proxy.streams.exec_stopped(&self.proxy.exec_id);
        self.proxy.tasks.close();
    }
}

fn crypto_provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

fn random_bytes(buf: &mut [u8]) -> Result<()> {
    crypto_provider()
        .secure_random
        .fill(buf)
        .map_err(|_| Error::new(ErrorKind::Io, "the system random source failed"))
}
