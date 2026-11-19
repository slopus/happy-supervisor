//! Command proxies (docs/proxy.md and the v2 delta): one HTTP proxy and one SOCKS5 proxy per
//! command, outside the sandbox. They apply the command's `network.egress` and `ports`, resolve
//! names themselves and filter internal addresses, and send requests for the credential route's
//! hosts through the control plane as `proxy.*` streams.

mod address;
mod ca;
pub mod egress;
mod http;
pub mod socks5;

use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use rustls::crypto::CryptoProvider;

use crate::protocol::ProxyMessage;
use crate::streams::{Streams, Upstream};
pub use ca::NodeCa;
pub use egress::NetDenied;

use crate::error::{Error, ErrorKind, Result};

/// Turns a host name into addresses. The proxies never connect by name, so the addresses they
/// check are the ones they connect to.
pub trait Resolver: Send + Sync + 'static {
    /// Blocking; called on a blocking thread.
    fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>>;
}

/// The operating system's resolver.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        use std::net::ToSocketAddrs;
        Ok((host, 0).to_socket_addrs()?.map(|a| a.ip()).collect())
    }
}

/// What every command proxy on this node shares: the stream table, the CA, the resolver and
/// where `net.denied` goes. Cheap to clone.
#[derive(Clone)]
pub struct ProxyManager {
    streams: Arc<Streams>,
    ca: NodeCa,
    resolver: Arc<dyn Resolver>,
    on_denied: Arc<dyn Fn(NetDenied) + Send + Sync>,
}

impl ProxyManager {
    /// `on_denied` is called with locks held, so it must not block.
    pub fn new(
        upstream: impl Upstream,
        ca: NodeCa,
        on_denied: impl Fn(NetDenied) + Send + Sync + 'static,
    ) -> ProxyManager {
        ProxyManager {
            streams: Arc::new(Streams::new(Box::new(upstream))),
            ca,
            resolver: Arc::new(SystemResolver),
            on_denied: Arc::new(on_denied),
        }
    }

    pub fn with_resolver(self, resolver: impl Resolver) -> ProxyManager {
        ProxyManager {
            resolver: Arc::new(resolver),
            ..self
        }
    }

    /// `public/ca-bundle.pem`, which sandboxed commands with a credential route may read.
    pub fn ca_bundle(&self) -> &Path {
        self.ca.bundle_path()
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
