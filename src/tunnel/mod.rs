//! TCP tunnels to the node's loopback ports (docs/tunnels.md): `tcp.open`, then `tcp.*`
//! streams in the same stream table, and under the same flow control, as the credential proxy.

use crate::error::{Error, ErrorKind, Result};
use crate::protocol::{TcpMessage, TcpOpenParams};
use crate::proxy::ProxyManager;

/// Every tunnel of this node. Cheap to clone.
#[derive(Clone)]
pub struct TunnelManager {
    _proxy: ProxyManager,
}

impl TunnelManager {
    /// Tunnels share `proxy`'s stream table, so the node-wide stream limit counts both.
    pub fn new(proxy: &ProxyManager) -> TunnelManager {
        TunnelManager {
            _proxy: proxy.clone(),
        }
    }

    /// Connects to the loopback port and opens the stream. `Ok` once connected.
    pub async fn open(&self, params: TcpOpenParams) -> Result<()> {
        let _ = params;
        Err(Error::new(ErrorKind::Io, "tcp.open is not implemented yet"))
    }

    /// A `tcp.*` message from the control plane. Never blocks.
    pub fn on_event(&self, message: TcpMessage) {
        let _ = message;
    }

    /// The session was lost: every tunnel is reset and its socket closed.
    pub fn session_lost(&self) {}
}
