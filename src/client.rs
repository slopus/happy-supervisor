//! The connection to the control plane (docs/api.md, Connection). Owned by the transport
//! track; the scaffold froze the signature.

use crate::error::{Error, Result};
use crate::state::StateDir;

/// Why [`run`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunExit {
    /// The control plane refused the credential with `401` or `403`, or sent `bye` with
    /// `revoked`. The CLI exits `3`.
    Revoked,
    /// The supervisor was asked to stop (Ctrl-C or SIGTERM).
    Interrupted,
}

/// Connects to the stored endpoint and serves the control plane, redialing until revoked or
/// interrupted. Drives one [`link::Session`](crate::link::Session) across every connection.
/// Re-reads the credentials before each dial, so a `node.update` takes effect.
pub async fn run(state: StateDir) -> Result<RunExit> {
    let _ = state;
    Err(Error::not_implemented("run"))
}
