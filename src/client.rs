//! The connection to the control plane (docs/api.md, Connection). Owned by the transport
//! track; the scaffold froze the signature.

use crate::error::{Error, Result};
use crate::state::StateDir;

/// Why [`run`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunExit {
    /// The control plane refused the credential with `401` or `403`. The CLI exits `3`.
    Revoked,
    /// The supervisor was asked to stop (Ctrl-C or SIGTERM).
    Interrupted,
}

/// Connects with the stored credentials and serves requests, redialing until revoked or
/// interrupted. Re-reads the credentials before each dial, so a rotated token is used.
pub async fn run(state: StateDir) -> Result<RunExit> {
    let _ = state;
    Err(Error::not_implemented("run"))
}
