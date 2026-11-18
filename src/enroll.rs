//! Joining a control plane (docs/api.md, Joining and credentials). Owned by the transport
//! track; the scaffold froze the signature.

use crate::error::{Error, Result};
use crate::state::{Credentials, StateDir};

/// Exchanges a join token for node credentials and stores them. `name` defaults to the
/// hostname.
pub async fn join(
    server: &str,
    token: &str,
    name: Option<String>,
    state: &StateDir,
) -> Result<Credentials> {
    let _ = (server, token, name, state);
    Err(Error::not_implemented("join"))
}
