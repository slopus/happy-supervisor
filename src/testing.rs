//! An in-process control plane for tests (docs/architecture.md, Testing), behind the `testing`
//! feature. Owned by the transport track; the scaffold froze the API below. It speaks the link
//! protocol through [`link::Session`](crate::link::Session) with
//! [`Role::ControlPlane`](crate::link::Role::ControlPlane), one session per node.

use serde_json::Value;

use crate::error::{Error, Result};
use crate::protocol::{Event, NodeInfo};

/// api.md's join endpoint and the WebSocket endpoint it hands out, served by axum on
/// `127.0.0.1:0`.
pub struct ControlPlane {
    unbuilt: Unbuilt,
}

enum Unbuilt {}

/// One accepted join.
#[derive(Clone, Debug, PartialEq)]
pub struct JoinRecord {
    pub join_token: String,
    pub installation_id: String,
    pub name: String,
    pub info: NodeInfo,
    pub node_id: String,
    pub node_token: String,
}

impl ControlPlane {
    pub async fn start() -> Result<ControlPlane> {
        Err(Error::not_implemented("testing::ControlPlane"))
    }

    /// `http://127.0.0.1:<port>/…/join`, for `join --url`.
    pub fn join_url(&self) -> String {
        match self.unbuilt {}
    }

    /// The `ws://127.0.0.1:<port>/…` endpoint that joins answer with.
    pub fn endpoint(&self) -> String {
        match self.unbuilt {}
    }

    /// A fresh single-use join token.
    pub fn issue_join_token(&self) -> String {
        match self.unbuilt {}
    }

    pub fn joins(&self) -> Vec<JoinRecord> {
        match self.unbuilt {}
    }

    /// Sends a command to the connected node, waiting for it to connect first, and waits for
    /// the reply. An `error` reply becomes the `Err`.
    pub async fn command(&self, kind: &str, body: Value) -> Result<Value> {
        let _ = (kind, body);
        match self.unbuilt {}
    }

    /// The next event from the node, `node.ready` included.
    pub async fn next_event(&self) -> Result<Event> {
        match self.unbuilt {}
    }

    /// Closes the current WebSocket without `bye`. The session survives.
    pub fn drop_connection(&self) {
        match self.unbuilt {}
    }

    /// While stalled, received messages are processed but no `ack` is sent.
    pub fn stall_acks(&self, stalled: bool) {
        let _ = stalled;
        match self.unbuilt {}
    }

    /// Forgets the node's session, so its next `hello` gets `resumed: false`.
    pub fn forget_session(&self) {
        match self.unbuilt {}
    }

    pub fn set_resume_window_ms(&self, ms: u64) {
        let _ = ms;
        match self.unbuilt {}
    }

    /// Sends `bye` with `revoked`, and answers later upgrades with this node's token with `401`.
    pub fn revoke(&self, node_id: &str) {
        let _ = node_id;
        match self.unbuilt {}
    }
}
