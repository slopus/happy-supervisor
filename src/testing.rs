//! An in-process control plane for tests (docs/architecture.md, Testing), behind the `testing`
//! feature. Owned by the transport track; the scaffold froze the API below.

use serde_json::Value;

use crate::error::{Error, Result};
use crate::protocol::Notification;

/// The api.md join and connect endpoints, served by axum on `127.0.0.1:0`.
pub struct ControlPlane {
    unbuilt: Unbuilt,
}

enum Unbuilt {}

/// One accepted `POST /v1/nodes/join`.
#[derive(Clone, Debug, PartialEq)]
pub struct JoinRecord {
    pub join_token: String,
    pub installation_id: String,
    pub info: Value,
    pub node_id: String,
    pub node_token: String,
}

impl ControlPlane {
    pub async fn start() -> Result<ControlPlane> {
        Err(Error::not_implemented("testing::ControlPlane"))
    }

    /// `http://127.0.0.1:<port>`, for `join --server`.
    pub fn url(&self) -> String {
        match self.unbuilt {}
    }

    /// A fresh single-use join token.
    pub fn issue_join_token(&self) -> String {
        match self.unbuilt {}
    }

    pub fn joins(&self) -> Vec<JoinRecord> {
        match self.unbuilt {}
    }

    /// Makes later upgrades with this node's token answer `401`, and closes its connection.
    pub fn revoke(&self, node_id: &str) {
        let _ = node_id;
        match self.unbuilt {}
    }

    /// Sends a request to the connected node, waiting for it to connect first. A JSON-RPC error
    /// answer becomes the `Err`.
    pub async fn request(&self, method: &str, params: Value) -> Result<Value> {
        let _ = (method, params);
        match self.unbuilt {}
    }

    /// The next notification from the connected node, `node.hello` included.
    pub async fn next_notification(&self) -> Result<Notification> {
        match self.unbuilt {}
    }
}
