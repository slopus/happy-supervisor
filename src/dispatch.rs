//! The request boundary: parses each method's params, resolves `access` once, and calls the
//! module that owns the method.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{Error, ErrorKind, Result};
use crate::events::{self, EventReceiver};
use crate::exec::ExecManager;
use crate::fs::{self, FsRequest};
use crate::policy::{Confinement, ResolvedPolicy};
use crate::protocol::{
    Access, EVENT_QUEUE_BYTES, Empty, ExecKillParams, ExecListResult, ExecLogParams,
    ExecStartParams, ExecWriteParams, FsMkdirParams, FsPathParams, FsReadParams, FsRemoveParams,
    FsWriteParams, Hello, Method, NodeInfo, RotateCredentialParams, SandboxInfo, WatchStartParams,
    WatchStopParams, WithAccess,
};
use crate::state::StateDir;
use crate::watch::WatchManager;

/// Everything one supervisor serves. Lives across connections.
pub struct Node {
    state: StateDir,
    installation_id: String,
    /// The joined name. `None` before joining, when NodeInfo falls back to the hostname.
    name: Option<String>,
    sandbox: SandboxInfo,
    exec: ExecManager,
    watch: WatchManager,
}

impl Node {
    /// Reads the installation ID and the joined name from `state` and probes the sandbox.
    /// Blocking.
    pub fn open(state: StateDir) -> Result<(Node, EventReceiver)> {
        let installation_id = state.installation_id()?;
        let name = state.credentials()?.map(|c| c.name);
        let sandbox = crate::sandbox::probe();
        Ok(Node::new(state, installation_id, name, sandbox))
    }

    pub fn new(
        state: StateDir,
        installation_id: String,
        name: Option<String>,
        sandbox: SandboxInfo,
    ) -> (Node, EventReceiver) {
        let (events, receiver) = events::channel(EVENT_QUEUE_BYTES);
        let node = Node {
            state,
            installation_id,
            name,
            sandbox,
            exec: ExecManager::new(events.clone()),
            watch: WatchManager::new(events),
        };
        (node, receiver)
    }

    pub fn sandbox(&self) -> &SandboxInfo {
        &self.sandbox
    }

    /// A freshly collected NodeInfo.
    pub async fn info(&self) -> Result<NodeInfo> {
        let installation_id = self.installation_id.clone();
        let name = self.name.clone();
        let sandbox = self.sandbox.clone();
        tokio::task::spawn_blocking(move || {
            crate::node_info::collect(&installation_id, name.as_deref(), &sandbox)
        })
        .await
        .map_err(|err| Error::new(ErrorKind::Io, format!("node info collection failed: {err}")))
    }

    /// The first frame of a connection.
    pub async fn hello(&self, node_id: String) -> Result<Hello> {
        Ok(Hello {
            node_id,
            installation_id: self.installation_id.clone(),
            version: crate::VERSION.to_string(),
            info: self.info().await?,
            execs: self.exec.list(),
            watches: self.watch.ids(),
        })
    }

    /// Kills every running command, for a normal exit.
    pub async fn shutdown(&self) {
        self.exec.shutdown().await;
    }

    async fn confine(&self, access: Access) -> Result<Confinement> {
        match access {
            Access::Raw {} => Ok(Confinement::Raw),
            Access::Sandboxed { policy } => {
                self.sandbox.require_available()?;
                let hidden = self.state.root().to_path_buf();
                let resolved =
                    tokio::task::spawn_blocking(move || ResolvedPolicy::resolve(&policy, &hidden))
                        .await
                        .map_err(|err| {
                            Error::new(ErrorKind::Io, format!("policy resolution failed: {err}"))
                        })?;
                Ok(Confinement::Sandboxed(resolved))
            }
        }
    }

    async fn rotate_credential(&self, params: RotateCredentialParams) -> Result<()> {
        let state = self.state.clone();
        tokio::task::spawn_blocking(move || {
            let mut credentials = state
                .credentials()?
                .ok_or_else(|| Error::new(ErrorKind::Io, "this node has no credentials"))?;
            credentials.node_token = params.node_token;
            state.store_credentials(&credentials)
        })
        .await
        .map_err(|err| Error::new(ErrorKind::Io, format!("credential rotation failed: {err}")))?
    }

    async fn fs(&self, request: FsRequest, access: Access) -> Result<Value> {
        let confinement = self.confine(access).await?;
        Ok(fs::handle(request, confinement).await?.into_value())
    }
}

/// Answers one request. The result is the JSON-RPC `result` or `error`.
pub async fn dispatch(node: &Node, method: &str, params: Value) -> Result<Value> {
    let method = Method::from_name(method).ok_or_else(|| {
        Error::new(
            ErrorKind::MethodNotFound,
            format!("unknown method `{method}`"),
        )
    })?;
    match method {
        Method::NodeInfo => {
            let Empty {} = parse(params)?;
            to_value(node.info().await?)
        }
        Method::NodeRotateCredential => {
            node.rotate_credential(parse(params)?).await?;
            to_value(Empty {})
        }
        Method::ExecStart => {
            let WithAccess { params, access } = parse::<WithAccess<ExecStartParams>>(params)?;
            let confinement = node.confine(access).await?;
            to_value(node.exec.start(params, confinement).await?)
        }
        Method::ExecWrite => {
            node.exec.write(parse::<ExecWriteParams>(params)?).await?;
            to_value(Empty {})
        }
        Method::ExecKill => {
            let ExecKillParams { exec_id, signal } = parse(params)?;
            node.exec.kill(&exec_id, signal)?;
            to_value(Empty {})
        }
        Method::ExecList => {
            let Empty {} = parse(params)?;
            to_value(ExecListResult {
                execs: node.exec.list(),
            })
        }
        Method::ExecLog => to_value(node.exec.log(parse::<ExecLogParams>(params)?).await?),
        Method::FsStat => {
            let WithAccess { params, access } = parse::<WithAccess<FsPathParams>>(params)?;
            node.fs(FsRequest::Stat(params), access).await
        }
        Method::FsList => {
            let WithAccess { params, access } = parse::<WithAccess<FsPathParams>>(params)?;
            node.fs(FsRequest::List(params), access).await
        }
        Method::FsRead => {
            let WithAccess { params, access } = parse::<WithAccess<FsReadParams>>(params)?;
            node.fs(FsRequest::Read(params), access).await
        }
        Method::FsWrite => {
            let WithAccess { params, access } = parse::<WithAccess<FsWriteParams>>(params)?;
            node.fs(FsRequest::Write(params), access).await
        }
        Method::FsMkdir => {
            let WithAccess { params, access } = parse::<WithAccess<FsMkdirParams>>(params)?;
            node.fs(FsRequest::Mkdir(params), access).await
        }
        Method::FsRemove => {
            let WithAccess { params, access } = parse::<WithAccess<FsRemoveParams>>(params)?;
            node.fs(FsRequest::Remove(params), access).await
        }
        Method::WatchStart => {
            let WithAccess { params, access } = parse::<WithAccess<WatchStartParams>>(params)?;
            let confinement = node.confine(access).await?;
            node.watch.start(params, confinement).await?;
            to_value(Empty {})
        }
        Method::WatchStop => {
            let WatchStopParams { watch_id } = parse(params)?;
            node.watch.stop(&watch_id)?;
            to_value(Empty {})
        }
    }
}

/// Absent params (`null`) parse as `{}`.
fn parse<T: DeserializeOwned>(params: Value) -> Result<T> {
    let params = match params {
        Value::Null => Value::Object(Default::default()),
        other => other,
    };
    serde_json::from_value(params).map_err(|err| Error::invalid_params(err.to_string()))
}

fn to_value(value: impl Serialize) -> Result<Value> {
    Ok(serde_json::to_value(value).expect("results serialize"))
}

#[cfg(all(test, unix))]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::protocol::{Mechanism, SandboxStatus};

    fn node() -> Node {
        let sandbox = SandboxInfo {
            mechanism: Mechanism::None,
            status: SandboxStatus::Unavailable {
                reason: "no sandbox in this test".to_string(),
            },
            baseline_read: vec![],
        };
        let state = StateDir::at("/nonexistent-state".into());
        Node::new(state, "tz4a98xxat96iws9zmbrgj3a".to_string(), None, sandbox).0
    }

    async fn call(method: &str, params: Value) -> Result<Value> {
        dispatch(&node(), method, params).await
    }

    #[tokio::test]
    async fn unknown_method() {
        assert_eq!(
            call("exec.nope", json!({})).await,
            Err(Error::new(
                ErrorKind::MethodNotFound,
                "unknown method `exec.nope`"
            ))
        );
    }

    #[tokio::test]
    async fn params_are_parsed_at_the_boundary() {
        let err = call("exec.kill", json!({ "execId": "bad id", "signal": "kill" }))
            .await
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidParams);
        assert_eq!(
            err.message,
            r#"execId must be 1 to 64 characters of [A-Za-z0-9_.-], got "bad id""#
        );
        let err = call("fs.stat", json!({ "path": "/x" })).await.unwrap_err();
        assert_eq!(err, Error::invalid_params("missing field `access`"));
    }

    #[tokio::test]
    async fn exec_list_answers_from_the_manager() {
        assert_eq!(
            call("exec.list", Value::Null).await,
            Ok(json!({ "execs": [] }))
        );
    }

    #[tokio::test]
    async fn sandboxed_access_is_refused_when_the_node_cannot_enforce_it() {
        let access = json!({
            "mode": "sandboxed",
            "policy": { "read": ["/"], "write": [], "localBind": false, "unixSockets": false }
        });
        let err = call("fs.stat", json!({ "path": "/", "access": access }))
            .await
            .unwrap_err();
        assert_eq!(err, Error::sandbox_unavailable("no sandbox in this test"));
        let err = call(
            "watch.start",
            json!({ "watchId": "w-1", "path": "/", "recursive": true, "access": access }),
        )
        .await
        .unwrap_err();
        assert_eq!(err, Error::sandbox_unavailable("no sandbox in this test"));
    }
}
