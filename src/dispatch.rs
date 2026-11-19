//! The message boundary: parses each command's body, resolves `access` once, and calls the
//! module that owns the command. Stream messages from the control plane go to the proxy.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Error, ErrorKind, Result};
use crate::exec::ExecManager;
use crate::exec::TunnelRoute;
use crate::fs::{self, FsRequest};
use crate::link::Outbox;
use crate::policy::{Confinement, Network, ResolvedPolicy};
use crate::protocol::{
    Access, CommandKind, Empty, ExecId, ExecKillParams, ExecListResult, ExecLogParams,
    ExecStartParams, ExecSummary, ExecWriteParams, FsMkdirParams, FsPathParams, FsReadParams,
    FsRemoveParams, FsRenameParams, FsWriteParams, NodeInfo, NodeUpdate, ProxyMessage, ProxySpec,
    SandboxInfo, TcpMessage, TcpOpenParams, Value, WatchId, WatchStartParams, WatchStopParams,
    WithAccess,
};
use crate::proxy::egress::{self, CommandProxy, CommandProxyConfig, ListenOn};
use crate::proxy::{NodeCa, ProxyManager};
use crate::state::StateDir;
use crate::tunnel::TunnelManager;
use crate::watch::WatchManager;

/// The longest path a Unix socket address holds on Linux, without its terminating NUL.
const MAX_SOCKET_PATH: usize = 107;

/// Everything one supervisor serves. Lives across connections and sessions.
pub struct Node {
    state: StateDir,
    installation_id: String,
    /// The joined name. `None` before joining, when NodeInfo falls back to the hostname.
    name: Option<String>,
    sandbox: SandboxInfo,
    exec: ExecManager,
    watch: WatchManager,
    proxy: ProxyManager,
    tunnels: TunnelManager,
    /// Names the next directory under `private/net` for an isolated exec's proxy sockets.
    net_dirs: AtomicU64,
}

impl Node {
    /// Reads the installation ID and the joined name from `state`, loads the proxy CA (writing
    /// `public/ca-bundle.pem`) and probes the sandbox. Blocking.
    pub fn open(state: StateDir, outbox: Outbox) -> Result<Node> {
        let installation_id = state.installation_id()?;
        let name = state.credentials()?.map(|c| c.name);
        let ca = NodeCa::load_or_create(&state.private_dir(), &state.public_dir())?;
        let denied = outbox.clone();
        let proxy = ProxyManager::new(outbox.clone(), ca, move |event| denied.net_denied(event));
        let records = crate::sandbox::placeholder_records(&state.private_dir());
        if let Err(err) = crate::sandbox::Placeholders::sweep(&records) {
            tracing::warn!("removing a previous run's placeholders failed: {err}");
        }
        let _ = std::fs::remove_dir_all(state.private_dir().join("net"));
        let sandbox = crate::sandbox::probe();
        Ok(Node::new(
            state,
            installation_id,
            name,
            sandbox,
            outbox,
            proxy,
        ))
    }

    pub fn new(
        state: StateDir,
        installation_id: String,
        name: Option<String>,
        sandbox: SandboxInfo,
        outbox: Outbox,
        proxy: ProxyManager,
    ) -> Node {
        Node {
            state,
            installation_id,
            name,
            sandbox,
            exec: ExecManager::new(outbox.clone()),
            watch: WatchManager::new(outbox),
            tunnels: TunnelManager::new(&proxy),
            proxy,
            net_dirs: AtomicU64::new(0),
        }
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

    /// The processes and watches a new session's `node.ready` lists, with fresh NodeInfo. The
    /// driver passes them to [`Session::ready`](crate::link::Session::ready).
    pub async fn ready_state(&self) -> Result<(NodeInfo, Vec<ExecSummary>, Vec<WatchId>)> {
        Ok((self.info().await?, self.exec.list(), self.watch.ids()))
    }

    /// The session was lost (api.md, Lost sessions): every open proxy stream ends.
    pub fn session_lost(&self) {
        self.proxy.session_lost();
        self.tunnels.session_lost();
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
                let hidden = self.state.private_dir();
                let resolved =
                    tokio::task::spawn_blocking(move || ResolvedPolicy::resolve(&policy, &hidden))
                        .await
                        .map_err(|err| {
                            Error::new(ErrorKind::Io, format!("policy resolution failed: {err}"))
                        })??;
                Ok(Confinement::Sandboxed(resolved))
            }
        }
    }

    /// Starts an exec's command proxy, when its policy isolates its network or it has a
    /// credential route (proxy.md). A credential route's CA bundle becomes readable.
    async fn command_proxy(
        &self,
        exec_id: &ExecId,
        credential: Option<ProxySpec>,
        confinement: &mut Confinement,
    ) -> Result<Option<CommandProxy>> {
        let egress = match &*confinement {
            Confinement::Sandboxed(policy) => match policy.network() {
                Network::Isolated { egress, ports, .. } => Some((egress.clone(), ports.clone())),
                Network::Host { .. } => None,
            },
            Confinement::Raw => None,
        };
        if egress.is_none() && credential.is_none() {
            return Ok(None);
        }
        let config = CommandProxyConfig {
            exec_id: exec_id.clone(),
            listen: self.proxy_listen(egress.is_some())?,
            egress,
            credential,
        };
        let proxy = egress::start(config, &self.proxy).await?;
        if let (Confinement::Sandboxed(policy), Some(bundle)) = (confinement, proxy.ca_bundle()) {
            policy.allow_read_file(bundle);
        }
        Ok(Some(proxy))
    }

    /// An isolated Linux sandbox has its own loopback, so it reaches its proxies through Unix
    /// sockets the helper bridges. A socket's path must fit the 108 bytes of a socket address,
    /// so their directory is a counter. An isolated Windows sandbox reaches only the loopback
    /// ports its firewall filters permit, which `install-sandbox` fixed.
    fn proxy_listen(&self, isolated: bool) -> Result<ListenOn> {
        #[cfg(windows)]
        if isolated {
            return crate::sandbox::windows::proxy_ports()
                .map(ListenOn::LoopbackRange)
                .ok_or_else(|| {
                    Error::sandbox_unavailable(
                        "the sandbox is not installed: run `happy-supervisor install-sandbox` \
                         as an administrator",
                    )
                });
        }
        if !(cfg!(target_os = "linux") && isolated) {
            return Ok(ListenOn::Loopback);
        }
        let n = self.net_dirs.fetch_add(1, Ordering::Relaxed);
        let dir = self.state.private_dir().join("net").join(n.to_string());
        let longest = dir.join("socks.sock").as_os_str().len();
        if longest > MAX_SOCKET_PATH {
            return Err(Error::sandbox_unavailable(format!(
                "the state directory's path is too long for the proxy sockets of isolated \
                 networking: {} is {longest} bytes, over {MAX_SOCKET_PATH}",
                dir.join("socks.sock").display()
            )));
        }
        Ok(ListenOn::UnixDir(dir))
    }

    async fn update(&self, update: NodeUpdate) -> Result<()> {
        if let Some(endpoint) = &update.endpoint {
            crate::enroll::check_url(endpoint, "wss", "ws")?;
        }
        let state = self.state.clone();
        tokio::task::spawn_blocking(move || {
            let mut credentials = state
                .credentials()?
                .ok_or_else(|| Error::new(ErrorKind::Io, "this node has no credentials"))?;
            if let Some(node_token) = update.node_token {
                credentials.node_token = node_token;
            }
            if let Some(endpoint) = update.endpoint {
                credentials.endpoint = endpoint;
            }
            state.store_credentials(&credentials)
        })
        .await
        .map_err(|err| Error::new(ErrorKind::Io, format!("node.update failed: {err}")))?
    }

    async fn fs(&self, request: FsRequest, access: Access) -> Result<Value> {
        let confinement = self.confine(access).await?;
        Ok(fs::handle(request, confinement).await?.into_value())
    }
}

/// Handles one message from the control plane. A command's result is the reply's `ok` or
/// `error`. A `proxy.*` stream message goes to the proxy and gets no reply (`None`); the node
/// drops one it cannot parse, and `proxy.request`, which only the node sends. Any other kind,
/// including an event the node does not know, is `unknown_kind` (api.md, Errors).
pub async fn dispatch(node: &Node, kind: &str, body: Value) -> Option<Result<Value>> {
    if TcpMessage::KINDS.contains(&kind) {
        match TcpMessage::parse(kind, body) {
            Ok(message) => node.tunnels.on_event(message),
            Err(err) => tracing::warn!("dropped a malformed {kind}: {err}"),
        }
        return None;
    }
    if !ProxyMessage::KINDS.contains(&kind) {
        return Some(command(node, kind, body).await);
    }
    match ProxyMessage::parse(kind, body) {
        Ok(ProxyMessage::Request(_)) => {
            tracing::warn!("dropped a proxy.request from the control plane");
        }
        Ok(message) => node.proxy.on_event(message),
        Err(err) => tracing::warn!("dropped a malformed {kind}: {err}"),
    }
    None
}

async fn command(node: &Node, kind: &str, body: Value) -> Result<Value> {
    let kind = CommandKind::from_name(kind).ok_or_else(|| {
        Error::new(
            ErrorKind::UnknownKind,
            format!("unknown message kind `{kind}`"),
        )
    })?;
    let params = body;
    match kind {
        CommandKind::NodeInfo => {
            let Empty {} = parse(params)?;
            to_value(node.info().await?)
        }
        CommandKind::NodeUpdate => {
            node.update(parse(params)?).await?;
            to_value(Empty {})
        }
        CommandKind::ExecStart => {
            let WithAccess { mut params, access } = parse::<WithAccess<ExecStartParams>>(params)?;
            let mut confinement = node.confine(access).await?;
            let proxy = node
                .command_proxy(&params.exec_id, params.proxy.take(), &mut confinement)
                .await?;
            to_value(node.exec.start(params, confinement, proxy).await?)
        }
        CommandKind::ExecWrite => {
            node.exec.write(parse::<ExecWriteParams>(params)?).await?;
            to_value(Empty {})
        }
        CommandKind::ExecKill => {
            let ExecKillParams { exec_id, signal } = parse(params)?;
            node.exec.kill(&exec_id, signal)?;
            to_value(Empty {})
        }
        CommandKind::ExecList => {
            let Empty {} = parse(params)?;
            to_value(ExecListResult {
                execs: node.exec.list(),
            })
        }
        CommandKind::ExecLog => to_value(node.exec.log(parse::<ExecLogParams>(params)?).await?),
        CommandKind::FsStat => {
            let WithAccess { params, access } = parse::<WithAccess<FsPathParams>>(params)?;
            node.fs(FsRequest::Stat(params), access).await
        }
        CommandKind::FsList => {
            let WithAccess { params, access } = parse::<WithAccess<FsPathParams>>(params)?;
            node.fs(FsRequest::List(params), access).await
        }
        CommandKind::FsRead => {
            let WithAccess { params, access } = parse::<WithAccess<FsReadParams>>(params)?;
            node.fs(FsRequest::Read(params), access).await
        }
        CommandKind::FsWrite => {
            let WithAccess { params, access } = parse::<WithAccess<FsWriteParams>>(params)?;
            node.fs(FsRequest::Write(params), access).await
        }
        CommandKind::FsMkdir => {
            let WithAccess { params, access } = parse::<WithAccess<FsMkdirParams>>(params)?;
            node.fs(FsRequest::Mkdir(params), access).await
        }
        CommandKind::FsRemove => {
            let WithAccess { params, access } = parse::<WithAccess<FsRemoveParams>>(params)?;
            node.fs(FsRequest::Remove(params), access).await
        }
        CommandKind::FsRename => {
            let WithAccess { params, access } = parse::<WithAccess<FsRenameParams>>(params)?;
            node.fs(FsRequest::Rename(params), access).await
        }
        CommandKind::WatchStart => {
            let WithAccess { params, access } = parse::<WithAccess<WatchStartParams>>(params)?;
            let confinement = node.confine(access).await?;
            node.watch.start(params, confinement).await?;
            to_value(Empty {})
        }
        CommandKind::TcpOpen => {
            let params: TcpOpenParams = parse(params)?;
            let route = match &params.exec_id {
                Some(exec_id) => node.exec.tunnel_route(exec_id)?,
                None => TunnelRoute::Loopback,
            };
            node.tunnels.open(params, route).await?;
            to_value(Empty {})
        }
        CommandKind::WatchStop => {
            let WatchStopParams { watch_id } = parse(params)?;
            node.watch.stop(&watch_id)?;
            to_value(Empty {})
        }
    }
}

/// An absent body (`null`) parses as `{}`.
fn parse<T: DeserializeOwned>(params: Value) -> Result<T> {
    let params = match params {
        Value::Null => Value::Map(Vec::new()),
        other => other,
    };
    crate::wire::from_value(params).map_err(Error::invalid_params)
}

fn to_value(value: impl Serialize) -> Result<Value> {
    Ok(crate::wire::to_value(&value))
}

#[cfg(all(test, unix))]
mod tests {
    use serde_json::json;

    use crate::testkit::cbor;

    use super::*;
    use crate::link::{ManualClock, NodeIdentity, Role, Session};
    use crate::protocol::{Mechanism, SandboxStatus};

    /// A node in a fresh state directory, which lives as long as the returned guard.
    fn node() -> (Node, tempfile::TempDir) {
        let sandbox = SandboxInfo {
            mechanism: Mechanism::None,
            status: SandboxStatus::Unavailable {
                reason: "no sandbox in this test".to_string(),
            },
            baseline_read: vec![],
            gaps: vec![],
        };
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::at(dir.path().to_path_buf());
        std::fs::create_dir(state.private_dir()).unwrap();
        std::fs::create_dir(state.public_dir()).unwrap();
        let identity = NodeIdentity {
            node_id: "n_1".to_string(),
            installation_id: "tz4a98xxat96iws9zmbrgj3a".to_string(),
        };
        let (_session, outbox) = Session::new(Role::Node(identity), ManualClock::new(0));
        let ca = NodeCa::load_or_create(&state.private_dir(), &state.public_dir()).unwrap();
        let proxy = ProxyManager::new(outbox.clone(), ca, |_| {});
        let installation_id = "tz4a98xxat96iws9zmbrgj3a".to_string();
        let node = Node::new(state, installation_id, None, sandbox, outbox, proxy);
        (node, dir)
    }

    async fn call(method: &str, params: serde_json::Value) -> Result<Value> {
        let (node, _dir) = node();
        dispatch(&node, method, cbor(params))
            .await
            .expect("a command gets a reply")
    }

    #[tokio::test]
    async fn stream_messages_get_no_reply() {
        let (node, _dir) = node();
        let stream = "u'0193a3b4-0000-7000-8000-000000000001'";
        for (kind, body) in [
            (
                "proxy.response",
                json!({ "streamId": stream, "status": 200, "headers": [] }),
            ),
            ("proxy.body", json!({ "streamId": stream, "data": "h'00'" })),
            ("proxy.end", json!({ "streamId": stream })),
            (
                "proxy.reset",
                json!({ "streamId": stream, "reason": "gone" }),
            ),
            ("proxy.credit", json!({ "streamId": stream, "bytes": 1 })),
            ("proxy.end", json!({ "streamId": "not a uuid" })),
            ("proxy.request", json!({})),
        ] {
            assert_eq!(dispatch(&node, kind, cbor(body)).await, None, "{kind}");
        }
    }

    #[tokio::test]
    async fn unknown_kind() {
        assert_eq!(
            call("exec.nope", json!({})).await,
            Err(Error::new(
                ErrorKind::UnknownKind,
                "unknown message kind `exec.nope`"
            ))
        );
        assert_eq!(
            call("reply", json!({})).await.unwrap_err().kind,
            ErrorKind::UnknownKind
        );
    }

    #[tokio::test]
    async fn bodies_are_parsed_at_the_boundary() {
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
        let err = call("node.update", json!({})).await.unwrap_err();
        assert_eq!(
            err,
            Error::invalid_params("node.update needs nodeToken, endpoint or both")
        );
    }

    #[tokio::test]
    async fn exec_list_answers_from_the_manager() {
        assert_eq!(
            call("exec.list", serde_json::Value::Null).await,
            Ok(cbor(json!({ "execs": [] })))
        );
    }

    #[tokio::test]
    async fn sandboxed_access_is_refused_when_the_node_cannot_enforce_it() {
        let access = json!({
            "mode": "sandboxed",
            "policy": {
                "filesystem": {
                    "read": { "default": "allow", "allow": [], "deny": [] },
                    "write": { "default": "deny", "allow": [], "deny": [] }
                },
                "network": { "mode": "host", "localBind": false, "unixSockets": false }
            }
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
