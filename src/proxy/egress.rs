//! One command's proxy (v2 proxy.md): its HTTP and SOCKS5 listeners, the decision every
//! outbound request goes through, the `net.denied` events, and the command's environment.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use super::{ProxyManager, address, http, socks5};
use crate::policy::{HostRules, host_allowed};
use crate::protocol::{ExecId, HostPattern, ProxyToken, TCP_CONNECT_TIMEOUT_MS};
use crate::sandbox::Endpoint;

pub use crate::protocol::ProxySpec as CredentialRoute;

/// Where the command reaches the HTTP proxy when it listens on a [`ListenOn::UnixDir`]: inside
/// the sandbox's network namespace, where the sandbox helper bridges it to `http.sock`.
pub const SANDBOX_HTTP: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3128);
/// Likewise for the SOCKS5 proxy and `socks.sock`.
pub const SANDBOX_SOCKS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080);

/// `net.denied` events per command per second; the rest are counted in `dropped`.
const DENIED_PER_SECOND: usize = 20;

pub struct CommandProxyConfig {
    pub exec_id: ExecId,
    /// `network.egress` and `network.ports` of an isolated command. `None` in host mode.
    pub egress: Option<(HostRules, Option<Vec<u16>>)>,
    pub credential: Option<CredentialRoute>,
    pub listen: ListenOn,
}

pub enum ListenOn {
    /// `127.0.0.1:<ephemeral>`, one port each.
    Loopback,
    /// `127.0.0.1` at the first free ports of this range, HTTP first. On Windows the sandbox's
    /// firewall filters permit only the range the install recorded.
    LoopbackRange(RangeInclusive<u16>),
    /// `http.sock` and `socks.sock` in this existing directory. Unix only.
    UnixDir(PathBuf),
}

/// `net.denied` (v2 proxy.md). Moves to `protocol.rs` when the integrator lands it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetDenied {
    pub exec_id: ExecId,
    pub host: String,
    pub port: u16,
    pub via: Via,
    pub reason: DenyReason,
    /// Refusals not reported since the previous event, because of the rate limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Via {
    Http,
    Socks5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DenyReason {
    /// The host does not pass `egress`.
    Egress,
    /// The port is not in `ports`.
    Port,
    /// Every address the name resolved to is internal.
    Address,
    /// The name resolved to nothing.
    Resolve,
    /// A credential-route host through SOCKS5, where the node cannot rewrite the request.
    Credential,
}

impl DenyReason {
    /// The one line an HTTP client gets with `403`.
    pub(crate) fn explain(self, host: &str, port: u16) -> String {
        let why = match self {
            DenyReason::Egress => "the host is not allowed by the network policy",
            DenyReason::Port => "the port is not allowed by the network policy",
            DenyReason::Address => "the host resolves only to internal addresses",
            DenyReason::Resolve => "the host does not resolve",
            DenyReason::Credential => "credential-route hosts are reachable only over HTTP",
        };
        format!("happy-supervisor refused {host}:{port}: {why}\n")
    }
}

/// What happens to one outbound request.
pub(crate) enum Route {
    /// Through the control plane (proxy.md, How requests travel).
    Credential,
    /// Straight out, to the first of these checked addresses that accepts.
    Direct(Vec<SocketAddr>),
    /// Refused by policy; a `net.denied` was sent or counted.
    Refused(DenyReason),
    /// Host mode only: the name did not resolve. Not a policy decision, so no event.
    Unresolved,
}

/// The isolated command's `network.egress` and `network.ports`.
struct Egress {
    rules: HostRules,
    ports: Option<Vec<u16>>,
    /// IP literals in `egress.allow`, which the address filter lets through.
    literals: Vec<IpAddr>,
}

/// One command's proxies, shared by their connections.
pub(crate) struct Command {
    pub(crate) exec_id: ExecId,
    egress: Option<Egress>,
    pub(crate) credential: Option<(ProxyToken, Vec<HostPattern>)>,
    /// `happy:<secret>`, which `proxy-authorization` must carry. Set when the HTTP proxy has a
    /// credential route and listens on TCP, where any local process could reach it.
    pub(crate) password: Option<String>,
    pub(crate) node: ProxyManager,
    limiter: Mutex<Limiter>,
    pub(crate) tasks: Tasks,
}

impl Command {
    /// The decision order of v2 proxy.md: credential route, egress, resolve and filter.
    pub(crate) async fn route(&self, host: &str, port: u16, via: Via) -> Route {
        let host = normalize(host);
        let host = host.as_str();
        if self.credential_host(host) {
            return match (via, &self.egress) {
                (Via::Socks5, _) => self.refuse(host, port, via, DenyReason::Credential),
                (Via::Http, Some(egress)) if !host_allowed(&egress.rules, host) => {
                    self.refuse(host, port, via, DenyReason::Egress)
                }
                (Via::Http, _) => Route::Credential,
            };
        }
        let Some(egress) = &self.egress else {
            return match self.resolve(host).await {
                Some(ips) => Route::Direct(ips.into_iter().map(|ip| (ip, port).into()).collect()),
                None => Route::Unresolved,
            };
        };
        if !host_allowed(&egress.rules, host) {
            return self.refuse(host, port, via, DenyReason::Egress);
        }
        if egress
            .ports
            .as_ref()
            .is_some_and(|ports| !ports.contains(&port))
        {
            return self.refuse(host, port, via, DenyReason::Port);
        }
        let Some(ips) = self.resolve(host).await else {
            return self.refuse(host, port, via, DenyReason::Resolve);
        };
        let own = address::own_addresses();
        let allowed: Vec<SocketAddr> = ips
            .into_iter()
            .filter(|ip| egress.literals.contains(ip) || !address::internal(*ip, &own))
            .map(|ip| (ip, port).into())
            .collect();
        if allowed.is_empty() {
            return self.refuse(host, port, via, DenyReason::Address);
        }
        Route::Direct(allowed)
    }

    pub(crate) fn credential_host(&self, host: &str) -> bool {
        self.credential
            .as_ref()
            .is_some_and(|(_, hosts)| hosts.iter().any(|pattern| pattern.matches(host)))
    }

    /// The host's addresses, canonical (IPv4-mapped as IPv4). `None` when there are none.
    async fn resolve(&self, host: &str) -> Option<Vec<IpAddr>> {
        let ips = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => {
                let resolver = self.node.resolver.clone();
                let name = host.to_owned();
                tokio::task::spawn_blocking(move || resolver.lookup(&name))
                    .await
                    .ok()?
                    .ok()?
            }
        };
        let mut ips: Vec<IpAddr> = ips.into_iter().map(|ip| ip.to_canonical()).collect();
        ips.dedup();
        (!ips.is_empty()).then_some(ips)
    }

    fn refuse(&self, host: &str, port: u16, via: Via, reason: DenyReason) -> Route {
        let mut limiter = self.limiter.lock().unwrap();
        if let Admit::Send { dropped } = limiter.admit(Instant::now()) {
            (self.node.on_denied)(NetDenied {
                exec_id: self.exec_id.clone(),
                host: host.to_owned(),
                port,
                via,
                reason,
                dropped,
            });
        }
        Route::Refused(reason)
    }
}

/// Lowercase, no trailing dot, no IPv6 brackets, IP literals in canonical form.
pub(crate) fn normalize(host: &str) -> String {
    let host = host.strip_suffix('.').unwrap_or(host);
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.to_canonical().to_string(),
        Err(_) => host.to_ascii_lowercase(),
    }
}

/// Connects to the first address that accepts, each within the tunnel connect timeout.
pub(crate) async fn connect(addresses: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::InvalidInput, "no address");
    for address in addresses {
        let timeout = Duration::from_millis(TCP_CONNECT_TIMEOUT_MS);
        match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
            Ok(Ok(tcp)) => {
                let _ = tcp.set_nodelay(true);
                return Ok(tcp);
            }
            Ok(Err(err)) => last = err,
            Err(_) => last = io::Error::new(io::ErrorKind::TimedOut, "connect timed out"),
        }
    }
    Err(last)
}

/// A sliding one-second window of the events sent, and the refusals since the last one.
#[derive(Default)]
pub(crate) struct Limiter {
    sent: VecDeque<Instant>,
    dropped: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admit {
    Send { dropped: Option<u64> },
    Drop,
}

impl Limiter {
    pub(crate) fn admit(&mut self, now: Instant) -> Admit {
        while self
            .sent
            .front()
            .is_some_and(|&at| now.duration_since(at) >= Duration::from_secs(1))
        {
            self.sent.pop_front();
        }
        if self.sent.len() >= DENIED_PER_SECOND {
            self.dropped += 1;
            return Admit::Drop;
        }
        self.sent.push_back(now);
        let dropped = std::mem::take(&mut self.dropped);
        Admit::Send {
            dropped: (dropped > 0).then_some(dropped),
        }
    }
}

/// The proxy's tasks. Closing aborts them and refuses new ones.
#[derive(Default)]
pub(crate) struct Tasks(Mutex<Option<JoinSet<()>>>);

impl Tasks {
    fn open() -> Tasks {
        Tasks(Mutex::new(Some(JoinSet::new())))
    }

    pub(crate) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        if let Some(set) = self.0.lock().unwrap().as_mut() {
            while set.try_join_next().is_some() {}
            set.spawn(task);
        }
    }

    fn close(&self) {
        self.0.lock().unwrap().take();
    }
}

/// A byte stream a proxy serves: TCP or a Unix socket.
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
}

impl Listener {
    /// `after` is the port the other listener of the pair took in a range.
    async fn bind(
        listen: &ListenOn,
        name: &str,
        after: Option<u16>,
    ) -> io::Result<(Listener, Endpoint)> {
        match listen {
            ListenOn::Loopback => {
                let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let address = tcp.local_addr()?;
                Ok((Listener::Tcp(tcp), Endpoint::Tcp(address)))
            }
            ListenOn::LoopbackRange(range) => {
                let first = after.map_or(*range.start(), |port| port.saturating_add(1));
                for port in first..=*range.end() {
                    if let Ok(tcp) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
                        let address = tcp.local_addr()?;
                        return Ok((Listener::Tcp(tcp), Endpoint::Tcp(address)));
                    }
                }
                Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("no free proxy port in {}-{}", range.start(), range.end()),
                ))
            }
            #[cfg(unix)]
            ListenOn::UnixDir(dir) => {
                let path = dir.join(name);
                let unix = tokio::net::UnixListener::bind(&path)?;
                Ok((Listener::Unix(unix), Endpoint::Unix(path)))
            }
            #[cfg(not(unix))]
            ListenOn::UnixDir(_) => {
                let _ = name;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Unix socket listeners need a Unix host",
                ))
            }
        }
    }

    async fn accept(&self) -> io::Result<Box<dyn Io>> {
        match self {
            Listener::Tcp(tcp) => {
                let (stream, _) = tcp.accept().await?;
                let _ = stream.set_nodelay(true);
                Ok(Box::new(stream))
            }
            #[cfg(unix)]
            Listener::Unix(unix) => Ok(Box::new(unix.accept().await?.0)),
        }
    }
}

async fn accept<F, Fut>(listener: Listener, command: Arc<Command>, serve: F)
where
    F: Fn(Arc<Command>, Box<dyn Io>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    loop {
        match listener.accept().await {
            Ok(stream) => command.tasks.spawn(serve(command.clone(), stream)),
            Err(err) => {
                tracing::warn!(exec_id = %command.exec_id, "proxy accept failed: {err}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// A running command proxy. Dropping it stops both listeners, resets the command's open
/// streams and removes its Unix sockets.
pub struct CommandProxy {
    pub http: Endpoint,
    pub socks: Endpoint,
    command: Arc<Command>,
}

/// Starts the command's HTTP and SOCKS5 proxies.
pub async fn start(cfg: CommandProxyConfig, node: &ProxyManager) -> io::Result<CommandProxy> {
    let CommandProxyConfig {
        exec_id,
        egress,
        credential,
        listen,
    } = cfg;
    let password = match (&credential, &listen) {
        (Some(_), ListenOn::Loopback | ListenOn::LoopbackRange(_)) => {
            let mut secret = [0u8; 32];
            super::random_bytes(&mut secret).map_err(io::Error::other)?;
            let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
            Some(format!("happy:{secret}"))
        }
        _ => None,
    };
    let egress = egress.map(|(rules, ports)| Egress {
        literals: rules
            .allow
            .iter()
            .filter_map(|entry| normalize(entry).parse::<IpAddr>().ok())
            .collect(),
        rules,
        ports,
    });
    let command = Arc::new(Command {
        exec_id,
        egress,
        credential: credential.map(|route| (route.token, route.hosts)),
        password,
        node: node.clone(),
        limiter: Mutex::default(),
        tasks: Tasks::open(),
    });
    let (http_listener, http) = Listener::bind(&listen, "http.sock", None).await?;
    let http_port = match &http {
        Endpoint::Tcp(address) => Some(address.port()),
        Endpoint::Unix(_) => None,
    };
    let (socks_listener, socks) = match Listener::bind(&listen, "socks.sock", http_port).await {
        Ok(bound) => bound,
        Err(err) => {
            remove_socket(&http);
            return Err(err);
        }
    };
    command
        .tasks
        .spawn(accept(http_listener, command.clone(), http::serve));
    command
        .tasks
        .spawn(accept(socks_listener, command.clone(), socks5::serve));
    Ok(CommandProxy {
        http,
        socks,
        command,
    })
}

impl CommandProxy {
    /// The variables to set in the command's environment, replacing any given.
    /// `supervisor` is this binary, which `GIT_SSH_COMMAND` runs as `__connect`.
    pub fn env(&self, supervisor: &Path) -> Vec<(String, String)> {
        let (http, socks) = match (&self.http, &self.socks) {
            (Endpoint::Tcp(http), Endpoint::Tcp(socks)) => (*http, *socks),
            _ => (SANDBOX_HTTP, SANDBOX_SOCKS),
        };
        let credential = self.ca_bundle().map(|ca_bundle| CredentialEnv {
            password: self.command.password.as_deref(),
            ca_bundle,
        });
        command_env(&match (&self.command.egress, credential) {
            (Some(_), credential) => CommandEnv::Isolated {
                http,
                socks,
                supervisor,
                credential,
            },
            (None, Some(credential)) => CommandEnv::Host { http, credential },
            (None, None) => return Vec::new(),
        })
    }

    /// The CA bundle the command must be able to read, when it has a credential route.
    pub fn ca_bundle(&self) -> Option<&Path> {
        self.command
            .credential
            .as_ref()
            .map(|_| self.command.node.ca_bundle())
    }
}

impl Drop for CommandProxy {
    fn drop(&mut self) {
        self.command
            .node
            .streams
            .exec_stopped(&self.command.exec_id);
        self.command.tasks.close();
        remove_socket(&self.http);
        remove_socket(&self.socks);
    }
}

fn remove_socket(endpoint: &Endpoint) {
    if let Endpoint::Unix(path) = endpoint {
        let _ = std::fs::remove_file(path);
    }
}

/// What the command's environment points at (v2 proxy.md, What the command sees).
pub enum CommandEnv<'a> {
    /// A host-mode command with a credential route.
    Host {
        http: SocketAddr,
        credential: CredentialEnv<'a>,
    },
    Isolated {
        http: SocketAddr,
        socks: SocketAddr,
        supervisor: &'a Path,
        credential: Option<CredentialEnv<'a>>,
    },
}

pub struct CredentialEnv<'a> {
    /// `happy:<secret>` for a proxy on a TCP port.
    pub password: Option<&'a str>,
    pub ca_bundle: &'a Path,
}

const CA_VARIABLES: [&str; 5] = [
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
];

/// The command's proxy variables, which replace any the control plane passed.
pub fn command_env(env: &CommandEnv) -> Vec<(String, String)> {
    let (http, credential) = match env {
        CommandEnv::Host { http, credential } => (*http, Some(credential)),
        CommandEnv::Isolated {
            http, credential, ..
        } => (*http, credential.as_ref()),
    };
    let http_url = match credential.and_then(|c| c.password) {
        Some(password) => format!("http://{password}@{http}"),
        None => format!("http://{http}"),
    };
    let mut vars: Vec<(String, String)> =
        ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
            .into_iter()
            .map(|name| (name.to_owned(), http_url.clone()))
            .collect();
    if let CommandEnv::Isolated {
        socks, supervisor, ..
    } = env
    {
        for name in ["ALL_PROXY", "all_proxy"] {
            vars.push((name.to_owned(), format!("socks5h://{socks}")));
        }
        vars.push((
            "GIT_SSH_COMMAND".to_owned(),
            format!(
                "ssh -o ProxyCommand='{} __connect %h %p'",
                proxy_command_word(supervisor)
            ),
        ));
    }
    for name in ["NO_PROXY", "no_proxy"] {
        vars.push((name.to_owned(), "localhost,127.0.0.1,::1".to_owned()));
    }
    if let Some(credential) = credential {
        let bundle = credential.ca_bundle.to_string_lossy();
        vars.extend(
            CA_VARIABLES
                .into_iter()
                .map(|name| (name.to_owned(), bundle.clone().into_owned())),
        );
    }
    vars
}

/// `path` as one word of the shell command ssh runs for `ProxyCommand`, which sits inside the
/// single quotes of `GIT_SSH_COMMAND`: double-quoted when needed, and `%` doubled for ssh.
fn proxy_command_word(path: &Path) -> String {
    let path = path.to_string_lossy().replace('%', "%%");
    let plain = |c: char| c.is_ascii_alphanumeric() || "/._-+:\\".contains(c);
    if path.chars().all(plain) {
        return path;
    }
    let escaped: String = path
        .chars()
        .flat_map(|c| match c {
            '"' | '\\' | '$' | '`' => vec!['\\', c],
            '\'' => "'\\''".chars().collect(),
            c => vec![c],
        })
        .collect();
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_sends_twenty_a_second_then_counts() {
        let mut limiter = Limiter::default();
        let start = Instant::now();
        let first: Vec<Admit> = (0..22).map(|_| limiter.admit(start)).collect();
        assert_eq!(first[0], Admit::Send { dropped: None });
        assert_eq!(first[19], Admit::Send { dropped: None });
        assert_eq!(first[20..], [Admit::Drop, Admit::Drop]);
        assert_eq!(
            limiter.admit(start + Duration::from_millis(999)),
            Admit::Drop
        );
        assert_eq!(
            limiter.admit(start + Duration::from_secs(1)),
            Admit::Send { dropped: Some(3) }
        );
        assert_eq!(
            limiter.admit(start + Duration::from_secs(1)),
            Admit::Send { dropped: None }
        );
    }

    #[test]
    fn proxy_command_word_quotes_only_when_needed() {
        assert_eq!(
            proxy_command_word(Path::new("/usr/local/bin/happy-supervisor")),
            "/usr/local/bin/happy-supervisor"
        );
        assert_eq!(
            proxy_command_word(Path::new("/opt/My Apps/100%/hs")),
            "\"/opt/My Apps/100%%/hs\""
        );
        assert_eq!(
            proxy_command_word(Path::new("/opt/it's $x/hs")),
            "\"/opt/it'\\''s \\$x/hs\""
        );
    }
}
