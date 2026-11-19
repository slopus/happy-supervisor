//! The command proxy (v2 proxy.md) against real clients and real sockets: what an isolated
//! command may reach through the HTTP and SOCKS5 proxies, what it is refused, and the
//! `net.denied` events the refusals send.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use happy_supervisor::policy::{Default, HostEntry, HostRules};
use happy_supervisor::protocol::{
    Bytes, DenyReason, ExecId, HostPattern, NetDenied, ProxyEnd, ProxyMessage, ProxyResponse,
    ProxySpec, ProxyToken, Scheme, TcpMessage, Via,
};
use happy_supervisor::proxy::egress::{
    self, CommandEnv, CommandProxy, CommandProxyConfig, CredentialEnv, ListenOn, command_env,
};
use happy_supervisor::proxy::{NodeCa, ProxyManager, Resolver, socks5};
use happy_supervisor::sandbox::Endpoint;
use happy_supervisor::streams::Upstream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::mpsc;

const SUPERVISOR: &str = "/opt/happy/happy-supervisor";

/// Test names: `*.test` never resolves through the system, so every answer comes from here.
struct Names;

impl Resolver for Names {
    fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let ips: &[&str] = match host {
            "allowed.test" | "loop.test" | "api.example.test" => &["127.0.0.1"],
            "intranet.test" => &["10.0.0.5"],
            "mixed.test" => &["10.0.0.5", "127.0.0.1"],
            _ => return Err(io::Error::new(io::ErrorKind::NotFound, "no such name")),
        };
        Ok(ips.iter().map(|ip| ip.parse().unwrap()).collect())
    }
}

struct Channel(mpsc::UnboundedSender<ProxyMessage>);

impl Upstream for Channel {
    fn proxy(&self, message: ProxyMessage) {
        let _ = self.0.send(message);
    }

    fn tcp(&self, message: TcpMessage) {
        panic!("a command proxy sent {message:?}");
    }
}

fn rules(default: Default, allow: &[&str], deny: &[&str]) -> HostRules {
    HostRules {
        default,
        allow: allow
            .iter()
            .map(|s| HostEntry::try_from(*s).unwrap())
            .collect(),
        deny: deny
            .iter()
            .map(|s| HostEntry::try_from(*s).unwrap())
            .collect(),
    }
}

struct Harness {
    manager: ProxyManager,
    proxy: Option<CommandProxy>,
    denied: mpsc::UnboundedReceiver<NetDenied>,
    from_node: mpsc::UnboundedReceiver<ProxyMessage>,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn isolated(egress: HostRules, ports: Option<Vec<u16>>) -> Harness {
        Harness::start(Some((egress, ports)), &[], ListenOn::Loopback).await
    }

    async fn start(
        egress: Option<(HostRules, Option<Vec<u16>>)>,
        credential_hosts: &[&str],
        listen: ListenOn,
    ) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let (private, public) = (dir.path().join("private"), dir.path().join("public"));
        std::fs::create_dir(&private).unwrap();
        std::fs::create_dir(&public).unwrap();
        let ca = NodeCa::load_or_create(&private, &public).unwrap();
        let (tx, from_node) = mpsc::unbounded_channel();
        let (denied_tx, denied) = mpsc::unbounded_channel();
        let manager = ProxyManager::new(Channel(tx), ca, move |event| {
            let _ = denied_tx.send(event);
        })
        .with_resolver(Names);
        let credential = (!credential_hosts.is_empty()).then(|| ProxySpec {
            token: ProxyToken::try_from("pt_1").unwrap(),
            hosts: credential_hosts
                .iter()
                .map(|h| HostPattern::try_from(*h).unwrap())
                .collect(),
        });
        let config = CommandProxyConfig {
            exec_id: ExecId::try_from("e_1").unwrap(),
            egress,
            credential,
            listen,
        };
        let proxy = egress::start(config, &manager).await.unwrap();
        Harness {
            manager,
            proxy: Some(proxy),
            denied,
            from_node,
            _dir: dir,
        }
    }

    fn proxy(&self) -> &CommandProxy {
        self.proxy.as_ref().unwrap()
    }

    fn http(&self) -> SocketAddr {
        match &self.proxy().http {
            Endpoint::Tcp(addr) => *addr,
            other => panic!("the HTTP proxy is at {other:?}"),
        }
    }

    fn socks(&self) -> SocketAddr {
        match &self.proxy().socks {
            Endpoint::Tcp(addr) => *addr,
            other => panic!("the SOCKS5 proxy is at {other:?}"),
        }
    }

    fn env(&self, name: &str) -> String {
        let env = self.proxy().env(Path::new(SUPERVISOR));
        let (_, value) = env.into_iter().find(|(n, _)| n == name).unwrap();
        value
    }

    /// `curl` with the command's environment and nothing else pointing it at a proxy.
    fn curl(&self, args: &[&str]) -> Command {
        let mut curl = Command::new("curl");
        curl.args(["-sS", "--max-time", "20"]);
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ] {
            curl.env_remove(name);
        }
        curl.args(args)
            .envs(self.proxy().env(Path::new(SUPERVISOR)))
            .kill_on_drop(true);
        // Windows' curl uses Schannel, which ignores CURL_CA_BUNDLE and checks revocation.
        #[cfg(windows)]
        {
            if let Some((_, bundle)) = self
                .proxy()
                .env(Path::new(SUPERVISOR))
                .into_iter()
                .find(|(n, _)| n == "CURL_CA_BUNDLE")
            {
                curl.arg("--cacert").arg(bundle);
            }
            curl.arg("--ssl-no-revoke");
        }
        curl
    }

    /// Every `net.denied` sent so far.
    fn events(&mut self) -> Vec<NetDenied> {
        std::iter::from_fn(|| self.denied.try_recv().ok()).collect()
    }
}

async fn run(mut curl: Command) -> (String, String) {
    let output = curl.output().await.unwrap();
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

/// A plain HTTP server on 127.0.0.1 answering every path with `hello from <path>`.
async fn upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = axum::Router::new()
        .fallback(|uri: axum::http::Uri| async move { format!("hello from {}", uri.path()) });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    port
}

fn denied(host: &str, port: u16, via: Via, reason: DenyReason) -> NetDenied {
    NetDenied {
        exec_id: ExecId::try_from("e_1").unwrap(),
        host: host.to_string(),
        port,
        via,
        reason,
        dropped: None,
    }
}

/// Sends `CONNECT target` and returns the status code and the response body.
async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &str,
) -> (u16, String) {
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nhost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    read_response(stream).await
}

/// Reads a response head and, when it has a `content-length`, the body.
async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> (u16, String) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let code = head[9..12].parse().unwrap();
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.unwrap();
    (code, String::from_utf8(body).unwrap())
}

/// SOCKS5 address of a request: a domain name, or the raw IPv4 or IPv6 form.
enum Target<'a> {
    Domain(&'a str),
    Ip(IpAddr),
}

/// Negotiates no authentication, sends `cmd` for `target:port`, and returns the reply code.
async fn socks_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cmd: u8,
    target: Target<'_>,
    port: u16,
) -> u8 {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await.unwrap();
    assert_eq!(choice, [5, 0]);
    let mut request = vec![5, cmd, 0];
    match target {
        Target::Domain(name) => {
            request.extend_from_slice(&[3, name.len() as u8]);
            request.extend_from_slice(name.as_bytes());
        }
        Target::Ip(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Target::Ip(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    let rest = match reply[3] {
        1 => 6,
        4 => 18,
        other => panic!("reply address type {other}"),
    };
    stream.read_exact(&mut vec![0u8; rest]).await.unwrap();
    reply[1]
}

async fn socks_connect(h: &Harness, target: Target<'_>, port: u16) -> (u8, TcpStream) {
    let mut tcp = TcpStream::connect(h.socks()).await.unwrap();
    let reply = socks_request(&mut tcp, 1, target, port).await;
    (reply, tcp)
}

/// A GET over an open tunnel, and the body of its response.
async fn get_over<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, path: &str) -> String {
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nhost: upstream\r\nconnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let (code, body) = read_response(stream).await;
    assert_eq!(code, 200);
    body
}

#[tokio::test]
async fn an_allowed_host_is_reached_through_both_proxies() {
    let port = upstream().await;
    let mut h = Harness::isolated(
        rules(Default::Deny, &["allowed.test", "127.0.0.1"], &[]),
        Some(vec![port]),
    )
    .await;
    let url = format!("http://allowed.test:{port}");

    let (stdout, stderr) = run(h.curl(&[&format!("{url}/absolute")])).await;
    assert_eq!(stdout, "hello from /absolute", "{stderr}");
    let (stdout, stderr) = run(h.curl(&["-p", &format!("{url}/connect")])).await;
    assert_eq!(stdout, "hello from /connect", "{stderr}");
    let socks = h.env("ALL_PROXY");
    let (stdout, stderr) = run(h.curl(&["-x", &socks, &format!("{url}/socks")])).await;
    assert_eq!(stdout, "hello from /socks", "{stderr}");
    let (reply, mut tcp) = socks_connect(&h, Target::Ip("127.0.0.1".parse().unwrap()), port).await;
    assert_eq!(reply, 0);
    assert_eq!(get_over(&mut tcp, "/ipv4").await, "hello from /ipv4");

    assert_eq!(h.events(), []);
}

#[tokio::test]
async fn a_host_outside_egress_is_refused() {
    let mut h = Harness::isolated(rules(Default::Deny, &["*.test"], &["evil.test"]), None).await;

    let mut tcp = TcpStream::connect(h.http()).await.unwrap();
    assert_eq!(
        http_connect(&mut tcp, "evil.test:443").await,
        (
            403,
            "happy-supervisor refused evil.test:443: the host is not allowed by the network policy\n"
                .to_string()
        )
    );
    let (stdout, _) = run(h.curl(&["-w", " %{http_code}", "http://EVIL.test./x"])).await;
    assert_eq!(
        stdout,
        "happy-supervisor refused evil.test:80: the host is not allowed by the network policy\n 403"
    );
    let (reply, _) = socks_connect(&h, Target::Domain("evil.test"), 22).await;
    assert_eq!(reply, 2);
    let (reply, _) = socks_connect(&h, Target::Domain("example.com"), 443).await;
    assert_eq!(reply, 2);
    let (reply, _) = socks_connect(&h, Target::Ip("::1".parse().unwrap()), 443).await;
    assert_eq!(reply, 2);

    assert_eq!(
        h.events(),
        [
            denied("evil.test", 443, Via::Http, DenyReason::Egress),
            denied("evil.test", 80, Via::Http, DenyReason::Egress),
            denied("evil.test", 22, Via::Socks5, DenyReason::Egress),
            denied("example.com", 443, Via::Socks5, DenyReason::Egress),
            denied("::1", 443, Via::Socks5, DenyReason::Egress),
        ]
    );
}

#[tokio::test]
async fn a_port_outside_ports_is_refused() {
    let port = upstream().await;
    let mut h = Harness::isolated(
        rules(Default::Deny, &["allowed.test", "127.0.0.1"], &[]),
        Some(vec![443]),
    )
    .await;

    let mut tcp = TcpStream::connect(h.http()).await.unwrap();
    let target = format!("allowed.test:{port}");
    assert_eq!(
        http_connect(&mut tcp, &target).await,
        (
            403,
            format!(
                "happy-supervisor refused {target}: the port is not allowed by the network policy\n"
            )
        )
    );
    let (reply, _) = socks_connect(&h, Target::Domain("allowed.test"), port).await;
    assert_eq!(reply, 2);

    assert_eq!(
        h.events(),
        [
            denied("allowed.test", port, Via::Http, DenyReason::Port),
            denied("allowed.test", port, Via::Socks5, DenyReason::Port),
        ]
    );
}

#[tokio::test]
async fn a_name_resolving_to_an_internal_address_is_refused() {
    let port = upstream().await;
    let mut h = Harness::isolated(
        rules(
            Default::Allow,
            &["loop.test", "intranet.test", "nowhere.test"],
            &[],
        ),
        None,
    )
    .await;

    let internal = "the host resolves only to internal addresses";
    for (target, shown, reason) in [
        (
            format!("loop.test:{port}"),
            format!("loop.test:{port}"),
            internal,
        ),
        (
            "intranet.test:80".into(),
            "intranet.test:80".into(),
            internal,
        ),
        (
            format!("127.0.0.1:{port}"),
            format!("127.0.0.1:{port}"),
            internal,
        ),
        (
            format!("[::ffff:127.0.0.1]:{port}"),
            format!("127.0.0.1:{port}"),
            internal,
        ),
        (
            "nowhere.test:80".into(),
            "nowhere.test:80".into(),
            "the host does not resolve",
        ),
    ] {
        let mut tcp = TcpStream::connect(h.http()).await.unwrap();
        assert_eq!(
            http_connect(&mut tcp, &target).await,
            (403, format!("happy-supervisor refused {shown}: {reason}\n")),
        );
    }
    let (reply, _) = socks_connect(&h, Target::Domain("loop.test"), port).await;
    assert_eq!(reply, 2);

    assert_eq!(
        h.events(),
        [
            denied("loop.test", port, Via::Http, DenyReason::Address),
            denied("intranet.test", 80, Via::Http, DenyReason::Address),
            denied("127.0.0.1", port, Via::Http, DenyReason::Address),
            denied("127.0.0.1", port, Via::Http, DenyReason::Address),
            denied("nowhere.test", 80, Via::Http, DenyReason::Resolve),
            denied("loop.test", port, Via::Socks5, DenyReason::Address),
        ]
    );
}

#[tokio::test]
async fn an_internal_address_named_in_egress_allow_is_reached() {
    let port = upstream().await;
    let mut h = Harness::isolated(
        rules(
            Default::Deny,
            &["loop.test", "mixed.test", "127.0.0.1"],
            &[],
        ),
        None,
    )
    .await;

    let (stdout, stderr) = run(h.curl(&[&format!("http://loop.test:{port}/loop")])).await;
    assert_eq!(stdout, "hello from /loop", "{stderr}");
    let (reply, mut tcp) = socks_connect(&h, Target::Domain("mixed.test"), port).await;
    assert_eq!(reply, 0, "10.0.0.5 is dropped, 127.0.0.1 is allowed");
    assert_eq!(get_over(&mut tcp, "/mixed").await, "hello from /mixed");
    assert_eq!(h.events(), []);
}

#[tokio::test]
async fn prefixes_decide_the_addresses_of_allowed_names() {
    let port = upstream().await;
    let mut h = Harness::isolated(
        rules(
            Default::Deny,
            &["loop.test", "mixed.test", "intranet.test", "127.0.0.0/8"],
            &["10.0.0.0/8"],
        ),
        None,
    )
    .await;

    let (stdout, stderr) = run(h.curl(&[&format!("http://loop.test:{port}/loop")])).await;
    assert_eq!(stdout, "hello from /loop", "{stderr}");
    let (reply, mut tcp) = socks_connect(&h, Target::Ip("127.0.0.1".parse().unwrap()), port).await;
    assert_eq!(reply, 0, "127.0.0.1 is allowed by 127.0.0.0/8");
    assert_eq!(get_over(&mut tcp, "/literal").await, "hello from /literal");
    let (reply, mut tcp) = socks_connect(&h, Target::Domain("mixed.test"), port).await;
    assert_eq!(
        reply, 0,
        "10.0.0.5 is denied by 10.0.0.0/8, 127.0.0.1 is allowed"
    );
    assert_eq!(get_over(&mut tcp, "/mixed").await, "hello from /mixed");
    let (reply, _) = socks_connect(&h, Target::Domain("intranet.test"), 80).await;
    assert_eq!(reply, 2);
    let (reply, _) = socks_connect(&h, Target::Ip("10.0.0.5".parse().unwrap()), 80).await;
    assert_eq!(reply, 2);
    let (reply, _) = socks_connect(&h, Target::Domain("allowed.test"), port).await;
    assert_eq!(reply, 2, "127.0.0.0/8 does not admit a name");

    assert_eq!(
        h.events(),
        [
            denied("intranet.test", 80, Via::Socks5, DenyReason::Egress),
            denied("10.0.0.5", 80, Via::Socks5, DenyReason::Egress),
            denied("allowed.test", port, Via::Socks5, DenyReason::Egress),
        ]
    );
}

#[tokio::test]
async fn the_nodes_own_address_is_refused() {
    let own = sysinfo::Networks::new_with_refreshed_list()
        .values()
        .flat_map(|data| data.ip_networks())
        .map(|network| network.addr)
        .find(|ip| matches!(ip, IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_private() && !v4.is_link_local()));
    let Some(own) = own else {
        eprintln!("skipped: this node has no public IPv4 address");
        return;
    };
    let mut h = Harness::isolated(rules(Default::Allow, &[], &[]), None).await;
    let (reply, _) = socks_connect(&h, Target::Ip(own), 80).await;
    assert_eq!(reply, 2);
    assert_eq!(
        h.events(),
        [denied(
            &own.to_string(),
            80,
            Via::Socks5,
            DenyReason::Address
        )]
    );
}

#[tokio::test]
async fn a_credential_host_through_socks_is_refused() {
    let mut h = Harness::start(
        Some((rules(Default::Deny, &["api.example.test"], &[]), None)),
        &["api.example.test"],
        ListenOn::Loopback,
    )
    .await;
    let (reply, _) = socks_connect(&h, Target::Domain("api.example.test"), 443).await;
    assert_eq!(reply, 2);
    assert_eq!(
        h.events(),
        [denied(
            "api.example.test",
            443,
            Via::Socks5,
            DenyReason::Credential
        )]
    );
    assert!(
        h.from_node.try_recv().is_err(),
        "nothing went to the control plane"
    );
}

#[tokio::test]
async fn a_credential_host_through_http_goes_to_the_control_plane() {
    let mut h = Harness::start(
        Some((
            rules(Default::Deny, &["api.example.test"], &[]),
            Some(vec![22]),
        )),
        &["api.example.test"],
        ListenOn::Loopback,
    )
    .await;
    assert!(h.env("HTTP_PROXY").starts_with("http://happy:"));

    for (url, scheme, port, path) in [
        (
            "http://api.example.test/v1/plain",
            Scheme::Http,
            80,
            "/v1/plain",
        ),
        (
            "https://api.example.test/v1/tls",
            Scheme::Https,
            443,
            "/v1/tls",
        ),
    ] {
        let client = tokio::spawn(run(h.curl(&[url])));
        let request = match tokio::time::timeout(Duration::from_secs(20), h.from_node.recv())
            .await
            .unwrap()
            .unwrap()
        {
            ProxyMessage::Request(request) => request,
            other => panic!("expected proxy.request, got {other:?}"),
        };
        assert_eq!(
            (
                request.exec_id.to_string(),
                request.token.as_str(),
                request.scheme,
                request.host.as_str(),
                request.port,
                request.path.as_str(),
            ),
            (
                "e_1".to_string(),
                "pt_1",
                scheme,
                "api.example.test",
                port,
                path
            )
        );
        let id = request.stream_id;
        h.manager.on_event(ProxyMessage::Response(ProxyResponse {
            stream_id: id,
            status: 200,
            headers: vec![("content-length".into(), Bytes(b"18".to_vec()))],
        }));
        h.manager
            .on_event(ProxyMessage::Body(happy_supervisor::protocol::ProxyBody {
                stream_id: id,
                data: Bytes(b"from control plane".to_vec()),
            }));
        h.manager
            .on_event(ProxyMessage::End(ProxyEnd { stream_id: id }));
        let (stdout, stderr) = client.await.unwrap();
        assert_eq!(stdout, "from control plane", "{stderr}");
        while let Ok(message) = h.from_node.try_recv() {
            assert!(
                matches!(message, ProxyMessage::End(_) | ProxyMessage::Credit(_)),
                "{message:?}"
            );
        }
    }
    assert_eq!(h.events(), []);
}

#[tokio::test]
async fn a_credential_host_outside_egress_is_refused_in_isolated_mode() {
    let mut h = Harness::start(
        Some((rules(Default::Deny, &[], &[]), None)),
        &["api.example.test"],
        ListenOn::Loopback,
    )
    .await;
    let (stdout, _) = run(h.curl(&["-w", " %{http_code}", "http://api.example.test/"])).await;
    assert_eq!(
        stdout,
        "happy-supervisor refused api.example.test:80: the host is not allowed by the network policy\n 403"
    );
    assert_eq!(
        h.events(),
        [denied(
            "api.example.test",
            80,
            Via::Http,
            DenyReason::Egress
        )]
    );
    assert!(
        h.from_node.try_recv().is_err(),
        "nothing went to the control plane"
    );
}

#[tokio::test]
async fn host_mode_reaches_any_address_and_still_refuses_credential_hosts_over_socks() {
    let port = upstream().await;
    let mut h = Harness::start(None, &["api.example.test"], ListenOn::Loopback).await;
    let (reply, mut tcp) = socks_connect(&h, Target::Domain("loop.test"), port).await;
    assert_eq!(reply, 0);
    assert_eq!(get_over(&mut tcp, "/host").await, "hello from /host");
    let (reply, _) = socks_connect(&h, Target::Domain("api.example.test"), 443).await;
    assert_eq!(reply, 2);
    let (reply, _) = socks_connect(&h, Target::Domain("nowhere.test"), 443).await;
    assert_eq!(
        reply, 4,
        "host unreachable, and no event: host mode has no policy"
    );
    assert_eq!(
        h.events(),
        [denied(
            "api.example.test",
            443,
            Via::Socks5,
            DenyReason::Credential
        )]
    );
}

#[tokio::test]
async fn refusals_past_twenty_a_second_are_counted_in_the_next_event() {
    let mut h = Harness::isolated(rules(Default::Deny, &[], &[]), None).await;
    let start = std::time::Instant::now();
    for _ in 0..25 {
        let (reply, _) = socks_connect(&h, Target::Domain("evil.test"), 443).await;
        assert_eq!(reply, 2);
    }
    assert!(
        start.elapsed() < Duration::from_millis(900),
        "too slow to test the limit"
    );
    assert_eq!(
        h.events(),
        vec![denied("evil.test", 443, Via::Socks5, DenyReason::Egress); 20]
    );

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (reply, _) = socks_connect(&h, Target::Domain("evil.test"), 443).await;
    assert_eq!(reply, 2);
    assert_eq!(
        h.events(),
        [NetDenied {
            dropped: Some(5),
            ..denied("evil.test", 443, Via::Socks5, DenyReason::Egress)
        }]
    );
}

#[tokio::test]
async fn socks5_answers_what_it_does_not_support() {
    let h = Harness::isolated(rules(Default::Allow, &[], &[]), None).await;
    for cmd in [2, 3] {
        let mut tcp = TcpStream::connect(h.socks()).await.unwrap();
        let reply = socks_request(&mut tcp, cmd, Target::Domain("example.com"), 443).await;
        assert_eq!(reply, 7, "command {cmd}");
    }
    let mut tcp = TcpStream::connect(h.socks()).await.unwrap();
    tcp.write_all(&[5, 1, 2]).await.unwrap();
    let mut choice = [0u8; 2];
    tcp.read_exact(&mut choice).await.unwrap();
    assert_eq!(choice, [5, 0xff]);
}

#[tokio::test]
async fn http_requests_other_than_connect_and_absolute_form_get_400() {
    let h = Harness::isolated(rules(Default::Allow, &[], &[]), None).await;
    let mut tcp = TcpStream::connect(h.http()).await.unwrap();
    tcp.write_all(b"GET /index.html HTTP/1.1\r\nhost: example.com\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_response(&mut tcp).await, (400, String::new()));
}

#[tokio::test]
async fn the_blocking_client_connects_through_the_socks_proxy() {
    let port = upstream().await;
    let h = Harness::isolated(
        rules(Default::Deny, &["allowed.test", "127.0.0.1"], &[]),
        None,
    )
    .await;
    let socks = h.socks();
    let (body, refused) = tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut tcp = socks5::connect(socks, "allowed.test", port).unwrap();
        tcp.write_all(b"GET /blocking HTTP/1.0\r\nhost: allowed.test\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        tcp.read_to_string(&mut response).unwrap();
        let body = response.split("\r\n\r\n").nth(1).unwrap().to_string();
        let refused = socks5::connect(socks, "evil.test", 22).unwrap_err();
        (body, (refused.kind(), refused.to_string()))
    })
    .await
    .unwrap();
    assert_eq!(body, "hello from /blocking");
    assert_eq!(
        refused,
        (
            io::ErrorKind::PermissionDenied,
            "socks5 reply 0x02".to_string()
        )
    );
}

#[tokio::test]
async fn the_environment_of_an_isolated_command_on_loopback() {
    let h = Harness::isolated(rules(Default::Deny, &[], &[]), None).await;
    let (http, socks) = (h.http(), h.socks());
    let env = h.proxy().env(Path::new(SUPERVISOR));
    let expected: Vec<(String, String)> = [
        ("HTTP_PROXY", format!("http://{http}")),
        ("HTTPS_PROXY", format!("http://{http}")),
        ("http_proxy", format!("http://{http}")),
        ("https_proxy", format!("http://{http}")),
        ("ALL_PROXY", format!("socks5h://{socks}")),
        ("all_proxy", format!("socks5h://{socks}")),
        (
            "GIT_SSH_COMMAND",
            "ssh -o ProxyCommand='/opt/happy/happy-supervisor __connect %h %p'".to_string(),
        ),
        ("NO_PROXY", "localhost,127.0.0.1,::1".to_string()),
        ("no_proxy", "localhost,127.0.0.1,::1".to_string()),
    ]
    .into_iter()
    .map(|(n, v)| (n.to_string(), v))
    .collect();
    assert_eq!(env, expected);
    assert_eq!(h.proxy().ca_bundle(), None);
}

#[test]
fn command_env_by_mode() {
    let http: SocketAddr = "127.0.0.1:3128".parse().unwrap();
    let socks: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let pairs = |env: Vec<(String, String)>| -> Vec<String> {
        env.into_iter().map(|(n, v)| format!("{n}={v}")).collect()
    };
    assert_eq!(
        pairs(command_env(&CommandEnv::Host {
            http: "127.0.0.1:40000".parse().unwrap(),
            credential: CredentialEnv {
                password: Some("happy:s3cret"),
                ca_bundle: Path::new("/state/public/ca-bundle.pem"),
            },
        })),
        [
            "HTTP_PROXY=http://happy:s3cret@127.0.0.1:40000",
            "HTTPS_PROXY=http://happy:s3cret@127.0.0.1:40000",
            "http_proxy=http://happy:s3cret@127.0.0.1:40000",
            "https_proxy=http://happy:s3cret@127.0.0.1:40000",
            "NO_PROXY=localhost,127.0.0.1,::1",
            "no_proxy=localhost,127.0.0.1,::1",
            "SSL_CERT_FILE=/state/public/ca-bundle.pem",
            "CURL_CA_BUNDLE=/state/public/ca-bundle.pem",
            "REQUESTS_CA_BUNDLE=/state/public/ca-bundle.pem",
            "NODE_EXTRA_CA_CERTS=/state/public/ca-bundle.pem",
            "GIT_SSL_CAINFO=/state/public/ca-bundle.pem",
        ]
    );
    assert_eq!(
        pairs(command_env(&CommandEnv::Isolated {
            http,
            socks,
            supervisor: Path::new("/opt/My Apps/hs"),
            credential: Some(CredentialEnv {
                password: None,
                ca_bundle: Path::new("/state/public/ca-bundle.pem"),
            }),
        })),
        [
            "HTTP_PROXY=http://127.0.0.1:3128",
            "HTTPS_PROXY=http://127.0.0.1:3128",
            "http_proxy=http://127.0.0.1:3128",
            "https_proxy=http://127.0.0.1:3128",
            "ALL_PROXY=socks5h://127.0.0.1:1080",
            "all_proxy=socks5h://127.0.0.1:1080",
            "GIT_SSH_COMMAND=ssh -o ProxyCommand='\"/opt/My Apps/hs\" __connect %h %p'",
            "NO_PROXY=localhost,127.0.0.1,::1",
            "no_proxy=localhost,127.0.0.1,::1",
            "SSL_CERT_FILE=/state/public/ca-bundle.pem",
            "CURL_CA_BUNDLE=/state/public/ca-bundle.pem",
            "REQUESTS_CA_BUNDLE=/state/public/ca-bundle.pem",
            "NODE_EXTRA_CA_CERTS=/state/public/ca-bundle.pem",
            "GIT_SSL_CAINFO=/state/public/ca-bundle.pem",
        ]
    );
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_listeners_serve_both_proxies_and_vanish_on_drop() {
    use tokio::net::UnixStream;

    let port = upstream().await;
    let sockets = tempfile::tempdir().unwrap();
    let mut h = Harness::start(
        Some((
            rules(Default::Deny, &["allowed.test", "127.0.0.1"], &[]),
            None,
        )),
        &[],
        ListenOn::UnixDir(sockets.path().to_path_buf()),
    )
    .await;
    let http = sockets.path().join("http.sock");
    let socks = sockets.path().join("socks.sock");
    assert_eq!(
        (&h.proxy().http, &h.proxy().socks),
        (
            &Endpoint::Unix(http.clone()),
            &Endpoint::Unix(socks.clone())
        )
    );
    assert_eq!(h.env("HTTP_PROXY"), "http://127.0.0.1:3128");
    assert_eq!(h.env("ALL_PROXY"), "socks5h://127.0.0.1:1080");

    let mut stream = UnixStream::connect(&http).await.unwrap();
    assert_eq!(
        http_connect(&mut stream, &format!("allowed.test:{port}")).await,
        (200, String::new())
    );
    assert_eq!(
        get_over(&mut stream, "/unix-http").await,
        "hello from /unix-http"
    );
    let mut stream = UnixStream::connect(&socks).await.unwrap();
    assert_eq!(
        socks_request(&mut stream, 1, Target::Domain("allowed.test"), port).await,
        0
    );
    assert_eq!(
        get_over(&mut stream, "/unix-socks").await,
        "hello from /unix-socks"
    );

    h.proxy.take();
    assert!(!http.exists() && !socks.exists());
    assert_eq!(h.events(), []);
}

#[tokio::test]
async fn a_port_range_listener_takes_two_ports_in_the_range_and_fails_when_none_are_free() {
    let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first = taken.local_addr().unwrap().port();
    let last = first.saturating_add(200);
    let h = Harness::start(
        Some((rules(Default::Deny, &[], &[]), None)),
        &[],
        ListenOn::LoopbackRange(first..=last),
    )
    .await;
    let (http, socks) = (h.http().port(), h.socks().port());
    assert!(
        first < http && http < socks && socks <= last,
        "{first} < {http} < {socks} <= {last}"
    );

    let dir = tempfile::tempdir().unwrap();
    let (private, public) = (dir.path().join("private"), dir.path().join("public"));
    std::fs::create_dir(&private).unwrap();
    std::fs::create_dir(&public).unwrap();
    let ca = NodeCa::load_or_create(&private, &public).unwrap();
    let (tx, _from_node) = mpsc::unbounded_channel();
    let manager = ProxyManager::new(Channel(tx), ca, |_| {});
    let config = CommandProxyConfig {
        exec_id: ExecId::try_from("e_2").unwrap(),
        egress: Some((rules(Default::Deny, &[], &[]), None)),
        credential: None,
        listen: ListenOn::LoopbackRange(first..=first),
    };
    let err = egress::start(config, &manager).await.err().unwrap();
    assert_eq!(
        (err.kind(), err.to_string()),
        (
            io::ErrorKind::AddrInUse,
            format!("no free proxy port in {first}-{first}")
        )
    );
}
