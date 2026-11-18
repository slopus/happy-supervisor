//! The credential proxy against real clients, with an in-memory control plane answering its
//! streams (docs/proxy.md).

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use happy_supervisor::protocol::{
    Bytes, ExecId, HostPattern, ProxyBody, ProxyCredit, ProxyEnd, ProxyMessage, ProxyRequest,
    ProxyReset, ProxyResponse, ProxySpec, ProxyToken, Scheme, StreamId, TcpMessage,
};
use happy_supervisor::proxy::{NodeCa, ProxyLease, ProxyManager};
use happy_supervisor::streams::Upstream;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::mpsc;

const TOKEN: &str = "pt_8f1c";
const WINDOW: usize = 1 << 20;

struct Channel(mpsc::UnboundedSender<ProxyMessage>);

impl Upstream for Channel {
    fn proxy(&self, message: ProxyMessage) {
        let _ = self.0.send(message);
    }

    fn tcp(&self, message: TcpMessage) {
        panic!("a proxy sent {message:?}");
    }
}

/// One command's proxy, and the control plane's end of its streams.
struct Harness {
    manager: ProxyManager,
    lease: Option<ProxyLease>,
    from_node: mpsc::UnboundedReceiver<ProxyMessage>,
    dir: tempfile::TempDir,
}

impl Harness {
    async fn start(hosts: &[&str]) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let (private, public) = (dir.path().join("private"), dir.path().join("public"));
        std::fs::create_dir(&private).unwrap();
        std::fs::create_dir(&public).unwrap();
        let ca = NodeCa::load_or_create(&private, &public).unwrap();
        let (tx, from_node) = mpsc::unbounded_channel();
        let manager = ProxyManager::new(Channel(tx), ca);
        let spec = ProxySpec {
            token: ProxyToken::try_from(TOKEN).unwrap(),
            hosts: hosts
                .iter()
                .map(|h| HostPattern::try_from(*h).unwrap())
                .collect(),
        };
        let lease = manager
            .start_for_exec(ExecId::try_from("build-1").unwrap(), spec)
            .await
            .unwrap();
        Harness {
            manager,
            lease: Some(lease),
            from_node,
            dir,
        }
    }

    fn lease(&self) -> &ProxyLease {
        self.lease.as_ref().unwrap()
    }

    fn env(&self, name: &str) -> String {
        let (_, value) = self.lease().env().iter().find(|(n, _)| n == name).unwrap();
        value.clone()
    }

    fn port(&self) -> u16 {
        self.env("HTTP_PROXY")
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }

    /// `curl` as the command would run it: with the lease's environment and nothing else
    /// pointing it at a proxy.
    fn curl(&self, args: &[&str]) -> Command {
        let mut curl = Command::new("curl");
        curl.args(["-sS", "--max-time", "30"])
            .args(args)
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .envs(self.lease().env().iter().cloned())
            .kill_on_drop(true);
        curl
    }

    async fn next(&mut self) -> ProxyMessage {
        tokio::time::timeout(Duration::from_secs(20), self.from_node.recv())
            .await
            .expect("the node sent nothing for 20 s")
            .expect("the proxy manager is gone")
    }

    /// The next message other than credit for a response body.
    async fn next_skipping_credit(&mut self) -> ProxyMessage {
        loop {
            match self.next().await {
                ProxyMessage::Credit(_) => continue,
                message => return message,
            }
        }
    }

    async fn request(&mut self) -> ProxyRequest {
        match self.next_skipping_credit().await {
            ProxyMessage::Request(request) => request,
            other => panic!("expected proxy.request, got {other:?}"),
        }
    }

    /// The request body up to `proxy.end`, credited as it arrives.
    async fn request_body(&mut self, id: StreamId) -> Vec<u8> {
        let mut body = Vec::new();
        loop {
            match self.next_skipping_credit().await {
                ProxyMessage::Body(ProxyBody { stream_id, data }) if stream_id == id => {
                    self.send(ProxyMessage::Credit(ProxyCredit {
                        stream_id: id,
                        bytes: data.0.len() as u64,
                    }));
                    body.extend_from_slice(&data.0);
                }
                ProxyMessage::End(ProxyEnd { stream_id }) if stream_id == id => return body,
                other => panic!("expected the body of {id:?}, got {other:?}"),
            }
        }
    }

    fn send(&self, message: ProxyMessage) {
        self.manager.on_event(message);
    }

    fn respond_head(&self, id: StreamId, status: u16, headers: &[(&str, &str)]) {
        self.send(ProxyMessage::Response(ProxyResponse {
            stream_id: id,
            status,
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), Bytes(v.as_bytes().to_vec())))
                .collect(),
        }));
    }

    fn respond_body(&self, id: StreamId, data: &[u8]) {
        self.send(ProxyMessage::Body(ProxyBody {
            stream_id: id,
            data: Bytes(data.to_vec()),
        }));
    }

    fn respond_end(&self, id: StreamId) {
        self.send(ProxyMessage::End(ProxyEnd { stream_id: id }));
    }

    fn respond(&self, id: StreamId, status: u16, headers: &[(&str, &str)], body: &[u8]) {
        self.respond_head(id, status, headers);
        self.respond_body(id, body);
        self.respond_end(id);
    }
}

fn header<'a>(request: &'a ProxyRequest, name: &str) -> Vec<&'a [u8]> {
    request
        .headers
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| v.0.as_slice())
        .collect()
}

async fn run(mut curl: Command) -> (String, String) {
    let output = curl.output().await.unwrap();
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[tokio::test]
async fn the_environment_points_at_the_proxy_and_the_bundle() {
    let h = Harness::start(&["api.example.test"]).await;
    let bundle = h.dir.path().join("public").join("ca-bundle.pem");
    assert_eq!(h.lease().ca_bundle(), bundle);
    assert_eq!(h.manager.ca_bundle(), bundle);
    let url = h.env("HTTP_PROXY");
    let secret = url
        .strip_prefix("http://happy:")
        .and_then(|rest| rest.strip_suffix(&format!("@127.0.0.1:{}", h.port())))
        .unwrap();
    assert_eq!(secret.len(), 43, "32 bytes, base64url without padding");
    assert!(
        secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
    let bundle = bundle.to_str().unwrap();
    let expected: Vec<(String, String)> = [
        ("HTTP_PROXY", url.as_str()),
        ("HTTPS_PROXY", &url),
        ("http_proxy", &url),
        ("https_proxy", &url),
        ("SSL_CERT_FILE", bundle),
        ("CURL_CA_BUNDLE", bundle),
        ("REQUESTS_CA_BUNDLE", bundle),
        ("NODE_EXTRA_CA_CERTS", bundle),
        ("GIT_SSL_CAINFO", bundle),
    ]
    .iter()
    .map(|(n, v)| (n.to_string(), v.to_string()))
    .collect();
    assert_eq!(h.lease().env(), expected);
}

#[tokio::test]
async fn a_listed_https_host_goes_through_the_control_plane() {
    let mut h = Harness::start(&["api.example.test"]).await;
    let curl = h.curl(&[
        "-X",
        "POST",
        "-H",
        "x-test: a",
        "-H",
        "x-test: b",
        "-H",
        "content-type: text/plain",
        "--data-binary",
        "hello upstream",
        "https://API.example.test/v1/things?x=1",
    ]);
    let client = tokio::spawn(async move { run(curl).await });

    let request = h.request().await;
    let id = request.stream_id;
    assert_eq!(
        (
            request.exec_id.as_str(),
            request.token.as_str(),
            request.method.as_str(),
            request.scheme,
            request.host.as_str(),
            request.port,
            request.path.as_str()
        ),
        (
            "build-1",
            TOKEN,
            "POST",
            Scheme::Https,
            "api.example.test",
            443,
            "/v1/things?x=1"
        )
    );
    assert_eq!(header(&request, "x-test"), [b"a".as_slice(), b"b"]);
    assert_eq!(header(&request, "host"), [b"API.example.test".as_slice()]);
    assert_eq!(header(&request, "content-length"), [b"14".as_slice()]);
    assert!(header(&request, "proxy-authorization").is_empty());
    assert_eq!(h.request_body(id).await, b"hello upstream");

    h.respond(
        id,
        201,
        &[("content-type", "text/plain"), ("x-upstream", "yes")],
        b"from the control plane",
    );
    let (stdout, stderr) = client.await.unwrap();
    assert_eq!(stdout, "from the control plane", "curl stderr: {stderr}");
}

/// The control plane adds the credential on its side and forwards to the real upstream, which
/// sees it. The command never had it.
#[tokio::test]
async fn an_injected_credential_reaches_the_upstream_but_not_the_command() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let app = axum::Router::new().route(
        "/whoami",
        axum::routing::get(|headers: axum::http::HeaderMap| async move {
            headers
                .get("authorization")
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_default()
        }),
    );
    tokio::spawn(async move { axum::serve(upstream, app).await.unwrap() });

    let mut h = Harness::start(&["api.github.test"]).await;
    let curl = h.curl(&["-v", "https://api.github.test/whoami"]);
    let client = tokio::spawn(async move { run(curl).await });

    let request = h.request().await;
    assert!(header(&request, "authorization").is_empty());
    h.request_body(request.stream_id).await;
    let forwarded = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{upstream_port}{}", request.path))
        .header("authorization", "Bearer ghp_from_the_control_plane")
        .send()
        .await
        .unwrap();
    let status = forwarded.status().as_u16();
    let body = forwarded.bytes().await.unwrap();
    h.respond(request.stream_id, status, &[], &body);

    let (stdout, stderr) = client.await.unwrap();
    assert_eq!(stdout, "Bearer ghp_from_the_control_plane");
    assert!(
        !stderr.to_ascii_lowercase().contains("> authorization"),
        "{stderr}"
    );
}

#[tokio::test]
async fn a_listed_plain_http_host_goes_through_the_control_plane() {
    let mut h = Harness::start(&["*.example.test"]).await;
    let curl = h.curl(&["http://registry.example.test:8080/pkg"]);
    let client = tokio::spawn(async move { run(curl).await });

    let request = h.request().await;
    assert_eq!(
        (
            request.scheme,
            request.host.as_str(),
            request.port,
            request.path.as_str()
        ),
        (Scheme::Http, "registry.example.test", 8080, "/pkg")
    );
    assert_eq!(h.request_body(request.stream_id).await, b"");
    h.respond(request.stream_id, 200, &[], b"plain");
    assert_eq!(client.await.unwrap().0, "plain");
}

#[tokio::test]
async fn an_unlisted_plain_http_host_is_forwarded_directly() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let app = axum::Router::new().route(
        "/direct",
        axum::routing::get(|headers: axum::http::HeaderMap| async move {
            format!(
                "direct, proxy-authorization={:?}",
                headers.get("proxy-authorization")
            )
        }),
    );
    tokio::spawn(async move { axum::serve(upstream, app).await.unwrap() });

    let mut h = Harness::start(&["api.example.test"]).await;
    let port = h.port().to_string();
    let (stdout, stderr) =
        run(h.curl(&["-v", &format!("http://localhost:{upstream_port}/direct")])).await;
    assert_eq!(stdout, "direct, proxy-authorization=None");
    assert!(
        stderr.contains(&format!("port {port}")),
        "curl used the proxy: {stderr}"
    );
    assert!(
        h.from_node.try_recv().is_err(),
        "nothing went to the control plane"
    );
}

#[tokio::test]
async fn an_unlisted_https_host_is_tunnelled_untouched() {
    let (server_port, server_ca) = tls_server(
        "localhost",
        b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\nconnection: close\r\n\r\ntunnel",
    )
    .await;
    let mut h = Harness::start(&["api.example.test"]).await;
    let ca_file = h.dir.path().join("server-ca.pem");
    std::fs::write(&ca_file, server_ca).unwrap();
    let (stdout, stderr) = run(h.curl(&[
        "--cacert",
        ca_file.to_str().unwrap(),
        &format!("https://localhost:{server_port}/"),
    ]))
    .await;
    assert_eq!(stdout, "tunnel", "{stderr}");
    assert!(
        h.from_node.try_recv().is_err(),
        "nothing went to the control plane"
    );
}

#[tokio::test]
async fn a_client_without_the_secret_gets_407() {
    let h = Harness::start(&["api.example.test"]).await;
    let port = h.port();
    for proxy in [
        format!("http://127.0.0.1:{port}"),
        format!("http://happy:wrong@127.0.0.1:{port}"),
    ] {
        let (code, _) = run(h.curl(&[
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--proxy",
            &proxy,
            "http://api.example.test/",
        ]))
        .await;
        assert_eq!(code, "407");
        let (code, _) = run(h.curl(&[
            "-o",
            "/dev/null",
            "-w",
            "%{http_connect}",
            "--proxy",
            &proxy,
            "https://api.example.test/",
        ]))
        .await;
        assert_eq!(code, "407");
    }
}

#[tokio::test]
async fn a_streamed_response_reaches_the_client_piece_by_piece() {
    let mut h = Harness::start(&["api.openai.test"]).await;
    let mut curl = h.curl(&["-N", "https://api.openai.test/v1/responses"]);
    curl.stdout(Stdio::piped());
    let mut child = curl.spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();

    let request = h.request().await;
    let id = request.stream_id;
    h.request_body(id).await;
    h.respond_head(id, 200, &[("content-type", "text/event-stream")]);
    for n in 1..=3 {
        h.respond_body(id, format!("data: {n}\n\n").as_bytes());
        let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .expect("the event arrived before the next was sent")
            .unwrap();
        assert_eq!(line.as_deref(), Some(format!("data: {n}").as_str()));
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some(""));
    }
    h.respond_end(id);
    assert_eq!(lines.next_line().await.unwrap(), None);
    assert!(child.wait().await.unwrap().success());
}

#[tokio::test]
async fn a_large_upload_waits_for_credit() {
    let mut h = Harness::start(&["upload.example.test"]).await;
    let upload: Vec<u8> = (0..3 * WINDOW).map(|i| (i % 251) as u8).collect();
    let file = h.dir.path().join("upload.bin");
    std::fs::write(&file, &upload).unwrap();
    let curl = h.curl(&[
        "-w",
        "%{http_code}",
        "--data-binary",
        &format!("@{}", file.display()),
        "https://upload.example.test/blob",
    ]);
    let client = tokio::spawn(async move { run(curl).await });

    let request = h.request().await;
    let id = request.stream_id;
    let mut received = Vec::new();
    while received.len() < WINDOW {
        match h.next().await {
            ProxyMessage::Body(body) => {
                assert!(body.data.0.len() <= 64 * 1024);
                received.extend_from_slice(&body.data.0);
            }
            other => panic!("expected the body, got {other:?}"),
        }
    }
    assert_eq!(
        received.len(),
        WINDOW,
        "exactly one window before any credit"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        h.from_node.try_recv().is_err(),
        "the sender paused without credit"
    );

    h.send(ProxyMessage::Credit(ProxyCredit {
        stream_id: id,
        bytes: WINDOW as u64,
    }));
    received.extend(h.request_body(id).await);
    assert_eq!(received.len(), upload.len());
    assert!(received == upload);

    h.respond(id, 200, &[], b"");
    assert_eq!(client.await.unwrap().0, "200");
}

#[tokio::test]
async fn a_reset_before_the_response_head_gives_502() {
    let mut h = Harness::start(&["api.example.test"]).await;
    let curl = h.curl(&[
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "https://api.example.test/",
    ]);
    let client = tokio::spawn(async move { run(curl).await });
    let request = h.request().await;
    h.send(ProxyMessage::Reset(ProxyReset {
        stream_id: request.stream_id,
        reason: "proxying is not supported".into(),
    }));
    assert_eq!(client.await.unwrap().0, "502");
}

#[tokio::test]
async fn an_invalid_response_head_gives_502_and_resets_the_stream() {
    let mut h = Harness::start(&["api.example.test"]).await;
    let curl = h.curl(&[
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "https://api.example.test/",
    ]);
    let client = tokio::spawn(async move { run(curl).await });
    let request = h.request().await;
    h.request_body(request.stream_id).await;
    h.respond_head(request.stream_id, 101, &[("upgrade", "websocket")]);
    assert_eq!(client.await.unwrap().0, "502");
    assert_eq!(
        h.next().await,
        ProxyMessage::Reset(ProxyReset {
            stream_id: request.stream_id,
            reason: "invalid proxy.response: status 101 Switching Protocols".into()
        })
    );
}

#[tokio::test]
async fn a_reset_after_the_response_head_closes_the_connection() {
    let mut h = Harness::start(&["api.example.test"]).await;
    let curl = h.curl(&["https://api.example.test/"]);
    let client = tokio::spawn(async move {
        let mut curl = curl;
        curl.output().await.unwrap()
    });
    let request = h.request().await;
    h.request_body(request.stream_id).await;
    h.respond_head(request.stream_id, 200, &[("content-length", "100")]);
    h.respond_body(request.stream_id, b"partial");
    assert_eq!(
        h.next().await,
        ProxyMessage::Credit(ProxyCredit {
            stream_id: request.stream_id,
            bytes: 7
        }),
        "the client took the piece"
    );
    h.send(ProxyMessage::Reset(ProxyReset {
        stream_id: request.stream_id,
        reason: "upstream died".into(),
    }));
    let output = client.await.unwrap();
    assert_eq!(output.stdout, b"partial");
    assert!(
        !output.status.success(),
        "curl saw the connection close mid-response"
    );
}

#[tokio::test]
async fn a_lost_session_fails_waiting_clients_with_502() {
    let mut h = Harness::start(&["api.example.test"]).await;
    let curl = h.curl(&[
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "http://api.example.test/",
    ]);
    let client = tokio::spawn(async move { run(curl).await });
    h.request().await;
    h.manager.session_lost();
    assert_eq!(client.await.unwrap().0, "502");
}

#[tokio::test]
async fn the_65th_concurrent_stream_gets_503() {
    let mut h = Harness::start(&["api.example.test"]).await;
    let port = h.port();
    let auth = auth_header(&h.env("HTTP_PROXY"));
    let mut held = Vec::new();
    for _ in 0..64 {
        let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        tcp.write_all(
            format!(
                "GET http://api.example.test/ HTTP/1.1\r\nhost: api.example.test\r\n{auth}\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        held.push(tcp);
    }
    let mut open = Vec::new();
    while open.len() < 64 {
        match h.next().await {
            ProxyMessage::Request(r) => open.push(r.stream_id),
            ProxyMessage::End(_) => {}
            other => panic!("{other:?}"),
        }
    }
    let (code, _) = run(h.curl(&[
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "http://api.example.test/",
    ]))
    .await;
    assert_eq!(code, "503");

    h.respond(open[0], 204, &[], b"");
    let curl = h.curl(&[
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "http://api.example.test/",
    ]);
    let client = tokio::spawn(async move { run(curl).await });
    let freed = loop {
        match h.next().await {
            ProxyMessage::Request(r) => break r.stream_id,
            ProxyMessage::End(_) | ProxyMessage::Credit(_) => {}
            other => panic!("{other:?}"),
        }
    };
    h.respond(freed, 200, &[], b"");
    assert_eq!(
        client.await.unwrap().0,
        "200",
        "a finished stream frees its slot"
    );
    drop(held);
}

#[tokio::test]
async fn an_upgrade_to_a_listed_host_gets_501() {
    let mut h = Harness::start(&["api.example.test"]).await;
    for url in ["http://api.example.test/ws", "https://api.example.test/ws"] {
        let (code, _) = run(h.curl(&[
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "-H",
            "Connection: Upgrade",
            "-H",
            "Upgrade: websocket",
            url,
        ]))
        .await;
        assert_eq!(code, "501", "{url}");
    }
    assert!(
        h.from_node.try_recv().is_err(),
        "nothing went to the control plane"
    );
}

#[tokio::test]
async fn an_upgrade_to_an_unlisted_host_is_tunnelled_directly() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut tcp, _) = upstream.accept().await.unwrap();
        read_head(&mut tcp).await;
        tcp.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: echo\r\n\r\n",
        )
        .await
        .unwrap();
        let mut buf = [0; 4];
        tcp.read_exact(&mut buf).await.unwrap();
        tcp.write_all(&buf).await.unwrap();
    });

    let h = Harness::start(&["api.example.test"]).await;
    let mut tcp = TcpStream::connect(("127.0.0.1", h.port())).await.unwrap();
    let auth = auth_header(&h.env("HTTP_PROXY"));
    tcp.write_all(
        format!(
            "GET http://localhost:{upstream_port}/echo HTTP/1.1\r\nhost: localhost\r\nconnection: upgrade\r\nupgrade: echo\r\n{auth}\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let head = read_head(&mut tcp).await;
    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{head}"
    );
    tcp.write_all(b"ping").await.unwrap();
    let mut echo = [0; 4];
    tcp.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");
}

/// Reads up to the blank line ending an HTTP head, one byte at a time so nothing after it is
/// consumed.
async fn read_head(tcp: &mut TcpStream) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tcp.read_u8().await.unwrap());
    }
    String::from_utf8(head).unwrap()
}

#[tokio::test]
async fn responses_are_framed_by_content_length_or_chunked() {
    let mut h = Harness::start(&["api.example.test"]).await;
    let auth = auth_header(&h.env("HTTP_PROXY"));
    for (headers, expected) in [
        (vec![("content-length", "5")], "content-length: 5\r\n"),
        (vec![], "transfer-encoding: chunked\r\n"),
    ] {
        let mut tcp = TcpStream::connect(("127.0.0.1", h.port())).await.unwrap();
        tcp.write_all(
            format!("GET http://api.example.test/ HTTP/1.1\r\nhost: api.example.test\r\nconnection: close\r\n{auth}\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let request = h.request().await;
        h.request_body(request.stream_id).await;
        let mut headers = headers.clone();
        headers.push(("keep-alive", "timeout=5"));
        h.respond(request.stream_id, 200, &headers, b"hello");
        let mut response = String::new();
        tcp.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains(expected), "{response}");
        assert!(!response.contains("keep-alive: timeout"), "{response}");
    }
}

#[tokio::test]
async fn dropping_the_lease_resets_open_streams_and_stops_the_listener() {
    let mut h = Harness::start(&["api.example.test"]).await;
    let port = h.port();
    let curl = h.curl(&["http://api.example.test/"]);
    let client = tokio::spawn(async move {
        let mut curl = curl;
        curl.output().await.unwrap()
    });
    let request = h.request().await;
    h.lease.take();
    let reset = loop {
        match h.next().await {
            ProxyMessage::Reset(reset) => break reset,
            ProxyMessage::End(_) => {}
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(
        reset,
        ProxyReset {
            stream_id: request.stream_id,
            reason: "the command exited".into()
        }
    );
    assert!(!client.await.unwrap().status.success());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
}

#[tokio::test]
async fn the_ca_persists_and_the_bundle_holds_system_roots_then_the_node_ca() {
    let dir = tempfile::tempdir().unwrap();
    let (private, public) = (dir.path().join("private"), dir.path().join("public"));
    std::fs::create_dir(&private).unwrap();
    std::fs::create_dir(&public).unwrap();
    let first = NodeCa::load_or_create(&private, &public).unwrap();
    let second = NodeCa::load_or_create(&private, &public).unwrap();
    assert_eq!(first.cert_der(), second.cert_der());

    let bundle = std::fs::read_to_string(public.join("ca-bundle.pem")).unwrap();
    let certs = pem_certs(&bundle);
    assert!(
        certs.len() >= 2,
        "system roots then the node CA, got {}",
        certs.len()
    );
    assert_eq!(certs.last().unwrap().as_slice(), first.cert_der());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &str| {
            std::fs::metadata(private.join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("proxy-ca.key"), 0o600);
        let bundle_mode = std::fs::metadata(public.join("ca-bundle.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(bundle_mode, 0o644);
    }
    let mut names: Vec<String> = std::fs::read_dir(&private)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["proxy-ca.crt", "proxy-ca.key"]);
}

fn auth_header(proxy_url: &str) -> String {
    use base64::Engine;
    let userinfo = proxy_url
        .strip_prefix("http://")
        .and_then(|rest| rest.split_once('@'))
        .unwrap()
        .0;
    format!(
        "proxy-authorization: Basic {}\r\n",
        base64::engine::general_purpose::STANDARD.encode(userinfo)
    )
}

fn pem_certs(pem: &str) -> Vec<Vec<u8>> {
    use base64::Engine;
    pem.split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .map(|block| {
            let body: String = block
                .split("-----END CERTIFICATE-----")
                .next()
                .unwrap()
                .split_whitespace()
                .collect();
            base64::engine::general_purpose::STANDARD
                .decode(body)
                .unwrap()
        })
        .collect()
}

/// A TLS server for `host` with its own CA, answering every connection with `response`.
/// Returns its port and the CA's PEM.
async fn tls_server(host: &str, response: &'static [u8]) -> (u16, String) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test server CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec![host.to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let mut buf = vec![0; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = tls.read(&mut buf).await.unwrap();
                    seen.extend_from_slice(&buf[..n]);
                }
                tls.write_all(response).await.unwrap();
                tls.shutdown().await.unwrap();
            });
        }
    });
    (port, ca_cert.pem())
}
