//! The node's side of the upgrade: dialing the control plane (or a `serve` node, for
//! [`Controller`](crate::Controller)) over `wss://`, `ws://` or `unix:`.

use std::sync::{Arc, OnceLock};

use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderValue, Request, StatusCode, header};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use sha1::{Digest as _, Sha1};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use url::Url;
use yawc::{HttpStream, Role, WebSocket};

use super::{DEFLATE_OFFER, SUBPROTOCOL, Socket, node_level, options};

/// How a dial ended.
pub enum Dialed {
    Open(Box<Socket>),
    /// The upgrade was answered `401` or `403`.
    Refused(StatusCode),
}

/// Opens the link WebSocket to `endpoint` with `token` as a bearer credential: `wss://`, or
/// `ws://` for tests and local listeners, or `unix:PATH` for a local listener's socket (serve.md).
/// `Err` describes a failure worth retrying.
pub async fn dial(endpoint: &Url, token: &str) -> Result<Dialed, String> {
    let (io, host_header, target) = connect(endpoint).await?;
    let key = base64::engine::general_purpose::STANDARD.encode(uuid::Uuid::now_v7().as_bytes());
    let bearer = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| "the token is not a valid header value".to_string())?;
    let request = Request::get(target)
        .header(header::HOST, host_header)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header(header::SEC_WEBSOCKET_KEY, &key)
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .header(header::SEC_WEBSOCKET_PROTOCOL, SUBPROTOCOL)
        .header(header::SEC_WEBSOCKET_EXTENSIONS, DEFLATE_OFFER)
        .header(header::AUTHORIZATION, bearer)
        .body(Empty::<Bytes>::new())
        .map_err(|err| format!("bad request: {err}"))?;

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|err| format!("HTTP: {err}"))?;
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let mut response = sender
        .send_request(request)
        .await
        .map_err(|err| format!("HTTP: {err}"))?;
    let status = response.status();
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return Ok(Dialed::Refused(status));
    }
    if status != StatusCode::SWITCHING_PROTOCOLS {
        return Err(format!("the upgrade was answered {status}"));
    }
    let headers = response.headers();
    if headers
        .get(header::SEC_WEBSOCKET_ACCEPT)
        .map(|v| v.as_bytes())
        != Some(accept(&key).as_bytes())
    {
        return Err("the upgrade answered a wrong Sec-WebSocket-Accept".to_string());
    }
    let protocol = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok());
    if protocol != Some(SUBPROTOCOL) {
        return Err(format!(
            "the server selected subprotocol {protocol:?}, not {SUBPROTOCOL}"
        ));
    }
    let extensions = headers
        .get(header::SEC_WEBSOCKET_EXTENSIONS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if extensions.split(';').next().map(str::trim) != Some("permessage-deflate") {
        return Err(format!(
            "the server did not accept permessage-deflate (Sec-WebSocket-Extensions: {extensions:?})"
        ));
    }
    let upgraded = hyper::upgrade::on(&mut response)
        .await
        .map_err(|err| format!("upgrade: {err}"))?;
    let ws = WebSocket::from_stream_with_extensions(
        HttpStream::from(TokioIo::new(upgraded)),
        Role::Client,
        Some(&extensions),
        options(true, node_level()),
    )
    .map_err(|err| format!("WebSocket: {err}"))?;
    Ok(Dialed::Open(Box::new(Socket::new(ws, Some(extensions)))))
}

/// The stream to `endpoint`, its `Host` header and the request target.
async fn connect(endpoint: &Url) -> Result<(Box<dyn Io>, String, String), String> {
    #[cfg(unix)]
    if endpoint.scheme() == "unix" {
        let unix = tokio::net::UnixStream::connect(endpoint.path())
            .await
            .map_err(|err| format!("connecting to {}: {err}", endpoint.path()))?;
        return Ok((Box::new(unix), "localhost".to_string(), "/".to_string()));
    }
    let host = endpoint
        .host_str()
        .ok_or_else(|| format!("{endpoint} has no host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = endpoint
        .port_or_known_default()
        .ok_or_else(|| format!("{endpoint} has no port"))?;
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|err| format!("connecting: {err}"))?;
    let _ = tcp.set_nodelay(true);
    let io: Box<dyn Io> = match endpoint.scheme() {
        "wss" => {
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|err| format!("bad host {host}: {err}"))?;
            let tls = tokio_rustls::TlsConnector::from(tls_config()?)
                .connect(name, tcp)
                .await
                .map_err(|err| format!("TLS: {err}"))?;
            Box::new(tls)
        }
        _ => Box::new(tcp),
    };
    let host_header = match endpoint.port() {
        Some(port) => format!("{}:{port}", endpoint.host_str().unwrap_or_default()),
        None => endpoint.host_str().unwrap_or_default().to_string(),
    };
    Ok((
        io,
        host_header,
        endpoint[url::Position::BeforePath..].to_string(),
    ))
}

/// `Sec-WebSocket-Accept` for `key` (RFC 6455, 4.2.2).
pub fn accept(key: &str) -> String {
    let mut sha = Sha1::new();
    sha.update(key.as_bytes());
    sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(sha.finalize())
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// TLS trusting the platform's store (api.md, Joining).
fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            let native = rustls_native_certs::load_native_certs();
            let (added, _) = roots.add_parsable_certificates(native.certs);
            if added == 0 {
                return Err(format!(
                    "no trusted certificates in the platform store: {:?}",
                    native.errors
                ));
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|err| format!("TLS: {err}"))?
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Ok(Arc::new(config))
        })
        .clone()
}
