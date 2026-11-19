//! The local listener, `happy-supervisor serve --listen` (docs/serve.md): the node accepts the
//! link WebSocket instead of dialing it, and serves whoever connects with the token. The link
//! itself is the same [`client`](crate::client) driver as `run`'s.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::client::RunExit;
use crate::error::{Error, Result};
use crate::state::StateDir;
use crate::ws::{SUBPROTOCOL, Socket};

/// Where `serve` listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Listen {
    /// `IP:PORT`. Port 0 picks one.
    Tcp(SocketAddr),
    /// `unix:PATH`. The socket file is created `0600`.
    Unix(PathBuf),
}

impl FromStr for Listen {
    type Err = Error;

    fn from_str(text: &str) -> Result<Listen> {
        if let Some(path) = text.strip_prefix("unix:") {
            if !cfg!(unix) {
                return Err(Error::invalid_params("unix: listeners need a Unix system"));
            }
            return Ok(Listen::Unix(PathBuf::from(path)));
        }
        text.parse().map(Listen::Tcp).map_err(|_| {
            Error::invalid_params(format!(
                "--listen {text:?} is neither IP:PORT nor unix:PATH"
            ))
        })
    }
}

/// The token a client must present, from `--token-file`: the file's contents without the
/// trailing newline, or one line of stdin for `-`.
pub fn read_token(file: &str) -> Result<String> {
    let text = if file == "-" {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        line
    } else {
        std::fs::read_to_string(file)?
    };
    let token = text.trim_end_matches(['\n', '\r']).to_string();
    if token.is_empty() {
        return Err(Error::invalid_params("the token is empty"));
    }
    Ok(token)
}

/// Listens on `listen` and serves the node to whoever connects with `token` until `stop`
/// resolves. `listening` gets the bound address (`127.0.0.1:41234`, `unix:/run/h.sock`) once
/// connections are accepted.
pub async fn serve_until(
    state: StateDir,
    listen: Listen,
    token: String,
    listening: impl FnOnce(String),
    stop: impl Future<Output = ()> + Send + 'static,
) -> Result<RunExit> {
    let _lock = state.lock()?;
    let (sockets_tx, sockets_rx) = mpsc::unbounded_channel();
    let accept = Accept {
        token: Arc::from(token.as_str()),
        sockets: sockets_tx,
    };
    let acceptor = match listen {
        Listen::Tcp(addr) => {
            if !addr.ip().is_loopback() {
                tracing::warn!(
                    "listening on {addr}, which is not loopback: the listener speaks plain ws://, so put TLS in front"
                );
            }
            let listener = tokio::net::TcpListener::bind(addr).await?;
            listening(listener.local_addr()?.to_string());
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            let _ = stream.set_nodelay(true);
                            accept.connection(stream);
                        }
                        Err(err) => tracing::warn!("accepting a connection failed: {err}"),
                    }
                }
            })
        }
        #[cfg(unix)]
        Listen::Unix(path) => {
            let listener = bind_unix(&path)?;
            listening(format!("unix:{}", path.display()));
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => accept.connection(stream),
                        Err(err) => tracing::warn!("accepting a connection failed: {err}"),
                    }
                }
            })
        }
        #[cfg(not(unix))]
        Listen::Unix(_) => {
            return Err(Error::invalid_params("unix: listeners need a Unix system"));
        }
    };
    let exit = crate::client::serve_until(state, sockets_rx, stop).await;
    acceptor.abort();
    exit
}

/// Binds `path` with mode `0600`. A socket file left by a node that is gone is replaced; one
/// that still answers is not.
#[cfg(unix)]
fn bind_unix(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            return Err(Error::new(
                crate::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(Error::new(
                crate::ErrorKind::AlreadyExists,
                format!("{} is in use", path.display()),
            ));
        }
        std::fs::remove_file(path)?;
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

#[derive(Clone)]
struct Accept {
    token: Arc<str>,
    sockets: mpsc::UnboundedSender<Box<Socket>>,
}

impl Accept {
    /// Serves one HTTP connection, which upgrades or is refused.
    fn connection(&self, stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) {
        let accept = self.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let accept = accept.clone();
                async move { Ok::<_, std::convert::Infallible>(accept.upgrade(request)) }
            });
            let served = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await;
            if let Err(err) = served {
                tracing::debug!("a listener connection ended: {err}");
            }
        });
    }

    /// Checks the request (serve.md) and upgrades it, handing the socket to the driver.
    fn upgrade(&self, mut request: Request<Incoming>) -> Response<Full<Bytes>> {
        let refuse = |status: StatusCode, why: &str| {
            let mut response = Response::new(Full::new(Bytes::from(why.to_string())));
            *response.status_mut() = status;
            response
        };
        if request.method() != Method::GET || request.uri().path() != "/" {
            return refuse(StatusCode::NOT_FOUND, "the link is at GET /");
        }
        let headers = request.headers();
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if !presented.is_some_and(|token| same(token.as_bytes(), self.token.as_bytes())) {
            return refuse(StatusCode::UNAUTHORIZED, "a wrong or missing token");
        }
        let offers_link = headers
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|p| p.trim() == SUBPROTOCOL));
        if !offers_link {
            return refuse(StatusCode::BAD_REQUEST, "offer happy-supervisor.v1");
        }
        let offers_deflate = headers
            .get(header::SEC_WEBSOCKET_EXTENSIONS)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(',')
                    .any(|e| e.trim().starts_with("permessage-deflate"))
            });
        if !offers_deflate {
            return refuse(StatusCode::BAD_REQUEST, "permessage-deflate is required");
        }
        let options = crate::ws::options(true, crate::ws::node_level());
        let (response, upgraded) =
            match yawc::WebSocket::upgrade_with_options(&mut request, options) {
                Ok(upgrade) => upgrade,
                Err(err) => return refuse(StatusCode::BAD_REQUEST, &err.to_string()),
            };
        let (mut parts, _) = response.into_parts();
        parts.headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(SUBPROTOCOL),
        );
        let extensions = parts
            .headers
            .get(header::SEC_WEBSOCKET_EXTENSIONS)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let sockets = self.sockets.clone();
        tokio::spawn(async move {
            match upgraded.await {
                Ok(ws) => {
                    let _ = sockets.send(Box::new(Socket::new(ws, extensions)));
                }
                Err(err) => tracing::warn!("a listener upgrade failed: {err}"),
            }
        });
        Response::from_parts(parts, Full::new(Bytes::new()))
    }
}

/// Compares in time that depends only on the lengths.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_addresses() {
        assert_eq!(
            "127.0.0.1:0".parse::<Listen>(),
            Ok(Listen::Tcp("127.0.0.1:0".parse().unwrap()))
        );
        assert_eq!(
            "[::1]:7777".parse::<Listen>(),
            Ok(Listen::Tcp("[::1]:7777".parse().unwrap()))
        );
        #[cfg(unix)]
        assert_eq!(
            "unix:/run/happy/supervisor.sock".parse::<Listen>(),
            Ok(Listen::Unix(PathBuf::from("/run/happy/supervisor.sock")))
        );
        assert_eq!(
            "localhost:7777".parse::<Listen>(),
            Err(Error::invalid_params(
                r#"--listen "localhost:7777" is neither IP:PORT nor unix:PATH"#
            ))
        );
    }

    #[test]
    fn tokens_compare_whole() {
        assert!(same(b"secret", b"secret"));
        assert!(!same(b"secret", b"secreT"));
        assert!(!same(b"secret", b"secret2"));
        assert!(!same(b"", b"x"));
    }

    #[test]
    fn a_token_file_loses_its_trailing_newline() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("token");
        std::fs::write(&file, "tok_123\r\n").unwrap();
        assert_eq!(
            read_token(file.to_str().unwrap()),
            Ok("tok_123".to_string())
        );
        std::fs::write(&file, "\n").unwrap();
        assert_eq!(
            read_token(file.to_str().unwrap()),
            Err(Error::invalid_params("the token is empty"))
        );
    }
}
