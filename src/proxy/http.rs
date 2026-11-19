//! The command's HTTP proxy: proxy authentication, `CONNECT`, absolute-form requests, and the
//! credential route's TLS termination and streams (proxy.md, How requests travel).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use base64::Engine;
use http::header::{self, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use super::egress::{Command, Io, Route, connect, explain, normalize};
use crate::protocol::{Bytes, DenyReason, ProxyRequest, ProxyResponse, Scheme, StreamId, Via};
use crate::streams::{Piece, StreamGuard, Streams};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = BoxBody<bytes::Bytes, BoxError>;

/// Removed before forwarding and after receiving, with every header named in `connection`.
/// `expect` is answered by the node itself, so it is not forwarded either.
const HOP_BY_HOP: [&str; 10] = [
    "connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "expect",
];

/// Serves one client connection of the command's HTTP proxy.
pub(crate) async fn serve(command: Arc<Command>, stream: Box<dyn Io>) {
    let service = service_fn(move |req| {
        let command = command.clone();
        async move { Ok::<_, Infallible>(command.handle(req).await) }
    });
    let _ = http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await;
}

impl Command {
    async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Response<Body> {
        if !self.authorized(&req) {
            let mut response = status(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
            response.headers_mut().insert(
                header::PROXY_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"happy-supervisor\""),
            );
            return response;
        }
        if req.method() == Method::CONNECT {
            return self.connect(req).await;
        }
        let Some(target) = Target::of(req.uri()) else {
            return status(StatusCode::BAD_REQUEST);
        };
        match self.route(&target.host, target.port, Via::Http).await {
            Route::Credential if is_upgrade(&req) => status(StatusCode::NOT_IMPLEMENTED),
            Route::Credential => self.forward(req, Scheme::Http, target).await,
            Route::Direct(addresses) => self.direct(req, &addresses).await,
            Route::Refused(reason) => refused(reason, &target),
            Route::Unresolved => status(StatusCode::BAD_GATEWAY),
        }
    }

    fn authorized<B>(&self, req: &Request<B>) -> bool {
        let Some(password) = &self.password else {
            return true;
        };
        let Some(value) = req.headers().get(header::PROXY_AUTHORIZATION) else {
            return false;
        };
        let Some((scheme, encoded)) = value.to_str().ok().and_then(|v| v.split_once(' ')) else {
            return false;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
            return false;
        };
        scheme.eq_ignore_ascii_case("basic") && constant_time_eq(&decoded, password.as_bytes())
    }

    async fn connect(self: Arc<Self>, mut req: Request<Incoming>) -> Response<Body> {
        let Some(target) = req.uri().authority().and_then(|a| {
            a.port_u16().map(|port| Target {
                host: normalize(a.host()),
                port,
            })
        }) else {
            return status(StatusCode::BAD_REQUEST);
        };
        let upgrade = hyper::upgrade::on(&mut req);
        match self.route(&target.host, target.port, Via::Http).await {
            Route::Credential => {
                let config = match self.node.ca.server_config(&target.host) {
                    Ok(config) => config,
                    Err(err) => {
                        tracing::warn!("no certificate for {}: {err}", target.host);
                        return status(StatusCode::BAD_GATEWAY);
                    }
                };
                let command = self.clone();
                self.tasks.spawn(async move {
                    let Ok(upgraded) = upgrade.await else { return };
                    let Ok(tls) = TlsAcceptor::from(config)
                        .accept(TokioIo::new(upgraded))
                        .await
                    else {
                        return;
                    };
                    let service = service_fn(move |req| {
                        let command = command.clone();
                        let target = target.clone();
                        async move { Ok::<_, Infallible>(command.tunneled(req, target).await) }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
            Route::Direct(addresses) => {
                let Ok(mut upstream) = connect(&addresses).await else {
                    return status(StatusCode::BAD_GATEWAY);
                };
                self.tasks.spawn(async move {
                    let Ok(upgraded) = upgrade.await else { return };
                    let _ =
                        tokio::io::copy_bidirectional(&mut TokioIo::new(upgraded), &mut upstream)
                            .await;
                });
            }
            Route::Refused(reason) => return refused(reason, &target),
            Route::Unresolved => return status(StatusCode::BAD_GATEWAY),
        }
        status(StatusCode::OK)
    }

    /// A request inside a terminated TLS tunnel to a credential-route host.
    async fn tunneled(self: Arc<Self>, req: Request<Incoming>, target: Target) -> Response<Body> {
        if is_upgrade(&req) || req.method() == Method::CONNECT {
            return status(StatusCode::NOT_IMPLEMENTED);
        }
        self.forward(req, Scheme::Https, target).await
    }

    /// Sends the request through the control plane as a stream.
    async fn forward(
        &self,
        req: Request<Incoming>,
        scheme: Scheme,
        target: Target,
    ) -> Response<Body> {
        let Some((token, _)) = &self.credential else {
            return status(StatusCode::BAD_GATEWAY);
        };
        let (parts, body) = req.into_parts();
        let headers = parts
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()));
        let request = ProxyRequest {
            stream_id: StreamId::generate(),
            exec_id: self.exec_id.clone(),
            token: token.clone(),
            method: parts.method.as_str().to_owned(),
            scheme,
            host: target.host,
            port: target.port,
            path: origin_form(&parts.uri),
            headers: end_to_end(headers.collect())
                .into_iter()
                .map(|(name, value)| (name, Bytes(value)))
                .collect(),
        };
        let streams = self.node.streams();
        let Ok((guard, head)) = streams.open_http(request) else {
            return status(StatusCode::SERVICE_UNAVAILABLE);
        };
        self.tasks.spawn(pump(streams.clone(), guard.id(), body));
        match head.await {
            Ok(Ok((response, pieces))) => respond(response, pieces, guard),
            _ => status(StatusCode::BAD_GATEWAY),
        }
    }

    /// Forwards a plain HTTP request from the node itself, to the checked `addresses`.
    async fn direct(&self, mut req: Request<Incoming>, addresses: &[SocketAddr]) -> Response<Body> {
        let upgrade = is_upgrade(&req).then(|| {
            (
                req.headers().get(header::UPGRADE).cloned(),
                hyper::upgrade::on(&mut req),
            )
        });
        let Ok(tcp) = connect(addresses).await else {
            return status(StatusCode::BAD_GATEWAY);
        };
        let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await
        else {
            return status(StatusCode::BAD_GATEWAY);
        };
        self.tasks.spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        let authority = req.uri().authority().map(|a| a.as_str().to_owned());
        let path = origin_form(req.uri());
        *req.uri_mut() = path.parse().unwrap_or_else(|_| Uri::from_static("/"));
        strip_hop_by_hop(req.headers_mut());
        if let (Some(authority), false) = (authority, req.headers().contains_key(header::HOST))
            && let Ok(host) = HeaderValue::from_str(&authority)
        {
            req.headers_mut().insert(header::HOST, host);
        }
        if let Some((Some(protocol), _)) = &upgrade {
            req.headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            req.headers_mut().insert(header::UPGRADE, protocol.clone());
        }
        let Ok(mut response) = sender.send_request(req).await else {
            return status(StatusCode::BAD_GATEWAY);
        };
        match upgrade {
            Some((_, client)) if response.status() == StatusCode::SWITCHING_PROTOCOLS => {
                let server = hyper::upgrade::on(&mut response);
                self.tasks.spawn(async move {
                    if let (Ok(client), Ok(server)) = (client.await, server.await) {
                        let _ = tokio::io::copy_bidirectional(
                            &mut TokioIo::new(client),
                            &mut TokioIo::new(server),
                        )
                        .await;
                    }
                });
            }
            _ => strip_hop_by_hop(response.headers_mut()),
        }
        response.map(|body| body.map_err(BoxError::from).boxed())
    }
}

#[derive(Clone)]
struct Target {
    host: String,
    port: u16,
}

impl Target {
    /// The target of an absolute-form `http://` request.
    fn of(uri: &Uri) -> Option<Target> {
        let authority = uri
            .authority()
            .filter(|_| uri.scheme_str() == Some("http"))?;
        Some(Target {
            host: normalize(authority.host()),
            port: authority.port_u16().unwrap_or(80),
        })
    }
}

fn origin_form(uri: &Uri) -> String {
    uri.path_and_query()
        .map(|pq| pq.as_str())
        .filter(|pq| !pq.is_empty())
        .unwrap_or("/")
        .to_owned()
}

fn is_upgrade<B>(req: &Request<B>) -> bool {
    req.headers().contains_key(header::UPGRADE)
}

/// Reads the client's request body into `proxy.body` pieces, pausing while the stream has no
/// window, then sends `proxy.end`.
async fn pump(streams: Arc<Streams>, id: StreamId, mut body: Incoming) {
    loop {
        match body.frame().await {
            None => return streams.end_outbound(id),
            Some(Err(_)) => return streams.reset(id, "the client's request body failed"),
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data()
                    && !streams.send_all(id, &data).await
                {
                    return;
                }
            }
        }
    }
}

fn respond(
    response: ProxyResponse,
    pieces: mpsc::UnboundedReceiver<Piece>,
    guard: StreamGuard,
) -> Response<Body> {
    let headers = end_to_end(
        response
            .headers
            .into_iter()
            .map(|(name, value)| (name, value.0))
            .collect(),
    );
    let mut builder = Response::builder().status(response.status);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let head = builder
        .body(())
        .map_err(|err| err.to_string())
        .and_then(|head| {
            if head.status().is_informational() {
                Err(format!("status {}", head.status()))
            } else {
                Ok(head)
            }
        });
    match head {
        Ok(head) => head.map(|()| ResponseBody { pieces, guard }.boxed()),
        Err(err) => {
            guard
                .streams()
                .reset(guard.id(), &format!("invalid proxy.response: {err}"));
            status(StatusCode::BAD_GATEWAY)
        }
    }
}

/// A response body arriving as `proxy.body`, credited as the client takes it.
struct ResponseBody {
    pieces: mpsc::UnboundedReceiver<Piece>,
    guard: StreamGuard,
}

impl hyper::body::Body for ResponseBody {
    type Data = bytes::Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<bytes::Bytes>, BoxError>>> {
        Poll::Ready(match ready!(self.pieces.poll_recv(cx)) {
            Some(Piece::Data(data)) => {
                self.guard.streams().consumed(self.guard.id(), data.len());
                Some(Ok(Frame::data(data.into())))
            }
            Some(Piece::Abort) => Some(Err("the response was abandoned".into())),
            None => None,
        })
    }
}

/// Drops hop-by-hop headers and the ones `connection` names. Names compare case-insensitively.
fn end_to_end(headers: Vec<(String, Vec<u8>)>) -> Vec<(String, Vec<u8>)> {
    let named = connection_tokens(
        headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
            .map(|(_, value)| value.as_slice()),
    );
    headers
        .into_iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value))
        .filter(|(name, _)| !HOP_BY_HOP.contains(&name.as_str()) && !named.contains(name))
        .collect()
}

fn strip_hop_by_hop(headers: &mut http::HeaderMap) {
    let named = connection_tokens(
        headers
            .get_all(header::CONNECTION)
            .iter()
            .map(HeaderValue::as_bytes),
    );
    for name in HOP_BY_HOP
        .iter()
        .copied()
        .chain(named.iter().map(String::as_str))
    {
        headers.remove(name);
    }
}

fn connection_tokens<'a>(values: impl Iterator<Item = &'a [u8]>) -> Vec<String> {
    values
        .flat_map(|value| value.split(|&b| b == b','))
        .map(|token| String::from_utf8_lossy(token).trim().to_ascii_lowercase())
        .collect()
}

/// `403` with the one-line reason.
fn refused(reason: DenyReason, target: &Target) -> Response<Body> {
    let mut response = Response::new(
        Full::new(bytes::Bytes::from(explain(
            reason,
            &target.host,
            target.port,
        )))
        .map_err(|never| match never {})
        .boxed(),
    );
    *response.status_mut() = StatusCode::FORBIDDEN;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn status(code: StatusCode) -> Response<Body> {
    let mut response = Response::new(Empty::new().map_err(|never| match never {}).boxed());
    *response.status_mut() = code;
    response
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
