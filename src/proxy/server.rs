//! One command's proxy: the loopback listener, proxy authentication, and the three kinds of
//! client request (proxy.md, How requests travel).

use std::convert::Infallible;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use base64::Engine;
use http::header::{self, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use super::ca::NodeCa;
use crate::error::Result;
use crate::protocol::{
    Bytes, ExecId, HostPattern, ProxyRequest, ProxyResponse, ProxyToken, Scheme, StreamId,
};
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

/// Everything one command's proxy needs, shared by its connections.
pub(crate) struct Proxy {
    pub(crate) exec_id: ExecId,
    pub(crate) token: ProxyToken,
    pub(crate) hosts: Vec<HostPattern>,
    /// `happy:<secret>`, what `proxy-authorization` must carry.
    pub(crate) credentials: String,
    pub(crate) streams: Arc<Streams>,
    pub(crate) ca: NodeCa,
    pub(crate) tasks: Tasks,
}

/// The proxy's tasks. Closing aborts them and refuses new ones.
#[derive(Default)]
pub(crate) struct Tasks(Mutex<Option<JoinSet<()>>>);

impl Tasks {
    pub(crate) fn open() -> Tasks {
        Tasks(Mutex::new(Some(JoinSet::new())))
    }

    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        if let Some(set) = self.0.lock().unwrap().as_mut() {
            while set.try_join_next().is_some() {}
            set.spawn(task);
        }
    }

    pub(crate) fn close(&self) {
        self.0.lock().unwrap().take();
    }
}

/// Binds `127.0.0.1:0` and serves it until the proxy's tasks close. Returns the port.
pub(crate) async fn listen(proxy: Arc<Proxy>) -> Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    proxy.tasks.spawn(accept(listener, proxy.clone()));
    Ok(port)
}

async fn accept(listener: TcpListener, proxy: Arc<Proxy>) {
    loop {
        match listener.accept().await {
            Ok((tcp, _)) => {
                let _ = tcp.set_nodelay(true);
                proxy.tasks.spawn(serve(proxy.clone(), tcp));
            }
            Err(err) => {
                tracing::warn!(exec_id = %proxy.exec_id, "proxy accept failed: {err}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn serve(proxy: Arc<Proxy>, tcp: TcpStream) {
    let service = service_fn(move |req| {
        let proxy = proxy.clone();
        async move { Ok::<_, Infallible>(proxy.handle(req).await) }
    });
    let _ = http1::Builder::new()
        .serve_connection(TokioIo::new(tcp), service)
        .with_upgrades()
        .await;
}

impl Proxy {
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
        if !self.listed(&target.host) {
            return self.direct(req, target).await;
        }
        if is_upgrade(&req) {
            return status(StatusCode::NOT_IMPLEMENTED);
        }
        self.forward(req, Scheme::Http, target).await
    }

    fn authorized<B>(&self, req: &Request<B>) -> bool {
        let Some(value) = req.headers().get(header::PROXY_AUTHORIZATION) else {
            return false;
        };
        let Some((scheme, encoded)) = value.to_str().ok().and_then(|v| v.split_once(' ')) else {
            return false;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
            return false;
        };
        scheme.eq_ignore_ascii_case("basic")
            && constant_time_eq(&decoded, self.credentials.as_bytes())
    }

    fn listed(&self, host: &str) -> bool {
        self.hosts.iter().any(|pattern| pattern.matches(host))
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
        if self.listed(&target.host) {
            let config = match self.ca.server_config(&target.host) {
                Ok(config) => config,
                Err(err) => {
                    tracing::warn!("no certificate for {}: {err}", target.host);
                    return status(StatusCode::BAD_GATEWAY);
                }
            };
            let proxy = self.clone();
            self.tasks.spawn(async move {
                let Ok(upgraded) = upgrade.await else { return };
                let Ok(tls) = TlsAcceptor::from(config)
                    .accept(TokioIo::new(upgraded))
                    .await
                else {
                    return;
                };
                let service = service_fn(move |req| {
                    let proxy = proxy.clone();
                    let target = target.clone();
                    async move { Ok::<_, Infallible>(proxy.tunneled(req, target).await) }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        } else {
            let mut upstream = match TcpStream::connect((target.host.as_str(), target.port)).await {
                Ok(upstream) => upstream,
                Err(_) => return status(StatusCode::BAD_GATEWAY),
            };
            self.tasks.spawn(async move {
                let Ok(upgraded) = upgrade.await else { return };
                let _ =
                    tokio::io::copy_bidirectional(&mut TokioIo::new(upgraded), &mut upstream).await;
            });
        }
        status(StatusCode::OK)
    }

    /// A request inside a terminated TLS tunnel to a listed host.
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
        let (parts, body) = req.into_parts();
        let headers = parts
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()));
        let request = ProxyRequest {
            stream_id: StreamId::generate(),
            exec_id: self.exec_id.clone(),
            token: self.token.clone(),
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
        let Ok((guard, head)) = self.streams.open_http(request) else {
            return status(StatusCode::SERVICE_UNAVAILABLE);
        };
        self.tasks
            .spawn(pump(self.streams.clone(), guard.id(), body));
        match head.await {
            Ok(Ok((response, pieces))) => respond(response, pieces, guard),
            _ => status(StatusCode::BAD_GATEWAY),
        }
    }

    /// Forwards a plain HTTP request to an unlisted host from the node itself.
    async fn direct(&self, mut req: Request<Incoming>, target: Target) -> Response<Body> {
        let upgrade = is_upgrade(&req).then(|| {
            (
                req.headers().get(header::UPGRADE).cloned(),
                hyper::upgrade::on(&mut req),
            )
        });
        let Ok(tcp) = TcpStream::connect((target.host.as_str(), target.port)).await else {
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

/// Lowercase, no trailing dot, no IPv6 brackets.
fn normalize(host: &str) -> String {
    let host = host.strip_suffix('.').unwrap_or(host);
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.to_ascii_lowercase()
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

fn status(code: StatusCode) -> Response<Body> {
    let mut response = Response::new(Empty::new().map_err(|never| match never {}).boxed());
    *response.status_mut() = code;
    response
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
