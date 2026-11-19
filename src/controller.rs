//! The control-plane side of the link for Rust programs and tests (docs/serve.md, The Rust
//! client): a [`ControlPlaneLink`] over a WebSocket it dials to a `serve` node, redialing when
//! the connection drops so the session resumes.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

use crate::error::{Error, ErrorKind, Result};
use crate::protocol::{Event, ProxyMessage, SessionId, TcpMessage, Value};
use crate::server::{ControlPlaneLink, LinkEvent, LinkEvents, RESUME_WINDOW_MS};
use crate::ws::{Dialed, Socket};

const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const REDIAL_MIN: Duration = Duration::from_millis(100);
const REDIAL_MAX: Duration = Duration::from_secs(5);

/// A connection to one node. Dropping it closes the connection; the node keeps its processes
/// and loses the session once the resume window passes.
pub struct Controller {
    link: Arc<ControlPlaneLink>,
    redial: tokio::task::JoinHandle<()>,
}

/// The node's events from the moment [`Controller::events`] was called.
pub struct Events {
    events: LinkEvents,
}

impl Events {
    /// The next event; `None` once the controller is gone.
    pub async fn next(&mut self) -> Option<Event> {
        loop {
            if let LinkEvent::Event(event) = self.events.next().await? {
                return Some(event);
            }
        }
    }
}

impl Controller {
    /// Connects to a node's listener (`ws://IP:PORT`, `unix:PATH`) with its token, and returns
    /// once the session is open.
    pub async fn connect(url: &str, token: &str) -> Result<Controller> {
        let url = Url::parse(url)
            .map_err(|err| Error::invalid_params(format!("bad node URL {url:?}: {err}")))?;
        let socket = dial(&url, token).await?;
        let link = Arc::new(ControlPlaneLink::new(RESUME_WINDOW_MS));
        let events = link.events();
        link.attach(socket);
        let redial = tokio::spawn(redial(link.clone(), events, url, token.to_string()));
        let controller = Controller { link, redial };
        controller.link.opened(OPEN_TIMEOUT).await?;
        Ok(controller)
    }

    /// Sends a command and waits for its reply, as `R`. An `error` reply is the `Err`, and so
    /// is losing the session first.
    pub async fn command<P, R>(&self, kind: &str, params: P) -> Result<R>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        self.link.opened(OPEN_TIMEOUT).await?;
        self.link.command(kind, params).await
    }

    /// [`Controller::command`] with an untyped body and result.
    pub async fn call(&self, kind: &str, body: Value) -> Result<Value> {
        self.link.opened(OPEN_TIMEOUT).await?;
        self.link.call(kind, body).await
    }

    /// Every event the node sends from now on: `exec.output`, `exec.exit`, `watch.event`,
    /// `net.denied`, `node.ready`, and the `proxy.*` and `tcp.*` stream messages.
    pub fn events(&self) -> Events {
        Events {
            events: self.link.events(),
        }
    }

    /// Sends a `proxy.*` stream message, as the control plane's side of a stream (proxy.md).
    pub fn send_proxy(&self, message: ProxyMessage) {
        self.link.send_proxy(message);
    }

    /// Sends a `tcp.*` stream message, as the control plane's end of a tunnel (tunnels.md).
    pub fn send_tcp(&self, message: TcpMessage) {
        self.link.send_tcp(message);
    }

    /// The open session, `None` while there is none.
    pub fn session(&self) -> Option<SessionId> {
        self.link.session()
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.redial.abort();
        self.link.close();
    }
}

/// Dials again whenever the connection drops, until the node refuses the token or a newer
/// connection takes it over.
async fn redial(link: Arc<ControlPlaneLink>, mut events: LinkEvents, url: Url, token: String) {
    while let Some(event) = events.next().await {
        let LinkEvent::Disconnected { replaced } = event else {
            continue;
        };
        if replaced {
            tracing::info!("another connection took over the node");
            link.close();
            return;
        }
        let mut delay = REDIAL_MIN;
        let socket = loop {
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(REDIAL_MAX);
            match dial(&url, &token).await {
                Ok(socket) => break socket,
                Err(err) if err.kind == ErrorKind::PermissionDenied => {
                    tracing::warn!("{err}");
                    link.close();
                    return;
                }
                Err(err) => tracing::debug!("{err}"),
            }
        };
        link.attach(socket);
    }
}

async fn dial(url: &Url, token: &str) -> Result<Socket> {
    match crate::ws::dial(url, token).await {
        Ok(Dialed::Open(socket)) => Ok(*socket),
        Ok(Dialed::Refused(status)) => Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("{url} refused the token ({status})"),
        )),
        Err(err) => Err(Error::new(
            ErrorKind::Io,
            format!("connecting to {url}: {err}"),
        )),
    }
}
