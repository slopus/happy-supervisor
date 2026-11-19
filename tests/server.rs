//! A control plane built on `ws::upgrade` and `ControlPlaneLink`, the way a real one is
//! (api.md, Control-plane library), with the real binary dialing it.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use happy_supervisor::protocol::{ByeReason, NodeInfo};
use happy_supervisor::server::{ControlPlaneLink, LinkEvent, LinkEvents, RESUME_WINDOW_MS};
use happy_supervisor::state::{Credentials, StateDir};
use http::{Request, Response, StatusCode, header};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::process::{Child, Command};

const BIN: &str = env!("CARGO_BIN_EXE_happy-supervisor");
const NODE_TOKEN: &str = "nt_server_test";
const WAIT: Duration = Duration::from_secs(30);

/// Accepts the node's WebSockets for one link, refusing other tokens with 401.
async fn control_plane(link: Arc<ControlPlaneLink>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}/nodes/connect", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let link = link.clone();
            let service = service_fn(move |request| {
                let link = link.clone();
                async move { Ok::<_, std::convert::Infallible>(accept(&link, request)) }
            });
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades(),
            );
        }
    });
    endpoint
}

fn accept(link: &Arc<ControlPlaneLink>, mut request: Request<Incoming>) -> Response<Full<Bytes>> {
    let refuse = |status, why: &str| {
        let mut response = Response::new(Full::new(Bytes::from(why.to_string())));
        *response.status_mut() = status;
        response
    };
    let bearer = format!("Bearer {NODE_TOKEN}");
    if request.headers().get(header::AUTHORIZATION) != Some(&bearer.parse().unwrap()) {
        return refuse(StatusCode::UNAUTHORIZED, "unknown node");
    }
    match happy_supervisor::ws::upgrade(&mut request, 2) {
        Ok((response, upgrading)) => {
            let link = link.clone();
            tokio::spawn(async move { link.attach(upgrading.socket().await.unwrap()) });
            response.map(|_| Full::new(Bytes::new()))
        }
        Err(refused) => refuse(refused.status, refused.reason),
    }
}

/// `happy-supervisor run` with credentials for `endpoint`.
fn run_node(state: &std::path::Path, endpoint: &str) -> Child {
    StateDir::open(Some(state.to_path_buf()))
        .unwrap()
        .store_credentials(&Credentials {
            endpoint: endpoint.to_string(),
            node_id: "node_server_test".to_string(),
            node_token: NODE_TOKEN.to_string(),
            name: "server-test".to_string(),
        })
        .unwrap();
    Command::new(BIN)
        .args(["run", "--state-dir"])
        .arg(state)
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

async fn next(events: &mut LinkEvents) -> LinkEvent {
    tokio::time::timeout(WAIT, events.next())
        .await
        .expect("no link event")
        .expect("the link is gone")
}

#[tokio::test]
async fn a_control_plane_accepts_a_node_and_revokes_it() {
    let link = Arc::new(ControlPlaneLink::new(RESUME_WINDOW_MS));
    let mut events = link.events();
    let endpoint = control_plane(link.clone()).await;
    let state = tempfile::tempdir().unwrap();
    let mut node = run_node(state.path(), &endpoint);

    let LinkEvent::Opened {
        session,
        resumed,
        hello,
    } = next(&mut events).await
    else {
        panic!("the first event is not Opened");
    };
    assert!(!resumed);
    assert_eq!(hello.node_id, "node_server_test");
    assert_eq!(link.session(), Some(session));
    let LinkEvent::Event(happy_supervisor::protocol::Event::NodeReady(ready)) =
        next(&mut events).await
    else {
        panic!("node.ready did not follow");
    };
    assert_eq!(ready.info.installation_id, hello.installation_id);

    let info: NodeInfo = link.command("node.info", ()).await.unwrap();
    assert_eq!(info.installation_id, hello.installation_id);
    let unknown = link
        .call("node.nope", happy_supervisor::protocol::Value::Null)
        .await
        .unwrap_err();
    assert_eq!(unknown.message, "unknown message kind `node.nope`");

    link.bye(ByeReason::Revoked, Some("revoked by the test".to_string()));
    let status = tokio::time::timeout(WAIT, node.wait())
        .await
        .expect("the node did not exit")
        .unwrap();
    assert_eq!(status.code(), Some(3));
    loop {
        if let LinkEvent::Lost { session: lost, .. } = next(&mut events).await {
            assert_eq!(lost, session);
            break;
        }
    }
    assert_eq!(link.session(), None);
}
