//! Every forwarded request on this node, each a small state machine per direction (proxy.md,
//! Link messages, Flow control, Limits and failure). All transitions happen under one lock,
//! and messages to the control plane are sent under it, so a stream's messages leave in the
//! order its transitions happened.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{Notify, mpsc, oneshot};

use super::Upstream;
use crate::protocol::{
    Bytes, ExecId, MAX_PROXY_BODY_BYTES, ProxyBody, ProxyCredit, ProxyEnd, ProxyMessage,
    ProxyRequest, ProxyReset, ProxyResponse, StreamId,
};

/// Each direction's initial flow-control window.
pub(crate) const WINDOW: u64 = 1 << 20;
pub(crate) const STREAMS_PER_EXEC: usize = 64;
pub(crate) const STREAMS_PER_NODE: usize = 1024;
/// Request body bytes in flight across the node. Every one of them sits in the link's retained
/// queue until acknowledged, and that queue ends the session at 64 MiB.
pub(crate) const NODE_UNCREDITED: u64 = 32 << 20;

pub(crate) struct Streams {
    upstream: Box<dyn Upstream>,
    table: Mutex<Table>,
    /// Woken when request bodies may be able to send more: credit arrived, or a stream ended.
    changed: Notify,
}

#[derive(Default)]
struct Table {
    streams: HashMap<StreamId, Stream>,
    /// Request body bytes sent on every stream and not yet credited.
    uncredited: u64,
}

struct Stream {
    exec_id: ExecId,
    request: RequestSide,
    response: ResponseSide,
}

/// The request body, node to control plane.
struct RequestSide {
    window: u64,
    uncredited: u64,
    ended: bool,
}

/// The response, control plane to node.
enum ResponseSide {
    AwaitingHead(oneshot::Sender<Head>),
    Body {
        client: mpsc::UnboundedSender<Piece>,
        /// Received and not yet passed on to the client.
        uncredited: u64,
    },
    Ended,
}

/// What a client waiting for a response gets. `Err` means it never will: answer `502`.
pub(crate) type Head = Result<(ProxyResponse, mpsc::UnboundedReceiver<Piece>), Failed>;

#[derive(Debug)]
pub(crate) struct Failed;

/// A piece of a response body. The channel closing is the end of the body.
#[derive(Debug)]
pub(crate) enum Piece {
    Data(Vec<u8>),
    /// The response will not complete. Close the client connection.
    Abort,
}

/// The stream limit is reached. Answer `503`.
#[derive(Debug)]
pub(crate) struct Busy;

pub(crate) enum Reserve {
    /// This many leading bytes went out as one `proxy.body`.
    Sent(usize),
    /// No window or node budget. Wait for [`Streams::changed`] and try again.
    Blocked,
    /// The stream is gone. Stop reading the request body.
    Gone,
}

/// Held by the client side of a stream. Dropping it before the stream completed resets it.
pub(crate) struct StreamGuard {
    streams: Arc<Streams>,
    id: StreamId,
}

impl StreamGuard {
    pub(crate) fn id(&self) -> StreamId {
        self.id
    }

    pub(crate) fn streams(&self) -> &Arc<Streams> {
        &self.streams
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.streams.reset(self.id, "client closed the connection");
    }
}

impl Streams {
    pub(crate) fn new(upstream: Box<dyn Upstream>) -> Streams {
        Streams {
            upstream,
            table: Mutex::new(Table::default()),
            changed: Notify::new(),
        }
    }

    pub(crate) fn changed(&self) -> &Notify {
        &self.changed
    }

    /// Sends `proxy.request` for a new stream.
    pub(crate) fn open(
        self: &Arc<Self>,
        request: ProxyRequest,
    ) -> Result<(StreamGuard, oneshot::Receiver<Head>), Busy> {
        let mut table = self.table.lock().unwrap();
        let of_exec = table
            .streams
            .values()
            .filter(|s| s.exec_id == request.exec_id)
            .count();
        if table.streams.len() >= STREAMS_PER_NODE || of_exec >= STREAMS_PER_EXEC {
            return Err(Busy);
        }
        let (head_tx, head_rx) = oneshot::channel();
        let id = request.stream_id;
        table.streams.insert(
            id,
            Stream {
                exec_id: request.exec_id.clone(),
                request: RequestSide {
                    window: WINDOW,
                    uncredited: 0,
                    ended: false,
                },
                response: ResponseSide::AwaitingHead(head_tx),
            },
        );
        self.upstream.send(ProxyMessage::Request(request));
        let guard = StreamGuard {
            streams: self.clone(),
            id,
        };
        Ok((guard, head_rx))
    }

    /// Sends as much of `data` as the stream's window and the node's budget allow, at most
    /// [`MAX_PROXY_BODY_BYTES`].
    pub(crate) fn send_body(&self, id: StreamId, data: &[u8]) -> Reserve {
        let mut table = self.table.lock().unwrap();
        let node_room = NODE_UNCREDITED.saturating_sub(table.uncredited);
        let Some(stream) = table.streams.get_mut(&id) else {
            return Reserve::Gone;
        };
        let n = (data.len() as u64)
            .min(MAX_PROXY_BODY_BYTES as u64)
            .min(stream.request.window)
            .min(node_room) as usize;
        if n == 0 {
            return Reserve::Blocked;
        }
        stream.request.window -= n as u64;
        stream.request.uncredited += n as u64;
        table.uncredited += n as u64;
        self.upstream.send(ProxyMessage::Body(ProxyBody {
            stream_id: id,
            data: Bytes(data[..n].to_vec()),
        }));
        Reserve::Sent(n)
    }

    pub(crate) fn end_request(&self, id: StreamId) {
        let mut table = self.table.lock().unwrap();
        let Some(stream) = table.streams.get_mut(&id) else {
            return;
        };
        stream.request.ended = true;
        self.upstream
            .send(ProxyMessage::End(ProxyEnd { stream_id: id }));
        self.complete_if_done(&mut table, id);
    }

    /// The client took `bytes` of the response body.
    pub(crate) fn client_took(&self, id: StreamId, bytes: usize) {
        let mut table = self.table.lock().unwrap();
        if let Some(Stream {
            response: ResponseSide::Body { uncredited, .. },
            ..
        }) = table.streams.get_mut(&id)
        {
            *uncredited = uncredited.saturating_sub(bytes as u64);
            self.upstream.send(ProxyMessage::Credit(ProxyCredit {
                stream_id: id,
                bytes: bytes as u64,
            }));
        }
    }

    /// Abandons the stream in both directions, telling the control plane.
    pub(crate) fn reset(&self, id: StreamId, reason: &str) {
        let mut table = self.table.lock().unwrap();
        self.reset_locked(&mut table, id, reason);
    }

    /// A message from the control plane.
    pub(crate) fn on_message(&self, message: ProxyMessage) {
        let mut table = self.table.lock().unwrap();
        match message {
            ProxyMessage::Request(_) => {}
            ProxyMessage::Response(response) => {
                let id = response.stream_id;
                let Some(stream) = table.streams.get_mut(&id) else {
                    return;
                };
                let ResponseSide::AwaitingHead(head) =
                    std::mem::replace(&mut stream.response, ResponseSide::Ended)
                else {
                    return self.reset_locked(&mut table, id, "a second proxy.response");
                };
                let (client, body) = mpsc::unbounded_channel();
                stream.response = ResponseSide::Body {
                    client,
                    uncredited: 0,
                };
                if head.send(Ok((response, body))).is_err() {
                    self.reset_locked(&mut table, id, "client closed the connection");
                }
            }
            ProxyMessage::Body(ProxyBody { stream_id, data }) => {
                let Some(stream) = table.streams.get_mut(&stream_id) else {
                    return;
                };
                let ResponseSide::Body { client, uncredited } = &mut stream.response else {
                    return self.reset_locked(
                        &mut table,
                        stream_id,
                        "proxy.body outside a response",
                    );
                };
                if data.0.len() > MAX_PROXY_BODY_BYTES {
                    return self.reset_locked(&mut table, stream_id, "proxy.body over 64 KiB");
                }
                *uncredited += data.0.len() as u64;
                if *uncredited > WINDOW {
                    return self.reset_locked(
                        &mut table,
                        stream_id,
                        "the response overran its window",
                    );
                }
                if client.send(Piece::Data(data.0)).is_err() {
                    self.reset_locked(&mut table, stream_id, "client closed the connection");
                }
            }
            ProxyMessage::End(ProxyEnd { stream_id }) => {
                let Some(stream) = table.streams.get_mut(&stream_id) else {
                    return;
                };
                match stream.response {
                    ResponseSide::Body { .. } => {
                        stream.response = ResponseSide::Ended;
                        self.complete_if_done(&mut table, stream_id);
                    }
                    ResponseSide::AwaitingHead(_) => {
                        self.reset_locked(&mut table, stream_id, "proxy.end before proxy.response")
                    }
                    ResponseSide::Ended => {}
                }
            }
            ProxyMessage::Reset(ProxyReset { stream_id, .. }) => {
                if let Some(stream) = table.remove(stream_id) {
                    stream.abort();
                    self.changed.notify_waiters();
                }
            }
            ProxyMessage::Credit(ProxyCredit { stream_id, bytes }) => {
                let Some(stream) = table.streams.get_mut(&stream_id) else {
                    return;
                };
                let freed = bytes.min(stream.request.uncredited);
                stream.request.window = stream.request.window.saturating_add(bytes);
                stream.request.uncredited -= freed;
                table.uncredited -= freed;
                self.changed.notify_waiters();
            }
        }
    }

    /// The command's proxy stopped: reset its streams.
    pub(crate) fn exec_stopped(&self, exec_id: &ExecId) {
        let mut table = self.table.lock().unwrap();
        let ids: Vec<StreamId> = table
            .streams
            .iter()
            .filter(|(_, s)| s.exec_id == *exec_id)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.reset_locked(&mut table, id, "the command exited");
        }
    }

    /// The session is gone and with it every stream. Nothing is sent: the control plane
    /// forgot them too.
    pub(crate) fn session_lost(&self) {
        let mut table = self.table.lock().unwrap();
        for (_, stream) in table.streams.drain() {
            stream.abort();
        }
        table.uncredited = 0;
        self.changed.notify_waiters();
    }

    fn reset_locked(&self, table: &mut Table, id: StreamId, reason: &str) {
        if let Some(stream) = table.remove(id) {
            self.upstream.send(ProxyMessage::Reset(ProxyReset {
                stream_id: id,
                reason: reason.to_owned(),
            }));
            stream.abort();
            self.changed.notify_waiters();
        }
    }

    fn complete_if_done(&self, table: &mut Table, id: StreamId) {
        if table
            .streams
            .get(&id)
            .is_some_and(|s| s.request.ended && matches!(s.response, ResponseSide::Ended))
        {
            table.remove(id);
            self.changed.notify_waiters();
        }
    }
}

impl Table {
    fn remove(&mut self, id: StreamId) -> Option<Stream> {
        let stream = self.streams.remove(&id)?;
        self.uncredited -= stream.request.uncredited;
        Some(stream)
    }
}

impl Stream {
    fn abort(self) {
        match self.response {
            ResponseSide::AwaitingHead(head) => {
                let _ = head.send(Err(Failed));
            }
            ResponseSide::Body { client, .. } => {
                let _ = client.send(Piece::Abort);
            }
            ResponseSide::Ended => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ProxyToken, Scheme};

    #[derive(Clone, Default)]
    struct Recorder(Arc<Mutex<Vec<ProxyMessage>>>);

    impl Upstream for Recorder {
        fn send(&self, message: ProxyMessage) {
            self.0.lock().unwrap().push(message);
        }
    }

    impl Recorder {
        fn take(&self) -> Vec<ProxyMessage> {
            std::mem::take(&mut self.0.lock().unwrap())
        }
    }

    fn streams() -> (Arc<Streams>, Recorder) {
        let recorder = Recorder::default();
        (Arc::new(Streams::new(Box::new(recorder.clone()))), recorder)
    }

    fn request(exec: &str) -> ProxyRequest {
        ProxyRequest {
            stream_id: StreamId::generate(),
            exec_id: ExecId::try_from(exec).unwrap(),
            token: ProxyToken::try_from("pt").unwrap(),
            method: "PUT".into(),
            scheme: Scheme::Https,
            host: "api.example.test".into(),
            port: 443,
            path: "/".into(),
            headers: Vec::new(),
        }
    }

    /// Sends `bytes` of request body, returning how many went out before the stream blocked.
    fn upload(streams: &Streams, id: StreamId, bytes: usize) -> usize {
        let data = vec![7u8; bytes];
        let mut sent = 0;
        while sent < bytes {
            match streams.send_body(id, &data[sent..]) {
                Reserve::Sent(n) => sent += n,
                Reserve::Blocked | Reserve::Gone => break,
            }
        }
        sent
    }

    #[test]
    fn the_node_caps_uncredited_request_bytes_across_streams() {
        let (streams, _) = streams();
        let guards: Vec<_> = (0..33)
            .map(|_| streams.open(request("upload")).unwrap().0)
            .collect();
        let sent: Vec<usize> = guards
            .iter()
            .map(|g| upload(&streams, g.id(), 2 * WINDOW as usize))
            .collect();
        assert_eq!(sent[..32], [WINDOW as usize; 32]);
        assert_eq!(sent[32], 0, "32 MiB in flight across the node");

        streams.on_message(ProxyMessage::Credit(ProxyCredit {
            stream_id: guards[0].id(),
            bytes: 100,
        }));
        assert_eq!(upload(&streams, guards[32].id(), WINDOW as usize), 100);
    }

    #[test]
    fn a_reset_stream_releases_its_share_of_the_node_budget() {
        let (streams, _) = streams();
        let guards: Vec<_> = (0..33)
            .map(|_| streams.open(request("upload")).unwrap().0)
            .collect();
        for g in &guards {
            upload(&streams, g.id(), WINDOW as usize);
        }
        streams.on_message(ProxyMessage::Reset(ProxyReset {
            stream_id: guards[0].id(),
            reason: "gone".into(),
        }));
        assert_eq!(
            upload(&streams, guards[32].id(), WINDOW as usize),
            WINDOW as usize
        );
    }

    #[test]
    fn the_node_limit_counts_every_command() {
        let (streams, _) = streams();
        let guards: Vec<_> = (0..STREAMS_PER_NODE)
            .map(|i| {
                streams
                    .open(request(&format!("exec-{}", i / 64)))
                    .unwrap()
                    .0
            })
            .collect();
        assert!(streams.open(request("another")).is_err());
        drop(guards);
        assert!(streams.open(request("another")).is_ok());
    }

    #[tokio::test]
    async fn a_body_before_the_response_head_resets_the_stream() {
        let (streams, recorder) = streams();
        let (guard, head) = streams.open(request("x")).unwrap();
        let id = guard.id();
        recorder.take();
        streams.on_message(ProxyMessage::Body(ProxyBody {
            stream_id: id,
            data: Bytes(b"early".to_vec()),
        }));
        assert!(matches!(head.await, Ok(Err(Failed))));
        assert_eq!(
            recorder.take(),
            [ProxyMessage::Reset(ProxyReset {
                stream_id: id,
                reason: "proxy.body outside a response".into()
            })]
        );
        drop(guard);
        assert_eq!(recorder.take(), [], "a reset stream is not reset twice");
    }

    #[tokio::test]
    async fn a_response_past_its_window_resets_the_stream() {
        let (streams, recorder) = streams();
        let (guard, head) = streams.open(request("x")).unwrap();
        let id = guard.id();
        streams.on_message(ProxyMessage::Response(ProxyResponse {
            stream_id: id,
            status: 200,
            headers: Vec::new(),
        }));
        let (_, mut pieces) = head.await.unwrap().unwrap();
        recorder.take();
        for _ in 0..16 {
            streams.on_message(ProxyMessage::Body(ProxyBody {
                stream_id: id,
                data: Bytes(vec![0; MAX_PROXY_BODY_BYTES]),
            }));
        }
        assert_eq!(recorder.take(), [], "exactly one window is fine");
        streams.on_message(ProxyMessage::Body(ProxyBody {
            stream_id: id,
            data: Bytes(vec![0]),
        }));
        assert_eq!(
            recorder.take(),
            [ProxyMessage::Reset(ProxyReset {
                stream_id: id,
                reason: "the response overran its window".into()
            })]
        );
        let mut data = 0;
        while let Some(Piece::Data(d)) = pieces.recv().await {
            data += d.len();
        }
        assert_eq!(data, WINDOW as usize);
    }
}
