//! The node's one stream table: credential-proxy streams (proxy.md) and TCP tunnels
//! (tunnels.md) under the same flow control and limits. Each stream is a small state machine per
//! direction. All transitions happen under one lock, and messages to the control plane are sent
//! under it, so a stream's messages leave in the order its transitions happened.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{Notify, mpsc, oneshot};

use crate::link::Outbox;
use crate::protocol::{
    Bytes, ExecId, MAX_PROXY_BODY_BYTES, MAX_STREAMS, MAX_TCP_DATA_BYTES, ProxyBody, ProxyCredit,
    ProxyEnd, ProxyMessage, ProxyRequest, ProxyReset, ProxyResponse, STREAM_WINDOW_BYTES, StreamId,
    TcpCredit, TcpData, TcpEnd, TcpMessage, TcpReset,
};

/// Where streams go: the link in the supervisor, an in-memory control plane in tests. Called
/// with internal locks held, so it must not block or call back into the node.
pub trait Upstream: Send + Sync + 'static {
    fn proxy(&self, message: ProxyMessage);
    fn tcp(&self, message: TcpMessage);
}

impl Upstream for Outbox {
    fn proxy(&self, message: ProxyMessage) {
        Outbox::proxy(self, message);
    }

    fn tcp(&self, message: TcpMessage) {
        Outbox::tcp(self, message);
    }
}

pub(crate) const PROXY_STREAMS_PER_EXEC: usize = 64;
/// Stream bytes sent by the node and not yet credited, across every stream. Every one of them
/// sits in the link's retained queue until acknowledged, and that queue ends the session at
/// 64 MiB.
pub(crate) const NODE_UNCREDITED: u64 = 32 << 20;

pub(crate) struct Streams {
    upstream: Box<dyn Upstream>,
    table: Mutex<Table>,
    /// Woken when senders may be able to send more: credit arrived, or a stream ended.
    changed: Notify,
}

#[derive(Default)]
struct Table {
    streams: HashMap<StreamId, Stream>,
    /// Bytes sent on every stream and not yet credited.
    uncredited: u64,
}

struct Stream {
    kind: Kind,
    outbound: Outbound,
    inbound: Inbound,
}

/// Which messages a stream speaks, and what only that kind has.
enum Kind {
    /// A credential-proxy request: `proxy.*`, counted against its command.
    Http { exec_id: ExecId },
    /// A tunnel: `tcp.*`. `abort` fires when the stream is reset or lost, so the tunnel closes
    /// its socket even while blocked on it.
    Tcp { abort: oneshot::Sender<()> },
}

/// Node to control plane: the request body, or bytes read from the local socket.
struct Outbound {
    window: u64,
    uncredited: u64,
    ended: bool,
}

/// Control plane to node: the response, or bytes for the local socket.
enum Inbound {
    /// A proxy stream before `proxy.response`.
    AwaitingHead(oneshot::Sender<Head>),
    Open {
        consumer: mpsc::UnboundedSender<Piece>,
        /// Received and not yet passed on.
        uncredited: u64,
    },
    Ended,
}

/// What a proxy client waiting for a response gets. `Err` means it never will: answer `502`.
pub(crate) type Head = Result<(ProxyResponse, mpsc::UnboundedReceiver<Piece>), Failed>;

#[derive(Debug)]
pub(crate) struct Failed;

/// A piece of inbound bytes. The channel closing is their end.
#[derive(Debug)]
pub(crate) enum Piece {
    Data(Vec<u8>),
    /// The stream will not complete. Close the client connection.
    Abort,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The stream limit is reached.
    Busy,
    /// A tunnel's ID is already a stream.
    InUse,
}

pub(crate) enum Reserve {
    /// This many leading bytes went out as one message.
    Sent(usize),
    /// No window or node budget. Wait for [`Streams::changed`] and try again.
    Blocked,
    /// The stream is gone. Stop reading the source.
    Gone,
}

/// A message from the control plane, whichever kind of stream it is for.
enum In {
    Head(ProxyResponse),
    Data(Vec<u8>),
    End,
    Reset,
    Credit(u64),
}

/// A message to the control plane, spoken in the stream's kind.
enum Out {
    Data(Vec<u8>),
    End,
    Reset(String),
    Credit(u64),
}

/// The local end of a tunnel: its inbound bytes, and the signal that it was reset or lost.
pub(crate) struct Tunnel {
    pub(crate) pieces: mpsc::UnboundedReceiver<Piece>,
    pub(crate) abort: oneshot::Receiver<()>,
}

/// Held by the client side of a proxy stream. Dropping it before the stream completed resets
/// it.
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

    /// Sends `proxy.request` for a new proxy stream.
    pub(crate) fn open_http(
        self: &Arc<Self>,
        request: ProxyRequest,
    ) -> Result<(StreamGuard, oneshot::Receiver<Head>), Refused> {
        let mut table = self.table.lock().unwrap();
        let of_exec = table
            .streams
            .values()
            .filter(|s| matches!(&s.kind, Kind::Http { exec_id } if *exec_id == request.exec_id))
            .count();
        if table.streams.len() >= MAX_STREAMS || of_exec >= PROXY_STREAMS_PER_EXEC {
            return Err(Refused::Busy);
        }
        let id = request.stream_id;
        if table.streams.contains_key(&id) {
            return Err(Refused::InUse);
        }
        let (head_tx, head_rx) = oneshot::channel();
        table.insert(
            id,
            Kind::Http {
                exec_id: request.exec_id.clone(),
            },
            Inbound::AwaitingHead(head_tx),
        );
        self.upstream.proxy(ProxyMessage::Request(request));
        let guard = StreamGuard {
            streams: self.clone(),
            id,
        };
        Ok((guard, head_rx))
    }

    /// Registers a tunnel the control plane named. Its inbound bytes are accepted, and
    /// buffered, at once: the control plane may send them before the connection exists.
    pub(crate) fn open_tcp(&self, id: StreamId) -> Result<Tunnel, Refused> {
        let mut table = self.table.lock().unwrap();
        if table.streams.contains_key(&id) {
            return Err(Refused::InUse);
        }
        if table.streams.len() >= MAX_STREAMS {
            return Err(Refused::Busy);
        }
        let (consumer, pieces) = mpsc::unbounded_channel();
        let (abort_tx, abort) = oneshot::channel();
        table.insert(
            id,
            Kind::Tcp { abort: abort_tx },
            Inbound::Open {
                consumer,
                uncredited: 0,
            },
        );
        Ok(Tunnel { pieces, abort })
    }

    /// Forgets a stream without telling the control plane: a tunnel whose connect failed.
    pub(crate) fn discard(&self, id: StreamId) {
        let mut table = self.table.lock().unwrap();
        if table.remove(id).is_some() {
            self.changed.notify_waiters();
        }
    }

    /// How many bytes the stream may send now. `None` once it is gone.
    pub(crate) fn room(&self, id: StreamId) -> Option<usize> {
        let table = self.table.lock().unwrap();
        let stream = table.streams.get(&id)?;
        let room = stream
            .outbound
            .window
            .min(NODE_UNCREDITED.saturating_sub(table.uncredited))
            .min(stream.kind.max_data() as u64);
        Some(room as usize)
    }

    /// Sends as much of `data` as the stream's window and the node's budget allow, in one
    /// message.
    pub(crate) fn send_data(&self, id: StreamId, data: &[u8]) -> Reserve {
        let mut table = self.table.lock().unwrap();
        let node_room = NODE_UNCREDITED.saturating_sub(table.uncredited);
        let Some(stream) = table.streams.get_mut(&id) else {
            return Reserve::Gone;
        };
        let n = (data.len() as u64)
            .min(stream.kind.max_data() as u64)
            .min(stream.outbound.window)
            .min(node_room) as usize;
        if n == 0 {
            return Reserve::Blocked;
        }
        stream.outbound.window -= n as u64;
        stream.outbound.uncredited += n as u64;
        table.uncredited += n as u64;
        self.emit(&table.streams[&id].kind, id, Out::Data(data[..n].to_vec()));
        Reserve::Sent(n)
    }

    /// Sends all of `data`, waiting for window and budget. `false` once the stream is gone.
    pub(crate) async fn send_all(&self, id: StreamId, mut data: &[u8]) -> bool {
        while !data.is_empty() {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match self.send_data(id, data) {
                Reserve::Sent(n) => data = &data[n..],
                Reserve::Blocked => changed.await,
                Reserve::Gone => return false,
            }
        }
        true
    }

    /// The node's side of the stream is complete.
    pub(crate) fn end_outbound(&self, id: StreamId) {
        let mut table = self.table.lock().unwrap();
        let Some(stream) = table.streams.get_mut(&id) else {
            return;
        };
        stream.outbound.ended = true;
        self.emit(&stream.kind, id, Out::End);
        self.complete_if_done(&mut table, id);
    }

    /// The consumer passed `bytes` of inbound data on, to the client or the local socket.
    pub(crate) fn consumed(&self, id: StreamId, bytes: usize) {
        let mut table = self.table.lock().unwrap();
        if let Some(Stream {
            kind,
            inbound: Inbound::Open { uncredited, .. },
            ..
        }) = table.streams.get_mut(&id)
        {
            *uncredited = uncredited.saturating_sub(bytes as u64);
            self.emit(kind, id, Out::Credit(bytes as u64));
        }
    }

    /// Abandons the stream in both directions, telling the control plane.
    pub(crate) fn reset(&self, id: StreamId, reason: &str) {
        let mut table = self.table.lock().unwrap();
        self.reset_locked(&mut table, id, reason);
    }

    /// A `proxy.*` message from the control plane.
    pub(crate) fn on_proxy(&self, message: ProxyMessage) {
        let (id, event) = match message {
            ProxyMessage::Request(_) => return,
            ProxyMessage::Response(response) => (response.stream_id, In::Head(response)),
            ProxyMessage::Body(m) => (m.stream_id, In::Data(m.data.0)),
            ProxyMessage::End(m) => (m.stream_id, In::End),
            ProxyMessage::Reset(m) => (m.stream_id, In::Reset),
            ProxyMessage::Credit(m) => (m.stream_id, In::Credit(m.bytes)),
        };
        self.on_message(id, false, event);
    }

    /// A `tcp.*` message from the control plane.
    pub(crate) fn on_tcp(&self, message: TcpMessage) {
        let (id, event) = match message {
            TcpMessage::Data(m) => (m.stream_id, In::Data(m.data.0)),
            TcpMessage::End(m) => (m.stream_id, In::End),
            TcpMessage::Reset(m) => (m.stream_id, In::Reset),
            TcpMessage::Credit(m) => (m.stream_id, In::Credit(m.bytes)),
        };
        self.on_message(id, true, event);
    }

    fn on_message(&self, id: StreamId, tcp: bool, event: In) {
        let mut table = self.table.lock().unwrap();
        let Some(stream) = table.streams.get_mut(&id) else {
            return;
        };
        if matches!(stream.kind, Kind::Tcp { .. }) != tcp {
            return;
        }
        match event {
            In::Head(response) => {
                let Inbound::AwaitingHead(head) =
                    std::mem::replace(&mut stream.inbound, Inbound::Ended)
                else {
                    return self.reset_locked(&mut table, id, "a second proxy.response");
                };
                let (consumer, body) = mpsc::unbounded_channel();
                stream.inbound = Inbound::Open {
                    consumer,
                    uncredited: 0,
                };
                if head.send(Ok((response, body))).is_err() {
                    self.reset_locked(&mut table, id, "client closed the connection");
                }
            }
            In::Data(data) => {
                let data_kind = stream.kind.data_kind();
                let max = stream.kind.max_data();
                let consumer = match &mut stream.inbound {
                    Inbound::Open {
                        consumer,
                        uncredited,
                    } => (consumer, uncredited),
                    Inbound::AwaitingHead(_) => {
                        return self.reset_locked(
                            &mut table,
                            id,
                            "proxy.body before proxy.response",
                        );
                    }
                    Inbound::Ended => {
                        let reason = format!("{data_kind} after the end");
                        return self.reset_locked(&mut table, id, &reason);
                    }
                };
                let (consumer, uncredited) = consumer;
                if data.len() > max {
                    let reason = format!("{data_kind} over 64 KiB");
                    return self.reset_locked(&mut table, id, &reason);
                }
                *uncredited += data.len() as u64;
                if *uncredited > STREAM_WINDOW_BYTES {
                    let reason = format!("{data_kind} overran the window");
                    return self.reset_locked(&mut table, id, &reason);
                }
                if consumer.send(Piece::Data(data)).is_err() {
                    self.reset_locked(&mut table, id, "client closed the connection");
                }
            }
            In::End => match stream.inbound {
                Inbound::Open { .. } => {
                    stream.inbound = Inbound::Ended;
                    self.complete_if_done(&mut table, id);
                }
                Inbound::AwaitingHead(_) => {
                    self.reset_locked(&mut table, id, "proxy.end before proxy.response")
                }
                Inbound::Ended => {}
            },
            In::Reset => {
                if let Some(stream) = table.remove(id) {
                    stream.abort();
                    self.changed.notify_waiters();
                }
            }
            In::Credit(bytes) => {
                let freed = bytes.min(stream.outbound.uncredited);
                stream.outbound.window = stream.outbound.window.saturating_add(bytes);
                stream.outbound.uncredited -= freed;
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
            .filter(|(_, s)| matches!(&s.kind, Kind::Http { exec_id: e } if e == exec_id))
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
            self.emit(&stream.kind, id, Out::Reset(reason.to_owned()));
            stream.abort();
            self.changed.notify_waiters();
        }
    }

    fn complete_if_done(&self, table: &mut Table, id: StreamId) {
        if table
            .streams
            .get(&id)
            .is_some_and(|s| s.outbound.ended && matches!(s.inbound, Inbound::Ended))
        {
            table.remove(id);
            self.changed.notify_waiters();
        }
    }

    fn emit(&self, kind: &Kind, stream_id: StreamId, out: Out) {
        match kind {
            Kind::Http { .. } => self.upstream.proxy(match out {
                Out::Data(data) => ProxyMessage::Body(ProxyBody {
                    stream_id,
                    data: Bytes(data),
                }),
                Out::End => ProxyMessage::End(ProxyEnd { stream_id }),
                Out::Reset(reason) => ProxyMessage::Reset(ProxyReset { stream_id, reason }),
                Out::Credit(bytes) => ProxyMessage::Credit(ProxyCredit { stream_id, bytes }),
            }),
            Kind::Tcp { .. } => self.upstream.tcp(match out {
                Out::Data(data) => TcpMessage::Data(TcpData {
                    stream_id,
                    data: Bytes(data),
                }),
                Out::End => TcpMessage::End(TcpEnd { stream_id }),
                Out::Reset(reason) => TcpMessage::Reset(TcpReset { stream_id, reason }),
                Out::Credit(bytes) => TcpMessage::Credit(TcpCredit { stream_id, bytes }),
            }),
        }
    }
}

impl Table {
    fn insert(&mut self, id: StreamId, kind: Kind, inbound: Inbound) {
        let outbound = Outbound {
            window: STREAM_WINDOW_BYTES,
            uncredited: 0,
            ended: false,
        };
        self.streams.insert(
            id,
            Stream {
                kind,
                outbound,
                inbound,
            },
        );
    }

    fn remove(&mut self, id: StreamId) -> Option<Stream> {
        let stream = self.streams.remove(&id)?;
        self.uncredited -= stream.outbound.uncredited;
        Some(stream)
    }
}

impl Kind {
    fn data_kind(&self) -> &'static str {
        match self {
            Kind::Http { .. } => "proxy.body",
            Kind::Tcp { .. } => "tcp.data",
        }
    }

    fn max_data(&self) -> usize {
        match self {
            Kind::Http { .. } => MAX_PROXY_BODY_BYTES,
            Kind::Tcp { .. } => MAX_TCP_DATA_BYTES,
        }
    }
}

impl Stream {
    fn abort(self) {
        match self.inbound {
            Inbound::AwaitingHead(head) => {
                let _ = head.send(Err(Failed));
            }
            Inbound::Open { consumer, .. } => {
                let _ = consumer.send(Piece::Abort);
            }
            Inbound::Ended => {}
        }
        if let Kind::Tcp { abort } = self.kind {
            let _ = abort.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ProxyToken, Scheme};

    const WINDOW: u64 = STREAM_WINDOW_BYTES;

    #[derive(Clone, Default)]
    struct Recorder(Arc<Mutex<Vec<Sent>>>);

    impl Upstream for Recorder {
        fn proxy(&self, message: ProxyMessage) {
            self.0.lock().unwrap().push(Sent::Proxy(message));
        }

        fn tcp(&self, message: TcpMessage) {
            self.0.lock().unwrap().push(Sent::Tcp(message));
        }
    }

    #[derive(Debug, PartialEq)]
    enum Sent {
        Proxy(ProxyMessage),
        Tcp(TcpMessage),
    }

    impl Recorder {
        fn take(&self) -> Vec<Sent> {
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
            match streams.send_data(id, &data[sent..]) {
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
            .map(|_| streams.open_http(request("upload")).unwrap().0)
            .collect();
        let sent: Vec<usize> = guards
            .iter()
            .map(|g| upload(&streams, g.id(), 2 * WINDOW as usize))
            .collect();
        assert_eq!(sent[..32], [WINDOW as usize; 32]);
        assert_eq!(sent[32], 0, "32 MiB in flight across the node");

        streams.on_proxy(ProxyMessage::Credit(ProxyCredit {
            stream_id: guards[0].id(),
            bytes: 100,
        }));
        assert_eq!(upload(&streams, guards[32].id(), WINDOW as usize), 100);
    }

    #[test]
    fn a_reset_stream_releases_its_share_of_the_node_budget() {
        let (streams, _) = streams();
        let guards: Vec<_> = (0..33)
            .map(|_| streams.open_http(request("upload")).unwrap().0)
            .collect();
        for g in &guards {
            upload(&streams, g.id(), WINDOW as usize);
        }
        streams.on_proxy(ProxyMessage::Reset(ProxyReset {
            stream_id: guards[0].id(),
            reason: "gone".into(),
        }));
        assert_eq!(
            upload(&streams, guards[32].id(), WINDOW as usize),
            WINDOW as usize
        );
    }

    #[test]
    fn tunnels_and_proxy_streams_share_the_node_limit() {
        let (streams, _) = streams();
        let _guards: Vec<_> = (0..MAX_STREAMS - 1)
            .map(|i| {
                streams
                    .open_http(request(&format!("exec-{}", i / 64)))
                    .unwrap()
                    .0
            })
            .collect();
        let last = StreamId::generate();
        let _tunnel = streams.open_tcp(last).unwrap();
        assert_eq!(streams.open_tcp(last).err(), Some(Refused::InUse));
        assert_eq!(
            streams.open_tcp(StreamId::generate()).err(),
            Some(Refused::Busy)
        );
        assert_eq!(
            streams.open_http(request("another")).err(),
            Some(Refused::Busy)
        );
        streams.discard(last);
        assert!(streams.open_tcp(StreamId::generate()).is_ok());
    }

    #[test]
    fn the_node_limit_counts_every_command() {
        let (streams, _) = streams();
        let guards: Vec<_> = (0..MAX_STREAMS)
            .map(|i| {
                streams
                    .open_http(request(&format!("exec-{}", i / 64)))
                    .unwrap()
                    .0
            })
            .collect();
        assert!(streams.open_http(request("another")).is_err());
        drop(guards);
        assert!(streams.open_http(request("another")).is_ok());
    }

    #[tokio::test]
    async fn a_body_before_the_response_head_resets_the_stream() {
        let (streams, recorder) = streams();
        let (guard, head) = streams.open_http(request("x")).unwrap();
        let id = guard.id();
        recorder.take();
        streams.on_proxy(ProxyMessage::Body(ProxyBody {
            stream_id: id,
            data: Bytes(b"early".to_vec()),
        }));
        assert!(matches!(head.await, Ok(Err(Failed))));
        assert_eq!(
            recorder.take(),
            [Sent::Proxy(ProxyMessage::Reset(ProxyReset {
                stream_id: id,
                reason: "proxy.body before proxy.response".into()
            }))]
        );
        drop(guard);
        assert_eq!(recorder.take(), [], "a reset stream is not reset twice");
    }

    #[tokio::test]
    async fn a_response_past_its_window_resets_the_stream() {
        let (streams, recorder) = streams();
        let (guard, head) = streams.open_http(request("x")).unwrap();
        let id = guard.id();
        streams.on_proxy(ProxyMessage::Response(ProxyResponse {
            stream_id: id,
            status: 200,
            headers: Vec::new(),
        }));
        let (_, mut pieces) = head.await.unwrap().unwrap();
        recorder.take();
        for _ in 0..16 {
            streams.on_proxy(ProxyMessage::Body(ProxyBody {
                stream_id: id,
                data: Bytes(vec![0; MAX_PROXY_BODY_BYTES]),
            }));
        }
        assert_eq!(recorder.take(), [], "exactly one window is fine");
        streams.on_proxy(ProxyMessage::Body(ProxyBody {
            stream_id: id,
            data: Bytes(vec![0]),
        }));
        assert_eq!(
            recorder.take(),
            [Sent::Proxy(ProxyMessage::Reset(ProxyReset {
                stream_id: id,
                reason: "proxy.body overran the window".into()
            }))]
        );
        let mut data = 0;
        while let Some(Piece::Data(d)) = pieces.recv().await {
            data += d.len();
        }
        assert_eq!(data, WINDOW as usize);
    }
}
