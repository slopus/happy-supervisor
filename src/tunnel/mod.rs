//! TCP tunnels to the node's loopback ports (docs/tunnels.md): `tcp.open`, then `tcp.*`
//! streams in the same stream table, and under the same flow control, as the credential proxy.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::sync::mpsc;

use crate::error::{Error, ErrorKind, Result};
use crate::protocol::{
    LoopbackHost, MAX_STREAMS, MAX_TCP_DATA_BYTES, StreamId, TCP_CONNECT_TIMEOUT_MS, TcpMessage,
    TcpOpenParams,
};
use crate::proxy::ProxyManager;
use crate::streams::{Piece, Refused, Streams, Tunnel};

/// Every tunnel of this node. Cheap to clone.
#[derive(Clone)]
pub struct TunnelManager {
    streams: Arc<Streams>,
}

/// Why a tunnel's socket closes before both directions ended.
enum Close {
    /// The control plane reset the stream, or the session was lost.
    Abort,
    /// The local socket failed. The control plane gets `tcp.reset` with this reason.
    Failed(String),
}

impl TunnelManager {
    /// Tunnels share `proxy`'s stream table, so the node-wide stream limit counts both.
    pub fn new(proxy: &ProxyManager) -> TunnelManager {
        TunnelManager {
            streams: proxy.streams().clone(),
        }
    }

    /// Connects to the loopback port and opens the stream. `Ok` once connected.
    pub async fn open(&self, params: TcpOpenParams) -> Result<()> {
        let id = params.stream_id;
        // Registered before the first await: `tcp.data` sent right behind `tcp.open` is
        // handled after this future first runs, and must find the stream.
        let tunnel = self.streams.open_tcp(id).map_err(|refused| match refused {
            Refused::InUse => Error::new(ErrorKind::AlreadyExists, format!("stream {id} is open")),
            Refused::Busy => Error::too_large(format!("{MAX_STREAMS} streams are open")),
        })?;
        let socket = match connect(params.host, params.port).await {
            Ok(socket) => socket,
            Err(err) => {
                self.streams.discard(id);
                return Err(err);
            }
        };
        if self.streams.room(id).is_none() {
            reset_socket(&socket);
            return Err(Error::new(
                ErrorKind::Io,
                "the stream was reset before the connection was established",
            ));
        }
        tokio::spawn(run(self.streams.clone(), id, socket, tunnel));
        Ok(())
    }

    /// A `tcp.*` message from the control plane. Never blocks.
    pub fn on_event(&self, message: TcpMessage) {
        self.streams.on_tcp(message);
    }

    /// The session was lost: every tunnel is reset and its socket closed. The table is shared
    /// with the proxy, so this ends proxy streams too.
    pub fn session_lost(&self) {
        self.streams.session_lost();
    }
}

async fn connect(host: LoopbackHost, port: u16) -> Result<TcpStream> {
    let attempts = async {
        let mut refused = false;
        let mut last = None;
        for &ip in host.addresses() {
            match TcpStream::connect(SocketAddr::new(ip, port)).await {
                Ok(socket) => return Ok(socket),
                Err(err) => {
                    refused |= err.kind() == std::io::ErrorKind::ConnectionRefused;
                    last = Some(err);
                }
            }
        }
        Err((refused, last.expect("a loopback host has an address")))
    };
    let target = format!("{}:{port}", String::from(host));
    match tokio::time::timeout(Duration::from_millis(TCP_CONNECT_TIMEOUT_MS), attempts).await {
        Ok(Ok(socket)) => {
            let _ = socket.set_nodelay(true);
            Ok(socket)
        }
        Ok(Err((true, _))) => Err(Error::new(
            ErrorKind::ConnectionRefused,
            format!("{target} refused the connection"),
        )),
        Ok(Err((false, err))) => Err(Error::new(
            ErrorKind::Io,
            format!("connecting to {target} failed: {err}"),
        )),
        Err(_) => Err(Error::new(
            ErrorKind::TimedOut,
            format!("connecting to {target} timed out after {TCP_CONNECT_TIMEOUT_MS} ms"),
        )),
    }
}

/// Carries one tunnel until both directions ended, or it is reset or lost.
async fn run(streams: Arc<Streams>, id: StreamId, mut socket: TcpStream, tunnel: Tunnel) {
    let Tunnel { pieces, abort } = tunnel;
    let close = {
        let (reader, writer) = socket.split();
        let upload = upload(&streams, id, reader);
        let download = download(&streams, id, writer, pieces);
        tokio::pin!(upload, download, abort);
        let (mut uploading, mut downloading, mut abortable) = (true, true, true);
        loop {
            if !uploading && !downloading {
                break None;
            }
            tokio::select! {
                end = &mut upload, if uploading => match end {
                    Ok(()) => uploading = false,
                    Err(close) => break Some(close),
                },
                end = &mut download, if downloading => match end {
                    Ok(()) => downloading = false,
                    Err(close) => break Some(close),
                },
                fired = &mut abort, if abortable => match fired {
                    Ok(()) => break Some(Close::Abort),
                    // The stream completed and was removed; the socket drains on its own.
                    Err(_) => abortable = false,
                },
            }
        }
    };
    match close {
        None => {}
        Some(Close::Abort) => reset_socket(&socket),
        Some(Close::Failed(reason)) => {
            streams.reset(id, &reason);
            reset_socket(&socket);
        }
    }
}

/// The local socket to the control plane, reading only as much as the window allows.
async fn upload(streams: &Streams, id: StreamId, mut reader: ReadHalf<'_>) -> Result<(), Close> {
    let mut buf = vec![0u8; MAX_TCP_DATA_BYTES];
    loop {
        let room = loop {
            let changed = streams.changed().notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match streams.room(id) {
                None => return Err(Close::Abort),
                Some(0) => changed.await,
                Some(room) => break room,
            }
        };
        let n = reader
            .read(&mut buf[..room])
            .await
            .map_err(|err| Close::Failed(format!("reading the local socket failed: {err}")))?;
        if n == 0 {
            streams.end_outbound(id);
            return Ok(());
        }
        if !streams.send_all(id, &buf[..n]).await {
            return Err(Close::Abort);
        }
    }
}

/// The control plane's bytes to the local socket, credited once written. Its `tcp.end`
/// becomes a write shutdown.
async fn download(
    streams: &Streams,
    id: StreamId,
    mut writer: WriteHalf<'_>,
    mut pieces: mpsc::UnboundedReceiver<Piece>,
) -> Result<(), Close> {
    let failed =
        |err: std::io::Error| Close::Failed(format!("writing the local socket failed: {err}"));
    while let Some(piece) = pieces.recv().await {
        match piece {
            Piece::Data(data) => {
                writer.write_all(&data).await.map_err(failed)?;
                streams.consumed(id, data.len());
            }
            Piece::Abort => return Err(Close::Abort),
        }
    }
    writer.shutdown().await.map_err(failed)
}

/// Makes the coming close an RST.
fn reset_socket(socket: &TcpStream) {
    // Deprecated because a nonzero linger blocks in close. Zero never does.
    #[allow(deprecated)]
    let _ = socket.set_linger(Some(Duration::ZERO));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ProxyMessage;
    use crate::streams::Upstream;

    struct Nowhere;

    impl Upstream for Nowhere {
        fn proxy(&self, _: ProxyMessage) {}
        fn tcp(&self, _: TcpMessage) {}
    }

    #[tokio::test]
    async fn past_the_stream_limit_tcp_open_is_too_large() {
        let tunnels = TunnelManager {
            streams: Arc::new(Streams::new(Box::new(Nowhere))),
        };
        let _open: Vec<_> = (0..MAX_STREAMS)
            .map(|_| tunnels.streams.open_tcp(StreamId::generate()).unwrap())
            .collect();
        let err = tunnels
            .open(TcpOpenParams {
                stream_id: StreamId::generate(),
                host: LoopbackHost::V4,
                port: 1,
            })
            .await
            .unwrap_err();
        assert_eq!(
            err,
            Error::new(ErrorKind::TooLarge, "1024 streams are open")
        );
    }
}
