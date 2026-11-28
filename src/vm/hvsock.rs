//! The host's side of Cloud Hypervisor's hybrid vsock (docs/vm-mode.md, Decision): the VMM
//! exposes the guest's vsock as a Unix socket. A host connection names the guest port with
//! `CONNECT <port>\n`, the VMM answers `OK <host port>\n` once the guest accepted, and the rest
//! of the stream is the guest's connection.

use std::io;
use std::path::Path;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

/// The longest answer the VMM sends: `OK ` and a 32-bit port.
const MAX_ANSWER: usize = 16;

/// Connects to guest `port` through the VMM's vsock socket at `socket`. Fails when nothing
/// listens there yet, which the VMM says by closing the connection.
pub async fn connect(socket: &Path, port: u32) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(socket).await?;
    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .await?;
    // One byte at a time, so nothing of the guest's stream after the answer is consumed.
    let mut answer = Vec::new();
    loop {
        let byte = match stream.read_u8().await {
            Ok(byte) => byte,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("nothing listens on vsock port {port} in the guest"),
                ));
            }
            Err(err) => return Err(err),
        };
        if byte == b'\n' {
            break;
        }
        answer.push(byte);
        if answer.len() > MAX_ANSWER {
            return Err(bad_answer(&answer));
        }
    }
    match answer
        .strip_prefix(b"OK ")
        .and_then(|port| std::str::from_utf8(port).ok())
        .map(str::parse::<u32>)
    {
        Some(Ok(_)) => Ok(stream),
        _ => Err(bad_answer(&answer)),
    }
}

fn bad_answer(answer: &[u8]) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "the VMM answered {:?} to CONNECT",
            String::from_utf8_lossy(answer)
        ),
    )
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncBufReadExt as _, BufReader};
    use tokio::net::UnixListener;

    use super::*;

    /// A stand-in for the VMM: reads the request line, sends `answer`, then `after`.
    async fn vmm(answer: &'static [u8], after: &'static [u8]) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (requests_tx, requests_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut request = String::new();
            stream.read_line(&mut request).await.unwrap();
            requests_tx.send(request).unwrap();
            stream.get_mut().write_all(answer).await.unwrap();
            stream.get_mut().write_all(after).await.unwrap();
        });
        let connected = connect(&path, 1024).await;
        let request = requests_rx.await.unwrap();
        match connected {
            Ok(mut stream) => {
                let mut rest = Vec::new();
                stream.read_to_end(&mut rest).await.unwrap();
                (
                    dir,
                    format!("{request}|{}", String::from_utf8(rest).unwrap()),
                )
            }
            Err(err) => (dir, format!("{request}|{err}")),
        }
    }

    #[tokio::test]
    async fn the_stream_after_ok_is_the_guests() {
        let (_dir, seen) = vmm(b"OK 1073741824\n", b"HTTP/1.1 101").await;
        assert_eq!(seen, "CONNECT 1024\n|HTTP/1.1 101");
    }

    #[tokio::test]
    async fn a_closed_connection_means_nothing_listens() {
        let (_dir, seen) = vmm(b"", b"").await;
        assert_eq!(
            seen,
            "CONNECT 1024\n|nothing listens on vsock port 1024 in the guest"
        );
    }

    #[tokio::test]
    async fn any_other_answer_is_refused() {
        let (_dir, seen) = vmm(b"NO\n", b"").await;
        assert_eq!(seen, "CONNECT 1024\n|the VMM answered \"NO\" to CONNECT");
    }
}
