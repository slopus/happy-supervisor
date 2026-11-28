//! `AF_VSOCK` for the guest's agent (`serve --listen vsock:PORT`, serve.md): a listener and
//! the streams it accepts, on tokio's reactor. tokio has no vsock type, so [`Stream`] is any
//! connected stream socket read and written with `read(2)` and `write(2)`.

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Listens on `port` of every CID this machine has, which in a guest is its own.
pub struct Listener {
    fd: AsyncFd<OwnedFd>,
}

impl Listener {
    pub fn bind(port: u32) -> io::Result<Listener> {
        // SAFETY: socket takes no pointers. The descriptor it returns is owned by nothing else.
        let fd = unsafe {
            let fd = libc::socket(
                libc::AF_VSOCK,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            OwnedFd::from_raw_fd(fd)
        };
        // SAFETY: sockaddr_vm is plain data, so zeroed is a valid value before it is filled.
        let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        address.svm_cid = libc::VMADDR_CID_ANY;
        address.svm_port = port;
        // SAFETY: `address` is a sockaddr_vm that lives across the call, and its size is passed.
        let bound = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const address).cast(),
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if bound != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: listen takes no pointers.
        if unsafe { libc::listen(fd.as_raw_fd(), 64) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Listener { fd: register(fd)? })
    }

    pub async fn accept(&self) -> io::Result<Stream> {
        loop {
            let mut ready = self.fd.readable().await?;
            let accepted = ready.try_io(|fd| {
                // SAFETY: a null address and length make accept4 write no address.
                let stream = unsafe {
                    libc::accept4(
                        fd.as_raw_fd(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    )
                };
                if stream < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: accept4 returned a new descriptor that nothing else owns.
                Ok(unsafe { OwnedFd::from_raw_fd(stream) })
            });
            match accepted {
                Ok(stream) => return Stream::new(stream?),
                Err(_would_block) => continue,
            }
        }
    }
}

/// A connected, non-blocking stream socket.
pub struct Stream {
    fd: AsyncFd<OwnedFd>,
}

impl Stream {
    /// `fd` must be a connected stream socket in non-blocking mode.
    pub fn new(fd: OwnedFd) -> io::Result<Stream> {
        Ok(Stream { fd: register(fd)? })
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut ready = ready!(self.fd.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            let read = ready.try_io(|fd| {
                // SAFETY: `unfilled` is initialized memory of that length, borrowed for the call.
                let n = unsafe {
                    libc::read(fd.as_raw_fd(), unfilled.as_mut_ptr().cast(), unfilled.len())
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(n as usize)
            });
            match read {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut ready = ready!(self.fd.poll_write_ready(cx))?;
            let written = ready.try_io(|fd| {
                // SAFETY: `data` is valid for reads of its length for the call. MSG_NOSIGNAL
                // turns a closed peer into EPIPE rather than SIGPIPE.
                let n = unsafe {
                    libc::send(
                        fd.as_raw_fd(),
                        data.as_ptr().cast(),
                        data.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(n as usize)
            });
            match written {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        // SAFETY: shutdown takes no pointers.
        if unsafe { libc::shutdown(self.fd.get_ref().as_raw_fd(), libc::SHUT_WR) } != 0 {
            return Poll::Ready(Err(io::Error::last_os_error()));
        }
        Poll::Ready(Ok(()))
    }
}

fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: an OwnedFd stays open, as the same descriptor, until the AsyncFd drops it.
    Ok(unsafe { AsyncFd::register(fd) }?)
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    /// The read and write paths, over a Unix socket pair: vsock needs a VM, or a host with
    /// `vsock_loopback` (tests/vm.rs runs them over real vsock).
    #[tokio::test]
    async fn a_stream_carries_bytes_both_ways_and_half_closes() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let mut a = Stream::new(OwnedFd::from(a)).unwrap();
        let mut b = tokio::net::UnixStream::from_std({
            b.set_nonblocking(true).unwrap();
            b
        })
        .unwrap();
        let big = vec![0x5a; 1 << 20];
        let writer = {
            let big = big.clone();
            tokio::spawn(async move {
                a.write_all(&big).await.unwrap();
                a.shutdown().await.unwrap();
                let mut reply = String::new();
                a.read_to_string(&mut reply).await.unwrap();
                reply
            })
        };
        let mut got = Vec::new();
        b.read_to_end(&mut got).await.unwrap();
        assert_eq!(got.len(), big.len());
        assert!(got == big);
        b.write_all(b"done").await.unwrap();
        drop(b);
        assert_eq!(writer.await.unwrap(), "done");
    }
}
