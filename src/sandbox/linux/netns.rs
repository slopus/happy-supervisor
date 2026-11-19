//! `tcp.open` with an `execId` into an isolated exec's network namespace (tunnels.md).
//!
//! The node and the helper share a `SOCK_SEQPACKET` socket pair. The node sends a port as two
//! big-endian bytes; the helper connects to `127.0.0.1:<port>` inside the namespace and replies
//! with a 4-byte errno, 0 carrying the connected socket as `SCM_RIGHTS`. The node never enters
//! the namespace.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

/// How long the node waits for the helper to answer one request.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the helper tries to connect inside the namespace.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The node's end of an isolated exec's control socket. Dropping it makes the helper stop
/// serving.
#[derive(Debug)]
pub struct NetnsControl {
    socket: Mutex<OwnedFd>,
}

impl NetnsControl {
    /// Connects to `127.0.0.1:port` inside the exec's network namespace. Blocks for up to about
    /// 10 seconds; a refused connection is an error with `ECONNREFUSED`.
    pub fn connect(&self, port: u16) -> io::Result<TcpStream> {
        let socket = self.socket.lock().unwrap_or_else(PoisonError::into_inner);
        send(socket.as_raw_fd(), &port.to_be_bytes(), None)?;
        let mut reply = [0u8; 4];
        let (len, fd) = recv(socket.as_raw_fd(), &mut reply)?;
        if len != reply.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the sandbox helper closed its control socket",
            ));
        }
        match (i32::from_be_bytes(reply), fd) {
            (0, Some(fd)) => Ok(TcpStream::from(fd)),
            (0, None) => Err(io::Error::other("the sandbox helper sent no socket")),
            (errno, _) => Err(io::Error::from_raw_os_error(errno)),
        }
    }
}

/// A new control socket pair: the node's end, and the end the helper inherits (close-on-exec,
/// so only the command that clears the flag passes it on).
pub fn pair() -> io::Result<(NetnsControl, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: socketpair writes two descriptors into `fds`, which this function then owns.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created and are owned by nothing else.
    let (node, helper) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    set_receive_timeout(node.as_raw_fd(), REPLY_TIMEOUT)?;
    Ok((
        NetnsControl {
            socket: Mutex::new(node),
        },
        helper,
    ))
}

/// Held by [`serve`] from a request to its reply, so the helper does not exit between them.
static IN_FLIGHT: Mutex<()> = Mutex::new(());

/// Waits for the request being answered, if any, and keeps the next one from starting. The
/// helper calls it before it exits: a command that accepts a connection and exits at once would
/// otherwise take the helper down before the connected socket reaches the node.
pub fn finish_serving() {
    std::mem::forget(IN_FLIGHT.lock().unwrap_or_else(PoisonError::into_inner));
}

/// The helper's side: answers requests until the node closes its end.
pub fn serve(socket: OwnedFd) {
    let mut request = [0u8; 2];
    loop {
        let len = match recv(socket.as_raw_fd(), &mut request) {
            Ok((len, _)) => len,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        if len == 0 {
            return;
        }
        let _answering = IN_FLIGHT.lock().unwrap_or_else(PoisonError::into_inner);
        let port = u16::from_be_bytes(request);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let sent = match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(stream) => send(
                socket.as_raw_fd(),
                &0i32.to_be_bytes(),
                Some(stream.as_raw_fd()),
            ),
            Err(err) => {
                let errno = err.raw_os_error().unwrap_or(libc::EIO);
                send(socket.as_raw_fd(), &errno.to_be_bytes(), None)
            }
        };
        if sent.is_err() {
            return;
        }
    }
}

fn set_receive_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as _,
        tv_usec: 0,
    };
    // SAFETY: `tv` is a valid timeval for the duration of the call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Space for one control message carrying one descriptor, aligned for `cmsghdr`.
#[repr(C)]
union ControlBuffer {
    _align: libc::cmsghdr,
    bytes: [u8; 64],
}

fn send(fd: RawFd, data: &[u8], pass: Option<RawFd>) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let mut control = ControlBuffer { bytes: [0; 64] };
    // SAFETY: an all-zero msghdr is valid.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(pass) = pass {
        // SAFETY: CMSG_SPACE only computes a size.
        let space = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) };
        // SAFETY: the buffer is 64 bytes and aligned for cmsghdr, more than one descriptor
        // needs, so CMSG_FIRSTHDR is non-null and the header and data fit inside it.
        unsafe {
            msg.msg_control = (&raw mut control.bytes).cast();
            msg.msg_controllen = space as _;
            let header = libc::CMSG_FIRSTHDR(&msg);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
            libc::CMSG_DATA(header)
                .cast::<RawFd>()
                .write_unaligned(pass);
        }
    }
    loop {
        // SAFETY: `msg` points at `iov`, `data` and `control`, all alive for the call.
        let rc = unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) };
        if rc >= 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Receives one message into `data`, and the descriptor it carried, if any.
fn recv(fd: RawFd, data: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut control = ControlBuffer { bytes: [0; 64] };
    // SAFETY: an all-zero msghdr is valid.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (&raw mut control).cast();
    msg.msg_controllen = size_of::<ControlBuffer>() as _;
    // SAFETY: `msg` points at buffers alive for the call; MSG_CMSG_CLOEXEC marks any received
    // descriptor close-on-exec.
    let len = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut received = None;
    // SAFETY: the kernel filled `control` and set msg_controllen; the CMSG macros walk only
    // inside it, and an SCM_RIGHTS message's data is a descriptor this process now owns.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let fd = libc::CMSG_DATA(header).cast::<RawFd>().read_unaligned();
                received = Some(OwnedFd::from_raw_fd(fd));
            }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
    }
    Ok((len as usize, received))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn connects_through_the_helper_and_reports_refusals() {
        let (control, helper) = pair().unwrap();
        let server = std::thread::spawn(move || serve(helper));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut stream = control.connect(port).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        stream.write_all(b"ping").unwrap();
        let mut got = [0u8; 4];
        accepted.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");

        let (_bound, closed) = bound_not_listening();
        let refused = control.connect(closed).unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(libc::ECONNREFUSED));

        drop(control);
        server.join().unwrap();
    }

    /// A TCP socket bound to a loopback port without listening: connections to the port are
    /// refused, and no other test can take it meanwhile.
    fn bound_not_listening() -> (OwnedFd, u16) {
        // SAFETY: plain socket calls on a descriptor this function owns, with a valid sockaddr.
        unsafe {
            let fd = OwnedFd::from_raw_fd(libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0));
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_addr.s_addr = u32::from(Ipv4Addr::LOCALHOST).to_be();
            let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            assert_eq!(libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len), 0);
            assert_eq!(
                libc::getsockname(fd.as_raw_fd(), (&raw mut addr).cast(), &mut len),
                0
            );
            (fd, u16::from_be(addr.sin_port))
        }
    }
}
