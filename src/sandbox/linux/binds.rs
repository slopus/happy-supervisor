//! Binds the sandbox refused, reported to the node (api.md, `net.bindDenied`).
//!
//! Where seccomp refuses `bind` (`BindDenial::Seccomp`), the filter hands the call to a seccomp
//! user notification instead of failing it. The helper installs that filter last thing before it
//! execs the command, and passes the listener to its parent half, which stays outside every
//! filter. The parent half reads the address the command asked for from its memory, sends the
//! node a TCP or UDP one over a `SOCK_SEQPACKET` pair, then refuses the call with `EPERM`, as the
//! filter would have. Nothing else answers the listener; if it closes, the kernel fails `bind`
//! with `ENOSYS`, so losing it never lets a bind through.
//!
//! Where Landlock refuses TCP `bind` instead (`unixSockets: true`), the binds the policy allows
//! would have to pass the listener too, so a lost listener would break them, and nothing is
//! reported. `listen` without `bind` is refused by the filter and not reported either.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::FileExt as _;

/// The node's end of an exec's report socket. The sandbox's copies close when it ends.
#[derive(Debug)]
pub struct BindReports {
    socket: OwnedFd,
}

impl BindReports {
    /// The next address the sandbox refused to bind. Blocks; `None` once the sandbox has
    /// closed its end.
    pub fn next(&self) -> Option<SocketAddr> {
        let mut record = [0u8; 32];
        loop {
            // SAFETY: recv writes at most `record.len()` bytes into `record`.
            let len = unsafe {
                libc::recv(
                    self.socket.as_raw_fd(),
                    record.as_mut_ptr().cast(),
                    record.len(),
                    0,
                )
            };
            match len {
                0 => return None,
                len if len < 0 => {
                    if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                        return None;
                    }
                }
                len => {
                    if let Some(addr) = decode(&record[..len as usize]) {
                        return Some(addr);
                    }
                }
            }
        }
    }
}

/// A new report socket pair: the node's end, and the end the helper inherits (close-on-exec,
/// so only the command that clears the flag passes it on).
pub fn pair() -> io::Result<(BindReports, OwnedFd)> {
    let (node, helper) = seqpacket_pair()?;
    Ok((BindReports { socket: node }, helper))
}

/// The pair the helper hands the listener over, from the half that installs the filter to the
/// half that answers it: (the parent's end, the child's end).
pub fn handoff() -> io::Result<(OwnedFd, OwnedFd)> {
    seqpacket_pair()
}

fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
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
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// The helper's child half, just before its other filters: installs the notifying filter and
/// sends its listener to the parent half on `handoff`. Whether `bind` now goes to the listener;
/// when it does not, the errno filter must refuse it.
pub fn hand_over(handoff: OwnedFd) -> bool {
    let Ok(listener) = super::seccomp::notify_bind() else {
        return false;
    };
    // Should the parent half not get it, closing it here leaves bind failing with ENOSYS.
    super::netns::send(handoff.as_raw_fd(), &[1], Some(listener.as_raw_fd())).is_ok()
}

/// The helper's parent half: takes the listener from `handoff`, then answers every `bind` it
/// reports until the command's sandbox ends, sending each TCP or UDP address on `node`.
pub fn serve(handoff: OwnedFd, node: OwnedFd) {
    let mut byte = [0u8; 1];
    let listener = match super::netns::recv(handoff.as_raw_fd(), &mut byte) {
        Ok((_, Some(listener))) => listener,
        // The child execs or fails without one: the errno filter refuses bind.
        _ => return,
    };
    drop(handoff);
    let mut reporting = true;
    loop {
        // SAFETY: an all-zero seccomp_notif is valid, and RECV requires it zeroed.
        let mut request: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: RECV writes one seccomp_notif into `request`.
        let rc = unsafe {
            libc::ioctl(
                listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_RECV,
                &raw mut request,
            )
        };
        if rc < 0 {
            match io::Error::last_os_error().raw_os_error() {
                // A signal, or a caller that died before its call was read.
                Some(libc::EINTR | libc::ENOENT) => continue,
                // Dropping the listener makes every later bind fail with ENOSYS.
                _ => return,
            }
        }
        let args = request.data.args;
        let addr = read_addr(request.pid, args[1], args[2])
            .filter(|_| still_waiting(listener.as_raw_fd(), request.id));
        if let (Some(addr), true) = (addr, reporting) {
            // Before the answer, so the node has it before the command can exit.
            reporting = super::netns::send(node.as_raw_fd(), &encode(addr), None).is_ok();
        }
        let response = libc::seccomp_notif_resp {
            id: request.id,
            val: 0,
            error: -libc::EPERM,
            flags: 0,
        };
        // SAFETY: SEND reads one seccomp_notif_resp. ENOENT means the caller is gone.
        unsafe {
            libc::ioctl(
                listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_SEND,
                &raw const response,
            )
        };
    }
}

/// Whether the call `id` still waits for its answer, so the memory just read was its caller's.
fn still_waiting(listener: RawFd, id: u64) -> bool {
    // SAFETY: ID_VALID reads one u64.
    unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_ID_VALID, &raw const id) == 0 }
}

/// The IPv4 or IPv6 address and port in the `sockaddr` of `len` bytes at `addr` in process
/// `pid`'s memory. `None` for another family, or when the memory cannot be read: Yama's
/// `ptrace_scope` 2 or 3, or a command that is not dumpable.
fn read_addr(pid: u32, addr: u64, len: u64) -> Option<SocketAddr> {
    let mut sockaddr = [0u8; size_of::<libc::sockaddr_in6>()];
    let len = usize::try_from(len).ok()?.min(sockaddr.len());
    let mem = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    mem.read_exact_at(&mut sockaddr[..len], addr).ok()?;
    parse_sockaddr(&sockaddr[..len])
}

fn parse_sockaddr(bytes: &[u8]) -> Option<SocketAddr> {
    let family = i32::from(u16::from_ne_bytes(bytes.get(..2)?.try_into().ok()?));
    let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
    let ip = match family {
        libc::AF_INET if bytes.len() >= size_of::<libc::sockaddr_in>() => {
            let octets: [u8; 4] = bytes[4..8].try_into().ok()?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        // The kernel takes the 24 bytes before sin6_scope_id as an IPv6 sockaddr.
        libc::AF_INET6 if bytes.len() >= 24 => {
            let octets: [u8; 16] = bytes[8..24].try_into().ok()?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// One report: the port, big-endian, then the 4 or 16 bytes of the address.
fn encode(addr: SocketAddr) -> Vec<u8> {
    let mut record = addr.port().to_be_bytes().to_vec();
    match addr.ip() {
        IpAddr::V4(ip) => record.extend(ip.octets()),
        IpAddr::V6(ip) => record.extend(ip.octets()),
    }
    record
}

fn decode(record: &[u8]) -> Option<SocketAddr> {
    let port = u16::from_be_bytes(record.get(..2)?.try_into().ok()?);
    let ip = match record.len() {
        6 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&record[2..]).ok()?)),
        18 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&record[2..]).ok()?)),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sockaddr_bytes<T>(sockaddr: &T) -> Vec<u8> {
        // SAFETY: reads the plain-data struct's own bytes.
        unsafe {
            std::slice::from_raw_parts((sockaddr as *const T).cast::<u8>(), size_of::<T>()).to_vec()
        }
    }

    #[test]
    fn sockaddrs_parse_as_the_kernel_reads_them() {
        // SAFETY: all-zero sockaddrs are valid.
        let mut v4: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        v4.sin_family = libc::AF_INET as libc::sa_family_t;
        v4.sin_port = 8765u16.to_be();
        v4.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        let v4 = sockaddr_bytes(&v4);
        assert_eq!(parse_sockaddr(&v4), Some("127.0.0.1:8765".parse().unwrap()));
        assert_eq!(parse_sockaddr(&v4[..15]), None);

        // SAFETY: as above.
        let mut v6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        v6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        v6.sin6_port = 3000u16.to_be();
        v6.sin6_addr.s6_addr = Ipv6Addr::LOCALHOST.octets();
        let v6 = sockaddr_bytes(&v6);
        assert_eq!(parse_sockaddr(&v6), Some("[::1]:3000".parse().unwrap()));
        assert_eq!(
            parse_sockaddr(&v6[..24]),
            Some("[::1]:3000".parse().unwrap())
        );
        assert_eq!(parse_sockaddr(&v6[..23]), None);

        let unix = (libc::AF_UNIX as u16).to_ne_bytes();
        assert_eq!(parse_sockaddr(&[unix[0], unix[1], 0, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn reports_cross_the_socket_until_it_closes() {
        let (reports, helper) = pair().unwrap();
        for addr in ["0.0.0.0:8765", "[::]:0"] {
            let addr: SocketAddr = addr.parse().unwrap();
            super::super::netns::send(helper.as_raw_fd(), &encode(addr), None).unwrap();
        }
        super::super::netns::send(helper.as_raw_fd(), &[1, 2, 3], None).unwrap();
        drop(helper);
        assert_eq!(reports.next(), Some("0.0.0.0:8765".parse().unwrap()));
        assert_eq!(reports.next(), Some("[::]:0".parse().unwrap()));
        assert_eq!(reports.next(), None);
    }
}
