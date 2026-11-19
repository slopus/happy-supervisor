//! The isolated sandbox's way out (proxy.md, Where it listens): inside the network namespace the
//! helper listens on `127.0.0.1:3128` and `127.0.0.1:1080` and splices each connection to the
//! node's HTTP and SOCKS5 proxy sockets, which are bind-mounted into the sandbox.

use std::io;
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

pub const HTTP_PORT: u16 = 3128;
pub const SOCKS_PORT: u16 = 1080;

/// The listeners, bound before the command starts so it never sees a refused proxy port.
pub struct Bridge {
    routes: Vec<(TcpListener, PathBuf)>,
}

impl Bridge {
    pub fn bind(http: PathBuf, socks: PathBuf) -> io::Result<Bridge> {
        let listen = |port| TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        Ok(Bridge {
            routes: vec![(listen(HTTP_PORT)?, http), (listen(SOCKS_PORT)?, socks)],
        })
    }

    /// Serves every route on its own threads, until the process exits.
    pub fn spawn(self) {
        for (listener, socket) in self.routes {
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let socket = socket.clone();
                    std::thread::spawn(move || {
                        if let Ok(upstream) = UnixStream::connect(&socket) {
                            splice(stream, upstream);
                        }
                    });
                }
            });
        }
    }
}

/// Copies both ways until each side has ended, passing each end of stream on as a shutdown.
fn splice(tcp: TcpStream, unix: UnixStream) {
    let (Ok(tcp_in), Ok(unix_out)) = (tcp.try_clone(), unix.try_clone()) else {
        return;
    };
    let upstream = std::thread::spawn(move || {
        let mut tcp_in = tcp_in;
        let mut unix_out = unix_out;
        let _ = io::copy(&mut tcp_in, &mut unix_out);
        let _ = unix_out.shutdown(Shutdown::Write);
    });
    let (mut unix_in, mut tcp_out) = (unix, tcp);
    let _ = io::copy(&mut unix_in, &mut tcp_out);
    let _ = tcp_out.shutdown(Shutdown::Write);
    let _ = upstream.join();
}
