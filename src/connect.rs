//! `happy-supervisor __connect <host> <port>`: the `ProxyCommand` of the `GIT_SSH_COMMAND` an
//! isolated command gets (proxy.md, Where it listens). It asks the SOCKS5 proxy in `ALL_PROXY`
//! for a connection to `<host>:<port>` and carries stdin and stdout over it.

use std::io::{self, Write as _};
use std::net::Shutdown;
use std::process::ExitCode;

use crate::proxy::socks5;

/// Runs `__connect` with the arguments after it.
pub fn main(args: impl IntoIterator<Item = String>) -> ExitCode {
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("happy-supervisor __connect: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: impl IntoIterator<Item = String>) -> io::Result<()> {
    let usage = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: __connect <host> <port>",
        )
    };
    let mut args = args.into_iter();
    let (Some(host), Some(port), None) = (args.next(), args.next(), args.next()) else {
        return Err(usage());
    };
    let port: u16 = port.parse().map_err(|_| usage())?;
    let proxy = socks5::proxy_from_env().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "ALL_PROXY does not name a socks5h:// proxy",
        )
    })?;
    let stream = socks5::connect(proxy, &host, port)?;
    let mut upstream = stream.try_clone()?;
    std::thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut upstream);
        let _ = upstream.shutdown(Shutdown::Write);
    });
    let mut stdout = io::stdout().lock();
    io::copy(&mut &stream, &mut stdout)?;
    stdout.flush()
}
