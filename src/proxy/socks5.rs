//! SOCKS5 (RFC 1928) without authentication, `CONNECT` only: the command's SOCKS5 proxy, and
//! the blocking client `__connect` uses to reach it.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::egress::{Command, Io, Route, Via, connect as connect_upstream};

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0x00;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// The reply codes the proxy sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    NotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

/// A client that sends nothing for this long during the handshake is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Serves one client connection of the command's SOCKS5 proxy.
pub(crate) async fn serve(command: Arc<Command>, mut client: Box<dyn Io>) {
    let Ok(Ok(Some((host, port)))) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut client)).await
    else {
        return;
    };
    let reply = match command.route(&host, port, Via::Socks5).await {
        Route::Direct(addresses) => match connect_upstream(&addresses).await {
            Ok(mut upstream) => {
                let bound = upstream
                    .local_addr()
                    .unwrap_or((Ipv4Addr::UNSPECIFIED, 0).into());
                if send_reply(&mut client, Reply::Succeeded, bound)
                    .await
                    .is_ok()
                {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
                return;
            }
            Err(err) => match err.kind() {
                io::ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                io::ErrorKind::NetworkUnreachable => Reply::NetworkUnreachable,
                io::ErrorKind::HostUnreachable | io::ErrorKind::TimedOut => Reply::HostUnreachable,
                _ => Reply::GeneralFailure,
            },
        },
        Route::Credential | Route::Refused(_) => Reply::NotAllowed,
        Route::Unresolved => Reply::HostUnreachable,
    };
    let _ = send_reply(&mut client, reply, (Ipv4Addr::UNSPECIFIED, 0).into()).await;
}

/// Negotiates no authentication and reads a `CONNECT` request. `Ok(None)` when the client asked
/// for something else and has already been answered.
async fn handshake(client: &mut Box<dyn Io>) -> io::Result<Option<(String, u16)>> {
    let [version, count] = read_array(client).await?;
    if version != VERSION {
        return Ok(None);
    }
    let mut methods = vec![0u8; count as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&NO_AUTH) {
        client.write_all(&[VERSION, NO_ACCEPTABLE_METHOD]).await?;
        return Ok(None);
    }
    client.write_all(&[VERSION, NO_AUTH]).await?;
    let [version, cmd, _reserved, atyp] = read_array(client).await?;
    if version != VERSION {
        return Ok(None);
    }
    let host = match atyp {
        ATYP_IPV4 => Ipv4Addr::from(read_array::<4>(client).await?).to_string(),
        ATYP_IPV6 => Ipv6Addr::from(read_array::<16>(client).await?).to_string(),
        ATYP_DOMAIN => {
            let [len] = read_array(client).await?;
            let mut name = vec![0u8; len as usize];
            client.read_exact(&mut name).await?;
            match String::from_utf8(name) {
                Ok(name) if !name.is_empty() => name,
                _ => {
                    send_reply(client, Reply::GeneralFailure, unspecified()).await?;
                    return Ok(None);
                }
            }
        }
        _ => {
            send_reply(client, Reply::AddressTypeNotSupported, unspecified()).await?;
            return Ok(None);
        }
    };
    let port = u16::from_be_bytes(read_array(client).await?);
    if cmd != CMD_CONNECT {
        send_reply(client, Reply::CommandNotSupported, unspecified()).await?;
        return Ok(None);
    }
    Ok(Some((host, port)))
}

async fn read_array<const N: usize>(client: &mut Box<dyn Io>) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    client.read_exact(&mut buf).await?;
    Ok(buf)
}

fn unspecified() -> SocketAddr {
    (Ipv4Addr::UNSPECIFIED, 0).into()
}

async fn send_reply(client: &mut Box<dyn Io>, reply: Reply, bound: SocketAddr) -> io::Result<()> {
    let mut message = vec![VERSION, reply as u8, 0];
    encode_address(&mut message, bound);
    client.write_all(&message).await?;
    client.flush().await
}

fn encode_address(out: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&address.port().to_be_bytes());
}

/// Connects to `host:port` through the SOCKS5 proxy at `proxy`. The proxy resolves `host`
/// unless it is an IP literal. A refusal is an error naming the reply code, as in
/// `socks5 reply 0x02`.
pub fn connect(proxy: SocketAddr, host: &str, port: u16) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy)?;
    stream.set_nodelay(true)?;
    stream.write_all(&[VERSION, 1, NO_AUTH])?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice)?;
    if choice != [VERSION, NO_AUTH] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the socks5 proxy requires authentication",
        ));
    }
    let mut request = vec![VERSION, CMD_CONNECT, 0];
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match bare.parse::<IpAddr>() {
        Ok(ip) => encode_address(&mut request, (ip, port).into()),
        Err(_) => {
            let name = u8::try_from(host.len())
                .ok()
                .filter(|&len| len > 0)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "a host name is 1 to 255 bytes")
                })?;
            request.extend_from_slice(&[ATYP_DOMAIN, name]);
            request.extend_from_slice(host.as_bytes());
            request.extend_from_slice(&port.to_be_bytes());
        }
    }
    stream.write_all(&request)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    let rest = match head[3] {
        ATYP_IPV4 => 4 + 2,
        ATYP_IPV6 => 16 + 2,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            len[0] as usize + 2
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("socks5 reply with address type {other:#04x}"),
            ));
        }
    };
    stream.read_exact(&mut vec![0u8; rest])?;
    match head[1] {
        0 => Ok(stream),
        code => Err(io::Error::new(
            if code == Reply::NotAllowed as u8 {
                io::ErrorKind::PermissionDenied
            } else {
                io::ErrorKind::ConnectionRefused
            },
            format!("socks5 reply {code:#04x}"),
        )),
    }
}

/// The SOCKS5 proxy `ALL_PROXY` (or `all_proxy`) names as `socks5h://<ip>:<port>` or
/// `socks5://<ip>:<port>`.
pub fn proxy_from_env() -> Option<SocketAddr> {
    ["ALL_PROXY", "all_proxy"].into_iter().find_map(|name| {
        let value = std::env::var(name).ok()?;
        let rest = value
            .strip_prefix("socks5h://")
            .or_else(|| value.strip_prefix("socks5://"))?;
        rest.trim_end_matches('/').parse().ok()
    })
}
