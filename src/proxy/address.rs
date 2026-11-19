//! Which resolved addresses an isolated command may not reach (v2 proxy.md, Resolve and
//! connect): the node itself and the networks around it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Whether `ip` is internal: loopback, private (RFC 1918, ULA), link-local, CGNAT, multicast,
/// unspecified or broadcast, an IPv6 address carrying such an IPv4 address, or one of `own`.
pub(crate) fn internal(ip: IpAddr, own: &[IpAddr]) -> bool {
    let ip = ip.to_canonical();
    if own.contains(&ip) {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => internal_v4(v4),
        IpAddr::V6(v6) => {
            internal_v6(v6)
                || embedded_v4(v6).is_some_and(|v4| internal_v4(v4) || own.contains(&v4.into()))
        }
    }
}

/// Azure's host endpoint (DHCP, DNS, the guest agent), reachable from every VM.
const AZURE_WIRESERVER: Ipv4Addr = Ipv4Addr::new(168, 63, 129, 16);

fn internal_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 0
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (a == 100 && (64..128).contains(&b))
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip == AZURE_WIRESERVER
}

fn internal_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_unspecified()
        || ip.is_loopback()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || (first & 0xffc0) == 0xfec0
        || ip.is_multicast()
}

/// The IPv4 address an IPv6 address delivers to: IPv4-compatible `::a.b.c.d`, NAT64
/// `64:ff9b::a.b.c.d` and 6to4 `2002:aabb:ccdd::`. IPv4-mapped is already canonical.
pub(crate) fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let low = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    match s {
        [0, 0, 0, 0, 0, 0, _, _] => Some(low),
        [0x64, 0xff9b, 0, 0, 0, 0, _, _] => Some(low),
        [0x2002, hi, lo, ..] => Some(Ipv4Addr::new(
            (hi >> 8) as u8,
            hi as u8,
            (lo >> 8) as u8,
            lo as u8,
        )),
        _ => None,
    }
}

/// This node's interface addresses, re-read at most once a second.
pub(crate) fn own_addresses() -> Vec<IpAddr> {
    static CACHE: Mutex<Option<(Instant, Vec<IpAddr>)>> = Mutex::new(None);
    let mut cache = CACHE.lock().unwrap();
    match &*cache {
        Some((at, addresses)) if at.elapsed() < Duration::from_secs(1) => addresses.clone(),
        _ => {
            let networks = sysinfo::Networks::new_with_refreshed_list();
            let addresses: Vec<IpAddr> = networks
                .values()
                .flat_map(|data| data.ip_networks())
                .map(|network| network.addr.to_canonical())
                .collect();
            *cache = Some((Instant::now(), addresses.clone()));
            addresses
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_addresses() {
        let own: [IpAddr; 1] = ["203.0.113.7".parse().unwrap()];
        let table = [
            ("127.0.0.1", true),
            ("127.255.0.9", true),
            ("10.1.2.3", true),
            ("172.16.0.1", true),
            ("172.32.0.1", false),
            ("192.168.1.1", true),
            ("169.254.169.254", true),
            ("168.63.129.16", true),
            ("168.63.129.17", false),
            ("100.64.0.1", true),
            ("100.127.255.255", true),
            ("100.128.0.1", false),
            ("224.0.0.251", true),
            ("255.255.255.255", true),
            ("0.0.0.0", true),
            ("0.1.2.3", true),
            ("203.0.113.7", true),
            ("8.8.8.8", false),
            ("::1", true),
            ("::", true),
            ("fd00::1", true),
            ("fc12::1", true),
            ("fe80::1", true),
            ("ff02::1", true),
            ("::ffff:127.0.0.1", true),
            ("::ffff:10.0.0.1", true),
            ("::ffff:203.0.113.7", true),
            ("::ffff:8.8.8.8", false),
            ("::7f00:1", true),
            ("64:ff9b::a00:1", true),
            ("64:ff9b::808:808", false),
            ("2002:a00:1::", true),
            ("2002:cb00:7107::1", true),
            ("2606:4700::1111", false),
        ];
        let got: Vec<(&str, bool)> = table
            .iter()
            .map(|(ip, _)| (*ip, internal(ip.parse().unwrap(), &own)))
            .collect();
        assert_eq!(got, table);
    }
}
