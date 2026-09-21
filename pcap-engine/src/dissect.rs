//! Per-packet summary for the packet list: protocol, addresses, ports, and a
//! small protocol-specific detail value. Pure Rust, bounds-checked everywhere,
//! never panics on short or malformed packets.

use crate::link::{
    LINKTYPE_ETHERNET, LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_LINUX_SLL, LINKTYPE_NULL,
    LINKTYPE_RAW,
};

pub const PROTO_OTHER: u8 = 0;
pub const PROTO_TCP: u8 = 1;
pub const PROTO_UDP: u8 = 2;
pub const PROTO_ICMP: u8 = 3;
pub const PROTO_ICMPV6: u8 = 4;
pub const PROTO_ARP: u8 = 5;
/// IPv4 carrying a protocol we do not decode further.
pub const PROTO_IPV4: u8 = 6;
/// IPv6 carrying a protocol we do not decode further.
pub const PROTO_IPV6: u8 = 7;
pub const PROTO_DNS: u8 = 8;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

const DNS_PORT: u16 = 53;

/// Fixed-size summary of one packet, stored column-wise in the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    /// One of the `PROTO_*` constants.
    pub proto: u8,
    /// 4, 6, or 0 when the packet has no IP (or ARP-over-IPv4) addresses.
    pub ip_version: u8,
    pub src_port: u16,
    pub dst_port: u16,
    /// Depends on `proto`:
    /// TCP: flag bits (FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32 ECE=64 CWR=128).
    /// ICMP / ICMPv6: `type << 8 | code`.
    /// ARP: operation (1 request, 2 reply).
    /// `PROTO_IPV4` / `PROTO_IPV6`: the IP protocol number.
    /// `PROTO_OTHER`: the EtherType, or 0 if unknown.
    pub detail: u16,
    /// IPv4 addresses use the first 4 bytes.
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

impl Default for Meta {
    fn default() -> Self {
        Meta {
            proto: PROTO_OTHER,
            ip_version: 0,
            src_port: 0,
            dst_port: 0,
            detail: 0,
            src: [0; 16],
            dst: [0; 16],
        }
    }
}

fn be16(data: &[u8], at: usize) -> Option<u16> {
    let b = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

/// Summarise one packet. `linktype` is the pcap LINKTYPE_* value.
pub fn dissect(data: &[u8], linktype: u16) -> Meta {
    match linktype {
        LINKTYPE_ETHERNET => ethernet(data),
        LINKTYPE_LINUX_SLL => linux_sll(data),
        LINKTYPE_RAW | LINKTYPE_IPV4 | LINKTYPE_IPV6 => ip_by_version(data),
        // 4-byte address-family header, then an IP packet.
        LINKTYPE_NULL => ip_by_version(data.get(4..).unwrap_or(&[])),
        _ => Meta::default(),
    }
}

fn ethernet(data: &[u8]) -> Meta {
    let Some(mut ethertype) = be16(data, 12) else {
        return Meta::default();
    };
    let mut at = 14;
    // Up to two stacked VLAN tags.
    for _ in 0..2 {
        if ethertype != ETHERTYPE_VLAN && ethertype != ETHERTYPE_QINQ {
            break;
        }
        let Some(inner) = be16(data, at + 2) else {
            return other(ethertype);
        };
        ethertype = inner;
        at += 4;
    }
    network(ethertype, data.get(at..).unwrap_or(&[]))
}

fn linux_sll(data: &[u8]) -> Meta {
    match be16(data, 14) {
        Some(proto) => network(proto, data.get(16..).unwrap_or(&[])),
        None => Meta::default(),
    }
}

fn other(ethertype: u16) -> Meta {
    Meta {
        detail: ethertype,
        ..Meta::default()
    }
}

fn network(ethertype: u16, payload: &[u8]) -> Meta {
    match ethertype {
        ETHERTYPE_IPV4 => ipv4(payload),
        ETHERTYPE_IPV6 => ipv6(payload),
        ETHERTYPE_ARP => arp(payload),
        t => other(t),
    }
}

fn ip_by_version(data: &[u8]) -> Meta {
    match data.first().map(|b| b >> 4) {
        Some(4) => ipv4(data),
        Some(6) => ipv6(data),
        _ => Meta::default(),
    }
}

fn arp(p: &[u8]) -> Meta {
    let mut m = Meta {
        proto: PROTO_ARP,
        ..Meta::default()
    };
    // Only the common IPv4-over-Ethernet form carries addresses we can show.
    let is_ipv4_eth = be16(p, 2) == Some(ETHERTYPE_IPV4) && p.get(4) == Some(&6) && p.get(5) == Some(&4);
    if let (true, Some(op), Some(spa), Some(tpa)) = (is_ipv4_eth, be16(p, 6), p.get(14..18), p.get(24..28)) {
        m.ip_version = 4;
        m.detail = op;
        m.src[..4].copy_from_slice(spa);
        m.dst[..4].copy_from_slice(tpa);
    }
    m
}

fn ipv4(p: &[u8]) -> Meta {
    let Some(h) = p.get(..20) else {
        return Meta {
            proto: PROTO_IPV4,
            ..Meta::default()
        };
    };
    let protocol = h[9];
    let mut m = Meta {
        proto: PROTO_IPV4,
        ip_version: 4,
        detail: u16::from(protocol),
        ..Meta::default()
    };
    m.src[..4].copy_from_slice(&h[12..16]);
    m.dst[..4].copy_from_slice(&h[16..20]);

    let header_len = usize::from(h[0] & 0x0f) * 4;
    let fragment_offset = (u16::from(h[6] & 0x1f) << 8) | u16::from(h[7]);
    // Later fragments have no transport header.
    if header_len >= 20 && fragment_offset == 0 {
        transport(&mut m, protocol, p.get(header_len..).unwrap_or(&[]));
    }
    m
}

fn ipv6(p: &[u8]) -> Meta {
    let Some(h) = p.get(..40) else {
        return Meta {
            proto: PROTO_IPV6,
            ..Meta::default()
        };
    };
    let mut m = Meta {
        proto: PROTO_IPV6,
        ip_version: 6,
        ..Meta::default()
    };
    m.src.copy_from_slice(&h[8..24]);
    m.dst.copy_from_slice(&h[24..40]);

    // Walk past extension headers to the real next protocol.
    let mut next = h[6];
    let mut at = 40usize;
    for _ in 0..8 {
        let step = match next {
            0 | 43 | 60 => p.get(at + 1).map(|len| (usize::from(*len) + 1) * 8), // hop-by-hop, routing, destination options
            51 => p.get(at + 1).map(|len| (usize::from(*len) + 2) * 4),           // authentication header
            44 => {
                // Fragment header: a non-zero offset means no transport header follows.
                match be16(p, at + 2) {
                    Some(f) if f >> 3 != 0 => break,
                    Some(_) => Some(8),
                    None => None,
                }
            }
            _ => break,
        };
        match (step, p.get(at)) {
            (Some(step), Some(&n)) => {
                next = n;
                at += step;
            }
            _ => break,
        }
    }
    m.detail = u16::from(next);
    transport(&mut m, next, p.get(at..).unwrap_or(&[]));
    m
}

/// Fill in transport-layer fields. Leaves `m` as generic IP if the protocol
/// is not one we decode.
fn transport(m: &mut Meta, protocol: u8, l4: &[u8]) {
    match protocol {
        IPPROTO_TCP => {
            m.proto = PROTO_TCP;
            m.src_port = be16(l4, 0).unwrap_or(0);
            m.dst_port = be16(l4, 2).unwrap_or(0);
            m.detail = l4.get(13).map_or(0, |f| u16::from(*f));
        }
        IPPROTO_UDP => {
            m.src_port = be16(l4, 0).unwrap_or(0);
            m.dst_port = be16(l4, 2).unwrap_or(0);
            m.detail = 0;
            m.proto = if m.src_port == DNS_PORT || m.dst_port == DNS_PORT {
                PROTO_DNS
            } else {
                PROTO_UDP
            };
        }
        IPPROTO_ICMP if m.ip_version == 4 => {
            m.proto = PROTO_ICMP;
            m.detail = icmp_type_code(l4);
        }
        IPPROTO_ICMPV6 if m.ip_version == 6 => {
            m.proto = PROTO_ICMPV6;
            m.detail = icmp_type_code(l4);
        }
        _ => {}
    }
}

fn icmp_type_code(l4: &[u8]) -> u16 {
    match (l4.first(), l4.get(1)) {
        (Some(t), Some(c)) => (u16::from(*t) << 8) | u16::from(*c),
        _ => 0,
    }
}
