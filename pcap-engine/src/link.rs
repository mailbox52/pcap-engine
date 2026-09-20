//! Link-layer preview: MAC header, RadioTap/802.11, or IPv4 preview.
//! Every read is bounds-checked; malformed or short packets never panic.

use serde::Serialize;

pub const LINKTYPE_NULL: u16 = 0;
pub const LINKTYPE_ETHERNET: u16 = 1;
pub const LINKTYPE_RAW: u16 = 101;
pub const LINKTYPE_IEEE802_11: u16 = 105;
pub const LINKTYPE_LINUX_SLL: u16 = 113;
pub const LINKTYPE_IEEE802_11_RADIOTAP: u16 = 127;
pub const LINKTYPE_IPV4: u16 = 228;
pub const LINKTYPE_IPV6: u16 = 229;

/// How many leading bytes are echoed back as hex.
const HEADER_HEX_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ipv4Preview {
    pub src: String,
    pub dst: String,
    pub protocol: u8,
    pub ttl: u8,
    pub total_len: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkPreview {
    /// "ethernet", "radiotap", "ieee802_11", "ipv4", "ipv6", "loopback",
    /// "linux_sll", or "unknown".
    pub kind: String,
    pub summary: String,
    pub dst_mac: Option<String>,
    pub src_mac: Option<String>,
    pub ethertype: Option<u16>,
    pub vlan_id: Option<u16>,
    pub ipv4: Option<Ipv4Preview>,
    /// First bytes of the packet, hex encoded.
    pub header_hex: String,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn mac(bytes: &[u8]) -> Option<String> {
    let b = bytes.get(..6)?;
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    ))
}

fn be16(data: &[u8], at: usize) -> Option<u16> {
    let b = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

fn le16(data: &[u8], at: usize) -> Option<u16> {
    let b = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

pub fn parse_ipv4(data: &[u8]) -> Option<Ipv4Preview> {
    let h = data.get(..20)?;
    if h[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Preview {
        total_len: u16::from_be_bytes([h[2], h[3]]),
        ttl: h[8],
        protocol: h[9],
        src: format!("{}.{}.{}.{}", h[12], h[13], h[14], h[15]),
        dst: format!("{}.{}.{}.{}", h[16], h[17], h[18], h[19]),
    })
}

fn blank(kind: &str, summary: String, data: &[u8]) -> LinkPreview {
    LinkPreview {
        kind: kind.to_string(),
        summary,
        dst_mac: None,
        src_mac: None,
        ethertype: None,
        vlan_id: None,
        ipv4: None,
        header_hex: hex(&data[..data.len().min(HEADER_HEX_BYTES)]),
    }
}

fn ethertype_name(t: u16) -> &'static str {
    match t {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86dd => "IPv6",
        0x8100 => "VLAN",
        0x88a8 => "QinQ",
        0x88cc => "LLDP",
        _ => "Other",
    }
}

fn ethernet(data: &[u8]) -> LinkPreview {
    let mut p = blank("ethernet", "Ethernet (truncated)".into(), data);
    let (Some(dst), Some(src)) = (data.get(..6).and_then(mac), data.get(6..12).and_then(mac))
    else {
        return p;
    };
    p.dst_mac = Some(dst);
    p.src_mac = Some(src);

    let mut at = 12;
    let Some(mut ethertype) = be16(data, at) else {
        return p;
    };
    at += 2;
    // Up to two stacked VLAN tags (802.1Q, or QinQ outer + inner).
    for _ in 0..2 {
        if ethertype != 0x8100 && ethertype != 0x88a8 {
            break;
        }
        let (Some(tci), Some(inner)) = (be16(data, at), be16(data, at + 2)) else {
            p.ethertype = Some(ethertype);
            p.summary = "Ethernet, VLAN tag (truncated)".into();
            return p;
        };
        p.vlan_id.get_or_insert(tci & 0x0fff);
        ethertype = inner;
        at += 4;
    }
    p.ethertype = Some(ethertype);
    if ethertype == 0x0800 {
        p.ipv4 = data.get(at..).and_then(parse_ipv4);
    }
    p.summary = match (&p.ipv4, p.vlan_id) {
        (Some(ip), _) => format!("Ethernet, IPv4 {} → {}", ip.src, ip.dst),
        (None, Some(v)) => format!("Ethernet, VLAN {v}, {}", ethertype_name(ethertype)),
        (None, None) => format!("Ethernet, {}", ethertype_name(ethertype)),
    };
    p
}

fn dot11_frame_kind(fc: u8) -> &'static str {
    match (fc >> 2) & 0x3 {
        0 => "management",
        1 => "control",
        2 => "data",
        _ => "extension",
    }
}

/// 802.11 MAC header starting at `data[at..]`.
fn dot11(data: &[u8], at: usize, kind: &str, prefix: &str) -> LinkPreview {
    let mut p = blank(kind, format!("{prefix} (truncated)"), data);
    let Some(fc) = data.get(at).copied() else {
        return p;
    };
    let frame_kind = dot11_frame_kind(fc);
    p.summary = format!("{prefix}, {frame_kind} frame");
    // Address 1 is the receiver, address 2 the transmitter. Some control
    // frames carry only address 1.
    p.dst_mac = data.get(at + 4..).and_then(mac);
    p.src_mac = data.get(at + 10..).and_then(mac);
    p
}

fn radiotap(data: &[u8]) -> LinkPreview {
    let Some(rt_len) = le16(data, 2).map(usize::from) else {
        return blank("radiotap", "RadioTap (truncated)".into(), data);
    };
    if data.first() != Some(&0) || rt_len < 8 || rt_len > data.len() {
        return blank("radiotap", "RadioTap (malformed header)".into(), data);
    }
    dot11(data, rt_len, "radiotap", "RadioTap + 802.11")
}

fn raw_ip(data: &[u8], kind: &str) -> LinkPreview {
    let mut p = blank(kind, "IP (truncated)".into(), data);
    match data.first().map(|b| b >> 4) {
        Some(4) => {
            p.kind = "ipv4".into();
            p.ipv4 = parse_ipv4(data);
            p.summary = match &p.ipv4 {
                Some(ip) => format!("IPv4 {} → {}", ip.src, ip.dst),
                None => "IPv4 (truncated)".into(),
            };
        }
        Some(6) => {
            p.kind = "ipv6".into();
            p.summary = "IPv6".into();
        }
        _ => p.summary = "Unrecognised IP version".into(),
    }
    p
}

/// Build a preview for one packet. `linktype` is the pcap LINKTYPE_* value.
pub fn link_preview(data: &[u8], linktype: u16) -> LinkPreview {
    match linktype {
        LINKTYPE_ETHERNET => ethernet(data),
        LINKTYPE_IEEE802_11_RADIOTAP => radiotap(data),
        LINKTYPE_IEEE802_11 => dot11(data, 0, "ieee802_11", "802.11"),
        LINKTYPE_RAW | LINKTYPE_IPV4 | LINKTYPE_IPV6 => raw_ip(data, "ipv4"),
        LINKTYPE_NULL => {
            // 4-byte address-family header, then an IP packet.
            let inner = data.get(4..).unwrap_or(&[]);
            let mut p = raw_ip(inner, "loopback");
            p.kind = "loopback".into();
            p.header_hex = hex(&data[..data.len().min(HEADER_HEX_BYTES)]);
            p
        }
        LINKTYPE_LINUX_SLL => blank("linux_sll", "Linux cooked capture".into(), data),
        other => blank("unknown", format!("Link type {other} (no preview)"), data),
    }
}
