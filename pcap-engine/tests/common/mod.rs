//! Tiny in-test builders for pcap / pcapng bytes, so fixtures are readable
//! and there are no binary files to maintain.
#![allow(dead_code)]

#[derive(Clone, Copy)]
pub struct Endian {
    pub big: bool,
}

impl Endian {
    pub const LE: Endian = Endian { big: false };
    pub const BE: Endian = Endian { big: true };

    pub fn u16(self, out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&if self.big { v.to_be_bytes() } else { v.to_le_bytes() });
    }
    pub fn u32(self, out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&if self.big { v.to_be_bytes() } else { v.to_le_bytes() });
    }
    pub fn i64(self, out: &mut Vec<u8>, v: i64) {
        out.extend_from_slice(&if self.big { v.to_be_bytes() } else { v.to_le_bytes() });
    }
}

/// Ethernet + IPv4 (10.0.0.1 -> 10.0.0.2, TCP) + `payload` bytes.
pub fn eth_ipv4_packet(payload: &[u8]) -> Vec<u8> {
    let mut p = vec![
        0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01, // dst mac
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // src mac
        0x08, 0x00, // ethertype IPv4
    ];
    let total = (20 + payload.len()) as u16;
    p.extend_from_slice(&[0x45, 0x00]);
    p.extend_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]); // id, flags, ttl=64, proto=TCP, csum
    p.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    p.extend_from_slice(payload);
    p
}

pub struct Pkt<'a> {
    pub ts_sec: u32,
    /// Fraction in the file's own unit (micro or nano).
    pub ts_frac: u32,
    pub orig_len: u32,
    pub data: &'a [u8],
}

/// Legacy pcap file. `magic` is the little-endian-interpreted constant:
/// 0xa1b2c3d4 (micro) or 0xa1b23c4d (nano); endianness picks byte order.
pub fn pcap_file(e: Endian, nano: bool, linktype: u32, pkts: &[Pkt]) -> Vec<u8> {
    let mut f = Vec::new();
    e.u32(&mut f, if nano { 0xa1b2_3c4d } else { 0xa1b2_c3d4 });
    e.u16(&mut f, 2);
    e.u16(&mut f, 4);
    e.u32(&mut f, 0); // thiszone
    e.u32(&mut f, 0); // sigfigs
    e.u32(&mut f, 65535);
    e.u32(&mut f, linktype);
    for p in pkts {
        e.u32(&mut f, p.ts_sec);
        e.u32(&mut f, p.ts_frac);
        e.u32(&mut f, p.data.len() as u32);
        e.u32(&mut f, p.orig_len);
        f.extend_from_slice(p.data);
    }
    f
}

fn pad4(out: &mut Vec<u8>) {
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn block(e: Endian, block_type: u32, body: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    let mut padded = body.to_vec();
    pad4(&mut padded);
    let total = (padded.len() + 12) as u32;
    e.u32(&mut b, block_type);
    e.u32(&mut b, total);
    b.extend_from_slice(&padded);
    e.u32(&mut b, total);
    b
}

pub fn shb(e: Endian) -> Vec<u8> {
    let mut body = Vec::new();
    e.u32(&mut body, 0x1a2b_3c4d);
    e.u16(&mut body, 1);
    e.u16(&mut body, 0);
    e.i64(&mut body, -1);
    block(e, 0x0a0d_0d0a, &body)
}

/// Interface Description Block. `tsresol` adds an if_tsresol option when set.
pub fn idb(e: Endian, linktype: u16, tsresol: Option<u8>) -> Vec<u8> {
    let mut body = Vec::new();
    e.u16(&mut body, linktype);
    e.u16(&mut body, 0);
    e.u32(&mut body, 65535);
    if let Some(r) = tsresol {
        e.u16(&mut body, 9); // if_tsresol
        e.u16(&mut body, 1);
        body.push(r);
        pad4(&mut body);
        e.u16(&mut body, 0); // opt_endofopt
        e.u16(&mut body, 0);
    }
    block(e, 0x0000_0001, &body)
}

pub fn epb(e: Endian, if_id: u32, ticks: u64, orig_len: u32, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    e.u32(&mut body, if_id);
    e.u32(&mut body, (ticks >> 32) as u32);
    e.u32(&mut body, ticks as u32);
    e.u32(&mut body, data.len() as u32);
    e.u32(&mut body, orig_len);
    body.extend_from_slice(data);
    block(e, 0x0000_0006, &body)
}

pub fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flatten().copied().collect()
}
