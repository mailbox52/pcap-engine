//! Whole-capture summary: totals, duration, protocol breakdown, top talkers.
//! Computed in one pass over the index columns.

use std::collections::HashMap;

use serde::Serialize;

use crate::core::PacketIndex;

/// How many talkers to report.
pub const TOP_TALKERS: usize = 10;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolStat {
    /// `dissect::PROTO_*` value.
    pub proto: u8,
    pub packets: u32,
    /// Sum of original packet lengths.
    pub bytes: f64,
}

/// An address seen as a source or destination. Bytes and packets count every
/// packet the address appears in (once per packet, even if it is both ends).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Talker {
    /// 4 or 6.
    pub ip_version: u8,
    /// IPv4 uses the first 4 bytes.
    pub addr: [u8; 16],
    pub packets: u32,
    pub bytes: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub total_packets: u32,
    /// Sum of original packet lengths (what was on the wire).
    pub total_bytes: f64,
    /// Sum of captured lengths (what is in the file).
    pub captured_bytes: f64,
    /// Earliest and latest timestamps. Both zero if no packet has a timestamp.
    pub first_sec: u32,
    pub first_nsec: u32,
    pub last_sec: u32,
    pub last_nsec: u32,
    pub duration_secs: f64,
    /// Protocols that occur, most packets first.
    pub protocols: Vec<ProtocolStat>,
    /// Up to `TOP_TALKERS`, most bytes first.
    pub top_talkers: Vec<Talker>,
}

type Key = (u8, [u8; 16]);

fn address_at(idx: &PacketIndex, packet: usize, offset: usize) -> [u8; 16] {
    let start = packet * 32 + offset;
    let mut a = [0u8; 16];
    a.copy_from_slice(&idx.addr[start..start + 16]);
    a
}

pub fn summarize(idx: &PacketIndex) -> Summary {
    let n = idx.len();
    let mut total_bytes: u64 = 0;
    let mut captured_bytes: u64 = 0;
    let mut first: Option<(u32, u32)> = None;
    let mut last: Option<(u32, u32)> = None;
    let mut per_proto = vec![(0u32, 0u64); 256];
    let mut talkers: HashMap<Key, (u32, u64)> = HashMap::new();

    for i in 0..n {
        let len = u64::from(idx.orig_len[i]);
        total_bytes += len;
        captured_bytes += u64::from(idx.cap_len[i]);

        // Simple packets in pcapng have no timestamp (stored as 0); skip those.
        let ts = (idx.ts_sec[i], idx.ts_nsec[i]);
        if ts != (0, 0) {
            first = Some(first.map_or(ts, |f| f.min(ts)));
            last = Some(last.map_or(ts, |l| l.max(ts)));
        }

        let p = &mut per_proto[usize::from(idx.proto[i])];
        p.0 += 1;
        p.1 += len;

        let version = idx.ip_version[i];
        if version != 0 {
            let src = address_at(idx, i, 0);
            let dst = address_at(idx, i, 16);
            let e = talkers.entry((version, src)).or_insert((0, 0));
            e.0 += 1;
            e.1 += len;
            if dst != src {
                let e = talkers.entry((version, dst)).or_insert((0, 0));
                e.0 += 1;
                e.1 += len;
            }
        }
    }

    let mut protocols: Vec<ProtocolStat> = per_proto
        .iter()
        .enumerate()
        .filter(|(_, (packets, _))| *packets > 0)
        .map(|(proto, (packets, bytes))| ProtocolStat {
            proto: proto as u8,
            packets: *packets,
            bytes: *bytes as f64,
        })
        .collect();
    protocols.sort_by(|a, b| b.packets.cmp(&a.packets).then(a.proto.cmp(&b.proto)));

    let mut ranked: Vec<(Key, (u32, u64))> = talkers.into_iter().collect();
    ranked.sort_by(|a, b| {
        b.1 .1
            .cmp(&a.1 .1)
            .then(b.1 .0.cmp(&a.1 .0))
            .then(a.0.cmp(&b.0))
    });
    let top_talkers = ranked
        .into_iter()
        .take(TOP_TALKERS)
        .map(|((ip_version, addr), (packets, bytes))| Talker {
            ip_version,
            addr,
            packets,
            bytes: bytes as f64,
        })
        .collect();

    let (first_sec, first_nsec) = first.unwrap_or((0, 0));
    let (last_sec, last_nsec) = last.unwrap_or((0, 0));
    let duration_secs = f64::from(last_sec) - f64::from(first_sec)
        + (f64::from(last_nsec) - f64::from(first_nsec)) / 1e9;

    Summary {
        total_packets: n as u32,
        total_bytes: total_bytes as f64,
        captured_bytes: captured_bytes as f64,
        first_sec,
        first_nsec,
        last_sec,
        last_nsec,
        duration_secs,
        protocols,
        top_talkers,
    }
}
