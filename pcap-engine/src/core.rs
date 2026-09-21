//! Pure-Rust capture indexing. No wasm or JS types in here, so it is
//! testable with plain `cargo test`.

use crate::dissect::{dissect, Meta};
use pcap_parser::pcapng::{Block, InterfaceDescriptionBlock};
use pcap_parser::{
    parse_pcap_frame, parse_pcap_frame_be, LegacyPcapSlice, PcapBlockOwned, PcapNGSlice,
};

/// Cap on how many non-fatal issues we record, so a hostile file cannot
/// grow this list without bound.
const MAX_ISSUES: usize = 20;
const DEFAULT_RESOLUTION: u64 = 1_000_000; // pcapng default: microseconds
const PCAP_HEADER_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pcap,
    PcapNg,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Pcap => "pcap",
            Format::PcapNg => "pcapng",
        }
    }
}

/// Fatal: nothing useful could be read at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    NotACapture,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::TooShort => write!(f, "File is too short to be a pcap or pcapng capture"),
            ParseError::NotACapture => write!(f, "File is not a recognised pcap or pcapng capture"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Columnar packet index. Column `i` describes packet `i`.
#[derive(Debug, Clone)]
pub struct PacketIndex {
    pub format: Format,
    pub ts_sec: Vec<u32>,
    pub ts_nsec: Vec<u32>,
    pub orig_len: Vec<u32>,
    pub cap_len: Vec<u32>,
    /// Byte offset of the packet data within the input buffer.
    pub offset: Vec<u32>,
    /// pcap LINKTYPE_* value for the packet's interface.
    pub linktype: Vec<u16>,
    /// `dissect::PROTO_*` value.
    pub proto: Vec<u8>,
    /// 4, 6, or 0 (no addresses).
    pub ip_version: Vec<u8>,
    pub src_port: Vec<u16>,
    pub dst_port: Vec<u16>,
    /// Protocol-specific value; see `dissect::Meta::detail`.
    pub detail: Vec<u16>,
    /// 32 bytes per packet: 16-byte source address then 16-byte destination.
    pub addr: Vec<u8>,
    /// False if parsing stopped early (truncated or corrupt file). Packets
    /// parsed before the problem are still present.
    pub complete: bool,
    pub issues: Vec<String>,
}

impl PacketIndex {
    fn new(format: Format, capacity: usize) -> Self {
        PacketIndex {
            format,
            ts_sec: Vec::with_capacity(capacity),
            ts_nsec: Vec::with_capacity(capacity),
            orig_len: Vec::with_capacity(capacity),
            cap_len: Vec::with_capacity(capacity),
            offset: Vec::with_capacity(capacity),
            linktype: Vec::with_capacity(capacity),
            proto: Vec::with_capacity(capacity),
            ip_version: Vec::with_capacity(capacity),
            src_port: Vec::with_capacity(capacity),
            dst_port: Vec::with_capacity(capacity),
            detail: Vec::with_capacity(capacity),
            addr: Vec::with_capacity(capacity * 32),
            complete: true,
            issues: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.ts_sec.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ts_sec.is_empty()
    }

    fn issue(&mut self, msg: impl Into<String>) {
        if self.issues.len() < MAX_ISSUES {
            self.issues.push(msg.into());
        }
    }

    /// Stop parsing: record why, and mark the result partial.
    fn stop(&mut self, msg: impl Into<String>) {
        self.complete = false;
        self.issue(msg);
    }

    /// Returns false (and stops) if the packet cannot be represented.
    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        data_offset: usize,
        ts: (u32, u32),
        orig_len: u32,
        cap_len: u32,
        linktype: u16,
        packet: &[u8],
    ) -> bool {
        let Ok(offset) = u32::try_from(data_offset) else {
            self.stop("Capture is larger than 4 GiB; packets past this point were skipped");
            return false;
        };
        self.ts_sec.push(ts.0);
        self.ts_nsec.push(ts.1);
        self.orig_len.push(orig_len);
        self.cap_len.push(cap_len);
        self.offset.push(offset);
        self.linktype.push(linktype);
        let meta: Meta = dissect(packet, linktype);
        self.proto.push(meta.proto);
        self.ip_version.push(meta.ip_version);
        self.src_port.push(meta.src_port);
        self.dst_port.push(meta.dst_port);
        self.detail.push(meta.detail);
        self.addr.extend_from_slice(&meta.src);
        self.addr.extend_from_slice(&meta.dst);
        true
    }
}

/// Parse a whole capture held in memory into a columnar index.
pub fn parse_capture(data: &[u8]) -> Result<PacketIndex, ParseError> {
    if data.len() < 24 {
        return Err(ParseError::TooShort);
    }
    // pcapng starts with a Section Header Block; legacy pcap with its magic.
    if let Ok(slice) = PcapNGSlice::from_slice(data) {
        return Ok(parse_pcapng(data, slice));
    }
    if let Ok(slice) = LegacyPcapSlice::from_slice(data) {
        return Ok(parse_legacy(data, slice));
    }
    Err(ParseError::NotACapture)
}

/// Offset of `sub` inside `whole`. `sub` must be a sub-slice of `whole`,
/// which holds for everything the slice parsers hand back.
fn offset_in(whole: &[u8], sub: &[u8]) -> Option<usize> {
    let start = (sub.as_ptr() as usize).checked_sub(whole.as_ptr() as usize)?;
    if start + sub.len() <= whole.len() {
        Some(start)
    } else {
        None
    }
}

fn parse_legacy(data: &[u8], slice: LegacyPcapSlice<'_>) -> PacketIndex {
    let nano = slice.header.is_nanosecond_precision();
    let linktype = u16::try_from(slice.header.network.0).unwrap_or(u16::MAX);
    // pcap-parser's `LegacyPcapSlice` iterator only decodes little-endian
    // records, so drive the frame parsers ourselves and pick by byte order.
    let parse_frame = if slice.header.is_bigendian() {
        parse_pcap_frame_be
    } else {
        parse_pcap_frame
    };
    let mut idx = PacketIndex::new(Format::Pcap, data.len() / 64);
    let mut rem = data.get(PCAP_HEADER_LEN..).unwrap_or(&[]);

    while !rem.is_empty() {
        let (next, block) = match parse_frame(rem) {
            Ok(ok) => ok,
            Err(_) => {
                idx.stop(format!(
                    "File is truncated or corrupt after packet {}",
                    idx.len()
                ));
                break;
            }
        };
        rem = next;
        let Some(offset) = offset_in(data, block.data) else {
            idx.stop("Internal error locating packet data");
            break;
        };
        let nsec = if nano {
            block.ts_usec.min(999_999_999)
        } else {
            block.ts_usec.saturating_mul(1000).min(999_999_999)
        };
        if !idx.push(
            offset,
            (block.ts_sec, nsec),
            block.origlen,
            block.caplen,
            linktype,
            block.data,
        ) {
            break;
        }
    }
    idx
}

#[derive(Clone, Copy)]
struct Interface {
    linktype: u16,
    resolution: u64,
    offset_secs: i64,
}

fn interface_from(idb: &InterfaceDescriptionBlock<'_>, idx: &mut PacketIndex) -> Interface {
    let resolution = match idb.ts_resolution() {
        Some(r) if r > 0 => r,
        _ => {
            idx.issue("Interface has an invalid timestamp resolution; assuming microseconds");
            DEFAULT_RESOLUTION
        }
    };
    Interface {
        linktype: u16::try_from(idb.linktype.0).unwrap_or(u16::MAX),
        resolution,
        offset_secs: idb.ts_offset(),
    }
}

/// Convert raw pcapng ticks into (seconds, nanoseconds).
fn split_ticks(ticks: u64, resolution: u64, offset_secs: i64) -> (u32, u32) {
    let secs = (ticks / resolution) as i128 + offset_secs as i128;
    let nsec = ((ticks % resolution) as u128 * 1_000_000_000u128 / resolution as u128) as u32;
    (secs.clamp(0, u32::MAX as i128) as u32, nsec)
}

fn parse_pcapng(data: &[u8], slice: PcapNGSlice<'_>) -> PacketIndex {
    let mut idx = PacketIndex::new(Format::PcapNg, data.len() / 64);
    // Interfaces are numbered per section; a new Section Header resets them.
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut warned_unknown_if = false;

    for item in slice {
        let block = match item {
            Ok(PcapBlockOwned::NG(b)) => b,
            Ok(_) => continue,
            Err(_) => {
                idx.stop(format!(
                    "File is truncated or corrupt after packet {}",
                    idx.len()
                ));
                break;
            }
        };
        match block {
            Block::SectionHeader(_) => interfaces.clear(),
            Block::InterfaceDescription(idb) => {
                let iface = interface_from(&idb, &mut idx);
                interfaces.push(iface);
            }
            Block::EnhancedPacket(epb) => {
                let iface = match interfaces.get(epb.if_id as usize) {
                    Some(i) => *i,
                    None => {
                        if !warned_unknown_if {
                            idx.issue("Packet refers to an undeclared interface; using defaults");
                            warned_unknown_if = true;
                        }
                        Interface {
                            linktype: 0,
                            resolution: DEFAULT_RESOLUTION,
                            offset_secs: 0,
                        }
                    }
                };
                let ticks = ((epb.ts_high as u64) << 32) | epb.ts_low as u64;
                let ts = split_ticks(ticks, iface.resolution, iface.offset_secs);
                // Data can include up to 3 bytes of padding; caplen is authoritative.
                let cap = (epb.caplen as usize).min(epb.data.len()) as u32;
                let Some(offset) = offset_in(data, epb.data) else {
                    idx.stop("Internal error locating packet data");
                    break;
                };
                if !idx.push(
                    offset,
                    ts,
                    epb.origlen,
                    cap,
                    iface.linktype,
                    epb.data.get(..cap as usize).unwrap_or(epb.data),
                ) {
                    break;
                }
            }
            Block::SimplePacket(spb) => {
                // Simple packets carry no timestamp and always use interface 0.
                let linktype = interfaces.first().map_or(0, |i| i.linktype);
                let cap = (spb.origlen as usize).min(spb.data.len()) as u32;
                let Some(offset) = offset_in(data, spb.data) else {
                    idx.stop("Internal error locating packet data");
                    break;
                };
                if !idx.push(
                    offset,
                    (0, 0),
                    spb.origlen,
                    cap,
                    linktype,
                    spb.data.get(..cap as usize).unwrap_or(spb.data),
                ) {
                    break;
                }
            }
            _ => {}
        }
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_microseconds() {
        assert_eq!(split_ticks(1_700_000_000_123_456, 1_000_000, 0), (1_700_000_000, 123_456_000));
    }

    #[test]
    fn ticks_nanoseconds() {
        assert_eq!(split_ticks(5_000_000_007, 1_000_000_000, 0), (5, 7));
    }

    #[test]
    fn ticks_power_of_two_resolution() {
        // 2^10 = 1024 ticks/sec; 512 ticks = 0.5 s
        assert_eq!(split_ticks(512, 1024, 0), (0, 500_000_000));
    }

    #[test]
    fn ticks_apply_offset() {
        assert_eq!(split_ticks(2_000_000, 1_000_000, 100), (102, 0));
    }
}
