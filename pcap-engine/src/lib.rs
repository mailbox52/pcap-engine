//! pcap-engine: `.pcap` / `.pcapng` parsing for the browser.
//!
//! `core` and `link` are plain Rust and unit tested natively. This file is
//! only the thin wasm-bindgen layer over them.

pub mod core;
pub mod dissect;
pub mod link;

use wasm_bindgen::prelude::*;

/// Result of parsing a capture. Holds only per-packet columns, not the file
/// bytes. The caller keeps the file and slices out packets on demand.
#[wasm_bindgen]
pub struct PcapIndex {
    inner: core::PacketIndex,
}

/// Clamp a JS-supplied `[start, end)` range to the packet count.
fn range(len: usize, start: u32, end: u32) -> std::ops::Range<usize> {
    let end = (end as usize).min(len);
    let start = (start as usize).min(end);
    start..end
}

#[wasm_bindgen]
impl PcapIndex {
    pub fn count(&self) -> u32 {
        self.inner.len() as u32
    }

    /// "pcap" or "pcapng".
    pub fn format(&self) -> String {
        self.inner.format.as_str().to_string()
    }

    /// False if the file was truncated or corrupt; packets before the
    /// problem are still available.
    pub fn complete(&self) -> bool {
        self.inner.complete
    }

    pub fn issues(&self) -> Vec<String> {
        self.inner.issues.clone()
    }

    pub fn ts_sec(&self, start: u32, end: u32) -> Vec<u32> {
        self.inner.ts_sec[range(self.inner.len(), start, end)].to_vec()
    }

    pub fn ts_nsec(&self, start: u32, end: u32) -> Vec<u32> {
        self.inner.ts_nsec[range(self.inner.len(), start, end)].to_vec()
    }

    pub fn orig_len(&self, start: u32, end: u32) -> Vec<u32> {
        self.inner.orig_len[range(self.inner.len(), start, end)].to_vec()
    }

    pub fn cap_len(&self, start: u32, end: u32) -> Vec<u32> {
        self.inner.cap_len[range(self.inner.len(), start, end)].to_vec()
    }

    /// Byte offset of each packet's data within the original file.
    pub fn offset(&self, start: u32, end: u32) -> Vec<u32> {
        self.inner.offset[range(self.inner.len(), start, end)].to_vec()
    }

    pub fn linktype(&self, start: u32, end: u32) -> Vec<u16> {
        self.inner.linktype[range(self.inner.len(), start, end)].to_vec()
    }

    /// Protocol id per packet (see `dissect::PROTO_*`).
    pub fn proto(&self, start: u32, end: u32) -> Vec<u8> {
        self.inner.proto[range(self.inner.len(), start, end)].to_vec()
    }

    /// 4, 6, or 0 per packet.
    pub fn ip_version(&self, start: u32, end: u32) -> Vec<u8> {
        self.inner.ip_version[range(self.inner.len(), start, end)].to_vec()
    }

    pub fn src_port(&self, start: u32, end: u32) -> Vec<u16> {
        self.inner.src_port[range(self.inner.len(), start, end)].to_vec()
    }

    pub fn dst_port(&self, start: u32, end: u32) -> Vec<u16> {
        self.inner.dst_port[range(self.inner.len(), start, end)].to_vec()
    }

    /// Protocol-specific value per packet (TCP flags, ICMP type/code, ARP op, ...).
    pub fn detail(&self, start: u32, end: u32) -> Vec<u16> {
        self.inner.detail[range(self.inner.len(), start, end)].to_vec()
    }

    /// 32 bytes per packet: 16-byte source address then 16-byte destination.
    pub fn addr(&self, start: u32, end: u32) -> Vec<u8> {
        let r = range(self.inner.len(), start, end);
        self.inner.addr[r.start * 32..r.end * 32].to_vec()
    }
}

/// Parse a whole capture held in memory.
#[wasm_bindgen]
pub fn parse_pcap_bytes(data: &[u8]) -> Result<PcapIndex, JsError> {
    let inner = core::parse_capture(data).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(PcapIndex { inner })
}

/// Link-layer preview for one packet's bytes. The worker passes just that
/// packet's slice of the file, so nothing large crosses the boundary.
#[wasm_bindgen]
pub fn link_preview(packet: &[u8], linktype: u32) -> Result<JsValue, JsError> {
    let lt = u16::try_from(linktype).unwrap_or(u16::MAX);
    let preview = link::link_preview(packet, lt);
    serde_wasm_bindgen::to_value(&preview).map_err(|e| JsError::new(&e.to_string()))
}
