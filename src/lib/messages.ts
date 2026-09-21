/** Message contract between the UI thread and pcap.worker.ts. */

/** Hard cap for v1: the file is read whole, then copied into Wasm memory. */
export const MAX_FILE_BYTES = 256 * 1024 * 1024;

/** Packets per `batch` message. */
export const BATCH_SIZE = 10_000;

/**
 * Shape returned by the Rust `link_preview` function (see pcap-engine/src/link.rs).
 * serde-wasm-bindgen turns Rust `None` into `undefined`, not `null`, so the
 * optional fields are missing rather than null. Always test them with `!= null`.
 */
export interface LinkPreview {
  kind: string;
  summary: string;
  dst_mac?: string | null;
  src_mac?: string | null;
  ethertype?: number | null;
  vlan_id?: number | null;
  ipv4?: {
    src: string;
    dst: string;
    protocol: number;
    ttl: number;
    total_len: number;
  } | null;
  header_hex: string;
}

/** Whole-capture summary from the Rust `summary()` (see pcap-engine/src/summary.rs). */
export interface CaptureSummary {
  totalPackets: number;
  /** Sum of original packet lengths (bytes on the wire). */
  totalBytes: number;
  /** Sum of captured lengths (bytes stored in the file). */
  capturedBytes: number;
  firstSec: number;
  firstNsec: number;
  lastSec: number;
  lastNsec: number;
  durationSecs: number;
  /** Protocols that occur, most packets first. */
  protocols: { proto: number; packets: number; bytes: number }[];
  /** Up to 10 addresses, most bytes first. */
  topTalkers: { ipVersion: number; addr: number[]; packets: number; bytes: number }[];
}

export type Stage = "reading" | "parsing" | "sending";

export type WorkerIn =
  | { type: "parse"; file: File }
  | { type: "dissect"; index: number };

export interface PacketBatch {
  type: "batch";
  /** Index of the first packet in this batch. */
  start: number;
  tsSec: Uint32Array;
  tsNsec: Uint32Array;
  origLen: Uint32Array;
  capLen: Uint32Array;
  offset: Uint32Array;
  linktype: Uint16Array;
  /** Protocol id (see PROTOCOLS in summary.ts). */
  proto: Uint8Array;
  /** 4, 6, or 0 when the packet has no addresses. */
  ipVer: Uint8Array;
  srcPort: Uint16Array;
  dstPort: Uint16Array;
  /** TCP flags, ICMP type/code, ARP operation, IP protocol, or EtherType, depending on proto. */
  detail: Uint16Array;
  /** 32 bytes per packet: 16-byte source address then 16-byte destination. */
  addr: Uint8Array;
}

export type WorkerOut =
  | { type: "status"; stage: Stage }
  | { type: "started"; format: string; total: number }
  | PacketBatch
  | { type: "summary"; summary: CaptureSummary }
  | {
      type: "done";
      total: number;
      format: string;
      /** False if the file was truncated or corrupt; earlier packets are still valid. */
      complete: boolean;
      issues: string[];
      elapsedMs: number;
    }
  | { type: "packet"; index: number; preview: LinkPreview }
  | {
      type: "error";
      message: string;
      /** "dissect" errors only affect the detail panel; anything else ends the parse. */
      scope?: "parse" | "dissect";
    };

export type Emit = (msg: WorkerOut, transfer?: Transferable[]) => void;
