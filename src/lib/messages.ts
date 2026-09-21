/** Message contract between the UI thread and pcap.worker.ts. */

/** Hard cap for v1: the file is read whole, then copied into Wasm memory. */
export const MAX_FILE_BYTES = 256 * 1024 * 1024;

/** Packets per `batch` message. */
export const BATCH_SIZE = 10_000;

/** Shape returned by the Rust `link_preview` function (see pcap-engine/src/link.rs). */
export interface LinkPreview {
  kind: string;
  summary: string;
  dst_mac: string | null;
  src_mac: string | null;
  ethertype: number | null;
  vlan_id: number | null;
  ipv4: {
    src: string;
    dst: string;
    protocol: number;
    ttl: number;
    total_len: number;
  } | null;
  header_hex: string;
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
}

export type WorkerOut =
  | { type: "status"; stage: Stage }
  | { type: "started"; format: string; total: number }
  | PacketBatch
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
  | { type: "error"; message: string };

export type Emit = (msg: WorkerOut, transfer?: Transferable[]) => void;
