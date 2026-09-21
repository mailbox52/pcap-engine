/* tslint:disable */
/* eslint-disable */

/**
 * Result of parsing a capture. Holds only per-packet columns, not the file
 * bytes. The caller keeps the file and slices out packets on demand.
 */
export class PcapIndex {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * 32 bytes per packet: 16-byte source address then 16-byte destination.
     */
    addr(start: number, end: number): Uint8Array;
    cap_len(start: number, end: number): Uint32Array;
    /**
     * False if the file was truncated or corrupt; packets before the
     * problem are still available.
     */
    complete(): boolean;
    count(): number;
    /**
     * Protocol-specific value per packet (TCP flags, ICMP type/code, ARP op, ...).
     */
    detail(start: number, end: number): Uint16Array;
    dst_port(start: number, end: number): Uint16Array;
    /**
     * "pcap" or "pcapng".
     */
    format(): string;
    /**
     * 4, 6, or 0 per packet.
     */
    ip_version(start: number, end: number): Uint8Array;
    issues(): string[];
    linktype(start: number, end: number): Uint16Array;
    /**
     * Byte offset of each packet's data within the original file.
     */
    offset(start: number, end: number): Uint32Array;
    orig_len(start: number, end: number): Uint32Array;
    /**
     * Protocol id per packet (see `dissect::PROTO_*`).
     */
    proto(start: number, end: number): Uint8Array;
    src_port(start: number, end: number): Uint16Array;
    ts_nsec(start: number, end: number): Uint32Array;
    ts_sec(start: number, end: number): Uint32Array;
}

/**
 * Link-layer preview for one packet's bytes. The worker passes just that
 * packet's slice of the file, so nothing large crosses the boundary.
 */
export function link_preview(packet: Uint8Array, linktype: number): any;

/**
 * Parse a whole capture held in memory.
 */
export function parse_pcap_bytes(data: Uint8Array): PcapIndex;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_pcapindex_free: (a: number, b: number) => void;
    readonly link_preview: (a: number, b: number, c: number) => [number, number, number];
    readonly parse_pcap_bytes: (a: number, b: number) => [number, number, number];
    readonly pcapindex_addr: (a: number, b: number, c: number) => [number, number];
    readonly pcapindex_cap_len: (a: number, b: number, c: number) => [number, number];
    readonly pcapindex_complete: (a: number) => number;
    readonly pcapindex_count: (a: number) => number;
    readonly pcapindex_detail: (a: number, b: number, c: number) => [number, number];
    readonly pcapindex_dst_port: (a: number, b: number, c: number) => [number, number];
    readonly pcapindex_format: (a: number) => [number, number];
    readonly pcapindex_ip_version: (a: number, b: number, c: number) => [number, number];
    readonly pcapindex_issues: (a: number) => [number, number];
    readonly pcapindex_linktype: (a: number, b: number, c: number) => [number, number];
    readonly pcapindex_offset: (a: number, b: number, c: number) => [number, number];
    readonly pcapindex_orig_len: (a: number, b: number, c: number) => [number, number];
    readonly pcapindex_proto: (a: number, b: number, c: number) => [number, number];
    readonly pcapindex_src_port: (a: number, b: number, c: number) => [number, number];
    readonly pcapindex_ts_nsec: (a: number, b: number, c: number) => [number, number];
    readonly pcapindex_ts_sec: (a: number, b: number, c: number) => [number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_drop_slice: (a: number, b: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
