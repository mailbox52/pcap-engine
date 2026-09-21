import type { PacketBatch } from "./messages";

/**
 * Main-thread copy of the per-packet columns the list needs, kept in a few
 * preallocated typed arrays (about 60 bytes per packet) rather than one JS
 * object per packet, so a million-packet capture stays small.
 *
 * Deliberately not React state: it is mutated in place as batches arrive, and
 * the component re-renders off the packet count.
 */
export class PacketStore {
  count = 0;
  total = 0;
  tsSec = new Uint32Array(0);
  tsNsec = new Uint32Array(0);
  origLen = new Uint32Array(0);
  capLen = new Uint32Array(0);
  linktype = new Uint16Array(0);
  proto = new Uint8Array(0);
  ipVer = new Uint8Array(0);
  srcPort = new Uint16Array(0);
  dstPort = new Uint16Array(0);
  detail = new Uint16Array(0);
  /** 32 bytes per packet: 16-byte source address, then 16-byte destination. */
  addr = new Uint8Array(0);

  reset(total: number) {
    this.count = 0;
    this.total = total;
    this.tsSec = new Uint32Array(total);
    this.tsNsec = new Uint32Array(total);
    this.origLen = new Uint32Array(total);
    this.capLen = new Uint32Array(total);
    this.linktype = new Uint16Array(total);
    this.proto = new Uint8Array(total);
    this.ipVer = new Uint8Array(total);
    this.srcPort = new Uint16Array(total);
    this.dstPort = new Uint16Array(total);
    this.detail = new Uint16Array(total);
    this.addr = new Uint8Array(total * 32);
  }

  add(b: PacketBatch) {
    const end = b.start + b.tsSec.length;
    if (end > this.total) return; // ignore anything outside what was announced
    this.tsSec.set(b.tsSec, b.start);
    this.tsNsec.set(b.tsNsec, b.start);
    this.origLen.set(b.origLen, b.start);
    this.capLen.set(b.capLen, b.start);
    this.linktype.set(b.linktype, b.start);
    this.proto.set(b.proto, b.start);
    this.ipVer.set(b.ipVer, b.start);
    this.srcPort.set(b.srcPort, b.start);
    this.dstPort.set(b.dstPort, b.start);
    this.detail.set(b.detail, b.start);
    this.addr.set(b.addr, b.start * 32);
    this.count = Math.max(this.count, end);
  }

  /** Seconds since the first packet, from the exact sec + nsec columns. */
  relativeSeconds(i: number): number {
    return this.tsSec[i] - this.tsSec[0] + (this.tsNsec[i] - this.tsNsec[0]) / 1e9;
  }

  /** ISO-8601 UTC timestamp with nanoseconds. */
  isoTime(i: number): string {
    const base = new Date(this.tsSec[i] * 1000).toISOString().slice(0, 19);
    return `${base}.${String(this.tsNsec[i]).padStart(9, "0")}Z`;
  }
}
