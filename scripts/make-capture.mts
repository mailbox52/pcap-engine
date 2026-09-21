/**
 * Writes a large synthetic .pcap for testing scroll performance.
 * Usage: npm run make-capture -- 1000000 big.pcap
 * (defaults: 1,000,000 packets -> big.pcap). About 130 MB per million packets.
 */
import { closeSync, openSync, writeSync } from "node:fs";

const count = Number(process.argv[2] ?? 1_000_000);
const out = process.argv[3] ?? "big.pcap";
if (!Number.isInteger(count) || count < 1) {
  console.error("Packet count must be a positive integer.");
  process.exit(1);
}

// Small deterministic PRNG (mulberry32) so the file is reproducible.
let seed = 0x9e3779b9;
const rand = () => {
  seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

const fd = openSync(out, "w");
const header = Buffer.alloc(24);
header.writeUInt32LE(0xa1b2c3d4, 0);
header.writeUInt16LE(2, 4);
header.writeUInt16LE(4, 6);
header.writeUInt32LE(65535, 16);
header.writeUInt32LE(1, 20); // Ethernet
writeSync(fd, header);

const PROTOCOLS = [6, 6, 6, 17, 17, 1]; // mostly TCP and UDP, some ICMP
let sec = 1_700_000_000;
let usec = 0;
const CHUNK = 20_000;

for (let start = 0; start < count; start += CHUNK) {
  const n = Math.min(CHUNK, count - start);
  const parts: Buffer[] = [];
  for (let k = 0; k < n; k++) {
    const i = start + k;
    const payloadLen = Math.floor(rand() * 121);
    const len = 14 + 20 + payloadLen;
    const pkt = Buffer.alloc(16 + len);
    usec += 50 + Math.floor(rand() * 5000);
    sec += Math.floor(usec / 1_000_000);
    usec %= 1_000_000;
    pkt.writeUInt32LE(sec, 0);
    pkt.writeUInt32LE(usec, 4);
    pkt.writeUInt32LE(len, 8);
    pkt.writeUInt32LE(len, 12);
    // Ethernet
    pkt.set([0xaa, 0xbb, 0xcc, 0, 0, 1 + (i % 250), 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00], 16);
    // IPv4
    pkt[30] = 0x45;
    pkt.writeUInt16BE(20 + payloadLen, 32);
    pkt[38] = 64;
    pkt[39] = PROTOCOLS[i % PROTOCOLS.length];
    pkt.set([10, 0, (i >> 8) & 0xff, 1 + (i % 250), 10, 0, 1, 1 + (i % 9)], 42);
    for (let b = 0; b < payloadLen; b++) pkt[50 + b] = Math.floor(rand() * 256);
    parts.push(pkt);
  }
  writeSync(fd, Buffer.concat(parts));
}
closeSync(fd);
console.log(`Wrote ${count.toLocaleString()} packets to ${out}`);
