/**
 * Runs the real compiled Wasm (src/pkg) through the same parse/dissect code
 * the worker uses, in Node. Fast way to check that a freshly built src/pkg
 * still behaves. Usage: npm run verify
 */
import { readFileSync } from "node:fs";
import { initSync, link_preview, parse_pcap_bytes } from "../src/pkg/pcap_engine.js";
import { BATCH_SIZE, type WorkerOut } from "../src/lib/messages";
import { dissectPacket, parseFile } from "../src/lib/parse-file";

initSync({ module: readFileSync(new URL("../src/pkg/pcap_engine_bg.wasm", import.meta.url)) });
const engine = { parse_pcap_bytes, link_preview };

let failures = 0;
function check(name: string, ok: boolean, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  " + detail : ""}`);
  if (!ok) failures++;
}

// ---- fixture builders (little-endian) ----
const u16 = (v: number) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };
const u32 = (v: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b; };

function ethIpv4(seq: number): Buffer {
  const payload = Buffer.from(`packet-${seq}`);
  const total = 20 + payload.length;
  return Buffer.concat([
    Buffer.from([0xaa, 0xbb, 0xcc, 0, 0, 1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00]),
    Buffer.from([0x45, 0, total >> 8, total & 0xff, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]),
    payload,
  ]);
}

function pcapFile(count: number): Buffer {
  const parts: Buffer[] = [
    u32(0xa1b2c3d4), u16(2), u16(4), u32(0), u32(0), u32(65535), u32(1),
  ];
  for (let i = 0; i < count; i++) {
    const d = ethIpv4(i);
    parts.push(u32(1_700_000_000 + i), u32(500_000), u32(d.length), u32(d.length), d);
  }
  return Buffer.concat(parts);
}

function pcapngBlock(type: number, body: Buffer): Buffer {
  const pad = (4 - (body.length % 4)) % 4;
  const total = body.length + pad + 12;
  return Buffer.concat([u32(type), u32(total), body, Buffer.alloc(pad), u32(total)]);
}

function pcapngFile(count: number): Buffer {
  const shb = pcapngBlock(0x0a0d0d0a, Buffer.concat([u32(0x1a2b3c4d), u16(1), u16(0), Buffer.alloc(8, 0xff)]));
  // Ethernet interface with nanosecond resolution (if_tsresol = 9)
  const opts = Buffer.concat([u16(9), u16(1), Buffer.from([9, 0, 0, 0]), u16(0), u16(0)]);
  const idb = pcapngBlock(1, Buffer.concat([u16(1), u16(0), u32(65535), opts]));
  const blocks = [shb, idb];
  for (let i = 0; i < count; i++) {
    const d = ethIpv4(i);
    const ticks = BigInt(1_700_000_000 + i) * 1_000_000_000n + 123n;
    blocks.push(pcapngBlock(6, Buffer.concat([
      u32(0), u32(Number(ticks >> 32n)), u32(Number(ticks & 0xffffffffn)), u32(d.length), u32(d.length), d,
    ])));
  }
  return Buffer.concat(blocks);
}

const toFile = (b: Buffer, name: string) => new File([new Uint8Array(b)], name);

async function run(file: File) {
  const msgs: WorkerOut[] = [];
  const emit = (m: WorkerOut) => { msgs.push(m); };
  const index = await parseFile(engine, file, emit);
  return { msgs, index };
}

// ---- 1. pcap, several batches ----
{
  const N = BATCH_SIZE * 2 + 500;
  const file = toFile(pcapFile(N), "big.pcap");
  const { msgs, index } = await run(file);
  const batches = msgs.filter((m) => m.type === "batch");
  const done = msgs.find((m) => m.type === "done");
  const started = msgs.find((m) => m.type === "started");
  check("pcap: index returned", index !== null);
  check("pcap: started reports total and format", started?.type === "started" && started.total === N && started.format === "pcap");
  check("pcap: 3 batches", batches.length === 3, `(got ${batches.length})`);
  const sum = batches.reduce((n, b) => n + (b.type === "batch" ? b.tsSec.length : 0), 0);
  check("pcap: batches cover every packet", sum === N, `(${sum}/${N})`);
  const last = batches[batches.length - 1];
  check("pcap: last batch start", last?.type === "batch" && last.start === BATCH_SIZE * 2);
  const first = batches[0];
  check(
    "pcap: first packet columns",
    first?.type === "batch" && first.tsSec[0] === 1_700_000_000 && first.tsNsec[0] === 500_000_000 &&
      first.origLen[0] === first.capLen[0] && first.linktype[0] === 1 && first.offset[0] === 24 + 16,
  );
  check("pcap: done is complete", done?.type === "done" && done.complete && done.total === N);

  if (index) {
    const out: WorkerOut[] = [];
    await dissectPacket(engine, file, index, 1234, (m) => { out.push(m); });
    const p = out[0];
    check(
      "pcap: dissect reads only that packet and decodes it",
      p?.type === "packet" && p.preview.kind === "ethernet" &&
        p.preview.ipv4?.src === "10.0.0.1" && p.preview.ipv4?.dst === "10.0.0.2" &&
        p.preview.dst_mac === "aa:bb:cc:00:00:01",
    );
    const bad: WorkerOut[] = [];
    await dissectPacket(engine, file, index, N + 5, (m) => { bad.push(m); });
    check("pcap: dissect out of range gives error, not crash", bad[0]?.type === "error");
    index.free();
  }
}

// ---- 2. pcapng with nanosecond interface ----
{
  const file = toFile(pcapngFile(50), "cap.pcapng");
  const { msgs, index } = await run(file);
  const b = msgs.find((m) => m.type === "batch");
  check(
    "pcapng: format and nanosecond timestamp",
    msgs.some((m) => m.type === "started" && m.format === "pcapng") &&
      b?.type === "batch" && b.tsSec[0] === 1_700_000_000 && b.tsNsec[0] === 123,
  );
  if (index) {
    const out: WorkerOut[] = [];
    await dissectPacket(engine, file, index, 7, (m) => { out.push(m); });
    check("pcapng: dissect", out[0]?.type === "packet" && out[0].preview.ipv4?.ttl === 64);
    index.free();
  }
}

// ---- 3. truncated file keeps earlier packets ----
{
  const full = pcapFile(100);
  const { msgs, index } = await run(toFile(full.subarray(0, full.length - 10), "cut.pcap"));
  const done = msgs.find((m) => m.type === "done");
  check(
    "truncated: partial result flagged",
    done?.type === "done" && done.total === 99 && !done.complete && done.issues.length > 0,
    done?.type === "done" ? `(total ${done.total})` : "",
  );
  index?.free();
}

// ---- 4. bad input produces an error message ----
{
  const { msgs, index } = await run(toFile(Buffer.from("this is not a capture file, just text ...."), "x.txt"));
  check("garbage: error message, no index", index === null && msgs.some((m) => m.type === "error"));
  const empty = await run(toFile(Buffer.alloc(0), "empty.pcap"));
  check("empty: error message", empty.index === null && empty.msgs.some((m) => m.type === "error"));
}

console.log(failures === 0 ? "\nAll checks passed." : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
