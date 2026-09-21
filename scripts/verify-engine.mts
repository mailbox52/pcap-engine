/**
 * Runs the real compiled Wasm (src/pkg) through the same parse/dissect code
 * the worker uses, in Node. Fast way to check that a freshly built src/pkg
 * still behaves. Usage: npm run verify
 */
import { readFileSync } from "node:fs";
import { initSync, link_preview, parse_pcap_bytes } from "../src/pkg/pcap_engine.js";
import { BATCH_SIZE, MAX_FILE_BYTES, type WorkerOut } from "../src/lib/messages";
import { dissectPacket, parseFile, runFilter } from "../src/lib/parse-file";
import { PacketStore } from "../src/lib/packet-store";
import { etherTypeName, formatBytes, formatDuration, hexLines, ipProtocolName, isoTimestamp, linkTypeName } from "../src/lib/format";
import { addressText, formatIPv6, infoText, protocolName, tcpFlagNames } from "../src/lib/summary";

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

const eth_ipv4_bytes = () => new Uint8Array(ethIpv4(0));
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
  check(
    "pcap: protocol columns (TCP over IPv4, addresses, ports from the fixture bytes)",
    first?.type === "batch" && first.proto[0] === 1 && first.ipVer[0] === 4 &&
      first.srcPort[0] === 0x7061 && first.dstPort[0] === 0x636b && first.detail[0] === 0 &&
      first.addr.slice(0, 4).join(".") === "10.0.0.1" && first.addr.slice(16, 20).join(".") === "10.0.0.2",
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

// ---- 5. main-thread store and formatting helpers ----
{
  const N = BATCH_SIZE * 2 + 500;
  const { msgs, index } = await run(toFile(pcapFile(N), "store.pcap"));
  const store = new PacketStore();
  for (const m of msgs) {
    if (m.type === "started") store.reset(m.total);
    else if (m.type === "batch") store.add(m);
  }
  check("store: holds every packet from all batches", store.count === N && store.total === N);
  check(
    "store: random access matches the source data",
    store.tsSec[0] === 1_700_000_000 && store.tsSec[N - 1] === 1_700_000_000 + N - 1 &&
      store.tsSec[BATCH_SIZE] === 1_700_000_000 + BATCH_SIZE && store.linktype[N - 1] === 1,
  );
  check("store: relative time is exact", store.relativeSeconds(0) === 0 && store.relativeSeconds(10) === 10);
  check("store: ISO timestamp with nanoseconds", store.isoTime(0) === "2023-11-14T22:13:20.500000000Z", store.isoTime(0));
  store.add({ type: "batch", start: N, tsSec: new Uint32Array(5), tsNsec: new Uint32Array(5), origLen: new Uint32Array(5), capLen: new Uint32Array(5), offset: new Uint32Array(5), linktype: new Uint16Array(5), proto: new Uint8Array(5), ipVer: new Uint8Array(5), srcPort: new Uint16Array(5), dstPort: new Uint16Array(5), detail: new Uint16Array(5), addr: new Uint8Array(160) });
  check("store: ignores batches outside the announced total", store.count === N);
  index?.free();

  check("format: link and protocol names", linkTypeName(1) === "Ethernet" && linkTypeName(999) === "Type 999" && ipProtocolName(6) === "6 (TCP)" && etherTypeName(0x0800) === "0x0800 (IPv4)");
  const lines = hexLines("48656c6c6f2c20776f726c6421000102" + "ff");
  check(
    "format: hex dump lines",
    lines.length === 2 && lines[0].offset === "0000" && lines[0].ascii === "Hello, world!..." && lines[1].offset === "0010" && lines[1].bytes === "ff" && lines[1].ascii === ".",
  );
}

// ---- 6. size cap ----
{
  // A stand-in with a huge size: the cap check must fire before the file is read.
  const huge = { size: MAX_FILE_BYTES + 1, arrayBuffer: () => { throw new Error("should not be read"); } } as unknown as File;
  const { msgs, index } = await run(huge);
  check("size cap: oversized file rejected before reading", index === null && msgs.length === 1 && msgs[0].type === "error" && /too large/i.test(msgs[0].message));
}

// ---- 7. optional fields from Rust arrive as undefined, not null ----
{
  const pkt = eth_ipv4_bytes();
  const p = link_preview(pkt, 1) as Record<string, unknown>;
  check(
    "link_preview: missing optional fields are undefined (UI must use != null)",
    p.vlan_id === undefined && p.ethertype === 0x0800 && typeof p.dst_mac === "string",
  );
}

// ---- 8. protocol capture through Wasm, store, and summary text ----
{
  const u16be = (v: number) => Buffer.from([v >> 8, v & 0xff]);
  const eth = (type: number, payload: Buffer) =>
    Buffer.concat([Buffer.from([0xaa, 0xbb, 0xcc, 0, 0, 1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]), u16be(type), payload]);
  const ip4 = (proto: number, src: number[], dst: number[], l4: Buffer) =>
    Buffer.concat([Buffer.from([0x45, 0]), u16be(20 + l4.length), Buffer.from([0, 0, 0, 0, 64, proto, 0, 0, ...src, ...dst]), l4]);
  const tcp = (sp: number, dp: number, flags: number) =>
    Buffer.concat([u16be(sp), u16be(dp), Buffer.alloc(8), Buffer.from([0x50, flags]), Buffer.alloc(6)]);
  const udp = (sp: number, dp: number) => Buffer.concat([u16be(sp), u16be(dp), Buffer.from([0, 8, 0, 0])]);
  const v6a = (last: number) => [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last];
  const ip6 = (next: number, src: number[], dst: number[], rest: Buffer) =>
    Buffer.concat([Buffer.from([0x60, 0, 0, 0]), u16be(rest.length), Buffer.from([next, 64, ...src, ...dst]), rest]);
  const arp = Buffer.concat([Buffer.from([0, 1, 8, 0, 6, 4, 0, 1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 10, 0, 0, 1]), Buffer.alloc(6), Buffer.from([10, 0, 0, 9])]);

  const packets = [
    eth(0x0800, ip4(6, [10, 0, 0, 1], [10, 0, 0, 2], tcp(443, 51234, 0x12))),
    eth(0x0800, ip4(17, [10, 0, 0, 2], [10, 0, 0, 3], udp(40000, 53))),
    eth(0x0800, ip4(1, [10, 0, 0, 3], [10, 0, 0, 4], Buffer.from([8, 0, 0, 0, 0, 1, 0, 1]))),
    eth(0x0806, arp),
    eth(0x86dd, ip6(6, v6a(1), v6a(2), tcp(22, 60000, 0x02))),
    eth(0x88cc, Buffer.alloc(30)),
  ];
  const parts: Buffer[] = [u32(0xa1b2c3d4), u16(2), u16(4), u32(0), u32(0), u32(65535), u32(1)];
  packets.forEach((d, i) => parts.push(u32(100 + i), u32(0), u32(d.length), u32(d.length), d));

  const { msgs, index } = await run(toFile(Buffer.concat(parts), "protocols.pcap"));
  const store = new PacketStore();
  for (const m of msgs) {
    if (m.type === "started") store.reset(m.total);
    else if (m.type === "batch") store.add(m);
  }
  const names = [0, 1, 2, 3, 4, 5].map((i) => protocolName(store.proto[i]));
  check("protocols: names", names.join(",") === "TCP,DNS,ICMP,ARP,TCP,Other", names.join(","));
  check("protocols: IPv4 addresses", addressText(store, 0, "src") === "10.0.0.1" && addressText(store, 0, "dst") === "10.0.0.2");
  check("protocols: IPv6 addresses", addressText(store, 4, "src") === "2001:db8::1" && addressText(store, 4, "dst") === "2001:db8::2");
  check("protocols: no addresses for non-IP", addressText(store, 5, "src") === "");
  check("info: TCP with flags", infoText(store, 0) === "443 → 51234 [SYN, ACK]", infoText(store, 0));
  check("info: DNS", infoText(store, 1) === "40000 → 53", infoText(store, 1));
  check("info: ICMP echo request", infoText(store, 2) === "Echo request", infoText(store, 2));
  check("info: ARP request", infoText(store, 3) === "Who has 10.0.0.9? Tell 10.0.0.1", infoText(store, 3));
  check("info: IPv6 TCP", infoText(store, 4) === "22 → 60000 [SYN]", infoText(store, 4));
  check("info: unknown EtherType", infoText(store, 5) === "EtherType 0x88cc (LLDP)", infoText(store, 5));

  const smIdx = msgs.findIndex((m) => m.type === "summary");
  const sm = smIdx >= 0 ? msgs[smIdx] : undefined;
  const summary = sm?.type === "summary" ? sm.summary : undefined;
  check("summary: sent once, before done", smIdx >= 0 && smIdx < msgs.findIndex((m) => m.type === "done"));
  check(
    "summary: totals and duration",
    summary?.totalPackets === 6 && summary.totalBytes === 298 && summary.capturedBytes === 298 &&
      summary.firstSec === 100 && summary.lastSec === 105 && summary.durationSecs === 5,
    JSON.stringify(summary && { p: summary.totalPackets, b: summary.totalBytes, d: summary.durationSecs }),
  );
  check(
    "summary: protocol breakdown (TCP 2 first)",
    summary?.protocols[0]?.proto === 1 && summary.protocols[0].packets === 2 && summary.protocols[0].bytes === 128 && summary.protocols.length === 5,
  );
  const t = summary?.topTalkers ?? [];
  check(
    "summary: top talkers ranked by bytes (both directions counted)",
    t.length === 7 && t[0].ipVersion === 4 && t[0].addr.slice(0, 4).join(".") === "10.0.0.1" && t[0].bytes === 96 && t[0].packets === 2,
  );
  check(
    "summary: IPv6 talker",
    t[3]?.ipVersion === 6 && formatIPv6(Uint8Array.from(t[3].addr), 0) === "2001:db8::1" && t[3].bytes === 74,
  );
  index?.free();
}

// ---- 9. text helpers that need no Wasm ----
{
  const v6 = (...g: number[]) => Uint8Array.from(g.flatMap((x) => [x >> 8, x & 0xff]));
  check("ipv6: zero run compressed", formatIPv6(v6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 0) === "2001:db8::1");
  check("ipv6: all zeros", formatIPv6(v6(0, 0, 0, 0, 0, 0, 0, 0), 0) === "::");
  check("ipv6: loopback", formatIPv6(v6(0, 0, 0, 0, 0, 0, 0, 1), 0) === "::1");
  check("ipv6: single zero group not compressed", formatIPv6(v6(1, 0, 2, 3, 4, 5, 6, 7), 0) === "1:0:2:3:4:5:6:7");
  check("ipv6: longest run wins", formatIPv6(v6(1, 0, 0, 2, 0, 0, 0, 3), 0) === "1:0:0:2::3");
  check("ipv6: trailing zeros", formatIPv6(v6(0xfe80, 0, 0, 0, 0, 0, 0, 0), 0) === "fe80::");
  check("bytes: formatting", formatBytes(0) === "0 B" && formatBytes(298) === "298 B" && formatBytes(1024) === "1.00 KB" && formatBytes(1536) === "1.50 KB" && formatBytes(109_986_168) === "105 MB" && formatBytes(1_048_576) === "1.00 MB");
  check("duration: formatting", formatDuration(0) === "0 s" && formatDuration(0.25) === "250 ms" && formatDuration(12.3456) === "12.35 s" && formatDuration(2547.314) === "42 min 27 s" && formatDuration(3725) === "1 h 02 min");
  check("iso timestamp", isoTimestamp(1_700_000_000, 5) === "2023-11-14T22:13:20.000000005Z");
  check("tcp flags: names in order", tcpFlagNames(0x12).join(",") === "SYN,ACK" && tcpFlagNames(0x01).join(",") === "FIN" && tcpFlagNames(0).length === 0);
}

// ---- 10. display filters (real Wasm parser + filter language) ----
{
  const u16be = (v: number) => Buffer.from([v >> 8, v & 0xff]);
  const eth = (type: number, payload: Buffer) =>
    Buffer.concat([Buffer.from([0xaa, 0xbb, 0xcc, 0, 0, 1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]), u16be(type), payload]);
  const ip4 = (proto: number, src: number[], dst: number[], l4: Buffer) =>
    Buffer.concat([Buffer.from([0x45, 0]), u16be(20 + l4.length), Buffer.from([0, 0, 0, 0, 64, proto, 0, 0, ...src, ...dst]), l4]);
  const tcp = (sp: number, dp: number, flags: number) =>
    Buffer.concat([u16be(sp), u16be(dp), Buffer.alloc(8), Buffer.from([0x50, flags]), Buffer.alloc(6)]);
  const udp = (sp: number, dp: number) => Buffer.concat([u16be(sp), u16be(dp), Buffer.from([0, 8, 0, 0])]);

  const packets = [
    eth(0x0800, ip4(6, [10, 0, 0, 1], [10, 0, 0, 2], tcp(443, 51234, 0x12))), // 0: TCP SYN,ACK
    eth(0x0800, ip4(17, [10, 0, 0, 2], [10, 0, 0, 3], udp(40000, 53))), // 1: DNS
    eth(0x0800, ip4(1, [10, 0, 0, 3], [10, 0, 0, 4], Buffer.from([8, 0, 0, 0, 0, 1, 0, 1]))), // 2: ICMP
    eth(0x0800, ip4(6, [10, 0, 0, 5], [10, 0, 0, 6], tcp(51235, 80, 0x02))), // 3: TCP SYN
  ];
  const parts: Buffer[] = [u32(0xa1b2c3d4), u16(2), u16(4), u32(0), u32(0), u32(65535), u32(1)];
  packets.forEach((d, i) => parts.push(u32(100 + i), u32(0), u32(d.length), u32(d.length), d));

  const { msgs, index } = await run(toFile(Buffer.concat(parts), "filter.pcap"));
  if (index) {
    const out: WorkerOut[] = [];
    runFilter(index, "tcp and port 443", 42, (m) => out.push(m));
    const matched = out.find((m) => m.type === "filtered");
    check(
      "filter: tcp and port 443 (real Wasm)",
      matched?.type === "filtered" && matched.requestId === 42 && Array.from(matched.indexes).join(",") === "0",
      matched?.type === "filtered" ? Array.from(matched.indexes).join(",") : JSON.stringify(matched),
    );

    const out2: WorkerOut[] = [];
    runFilter(index, "", 43, (m) => out2.push(m));
    const all = out2.find((m) => m.type === "filtered");
    check("filter: empty query matches everything", all?.type === "filtered" && all.indexes.length === 4);

    const out3: WorkerOut[] = [];
    runFilter(index, "syn and not ack", 44, (m) => out3.push(m));
    const syn = out3.find((m) => m.type === "filtered");
    check(
      "filter: syn and not ack",
      syn?.type === "filtered" && Array.from(syn.indexes).join(",") === "3",
      syn?.type === "filtered" ? Array.from(syn.indexes).join(",") : JSON.stringify(syn),
    );

    const badOut: WorkerOut[] = [];
    runFilter(index, "bogus_term", 45, (m) => badOut.push(m));
    const bad = badOut.find((m) => m.type === "error");
    check(
      "filter: unknown term reports a plain message and a position",
      bad?.type === "error" && bad.scope === "filter" && bad.requestId === 45 && bad.message.includes("bogus_term") &&
        typeof bad.position === "number" && !bad.message.includes("at character"),
      JSON.stringify(bad),
    );

    // .0-.3 covers pkt0 (.1/.2), pkt1 (.2/.3), pkt2's source .3 (dst .4 is outside);
    // pkt3 (.5/.6) is entirely outside the range.
    const cidrOut: WorkerOut[] = [];
    runFilter(index, "10.0.0.0/30", 46, (m) => cidrOut.push(m));
    const cidr = cidrOut.find((m) => m.type === "filtered");
    check(
      "filter: CIDR range",
      cidr?.type === "filtered" && Array.from(cidr.indexes).join(",") === "0,1,2",
      cidr?.type === "filtered" ? Array.from(cidr.indexes).join(",") : JSON.stringify(cidr),
    );

    index.free();
  } else {
    check("filter: index available", false, "parse failed");
  }
}

console.log(failures === 0 ? "\nAll checks passed." : `\n${failures} check(s) FAILED.`);
process.exitCode = failures === 0 ? 0 : 1;
