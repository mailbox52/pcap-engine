/**
 * Worker-side logic, kept free of worker globals so it can be run and
 * tested from Node (see scripts/verify-engine.ts).
 */
import type { PcapIndex } from "../pkg/pcap_engine";
import { BATCH_SIZE, MAX_FILE_BYTES, type CaptureSummary, type Emit, type LinkPreview } from "./messages";

/** The slice of the wasm-bindgen module the worker logic needs. */
export interface Engine {
  parse_pcap_bytes(data: Uint8Array): PcapIndex;
  link_preview(packet: Uint8Array, linktype: number): unknown;
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Read `file`, parse it in Wasm, and emit the packet columns in batches.
 * Returns the index (kept alive for later `dissectPacket` calls), or null
 * after emitting an `error` message.
 */
export async function parseFile(engine: Engine, file: File, emit: Emit): Promise<PcapIndex | null> {
  const t0 = performance.now();

  if (file.size > MAX_FILE_BYTES) {
    const mb = Math.round(MAX_FILE_BYTES / (1024 * 1024));
    emit({ type: "error", message: `File is too large. The limit is ${mb} MB.` });
    return null;
  }

  let index: PcapIndex;
  try {
    emit({ type: "status", stage: "reading" });
    const buffer = await file.arrayBuffer();
    emit({ type: "status", stage: "parsing" });
    // The bytes are copied into Wasm memory here; `buffer` is dropped when
    // this block ends, so only the packet index stays resident.
    index = engine.parse_pcap_bytes(new Uint8Array(buffer));
  } catch (e) {
    emit({ type: "error", message: errorMessage(e) });
    return null;
  }

  const total = index.count();
  const format = index.format();
  emit({ type: "started", format, total });
  emit({ type: "status", stage: "sending" });

  for (let start = 0; start < total; start += BATCH_SIZE) {
    const end = Math.min(start + BATCH_SIZE, total);
    // Each call returns a fresh typed array, so its buffer can be transferred.
    const tsSec = index.ts_sec(start, end);
    const tsNsec = index.ts_nsec(start, end);
    const origLen = index.orig_len(start, end);
    const capLen = index.cap_len(start, end);
    const offset = index.offset(start, end);
    const linktype = index.linktype(start, end);
    const proto = index.proto(start, end);
    const ipVer = index.ip_version(start, end);
    const srcPort = index.src_port(start, end);
    const dstPort = index.dst_port(start, end);
    const detail = index.detail(start, end);
    const addr = index.addr(start, end);
    emit(
      { type: "batch", start, tsSec, tsNsec, origLen, capLen, offset, linktype, proto, ipVer, srcPort, dstPort, detail, addr },
      [
        tsSec, tsNsec, origLen, capLen, offset, linktype, proto, ipVer, srcPort, dstPort, detail, addr,
      ].map((a) => a.buffer) as Transferable[],
    );
  }

  try {
    emit({ type: "summary", summary: index.summary() as CaptureSummary });
  } catch {
    // The list still works without the summary panel, so do not fail the load.
  }

  emit({
    type: "done",
    total,
    format,
    complete: index.complete(),
    issues: index.issues(),
    elapsedMs: Math.round(performance.now() - t0),
  });
  return index;
}

/** Look up one packet's bytes in the file and emit its link-layer preview. */
export async function dissectPacket(
  engine: Engine,
  file: File,
  index: PcapIndex,
  packetIndex: number,
  emit: Emit,
): Promise<void> {
  try {
    if (!Number.isInteger(packetIndex) || packetIndex < 0 || packetIndex >= index.count()) {
      throw new Error(`No packet at index ${packetIndex}`);
    }
    const offset = index.offset(packetIndex, packetIndex + 1)[0];
    const capLen = index.cap_len(packetIndex, packetIndex + 1)[0];
    const linktype = index.linktype(packetIndex, packetIndex + 1)[0];
    // Only this packet's bytes are read from the file.
    const bytes = new Uint8Array(await file.slice(offset, offset + capLen).arrayBuffer());
    const preview = engine.link_preview(bytes, linktype) as LinkPreview;
    emit({ type: "packet", index: packetIndex, preview });
  } catch (e) {
    emit({ type: "error", message: errorMessage(e), scope: "dissect" });
  }
}
