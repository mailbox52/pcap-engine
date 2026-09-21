/// Background thread: loads the Wasm engine and does all file reading and
/// parsing, so the React UI thread never blocks.
import init, { link_preview, parse_pcap_bytes, type PcapIndex } from "../pkg/pcap_engine";
import type { WorkerIn, WorkerOut } from "../lib/messages";
import { dissectPacket, parseFile, runFilter } from "../lib/parse-file";

// Minimal typing for the worker global. Avoids pulling the "webworker" lib
// into the same tsconfig as the DOM lib.
interface WorkerScope {
  postMessage(message: unknown, transfer?: Transferable[]): void;
  onmessage: ((event: MessageEvent<WorkerIn>) => void) | null;
}
const ctx = self as unknown as WorkerScope;

const emit = (msg: WorkerOut, transfer: Transferable[] = []) => ctx.postMessage(msg, transfer);

// Initialise Wasm once per worker and cache the promise.
let ready: Promise<unknown> | null = null;
function ensureReady(): Promise<unknown> {
  ready ??= init({ module_or_path: new URL("../pkg/pcap_engine_bg.wasm", import.meta.url) }).catch((e) => {
    ready = null; // allow a retry on the next message
    throw e;
  });
  return ready;
}

const engine = { parse_pcap_bytes, link_preview };
let current: { file: File; index: PcapIndex } | null = null;

ctx.onmessage = async (event: MessageEvent<WorkerIn>) => {
  const msg = event.data;
  try {
    await ensureReady();
  } catch (e) {
    emit({ type: "error", message: `Could not load the Wasm engine: ${e instanceof Error ? e.message : String(e)}` });
    return;
  }

  if (msg.type === "parse") {
    current?.index.free();
    current = null;
    const index = await parseFile(engine, msg.file, emit);
    if (index) current = { file: msg.file, index };
  } else if (msg.type === "dissect") {
    if (!current) {
      emit({ type: "error", message: "No capture is loaded.", scope: "dissect" });
      return;
    }
    await dissectPacket(engine, current.file, current.index, msg.index, emit);
  } else if (msg.type === "filter") {
    if (!current) {
      emit({ type: "error", message: "No capture is loaded.", scope: "filter", requestId: msg.requestId });
      return;
    }
    runFilter(current.index, msg.query, msg.requestId, emit);
  }
};
