# pcap-engine: Spec & Guidelines

## Goal
A client-side `.pcap` / `.pcapng` viewer. Rust compiled to Wasm parses the file inside a Web Worker; a Next.js (App Router) UI shows a virtualized packet list. Nothing is uploaded anywhere.

## Hard Rules
1. **No server processing.** No `/api` routes that accept files or binary data.
2. **No parsing on the main thread.** All file reading and Wasm calls live in `src/workers/pcap.worker.ts`.
3. **Main thread never copies the file.** Pass the `File` object to the worker (structured clone of a `File` is a cheap handle); the worker reads it.
4. **Commit `src/pkg/`.** Vercel does not have Rust. Build Wasm locally, commit the output, and Vercel only runs `next build`.

## Stack
- Next.js (App Router), React, TypeScript, Tailwind
- Rust `cdylib` crate: `wasm-bindgen`, `pcap-parser`
- Build: `wasm-pack build --target web` (or `cargo build` + `wasm-bindgen`)
- List UI: `@tanstack/react-virtual`
- Bundler: Webpack. If the Next version defaults to Turbopack, use `next dev --webpack` and `next build --webpack`.

## Layout
```
pcap-engine/
├── pcap-engine/          # Rust crate (Cargo.toml, src/lib.rs, tests/fixtures/)
├── src/
│   ├── pkg/              # Wasm output (committed)
│   ├── workers/pcap.worker.ts
│   ├── components/PcapUploader.tsx
│   └── app/
├── next.config.mjs       # webpack: experiments.asyncWebAssembly = true
└── CLAUDE.md
```

## Status
- **Phase 1 crate exists** in `pcap-engine/`. Parsing (`src/core.rs`) and link-layer previews (`src/link.rs`) are plain Rust with 32 passing native tests. `src/lib.rs` is the thin wasm-bindgen layer and has only been compiled natively, never for `wasm32-unknown-unknown`.
- **Wasm API:** `parse_pcap_bytes(&[u8]) -> PcapIndex` (columns via `ts_sec/ts_nsec/orig_len/cap_len/offset/linktype(start, end)`, plus `count/format/complete/issues`), and `link_preview(packet_bytes, linktype)` returning a `LinkPreview` object.
- **The file stays in JS.** The index stores each packet's byte `offset`; for a detail view the worker passes only that packet's slice to `link_preview`. Wasm never retains the file.
- **Legacy big-endian pcap** needed custom handling: `pcap-parser`'s `LegacyPcapSlice` iterator decodes only little-endian records. `core.rs` calls `parse_pcap_frame_be` itself. Keep the big-endian tests.
- **Phase 1 is done.** The GitHub Actions workflow (`.github/workflows/wasm.yml`) runs the tests, clippy, and `wasm-pack build` on every change under `pcap-engine/`, and commits the result to `src/pkg`. The developer machine has no Rust toolchain, so Wasm rebuilds happen in CI: push, wait for the run, then `git pull`.
- **Phase 2 is written.** Next.js 15 (webpack), Tailwind 4. `src/lib/parse-file.ts` holds the worker logic (read file, parse, batch, dissect) with no worker globals; `src/workers/pcap.worker.ts` is a thin shell around it. `src/lib/messages.ts` is the message contract. `src/components/PcapUploader.tsx` is the picker, live packet counter, and a table of the first 20 packets.
- **Checked so far:** `npm run typecheck`; `npm run build` (the worker chunk and `pcap_engine_bg.wasm` are emitted, and served as `application/wasm`); and `npm run verify`, which runs the real compiled `src/pkg` Wasm through the same parse/dissect code in Node (batching, pcap and pcapng, truncated and garbage input, single-packet dissect). **Not yet checked:** running in a real browser.
- **Next:** open the app in a browser and load a real capture; then Phase 3 (virtualized list with `@tanstack/react-virtual`, click a row to `dissect`).

## Design Decisions (v1)
- **Whole-file parse, size-capped.** The worker reads the file into memory, copies it into Wasm, and parses. Cap at **256 MB** with a clear error above that. Streaming / chunked parsing is a v2 feature.
- **Columnar output, not objects.** Rust returns packet summaries as typed arrays (timestamps, orig len, cap len, byte offset, protocol id), not thousands of JS objects.
- **Batched.** The worker posts results every ~10k packets so the counter updates live.
- **Lazy detail.** Full dissection of a packet happens only when the user selects a row (`dissect_packet(offset)` returns one `ParsedPacket`).
- **Init once.** Call `init()` for the Wasm module once per worker and cache the promise.

## Worker Message Contract
```ts
type WorkerIn =
  | { type: 'parse'; file: File }
  | { type: 'dissect'; index: number };   // worker slices that packet from the File it kept

type WorkerOut =
  | { type: 'batch'; tsSec: Uint32Array; tsNsec: Uint32Array; origLen: Uint32Array;
      capLen: Uint32Array; offset: Uint32Array; linktype: Uint16Array }  // transferred, not cloned
  | { type: 'done'; total: number }
  | { type: 'packet'; index: number; preview: LinkPreview }  // shape: pcap-engine/src/link.rs
  | { type: 'error'; message: string };
```

## Parser Requirements
- Formats: pcap (micro and nano magic, both endiannesses) and pcapng.
- pcapng: track multiple interfaces and each interface's timestamp resolution (`if_tsresol`).
- Per packet: timestamp (sec + nsec), original vs. captured length, link-layer preview (Ethernet MAC header, RadioTap, or first IPv4 bytes).
- Truncated or malformed files return the packets parsed so far plus an error. They never panic.

## Phases & Definition of Done

### Phase 1: Engine (Rust crate written; see Status)
- [x] `cargo test` passes on fixtures: pcap micro/nano, big/little endian, pcapng (multi-interface, per-interface timestamp resolution, big-endian, multiple sections), truncated at every byte, corrupted bytes, empty, garbage.
- [ ] `cargo clippy --target wasm32-unknown-unknown -- -D warnings` is clean. (Not yet run: `cargo build` is warning-free under `RUSTFLAGS="-D warnings"`, but clippy was unavailable when the crate was written.)
- [ ] `wasm-pack build --target web --out-dir ../src/pkg` succeeds. (Not yet run; needs a machine with the wasm32 target.)

### Phase 2: Worker Bridge (written; see Status)
- [x] `next.config.mjs` enables `asyncWebAssembly`.
- [x] Worker created with `new Worker(new URL('../workers/pcap.worker.ts', import.meta.url))` in a `"use client"` component.
- [x] Worker sends `batch` messages with transferred typed arrays, then `done`.
- [x] Bad input produces an `error` message, not a hung UI.
- [ ] Confirmed working in a real browser with a real capture file (not yet done).

### Phase 3: UI
- [ ] Choosing a file (drag-drop or picker) updates a live packet counter.
- [ ] List is virtualized; scrolling a 1M-packet capture shows no long frames in the Chrome Performance panel.
- [ ] Selecting a row shows dissected detail.
- [ ] Files over the cap show a clear error.

### Phase 4: Make It Useful (v1.5)
Build after Phases 1-3 work end to end. Each item is independent, so ship them in this order.

**4a. Readable rows (protocol, addresses, ports)**
- [ ] Rust parses Ethernet, IPv4/IPv6, TCP, UDP, ICMP, and ARP headers.
- [ ] Each list row shows time, source, destination, protocol label, length, and a short info string (e.g. `443 → 51234 [SYN, ACK]`).
- [ ] Batch output gains columns: `src`, `dst` (IP as u32 pair, or 16-byte slots for IPv6), `srcPort`, `dstPort`, `proto`. Still typed arrays, no per-packet objects.
- [ ] Unknown or unsupported protocols show as "Other" and never break parsing.

**4b. Summary panel**
- [ ] After loading: total packets, total bytes, capture duration, average packet size.
- [ ] Protocol breakdown (count and percent).
- [ ] Top talkers: top 10 IPs by bytes.
- [ ] Computed in Rust in one pass and returned as a single `summary` message.

**4c. Search and filters**
- [ ] A search box accepting simple terms: a protocol (`tcp`), an IP (`192.168.1.5`), or a port (`port 443`). Combine with `and`.
- [ ] Filtering runs in the worker over the columnar arrays and returns a list of matching row indexes. The UI never scans all packets.
- [ ] The counter shows "N of M packets" while filtered.
- [ ] Invalid filter text shows an inline hint, not an error state.

**4d. Sample capture**
- [ ] A "Try a sample" button loads a small bundled `.pcap` (under 200 KB, in `public/`), fetched as a static file and fed through the same worker path as a user upload.
- [ ] The sample includes a mix of TCP, UDP, DNS, and ARP so every feature has something to show.

**4e. Privacy note**
- [ ] A visible line on the page: "Your file never leaves this browser." It must stay true, which is why the no-server rule exists.

Additional worker messages for Phase 4:
```ts
type WorkerIn =
  | { type: 'filter'; query: string };            // added

type WorkerOut =
  | { type: 'summary'; totalPackets: number; totalBytes: number; durationSec: number;
      protocols: { name: string; count: number }[];
      topTalkers: { ip: string; bytes: number }[] }
  | { type: 'filtered'; indexes: Uint32Array }    // transferred
  | { type: 'filterError'; message: string };
```

## Commands
```bash
# Build Wasm (run locally, commit src/pkg)
npm run wasm        # cd pcap-engine && wasm-pack build --target web --out-dir ../src/pkg

npm run dev         # Next dev server (webpack)
npm run build       # Production build (uses committed src/pkg)
npm run typecheck   # tsc --noEmit
npm run verify      # Runs the compiled src/pkg Wasm through the worker logic in Node
cargo test          # from pcap-engine/ (needs Rust; CI runs it otherwise)
```
Do not add `wasm` to `prebuild` or `predev` for Vercel; run it manually when the Rust changes.

## Out of Scope (v1)
Streaming/chunked parsing, deep application-layer decoding (HTTP, TLS, etc.), TCP stream reassembly, conversation grouping, hex/ASCII view, traffic timeline chart, CSV export, any backend. These are candidates for a later phase.
