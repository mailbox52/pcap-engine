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
- **Phase 2 confirmed in a real browser** with `sample.pcap`, `sample.pcapng`, and a non-capture file (error message shown, page stays usable).
- **Phase 3 is written.** `src/lib/packet-store.ts` keeps the columns on the main thread in preallocated typed arrays (about 22 bytes per packet, filled as batches arrive). `PacketList.tsx` is the virtualized list, `PacketDetail.tsx` the detail panel (timestamp, lengths, MACs, EtherType/VLAN, IPv4 fields, hex dump of the first 32 bytes). Rows are clickable only after loading finishes. Dissect errors carry `scope: "dissect"` so they only affect the detail panel.
- **Checked so far:** typecheck, build, `npm run verify` (now includes the store, formatting helpers, and size cap), the detail panel rendered on the server, and a synthetic 1,000,000-packet, 110 MB capture parsed through the real Wasm in about 250 ms into 100 batches. **Not yet checked:** scrolling that capture in a browser.
- **Known limit:** rows are 24 px, so 1M packets make a 24M px scroll area. Chrome allows about 33M px, Firefox about 17.9M px (roughly 745k rows). Beyond that in Firefox the list needs a windowing workaround.
- **Phase 3 confirmed in a real browser**, including a 1,000,000-packet capture (a browser freeze seen once in dev mode on the developer's laptop did not recur and was put down to the machine; 200k packets was always smooth).
- **Phase 4a is done and confirmed in a browser.** Order of work: push, wait for the GitHub Actions run to rebuild `src/pkg` (it also runs the new Rust tests and clippy on the wasm32 target, which were only run natively when the code was written), `git pull`, then `npm run verify` (now 41 checks; the protocol ones only pass against the rebuilt Wasm) and `npm run dev`. The main-thread store is now about 60 bytes per packet (about 60 MB per million).
- **Phase 4b is done and confirmed in a browser** (screenshot with `sample.pcap`: 3,000 packets, 30.38 s, 685 KB, protocol bars, 10 top talkers).
- **Phase 4c is written:** `pcap-engine/src/filter.rs` is a small display-filter language (protocols, TCP flags, addresses/CIDR, ports, length comparisons, `and`/`or`/`not`/parens — see the module doc comment for the full grammar), exposed as `PcapIndex.filter(query)`. 13 Rust tests, clippy clean, ~10 ms on 1,000,000 packets natively. `FilterBar.tsx` is the query box (debounced, clickable examples, shows match count or the error text); `PacketList.tsx` now takes an optional `indexes` prop so it draws only the filtered rows while keyboard nav (arrows/Home/End/PageUp/Down) still works against the filtered order. A `requestId` on each `filter` message means a reply for a query the user has since edited is dropped rather than shown (handles fast typing). Wired into `PcapUploader.tsx`.
- **Checked so far:** Rust tests + clippy; typecheck; production build; `FilterBar` rendered on the server in four states (placeholder examples, error, pending, disabled); the worker round trip (`runFilter` in `parse-file.ts`) exercised end to end, including the error shape (`{message, position}`, not the `JsError` string other calls use — `PcapIndex.filter` throws a plain object via `js_sys::Reflect`, see `pcap-engine/src/lib.rs`); `npm run verify` extended to 51 checks against a hand-written reference-filter shim standing in for the not-yet-built Wasm method. **Not yet checked:** the real Wasm build (needs the CI run), or anything in a browser.
- **Next:** push, wait for Actions, `git pull`, `npm run verify` (the 5 new filter checks only pass against the rebuilt Wasm) and confirm 4c in a browser; then 4d bundled sample. (4e, the privacy note, is already on the page.)

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
  | { type: 'batch'; start: number; tsSec: Uint32Array; tsNsec: Uint32Array; origLen: Uint32Array;
      capLen: Uint32Array; offset: Uint32Array; linktype: Uint16Array;
      proto: Uint8Array; ipVer: Uint8Array; srcPort: Uint16Array; dstPort: Uint16Array;
      detail: Uint16Array; addr: Uint8Array }  // transferred, not cloned; shape in src/lib/messages.ts
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

### Phase 3: UI (written; needs a browser check on a big capture)
- [x] Choosing a file (drag-drop or picker) updates a live packet counter.
- [x] List is virtualized (`@tanstack/react-virtual`); only visible rows exist in the DOM.
- [ ] Scrolling a 1M-packet capture shows no long frames in the Chrome Performance panel (`npm run make-capture` makes the file; not yet checked in a browser).
- [x] Selecting a row (click, or arrow keys / Page Up/Down / Home / End) shows dissected detail.
- [x] Files over the cap show a clear error (checked in `npm run verify`).

### Phase 4: Make It Useful (v1.5)
Build after Phases 1-3 work end to end. Each item is independent, so ship them in this order.

**4a. Readable rows (protocol, addresses, ports)** (done, confirmed in a browser)
- [x] Rust parses Ethernet (with VLAN), Linux cooked, raw IP and loopback framing, then IPv4/IPv6 (including extension headers), TCP, UDP, ICMP, ICMPv6, ARP, and DNS by port. `pcap-engine/src/dissect.rs`, 14 unit tests plus prefix-truncation fuzzing.
- [x] Each list row shows time, source, destination, protocol label, length, and a short info string (e.g. `443 → 51234 [SYN, ACK]`).
- [x] Batch output gains typed-array columns: `proto`, `ipVer`, `srcPort`, `dstPort`, `detail` (TCP flags / ICMP type+code / ARP op / IP protocol / EtherType), and `addr` (32 bytes per packet: 16-byte source then 16-byte destination; IPv4 uses the first 4 bytes). No per-packet objects.
- [x] Unknown or unsupported protocols show as "Other" and never break parsing.

**4b. Summary panel** (written; needs the CI Wasm build and a browser check)
- [x] After loading: total packets, capture duration, size on the wire (and captured size when the two differ), average packet size, start and end time (UTC).
- [x] Protocol breakdown (count and percent, with bars).
- [x] Top talkers: top 10 addresses by bytes. An address counts every packet it appears in, once per packet, in either direction.
- [x] Computed in Rust in one pass (`pcap-engine/src/summary.rs`, 8 tests; about 120 ms natively for 1M packets) and sent as a single `summary` message just before `done`.
- [x] Seen in a browser (confirmed with `sample.pcap`: 3,000 packets, protocol bars, 10 top talkers).

**4c. Search and filters** (written; needs the CI Wasm build and a browser check)
- [x] A query box, well beyond the original scope: protocol keywords (`tcp` `udp` `dns` `icmp` `icmpv6` `arp` `ipv4` `ipv6` `other`), TCP flags (`syn` `ack` `fin` `rst` `psh` `urg`), addresses and CIDR ranges (`10.0.0.1`, `10.0.0.0/24`, IPv6 too), `host`/`src`/`dst`, `port`/`sport`/`dport`, `len > N` (also `>=` `<` `<=` `=`), and `and`/`or`/`not` with parentheses (also `&&` `||` `!`). Grammar and precedence documented at the top of `pcap-engine/src/filter.rs`.
- [x] Filtering runs in Rust in the worker over the columnar arrays and returns matching packet indexes as a transferred `Uint32Array`; the list only ever draws the rows currently in view. About 10 ms for a 1,000,000-packet capture natively.
- [x] The bar shows "N of M packets" while filtered; typing is debounced (150 ms) and a `requestId` on each `filter` request means a stale reply (from a query the user has since changed) is dropped rather than shown.
- [x] Invalid filter text shows the error message below the box (input border turns red); the list underneath keeps showing its last good result rather than going blank.
- [ ] Seen in a browser.

**4d. Sample capture**
- [ ] A "Try a sample" button loads a small bundled `.pcap` (under 200 KB, in `public/`), fetched as a static file and fed through the same worker path as a user upload.
- [ ] The sample includes a mix of TCP, UDP, DNS, and ARP so every feature has something to show.

**4e. Privacy note**
- [ ] A visible line on the page: "Your file never leaves this browser." It must stay true, which is why the no-server rule exists.

Additional worker messages for Phase 4:
```ts
type WorkerIn =
  | { type: 'filter'; query: string; requestId: number };  // requestId lets a stale reply be dropped

type WorkerOut =
  | { type: 'summary'; summary: CaptureSummary }   // shape in src/lib/messages.ts
  | { type: 'filtered'; requestId: number; indexes: Uint32Array }    // transferred

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
npm run make-capture -- 1000000 big.pcap   # synthetic large capture (about 110 MB) for scroll testing
cargo test          # from pcap-engine/ (needs Rust; CI runs it otherwise)
```
Do not add `wasm` to `prebuild` or `predev` for Vercel; run it manually when the Rust changes.

## Out of Scope (v1)
Streaming/chunked parsing, deep application-layer decoding (HTTP, TLS, etc.), TCP stream reassembly, conversation grouping, hex/ASCII view, traffic timeline chart, CSV export, any backend. These are candidates for a later phase.
