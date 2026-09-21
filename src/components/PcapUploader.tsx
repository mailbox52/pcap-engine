"use client";

import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import type { LinkPreview, Stage, WorkerIn, WorkerOut } from "@/lib/messages";
import { PacketStore } from "@/lib/packet-store";
import PacketDetail from "./PacketDetail";
import PacketList from "./PacketList";

interface State {
  status: "idle" | "working" | "done" | "error";
  fileName: string;
  stage: Stage | null;
  format: string;
  total: number | null;
  /** Packets received from the worker so far; also drives list re-renders. */
  received: number;
  complete: boolean;
  issues: string[];
  elapsedMs: number | null;
  error: string | null;
  selected: number | null;
  detail: LinkPreview | null;
  detailError: string | null;
}

const initial: State = {
  status: "idle",
  fileName: "",
  stage: null,
  format: "",
  total: null,
  received: 0,
  complete: true,
  issues: [],
  elapsedMs: null,
  error: null,
  selected: null,
  detail: null,
  detailError: null,
};

type Action =
  | { type: "start"; fileName: string }
  | { type: "msg"; msg: WorkerOut }
  | { type: "fail"; message: string }
  | { type: "select"; index: number };

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "start":
      return { ...initial, status: "working", fileName: action.fileName };
    case "fail":
      return { ...state, status: "error", error: action.message };
    case "select":
      return { ...state, selected: action.index, detail: null, detailError: null };
    case "msg": {
      const m = action.msg;
      switch (m.type) {
        case "status":
          return { ...state, stage: m.stage };
        case "started":
          return { ...state, format: m.format, total: m.total };
        case "batch":
          return { ...state, received: state.received + m.tsSec.length };
        case "done":
          return {
            ...state,
            status: "done",
            stage: null,
            total: m.total,
            format: m.format,
            complete: m.complete,
            issues: m.issues,
            elapsedMs: m.elapsedMs,
          };
        case "packet":
          // Ignore replies for a row that is no longer selected.
          return m.index === state.selected ? { ...state, detail: m.preview, detailError: null } : state;
        case "error":
          if (m.scope === "dissect") return { ...state, detailError: m.message };
          return { ...state, status: "error", stage: null, error: m.message };
        default:
          return state;
      }
    }
  }
}

const STAGE_LABEL: Record<Stage, string> = {
  reading: "Reading file…",
  parsing: "Parsing packets…",
  sending: "Loading results…",
};

export default function PcapUploader() {
  const [state, dispatch] = useReducer(reducer, initial);
  const [dragging, setDragging] = useState(false);
  const [store] = useState(() => new PacketStore());
  const workerRef = useRef<Worker | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const stopWorker = useCallback(() => {
    workerRef.current?.terminate();
    workerRef.current = null;
  }, []);

  useEffect(() => stopWorker, [stopWorker]);

  const openFile = useCallback(
    (file: File) => {
      // A fresh worker per file: terminating the old one cancels any parse in flight.
      stopWorker();
      store.reset(0);
      dispatch({ type: "start", fileName: file.name });

      let worker: Worker;
      try {
        worker = new Worker(new URL("../workers/pcap.worker.ts", import.meta.url));
      } catch (e) {
        dispatch({ type: "fail", message: `Could not start the background worker: ${String(e)}` });
        return;
      }
      workerRef.current = worker;

      worker.onmessage = (event: MessageEvent<WorkerOut>) => {
        if (workerRef.current !== worker) return; // stale worker
        const msg = event.data;
        // The store is filled before the dispatch, so any render sees the data.
        if (msg.type === "started") store.reset(msg.total);
        else if (msg.type === "batch") store.add(msg);
        dispatch({ type: "msg", msg });
      };
      worker.onerror = (event) => {
        if (workerRef.current !== worker) return;
        dispatch({ type: "fail", message: event.message || "The background worker crashed." });
      };

      const msg: WorkerIn = { type: "parse", file };
      worker.postMessage(msg);
    },
    [stopWorker, store],
  );

  const selectPacket = useCallback((index: number) => {
    dispatch({ type: "select", index });
    const msg: WorkerIn = { type: "dissect", index };
    workerRef.current?.postMessage(msg);
  }, []);

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) openFile(file);
  };

  const working = state.status === "working";
  const showList = state.received > 0;

  return (
    <div>
      <div
        role="button"
        tabIndex={0}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={`cursor-pointer rounded-xl border border-dashed px-6 py-10 text-center transition-colors ${
          dragging ? "border-sky-400 bg-sky-400/10" : "border-zinc-700 hover:border-zinc-500"
        }`}
      >
        <p className="text-sm text-zinc-300">Drop a capture here, or click to choose a file</p>
        <p className="mt-1 text-xs text-zinc-500">.pcap or .pcapng, up to 256 MB</p>
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) openFile(file);
            e.target.value = ""; // allow re-selecting the same file
          }}
        />
      </div>

      {state.status !== "idle" && (
        <section className="mt-8">
          <div className="flex items-baseline justify-between gap-4">
            <h2 className="truncate text-sm text-zinc-400">{state.fileName}</h2>
            {working && state.stage && <span className="text-xs text-sky-300">{STAGE_LABEL[state.stage]}</span>}
          </div>

          <div className="mt-2 flex flex-wrap items-end gap-x-8 gap-y-2">
            <div>
              <div className="text-4xl font-semibold tabular-nums" data-testid="packet-count">
                {state.received.toLocaleString()}
                {state.total !== null && state.status !== "done" && (
                  <span className="text-lg text-zinc-500"> / {state.total.toLocaleString()}</span>
                )}
              </div>
              <div className="text-xs text-zinc-500">packets</div>
            </div>
            {state.format && (
              <div className="text-sm text-zinc-400">
                Format: <span className="text-zinc-200">{state.format}</span>
              </div>
            )}
            {state.elapsedMs !== null && (
              <div className="text-sm text-zinc-400">
                Parsed in <span className="text-zinc-200">{state.elapsedMs.toLocaleString()} ms</span>
              </div>
            )}
          </div>

          {state.status === "error" && (
            <p className="mt-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200">
              {state.error}
            </p>
          )}

          {state.status === "done" && !state.complete && (
            <p className="mt-4 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
              This capture looks truncated or damaged. Showing the packets that could be read.
            </p>
          )}

          {state.issues.length > 0 && (
            <ul className="mt-3 list-disc pl-5 text-xs text-zinc-500">
              {state.issues.map((issue, i) => (
                <li key={i}>{issue}</li>
              ))}
            </ul>
          )}

          {showList && (
            <div className="mt-6 grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
              <PacketList
                store={store}
                count={state.received}
                selected={state.selected}
                interactive={state.status === "done"}
                onSelect={selectPacket}
              />
              {state.selected !== null ? (
                <PacketDetail
                  store={store}
                  index={state.selected}
                  preview={state.detail}
                  error={state.detailError}
                />
              ) : (
                <p className="rounded-lg border border-dashed border-zinc-800 p-4 text-xs text-zinc-500">
                  {state.status === "done"
                    ? "Select a packet to see its details. Arrow keys, Page Up/Down, Home and End also work."
                    : "Details are available once loading finishes."}
                </p>
              )}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
