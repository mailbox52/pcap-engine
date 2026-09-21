"use client";

import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import type { PacketBatch, Stage, WorkerIn, WorkerOut } from "@/lib/messages";

const PREVIEW_ROWS = 20;

interface Row {
  n: number;
  time: string;
  origLen: number;
  capLen: number;
  linktype: number;
}

interface State {
  status: "idle" | "working" | "done" | "error";
  fileName: string;
  stage: Stage | null;
  format: string;
  total: number | null;
  received: number;
  rows: Row[];
  complete: boolean;
  issues: string[];
  elapsedMs: number | null;
  error: string | null;
}

const initial: State = {
  status: "idle",
  fileName: "",
  stage: null,
  format: "",
  total: null,
  received: 0,
  rows: [],
  complete: true,
  issues: [],
  elapsedMs: null,
  error: null,
};

type Action =
  | { type: "start"; fileName: string }
  | { type: "msg"; msg: WorkerOut }
  | { type: "fail"; message: string };

/** Rows for the first packets of a batch, with time in seconds relative to that batch's first packet. */
function previewRows(b: PacketBatch): Row[] {
  const rows: Row[] = [];
  const count = Math.min(PREVIEW_ROWS, b.tsSec.length);
  for (let i = 0; i < count; i++) {
    // Exact sec + nsec columns, subtracted before converting to float.
    const secs = b.tsSec[i] - b.tsSec[0] + (b.tsNsec[i] - b.tsNsec[0]) / 1e9;
    rows.push({
      n: b.start + i + 1,
      time: secs.toFixed(6),
      origLen: b.origLen[i],
      capLen: b.capLen[i],
      linktype: b.linktype[i],
    });
  }
  return rows;
}

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "start":
      return { ...initial, status: "working", fileName: action.fileName };
    case "fail":
      return { ...state, status: "error", error: action.message };
    case "msg": {
      const m = action.msg;
      switch (m.type) {
        case "status":
          return { ...state, stage: m.stage };
        case "started":
          return { ...state, format: m.format, total: m.total };
        case "batch": {
          const rows =
            state.rows.length === 0 && m.start === 0 ? previewRows(m) : state.rows;
          return { ...state, received: state.received + m.tsSec.length, rows };
        }
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
        case "error":
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
        dispatch({ type: "msg", msg: event.data });
      };
      worker.onerror = (event) => {
        if (workerRef.current !== worker) return;
        dispatch({ type: "fail", message: event.message || "The background worker crashed." });
      };

      const msg: WorkerIn = { type: "parse", file };
      worker.postMessage(msg);
    },
    [stopWorker],
  );

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) openFile(file);
  };

  const working = state.status === "working";

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
        className={`cursor-pointer rounded-xl border border-dashed px-6 py-12 text-center transition-colors ${
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

          {state.rows.length > 0 && (
            <div className="mt-6 overflow-x-auto rounded-lg border border-zinc-800">
              <table className="w-full text-left text-xs tabular-nums">
                <thead className="bg-zinc-900 text-zinc-400">
                  <tr>
                    <th className="px-3 py-2 font-medium">#</th>
                    <th className="px-3 py-2 font-medium">Time (s)</th>
                    <th className="px-3 py-2 font-medium">Original</th>
                    <th className="px-3 py-2 font-medium">Captured</th>
                    <th className="px-3 py-2 font-medium">Link type</th>
                  </tr>
                </thead>
                <tbody>
                  {state.rows.map((r) => (
                    <tr key={r.n} className="border-t border-zinc-800">
                      <td className="px-3 py-1.5 text-zinc-500">{r.n}</td>
                      <td className="px-3 py-1.5">{r.time}</td>
                      <td className="px-3 py-1.5">{r.origLen}</td>
                      <td className="px-3 py-1.5">{r.capLen}</td>
                      <td className="px-3 py-1.5">{r.linktype}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {state.received > PREVIEW_ROWS && (
                <p className="border-t border-zinc-800 px-3 py-2 text-xs text-zinc-500">
                  Showing the first {PREVIEW_ROWS} packets. The full scrolling list comes next.
                </p>
              )}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
