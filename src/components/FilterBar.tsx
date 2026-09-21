"use client";

/**
 * The filter query box. Debounces input, and only ever shows the error for
 * the query currently in the box (a stale error from a query the user has
 * since edited is never shown).
 */
import { useEffect, useRef, useState } from "react";

const DEBOUNCE_MS = 150;

export interface FilterState {
  /** Indexes of the matching packets, or undefined while no filter is applied. */
  indexes?: Uint32Array;
  error: string | null;
  /** 0-based character offset into the query where the error starts, if known. */
  errorPosition: number | null;
  pending: boolean;
}

interface Props {
  state: FilterState;
  /** Called (debounced) whenever the query text settles. Empty string clears the filter. */
  onQuery: (query: string) => void;
  disabled: boolean;
  totalPackets: number;
}

const EXAMPLES = ["tcp", "udp", "port 443", "10.0.0.1", "10.0.0.0/24", "tcp and port 443", "len > 1000", "not arp"];

export default function FilterBar({ state, onQuery, disabled, totalPackets }: Props) {
  const [text, setText] = useState("");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  const handleChange = (value: string) => {
    setText(value);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => onQuery(value), DEBOUNCE_MS);
  };

  const clear = () => {
    if (timer.current) clearTimeout(timer.current);
    setText("");
    onQuery("");
    inputRef.current?.focus();
  };

  const hasError = state.error !== null;
  const matchCount = state.indexes ? state.indexes.length : totalPackets;
  const filtering = text.trim().length > 0;

  return (
    <div>
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <input
            ref={inputRef}
            type="text"
            value={text}
            disabled={disabled}
            onChange={(e) => handleChange(e.target.value)}
            placeholder={disabled ? "Filter (available once loading finishes)" : "Filter, e.g. tcp and port 443"}
            spellCheck={false}
            aria-invalid={hasError}
            aria-describedby={hasError ? "filter-error" : undefined}
            className={`w-full rounded-lg border bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none disabled:cursor-not-allowed disabled:opacity-50 ${
              hasError ? "border-red-500/60 focus:border-red-500" : "border-zinc-700 focus:border-sky-500/60"
            }`}
          />
          {state.pending && !hasError && (
            <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-zinc-500">
              filtering…
            </span>
          )}
        </div>
        {text.length > 0 && (
          <button
            type="button"
            onClick={clear}
            disabled={disabled}
            className="shrink-0 rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-400 hover:border-zinc-500 hover:text-zinc-200 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Clear
          </button>
        )}
      </div>

      {hasError ? (
        <p id="filter-error" className="mt-1.5 text-xs text-red-300">
          {state.error}
        </p>
      ) : filtering && !state.pending ? (
        <p className="mt-1.5 text-xs text-zinc-500">
          {matchCount.toLocaleString()} of {totalPackets.toLocaleString()} packets
        </p>
      ) : !disabled && !filtering ? (
        <p className="mt-1.5 text-xs text-zinc-600">
          Try: {EXAMPLES.map((ex, i) => (
            <span key={ex}>
              {i > 0 && ", "}
              <button
                type="button"
                onClick={() => handleChange(ex)}
                className="rounded text-zinc-500 underline decoration-dotted underline-offset-2 hover:text-zinc-300"
              >
                {ex}
              </button>
            </span>
          ))}
        </p>
      ) : null}
    </div>
  );
}
