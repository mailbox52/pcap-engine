"use client";

import { useEffect, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { PacketStore } from "@/lib/packet-store";
import { addressText, infoText, protocolColor, protocolName } from "@/lib/summary";

const ROW_HEIGHT = 24;
const COLUMNS = "grid grid-cols-[5.5rem_7rem_minmax(7.5rem,10rem)_minmax(7.5rem,10rem)_4.75rem_4rem_minmax(12rem,1fr)]";

interface Props {
  store: PacketStore;
  /** Number of packets available so far. Changing it re-renders the list. */
  count: number;
  /**
   * When a filter is active, the packet index for each visible row, in
   * display order. Row 0 shows packet `indexes[0]`, and so on. Arrow-key
   * navigation and Home/End move through this list, not the raw packet
   * order. Omit (or pass all packets) when no filter is active.
   */
  indexes?: Uint32Array;
  selected: number | null;
  /** Rows are only clickable once the whole capture is loaded. */
  interactive: boolean;
  onSelect: (index: number) => void;
}

/** Scrolling packet list. Only the rows in view (plus a small overscan) exist in the DOM. */
export default function PacketList({ store, count, indexes, selected, interactive, onSelect }: Props) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const rowCount = indexes ? indexes.length : count;
  const packetAt = (row: number) => (indexes ? indexes[row] : row);
  // Position of `selected` within the current (possibly filtered) row order, or -1.
  const selectedRow = selected === null ? -1 : indexes ? indexes.indexOf(selected) : selected;

  const virtualizer = useVirtualizer({
    count: rowCount,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  // Start at the top for a new capture, or whenever the filter changes.
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: 0 });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [count === 0, indexes]);

  const moveToRow = (row: number) => {
    const next = Math.max(0, Math.min(rowCount - 1, row));
    virtualizer.scrollToIndex(next, { align: "auto" });
    onSelect(packetAt(next));
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!interactive || rowCount === 0) return;
    const page = Math.max(1, Math.floor((scrollRef.current?.clientHeight ?? 400) / ROW_HEIGHT) - 1);
    const cur = selectedRow;
    const targets: Record<string, number> = {
      ArrowDown: cur + 1,
      ArrowUp: cur === -1 ? 0 : cur - 1,
      PageDown: cur + page,
      PageUp: cur - page,
      Home: 0,
      End: rowCount - 1,
    };
    if (e.key in targets) {
      e.preventDefault();
      moveToRow(targets[e.key]);
    }
  };

  return (
    <div
      ref={scrollRef}
      tabIndex={0}
      onKeyDown={onKeyDown}
      role="grid"
      aria-rowcount={rowCount}
      aria-label="Packets"
      className="h-[28rem] overflow-auto rounded-lg border border-zinc-800 text-xs tabular-nums outline-none focus-visible:border-sky-500/60"
    >
      <div className="min-w-[49rem]">
        <div className={`${COLUMNS} sticky top-0 z-10 bg-zinc-900 text-zinc-400`}>
          <div className="px-3 py-2 font-medium">#</div>
          <div className="px-3 py-2 font-medium">Time (s)</div>
          <div className="px-3 py-2 font-medium">Source</div>
          <div className="px-3 py-2 font-medium">Destination</div>
          <div className="px-3 py-2 font-medium">Protocol</div>
          <div className="px-3 py-2 font-medium">Length</div>
          <div className="px-3 py-2 font-medium">Info</div>
        </div>

        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {virtualizer.getVirtualItems().map((v) => {
            const i = packetAt(v.index);
            const isSelected = i === selected;
            const src = addressText(store, i, "src");
            const dst = addressText(store, i, "dst");
            const info = infoText(store, i);
            return (
              <div
                key={v.key}
                role="row"
                aria-rowindex={i + 1}
                aria-selected={isSelected}
                onClick={interactive ? () => onSelect(i) : undefined}
                className={`${COLUMNS} absolute left-0 top-0 w-full items-center border-t border-zinc-800/70 ${
                  isSelected ? "bg-sky-500/20" : interactive ? "cursor-pointer hover:bg-zinc-800/60" : ""
                }`}
                style={{ height: v.size, transform: `translateY(${v.start}px)` }}
              >
                <div className="px-3 text-zinc-500">{(i + 1).toLocaleString()}</div>
                <div className="px-3">{store.relativeSeconds(i).toFixed(6)}</div>
                <div className="truncate px-3" title={src}>{src}</div>
                <div className="truncate px-3" title={dst}>{dst}</div>
                <div className={`px-3 ${protocolColor(store.proto[i])}`}>{protocolName(store.proto[i])}</div>
                <div className="px-3">{store.origLen[i]}</div>
                <div className="truncate px-3 text-zinc-300" title={info}>{info}</div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
