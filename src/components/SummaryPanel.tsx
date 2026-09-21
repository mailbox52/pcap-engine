import type { CaptureSummary } from "@/lib/messages";
import { formatBytes, formatDuration, isoTimestamp } from "@/lib/format";
import { formatIPv4, formatIPv6, protocolBarColor, protocolColor, protocolName } from "@/lib/summary";

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-1">
      <dt className="text-zinc-500">{label}</dt>
      <dd className="text-right text-zinc-200 tabular-nums">{value}</dd>
    </div>
  );
}

function clock(sec: number, nsec: number): string {
  // 2023-11-14 22:13:20 UTC
  return `${isoTimestamp(sec, nsec).slice(0, 19).replace("T", " ")} UTC`;
}

function talkerText(t: CaptureSummary["topTalkers"][number]): string {
  const bytes = Uint8Array.from(t.addr);
  return t.ipVersion === 6 ? formatIPv6(bytes, 0) : formatIPv4(bytes, 0);
}

export default function SummaryPanel({ summary }: { summary: CaptureSummary }) {
  const total = Math.max(1, summary.totalPackets);
  const hasTime = summary.firstSec !== 0 || summary.lastSec !== 0 || summary.firstNsec !== 0;
  const average = summary.totalPackets > 0 ? summary.totalBytes / summary.totalPackets : 0;
  const maxTalkerBytes = Math.max(1, ...summary.topTalkers.map((t) => t.bytes));

  return (
    <section aria-label="Capture summary" className="grid gap-6 rounded-lg border border-zinc-800 p-4 text-xs lg:grid-cols-3">
      <div>
        <h3 className="text-sm font-medium text-zinc-200">Overview</h3>
        <dl className="mt-2 divide-y divide-zinc-800/70">
          <Row label="Packets" value={summary.totalPackets.toLocaleString()} />
          <Row label="Duration" value={hasTime ? formatDuration(summary.durationSecs) : "n/a"} />
          <Row label="Size on the wire" value={formatBytes(summary.totalBytes)} />
          {summary.capturedBytes < summary.totalBytes && (
            <Row label="Size captured" value={formatBytes(summary.capturedBytes)} />
          )}
          <Row label="Average packet" value={`${Math.round(average)} B`} />
          {hasTime && <Row label="Start" value={clock(summary.firstSec, summary.firstNsec)} />}
          {hasTime && <Row label="End" value={clock(summary.lastSec, summary.lastNsec)} />}
        </dl>
      </div>

      <div>
        <h3 className="text-sm font-medium text-zinc-200">Protocols</h3>
        <ul className="mt-2 space-y-2">
          {summary.protocols.map((p) => {
            const pct = (p.packets / total) * 100;
            return (
              <li key={p.proto}>
                <div className="flex justify-between gap-3">
                  <span className={protocolColor(p.proto)}>{protocolName(p.proto)}</span>
                  <span className="text-zinc-400 tabular-nums">
                    {p.packets.toLocaleString()} · {pct < 0.1 ? "<0.1" : pct.toFixed(1)}%
                  </span>
                </div>
                <div className="mt-1 h-1.5 rounded bg-zinc-800">
                  <div
                    className={`h-1.5 rounded ${protocolBarColor(p.proto)}`}
                    style={{ width: `${Math.max(pct, 0.5)}%` }}
                  />
                </div>
              </li>
            );
          })}
        </ul>
      </div>

      <div>
        <h3 className="text-sm font-medium text-zinc-200">Top talkers</h3>
        {summary.topTalkers.length === 0 ? (
          <p className="mt-2 text-zinc-500">No IP addresses in this capture.</p>
        ) : (
          <ol className="mt-2 space-y-2">
            {summary.topTalkers.map((t, i) => (
              <li key={`${t.ipVersion}-${talkerText(t)}`}>
                <div className="flex justify-between gap-3">
                  <code className="truncate text-zinc-200" title={talkerText(t)}>
                    {talkerText(t)}
                  </code>
                  <span className="shrink-0 text-zinc-400 tabular-nums">
                    {formatBytes(t.bytes)} · {t.packets.toLocaleString()} pkts
                  </span>
                </div>
                <div className="mt-1 h-1.5 rounded bg-zinc-800">
                  <div
                    className={`h-1.5 rounded ${i === 0 ? "bg-sky-400" : "bg-zinc-500"}`}
                    style={{ width: `${Math.max((t.bytes / maxTalkerBytes) * 100, 0.5)}%` }}
                  />
                </div>
              </li>
            ))}
          </ol>
        )}
      </div>
    </section>
  );
}
