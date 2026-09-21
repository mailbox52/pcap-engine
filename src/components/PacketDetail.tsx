import type { LinkPreview } from "@/lib/messages";
import type { PacketStore } from "@/lib/packet-store";
import { etherTypeName, hexLines, ipProtocolName, linkTypeName } from "@/lib/format";

interface Props {
  store: PacketStore;
  index: number;
  preview: LinkPreview | null;
  error: string | null;
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-1">
      <dt className="text-zinc-500">{label}</dt>
      <dd className="text-right text-zinc-200">{value}</dd>
    </div>
  );
}

export default function PacketDetail({ store, index, preview, error }: Props) {
  const orig = store.origLen[index];
  const cap = store.capLen[index];

  return (
    <aside className="rounded-lg border border-zinc-800 p-4 text-xs">
      <h3 className="text-sm font-medium text-zinc-200">Packet {(index + 1).toLocaleString()}</h3>

      <dl className="mt-2 divide-y divide-zinc-800/70">
        <Field label="Timestamp (UTC)" value={<span className="tabular-nums">{store.isoTime(index)}</span>} />
        <Field label="Length" value={`${orig} bytes${cap < orig ? ` (${cap} captured)` : ""}`} />
        <Field label="Link type" value={linkTypeName(store.linktype[index])} />
      </dl>

      {error && <p className="mt-3 text-red-300">{error}</p>}
      {!error && !preview && <p className="mt-3 text-zinc-500">Reading packet…</p>}

      {preview && (
        <>
          <p className="mt-3 text-zinc-300">{preview.summary}</p>

          <dl className="mt-2 divide-y divide-zinc-800/70">
            {preview.dst_mac && <Field label="Destination MAC" value={<code>{preview.dst_mac}</code>} />}
            {preview.src_mac && <Field label="Source MAC" value={<code>{preview.src_mac}</code>} />}
            {preview.ethertype != null && <Field label="EtherType" value={etherTypeName(preview.ethertype)} />}
            {preview.vlan_id != null && <Field label="VLAN" value={preview.vlan_id} />}
          </dl>

          {preview.ipv4 && (
            <>
              <h4 className="mt-4 text-zinc-400">IPv4</h4>
              <dl className="mt-1 divide-y divide-zinc-800/70">
                <Field label="Source" value={<code>{preview.ipv4.src}</code>} />
                <Field label="Destination" value={<code>{preview.ipv4.dst}</code>} />
                <Field label="Protocol" value={ipProtocolName(preview.ipv4.protocol)} />
                <Field label="TTL" value={preview.ipv4.ttl} />
                <Field label="Total length" value={preview.ipv4.total_len} />
              </dl>
            </>
          )}

          <h4 className="mt-4 text-zinc-400">First bytes</h4>
          <pre className="mt-1 overflow-x-auto rounded bg-zinc-900 p-2 font-mono leading-5 text-zinc-300">
            {hexLines(preview.header_hex).map((l) => (
              <div key={l.offset}>
                <span className="text-zinc-600">{l.offset}</span>  {l.bytes.padEnd(47, " ")}  <span className="text-zinc-500">{l.ascii}</span>
              </div>
            ))}
          </pre>
        </>
      )}
    </aside>
  );
}
