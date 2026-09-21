const LINK_TYPES: Record<number, string> = {
  0: "Loopback",
  1: "Ethernet",
  101: "Raw IP",
  105: "802.11",
  113: "Linux SLL",
  127: "RadioTap",
  228: "IPv4",
  229: "IPv6",
};

export function linkTypeName(linktype: number): string {
  return LINK_TYPES[linktype] ?? `Type ${linktype}`;
}

const ETHERTYPES: Record<number, string> = {
  0x0800: "IPv4",
  0x0806: "ARP",
  0x86dd: "IPv6",
  0x8100: "VLAN",
  0x88a8: "QinQ",
  0x88cc: "LLDP",
};

export function etherTypeName(t: number): string {
  const hex = "0x" + t.toString(16).padStart(4, "0");
  return ETHERTYPES[t] ? `${hex} (${ETHERTYPES[t]})` : hex;
}

const IP_PROTOCOLS: Record<number, string> = { 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP" };

export function ipProtocolName(p: number): string {
  return IP_PROTOCOLS[p] ? `${p} (${IP_PROTOCOLS[p]})` : String(p);
}

export interface HexLine {
  offset: string;
  bytes: string;
  ascii: string;
}

/** Turn a hex string like "aabbcc..." into 16-byte hex-dump lines. */
export function hexLines(hex: string): HexLine[] {
  const lines: HexLine[] = [];
  for (let at = 0; at < hex.length; at += 32) {
    const chunk = hex.slice(at, at + 32);
    const bytes: string[] = [];
    let ascii = "";
    for (let i = 0; i + 1 < chunk.length; i += 2) {
      const byte = parseInt(chunk.slice(i, i + 2), 16);
      bytes.push(chunk.slice(i, i + 2));
      ascii += byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".";
    }
    lines.push({
      offset: (at / 2).toString(16).padStart(4, "0"),
      bytes: bytes.join(" "),
      ascii,
    });
  }
  return lines;
}

/** "1.50 KB", "105 MB", ... for byte counts. */
export function formatBytes(n: number): string {
  if (n < 1024) return `${Math.round(n)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n;
  let u = -1;
  do {
    v /= 1024;
    u++;
  } while (v >= 1024 && u < units.length - 1);
  const digits = v >= 100 ? 0 : v >= 10 ? 1 : 2;
  return `${v.toFixed(digits)} ${units[u]}`;
}

/** "250 ms", "12.35 s", "42 min 27 s", "1 h 02 min". */
export function formatDuration(secs: number): string {
  if (!(secs > 0)) return "0 s";
  if (secs < 1) return `${Math.round(secs * 1000)} ms`;
  if (secs < 59.995) return `${secs.toFixed(2)} s`;
  const total = Math.round(secs);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return h > 0 ? `${h} h ${String(m).padStart(2, "0")} min` : `${m} min ${s} s`;
}

/** ISO-8601 UTC timestamp with nanoseconds: 2023-11-14T22:13:20.500000000Z */
export function isoTimestamp(sec: number, nsec: number): string {
  const base = new Date(sec * 1000).toISOString().slice(0, 19);
  return `${base}.${String(nsec).padStart(9, "0")}Z`;
}
