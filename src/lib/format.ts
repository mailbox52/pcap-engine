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
