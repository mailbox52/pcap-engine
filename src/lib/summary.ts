/**
 * Turns the numeric per-packet columns into the text shown in the list:
 * protocol name, addresses, and the Info column. Keep the protocol ids in
 * step with pcap-engine/src/dissect.rs.
 */
import type { PacketStore } from "./packet-store";
import { etherTypeName, ipProtocolName, linkTypeName } from "./format";

export const PROTO = {
  OTHER: 0,
  TCP: 1,
  UDP: 2,
  ICMP: 3,
  ICMPV6: 4,
  ARP: 5,
  IPV4: 6,
  IPV6: 7,
  DNS: 8,
} as const;

export const PROTOCOL_NAMES = ["Other", "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "IPv4", "IPv6", "DNS"];

export function protocolName(proto: number): string {
  return PROTOCOL_NAMES[proto] ?? "Other";
}

/** Tailwind text colour for each protocol (full class names so Tailwind picks them up). */
export function protocolColor(proto: number): string {
  switch (proto) {
    case PROTO.TCP:
      return "text-sky-300";
    case PROTO.UDP:
      return "text-emerald-300";
    case PROTO.DNS:
      return "text-teal-300";
    case PROTO.ICMP:
    case PROTO.ICMPV6:
      return "text-amber-300";
    case PROTO.ARP:
      return "text-violet-300";
    case PROTO.IPV4:
    case PROTO.IPV6:
      return "text-zinc-300";
    default:
      return "text-zinc-500";
  }
}

export function formatIPv4(b: Uint8Array, at: number): string {
  return `${b[at]}.${b[at + 1]}.${b[at + 2]}.${b[at + 3]}`;
}

/** RFC 5952 text form: lowercase, no leading zeros, longest run of zero groups as "::". */
export function formatIPv6(b: Uint8Array, at: number): string {
  const groups: number[] = [];
  for (let i = 0; i < 8; i++) groups.push((b[at + i * 2] << 8) | b[at + i * 2 + 1]);

  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  if (bestLen < 2) return groups.map((g) => g.toString(16)).join(":");

  const head = groups.slice(0, bestStart).map((g) => g.toString(16)).join(":");
  const tail = groups.slice(bestStart + bestLen).map((g) => g.toString(16)).join(":");
  return `${head}::${tail}`;
}

/** Source or destination address text for packet `i`, or "" if it has none. */
export function addressText(store: PacketStore, i: number, side: "src" | "dst"): string {
  const ver = store.ipVer[i];
  const at = i * 32 + (side === "src" ? 0 : 16);
  if (ver === 4) return formatIPv4(store.addr, at);
  if (ver === 6) return formatIPv6(store.addr, at);
  return "";
}

const TCP_FLAGS: [number, string][] = [
  [0x01, "FIN"],
  [0x02, "SYN"],
  [0x04, "RST"],
  [0x08, "PSH"],
  [0x10, "ACK"],
  [0x20, "URG"],
  [0x40, "ECE"],
  [0x80, "CWR"],
];

export function tcpFlagNames(flags: number): string[] {
  return TCP_FLAGS.filter(([bit]) => (flags & bit) !== 0).map(([, name]) => name);
}

const ICMP_TYPES: Record<number, string> = {
  0: "Echo reply",
  3: "Destination unreachable",
  5: "Redirect",
  8: "Echo request",
  11: "Time exceeded",
};

const ICMPV6_TYPES: Record<number, string> = {
  1: "Destination unreachable",
  2: "Packet too big",
  3: "Time exceeded",
  128: "Echo request",
  129: "Echo reply",
  133: "Router solicitation",
  134: "Router advertisement",
  135: "Neighbor solicitation",
  136: "Neighbor advertisement",
};

function icmpText(detail: number, names: Record<number, string>): string {
  const type = detail >> 8;
  const code = detail & 0xff;
  return names[type] ?? `Type ${type}, code ${code}`;
}

/** The Info column: a short protocol-specific description. */
export function infoText(store: PacketStore, i: number): string {
  const proto = store.proto[i];
  const detail = store.detail[i];
  const sp = store.srcPort[i];
  const dp = store.dstPort[i];

  switch (proto) {
    case PROTO.TCP: {
      const flags = tcpFlagNames(detail);
      return `${sp} → ${dp} [${flags.join(", ")}]`;
    }
    case PROTO.UDP:
    case PROTO.DNS:
      return `${sp} → ${dp}`;
    case PROTO.ICMP:
      return icmpText(detail, ICMP_TYPES);
    case PROTO.ICMPV6:
      return icmpText(detail, ICMPV6_TYPES);
    case PROTO.ARP:
      if (store.ipVer[i] !== 4) return "ARP";
      if (detail === 1) return `Who has ${addressText(store, i, "dst")}? Tell ${addressText(store, i, "src")}`;
      if (detail === 2) return `Reply from ${addressText(store, i, "src")}`;
      return `ARP operation ${detail}`;
    case PROTO.IPV4:
    case PROTO.IPV6:
      return `IP protocol ${ipProtocolName(detail)}`;
    default:
      return detail !== 0 ? `EtherType ${etherTypeName(detail)}` : linkTypeName(store.linktype[i]);
  }
}
