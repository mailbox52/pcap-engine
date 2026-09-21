mod common;

use common::*;
use pcap_engine::core::parse_capture;
use pcap_engine::dissect::*;
use pcap_engine::summary::{summarize, TOP_TALKERS};

const A: [u8; 4] = [10, 0, 0, 1];
const B: [u8; 4] = [10, 0, 0, 2];
const C: [u8; 4] = [10, 0, 0, 3];
const D: [u8; 4] = [10, 0, 0, 4];
const E: [u8; 4] = [10, 0, 0, 9];

fn v6(last: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    a[15] = last;
    a
}

/// Six packets: TCP A->B (54 B), DNS B->C (42), ICMP C->D (42), ARP A->E (42),
/// IPv6 TCP ::1 -> ::2 (74), and an LLDP frame with no addresses (44).
fn sample() -> Vec<Vec<u8>> {
    vec![
        eth_frame(0x0800, &ipv4_packet(6, A, B, 0, &tcp_segment(443, 51234, 0x12))),
        eth_frame(0x0800, &ipv4_packet(17, B, C, 0, &udp_datagram(40000, 53))),
        eth_frame(0x0800, &ipv4_packet(1, C, D, 0, &[8, 0, 0, 0, 0, 1, 0, 1])),
        eth_frame(0x0806, &arp_packet(1, A, E)),
        eth_frame(0x86dd, &ipv6_packet(6, v6(1), v6(2), &tcp_segment(22, 60000, 0x02))),
        eth_frame(0x88cc, &[0u8; 30]),
    ]
}

fn file_from(packets: &[Vec<u8>], secs: &[u32]) -> Vec<u8> {
    let pkts: Vec<Pkt> = packets
        .iter()
        .zip(secs)
        .map(|(d, s)| Pkt { ts_sec: *s, ts_frac: 0, orig_len: d.len() as u32, data: d })
        .collect();
    pcap_file(Endian::LE, false, 1, &pkts)
}

fn addr4(t: &pcap_engine::summary::Talker) -> [u8; 4] {
    [t.addr[0], t.addr[1], t.addr[2], t.addr[3]]
}

#[test]
fn totals_duration_and_protocol_breakdown() {
    let idx = parse_capture(&file_from(&sample(), &[100, 101, 102, 103, 104, 105])).unwrap();
    let s = summarize(&idx);
    assert_eq!(s.total_packets, 6);
    assert_eq!(s.total_bytes, 298.0);
    assert_eq!(s.captured_bytes, 298.0);
    assert_eq!((s.first_sec, s.last_sec), (100, 105));
    assert_eq!(s.duration_secs, 5.0);

    let got: Vec<(u8, u32, f64)> = s.protocols.iter().map(|p| (p.proto, p.packets, p.bytes)).collect();
    // Most packets first; ties broken by protocol id.
    let want = vec![
        (PROTO_TCP, 2, 128.0),
        (PROTO_OTHER, 1, 44.0),
        (PROTO_ICMP, 1, 42.0),
        (PROTO_ARP, 1, 42.0),
        (PROTO_DNS, 1, 42.0),
    ];
    assert_eq!(got, want);
}

#[test]
fn top_talkers_count_both_directions_and_rank_by_bytes() {
    let idx = parse_capture(&file_from(&sample(), &[100, 101, 102, 103, 104, 105])).unwrap();
    let s = summarize(&idx);
    // A: TCP 54 + ARP 42 = 96 (2 packets); B: TCP 54 + DNS 42 = 96 (2); C: DNS 42 + ICMP 42 = 84;
    // ::1 and ::2: 74 each; D and E: 42 each.
    assert_eq!(s.top_talkers.len(), 7);
    let t = &s.top_talkers;
    assert_eq!((addr4(&t[0]), t[0].bytes, t[0].packets, t[0].ip_version), (A, 96.0, 2, 4));
    assert_eq!((addr4(&t[1]), t[1].bytes), (B, 96.0));
    assert_eq!((addr4(&t[2]), t[2].bytes, t[2].packets), (C, 84.0, 2));
    assert_eq!((t[3].addr, t[3].bytes, t[3].ip_version), (v6(1), 74.0, 6));
    assert_eq!(t[4].addr, v6(2));
    assert_eq!((addr4(&t[5]), t[5].bytes), (D, 42.0));
    assert_eq!(addr4(&t[6]), E);
}

#[test]
fn a_packet_to_itself_counts_once() {
    let pkt = eth_frame(0x0800, &ipv4_packet(1, A, A, 0, &[8, 0, 0, 0, 0, 1, 0, 1]));
    let idx = parse_capture(&file_from(&[pkt], &[1])).unwrap();
    let s = summarize(&idx);
    assert_eq!(s.top_talkers.len(), 1);
    assert_eq!((s.top_talkers[0].packets, s.top_talkers[0].bytes), (1, 42.0));
}

#[test]
fn only_the_top_ten_talkers_are_kept() {
    let packets: Vec<Vec<u8>> = (1..=20u8)
        .map(|i| eth_frame(0x0800, &ipv4_packet(1, [10, 1, 0, i], [10, 2, 0, i], 0, &[8, 0, 0, 0, 0, 1, 0, 1])))
        .collect();
    let secs: Vec<u32> = (1..=20).collect();
    let idx = parse_capture(&file_from(&packets, &secs)).unwrap();
    assert_eq!(summarize(&idx).top_talkers.len(), TOP_TALKERS);
}

#[test]
fn timestamps_out_of_order_still_give_the_right_span() {
    let idx = parse_capture(&file_from(&sample(), &[105, 100, 103, 101, 104, 102])).unwrap();
    let s = summarize(&idx);
    assert_eq!((s.first_sec, s.last_sec, s.duration_secs), (100, 105, 5.0));
}

#[test]
fn nanosecond_precision_in_duration() {
    let pkts = sample();
    let a = Pkt { ts_sec: 10, ts_frac: 100_000_000, orig_len: pkts[0].len() as u32, data: &pkts[0] };
    let b = Pkt { ts_sec: 12, ts_frac: 350_000_000, orig_len: pkts[1].len() as u32, data: &pkts[1] };
    let file = pcap_file(Endian::LE, true, 1, &[a, b]);
    let s = summarize(&parse_capture(&file).unwrap());
    assert_eq!((s.first_nsec, s.last_nsec), (100_000_000, 350_000_000));
    assert!((s.duration_secs - 2.25).abs() < 1e-9);
}

#[test]
fn empty_capture_summarises_to_zeros() {
    let file = pcap_file(Endian::LE, false, 1, &[]);
    let s = summarize(&parse_capture(&file).unwrap());
    assert_eq!(s.total_packets, 0);
    assert_eq!((s.total_bytes, s.duration_secs), (0.0, 0.0));
    assert!(s.protocols.is_empty() && s.top_talkers.is_empty());
}

#[test]
fn snaplen_truncated_packets_report_wire_and_captured_bytes_separately() {
    let pkts = sample();
    let p = Pkt { ts_sec: 1, ts_frac: 0, orig_len: 1500, data: &pkts[0] };
    let file = pcap_file(Endian::LE, false, 1, &[p]);
    let s = summarize(&parse_capture(&file).unwrap());
    assert_eq!((s.total_bytes, s.captured_bytes), (1500.0, 54.0));
}
