mod common;

use common::*;
use pcap_engine::core::parse_capture;
use pcap_engine::filter::filter;

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

/// 0: TCP A->B :443 SYN,ACK; 1: DNS B->C; 2: ICMP C->D; 3: ARP A->E;
/// 4: IPv6 TCP ::1->::2 SYN; 5: LLDP (no addresses); 6: TCP A->C :80 SYN only, len 1400.
fn capture() -> Vec<u8> {
    let big_payload = vec![0u8; 1400 - 14 - 20 - 20];
    let mut last = ipv4_packet(6, A, C, 0, &tcp_segment(51235, 80, 0x02));
    last.extend_from_slice(&big_payload);
    let pkts: [Vec<u8>; 7] = [
        eth_frame(0x0800, &ipv4_packet(6, A, B, 0, &tcp_segment(443, 51234, 0x12))),
        eth_frame(0x0800, &ipv4_packet(17, B, C, 0, &udp_datagram(40000, 53))),
        eth_frame(0x0800, &ipv4_packet(1, C, D, 0, &[8, 0, 0, 0, 0, 1, 0, 1])),
        eth_frame(0x0806, &arp_packet(1, A, E)),
        eth_frame(0x86dd, &ipv6_packet(6, v6(1), v6(2), &tcp_segment(22, 60000, 0x02))),
        eth_frame(0x88cc, &[0u8; 30]),
        eth_frame(0x0800, &last),
    ];
    let secs: Vec<u32> = (100..100 + pkts.len() as u32).collect();
    let entries: Vec<Pkt> = pkts
        .iter()
        .zip(&secs)
        .map(|(d, s)| Pkt { ts_sec: *s, ts_frac: 0, orig_len: d.len() as u32, data: d })
        .collect();
    pcap_file(Endian::LE, false, 1, &entries)
}

fn matches(query: &str) -> Vec<u32> {
    let idx = parse_capture(&capture()).unwrap();
    filter(&idx, query).unwrap()
}

#[test]
fn empty_query_matches_everything() {
    assert_eq!(matches(""), vec![0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(matches("   "), vec![0, 1, 2, 3, 4, 5, 6]);
}

#[test]
fn protocol_keywords() {
    assert_eq!(matches("tcp"), vec![0, 4, 6]);
    assert_eq!(matches("udp"), vec![1]); // DNS counts as udp too
    assert_eq!(matches("dns"), vec![1]);
    assert_eq!(matches("icmp"), vec![2]);
    assert_eq!(matches("arp"), vec![3]);
    assert_eq!(matches("other"), vec![5]);
    assert_eq!(matches("ipv6"), vec![4]);
    assert_eq!(matches("ipv4"), vec![0, 1, 2, 6]); // ARP is excluded even though it carries IPv4 addresses
}

#[test]
fn tcp_flags() {
    assert_eq!(matches("syn"), vec![0, 4, 6]);
    assert_eq!(matches("ack"), vec![0]);
    assert_eq!(matches("syn and ack"), vec![0]);
    assert_eq!(matches("syn and not ack"), vec![4, 6]);
}

#[test]
fn addresses_and_cidr() {
    assert_eq!(matches("10.0.0.1"), vec![0, 3, 6]); // src or dst
    assert_eq!(matches("src 10.0.0.1"), vec![0, 3, 6]);
    assert_eq!(matches("dst 10.0.0.1"), Vec::<u32>::new());
    assert_eq!(matches("host 10.0.0.2"), vec![0, 1]);
    assert_eq!(matches("10.0.0.0/24"), vec![0, 1, 2, 3, 6]);
    assert_eq!(matches("10.0.0.0/30"), vec![0, 1, 2, 3, 6]); // .1-.4 inclusive... check exact bits below
    assert_eq!(matches("2001:db8::1"), vec![4]);
    assert_eq!(matches("2001:db8::/32"), vec![4]);
    assert_eq!(matches("10.0.0.4"), vec![2]);
}

#[test]
fn cidr_boundary_is_exact() {
    // 10.0.0.0/30 covers .0-.3; packet 2 uses .3 and .4, so it matches on src=.3 only.
    assert_eq!(matches("src 10.0.0.0/30"), vec![0, 1, 2, 3, 6]);
    assert_eq!(matches("dst 10.0.0.0/30"), vec![0, 1, 6]); // dst=.2 (pkt0), .3 (pkt1), .3 (pkt6)
}

#[test]
fn ports() {
    assert_eq!(matches("port 443"), vec![0]);
    assert_eq!(matches("sport 443"), vec![0]);
    assert_eq!(matches("dport 443"), Vec::<u32>::new());
    assert_eq!(matches("port 80"), vec![6]);
    assert_eq!(matches("port 22"), vec![4]);
    assert_eq!(matches("port 9"), Vec::<u32>::new());
    // ICMP and ARP have no ports, even though their `detail` field could collide.
    assert_eq!(matches("port 1"), Vec::<u32>::new());
}

#[test]
fn length_comparisons() {
    assert_eq!(matches("len > 1000"), vec![6]);
    assert_eq!(matches("len >= 1400"), vec![6]);
    assert_eq!(matches("len < 50"), vec![1, 2, 3, 5]); // DNS, ICMP, ARP (42), LLDP (44)
    assert_eq!(matches("len <= 42"), vec![1, 2, 3]); // DNS, ICMP, ARP all 42 bytes (LLDP is 44)
    let exact_len = {
        let idx = parse_capture(&capture()).unwrap();
        idx.orig_len[0]
    };
    assert_eq!(matches(&format!("len = {exact_len}")), vec![0]);
    assert_eq!(matches(&format!("len == {exact_len}")), vec![0]);
}

#[test]
fn boolean_combinations_and_precedence() {
    assert_eq!(matches("tcp and port 443"), vec![0]);
    assert_eq!(matches("tcp or arp"), vec![0, 3, 4, 6]);
    assert_eq!(matches("not tcp"), vec![1, 2, 3, 5]);
    // 'not' binds tighter than 'and': (not tcp) and udp
    assert_eq!(matches("not tcp and udp"), vec![1]);
    // Parentheses override precedence.
    assert_eq!(matches("not (tcp and port 443)"), vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(matches("(tcp or arp) and 10.0.0.1"), vec![0, 3, 6]);
    assert_eq!(matches("!tcp && udp"), vec![1]);
    assert_eq!(matches("icmp || arp"), vec![2, 3]);
}

#[test]
fn case_and_whitespace_are_flexible() {
    assert_eq!(matches("TCP AND PORT 443"), vec![0]);
    assert_eq!(matches("  tcp   and   port   443  "), vec![0]);
    assert_eq!(matches("tcp\tand\nport 443"), vec![0]);
}

#[test]
fn unknown_word_reports_position() {
    let idx = parse_capture(&capture()).unwrap();
    let e = filter(&idx, "bogus").unwrap_err();
    assert_eq!(e.position, 0);
    assert!(e.message.contains("bogus"));

    let e = filter(&idx, "tcp and bogus").unwrap_err();
    assert_eq!(e.position, 8);
}

#[test]
fn malformed_queries_report_a_position_and_never_panic() {
    let idx = parse_capture(&capture()).unwrap();
    for q in [
        "tcp and",
        "and tcp",
        "(tcp",
        "tcp)",
        "port",
        "port abc",
        "len",
        "len 5",
        "len > abc",
        "999.999.999.999",
        "10.0.0.1/99",
        "2001:db8::1/200",
        "tcp tcp",
        "()",
        "not",
        "src",
    ] {
        let r = filter(&idx, q);
        assert!(r.is_err(), "expected '{q}' to be rejected");
        let e = r.unwrap_err();
        assert!(e.position <= q.len(), "position out of range for '{q}'");
    }
}

#[test]
fn addr_expression_requires_matching_ip_version() {
    // An IPv4 CIDR should never match an IPv6 packet's slot, and vice versa.
    assert!(!matches("10.0.0.0/0").contains(&4));
    assert!(!matches("::/0").contains(&0));
}

#[test]
fn every_prefix_of_a_query_is_handled_without_panic() {
    let idx = parse_capture(&capture()).unwrap();
    let full = "(tcp and port 443) or (udp and not dns) or 10.0.0.0/24 and len > 100 and not (syn or ack)";
    for cut in 0..=full.len() {
        if !full.is_char_boundary(cut) {
            continue;
        }
        let _ = filter(&idx, &full[..cut]);
    }
}
