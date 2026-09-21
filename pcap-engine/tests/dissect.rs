mod common;

use common::*;
use pcap_engine::dissect::*;

const A: [u8; 4] = [192, 168, 1, 10];
const B: [u8; 4] = [8, 8, 8, 8];

fn v4(m: &Meta, which_src: bool) -> [u8; 4] {
    let a = if which_src { &m.src } else { &m.dst };
    [a[0], a[1], a[2], a[3]]
}

fn v6addr(last: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0x20;
    a[1] = 0x01;
    a[2] = 0x0d;
    a[3] = 0xb8;
    a[15] = last;
    a
}

#[test]
fn tcp_syn_ack() {
    let pkt = eth_frame(0x0800, &ipv4_packet(6, A, B, 0, &tcp_segment(443, 51234, 0x12)));
    let m = dissect(&pkt, 1);
    assert_eq!(m.proto, PROTO_TCP);
    assert_eq!(m.ip_version, 4);
    assert_eq!((m.src_port, m.dst_port), (443, 51234));
    assert_eq!(m.detail, 0x12);
    assert_eq!((v4(&m, true), v4(&m, false)), (A, B));
}

#[test]
fn udp_and_dns() {
    let plain = eth_frame(0x0800, &ipv4_packet(17, A, B, 0, &udp_datagram(5000, 6000)));
    let m = dissect(&plain, 1);
    assert_eq!((m.proto, m.src_port, m.dst_port), (PROTO_UDP, 5000, 6000));

    let query = eth_frame(0x0800, &ipv4_packet(17, A, B, 0, &udp_datagram(40000, 53)));
    assert_eq!(dissect(&query, 1).proto, PROTO_DNS);
    let reply = eth_frame(0x0800, &ipv4_packet(17, B, A, 0, &udp_datagram(53, 40000)));
    assert_eq!(dissect(&reply, 1).proto, PROTO_DNS);
}

#[test]
fn icmp_echo_request() {
    let pkt = eth_frame(0x0800, &ipv4_packet(1, A, B, 0, &[8, 0, 0, 0, 0, 1, 0, 1]));
    let m = dissect(&pkt, 1);
    assert_eq!(m.proto, PROTO_ICMP);
    assert_eq!(m.detail, 0x0800);
}

#[test]
fn arp_request() {
    let pkt = eth_frame(0x0806, &arp_packet(1, A, [192, 168, 1, 1]));
    let m = dissect(&pkt, 1);
    assert_eq!(m.proto, PROTO_ARP);
    assert_eq!(m.ip_version, 4);
    assert_eq!(m.detail, 1);
    assert_eq!((v4(&m, true), v4(&m, false)), (A, [192, 168, 1, 1]));
}

#[test]
fn ipv6_tcp() {
    let pkt = eth_frame(0x86dd, &ipv6_packet(6, v6addr(1), v6addr(2), &tcp_segment(22, 60000, 0x02)));
    let m = dissect(&pkt, 1);
    assert_eq!((m.proto, m.ip_version), (PROTO_TCP, 6));
    assert_eq!((m.src_port, m.dst_port, m.detail), (22, 60000, 0x02));
    assert_eq!(m.src, v6addr(1));
    assert_eq!(m.dst, v6addr(2));
}

#[test]
fn ipv6_skips_extension_headers() {
    // Hop-by-hop header (8 bytes) whose next header is UDP.
    let mut rest = vec![17, 0, 0, 0, 0, 0, 0, 0];
    rest.extend_from_slice(&udp_datagram(1234, 5678));
    let pkt = eth_frame(0x86dd, &ipv6_packet(0, v6addr(1), v6addr(2), &rest));
    let m = dissect(&pkt, 1);
    assert_eq!((m.proto, m.src_port, m.dst_port), (PROTO_UDP, 1234, 5678));
}

#[test]
fn icmpv6_neighbor_solicitation() {
    let pkt = eth_frame(0x86dd, &ipv6_packet(58, v6addr(1), v6addr(2), &[135, 0, 0, 0, 0, 0, 0, 0]));
    let m = dissect(&pkt, 1);
    assert_eq!(m.proto, PROTO_ICMPV6);
    assert_eq!(m.detail, 135 << 8);
}

#[test]
fn ipv6_later_fragment_has_no_transport() {
    // Fragment header: next=UDP, offset 1 (non-zero).
    let mut rest = vec![17, 0, 0, 8, 0, 0, 0, 1];
    rest.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let pkt = eth_frame(0x86dd, &ipv6_packet(44, v6addr(1), v6addr(2), &rest));
    let m = dissect(&pkt, 1);
    assert_eq!(m.proto, PROTO_IPV6);
    assert_eq!((m.src_port, m.dst_port), (0, 0));
}

#[test]
fn ipv4_later_fragment_has_no_transport() {
    let pkt = eth_frame(0x0800, &ipv4_packet(17, A, B, 0x00b9, &[1, 2, 3, 4, 5, 6, 7, 8]));
    let m = dissect(&pkt, 1);
    assert_eq!(m.proto, PROTO_IPV4);
    assert_eq!(m.detail, 17);
    assert_eq!((m.src_port, m.dst_port), (0, 0));
    assert_eq!((v4(&m, true), v4(&m, false)), (A, B));
}

#[test]
fn vlan_tagged_frame_is_unwrapped() {
    let inner = ipv4_packet(6, A, B, 0, &tcp_segment(80, 1000, 0x10));
    let mut payload = vec![0x00, 0x2a, 0x08, 0x00]; // VLAN 42, then IPv4
    payload.extend_from_slice(&inner);
    let pkt = eth_frame(0x8100, &payload);
    let m = dissect(&pkt, 1);
    assert_eq!((m.proto, m.src_port, m.dst_port), (PROTO_TCP, 80, 1000));
}

#[test]
fn unknown_ethertype_keeps_the_type() {
    let m = dissect(&eth_frame(0x88cc, &[0u8; 30]), 1);
    assert_eq!(m.proto, PROTO_OTHER);
    assert_eq!(m.detail, 0x88cc);
    assert_eq!(m.ip_version, 0);
}

#[test]
fn other_link_layers() {
    let ip = ipv4_packet(6, A, B, 0, &tcp_segment(1, 2, 0x02));
    assert_eq!(dissect(&ip, 101).proto, PROTO_TCP); // raw IP
    let mut lo = vec![2, 0, 0, 0];
    lo.extend_from_slice(&ip);
    assert_eq!(dissect(&lo, 0).proto, PROTO_TCP); // loopback
    let mut sll = vec![0u8; 14];
    sll.extend_from_slice(&[0x08, 0x00]);
    sll.extend_from_slice(&ip);
    assert_eq!(dissect(&sll, 113).proto, PROTO_TCP); // Linux cooked
    let m = dissect(&[1, 2, 3, 4], 127); // RadioTap: not decoded
    assert_eq!(m, Meta::default());
}

#[test]
fn truncated_transport_headers_do_not_panic_and_keep_what_they_can() {
    let full = ipv4_packet(6, A, B, 0, &tcp_segment(443, 51234, 0x12));
    // Cut inside the TCP header: two bytes of ports are all that is left.
    let m = dissect(&eth_frame(0x0800, &full[..22]), 1);
    assert_eq!(m.proto, PROTO_TCP);
    assert_eq!(m.src_port, 443);
    assert_eq!(m.detail, 0);
    // Cut inside the IPv4 header: no addresses.
    let m = dissect(&eth_frame(0x0800, &full[..10]), 1);
    assert_eq!(m.proto, PROTO_IPV4);
    assert_eq!(m.ip_version, 0);
}

#[test]
fn any_prefix_of_any_packet_under_any_linktype_never_panics() {
    let ip4 = ipv4_packet(6, A, B, 0, &tcp_segment(443, 51234, 0x12));
    let samples: Vec<Vec<u8>> = vec![
        eth_frame(0x0800, &ip4),
        eth_frame(0x0806, &arp_packet(1, A, B)),
        eth_frame(0x86dd, &ipv6_packet(58, v6addr(1), v6addr(2), &[135, 0, 0, 0])),
        eth_frame(0x8100, &[0, 42, 0x81, 0, 0, 43, 0x08, 0]),
        ip4.clone(),
        ipv6_packet(0, v6addr(1), v6addr(2), &[44, 0, 0, 8, 0, 0, 0, 1]),
        vec![0xffu8; 80],
        vec![],
    ];
    for s in &samples {
        for cut in 0..=s.len() {
            for lt in [0u16, 1, 101, 105, 113, 127, 228, 229, 9999, u16::MAX] {
                let _ = dissect(&s[..cut], lt);
            }
        }
    }
}
