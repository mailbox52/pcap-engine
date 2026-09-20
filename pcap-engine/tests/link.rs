mod common;

use common::eth_ipv4_packet;
use pcap_engine::link::*;

#[test]
fn ethernet_ipv4_preview() {
    let pkt = eth_ipv4_packet(b"data");
    let p = link_preview(&pkt, LINKTYPE_ETHERNET);
    assert_eq!(p.kind, "ethernet");
    assert_eq!(p.dst_mac.as_deref(), Some("aa:bb:cc:00:00:01"));
    assert_eq!(p.src_mac.as_deref(), Some("11:22:33:44:55:66"));
    assert_eq!(p.ethertype, Some(0x0800));
    let ip = p.ipv4.expect("ipv4 preview");
    assert_eq!((ip.src.as_str(), ip.dst.as_str()), ("10.0.0.1", "10.0.0.2"));
    assert_eq!((ip.protocol, ip.ttl, ip.total_len), (6, 64, 24));
    assert!(p.summary.contains("10.0.0.1"));
    assert!(p.header_hex.starts_with("aabbcc000001"));
}

#[test]
fn ethernet_vlan_tag_is_unwrapped() {
    let mut pkt = vec![0u8; 12];
    pkt.extend_from_slice(&[0x81, 0x00, 0x00, 0x2a, 0x08, 0x00]); // VLAN 42 -> IPv4
    pkt.extend_from_slice(&eth_ipv4_packet(b"")[14..]);
    let p = link_preview(&pkt, LINKTYPE_ETHERNET);
    assert_eq!(p.vlan_id, Some(42));
    assert_eq!(p.ethertype, Some(0x0800));
    assert!(p.ipv4.is_some());
}

#[test]
fn ethernet_arp_has_no_ipv4() {
    let mut pkt = vec![0xffu8; 6];
    pkt.extend_from_slice(&[1, 2, 3, 4, 5, 6, 0x08, 0x06]);
    pkt.extend_from_slice(&[0u8; 28]);
    let p = link_preview(&pkt, LINKTYPE_ETHERNET);
    assert_eq!(p.ethertype, Some(0x0806));
    assert!(p.ipv4.is_none());
    assert!(p.summary.contains("ARP"));
}

#[test]
fn radiotap_then_dot11_addresses() {
    // 8-byte radiotap header, then an 802.11 data frame header.
    let mut pkt = vec![0, 0, 8, 0, 0, 0, 0, 0];
    pkt.extend_from_slice(&[0x08, 0x01, 0, 0]); // frame control (data), duration
    pkt.extend_from_slice(&[1, 1, 1, 1, 1, 1]); // addr1 (receiver)
    pkt.extend_from_slice(&[2, 2, 2, 2, 2, 2]); // addr2 (transmitter)
    pkt.extend_from_slice(&[3, 3, 3, 3, 3, 3]);
    let p = link_preview(&pkt, LINKTYPE_IEEE802_11_RADIOTAP);
    assert_eq!(p.kind, "radiotap");
    assert_eq!(p.dst_mac.as_deref(), Some("01:01:01:01:01:01"));
    assert_eq!(p.src_mac.as_deref(), Some("02:02:02:02:02:02"));
    assert!(p.summary.contains("data"));
}

#[test]
fn radiotap_with_bad_length_is_reported_not_fatal() {
    let p = link_preview(&[0, 0, 0xff, 0xff, 0, 0, 0, 0], LINKTYPE_IEEE802_11_RADIOTAP);
    assert!(p.summary.contains("malformed"));
}

#[test]
fn raw_ipv4_and_loopback() {
    let eth = eth_ipv4_packet(b"z");
    let p = link_preview(&eth[14..], LINKTYPE_RAW);
    assert_eq!(p.kind, "ipv4");
    assert!(p.ipv4.is_some());

    let mut lo = vec![2, 0, 0, 0];
    lo.extend_from_slice(&eth[14..]);
    let p = link_preview(&lo, LINKTYPE_NULL);
    assert_eq!(p.kind, "loopback");
    assert!(p.ipv4.is_some());
}

#[test]
fn unknown_linktype_still_gives_hex() {
    let p = link_preview(&[1, 2, 3], 9999);
    assert_eq!(p.kind, "unknown");
    assert_eq!(p.header_hex, "010203");
}

#[test]
fn header_hex_is_capped() {
    let p = link_preview(&[0xabu8; 500], 9999);
    assert_eq!(p.header_hex.len(), 64);
}

#[test]
fn any_prefix_of_any_packet_under_any_linktype_never_panics() {
    let mut samples: Vec<Vec<u8>> = vec![
        eth_ipv4_packet(b"abc"),
        vec![0, 0, 8, 0, 0, 0, 0, 0, 0x08, 1, 0, 0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2],
        vec![0x81, 0, 0x81, 0, 0x81, 0, 0x81, 0],
        vec![0xffu8; 40],
        vec![],
    ];
    samples.push(eth_ipv4_packet(b"")[14..].to_vec());
    for s in &samples {
        for cut in 0..=s.len() {
            for lt in [0u16, 1, 101, 105, 113, 127, 228, 229, 9999, u16::MAX] {
                let _ = link_preview(&s[..cut], lt);
            }
        }
    }
}
