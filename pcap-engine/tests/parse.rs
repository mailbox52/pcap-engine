mod common;

use common::*;
use pcap_engine::core::{parse_capture, Format, ParseError};

const RES_MICRO: u32 = 1_700_000_000;

fn assert_data_at_offsets(file: &[u8], idx: &pcap_engine::core::PacketIndex, expected: &[&[u8]]) {
    assert_eq!(idx.len(), expected.len());
    for (i, want) in expected.iter().enumerate() {
        let off = idx.offset[i] as usize;
        let cap = idx.cap_len[i] as usize;
        assert_eq!(&file[off..off + cap], *want, "packet {i} bytes at recorded offset");
    }
}

// ---------- legacy pcap ----------

#[test]
fn pcap_micro_little_endian() {
    let a = eth_ipv4_packet(b"hello");
    let b = eth_ipv4_packet(b"world!!");
    let file = pcap_file(
        Endian::LE,
        false,
        1,
        &[
            Pkt { ts_sec: RES_MICRO, ts_frac: 250_000, orig_len: a.len() as u32, data: &a },
            // captured shorter than original (snaplen-style truncation)
            Pkt { ts_sec: RES_MICRO + 1, ts_frac: 5, orig_len: 1500, data: &b },
        ],
    );
    let idx = parse_capture(&file).unwrap();
    assert_eq!(idx.format, Format::Pcap);
    assert!(idx.complete);
    assert_eq!(idx.ts_sec, vec![RES_MICRO, RES_MICRO + 1]);
    assert_eq!(idx.ts_nsec, vec![250_000_000, 5_000]);
    assert_eq!(idx.orig_len, vec![a.len() as u32, 1500]);
    assert_eq!(idx.cap_len, vec![a.len() as u32, b.len() as u32]);
    assert_eq!(idx.linktype, vec![1, 1]);
    assert_data_at_offsets(&file, &idx, &[&a, &b]);
}

#[test]
fn pcap_nano_little_endian() {
    let a = eth_ipv4_packet(b"x");
    let file = pcap_file(
        Endian::LE,
        true,
        1,
        &[Pkt { ts_sec: 10, ts_frac: 123_456_789, orig_len: a.len() as u32, data: &a }],
    );
    let idx = parse_capture(&file).unwrap();
    assert_eq!(idx.ts_sec, vec![10]);
    assert_eq!(idx.ts_nsec, vec![123_456_789]);
}

#[test]
fn pcap_micro_big_endian() {
    let a = eth_ipv4_packet(b"be");
    let file = pcap_file(
        Endian::BE,
        false,
        1,
        &[Pkt { ts_sec: 99, ts_frac: 999_999, orig_len: a.len() as u32, data: &a }],
    );
    let idx = parse_capture(&file).unwrap();
    assert_eq!(idx.ts_sec, vec![99]);
    assert_eq!(idx.ts_nsec, vec![999_999_000]);
    assert_data_at_offsets(&file, &idx, &[&a]);
}

#[test]
fn pcap_nano_big_endian() {
    let a = eth_ipv4_packet(b"be-nano");
    let file = pcap_file(
        Endian::BE,
        true,
        127,
        &[Pkt { ts_sec: 7, ts_frac: 42, orig_len: a.len() as u32, data: &a }],
    );
    let idx = parse_capture(&file).unwrap();
    assert_eq!(idx.ts_nsec, vec![42]);
    assert_eq!(idx.linktype, vec![127]);
}

#[test]
fn pcap_header_only_is_valid_and_empty() {
    let file = pcap_file(Endian::LE, false, 1, &[]);
    let idx = parse_capture(&file).unwrap();
    assert!(idx.is_empty());
    assert!(idx.complete);
}

#[test]
fn pcap_truncated_mid_packet_keeps_earlier_packets() {
    let a = eth_ipv4_packet(b"first");
    let b = eth_ipv4_packet(b"second-packet");
    let full = pcap_file(
        Endian::LE,
        false,
        1,
        &[
            Pkt { ts_sec: 1, ts_frac: 0, orig_len: a.len() as u32, data: &a },
            Pkt { ts_sec: 2, ts_frac: 0, orig_len: b.len() as u32, data: &b },
        ],
    );
    let cut = &full[..full.len() - 5];
    let idx = parse_capture(cut).unwrap();
    assert_eq!(idx.len(), 1);
    assert!(!idx.complete);
    assert!(!idx.issues.is_empty());
    assert_data_at_offsets(cut, &idx, &[&a]);
}

#[test]
fn pcap_truncated_in_record_header() {
    let a = eth_ipv4_packet(b"first");
    let full = pcap_file(
        Endian::LE,
        false,
        1,
        &[
            Pkt { ts_sec: 1, ts_frac: 0, orig_len: a.len() as u32, data: &a },
            Pkt { ts_sec: 2, ts_frac: 0, orig_len: a.len() as u32, data: &a },
        ],
    );
    // Leave only 6 bytes of the second record header.
    let first_end = 24 + 16 + a.len();
    let idx = parse_capture(&full[..first_end + 6]).unwrap();
    assert_eq!(idx.len(), 1);
    assert!(!idx.complete);
}

// ---------- pcapng ----------

#[test]
fn pcapng_multi_interface_with_different_resolutions() {
    let e = Endian::LE;
    let a = eth_ipv4_packet(b"iface0");
    let b = eth_ipv4_packet(b"iface1");
    // if 0: Ethernet, default (microsecond) resolution
    // if 1: RadioTap, nanosecond resolution (if_tsresol = 9)
    let file = concat(&[
        shb(e),
        idb(e, 1, None),
        idb(e, 127, Some(9)),
        epb(e, 0, 1_700_000_000u64 * 1_000_000 + 250_000, a.len() as u32, &a),
        epb(e, 1, 1_700_000_001u64 * 1_000_000_000 + 123_456_789, b.len() as u32, &b),
    ]);
    let idx = parse_capture(&file).unwrap();
    assert_eq!(idx.format, Format::PcapNg);
    assert!(idx.complete);
    assert_eq!(idx.linktype, vec![1, 127]);
    assert_eq!(idx.ts_sec, vec![1_700_000_000, 1_700_000_001]);
    assert_eq!(idx.ts_nsec, vec![250_000_000, 123_456_789]);
    assert_data_at_offsets(&file, &idx, &[&a, &b]);
}

#[test]
fn pcapng_millisecond_resolution() {
    let e = Endian::LE;
    let a = eth_ipv4_packet(b"ms");
    let file = concat(&[
        shb(e),
        idb(e, 1, Some(3)), // 10^3 ticks per second
        epb(e, 0, 5_500, a.len() as u32, &a), // 5.5 s
    ]);
    let idx = parse_capture(&file).unwrap();
    assert_eq!(idx.ts_sec, vec![5]);
    assert_eq!(idx.ts_nsec, vec![500_000_000]);
}

#[test]
fn pcapng_big_endian() {
    let e = Endian::BE;
    let a = eth_ipv4_packet(b"big");
    let file = concat(&[shb(e), idb(e, 1, Some(9)), epb(e, 0, 3_000_000_042, a.len() as u32, &a)]);
    let idx = parse_capture(&file).unwrap();
    assert_eq!(idx.ts_sec, vec![3]);
    assert_eq!(idx.ts_nsec, vec![42]);
    assert_data_at_offsets(&file, &idx, &[&a]);
}

#[test]
fn pcapng_unpadded_packet_length_uses_caplen() {
    // 5-byte packet forces 3 bytes of block padding.
    let e = Endian::LE;
    let data = [1u8, 2, 3, 4, 5];
    let file = concat(&[shb(e), idb(e, 1, None), epb(e, 0, 1_000_000, 5, &data)]);
    let idx = parse_capture(&file).unwrap();
    assert_eq!(idx.cap_len, vec![5]);
    assert_data_at_offsets(&file, &idx, &[&data]);
}

#[test]
fn pcapng_new_section_resets_interfaces() {
    let e = Endian::LE;
    let a = eth_ipv4_packet(b"s1");
    let b = eth_ipv4_packet(b"s2");
    let file = concat(&[
        shb(e),
        idb(e, 1, Some(9)),
        epb(e, 0, 1_000_000_000, a.len() as u32, &a),
        shb(e),
        idb(e, 127, None), // new section: interface 0 is now RadioTap, microseconds
        epb(e, 0, 2_000_000, b.len() as u32, &b),
    ]);
    let idx = parse_capture(&file).unwrap();
    assert_eq!(idx.linktype, vec![1, 127]);
    assert_eq!(idx.ts_sec, vec![1, 2]);
}

#[test]
fn pcapng_packet_for_undeclared_interface_is_kept_with_warning() {
    let e = Endian::LE;
    let a = eth_ipv4_packet(b"?");
    let file = concat(&[shb(e), epb(e, 3, 1_000_000, a.len() as u32, &a)]);
    let idx = parse_capture(&file).unwrap();
    assert_eq!(idx.len(), 1);
    assert!(idx.complete);
    assert!(!idx.issues.is_empty());
}

#[test]
fn pcapng_truncated_keeps_earlier_packets() {
    let e = Endian::LE;
    let a = eth_ipv4_packet(b"one");
    let b = eth_ipv4_packet(b"two-two");
    let full = concat(&[
        shb(e),
        idb(e, 1, None),
        epb(e, 0, 1_000_000, a.len() as u32, &a),
        epb(e, 0, 2_000_000, b.len() as u32, &b),
    ]);
    let cut = &full[..full.len() - 9];
    let idx = parse_capture(cut).unwrap();
    assert_eq!(idx.len(), 1);
    assert!(!idx.complete);
    assert!(!idx.issues.is_empty());
}

#[test]
fn pcapng_with_no_packets() {
    let e = Endian::LE;
    let file = concat(&[shb(e), idb(e, 1, None)]);
    let idx = parse_capture(&file).unwrap();
    assert!(idx.is_empty());
    assert!(idx.complete);
}

// ---------- rejection & robustness ----------

#[test]
fn empty_and_tiny_inputs_are_rejected() {
    assert_eq!(parse_capture(&[]).unwrap_err(), ParseError::TooShort);
    assert_eq!(parse_capture(&[0xd4, 0xc3, 0xb2, 0xa1]).unwrap_err(), ParseError::TooShort);
}

#[test]
fn garbage_is_rejected() {
    let junk = vec![0x42u8; 4096];
    assert_eq!(parse_capture(&junk).unwrap_err(), ParseError::NotACapture);
    let text = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: not-a-pcap\r\n\r\n";
    assert_eq!(parse_capture(text).unwrap_err(), ParseError::NotACapture);
}

#[test]
fn every_truncation_point_is_handled_without_panic() {
    let e = Endian::LE;
    let a = eth_ipv4_packet(b"payload-a");
    let b = eth_ipv4_packet(b"payload-bb");
    let ng = concat(&[
        shb(e),
        idb(e, 1, Some(9)),
        epb(e, 0, 1_000_000_000, a.len() as u32, &a),
        epb(e, 0, 2_000_000_000, b.len() as u32, &b),
    ]);
    let legacy = pcap_file(
        e,
        false,
        1,
        &[
            Pkt { ts_sec: 1, ts_frac: 0, orig_len: a.len() as u32, data: &a },
            Pkt { ts_sec: 2, ts_frac: 0, orig_len: b.len() as u32, data: &b },
        ],
    );
    for file in [&ng, &legacy] {
        for cut in 0..=file.len() {
            match parse_capture(&file[..cut]) {
                Ok(idx) => {
                    // Whatever was parsed must point at real bytes in the input.
                    for i in 0..idx.len() {
                        let end = idx.offset[i] as usize + idx.cap_len[i] as usize;
                        assert!(end <= cut, "packet {i} extends past truncated input");
                    }
                }
                Err(_) => {}
            }
        }
    }
}

#[test]
fn corrupted_bytes_never_panic() {
    let e = Endian::LE;
    let a = eth_ipv4_packet(b"payload");
    let base = concat(&[
        shb(e),
        idb(e, 1, None),
        epb(e, 0, 1_000_000, a.len() as u32, &a),
        epb(e, 0, 2_000_000, a.len() as u32, &a),
    ]);
    for i in 0..base.len() {
        for flip in [0x00u8, 0xff, 0x80] {
            let mut f = base.clone();
            f[i] = flip;
            if let Ok(idx) = parse_capture(&f) {
                for j in 0..idx.len() {
                    let end = idx.offset[j] as usize + idx.cap_len[j] as usize;
                    assert!(end <= f.len());
                }
            }
        }
    }
}
