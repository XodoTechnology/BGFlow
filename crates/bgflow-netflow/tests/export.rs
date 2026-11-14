//! Encoder roundtrip tests: FlowExporter output is fed back through our
//! own NetFlow v9 / IPFIX decoders — the strongest available check that
//! templates, field layouts and headers are wire-correct.

use bgflow_netflow::{
    parse_datagram, ExportProto, FlowExporter, ProtoHint, SessionState, DEFAULT_TEMPLATE_REFRESH_MS,
};
use bgflow_types::{ip_to_u128, ip_string, FlowRecord};
use std::net::{IpAddr, Ipv4Addr};

const EXPORTER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const NOW_MS: u64 = 1_700_000_000_000;
const BOOT_MS: i64 = NOW_MS as i64 - 3_600_000; // daemon "up" 1h

fn v4(a: u8, b: u8, c: u8, d: u8) -> u128 {
    ip_to_u128(&IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
}

fn flow(src: u128, dst: u128, sp: u16, dp: u16, bytes: u64) -> FlowRecord {
    FlowRecord {
        ts_ms: NOW_MS - 5_000,
        duration_ms: 4_000,
        src_ip: src,
        dst_ip: dst,
        src_port: sp,
        dst_port: dp,
        protocol: 6,
        tcp_flags: 0x18,
        bytes,
        packets: bytes / 100,
        src_asn: 64512,
        dst_asn: 15169,
        vlan: 100,
        ingress_if: 1,
        egress_if: 2,
        ip_ttl: 64,
        ..Default::default()
    }
}

fn sample_flows() -> Vec<FlowRecord> {
    let v6a = ip_to_u128(&"2001:db8::1".parse::<IpAddr>().unwrap());
    let v6b = ip_to_u128(&"2001:db8::2".parse::<IpAddr>().unwrap());
    vec![
        flow(v4(192, 0, 2, 1), v4(203, 0, 113, 9), 40000, 443, 5000),
        flow(v4(10, 1, 2, 3), v4(8, 8, 8, 8), 51000, 53, 1200),
        flow(v6a, v6b, 1234, 80, 999),
        // mixed family -> v6 template with v4-mapped src
        flow(v4(172, 16, 0, 1), v6b, 9999, 8080, 77),
    ]
}

fn roundtrip(proto: ExportProto, hint: ProtoHint) -> Vec<FlowRecord> {
    let mut ex = FlowExporter::new(proto, 1, BOOT_MS, DEFAULT_TEMPLATE_REFRESH_MS);
    let datagrams = ex.encode(&sample_flows(), NOW_MS, 1400);
    assert!(!datagrams.is_empty());
    let mut st = SessionState::default();
    let mut out = Vec::new();
    for d in &datagrams {
        assert!(d.len() <= 1400 + 8, "datagram {} bytes exceeds cap", d.len());
        out.extend(parse_datagram(&mut st, hint, d, EXPORTER, NOW_MS));
    }
    out
}

#[test]
fn netflow_v9_roundtrip() {
    let recs = roundtrip(ExportProto::NetFlow9, ProtoHint::NetFlow9);
    assert_eq!(recs.len(), 4, "all four flows decoded");
    let a = recs
        .iter()
        .find(|r| ip_string(r.src_ip).ends_with("192.0.2.1"))
        .expect("v4 flow present");
    assert_eq!(ip_string(a.dst_ip), "203.0.113.9");
    assert_eq!(a.src_port, 40000);
    assert_eq!(a.dst_port, 443);
    assert_eq!(a.protocol, 6);
    assert_eq!(a.tcp_flags, 0x18);
    assert_eq!(a.bytes, 5000);
    assert_eq!(a.packets, 50);
    assert_eq!(a.src_asn, 64512);
    assert_eq!(a.dst_asn, 15169);
    assert_eq!(a.vlan, 100);
    assert_eq!(a.ingress_if, 1);
    assert_eq!(a.egress_if, 2);
    assert_eq!(a.ip_ttl, 64);
    // timestamps reconstruct exactly (flow ts is NOW-5s by fixture design)
    assert!((a.ts_ms as i64 - (NOW_MS as i64 - 5000)).abs() < 2000);

    // v6 flow decoded with full addresses
    let v6 = recs
        .iter()
        .find(|r| ip_string(r.src_ip).contains(':'))
        .expect("v6 flow present");
    assert!(ip_string(v6.src_ip).starts_with("2001:db8"));
    assert_eq!(v6.dst_port, 80);
}

#[test]
fn ipfix_roundtrip() {
    let recs = roundtrip(ExportProto::Ipfix, ProtoHint::Ipfix);
    assert_eq!(recs.len(), 4);
    let a = recs
        .iter()
        .find(|r| ip_string(r.src_ip).ends_with("192.0.2.1"))
        .expect("v4 flow present");
    assert_eq!(a.bytes, 5000);
    assert_eq!(a.src_port, 40000);
}

#[test]
fn templates_refresh_and_packing() {
    let mut ex = FlowExporter::new(ExportProto::NetFlow9, 7, BOOT_MS, 3_600_000);
    let flows = sample_flows();
    // First datagram carries template flowsets (set id 0).
    let d1 = ex.encode(&flows, NOW_MS, 1400);
    assert!(!d1.is_empty());
    let first = &d1[0];
    // RFC 3954 v9 header is 20 bytes — first set id sits at offset 20.
    assert_eq!(u16::from_be_bytes([first[20], first[21]]), 0, "template set first");
    // Same timestamp again -> no templates.
    let d2 = ex.encode(&flows, NOW_MS + 60_000, 1400);
    let has_template = d2.iter().any(|d| {
        d.len() > 22 && u16::from_be_bytes([d[20], d[21]]) == 0
    });
    assert!(!has_template, "no template resend within refresh window");
    // Past refresh window -> templates again.
    let d3 = ex.encode(&flows, NOW_MS + 3_700_000, 1400);
    let has_template = d3.iter().any(|d| {
        d.len() > 22 && u16::from_be_bytes([d[20], d[21]]) == 0
    });
    assert!(has_template, "template resent after refresh window");
}

#[test]
fn empty_and_small_datagrams() {
    let mut ex = FlowExporter::new(ExportProto::NetFlow9, 1, BOOT_MS, 3_600_000);
    assert!(ex.encode(&[], NOW_MS, 1400).is_empty());
    // Small-ish cap forces multiple datagrams (templates alone ~192B) —
    // every one must fit and decode.
    let dgrams = ex.encode(&sample_flows(), NOW_MS, 420);
    assert!(dgrams.len() > 1, "small cap splits datagrams");
    let mut st = SessionState::default();
    let mut n = 0;
    for d in &dgrams {
        assert!(d.len() <= 420 + 8, "datagram {} over cap", d.len());
        n += parse_datagram(&mut st, ProtoHint::NetFlow9, d, EXPORTER, NOW_MS).len();
    }
    assert_eq!(n, 4, "all flows survive datagram splitting");
}
