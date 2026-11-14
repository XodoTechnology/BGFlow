//! Parser tests: hand-crafted wire fixtures for NetFlow v5/v9, IPFIX,
//! sFlow, plus malformed-input robustness checks.

use bgflow_netflow::{parse_datagram, IpfixTcpDecoder, ProtoHint, SessionState};
use bgflow_types::{ip_string, u128_to_ip};
use std::net::{IpAddr, Ipv4Addr};

const EXPORTER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const NOW_MS: u64 = 1_700_000_000_000;

fn v4_last(ip: u128) -> String {
    ip_string(ip)
}

// ---------------------------------------------------------------------------
// NetFlow v5
// ---------------------------------------------------------------------------

fn nfv5_datagram() -> Vec<u8> {
    let mut p = Vec::new();
    let now_s = 1_700_000_000u32;
    // header: ver=5, count=2, sysUpTime=60_000ms, unixSecs, unixNsecs=0,
    // flowSeq=1, engineType=1, engineId=0, sampling=0
    p.extend_from_slice(&5u16.to_be_bytes());
    p.extend_from_slice(&2u16.to_be_bytes());
    p.extend_from_slice(&60_000u32.to_be_bytes());
    p.extend_from_slice(&now_s.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.push(1);
    p.push(0);
    p.extend_from_slice(&0u16.to_be_bytes());

    // record 1: 192.168.1.10:12345 -> 8.8.8.8:53 UDP, 10 pkts, 840 B
    let mut r = Vec::new();
    r.extend_from_slice(&[192, 168, 1, 10]);
    r.extend_from_slice(&[8, 8, 8, 8]);
    r.extend_from_slice(&[10, 0, 0, 1]); // nexthop
    r.extend_from_slice(&1u16.to_be_bytes()); // input
    r.extend_from_slice(&2u16.to_be_bytes()); // output
    r.extend_from_slice(&10u32.to_be_bytes()); // dPkts
    r.extend_from_slice(&840u32.to_be_bytes()); // dOctets
    r.extend_from_slice(&59_000u32.to_be_bytes()); // first (ms since boot)
    r.extend_from_slice(&60_000u32.to_be_bytes()); // last
    r.extend_from_slice(&12345u16.to_be_bytes()); // srcport
    r.extend_from_slice(&53u16.to_be_bytes()); // dstport
    r.push(0); // pad
    r.push(0); // tcp_flags
    r.push(17); // proto UDP
    r.push(0); // tos
    r.extend_from_slice(&65001u16.to_be_bytes()); // src_as
    r.extend_from_slice(&15169u16.to_be_bytes()); // dst_as
    r.push(24); // src_mask
    r.push(24); // dst_mask
    r.extend_from_slice(&0u16.to_be_bytes()); // pad2
    assert_eq!(r.len(), 48);
    p.extend_from_slice(&r);

    // record 2: 10.0.0.5:443 -> 1.1.1.1:8443 TCP
    let mut r2 = r.clone();
    r2[0..4].copy_from_slice(&[10, 0, 0, 5]);
    r2[4..8].copy_from_slice(&[1, 1, 1, 1]);
    r2[32..34].copy_from_slice(&443u16.to_be_bytes());
    r2[34..36].copy_from_slice(&8443u16.to_be_bytes());
    r2[36] = 0;
    r2[37] = 0x12; // tcp flags SYN+ACK
    r2[38] = 6; // TCP
    r2[16..20].copy_from_slice(&3u32.to_be_bytes());
    r2[20..24].copy_from_slice(&2920u32.to_be_bytes());
    p.extend_from_slice(&r2);
    p
}

#[test]
fn netflow_v5_parses_records() {
    let mut st = SessionState::default();
    let recs = parse_datagram(&mut st, ProtoHint::Auto, &nfv5_datagram(), EXPORTER, NOW_MS);
    assert_eq!(recs.len(), 2);

    let a = &recs[0];
    assert_eq!(v4_last(a.src_ip), "192.168.1.10");
    assert_eq!(v4_last(a.dst_ip), "8.8.8.8");
    assert_eq!(a.src_port, 12345);
    assert_eq!(a.dst_port, 53);
    assert_eq!(a.protocol, 17);
    assert_eq!(a.packets, 10);
    assert_eq!(a.bytes, 840);
    assert_eq!(a.src_asn, 65001);
    assert_eq!(a.dst_asn, 15169);
    // ts: boot = export(1.7e12) - uptime(60s) ; last=60s -> ts = 1.7e12
    assert_eq!(a.ts_ms, 1_700_000_000_000);
    assert_eq!(a.duration_ms, 1000);
    assert_eq!(v4_last(a.exporter), "10.0.0.1");

    let b = &recs[1];
    assert_eq!(b.protocol, 6);
    assert_eq!(b.tcp_flags, 0x12);
    assert_eq!(b.packets, 3);
    assert_eq!(b.bytes, 2920);
}

#[test]
fn netflow_v5_truncated_and_garbage() {
    let mut st = SessionState::default();
    assert!(parse_datagram(&mut st, ProtoHint::Auto, &[], EXPORTER, NOW_MS).is_empty());
    assert!(parse_datagram(&mut st, ProtoHint::Auto, &[0u8; 10], EXPORTER, NOW_MS).is_empty());
    // header only, count=5 but no records
    let mut p = nfv5_datagram();
    p.truncate(24);
    assert!(parse_datagram(&mut st, ProtoHint::NetFlow5, &p, EXPORTER, NOW_MS).is_empty());
    // random garbage doesn't panic
    let garbage = vec![0xabu8; 500];
    let _ = parse_datagram(&mut st, ProtoHint::Auto, &garbage, EXPORTER, NOW_MS);
}

// ---------------------------------------------------------------------------
// NetFlow v9
// ---------------------------------------------------------------------------

/// Build an NFv9 template field entry: (ie, len).
fn nfv9_field(ie: u16, len: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ie.to_be_bytes());
    v.extend_from_slice(&len.to_be_bytes());
    v
}

fn nfv9_header(count: u16, sysup: u32, unix: u32, domain: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&9u16.to_be_bytes());
    p.extend_from_slice(&count.to_be_bytes());
    p.extend_from_slice(&sysup.to_be_bytes());
    p.extend_from_slice(&unix.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes()); // sequence number (RFC 3954)
    p.extend_from_slice(&domain.to_be_bytes()); // source id
    p
}

fn nfv9_flowset(set_id: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&set_id.to_be_bytes());
    v.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// Template 256 with common flow fields.
fn nfv9_template_body() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&256u16.to_be_bytes()); // template id
    let fields: &[(u16, u16)] = &[
        (8, 4),   // src ipv4
        (12, 4),  // dst ipv4
        (7, 2),   // src port
        (11, 2),  // dst port
        (4, 1),   // protocol
        (1, 4),   // octet delta count
        (2, 4),   // packet delta count
        (21, 4),  // flow end sysup time
        (22, 4),  // flow start sysup time
        (16, 4),  // bgp src as
        (17, 4),  // bgp dst as
    ];
    b.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for (ie, l) in fields {
        b.extend_from_slice(&nfv9_field(*ie, *l));
    }
    b
}

fn nfv9_record(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, proto: u8,
               bytes: u32, pkts: u32, first: u32, last: u32, sas: u32, das: u32) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&src);
    r.extend_from_slice(&dst);
    r.extend_from_slice(&sport.to_be_bytes());
    r.extend_from_slice(&dport.to_be_bytes());
    r.push(proto);
    r.extend_from_slice(&bytes.to_be_bytes());
    r.extend_from_slice(&pkts.to_be_bytes());
    r.extend_from_slice(&first.to_be_bytes());
    r.extend_from_slice(&last.to_be_bytes());
    r.extend_from_slice(&sas.to_be_bytes());
    r.extend_from_slice(&das.to_be_bytes());
    r
}

#[test]
fn netflow_v9_template_then_data() {
    let mut st = SessionState::default();
    // Packet 1: template set only (count=1)
    let mut p1 = nfv9_header(1, 5_000, 1_700_000_000, 0);
    let tset = nfv9_flowset(0, &nfv9_template_body());
    p1.extend_from_slice(&tset);
    let r1 = parse_datagram(&mut st, ProtoHint::NetFlow9, &p1, EXPORTER, NOW_MS);
    assert!(r1.is_empty(), "template-only packet yields no flows");

    // Packet 2: data set id=256 with one record (33 bytes)
    // NOTE: record field order follows the template — field 21 (end sysup)
    // precedes field 22 (start sysup).
    let rec = nfv9_record(
        [10, 1, 2, 3], [8, 8, 4, 4], 51000, 443, 6, 1_000_000, 500, 5_000, 4_000, 64512, 15169,
    );
    let mut p2 = nfv9_header(1, 5_000, 1_700_000_000, 0);
    let dset = nfv9_flowset(256, &rec);
    p2.extend_from_slice(&dset);
    let recs = parse_datagram(&mut st, ProtoHint::NetFlow9, &p2, EXPORTER, NOW_MS);
    assert_eq!(recs.len(), 1);
    let f = &recs[0];
    assert_eq!(v4_last(f.src_ip), "10.1.2.3");
    assert_eq!(v4_last(f.dst_ip), "8.8.4.4");
    assert_eq!(f.src_port, 51000);
    assert_eq!(f.dst_port, 443);
    assert_eq!(f.protocol, 6);
    assert_eq!(f.bytes, 1_000_000);
    assert_eq!(f.packets, 500);
    assert_eq!(f.src_asn, 64512);
    assert_eq!(f.dst_asn, 15169);
    // boot = unix*1000 - sysup(5000) ; end_sysup=5000 -> ts = unix*1000
    assert_eq!(f.ts_ms, 1_700_000_000_000);
    assert_eq!(f.duration_ms, 1000);

    // Same datagram containing template+data also works (single packet).
    let mut st2 = SessionState::default();
    let mut p3 = nfv9_header(2, 5_000, 1_700_000_000, 0);
    p3.extend_from_slice(&nfv9_flowset(0, &nfv9_template_body()));
    p3.extend_from_slice(&nfv9_flowset(256, &rec));
    let recs3 = parse_datagram(&mut st2, ProtoHint::NetFlow9, &p3, EXPORTER, NOW_MS);
    assert_eq!(recs3.len(), 1);
}

#[test]
fn netflow_v9_bad_set_length_stops() {
    let mut st = SessionState::default();
    // count=1, set claims length 60000 (> payload) -> no records, no panic
    let mut p = nfv9_header(1, 0, 1_700_000_000, 0);
    p.extend_from_slice(&0u16.to_be_bytes()); // set id 0
    p.extend_from_slice(&60000u16.to_be_bytes()); // absurd length
    p.extend_from_slice(&[0u8; 20]);
    let recs = parse_datagram(&mut st, ProtoHint::NetFlow9, &p, EXPORTER, NOW_MS);
    assert!(recs.is_empty());
}

// ---------------------------------------------------------------------------
// IPFIX
// ---------------------------------------------------------------------------

fn ipfix_field(ie: u16, len: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ie.to_be_bytes());
    v.extend_from_slice(&len.to_be_bytes());
    v
}

fn ipfix_ent_field(ie: u16, len: u16, pen: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(ie | 0x8000).to_be_bytes());
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(&pen.to_be_bytes());
    v
}

fn ipfix_header(msg_len: usize, export: u32, domain: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&10u16.to_be_bytes());
    p.extend_from_slice(&(msg_len as u16).to_be_bytes());
    p.extend_from_slice(&export.to_be_bytes());
    p.extend_from_slice(&7u32.to_be_bytes()); // seq
    p.extend_from_slice(&domain.to_be_bytes());
    p
}

fn ipfix_set(set_id: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&set_id.to_be_bytes());
    v.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// IPFIX template 300: v4 addrs, ports, proto, octet count, one enterprise
/// field (8 bytes, ignored), one variable-length field (ignored).
fn ipfix_template_body() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&300u16.to_be_bytes());
    let nfields = 8u16;
    b.extend_from_slice(&nfields.to_be_bytes());
    b.extend_from_slice(&ipfix_field(8, 4));    // src ipv4
    b.extend_from_slice(&ipfix_field(12, 4));   // dst ipv4
    b.extend_from_slice(&ipfix_field(7, 2));    // src port
    b.extend_from_slice(&ipfix_field(11, 2));   // dst port
    b.extend_from_slice(&ipfix_field(4, 1));    // protocol
    b.extend_from_slice(&ipfix_field(85, 4));   // octet total count
    b.extend_from_slice(&ipfix_ent_field(999, 8, 29305)); // enterprise, skipped
    b.extend_from_slice(&ipfix_field(230, 0xffff));       // variable-length, skipped
    b
}

fn ipfix_datagram() -> Vec<u8> {
    // data record: src 192.0.2.1:40000 -> dst 203.0.113.9:443 TCP,
    // 5000 octets, enterprise 8B, vlen "hello" (5 bytes)
    let mut rec = Vec::new();
    rec.extend_from_slice(&[192, 0, 2, 1]);
    rec.extend_from_slice(&[203, 0, 113, 9]);
    rec.extend_from_slice(&40000u16.to_be_bytes());
    rec.extend_from_slice(&443u16.to_be_bytes());
    rec.push(6);
    rec.extend_from_slice(&5000u32.to_be_bytes());
    rec.extend_from_slice(&[0xAA; 8]); // enterprise payload
    rec.push(5); // vlen length
    rec.extend_from_slice(b"hello");

    let tset = ipfix_set(2, &ipfix_template_body());
    let dset = ipfix_set(300, &rec);
    let msg_len = 16 + tset.len() + dset.len();
    let mut p = ipfix_header(msg_len, 1_700_000_000, 9);
    p.extend_from_slice(&tset);
    p.extend_from_slice(&dset);
    p
}

#[test]
fn ipfix_template_data_variable_length() {
    let mut st = SessionState::default();
    let recs = parse_datagram(&mut st, ProtoHint::Ipfix, &ipfix_datagram(), EXPORTER, NOW_MS);
    assert_eq!(recs.len(), 1, "template+data in one message");
    let f = &recs[0];
    assert_eq!(v4_last(f.src_ip), "192.0.2.1");
    assert_eq!(v4_last(f.dst_ip), "203.0.113.9");
    assert_eq!(f.src_port, 40000);
    assert_eq!(f.dst_port, 443);
    assert_eq!(f.protocol, 6);
    assert_eq!(f.bytes, 5000);
    // No sysUpTime fields -> boot estimate defaults; ts falls back to export time.
    assert_eq!(f.ts_ms, 1_700_000_000_000);
}

#[test]
fn ipfix_two_records_in_set() {
    let mut st = SessionState::default();
    let rec1 = {
        let mut r = Vec::new();
        r.extend_from_slice(&[10, 0, 0, 1]);
        r.extend_from_slice(&[10, 0, 0, 2]);
        r.extend_from_slice(&1000u16.to_be_bytes());
        r.extend_from_slice(&2000u16.to_be_bytes());
        r.push(17);
        r.extend_from_slice(&100u32.to_be_bytes());
        r.extend_from_slice(&[0u8; 8]);
        r.push(0); // vlen len 0
        r
    };
    let rec2 = rec1.clone();
    let mut body = rec1;
    body.extend_from_slice(&rec2);

    let tset = ipfix_set(2, &ipfix_template_body());
    let dset = ipfix_set(300, &body);
    let msg_len = 16 + tset.len() + dset.len();
    let mut p = ipfix_header(msg_len, 1_700_000_000, 4);
    p.extend_from_slice(&tset);
    p.extend_from_slice(&dset);
    let recs = parse_datagram(&mut st, ProtoHint::Ipfix, &p, EXPORTER, NOW_MS);
    assert_eq!(recs.len(), 2, "two variable-length records decoded");
}

#[test]
fn ipfix_truncated_and_bad_length() {
    let mut st = SessionState::default();
    // too short
    assert!(parse_datagram(&mut st, ProtoHint::Ipfix, &[0u8; 8], EXPORTER, NOW_MS).is_empty());
    // header claims huge length but payload short -> parses what's there
    let mut p = ipfix_header(60000, 1_700_000_000, 1);
    p.extend_from_slice(&[0u8; 10]);
    let _ = parse_datagram(&mut st, ProtoHint::Ipfix, &p, EXPORTER, NOW_MS);
    // garbage
    let _ = parse_datagram(&mut st, ProtoHint::Auto, &vec![0xffu8; 300], EXPORTER, NOW_MS);
}

// ---------------------------------------------------------------------------
// sFlow
// ---------------------------------------------------------------------------

fn xdr_addr_v4(a: [u8; 4]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&1u32.to_be_bytes()); // AF=1 IPv4
    v.extend_from_slice(&a);
    v
}

fn sflow_datagram() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&5u32.to_be_bytes()); // version
    p.extend_from_slice(&xdr_addr_v4([10, 0, 0, 1])); // agent
    p.extend_from_slice(&0u32.to_be_bytes()); // sub agent
    p.extend_from_slice(&42u32.to_be_bytes()); // seq
    p.extend_from_slice(&1_000_000u32.to_be_bytes()); // uptime ms
    p.extend_from_slice(&1u32.to_be_bytes()); // num samples

    // flow sample body:
    // seq u32, source_id u32, sampling_rate u32, pool u32, drops u32,
    // input u32, output u32, num_records u32
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes()); // sample seq
    body.extend_from_slice(&0u32.to_be_bytes()); // source id (interlaced)
    body.extend_from_slice(&100u32.to_be_bytes()); // sampling rate 1:100
    body.extend_from_slice(&0u32.to_be_bytes()); // pool
    body.extend_from_slice(&0u32.to_be_bytes()); // drops
    body.extend_from_slice(&1u32.to_be_bytes()); // input if
    body.extend_from_slice(&2u32.to_be_bytes()); // output if
    body.extend_from_slice(&1u32.to_be_bytes()); // num records

    // sampled_ipv4 record (format=3): ip_len, proto, src4, dst4,
    // sport u32, dport u32, tcp_flags u32, tos u32
    let mut rec = Vec::new();
    rec.extend_from_slice(&500u32.to_be_bytes()); // ip packet len
    rec.extend_from_slice(&6u32.to_be_bytes()); // TCP
    rec.extend_from_slice(&[192, 168, 1, 5]);
    rec.extend_from_slice(&[93, 184, 216, 34]);
    rec.extend_from_slice(&51000u32.to_be_bytes());
    rec.extend_from_slice(&443u32.to_be_bytes());
    rec.extend_from_slice(&0x12u32.to_be_bytes()); // tcp flags
    rec.extend_from_slice(&0u32.to_be_bytes()); // tos

    body.extend_from_slice(&3u32.to_be_bytes()); // data_format sampled_ipv4
    body.extend_from_slice(&(rec.len() as u32).to_be_bytes());
    body.extend_from_slice(&rec);

    // sample header: format=1 (flow), length=body.len()
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(&(body.len() as u32).to_be_bytes());
    p.extend_from_slice(&body);
    p
}

#[test]
fn sflow_sampled_ipv4_with_sampling() {
    let mut st = SessionState::default();
    let now = 1_700_000_000_000u64;
    let recs = parse_datagram(&mut st, ProtoHint::SFlow, &sflow_datagram(), EXPORTER, now);
    assert_eq!(recs.len(), 1);
    let f = &recs[0];
    assert_eq!(v4_last(f.src_ip), "192.168.1.5");
    assert_eq!(v4_last(f.dst_ip), "93.184.216.34");
    assert_eq!(f.src_port, 51000);
    assert_eq!(f.dst_port, 443);
    assert_eq!(f.protocol, 6);
    assert_eq!(f.tcp_flags, 0x12);
    // sampling rate 100: bytes=500*100, packets=1*100
    assert_eq!(f.bytes, 50_000);
    assert_eq!(f.packets, 100);
    assert_eq!(f.sampler_interval, 100);
    assert_eq!(v4_last(f.exporter), "10.0.0.1"); // agent addr, not UDP src
    assert_eq!(f.ts_ms, now); // sFlow uses receipt time
    assert_eq!(f.ingress_if, 1);
    assert_eq!(f.egress_if, 2);
}

#[test]
fn sflow_garbage_and_wrong_version() {
    let mut st = SessionState::default();
    // version 6 -> rejected
    let mut p = sflow_datagram();
    p[0..4].copy_from_slice(&6u32.to_be_bytes());
    assert!(parse_datagram(&mut st, ProtoHint::SFlow, &p, EXPORTER, NOW_MS).is_empty());
    // truncated mid-sample -> no panic, partial/empty
    let p2 = sflow_datagram();
    let cut = &p2[..p2.len() - 10];
    let _ = parse_datagram(&mut st, ProtoHint::SFlow, cut, EXPORTER, NOW_MS);
    // auto-detect picks sFlow by version u32==5
    let recs = parse_datagram(&mut st, ProtoHint::Auto, &sflow_datagram(), EXPORTER, NOW_MS);
    assert_eq!(recs.len(), 1);
}

// ---------------------------------------------------------------------------
// Auto-detection
// ---------------------------------------------------------------------------

#[test]
fn auto_detect_dispatches_correctly() {
    let mut st = SessionState::default();
    // v5 packet -> version u16 = 5
    let r5 = parse_datagram(&mut st, ProtoHint::Auto, &nfv5_datagram(), EXPORTER, NOW_MS);
    assert_eq!(r5.len(), 2);
    // sFlow -> u32 version 5
    let rs = parse_datagram(&mut st, ProtoHint::Auto, &sflow_datagram(), EXPORTER, NOW_MS);
    assert_eq!(rs.len(), 1);
    // IPFIX -> version u16 = 10
    let ri = parse_datagram(&mut st, ProtoHint::Auto, &ipfix_datagram(), EXPORTER, NOW_MS);
    assert_eq!(ri.len(), 1);
    // unknown version -> empty
    let mut bad = nfv5_datagram();
    bad[0] = 0;
    bad[1] = 99;
    let rb = parse_datagram(&mut st, ProtoHint::Auto, &bad, EXPORTER, NOW_MS);
    assert!(rb.is_empty());
}

#[test]
fn ipfix_tcp_stream_reassembly() {
    let msg = ipfix_datagram();
    let mut dec = IpfixTcpDecoder::new(EXPORTER);
    // Feed byte-by-byte: exercises header wait, partial message, resync paths.
    let mut out = Vec::new();
    for chunk in msg.chunks(7) {
        out.extend(dec.feed(chunk, NOW_MS));
    }
    assert_eq!(out.len(), 1);
    assert_eq!(v4_last(out[0].src_ip), "192.0.2.1");
    assert_eq!(out[0].dst_port, 443);

    // Two messages back-to-back in one feed.
    let mut dec2 = IpfixTcpDecoder::new(EXPORTER);
    let mut both = msg.clone();
    both.extend_from_slice(&msg);
    let out2 = dec2.feed(&both, NOW_MS);
    assert_eq!(out2.len(), 2);

    // Garbage prefix then valid message -> resync finds the header.
    let mut dec3 = IpfixTcpDecoder::new(EXPORTER);
    let mut junked = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02];
    junked.extend_from_slice(&msg);
    let out3 = dec3.feed(&junked, NOW_MS);
    assert_eq!(out3.len(), 1);
}

#[test]
fn u128_ip_roundtrip() {
    for ip in ["1.2.3.4", "192.168.0.1", "255.255.255.255"] {
        let a: IpAddr = ip.parse().unwrap();
        let v = bgflow_types::ip_to_u128(&a);
        assert_eq!(ip_string(v), ip);
        assert_eq!(u128_to_ip(v), a);
    }
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let v6v = bgflow_types::ip_to_u128(&v6);
    assert_eq!(u128_to_ip(v6v), v6);
}
