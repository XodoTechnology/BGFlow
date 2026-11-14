//! Decode a length-prefixed datagram capture (2-byte BE length + payload
//! per record, as written by tests/tools) through the real parsers and
//! print per-capture flow counts plus a sample record.
//!
//! Usage: decode_capture <file> <netflow9|ipfix|auto>

use bgflow_netflow::{parse_datagram, ProtoHint, SessionState};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: decode_capture <file> <hint>");
    let hint = match std::env::args().nth(2).as_deref() {
        Some("netflow9") | Some("v9") => ProtoHint::NetFlow9,
        Some("ipfix") => ProtoHint::Ipfix,
        _ => ProtoHint::Auto,
    };
    let data = std::fs::read(&path).expect("read capture");
    let mut off = 0usize;
    let mut st = SessionState::default();
    let exporter: IpAddr = "127.0.0.1".parse().unwrap();
    let (mut dgrams, mut recs, mut empty) = (0u64, 0u64, 0u64);
    let mut sample: Option<bgflow_types::FlowRecord> = None;
    while off + 2 <= data.len() {
        let len = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if off + len > data.len() {
            eprintln!("truncated datagram at offset {off}");
            break;
        }
        let d = &data[off..off + len];
        off += len;
        dgrams += 1;
        let rs = parse_datagram(&mut st, hint, d, exporter, now_ms());
        if rs.is_empty() {
            empty += 1;
        }
        recs += rs.len() as u64;
        if sample.is_none() {
            sample = rs.first().copied();
        }
    }
    println!("datagrams={dgrams} records={recs} empty={empty}");
    if let Some(r) = sample {
        println!(
            "sample: {} -> {} proto={} bytes={} pkts={} asn={}->{} vlan={} ttl={} ts_ms={}",
            bgflow_types::ip_string(r.src_ip),
            bgflow_types::ip_string(r.dst_ip),
            r.protocol,
            r.bytes,
            r.packets,
            r.src_asn,
            r.dst_asn,
            r.vlan,
            r.ip_ttl,
            r.ts_ms
        );
    }
}
