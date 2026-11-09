//! NetFlow v5 parser — fixed 48-byte records, 24-byte header.
//! All fields big-endian.

use crate::cursor::Cursor;
use crate::template::{ip_u128, FlowBuilder, TimeCtx};
use bgflow_types::FlowRecord;
use std::net::{IpAddr, Ipv4Addr};

const HEADER_LEN: usize = 24;
const RECORD_LEN: usize = 48;

pub fn parse(payload: &[u8], exporter: IpAddr, _now_ms: u64) -> Vec<FlowRecord> {
    if payload.len() < HEADER_LEN {
        return Vec::new();
    }
    let mut cur = Cursor::new(payload);
    let _version = match cur.u16() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let count = match cur.u16() {
        Ok(v) => v as usize,
        Err(_) => return Vec::new(),
    };
    let sys_uptime = match cur.u32() {
        Ok(v) => v as u64,
        Err(_) => return Vec::new(),
    };
    let unix_secs = match cur.u32() {
        Ok(v) => v as u64,
        Err(_) => return Vec::new(),
    };
    let unix_nsecs = match cur.u32() {
        Ok(v) => v as u64,
        Err(_) => return Vec::new(),
    };
    let _flow_seq = match cur.u32() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let engine_type = match cur.u8() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let engine_id = match cur.u8() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let sampling_interval = match cur.u16() {
        Ok(v) => v as u32,
        Err(_) => return Vec::new(),
    };

    // boot epoch estimate: unix time at export minus uptime
    let export_ms = unix_secs * 1000 + unix_nsecs / 1_000_000;
    let boot_ms = export_ms as i64 - sys_uptime as i64;
    let ctx = TimeCtx {
        export_ms,
        boot_ms: Some(boot_ms),
    };

    let max_records = count.min((payload.len() - HEADER_LEN) / RECORD_LEN);
    let mut out = Vec::with_capacity(max_records);

    for _ in 0..max_records {
        let rec = match cur.slice(RECORD_LEN) {
            Ok(r) => r,
            Err(_) => break,
        };
        if let Some(f) = parse_record(rec, engine_type, engine_id, sampling_interval) {
            out.push(f.finish(&ctx, boot_ms, exporter));
        }
    }
    out
}

fn parse_record(
    r: &[u8],
    engine_type: u8,
    engine_id: u8,
    sampling_interval: u32,
) -> Option<FlowBuilder> {
    // Layout (48 bytes, all big-endian):
    //  0  srcaddr(4)  4  dstaddr(4)  8  nexthop(4)
    // 12  input(2)   14  output(2)
    // 16  dPkts(4)   20  dOctets(4)
    // 24  First(4)   28  Last(4)     (ms since boot)
    // 32  srcport(2) 34  dstport(2)
    // 36  pad(1)     37  tcp_flags(1) 38 prot(1) 39 tos(1)
    // 40  src_as(2)  42  dst_as(2)
    // 44  src_mask(1) 45 dst_mask(1) 46 pad(2)
    let mut b = FlowBuilder::default();

    b.src_ip = ip_u128(&IpAddr::V4(Ipv4Addr::new(r[0], r[1], r[2], r[3])));
    b.dst_ip = ip_u128(&IpAddr::V4(Ipv4Addr::new(r[4], r[5], r[6], r[7])));
    b.next_hop = ip_u128(&IpAddr::V4(Ipv4Addr::new(r[8], r[9], r[10], r[11])));
    b.ingress_if = u16::from_be_bytes([r[12], r[13]]) as u32;
    b.egress_if = u16::from_be_bytes([r[14], r[15]]) as u32;
    b.packets = u32::from_be_bytes(r[16..20].try_into().unwrap()) as u64;
    b.bytes = u32::from_be_bytes(r[20..24].try_into().unwrap()) as u64;
    let first = u32::from_be_bytes(r[24..28].try_into().unwrap()) as u64;
    let last = u32::from_be_bytes(r[28..32].try_into().unwrap()) as u64;
    b.src_port = u16::from_be_bytes([r[32], r[33]]);
    b.dst_port = u16::from_be_bytes([r[34], r[35]]);
    b.tcp_flags = r[37];
    b.protocol = r[38];
    b.src_asn = u16::from_be_bytes([r[40], r[41]]) as u32;
    b.dst_asn = u16::from_be_bytes([r[42], r[43]]) as u32;
    b.engine_type = engine_type;
    b.engine_id = engine_id;
    b.sampler_interval = sampling_interval;

    // sysUpTime-based timestamps (ms since boot)
    b.start_sysup_ms = Some(first);
    b.end_sysup_ms = Some(last);
    b.start_set = true;
    b.end_set = true;

    Some(b)
}
