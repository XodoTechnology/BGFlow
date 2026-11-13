//! sFlow v5 parser (RFC 3176 + sFlow.org v5 structures).
//!
//! sFlow uses XDR encoding: all integers big-endian, opaque types are
//! u32-length-prefixed and padded to 4-byte boundaries.
//!
//! Datagrams contain samples; flow samples contain records. Each record is
//! length-delimited: {data_format u32, length u32, data}. Packet records
//! (raw header / IPv4 / IPv6) describe a sampled packet; extended records
//! (switch/router/gateway) that follow enrich the preceding packet record.
//!
//! sFlow is packet-sampled: we scale byte/packet estimates by the sample's
//! sampling_rate so aggregates approximate real traffic volume.

use crate::cursor::Cursor;
use crate::template::{ip_u128, FlowBuilder};
use anyhow::Result;
use bgflow_types::FlowRecord;
use std::net::IpAddr;

// Sample formats (low 12 bits of packed format; enterprise in high bits).
const SAMPLE_FLOW: u32 = 1;
const SAMPLE_EXPANDED_FLOW: u32 = 3;
const SAMPLE_DROP: u32 = 5;

// Flow data record types.
const FLOW_RAW: u32 = 1;
const FLOW_ETH: u32 = 2;
const FLOW_IPV4: u32 = 3;
const FLOW_IPV6: u32 = 4;
const FLOW_EXT_SWITCH: u32 = 1001;
const FLOW_EXT_ROUTER: u32 = 1002;
const FLOW_EXT_GATEWAY: u32 = 1003;

fn fmt_of(data_format: u32) -> u32 {
    data_format & 0x0fff
}

fn ent_of(data_format: u32) -> u32 {
    data_format >> 12
}

/// Read an XDR address: type u32 (1=v4, 2=v6) + address bytes.
fn read_xdr_address(cur: &mut Cursor) -> Result<u128> {
    let t = cur.u32()?;
    match t {
        1 => {
            let b = cur.slice(4)?;
            Ok(ip_u128(&IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))))
        }
        2 => {
            let b = cur.slice(16)?;
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Ok(ip_u128(&IpAddr::V6(std::net::Ipv6Addr::from(a))))
        }
        _ => Ok(0),
    }
}

/// Read XDR opaque<>: u32 length + bytes + zero padding to 4-byte boundary.
fn read_xdr_opaque<'a>(cur: &mut Cursor<'a>) -> Result<&'a [u8]> {
    let len = cur.u32()? as usize;
    let data = cur.slice(len)?;
    let pad = (4 - (len % 4)) % 4;
    cur.skip(pad)?;
    Ok(data)
}

pub fn parse(payload: &[u8], _exporter: IpAddr, now_ms: u64) -> Vec<FlowRecord> {
    let mut cur = Cursor::new(payload);
    let version = match cur.u32() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    if version != 5 {
        return Vec::new();
    }
    // agent address
    let agent = match read_xdr_address(&mut cur) {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    let _sub_agent = match cur.u32() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let _seq = match cur.u32() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let _uptime = match cur.u32() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let num_samples = match cur.u32() {
        Ok(v) => v as usize,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for _ in 0..num_samples.min(1000) {
        if cur.remaining() < 8 {
            break;
        }
        let sample_format = match cur.u32() {
            Ok(v) => v,
            Err(_) => break,
        };
        let sample_len = match cur.u32() {
            Ok(v) => v as usize,
            Err(_) => break,
        };
        if sample_len > cur.remaining() {
            break;
        }
        let body = match cur.slice(sample_len) {
            Ok(b) => b,
            Err(_) => break,
        };

        let fmt = fmt_of(sample_format);
        if ent_of(sample_format) != 0 {
            continue; // enterprise sample — skip
        }
        match fmt {
            SAMPLE_FLOW | SAMPLE_EXPANDED_FLOW | SAMPLE_DROP => {
                parse_flow_sample(body, fmt, agent, now_ms, &mut out);
            }
            _ => {} // counter/gauge samples ignored
        }
    }
    out
}

fn parse_flow_sample(
    body: &[u8],
    fmt: u32,
    agent: u128,
    now_ms: u64,
    out: &mut Vec<FlowRecord>,
) {
    let mut cur = Cursor::new(body);
    let _seq = match cur.u32() {
        Ok(v) => v,
        Err(_) => return,
    };
    // source id: interlaced (type<<24|value) for FLOW samples, explicit
    // type+value pair for expanded/drop samples.
    match fmt {
        SAMPLE_FLOW => {
            if cur.u32().is_err() {
                return;
            }
        }
        _ => {
            if cur.u32().is_err() || cur.u32().is_err() {
                return;
            }
        }
    }

    // sample parameters
    let (sampling_rate, input_if, output_if, records_count) = match fmt {
        SAMPLE_FLOW => {
            let rate = cur.u32().unwrap_or(0);
            let _pool = cur.u32();
            let _drops = cur.u32();
            let input = cur.u32().unwrap_or(0);
            let output = cur.u32().unwrap_or(0);
            let count = cur.u32().unwrap_or(0);
            (rate, input, output, count)
        }
        SAMPLE_EXPANDED_FLOW => {
            let rate = cur.u32().unwrap_or(0);
            let _pool = cur.u32();
            let _drops = cur.u32();
            let _in_fmt = cur.u32();
            let input = cur.u32().unwrap_or(0);
            let _out_fmt = cur.u32();
            let output = cur.u32().unwrap_or(0);
            let count = cur.u32().unwrap_or(0);
            (rate, input, output, count)
        }
        SAMPLE_DROP => {
            let _drops = cur.u32();
            let input = cur.u32().unwrap_or(0);
            let output = cur.u32().unwrap_or(0);
            let _reason = cur.u32();
            let count = cur.u32().unwrap_or(0);
            (0, input, output, count)
        }
        _ => unreachable!(),
    };

    let rate = if sampling_rate == 0 { 1 } else { sampling_rate as u64 };
    let mut current: Option<FlowBuilder> = None;

    for _ in 0..records_count.min(1000) {
        if cur.remaining() < 8 {
            break;
        }
        let data_format = match cur.u32() {
            Ok(v) => v,
            Err(_) => break,
        };
        let rec_len = match cur.u32() {
            Ok(v) => v as usize,
            Err(_) => break,
        };
        if rec_len > cur.remaining() {
            break;
        }
        let rec = match cur.slice(rec_len) {
            Ok(r) => r,
            Err(_) => break,
        };
        if ent_of(data_format) != 0 {
            continue;
        }
        let rtype = fmt_of(data_format);
        let mut rc = Cursor::new(rec);
        match rtype {
            FLOW_RAW => {
                // sampled_header: protocol, frame_length, stripped,
                // header_length + opaque header
                let hdr_proto = rc.u32().unwrap_or(0);
                let frame_len = rc.u32().unwrap_or(0) as u64;
                let _stripped = rc.u32();
                let hdr = match read_xdr_opaque(&mut rc) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                // Emit previous pending record, start new one if header parses.
                if let Some(b) = current.take() {
                    out.push(finalize(b, agent, input_if, output_if, rate, now_ms));
                }
                if let Some(pkt) = parse_l2_packet(hdr, hdr_proto) {
                    let mut b = FlowBuilder::default();
                    b.src_ip = pkt.src_ip;
                    b.dst_ip = pkt.dst_ip;
                    b.protocol = pkt.proto;
                    b.src_port = pkt.src_port;
                    b.dst_port = pkt.dst_port;
                    b.tcp_flags = pkt.tcp_flags;
                    b.vlan = pkt.vlan;
                    b.bytes = pkt.ip_len.max(frame_len as u32) as u64;
                    b.packets = 1;
                    b.sampler_interval = sampling_rate;
                    current = Some(b);
                }
            }
            FLOW_IPV4 | FLOW_IPV6 => {
                // sampled_ipv4 / sampled_ipv6
                let ip_len = rc.u32().unwrap_or(0);
                let proto = rc.u32().unwrap_or(0) as u8;
                let (src, dst) = if rtype == FLOW_IPV4 {
                    let s = rc.slice(4).unwrap_or(&[0; 4]);
                    let d = rc.slice(4).unwrap_or(&[0; 4]);
                    (
                        ip_u128(&IpAddr::V4(std::net::Ipv4Addr::new(s[0], s[1], s[2], s[3]))),
                        ip_u128(&IpAddr::V4(std::net::Ipv4Addr::new(d[0], d[1], d[2], d[3]))),
                    )
                } else {
                    let s = rc.slice(16).unwrap_or(&[0; 16]);
                    let d = rc.slice(16).unwrap_or(&[0; 16]);
                    let mut sa = [0u8; 16];
                    let mut da = [0u8; 16];
                    sa.copy_from_slice(s);
                    da.copy_from_slice(d);
                    (
                        ip_u128(&IpAddr::V6(std::net::Ipv6Addr::from(sa))),
                        ip_u128(&IpAddr::V6(std::net::Ipv6Addr::from(da))),
                    )
                };
                let src_port = rc.u32().unwrap_or(0) as u16;
                let dst_port = rc.u32().unwrap_or(0) as u16;
                let tcp_flags = rc.u32().unwrap_or(0) as u8;
                // tos/priority — not stored

                if let Some(b) = current.take() {
                    out.push(finalize(b, agent, input_if, output_if, rate, now_ms));
                }
                let mut b = FlowBuilder::default();
                b.src_ip = src;
                b.dst_ip = dst;
                b.protocol = proto;
                b.src_port = src_port;
                b.dst_port = dst_port;
                b.tcp_flags = tcp_flags;
                b.bytes = ip_len.max(1) as u64;
                b.packets = 1;
                b.sampler_interval = sampling_rate;
                current = Some(b);
            }
            FLOW_EXT_SWITCH => {
                // src_vlan, src_priority, dst_vlan, dst_priority
                if let Some(b) = current.as_mut() {
                    let sv = rc.u32().unwrap_or(0) as u16;
                    let _sp = rc.u32();
                    let dv = rc.u32().unwrap_or(0) as u16;
                    let _dp = rc.u32();
                    if b.vlan == 0 {
                        b.vlan = if dv != 0 { dv } else { sv };
                    }
                }
            }
            FLOW_EXT_ROUTER => {
                if let Some(b) = current.as_mut() {
                    if let Ok(nh) = read_xdr_address(&mut rc) {
                        if nh != 0 {
                            b.next_hop = nh;
                        }
                    }
                    let _src_mask = rc.u32();
                    let _dst_mask = rc.u32();
                }
            }
            FLOW_EXT_GATEWAY => {
                if let Some(b) = current.as_mut() {
                    if let Ok(nh) = read_xdr_address(&mut rc) {
                        if nh != 0 && b.next_hop == 0 {
                            b.next_hop = nh;
                        }
                    }
                    if let Ok(asn) = rc.u32() {
                        if b.dst_asn == 0 {
                            b.dst_asn = asn;
                        }
                    }
                    if let Ok(src_as) = rc.u32() {
                        if b.src_asn == 0 {
                            b.src_asn = src_as;
                        }
                    }
                    let _src_peer_as = rc.u32();
                    // remaining variable-length fields ignored (record is
                    // length-delimited so we simply stop reading)
                }
            }
            FLOW_ETH => {
                // sampled_ethernet: opaque L2 header — may carry 802.1Q tags.
                if let Ok(h) = read_xdr_opaque(&mut rc) {
                    if let Some(b) = current.as_mut() {
                        if b.vlan == 0 {
                            b.vlan = vlan_from_eth(&h);
                        }
                    }
                }
            }
            _ => {} // other record types carry no usable L3 info
        }
    }

    if let Some(b) = current.take() {
        out.push(finalize(b, agent, input_if, output_if, rate, now_ms));
    }
}

/// Convert a finished FlowBuilder into a FlowRecord with sFlow-specific
/// defaults (timestamp = receipt time, sampled byte/packet scaling).
fn finalize(
    mut b: FlowBuilder,
    agent: u128,
    input_if: u32,
    output_if: u32,
    rate: u64,
    now_ms: u64,
) -> FlowRecord {
    // Scale sampled estimates.
    b.bytes = b.bytes.saturating_mul(rate);
    b.packets = b.packets.saturating_mul(rate);
    if b.ingress_if == 0 {
        b.ingress_if = input_if & 0x7fff_ffff;
    }
    if b.egress_if == 0 {
        b.egress_if = output_if & 0x7fff_ffff;
    }
    // finish() resolves ts from export_ms fallback and sets exporter.
    let ctx = crate::template::TimeCtx {
        export_ms: now_ms,
        boot_ms: None,
    };
    b.finish(&ctx, now_ms as i64, bgflow_types::u128_to_ip(agent))
}

/// Parsed packet header fields from an sFlow raw sample.
struct ParsedPacket {
    src_ip: u128,
    dst_ip: u128,
    proto: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    ip_len: u32,
    vlan: u16,
}

/// First non-zero 802.1Q/1ad/9100 VID in an ethernet header (0 = untagged).
fn vlan_from_eth(h: &[u8]) -> u16 {
    if h.len() < 14 {
        return 0;
    }
    let mut et = be16(h, 12);
    let mut off = 14usize;
    let mut vlan = 0u16;
    loop {
        match et {
            0x8100 | 0x88a8 | 0x9100 => {
                if h.len() < off + 4 {
                    return vlan;
                }
                if vlan == 0 {
                    vlan = (be16(h, off) & 0x0fff) as u16;
                }
                et = be16(h, off + 2);
                off += 4;
            }
            _ => return vlan,
        }
    }
}

/// Parse a sampled packet header (L2 or raw IP) into flow tuple fields.
/// `hdr_proto` is the sFlow header_protocol: 1=ethernet, 11=IPv4, 12=IPv6,
/// 13=MPLS, others treated as ethernet.
fn parse_l2_packet(data: &[u8], hdr_proto: u32) -> Option<ParsedPacket> {
    let mut off = 0usize;
    match hdr_proto {
        11 => {} // raw IPv4
        12 => {} // raw IPv6
        _ => {
            // Assume Ethernet-ish: dst(6) src(6) ethertype(2)
            if data.len() < 14 {
                return None;
            }
            let vlan = vlan_from_eth(data);
            off = 12;
            let mut ethertype = be16(data, off);
            off += 2;
            // VLAN tags (802.1Q/1ad/9100)
            loop {
                match ethertype {
                    0x8100 | 0x88a8 | 0x9100 => {
                        if data.len() < off + 4 {
                            return None;
                        }
                        ethertype = be16(data, off + 2);
                        off += 4;
                    }
                    0x8864 | 0x8863 => {
                        // PPPoE: 6-byte header + 2-byte proto
                        if data.len() < off + 8 {
                            return None;
                        }
                        ethertype = be16(data, off + 6);
                        off += 8;
                    }
                    0x8847 | 0x8848 => {
                        // MPLS label stack: 4 bytes per label, bottom bit set
                        // on last label (S bit = 0x10000 in the u32).
                        let mut hops = 0;
                        loop {
                            if data.len() < off + 4 || hops > 8 {
                                return None;
                            }
                            let label = be32(data, off);
                            off += 4;
                            hops += 1;
                            if label & 0x0001_0000 != 0 {
                                break;
                            }
                        }
                        if data.len() < off + 1 {
                            return None;
                        }
                        // version nibble decides v4/v6
                        let v = data[off] >> 4;
                        return match v {
                            4 => parse_ipv4(&data[off..]).map(|mut p| {
                                p.vlan = vlan;
                                p
                            }),
                            6 => parse_ipv6(&data[off..]).map(|mut p| {
                                p.vlan = vlan;
                                p
                            }),
                            _ => None,
                        };
                    }
                    _ => break,
                }
            }
            match ethertype {
                0x0800 => {
                    return parse_ipv4(&data[off..]).map(|mut p| {
                        p.vlan = vlan;
                        p
                    })
                }
                0x86DD => {
                    return parse_ipv6(&data[off..]).map(|mut p| {
                        p.vlan = vlan;
                        p
                    })
                }
                _ => return None,
            }
        }
    }
    // hdr_proto 11/12: data starts at IP header
    if data.len() < 1 {
        return None;
    }
    match data[0] >> 4 {
        4 => parse_ipv4(&data[off..]),
        6 => parse_ipv6(&data[off..]),
        _ => None,
    }
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Parse an IPv4 packet (header onward) into flow fields.
fn parse_ipv4(p: &[u8]) -> Option<ParsedPacket> {
    if p.len() < 20 {
        return None;
    }
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    if ihl < 20 || p.len() < ihl {
        return None;
    }
    let total_len = be16(p, 2) as u32;
    let frag = be16(p, 6);
    let proto = p[9];
    let src = ip_u128(&IpAddr::V4(std::net::Ipv4Addr::new(p[12], p[13], p[14], p[15])));
    let dst = ip_u128(&IpAddr::V4(std::net::Ipv4Addr::new(p[16], p[17], p[18], p[19])));

    let mut pkt = ParsedPacket {
        src_ip: src,
        dst_ip: dst,
        proto,
        src_port: 0,
        dst_port: 0,
        tcp_flags: 0,
        ip_len: total_len.max(ihl as u32),
        vlan: 0,
    };

    // Only first fragments carry ports.
    let is_first_frag = frag & 0x1fff == 0;
    if is_first_frag && p.len() >= ihl + 4 {
        let l4 = &p[ihl..];
        match proto {
            6 => {
                // TCP: ports at 0,2; flags byte at offset 13
                if l4.len() >= 14 {
                    pkt.src_port = be16(l4, 0);
                    pkt.dst_port = be16(l4, 2);
                    pkt.tcp_flags = l4[13];
                }
            }
            17 => {
                if l4.len() >= 4 {
                    pkt.src_port = be16(l4, 0);
                    pkt.dst_port = be16(l4, 2);
                }
            }
            _ => {}
        }
    }
    Some(pkt)
}

/// Parse an IPv6 packet (header onward) into flow fields.
fn parse_ipv6(p: &[u8]) -> Option<ParsedPacket> {
    if p.len() < 40 {
        return None;
    }
    let payload_len = be16(p, 4) as u32;
    let mut nexthdr = p[6];
    let src = {
        let mut a = [0u8; 16];
        a.copy_from_slice(&p[8..24]);
        ip_u128(&IpAddr::V6(std::net::Ipv6Addr::from(a)))
    };
    let dst = {
        let mut a = [0u8; 16];
        a.copy_from_slice(&p[24..40]);
        ip_u128(&IpAddr::V6(std::net::Ipv6Addr::from(a)))
    };

    let mut off = 40usize;
    // Skip extension headers.
    let mut hops = 0;
    loop {
        hops += 1;
        if hops > 8 || p.len() < off + 2 {
            return None;
        }
        match nexthdr {
            0 | 43 | 60 | 135 => {
                // hop-by-hop, routing, dest-opts, mobility: len in 8-octet units
                let nxt = p[off];
                let ext_len = ((p[off + 1] as usize) + 1) * 8;
                off += ext_len;
                nexthdr = nxt;
            }
            44 => {
                // fragment header: fixed 8 bytes. Field layout:
                // [next_header u8][reserved u8][frag_off+res+M u16][id u32]
                // offset occupies bits 3..15; bit 0 is the M (more) flag.
                let nxt = p[off];
                let frag_field = be16(p, off + 2);
                let frag_off = frag_field & 0xfff8; // offset only, NOT the M flag
                off += 8;
                nexthdr = nxt;
                if frag_off != 0 {
                    // non-first fragment: no ports
                    return Some(ParsedPacket {
                        src_ip: src,
                        dst_ip: dst,
                        proto: nexthdr,
                        src_port: 0,
                        dst_port: 0,
                        tcp_flags: 0,
                        ip_len: 40 + payload_len,
                        vlan: 0,
                    });
                }
            }
            51 => {
                // AH: len in 32-bit words minus 2
                let nxt = p[off];
                let ext_len = ((p[off + 1] as usize) + 2) * 4;
                off += ext_len;
                nexthdr = nxt;
            }
            _ => break,
        }
    }

    let mut pkt = ParsedPacket {
        src_ip: src,
        dst_ip: dst,
        proto: nexthdr,
        src_port: 0,
        dst_port: 0,
        tcp_flags: 0,
        ip_len: 40 + payload_len,
        vlan: 0,
    };
    if p.len() >= off + 4 {
        let l4 = &p[off..];
        match nexthdr {
            6 => {
                if l4.len() >= 14 {
                    pkt.src_port = be16(l4, 0);
                    pkt.dst_port = be16(l4, 2);
                    pkt.tcp_flags = l4[13];
                }
            }
            17 => {
                pkt.src_port = be16(l4, 0);
                pkt.dst_port = be16(l4, 2);
            }
            _ => {}
        }
    }
    Some(pkt)
}
