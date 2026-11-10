//! Shared template machinery for NetFlow v9 and IPFIX.
//!
//! Both protocols describe flow records via templates: a list of fields
//! (information element id + length). IPFIX adds an enterprise bit and
//! variable-length fields; NetFlow v9 is the simpler subset.
//!
//! All multi-byte integers are big-endian.

use crate::cursor::Cursor;
use anyhow::Result;
use bgflow_types::FlowRecord;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One field in a template.
#[derive(Debug, Clone, Copy)]
pub struct FieldSpec {
    /// Information element id (IPFIX enterprise bit already stripped).
    pub ie: u16,
    /// Encoded length in bytes; 0xffff = variable-length (IPFIX only).
    pub len: u16,
    /// True for IPFIX enterprise-specific fields — never mapped to
    /// standard semantics, but still consumes `len` bytes in records.
    pub enterprise: bool,
}

/// A parsed template: the ordered field list for one template id.
#[derive(Debug, Clone, Default)]
pub struct Template {
    pub fields: Vec<FieldSpec>,
}

impl Template {
    /// Fixed portion size in bytes (variable-length fields contribute 0).
    pub fn fixed_len(&self) -> usize {
        self.fields
            .iter()
            .map(|f| if f.len == 0xffff { 0 } else { f.len as usize })
            .sum()
    }
}

/// Time context for one export packet, used to resolve sysUpTime-based
/// timestamps into epoch milliseconds.
#[derive(Debug, Clone, Copy)]
pub struct TimeCtx {
    /// Best estimate of when the export packet was sent, unix ms.
    pub export_ms: u64,
    /// Estimated device boot time, unix ms, when known from the packet
    /// header (NetFlow v5/v9 provide unix_secs + sys_uptime directly).
    pub boot_ms: Option<i64>,
}

/// Partially decoded flow record; timestamps may still be in sysUpTime
/// units and are resolved in `finish`.
#[derive(Debug, Default)]
pub struct FlowBuilder {
    pub ts_ms: u64,
    pub duration_ms: u32,
    pub src_ip: u128,
    pub dst_ip: u128,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub ingress_if: u32,
    pub egress_if: u32,
    pub next_hop: u128,
    pub src_asn: u32,
    pub dst_asn: u32,
    pub src_country: u16,
    pub dst_country: u16,
    pub src_org: u32,
    pub dst_org: u32,
    pub vlan: u16,
    pub bytes: u64,
    pub packets: u64,
    pub exporter: u128,
    pub engine_id: u8,
    pub engine_type: u8,
    pub sampler_interval: u32,
    pub tcp_state: u8,
    pub ip_ttl: u8,
    pub flow_end_reason: u8,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub post_nat_src: u128,
    pub post_nat_dst: u128,

    // unresolved timestamp candidates (epoch ms or sysUpTime ms)
    pub end_epoch_ms: Option<u64>,
    pub start_epoch_ms: Option<u64>,
    pub end_sysup_ms: Option<u64>,
    pub start_sysup_ms: Option<u64>,
    pub end_set: bool,
    pub start_set: bool,
}

fn v4_to_u128(b: &[u8]) -> u128 {
    let v4 = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    u128::from_be_bytes(v4.to_ipv6_mapped().octets())
}

fn v6_to_u128(b: &[u8]) -> u128 {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[..16]);
    u128::from_be_bytes(Ipv6Addr::from(a).octets())
}

/// Read an unsigned big-endian integer of `len` bytes into u64/u128.
fn be_uint(b: &[u8]) -> u128 {
    if b.len() >= 16 {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&b[b.len() - 16..]);
        u128::from_be_bytes(buf)
    } else {
        let mut buf = [0u8; 16];
        buf[16 - b.len()..].copy_from_slice(b);
        u128::from_be_bytes(buf)
    }
}

impl FlowBuilder {
    /// Resolve timestamps and produce a FlowRecord.
    /// `boot_ms` resolves sysUpTime-based fields when the packet header
    /// did not provide a boot estimate.
    pub fn finish(mut self, ctx: &TimeCtx, boot_ms: i64, exporter: IpAddr) -> FlowRecord {
        // sysUpTime -> epoch using boot estimate
        let end_epoch = self
            .end_epoch_ms
            .or_else(|| self.end_sysup_ms.map(|s| (boot_ms + s as i64).max(0) as u64));
        let start_epoch = self
            .start_epoch_ms
            .or_else(|| self.start_sysup_ms.map(|s| (boot_ms + s as i64).max(0) as u64));

        if let Some(e) = end_epoch {
            self.ts_ms = e;
        } else {
            // No usable timestamp: fall back to export time.
            self.ts_ms = ctx.export_ms;
        }
        self.duration_ms = match (start_epoch, end_epoch) {
            (Some(s), Some(e)) if e >= s => (e - s).min(u32::MAX as u64) as u32,
            _ => 0,
        };
        self.exporter = ip_u128(&exporter);

        FlowRecord {
            ts_ms: self.ts_ms,
            duration_ms: self.duration_ms,
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            protocol: self.protocol,
            tcp_flags: self.tcp_flags,
            ingress_if: self.ingress_if,
            egress_if: self.egress_if,
            next_hop: self.next_hop,
            src_asn: self.src_asn,
            dst_asn: self.dst_asn,
            src_country: self.src_country,
            dst_country: self.dst_country,
            src_org: self.src_org,
            dst_org: self.dst_org,
            vlan: self.vlan,
            bytes: self.bytes,
            packets: self.packets,
            exporter: self.exporter,
            engine_id: self.engine_id,
            engine_type: self.engine_type,
            sampler_interval: self.sampler_interval,
            tcp_state: self.tcp_state,
            label_id: 0,
            ip_ttl: self.ip_ttl,
            flow_end_reason: self.flow_end_reason,
            icmp_type: self.icmp_type,
            icmp_code: self.icmp_code,
            post_nat_src: self.post_nat_src,
            post_nat_dst: self.post_nat_dst,
        }
    }
}

// IANA IPFIX / NetFlow v9 information element ids we map.
mod ie {
    pub const OCTET_DELTA_COUNT: u16 = 1;
    pub const PACKET_DELTA_COUNT: u16 = 2;
    pub const PROTOCOL_IDENTIFIER: u16 = 4;
    pub const TCP_CONTROL_BITS: u16 = 6;
    pub const SOURCE_TRANSPORT_PORT: u16 = 7;
    pub const SOURCE_IPV4_ADDRESS: u16 = 8;
    pub const INGRESS_INTERFACE: u16 = 10;
    pub const DESTINATION_TRANSPORT_PORT: u16 = 11;
    pub const DESTINATION_IPV4_ADDRESS: u16 = 12;
    pub const EGRESS_INTERFACE: u16 = 14;
    pub const IP_NEXT_HOP_IPV4_ADDRESS: u16 = 15;
    pub const BGP_SOURCE_AS_NUMBER: u16 = 16;
    pub const BGP_DESTINATION_AS_NUMBER: u16 = 17;
    pub const BGP_NEXT_HOP_IPV4_ADDRESS: u16 = 18;
    pub const FLOW_END_SYS_UP_TIME: u16 = 21;
    pub const FLOW_START_SYS_UP_TIME: u16 = 22;
    pub const SOURCE_IPV6_ADDRESS: u16 = 27;
    pub const DESTINATION_IPV6_ADDRESS: u16 = 28;
    pub const SAMPLING_INTERVAL: u16 = 34;
    pub const ENGINE_TYPE: u16 = 38;
    pub const ENGINE_ID: u16 = 39;
    pub const VLAN_ID: u16 = 58;
    pub const POST_VLAN_ID: u16 = 59;
    pub const IP_NEXT_HOP_IPV6_ADDRESS: u16 = 62;
    pub const SAMPLER_RANDOM_INTERVAL: u16 = 50;
    pub const OCTET_TOTAL_COUNT: u16 = 85;
    pub const PACKET_TOTAL_COUNT: u16 = 86;
    pub const FLOW_START_SECONDS: u16 = 150;
    pub const FLOW_END_SECONDS: u16 = 151;
    pub const FLOW_START_MILLISECONDS: u16 = 152;
    pub const FLOW_END_MILLISECONDS: u16 = 153;
    pub const FLOW_START_MICROSECONDS: u16 = 154;
    pub const FLOW_END_MICROSECONDS: u16 = 155;
    pub const FLOW_START_NANOSECONDS: u16 = 156;
    pub const FLOW_END_NANOSECONDS: u16 = 157;
    pub const ICMP_TYPE_CODE_IPV4: u16 = 32;
    pub const IP_VERSION: u16 = 60;
    pub const FLOW_END_REASON: u16 = 136;
    pub const ICMP_TYPE_CODE_IPV6: u16 = 139;
    pub const IP_TTL: u16 = 192;
    pub const POST_NAT_SRC_IPV4: u16 = 225;
    pub const POST_NAT_DST_IPV4: u16 = 226;
    pub const POST_NAT_SRC_IPV6: u16 = 281;
    pub const POST_NAT_DST_IPV6: u16 = 282;
    pub const INGRESS_PHYSICAL_INTERFACE: u16 = 252;
    pub const EGRESS_PHYSICAL_INTERFACE: u16 = 253;
    pub const DOT1Q_VLAN_ID: u16 = 243;
    pub const DOT1Q_CUSTOMER_VLAN_ID: u16 = 245;
}

/// Decode one data record's fields into a FlowBuilder.
/// `bytes` is the remaining record payload (the cursor stops at the end of
/// the fields described by the template).
/// `sysup_max` accumulates the largest sysUpTime value seen, used by the
/// caller to estimate the exporter's boot epoch for IPFIX.
/// Returns (builder, bytes_consumed).
pub fn decode_record(
    template: &Template,
    bytes: &[u8],
    sysup_max: &mut u64,
) -> Result<(FlowBuilder, usize)> {
    let mut cur = Cursor::new(bytes);
    let mut b = FlowBuilder::default();

    for f in &template.fields {
        // Determine this field's encoded length.
        let vlen = if f.len == 0xffff {
            // Variable-length (IPFIX): 1-byte length, or 0xff + u16 length.
            let l = cur.u8()? as usize;
            let len = if l == 0xff {
                cur.u16()? as usize
            } else {
                l
            };
            len
        } else {
            f.len as usize
        };
        let val = cur.slice(vlen)?;

        if f.enterprise {
            continue; // unknown semantics — already consumed above
        }

        match f.ie {
            ie::OCTET_DELTA_COUNT | ie::OCTET_TOTAL_COUNT => {
                let v = be_uint(val) as u64;
                if v != 0 {
                    b.bytes = v;
                }
            }
            ie::PACKET_DELTA_COUNT | ie::PACKET_TOTAL_COUNT => {
                let v = be_uint(val) as u64;
                if v != 0 {
                    b.packets = v;
                }
            }
            ie::PROTOCOL_IDENTIFIER => {
                if !val.is_empty() {
                    b.protocol = val[val.len() - 1];
                }
            }
            ie::TCP_CONTROL_BITS => {
                if !val.is_empty() {
                    b.tcp_flags = val[val.len() - 1];
                }
            }
            ie::SOURCE_TRANSPORT_PORT => {
                b.src_port = be_uint(val) as u16;
            }
            ie::DESTINATION_TRANSPORT_PORT => {
                b.dst_port = be_uint(val) as u16;
            }
            ie::SOURCE_IPV4_ADDRESS => {
                if val.len() >= 4 {
                    b.src_ip = v4_to_u128(&val[val.len() - 4..]);
                }
            }
            ie::DESTINATION_IPV4_ADDRESS => {
                if val.len() >= 4 {
                    b.dst_ip = v4_to_u128(&val[val.len() - 4..]);
                }
            }
            ie::SOURCE_IPV6_ADDRESS => {
                if val.len() >= 16 {
                    b.src_ip = v6_to_u128(&val[val.len() - 16..]);
                }
            }
            ie::DESTINATION_IPV6_ADDRESS => {
                if val.len() >= 16 {
                    b.dst_ip = v6_to_u128(&val[val.len() - 16..]);
                }
            }
            ie::IP_NEXT_HOP_IPV4_ADDRESS | ie::BGP_NEXT_HOP_IPV4_ADDRESS => {
                if val.len() >= 4 {
                    let ip = v4_to_u128(&val[val.len() - 4..]);
                    if b.next_hop == 0 {
                        b.next_hop = ip;
                    }
                }
            }
            ie::IP_NEXT_HOP_IPV6_ADDRESS => {
                if val.len() >= 16 {
                    let ip = v6_to_u128(&val[val.len() - 16..]);
                    if b.next_hop == 0 {
                        b.next_hop = ip;
                    }
                }
            }
            ie::BGP_SOURCE_AS_NUMBER => {
                b.src_asn = be_uint(val) as u32;
            }
            ie::BGP_DESTINATION_AS_NUMBER => {
                b.dst_asn = be_uint(val) as u32;
            }
            ie::INGRESS_INTERFACE | ie::INGRESS_PHYSICAL_INTERFACE => {
                let v = be_uint(val) as u32;
                if b.ingress_if == 0 {
                    b.ingress_if = v;
                }
            }
            ie::EGRESS_INTERFACE | ie::EGRESS_PHYSICAL_INTERFACE => {
                let v = be_uint(val) as u32;
                if b.egress_if == 0 {
                    b.egress_if = v;
                }
            }
            ie::VLAN_ID | ie::DOT1Q_VLAN_ID | ie::DOT1Q_CUSTOMER_VLAN_ID | ie::POST_VLAN_ID => {
                if b.vlan == 0 {
                    b.vlan = be_uint(val) as u16;
                }
            }
            ie::SAMPLING_INTERVAL => {
                b.sampler_interval = be_uint(val) as u32;
            }
            ie::SAMPLER_RANDOM_INTERVAL => {
                if b.sampler_interval == 0 {
                    b.sampler_interval = be_uint(val) as u32;
                }
            }
            ie::ENGINE_TYPE => {
                if !val.is_empty() {
                    b.engine_type = val[val.len() - 1];
                }
            }
            ie::ENGINE_ID => {
                if !val.is_empty() {
                    b.engine_id = val[val.len() - 1];
                }
            }
            ie::FLOW_START_MILLISECONDS => {
                b.start_epoch_ms = Some(be_uint(val) as u64);
                b.start_set = true;
            }
            ie::FLOW_END_MILLISECONDS => {
                b.end_epoch_ms = Some(be_uint(val) as u64);
                b.end_set = true;
            }
            ie::FLOW_START_SECONDS => {
                if !b.start_set {
                    b.start_epoch_ms = Some(be_uint(val) as u64 * 1000);
                    b.start_set = true;
                }
            }
            ie::FLOW_END_SECONDS => {
                if !b.end_set {
                    b.end_epoch_ms = Some(be_uint(val) as u64 * 1000);
                    b.end_set = true;
                }
            }
            ie::FLOW_START_MICROSECONDS => {
                if !b.start_set {
                    b.start_epoch_ms = Some(be_uint(val) as u64 / 1000);
                    b.start_set = true;
                }
            }
            ie::FLOW_END_MICROSECONDS => {
                if !b.end_set {
                    b.end_epoch_ms = Some(be_uint(val) as u64 / 1000);
                    b.end_set = true;
                }
            }
            ie::FLOW_START_NANOSECONDS => {
                if !b.start_set {
                    b.start_epoch_ms = Some(be_uint(val) as u64 / 1_000_000);
                    b.start_set = true;
                }
            }
            ie::FLOW_END_NANOSECONDS => {
                if !b.end_set {
                    b.end_epoch_ms = Some(be_uint(val) as u64 / 1_000_000);
                    b.end_set = true;
                }
            }
            ie::FLOW_START_SYS_UP_TIME => {
                let s = be_uint(val) as u64;
                b.start_sysup_ms = Some(s);
                *sysup_max = (*sysup_max).max(s);
            }
            ie::FLOW_END_SYS_UP_TIME => {
                let s = be_uint(val) as u64;
                b.end_sysup_ms = Some(s);
                *sysup_max = (*sysup_max).max(s);
            }
            ie::IP_TTL => {
                if !val.is_empty() {
                    b.ip_ttl = val[val.len() - 1];
                }
            }
            ie::FLOW_END_REASON => {
                if !val.is_empty() {
                    b.flow_end_reason = val[val.len() - 1];
                }
            }
            ie::ICMP_TYPE_CODE_IPV4 | ie::ICMP_TYPE_CODE_IPV6 => {
                // [type u8][code u8]
                if !val.is_empty() {
                    b.icmp_type = val[0];
                    if val.len() > 1 {
                        b.icmp_code = val[1];
                    }
                }
            }
            ie::POST_NAT_SRC_IPV4 | ie::POST_NAT_SRC_IPV6 => {
                if val.len() >= 4 {
                    b.post_nat_src = if val.len() >= 16 {
                        v6_to_u128(&val[val.len() - 16..])
                    } else {
                        v4_to_u128(&val[val.len() - 4..])
                    };
                }
            }
            ie::POST_NAT_DST_IPV4 | ie::POST_NAT_DST_IPV6 => {
                if val.len() >= 4 {
                    b.post_nat_dst = if val.len() >= 16 {
                        v6_to_u128(&val[val.len() - 16..])
                    } else {
                        v4_to_u128(&val[val.len() - 4..])
                    };
                }
            }
            _ => {}
        }
    }

    Ok((b, cur.position()))
}

/// Parse a NetFlow v9 / IPFIX template field list.
/// `ipfix` = true enables the enterprise bit and 0xffff variable length.
pub fn parse_template_fields(
    cur: &mut Cursor,
    field_count: usize,
    ipfix: bool,
) -> Result<Vec<FieldSpec>> {
    let mut fields = Vec::with_capacity(field_count.min(256));
    for _ in 0..field_count {
        let raw_type = cur.u16()?;
        let len = cur.u16()?;
        let (ie, enterprise, has_pen) = if ipfix && raw_type & 0x8000 != 0 {
            let pen = cur.u32()?;
            (raw_type & 0x7fff, pen != 0, true)
        } else {
            (raw_type, false, false)
        };
        let _ = has_pen;
        fields.push(FieldSpec { ie, len, enterprise });
    }
    Ok(fields)
}

/// ip_to_u128 helper used by finish().
pub fn ip_u128(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => v4_to_u128(&v4.octets()),
        IpAddr::V6(v6) => v6_to_u128(&v6.octets()),
    }
}

/// Sanity guard: a decoded record is interesting only if it has at least
/// an IP pair or non-zero counters.
pub fn record_is_meaningful(b: &FlowBuilder) -> bool {
    b.src_ip != 0 || b.dst_ip != 0 || b.bytes != 0 || b.packets != 0
}
