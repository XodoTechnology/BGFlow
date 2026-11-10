//! Core data types shared across BGFlow crates.

use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A single flow record, the atomic unit of the system.
///
/// Field order matches the on-disk columnar schema in `bgflow-store`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct FlowRecord {
    /// Time the flow was last seen, unix epoch milliseconds.
    pub ts_ms: u64,
    /// Flow duration in milliseconds (last_seen - first_seen).
    pub duration_ms: u32,
    pub src_ip: u128,
    pub dst_ip: u128,
    pub src_port: u16,
    pub dst_port: u16,
    /// IANA protocol number (6 = TCP, 17 = UDP, 1 = ICMP, ...).
    pub protocol: u8,
    /// TCP flags bitmask (0 for non-TCP).
    pub tcp_flags: u8,
    pub ingress_if: u32,
    pub egress_if: u32,
    pub next_hop: u128,
    pub src_asn: u32,
    pub dst_asn: u32,
    /// ISO 3166-1 numeric country code, 0 = unknown.
    pub src_country: u16,
    pub dst_country: u16,
    /// Interned organization IDs (see bgflowd's string table); 0 = unknown.
    pub src_org: u32,
    pub dst_org: u32,
    pub vlan: u16,
    /// Total layer-3 bytes in the flow (post-sampling-scaling if sampled).
    pub bytes: u64,
    pub packets: u64,
    /// IP address of the exporting router/switch.
    pub exporter: u128,
    pub engine_id: u8,
    pub engine_type: u8,
    /// Sampling interval reported by the exporter (0 = unsampled).
    pub sampler_interval: u32,
    /// TCP state if known (0 = unknown, else RFC 793-ish state code).
    pub tcp_state: u8,
    /// Matched label rule id (0 = none). Rules are defined in config.
    pub label_id: u32,
    /// IP TTL observed on the flow (IE 192; 0 = not reported).
    pub ip_ttl: u8,
    /// Why the flow ended (IE 136 flowEndReason; 0 = unknown).
    /// 1=idle, 2=active timeout, 3=end of flow, 4=forced export, ...
    pub flow_end_reason: u8,
    /// ICMP type/code for ICMP/ICMPv6 flows (IE 32/139; 0 = n/a).
    pub icmp_type: u8,
    pub icmp_code: u8,
    /// Post-NAT addresses when the exporter reports them
    /// (IE 225/226 v4, 281/282 v6). 0 = not reported.
    pub post_nat_src: u128,
    pub post_nat_dst: u128,
}

/// Pre-aggregated rollup record: one row per (minute, exporter, protocol,
/// src/dst ASN, src/dst IP). Produced continuously at ingest time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct RollupRecord {
    /// Minute-aligned unix ms timestamp.
    pub bucket_ms: u64,
    pub exporter: u128,
    pub protocol: u8,
    pub src_asn: u32,
    pub dst_asn: u32,
    pub src_ip: u128,
    pub dst_ip: u128,
    pub src_port: u16,
    pub dst_port: u16,
    pub src_country: u16,
    pub dst_country: u16,
    /// Interned org ids (same table as FlowRecord; 0 = unknown).
    pub src_org: u32,
    pub dst_org: u32,
    /// Matched label id (0 = none) — enables per-label stats on rollups.
    pub label_id: u32,
    pub bytes: u64,
    pub packets: u64,
    pub flows: u64,
    pub min_ts_ms: u64,
    pub max_ts_ms: u64,
}

// ---------------------------------------------------------------------------
// IP helpers
// ---------------------------------------------------------------------------

/// Convert an `IpAddr` to the canonical u128 used on disk.
/// IPv4 is stored in IPv4-mapped IPv6 form (::ffff:a.b.c.d) so it can never
/// collide with a real IPv6 address.
pub fn ip_to_u128(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from_be_bytes(v4.to_ipv6_mapped().octets()),
        IpAddr::V6(v6) => u128::from_be_bytes(v6.octets()),
    }
}

/// Convert a stored u128 back to an `IpAddr`.
pub fn u128_to_ip(v: u128) -> IpAddr {
    let b = v.to_be_bytes();
    if b[0..10].iter().all(|&x| x == 0) && b[10] == 0xff && b[11] == 0xff {
        IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]))
    } else {
        IpAddr::V6(Ipv6Addr::from(b))
    }
}

/// True if the stored u128 is an IPv4-mapped address (::ffff:a.b.c.d),
/// i.e. the value represents an IPv4 endpoint.
pub fn is_v4_mapped(v: u128) -> bool {
    let b = v.to_be_bytes();
    b[0..10].iter().all(|&x| x == 0) && b[10] == 0xff && b[11] == 0xff
}

/// Display form of a stored u128 IP (dotted quad for v4, compressed for v6).
pub fn ip_string(v: u128) -> String {
    u128_to_ip(v).to_string()
}

/// Pack an ISO 3166-1 alpha-2 country code into a u16 (`"US"` -> 0x5553).
/// Returns 0 for empty/invalid input.
pub fn country_pack(code: &str) -> u16 {
    let b = code.as_bytes();
    if b.len() == 2 && b[0].is_ascii_alphabetic() && b[1].is_ascii_alphabetic() {
        ((b[0] as u16) << 8) | b[1] as u16
    } else {
        0
    }
}

/// Unpack a stored u16 country code back to an alpha-2 string.
/// Returns an empty string for 0/invalid values.
pub fn country_str(v: u16) -> String {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    if hi.is_ascii_alphabetic() && lo.is_ascii_alphabetic() {
        format!("{}{}", hi as char, lo as char)
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Well-known protocol numbers
// ---------------------------------------------------------------------------

pub fn protocol_name(p: u8) -> &'static str {
    match p {
        0 => "HOPOPT",
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        132 => "SCTP",
        _ => "other",
    }
}
