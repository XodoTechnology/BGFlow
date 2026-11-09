//! Query path: scans segment files directly using the writer-published
//! segment indexes, so HTTP queries never contend with the ingest writer.

use crate::enrich::StringTable;
use crate::rules::Ruleset;
use crate::writer::SegmentIndex;
use anyhow::Result;
use bgflow_store::{for_each_segment_info, Record};
use bgflow_types::{ip_string, ip_to_u128, u128_to_ip, country_str, protocol_name, FlowRecord, RollupRecord};
use std::ops::ControlFlow;
use std::sync::Arc;

pub struct Ctx {
    pub flow_index: SegmentIndex,
    pub rollup_index: SegmentIndex,
    pub orgs: Arc<StringTable>,
    pub rules: Arc<Ruleset>,
    /// label_id -> rule name, precomputed at startup.
    pub label_names: std::collections::HashMap<u32, String>,
}

// ---------------------------------------------------------------------------
// Time parameter parsing
// ---------------------------------------------------------------------------

/// Parse a time param: epoch seconds, epoch millis, or relative "-<n><unit>"
/// where unit is s/m/h/d. Returns milliseconds.
pub fn parse_time(s: Option<&str>, default_ms: u64) -> u64 {
    let Some(s) = s else { return default_ms };
    let s = s.trim();
    if s.is_empty() {
        return default_ms;
    }
    if let Some(rel) = s.strip_prefix('-') {
        let (num, unit) = rel.split_at(rel.len().saturating_sub(1));
        let n: u64 = num.parse().unwrap_or(0);
        let mult = match unit {
            "s" => 1_000u64,
            "m" => 60_000,
            "h" => 3_600_000,
            "d" => 86_400_000,
            _ => return default_ms,
        };
        return crate::metrics::now_ms().saturating_sub(n.saturating_mul(mult));
    }
    if let Ok(v) = s.parse::<u64>() {
        // Heuristic: < 1e11 is seconds, >= 1e11 is millis.
        return if v < 100_000_000_000 { v * 1000 } else { v };
    }
    default_ms
}

/// Default range: last 24h.
pub fn default_range() -> (u64, u64) {
    let now = crate::metrics::now_ms();
    (now - 86_400_000, now)
}

// ---------------------------------------------------------------------------
// Raw flow queries
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct FlowQuery {
    pub from_ms: u64,
    pub to_ms: u64,
    pub src: Option<u128>,
    pub dst: Option<u128>,
    pub proto: Option<u8>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub exporter: Option<u128>,
    pub src_asn: Option<u32>,
    pub dst_asn: Option<u32>,
    pub label: Option<u32>,
    pub limit: usize,
    pub newest_first: bool,
}

impl FlowQuery {
    fn matches(&self, f: &FlowRecord) -> bool {
        if let Some(v) = self.src {
            if f.src_ip != v {
                return false;
            }
        }
        if let Some(v) = self.dst {
            if f.dst_ip != v {
                return false;
            }
        }
        if let Some(v) = self.proto {
            if f.protocol != v {
                return false;
            }
        }
        if let Some(v) = self.sport {
            if f.src_port != v {
                return false;
            }
        }
        if let Some(v) = self.dport {
            if f.dst_port != v {
                return false;
            }
        }
        if let Some(v) = self.exporter {
            if f.exporter != v {
                return false;
            }
        }
        if let Some(v) = self.src_asn {
            if f.src_asn != v {
                return false;
            }
        }
        if let Some(v) = self.dst_asn {
            if f.dst_asn != v {
                return false;
            }
        }
        if let Some(v) = self.label {
            if f.label_id != v {
                return false;
            }
        }
        true
    }
}

/// Scan raw flows newest-first (or oldest), collecting up to `limit` matches.
pub fn flows(ctx: &Ctx, q: &FlowQuery) -> Result<Vec<FlowRecord>> {
    let infos = ctx.flow_index.read().unwrap().clone();
    let mut out: Vec<FlowRecord> = Vec::with_capacity(q.limit.min(1024));
    for_each_segment_info::<FlowRecord>(
        &infos,
        FlowRecord::schema(),
        q.from_ms,
        q.to_ms,
        q.newest_first,
        |scan| {
            for i in 0..scan.rows {
                let f = FlowRecord::from_scan(scan, i);
                if f.ts_ms < q.from_ms || f.ts_ms > q.to_ms {
                    continue;
                }
                if !q.matches(&f) {
                    continue;
                }
                out.push(f);
                if out.len() >= q.limit {
                    return ControlFlow::Break(());
                }
            }
            ControlFlow::Continue(())
        },
    )?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Rollup queries (aggregates over the long-retention dataset)
// ---------------------------------------------------------------------------

/// Stream rollup rows in [from,to] matching `pred`.
pub fn rollup_each(
    ctx: &Ctx,
    from_ms: u64,
    to_ms: u64,
    pred: impl Fn(&RollupRecord) -> bool,
    mut f: impl FnMut(RollupRecord),
) -> Result<()> {
    let infos = ctx.rollup_index.read().unwrap().clone();
    for_each_segment_info::<RollupRecord>(
        &infos,
        RollupRecord::schema(),
        from_ms,
        to_ms,
        false,
        |scan| {
            for i in 0..scan.rows {
                let r = RollupRecord::from_scan(scan, i);
                if r.bucket_ms + 60_000 < from_ms || r.bucket_ms > to_ms {
                    continue;
                }
                if pred(&r) {
                    f(r);
                }
            }
            ControlFlow::Continue(())
        },
    )
}

/// Shared rollup filter built from API query params.
#[derive(Debug, Default, Clone)]
pub struct RollupFilter {
    pub exporter: Option<u128>,
    pub proto: Option<u8>,
    pub src_asn: Option<u32>,
    pub dst_asn: Option<u32>,
    pub src_ip: Option<u128>,
    pub dst_ip: Option<u128>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub src_country: Option<u16>,
    pub dst_country: Option<u16>,
}

impl RollupFilter {
    pub fn matches(&self, r: &RollupRecord) -> bool {
        if let Some(v) = self.exporter {
            if r.exporter != v {
                return false;
            }
        }
        if let Some(v) = self.proto {
            if r.protocol != v {
                return false;
            }
        }
        if let Some(v) = self.src_asn {
            if r.src_asn != v {
                return false;
            }
        }
        if let Some(v) = self.dst_asn {
            if r.dst_asn != v {
                return false;
            }
        }
        if let Some(v) = self.src_ip {
            if r.src_ip != v {
                return false;
            }
        }
        if let Some(v) = self.dst_ip {
            if r.dst_ip != v {
                return false;
            }
        }
        if let Some(v) = self.src_port {
            if r.src_port != v {
                return false;
            }
        }
        if let Some(v) = self.dst_port {
            if r.dst_port != v {
                return false;
            }
        }
        if let Some(v) = self.src_country {
            if r.src_country != v {
                return false;
            }
        }
        if let Some(v) = self.dst_country {
            if r.dst_country != v {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// JSON serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a FlowRecord to JSON, resolving org ids to names and label ids
/// to rule names.
pub fn flow_json(ctx: &Ctx, f: &FlowRecord) -> serde_json::Value {
    let label = ctx.label_names.get(&f.label_id).cloned();
    serde_json::json!({
        "ts": f.ts_ms / 1000,
        "ts_ms": f.ts_ms,
        "duration_ms": f.duration_ms,
        "src_ip": ip_string(f.src_ip),
        "dst_ip": ip_string(f.dst_ip),
        "src_port": f.src_port,
        "dst_port": f.dst_port,
        "protocol": f.protocol,
        "protocol_name": protocol_name(f.protocol),
        "tcp_flags": f.tcp_flags,
        "ingress_if": f.ingress_if,
        "egress_if": f.egress_if,
        "next_hop": ip_string(f.next_hop),
        "src_asn": f.src_asn,
        "dst_asn": f.dst_asn,
        "src_org": ctx.orgs.name(f.src_org),
        "dst_org": ctx.orgs.name(f.dst_org),
        "src_country": country_str(f.src_country),
        "dst_country": country_str(f.dst_country),
        "vlan": f.vlan,
        "bytes": f.bytes,
        "packets": f.packets,
        "exporter": ip_string(f.exporter),
        "engine_id": f.engine_id,
        "engine_type": f.engine_type,
        "sampler_interval": f.sampler_interval,
        "tcp_state": f.tcp_state,
        "label": label,
        "label_id": f.label_id,
    })
}

/// Format a rollup "by" dimension key for top-N output.
pub fn dim_value(by: &str, r: &RollupRecord) -> serde_json::Value {
    match by {
        "src_ip" => serde_json::json!(ip_string(r.src_ip)),
        "dst_ip" => serde_json::json!(ip_string(r.dst_ip)),
        "src_asn" => serde_json::json!(r.src_asn),
        "dst_asn" => serde_json::json!(r.dst_asn),
        "src_port" => serde_json::json!(r.src_port),
        "dst_port" => serde_json::json!(r.dst_port),
        "proto" | "protocol" => serde_json::json!(protocol_name(r.protocol)),
        "exporter" => serde_json::json!(ip_string(r.exporter)),
        "src_country" => serde_json::json!(country_str(r.src_country)),
        "dst_country" => serde_json::json!(country_str(r.dst_country)),
        _ => serde_json::json!(null),
    }
}

/// Raw u128 key for grouping by a dimension.
pub fn dim_key(by: &str, r: &RollupRecord) -> u128 {
    match by {
        "src_ip" => r.src_ip,
        "dst_ip" => r.dst_ip,
        "src_asn" => r.src_asn as u128,
        "dst_asn" => r.dst_asn as u128,
        "src_port" => r.src_port as u128,
        "dst_port" => r.dst_port as u128,
        "proto" | "protocol" => r.protocol as u128,
        "exporter" => r.exporter,
        "src_country" => r.src_country as u128,
        "dst_country" => r.dst_country as u128,
        _ => 0,
    }
}

/// Format a grouped u128 dimension key for top-N output.
pub fn format_key(by: &str, key: u128) -> serde_json::Value {
    match by {
        "src_ip" => serde_json::json!(ip_string(key)),
        "dst_ip" => serde_json::json!(ip_string(key)),
        "src_asn" => serde_json::json!(key as u32),
        "dst_asn" => serde_json::json!(key as u32),
        "src_port" => serde_json::json!(key as u16),
        "dst_port" => serde_json::json!(key as u16),
        "proto" | "protocol" => serde_json::json!(protocol_name(key as u8)),
        "exporter" => serde_json::json!(ip_string(key)),
        "src_country" => serde_json::json!(country_str(key as u16)),
        "dst_country" => serde_json::json!(country_str(key as u16)),
        _ => serde_json::json!(key),
    }
}

/// Parse an IP filter param (plain IP or CIDR prefix -> exact/prefix match).
/// Returns (addr, prefix_bits); prefix_bits=128/32 means exact.
pub fn parse_ip_filter(s: &str) -> Option<(u128, u8)> {
    if let Some((a, l)) = s.split_once('/') {
        let ip: std::net::IpAddr = a.parse().ok()?;
        let bits: u8 = l.parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return None;
        }
        let v = ip_to_u128(&ip);
        let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
        Some((v & mask, bits))
    } else {
        let ip: std::net::IpAddr = s.parse().ok()?;
        Some((ip_to_u128(&ip), if ip.is_ipv4() { 32 } else { 128 }))
    }
}

