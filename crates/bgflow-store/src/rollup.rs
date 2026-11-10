//! In-memory rollup aggregation.
//!
//! Flows are aggregated by (minute, exporter, protocol, src/dst ASN,
//! src/dst IP, src/dst port) — timestamps, flags and interface details are
//! dropped so the rollup compresses well while preserving every grouping
//! dimension needed for top-talker / top-port / timeseries queries.
//! Finished minute buckets are drained into the rollup dataset.

use crate::timeutil::{hour_floor, minute_floor};
use bgflow_types::{ip_to_u128, u128_to_ip, FlowRecord, RollupRecord};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RollupKey {
    bucket_ms: u64,
    exporter: u128,
    protocol: u8,
    src_asn: u32,
    dst_asn: u32,
    src_ip: u128,
    dst_ip: u128,
    src_port: u16,
    dst_port: u16,
    src_country: u16,
    dst_country: u16,
    src_org: u32,
    dst_org: u32,
    label_id: u32,
}

#[derive(Debug, Default, Clone, Copy)]
struct RollupAccum {
    bytes: u64,
    packets: u64,
    flows: u64,
    min_ts: u64,
    max_ts: u64,
}

#[derive(Debug)]
pub struct RollupAggregator {
    map: HashMap<RollupKey, RollupAccum>,
    /// Coarse mode: hour buckets + IPs masked to /24 (v4) or /48 (v6).
    /// Used for the long-retention "big picture" dataset.
    coarse: bool,
}

/// Mask an IP for coarse aggregation: v4 -> /24, v6 -> /48.
/// Done via IpAddr so the v4-mapped storage form (and display) is preserved.
fn coarse_mask(ip: u128) -> u128 {
    match u128_to_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            ip_to_u128(&IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], 0)))
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let mut b = [0u8; 16];
            b[..6].copy_from_slice(&o[..6]);
            ip_to_u128(&IpAddr::V6(Ipv6Addr::from(b)))
        }
    }
}

impl RollupAggregator {
    pub fn new() -> Self {
        RollupAggregator { map: HashMap::new(), coarse: false }
    }

    /// Hourly buckets with /24·/48-masked IPs — far fewer distinct keys,
    /// suited to year-plus retention.
    pub fn coarse() -> Self {
        RollupAggregator { map: HashMap::new(), coarse: true }
    }

    /// Current number of in-memory aggregates (for metrics/health).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Add a flow record to the aggregation.
    pub fn add(&mut self, f: &FlowRecord) {
        let (bucket_ms, src_ip, dst_ip) = if self.coarse {
            (
                hour_floor(f.ts_ms),
                coarse_mask(f.src_ip),
                coarse_mask(f.dst_ip),
            )
        } else {
            (minute_floor(f.ts_ms), f.src_ip, f.dst_ip)
        };
        let key = RollupKey {
            bucket_ms,
            exporter: f.exporter,
            protocol: f.protocol,
            src_asn: f.src_asn,
            dst_asn: f.dst_asn,
            src_ip,
            dst_ip,
            src_port: f.src_port,
            dst_port: f.dst_port,
            src_country: f.src_country,
            dst_country: f.dst_country,
            src_org: f.src_org,
            dst_org: f.dst_org,
            label_id: f.label_id,
        };
        let e = self.map.entry(key).or_insert(RollupAccum {
            min_ts: f.ts_ms,
            max_ts: f.ts_ms,
            ..Default::default()
        });
        e.bytes += f.bytes;
        e.packets += f.packets;
        e.flows += 1;
        if f.ts_ms < e.min_ts {
            e.min_ts = f.ts_ms;
        }
        if f.ts_ms > e.max_ts {
            e.max_ts = f.ts_ms;
        }
    }

    fn period_floor(&self, ms: u64) -> u64 {
        if self.coarse { hour_floor(ms) } else { minute_floor(ms) }
    }

    fn to_record(k: &RollupKey, v: &RollupAccum) -> RollupRecord {
        RollupRecord {
            bucket_ms: k.bucket_ms,
            exporter: k.exporter,
            protocol: k.protocol,
            src_asn: k.src_asn,
            dst_asn: k.dst_asn,
            src_ip: k.src_ip,
            dst_ip: k.dst_ip,
            src_port: k.src_port,
            dst_port: k.dst_port,
            src_country: k.src_country,
            dst_country: k.dst_country,
            src_org: k.src_org,
            dst_org: k.dst_org,
            label_id: k.label_id,
            bytes: v.bytes,
            packets: v.packets,
            flows: v.flows,
            min_ts_ms: v.min_ts,
            max_ts_ms: v.max_ts,
        }
    }

    /// Drain all buckets strictly before `now_ms`'s period
    /// (minute, or hour in coarse mode).
    pub fn drain_finished(&mut self, now_ms: u64) -> Vec<RollupRecord> {
        let current = self.period_floor(now_ms);
        let mut out = Vec::new();
        self.map.retain(|k, v| {
            if k.bucket_ms < current {
                out.push(Self::to_record(k, v));
                false
            } else {
                true
            }
        });
        out
    }

    /// Drain everything (shutdown path).
    pub fn drain_all(&mut self) -> Vec<RollupRecord> {
        let mut out = Vec::with_capacity(self.map.len());
        for (k, v) in self.map.drain() {
            out.push(Self::to_record(&k, &v));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgflow_types::{ip_to_u128, FlowRecord};

    fn mkflow(ts: u64, src: u128, dst: u128) -> FlowRecord {
        FlowRecord {
            ts_ms: ts,
            src_ip: src,
            dst_ip: dst,
            bytes: 1000,
            packets: 10,
            ..Default::default()
        }
    }

    #[test]
    fn coarse_masks_and_hour_buckets() {
        let mut agg = RollupAggregator::coarse();
        // two IPs in same /24, different minutes, same hour
        let a = ip_to_u128(&"10.1.2.3".parse().unwrap());
        let b = ip_to_u128(&"10.1.2.200".parse().unwrap());
        let c = ip_to_u128(&"10.1.3.1".parse().unwrap()); // different /24
        let t0 = 1_700_000_000_000u64;
        agg.add(&mkflow(t0, a, a));
        agg.add(&mkflow(t0 + 60_000, b, b));
        agg.add(&mkflow(t0 + 3_600_000, c, c));
        let recs = agg.drain_all();
        // a+b merge into one masked key; c is a separate key+hour
        assert_eq!(recs.len(), 2);
        let same24 = recs.iter().find(|r| r.bytes == 2000).unwrap();
        // masked src must be the /24 base in v4-mapped form
        assert_eq!(same24.src_ip, ip_to_u128(&"10.1.2.0".parse().unwrap()));
        // bucket is hour-aligned
        assert_eq!(same24.bucket_ms % 3_600_000, 0);
    }
}
