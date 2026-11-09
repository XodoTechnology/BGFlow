//! In-memory rollup aggregation.
//!
//! Flows are aggregated by (minute, exporter, protocol, src/dst ASN,
//! src/dst IP, src/dst port) — timestamps, flags and interface details are
//! dropped so the rollup compresses well while preserving every grouping
//! dimension needed for top-talker / top-port / timeseries queries.
//! Finished minute buckets are drained into the rollup dataset.

use crate::timeutil::minute_floor;
use bgflow_types::{FlowRecord, RollupRecord};
use std::collections::HashMap;

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
}

#[derive(Debug, Default, Clone, Copy)]
struct RollupAccum {
    bytes: u64,
    packets: u64,
    flows: u64,
    min_ts: u64,
    max_ts: u64,
}

#[derive(Debug, Default)]
pub struct RollupAggregator {
    map: HashMap<RollupKey, RollupAccum>,
}

impl RollupAggregator {
    pub fn new() -> Self {
        RollupAggregator::default()
    }

    /// Current number of in-memory aggregates (for metrics/health).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Add a flow record to the aggregation.
    pub fn add(&mut self, f: &FlowRecord) {
        let key = RollupKey {
            bucket_ms: minute_floor(f.ts_ms),
            exporter: f.exporter,
            protocol: f.protocol,
            src_asn: f.src_asn,
            dst_asn: f.dst_asn,
            src_ip: f.src_ip,
            dst_ip: f.dst_ip,
            src_port: f.src_port,
            dst_port: f.dst_port,
            src_country: f.src_country,
            dst_country: f.dst_country,
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

    /// Drain all buckets strictly before `now_ms`'s minute.
    /// Returns rollup records ready to be pushed into the rollup dataset.
    pub fn drain_finished(&mut self, now_ms: u64) -> Vec<RollupRecord> {
        let current_min = minute_floor(now_ms);
        let mut out = Vec::new();
        self.map.retain(|k, v| {
            if k.bucket_ms < current_min {
                out.push(RollupRecord {
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
                    bytes: v.bytes,
                    packets: v.packets,
                    flows: v.flows,
                    min_ts_ms: v.min_ts,
                    max_ts_ms: v.max_ts,
                });
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
            out.push(RollupRecord {
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
                bytes: v.bytes,
                packets: v.packets,
                flows: v.flows,
                min_ts_ms: v.min_ts,
                max_ts_ms: v.max_ts,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(ts: u64, bytes: u64) -> FlowRecord {
        FlowRecord {
            ts_ms: ts,
            bytes,
            packets: 1,
            ..Default::default()
        }
    }

    #[test]
    fn aggregates_and_drains() {
        let mut agg = RollupAggregator::new();
        let base = 1_700_000_000_000u64;
        agg.add(&flow(base + 1000, 100));
        agg.add(&flow(base + 2000, 200));
        agg.add(&flow(base + 70_000, 50)); // next minute bucket

        // Nothing finished yet if "now" is inside first minute.
        let now = base + 30_000;
        assert!(agg.drain_finished(now).is_empty());

        // Once now crosses into the second minute, first bucket drains.
        let recs = agg.drain_finished(base + 61_000);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].flows, 2);
        assert_eq!(recs[0].bytes, 300);
        assert_eq!(recs[0].packets, 2);
        assert_eq!(recs[0].min_ts_ms, base + 1000);
        assert_eq!(recs[0].max_ts_ms, base + 2000);

        let rest = agg.drain_all();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].bytes, 50);
    }
}
