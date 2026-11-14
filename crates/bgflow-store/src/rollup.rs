//! In-memory rollup aggregation.
//!
//! Flows are aggregated by (minute, exporter, protocol, src/dst ASN,
//! src/dst IP, src/dst port) — timestamps, flags and interface details are
//! dropped so the rollup compresses well while preserving every grouping
//! dimension needed for top-talker / top-port / timeseries queries.
//! Finished minute buckets are drained into the rollup dataset.

use crate::timeutil::{hour_floor, minute_floor};
use bgflow_types::{ip_to_u128, u128_to_ip, FlowRecord, GeoRecord, RollupRecord};
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
    vlan: u16,
    ingress_if: u32,
    egress_if: u32,
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
    /// When true, bytes/packets are multiplied by `sampler_interval`
    /// (1-in-N sampling) so rates reflect the unsampled traffic volume.
    /// Enable only for exporters that report raw sampled counts.
    weight_samples: bool,
}

/// Mask an IP for coarse aggregation: v4 -> /24, v6 -> /48.
/// Done via IpAddr so the v4-mapped storage form (and display) is preserved.
pub fn coarse_mask(ip: u128) -> u128 {
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
        RollupAggregator { map: HashMap::new(), coarse: false, weight_samples: false }
    }

    /// Hourly buckets with /24·/48-masked IPs — far fewer distinct keys,
    /// suited to year-plus retention.
    pub fn coarse() -> Self {
        RollupAggregator { map: HashMap::new(), coarse: true, weight_samples: false }
    }

    /// Enable sampler-interval weighting (see field docs).
    pub fn with_sampling(mut self, on: bool) -> Self {
        self.weight_samples = on;
        self
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
            vlan: f.vlan,
            ingress_if: f.ingress_if,
            egress_if: f.egress_if,
        };
        let e = self.map.entry(key).or_insert(RollupAccum {
            min_ts: f.ts_ms,
            max_ts: f.ts_ms,
            ..Default::default()
        });
        // Sampled flows (sFlow, sampled NetFlow/IPFIX) report 1-in-N
        // counts — scale bytes/packets back up when enabled. `flows`
        // stays the observed record count.
        let w = if self.weight_samples && f.sampler_interval > 1 {
            f.sampler_interval as u64
        } else {
            1
        };
        e.bytes += f.bytes.saturating_mul(w);
        e.packets += f.packets.saturating_mul(w);
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
            vlan: k.vlan,
            ingress_if: k.ingress_if,
            egress_if: k.egress_if,
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

    /// Emergency cardinality bound: when the live map grows past `cap`
    /// (e.g. a spoofed-source flood exploding distinct tuples), drain an
    /// arbitrary subset down to ~75% of cap. Correctness is preserved —
    /// readers sum rollup rows, so a tuple that keeps arriving simply
    /// produces additional records for the same bucket — at the cost of
    /// somewhat more, smaller segments.
    pub fn drain_over(&mut self, cap: usize) -> Vec<RollupRecord> {
        if self.map.len() <= cap {
            return Vec::new();
        }
        let target = cap.saturating_mul(3) / 4;
        let n = self.map.len() - target;
        // HashMap iteration order is hash-dependent → effectively an
        // unbiased subset, so no tuple class is preferentially flushed.
        let keys: Vec<RollupKey> = self.map.keys().take(n).copied().collect();
        let mut out = Vec::with_capacity(n);
        for k in keys {
            if let Some(v) = self.map.remove(&k) {
                out.push(Self::to_record(&k, &v));
            }
        }
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

// ---------------------------------------------------------------------------
// Geo aggregation — one row per (minute bucket, ~1° cell)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GeoKey {
    bucket_ms: u64,
    /// Rounded cell latitude + 90 (0..=180).
    lat_cell: u8,
    /// Rounded cell longitude + 180 (0..=360).
    lon_cell: u16,
}

#[derive(Debug, Default, Clone, Copy)]
struct GeoAccum {
    bytes: u64,
    packets: u64,
    flows: u64,
    lat_sum: u64,
    lon_sum: u64,
    dst_w: u64,
    src_w: u64,
    dst_cc: u16,
    src_cc: u16,
    city: u32,
}

/// Aggregates flows into geo bubbles for /api/v1/geo. Endpoint choice
/// mirrors the raw-scan path: dst geo when present, else src; each flow's
/// bytes weight exactly one side. Country/city keep first-nonzero-wins
/// semantics per cell.
#[derive(Debug)]
pub struct GeoAggregator {
    map: HashMap<GeoKey, GeoAccum>,
    weight_samples: bool,
}

impl GeoAggregator {
    pub fn new() -> Self {
        GeoAggregator { map: HashMap::new(), weight_samples: false }
    }

    /// See RollupAggregator::with_sampling.
    pub fn with_sampling(mut self, on: bool) -> Self {
        self.weight_samples = on;
        self
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn add(&mut self, f: &FlowRecord) {
        // dst endpoint wins when it carries any geo, else src — same rule
        // as the /geo raw-scan path.
        let (lat, lon, city, cc, is_dst) = if f.dst_lat != 0 || f.dst_lon != 0 || f.dst_city != 0 {
            (f.dst_lat, f.dst_lon, f.dst_city, f.dst_country, true)
        } else {
            (f.src_lat, f.src_lon, f.src_city, f.src_country, false)
        };
        if lat == 0 && lon == 0 {
            return;
        }
        // ~1° cells, identical rounding to the raw-scan path.
        let la = (lat as f64 / 100_000.0 - 90.0).round() as i32;
        let lo = (lon as f64 / 100_000.0 - 180.0).round() as i32;
        let key = GeoKey {
            bucket_ms: minute_floor(f.ts_ms),
            lat_cell: (la + 90) as u8,
            lon_cell: (lo + 180) as u16,
        };
        let e = self.map.entry(key).or_default();
        let w = if self.weight_samples && f.sampler_interval > 1 {
            f.sampler_interval as u64
        } else {
            1
        };
        e.bytes += f.bytes.saturating_mul(w);
        e.packets += f.packets.saturating_mul(w);
        e.flows += 1;
        e.lat_sum += lat as u64;
        e.lon_sum += lon as u64;
        if is_dst {
            e.dst_w += f.bytes.saturating_mul(w);
            if e.dst_cc == 0 {
                e.dst_cc = cc;
            }
        } else {
            e.src_w += f.bytes.saturating_mul(w);
            if e.src_cc == 0 {
                e.src_cc = cc;
            }
        }
        if e.city == 0 {
            e.city = city;
        }
    }

    fn to_record(k: &GeoKey, v: &GeoAccum) -> GeoRecord {
        GeoRecord {
            bucket_ms: k.bucket_ms,
            lat_cell: k.lat_cell,
            lon_cell: k.lon_cell,
            city: v.city,
            src_cc: v.src_cc,
            dst_cc: v.dst_cc,
            bytes: v.bytes,
            packets: v.packets,
            flows: v.flows,
            lat_sum: v.lat_sum,
            lon_sum: v.lon_sum,
            dst_w: v.dst_w,
            src_w: v.src_w,
        }
    }

    /// Drain buckets strictly before `now_ms`'s minute.
    pub fn drain_finished(&mut self, now_ms: u64) -> Vec<GeoRecord> {
        let current = minute_floor(now_ms);
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

    /// Cardinality bound — same contract as RollupAggregator::drain_over.
    pub fn drain_over(&mut self, cap: usize) -> Vec<GeoRecord> {
        if self.map.len() <= cap {
            return Vec::new();
        }
        let target = cap.saturating_mul(3) / 4;
        let n = self.map.len() - target;
        let keys: Vec<GeoKey> = self.map.keys().take(n).copied().collect();
        let mut out = Vec::with_capacity(n);
        for k in keys {
            if let Some(v) = self.map.remove(&k) {
                out.push(Self::to_record(&k, &v));
            }
        }
        out
    }

    pub fn drain_all(&mut self) -> Vec<GeoRecord> {
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

    fn mkgeo(ts: u64, dst_geo: bool) -> FlowRecord {
        FlowRecord {
            ts_ms: ts,
            bytes: 500,
            packets: 5,
            // stored-scaled coords: (deg+90)*1e5 / (deg+180)*1e5
            src_lat: ((40.0f64 + 90.0) * 100000.0) as u32, // 40°N-ish cell
            src_lon: ((-74.0f64 + 180.0) * 100000.0) as u32,
            src_city: 7,
            src_country: 840, // US
            dst_lat: if dst_geo { ((51.5f64 + 90.0) * 100000.0) as u32 } else { 0 },
            dst_lon: if dst_geo { ((-0.12f64 + 180.0) * 100000.0) as u32 } else { 0 },
            dst_city: if dst_geo { 9 } else { 0 },
            dst_country: if dst_geo { 826 } else { 0 }, // GB
            ..Default::default()
        }
    }

    #[test]
    fn geo_aggregates_cells_and_sides() {
        let mut agg = GeoAggregator::new();
        let t0 = 1_700_000_000_000u64;
        // dst has geo -> dst endpoint wins, dst side weighted
        agg.add(&mkgeo(t0, true));
        agg.add(&mkgeo(t0 + 1000, true));
        // dst lacks geo -> src endpoint wins
        agg.add(&mkgeo(t0 + 2000, false));
        let recs = agg.drain_all();
        assert_eq!(recs.len(), 2, "two distinct cells");
        let london = recs.iter().find(|r| r.dst_w > 0).unwrap();
        assert_eq!(london.flows, 2);
        assert_eq!(london.bytes, 1000);
        assert_eq!(london.dst_cc, 826);
        assert_eq!(london.src_w, 0);
        assert_eq!(london.city, 9);
        // cell coords: lon -0.12 -> cell ~0 (+180 bias); lat 51.5 -> ~52 (+90)
        assert_eq!(london.lon_cell, 180);
        let ny = recs.iter().find(|r| r.src_w > 0).unwrap();
        assert_eq!(ny.flows, 1);
        assert_eq!(ny.src_cc, 840);
        assert_eq!(ny.city, 7);
        // lat_sum/lon_sum reconstruct a centroid near the source coords
        let lat_deg = ny.lat_sum as f64 / ny.flows as f64 / 100000.0 - 90.0;
        assert!((lat_deg - 40.0).abs() < 0.001);
    }

    #[test]
    fn geo_skips_geo_less_flows() {
        let mut agg = GeoAggregator::new();
        let mut f = mkgeo(1_700_000_000_000, false);
        f.src_lat = 0;
        f.src_lon = 0;
        f.src_city = 0;
        agg.add(&f);
        assert!(agg.drain_all().is_empty());
    }
}
