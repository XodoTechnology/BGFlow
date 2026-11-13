//! Incremental "hot" aggregates — the alternative to scanning tens of
//! millions of rollup rows per dashboard refresh.
//!
//! As rollup buckets drain, their records also fold into per-bucket
//! in-memory aggregates covering a rolling window: minute-granularity
//! buckets for the recent detail window, hour-granularity buckets for
//! the full window. Queries inside the covered range are served from a
//! few tens of MB of structures in microseconds; anything older or
//! filtered falls back to segment scans.
//!
//! Top-N dimensions use bounded per-bucket candidate sets (top-K), so
//! memory stays flat regardless of IP cardinality. A key that is truly
//! top-N over a range is essentially always within top-K of at least
//! one bucket, so merged results match exact scans for all practical
//! purposes — the same approximation real flow analyzers rely on.

use crate::api::{Agg, SeriesPt};
use bgflow_store::schema::rollup_idx;
use bgflow_store::timeutil::{hour_floor, minute_floor};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Dimensions the hot tier tracks (order = index into `HotBucket::top`).
/// Bounded top-K per dimension per bucket.
pub const HOT_DIMS: [&str; 7] = [
    "src_ip", "dst_ip", "src_asn", "dst_asn", "dst_port", "src_country", "dst_country",
];

pub fn hot_dim_idx(by: &str) -> Option<usize> {
    HOT_DIMS.iter().position(|d| *d == by)
}

/// Bounded per-key aggregate map: keeps the top `cap` keys by bytes,
/// pruning to `cap/2` when full. Approximate for keys near the boundary,
/// exact for the heavy hitters that matter.
#[derive(Debug)]
pub struct TopK {
    map: HashMap<u128, Agg>,
    cap: usize,
}

impl TopK {
    fn new(cap: usize) -> Self {
        TopK { map: HashMap::new(), cap: cap.max(16) }
    }

    #[inline]
    fn add(&mut self, k: u128, a: Agg) {
        match self.map.entry(k) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                let v = e.get_mut();
                v.bytes += a.bytes;
                v.packets += a.packets;
                v.flows += a.flows;
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(a);
            }
        }
        if self.map.len() > self.cap {
            self.prune();
        }
    }

    fn prune(&mut self) {
        let keep = self.cap / 2;
        let mut v: Vec<(u128, Agg)> = self.map.drain().collect();
        if v.len() > keep {
            v.select_nth_unstable_by(keep, |a, b| {
                b.1.bytes.cmp(&a.1.bytes).then(b.1.flows.cmp(&a.1.flows))
            });
            v.truncate(keep);
        }
        self.map = v.into_iter().collect();
    }

    fn merge(&mut self, o: &TopK) {
        for (k, a) in &o.map {
            self.add(*k, *a);
        }
    }
}

/// Aggregates for one time bucket (minute or hour granularity).
#[derive(Debug)]
pub struct HotBucket {
    pub bytes: u64,
    pub packets: u64,
    pub flows: u64,
    /// [inbound, outbound, transit] — direction vs `local_asns` at the
    /// time the record was aggregated (rebuilt on config change).
    pub dir: [Agg; 3],
    /// Exact per-protocol aggregates (≤256 entries).
    pub by_proto: HashMap<u8, Agg>,
    /// Bounded top-K per HOT_DIMS dimension.
    pub top: Vec<TopK>,
}

/// Field bundle `add_one` consumes — lets both the writer (RollupRecord)
/// and the rebuild scan (RollupRow) feed the tier without constructing
/// intermediate records.
#[derive(Clone, Copy)]
pub struct HotRec {
    pub bucket_ms: u64,
    pub protocol: u8,
    pub src_asn: u32,
    pub dst_asn: u32,
    pub src_ip: u128,
    pub dst_ip: u128,
    pub dst_port: u16,
    pub src_country: u16,
    pub dst_country: u16,
    pub bytes: u64,
    pub packets: u64,
    pub flows: u64,
}

impl HotBucket {
    fn new(cap: usize) -> Self {
        HotBucket {
            bytes: 0,
            packets: 0,
            flows: 0,
            dir: [Agg::default(); 3],
            by_proto: HashMap::new(),
            top: (0..HOT_DIMS.len()).map(|_| TopK::new(cap)).collect(),
        }
    }

    #[inline]
    fn add(&mut self, r: &HotRec, local: &HashSet<u32>) {
        let a = Agg { bytes: r.bytes, packets: r.packets, flows: r.flows };
        self.bytes += r.bytes;
        self.packets += r.packets;
        self.flows += r.flows;
        // dst local → inbound(0); src local → outbound(1); else transit(2)
        let d = match (local.contains(&r.src_asn), local.contains(&r.dst_asn)) {
            (true, false) => 1,
            (false, true) => 0,
            _ => 2,
        };
        let dd = &mut self.dir[d];
        dd.bytes += a.bytes;
        dd.packets += a.packets;
        dd.flows += a.flows;
        let p = self.by_proto.entry(r.protocol).or_default();
        p.bytes += a.bytes;
        p.packets += a.packets;
        p.flows += a.flows;
        self.top[0].add(r.src_ip, a);
        self.top[1].add(r.dst_ip, a);
        self.top[2].add(r.src_asn as u128, a);
        self.top[3].add(r.dst_asn as u128, a);
        self.top[4].add(r.dst_port as u128, a);
        self.top[5].add(r.src_country as u128, a);
        self.top[6].add(r.dst_country as u128, a);
    }

    fn merge(&mut self, o: &HotBucket) {
        self.bytes += o.bytes;
        self.packets += o.packets;
        self.flows += o.flows;
        for i in 0..3 {
            self.dir[i].bytes += o.dir[i].bytes;
            self.dir[i].packets += o.dir[i].packets;
            self.dir[i].flows += o.dir[i].flows;
        }
        for (p, a) in &o.by_proto {
            let e = self.by_proto.entry(*p).or_default();
            e.bytes += a.bytes;
            e.packets += a.packets;
            e.flows += a.flows;
        }
        for (t, ot) in self.top.iter_mut().zip(o.top.iter()) {
            t.merge(ot);
        }
    }
}

/// The hot tier: two granularities over one rolling window.
pub struct HotStats {
    /// Recent detail window, minute buckets.
    pub minutes: BTreeMap<u64, HotBucket>,
    /// Full window, hour buckets.
    pub hours: BTreeMap<u64, HotBucket>,
    /// Oldest data timestamp the tier was built against — coverage is
    /// `[max(now - window, data_floor), now]`; 0 = not built yet.
    pub data_floor: u64,
    /// Hash of `local_asns` the direction splits were built with.
    pub asns_stamp: u64,
    detail_ms: u64,
    window_ms: u64,
    min_cap: usize,
    hour_cap: usize,
}

impl HotStats {
    pub fn new(window_ms: u64, detail_ms: u64) -> Self {
        HotStats {
            minutes: BTreeMap::new(),
            hours: BTreeMap::new(),
            data_floor: 0,
            asns_stamp: 0,
            detail_ms,
            window_ms,
            min_cap: 256,
            hour_cap: 512,
        }
    }

    /// Fold one drained rollup record into both granularities. Cheap —
    /// called per record; eviction happens in `add_batch`/`evict`.
    #[inline]
    pub fn add_one(&mut self, r: &HotRec, local: &HashSet<u32>, now: u64) {
        let hb = hour_floor(r.bucket_ms);
        self.hours
            .entry(hb)
            .or_insert_with(|| HotBucket::new(self.hour_cap))
            .add(r, local);
        let mb = minute_floor(r.bucket_ms);
        if mb + self.detail_ms >= now {
            self.minutes
                .entry(mb)
                .or_insert_with(|| HotBucket::new(self.min_cap))
                .add(r, local);
        }
    }

    /// Fold a drained batch, then evict aged buckets once.
    pub fn add_batch(&mut self, recs: &[HotRec], local: &HashSet<u32>, now: u64) {
        for r in recs {
            self.add_one(r, local, now);
        }
        self.evict(now);
    }

    /// Drop buckets that aged out of their windows.
    pub fn evict(&mut self, now: u64) {
        let hmin = now.saturating_sub(self.window_ms);
        let mmin = now.saturating_sub(self.detail_ms);
        while self.hours.keys().next().is_some_and(|k| *k < hmin) {
            self.hours.pop_first();
        }
        while self.minutes.keys().next().is_some_and(|k| *k < mmin) {
            self.minutes.pop_first();
        }
    }

    /// Merge another HotStats (per-worker partial or rebuild result).
    /// Coverage stamps are NOT merged — the caller sets them.
    pub fn merge_from(&mut self, o: HotStats) {
        for (k, b) in o.minutes {
            self.minutes
                .entry(k)
                .or_insert_with(|| HotBucket::new(self.min_cap))
                .merge(&b);
        }
        for (k, b) in o.hours {
            self.hours
                .entry(k)
                .or_insert_with(|| HotBucket::new(self.hour_cap))
                .merge(&b);
        }
    }

}

/// Merged query result over a range — what the API formats into the
/// same JSON shapes the segment-scan path produces.
pub struct HotView {
    pub total: Agg,
    /// Re-bucketed to `size` ms: bucket_start → SeriesPt.
    pub series: BTreeMap<u64, SeriesPt>,
    pub by_proto: HashMap<u8, Agg>,
    /// Per HOT_DIMS dimension: merged candidate map (untruncated —
    /// callers apply their own limit).
    pub tops: Vec<HashMap<u128, Agg>>,
}

impl HotStats {
    /// Whether `[from, to]` is fully covered by the requested tier.
    /// Coverage slides with the window: buckets older than
    /// `now - detail|window` are evicted, and nothing before
    /// `data_floor` exists in any dataset — so when the window floor
    /// reaches back past `data_floor`, even earlier `from` values are
    /// safe (the uncovered prefix is provably empty).
    pub fn covers(&self, from: u64, use_minutes: bool) -> bool {
        if self.data_floor == 0 {
            return false;
        }
        let now = crate::metrics::now_ms();
        let win = if use_minutes { self.detail_ms } else { self.window_ms };
        let win_floor = now.saturating_sub(win);
        from >= win_floor.max(self.data_floor) || self.data_floor >= win_floor
    }

    pub fn detail_ms(&self) -> u64 {
        self.detail_ms
    }

    /// Update window sizes after a config reload; eviction trims any
    /// buckets that fall outside the new windows on the next add.
    pub fn set_windows(&mut self, window_ms: u64, detail_ms: u64) {
        self.window_ms = window_ms;
        self.detail_ms = detail_ms;
    }

    /// Merge all buckets overlapping `[from, to]` into a HotView.
    /// `use_minutes` picks the granularity; `size` is the output series
    /// bucket width (re-bucketing is exact — buckets are disjoint).
    /// `mask_ips` applies the coarse /24·/48 mask to src/dst IP top
    /// keys — required when standing in for the hourly dataset, whose
    /// records carry masked IPs (hour buckets here are built from
    /// full-fidelity minute records).
    pub fn view(&self, from: u64, to: u64, size: u64, use_minutes: bool, mask_ips: bool) -> HotView {
        if from > to {
            return HotView {
                total: Agg::default(),
                series: BTreeMap::new(),
                by_proto: HashMap::new(),
                tops: (0..HOT_DIMS.len()).map(|_| HashMap::new()).collect(),
            };
        }
        let (map, period) = if use_minutes {
            (&self.minutes, 60_000u64)
        } else {
            (&self.hours, 3_600_000u64)
        };
        // Buckets starting in (from - period, to] can overlap the range.
        let lo = from.saturating_sub(period);
        let mut v = HotView {
            total: Agg::default(),
            series: BTreeMap::new(),
            by_proto: HashMap::new(),
            tops: (0..HOT_DIMS.len()).map(|_| HashMap::new()).collect(),
        };
        for (&k, b) in map.range(lo..=to) {
            if k + period < from || k > to {
                continue;
            }
            v.total.bytes += b.bytes;
            v.total.packets += b.packets;
            v.total.flows += b.flows;
            let sb = (k / size) * size;
            let s = v.series.entry(sb).or_insert_with(SeriesPt::default);
            s.total.bytes += b.bytes;
            s.total.packets += b.packets;
            s.total.flows += b.flows;
            s.inn.bytes += b.dir[0].bytes;
            s.inn.packets += b.dir[0].packets;
            s.inn.flows += b.dir[0].flows;
            s.out.bytes += b.dir[1].bytes;
            s.out.packets += b.dir[1].packets;
            s.out.flows += b.dir[1].flows;
            s.tr.bytes += b.dir[2].bytes;
            s.tr.packets += b.dir[2].packets;
            s.tr.flows += b.dir[2].flows;
            for (p, a) in &b.by_proto {
                let e = v.by_proto.entry(*p).or_default();
                e.bytes += a.bytes;
                e.packets += a.packets;
                e.flows += a.flows;
            }
            for (i, t) in b.top.iter().enumerate() {
                for (k, a) in &t.map {
                    let e = v.tops[i].entry(*k).or_default();
                    e.bytes += a.bytes;
                    e.packets += a.packets;
                    e.flows += a.flows;
                }
            }
        }
        if mask_ips {
            // Hour-tier stand-in for the hourly dataset: collapse IP
            // top keys to their /24·/48 bases, merging aggregates —
            // identical to what coarse rollup rows would have produced.
            for dim in 0..2 {
                let mut m: HashMap<u128, Agg> = HashMap::new();
                for (k, a) in v.tops[dim].drain() {
                    let e = m.entry(bgflow_store::rollup::coarse_mask(k)).or_default();
                    e.bytes += a.bytes;
                    e.packets += a.packets;
                    e.flows += a.flows;
                }
                v.tops[dim] = m;
            }
        }
        v
    }
}

/// Deterministic fingerprint of the local-ASN set — detects when
/// direction splits need a rebuild.
pub fn asns_stamp(local: &[u32]) -> u64 {
    let mut v = local.to_vec();
    v.sort_unstable();
    v.dedup();
    // FNV-1a — stable across processes.
    let mut h = 0xcbf29ce484222325u64;
    for n in v {
        for b in n.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

/// Rebuild the hot tier from rollup segments over the configured
/// windows, then swap it in atomically. Previous contents stay live
/// until the swap, so queries never see a half-built tier.
pub fn rebuild(
    ctx: &crate::query::Ctx,
    hot: &std::sync::RwLock<HotStats>,
    local: &std::sync::RwLock<Vec<u32>>,
) -> anyhow::Result<()> {
    use crate::query::{self, RollupSet};

    // Wait for the writer's first index publish — rebuilding against an
    // empty index would claim coverage it doesn't have. Bounded wait:
    // a daemon with no rollup data yet just builds an empty tier.
    let mut waited = 0u32;
    loop {
        if !ctx.rollup_index.read().unwrap().is_empty() {
            break;
        }
        if waited >= 300 {
            tracing::info!("hot tier: no rollup segments yet, starting empty");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        waited += 1;
    }

    let (window_ms, detail_ms) = {
        let h = hot.read().unwrap();
        (h.window_ms, h.detail_ms)
    };
    let now = crate::metrics::now_ms();
    let from = now.saturating_sub(window_ms);

    // Coverage can't precede the oldest retained rollup segment.
    let data_from = ctx
        .rollup_index
        .read()
        .unwrap()
        .iter()
        .map(|s| s.header.min_ts_ms)
        .min()
        .unwrap_or(now);

    let local_snapshot = local.read().unwrap().clone();
    let local_set: HashSet<u32> = local_snapshot.iter().copied().collect();
    let stamp = asns_stamp(&local_snapshot);

    let needed = vec![
        rollup_idx::BUCKET_MS,
        rollup_idx::BYTES,
        rollup_idx::PACKETS,
        rollup_idx::FLOWS,
        rollup_idx::PROTOCOL,
        rollup_idx::SRC_IP,
        rollup_idx::DST_IP,
        rollup_idx::SRC_ASN,
        rollup_idx::DST_ASN,
        rollup_idx::DST_PORT,
        rollup_idx::SRC_COUNTRY,
        rollup_idx::DST_COUNTRY,
    ];

    // Per-worker partial HotStats merged at the end — same pattern as
    // the bounded accumulator in rollup_scan_par.
    let local_c = local_set.clone();
    let mut stats = query::rollup_scan_par::<HotStats>(
        ctx,
        RollupSet::Minute,
        from,
        now,
        &needed,
        || HotStats::new(window_ms, detail_ms),
        {
            let local = local_c.clone();
            move |stats: &mut HotStats, r: &query::RollupRow| {
                stats.add_one(
                    &HotRec {
                        bucket_ms: r.bucket_ms(),
                        protocol: r.protocol(),
                        src_asn: r.src_asn(),
                        dst_asn: r.dst_asn(),
                        src_ip: r.src_ip(),
                        dst_ip: r.dst_ip(),
                        dst_port: r.dst_port(),
                        src_country: r.src_country(),
                        dst_country: r.dst_country(),
                        bytes: r.bytes(),
                        packets: r.packets(),
                        flows: r.flows(),
                    },
                    &local,
                    now,
                );
            }
        },
        |a: &mut HotStats, b: HotStats| a.merge_from(b),
    )?;

    stats.evict(now);
    stats.data_floor = data_from;
    stats.asns_stamp = stamp;
    let buckets = stats.minutes.len() + stats.hours.len();
    *hot.write().unwrap() = stats;
    tracing::info!("hot tier rebuilt: {} buckets", buckets);
    Ok(())
}
