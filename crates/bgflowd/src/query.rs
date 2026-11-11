//! Query path: scans segment files directly using the writer-published
//! segment indexes, so HTTP queries never contend with the ingest writer.

use crate::enrich::{PtrCache, StringTable};
use crate::rules::Ruleset;
use crate::writer::SegmentIndex;
use anyhow::Result;
use bgflow_store::encode::ColumnData;
use bgflow_store::schema::rollup_idx;
use bgflow_store::{for_each_segment_info, Record};
use bgflow_types::{ip_string, ip_to_u128, is_v4_mapped, country_str, protocol_name, FlowRecord, RollupRecord};
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::{Arc, RwLock};

/// Friendly exporter names from `[exporter_names]` config — bidirectional
/// lookup so filters accept either IPs or names. Swapped on SIGHUP reload.
#[derive(Default)]
pub struct ExporterNames {
    by_ip: HashMap<u128, String>,
    by_name: HashMap<String, u128>,
}

impl ExporterNames {
    pub fn build(map: &std::collections::BTreeMap<String, String>) -> Self {
        let mut e = ExporterNames::default();
        for (ip_s, name) in map {
            if let Ok(ip) = ip_s.trim().parse::<std::net::IpAddr>() {
                let u = ip_to_u128(&ip);
                e.by_ip.insert(u, name.clone());
                e.by_name.insert(name.trim().to_lowercase(), u);
            }
        }
        e
    }

    pub fn name_of(&self, ip: u128) -> Option<&str> {
        self.by_ip.get(&ip).map(|s| s.as_str())
    }

    /// Resolve a filter token: IP literal, "name (ip)" display form, or
    /// configured name (case-insensitive).
    pub fn resolve(&self, token: &str) -> Option<u128> {
        let t = token.trim();
        if let Ok(ip) = t.parse::<std::net::IpAddr>() {
            return Some(ip_to_u128(&ip));
        }
        // Display form "name (ip)" → use the parenthesized IP.
        if let (Some(start), Some(end)) = (t.rfind('('), t.rfind(')')) {
            if end == t.len() - 1 {
                if let Ok(ip) = t[start + 1..end].trim().parse::<std::net::IpAddr>() {
                    return Some(ip_to_u128(&ip));
                }
            }
        }
        self.by_name.get(&t.to_lowercase()).copied()
    }
}

/// Interface names from `[interface_names]` config, keyed by ifIndex.
/// Swapped on SIGHUP reload like exporter names.
#[derive(Default)]
pub struct InterfaceNames {
    by_if: HashMap<u32, String>,
}

impl InterfaceNames {
    pub fn build(map: &std::collections::BTreeMap<String, String>) -> Self {
        let mut e = InterfaceNames::default();
        for (k, v) in map {
            if let Ok(i) = k.trim().parse::<u32>() {
                e.by_if.insert(i, v.clone());
            }
        }
        e
    }

    pub fn name_of(&self, ifindex: u32) -> Option<&str> {
        self.by_if.get(&ifindex).map(|s| s.as_str())
    }

    pub fn all(&self) -> &HashMap<u32, String> {
        &self.by_if
    }
}

#[derive(Clone)]
pub struct Ctx {
    pub flow_index: SegmentIndex,
    pub rollup_index: SegmentIndex,
    /// Coarse hourly rollups (/24·/48-masked IPs, long retention).
    pub hourly_index: SegmentIndex,
    pub orgs: Arc<StringTable>,
    /// City-name string table for geo_city ids.
    pub cities: Arc<StringTable>,
    pub rules: Arc<Ruleset>,
    pub exporter_names: Arc<RwLock<ExporterNames>>,
    pub interface_names: Arc<RwLock<InterfaceNames>>,
    /// Reverse-DNS cache — non-blocking lookups for flow rows.
    pub ptr: Arc<PtrCache>,
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
    /// (masked base, mask) — mask=0 matches everything. See parse_ip_filter.
    pub src: Option<(u128, u128)>,
    pub dst: Option<(u128, u128)>,
    pub proto: Option<u8>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    /// Exporter allowlist — empty = all. Comma-separated in the API.
    pub exporters: Vec<u128>,
    pub src_asn: Option<u32>,
    pub dst_asn: Option<u32>,
    pub label: Option<u32>,
    /// IP version filters: 4 or 6 (matches that endpoint's address family).
    pub src_ipver: Option<u8>,
    pub dst_ipver: Option<u8>,
    pub src_org: Option<u32>,
    pub dst_org: Option<u32>,
    pub limit: usize,
    /// Skip this many matching rows before collecting (pagination).
    pub offset: usize,
    pub newest_first: bool,
}

impl FlowQuery {
    fn matches(&self, f: &FlowRecord) -> bool {
        if let Some((base, mask)) = self.src {
            if (f.src_ip & mask) != base {
                return false;
            }
        }
        if let Some((base, mask)) = self.dst {
            if (f.dst_ip & mask) != base {
                return false;
            }
        }
        if let Some(v) = self.src_ipver {
            if (if is_v4_mapped(f.src_ip) { 4 } else { 6 }) != v {
                return false;
            }
        }
        if let Some(v) = self.dst_ipver {
            if (if is_v4_mapped(f.dst_ip) { 4 } else { 6 }) != v {
                return false;
            }
        }
        if let Some(v) = self.src_org {
            if f.src_org != v {
                return false;
            }
        }
        if let Some(v) = self.dst_org {
            if f.dst_org != v {
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
        if !self.exporters.is_empty() && !self.exporters.contains(&f.exporter) {
            return false;
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

/// Scan raw flows newest-first (or oldest), collecting up to `limit` matches
/// after skipping `offset`.
pub fn flows(ctx: &Ctx, q: &FlowQuery) -> Result<Vec<FlowRecord>> {
    let infos = ctx.flow_index.read().unwrap().clone();
    let mut out: Vec<FlowRecord> = Vec::with_capacity(q.limit.min(1024));
    let mut skipped = 0usize;
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
                if skipped < q.offset {
                    skipped += 1;
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
// Rollup queries (aggregates over the rollup datasets)
// ---------------------------------------------------------------------------

/// Which rollup dataset to scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollupSet {
    /// 1-minute buckets, full IPs (standard retention).
    Minute,
    /// Hourly buckets, /24·/48-masked IPs (coarse long-retention dataset).
    Hourly,
}

impl RollupSet {
    /// Bucket width in ms — used for range pruning.
    pub fn period_ms(self) -> u64 {
        match self {
            RollupSet::Minute => 60_000,
            RollupSet::Hourly => 3_600_000,
        }
    }
}

/// Sparse per-row view over a decoded segment — only the columns the query
/// needs were decompressed. Missing columns read as 0.
pub struct RollupRow<'a> {
    arr: &'a [Option<&'a ColumnData>],
    i: usize,
}

impl RollupRow<'_> {
    #[inline]
    pub fn v(&self, idx: usize) -> u128 {
        self.arr
            .get(idx)
            .copied()
            .flatten()
            .map(|c| c.value_at(self.i))
            .unwrap_or(0)
    }
    #[inline]
    pub fn bucket_ms(&self) -> u64 {
        self.v(rollup_idx::BUCKET_MS) as u64
    }
    #[inline]
    pub fn bytes(&self) -> u64 {
        self.v(rollup_idx::BYTES) as u64
    }
    #[inline]
    pub fn packets(&self) -> u64 {
        self.v(rollup_idx::PACKETS) as u64
    }
    #[inline]
    pub fn flows(&self) -> u64 {
        self.v(rollup_idx::FLOWS) as u64
    }
    #[inline]
    pub fn protocol(&self) -> u8 {
        self.v(rollup_idx::PROTOCOL) as u8
    }
    #[inline]
    pub fn src_ip(&self) -> u128 {
        self.v(rollup_idx::SRC_IP)
    }
    #[inline]
    pub fn dst_ip(&self) -> u128 {
        self.v(rollup_idx::DST_IP)
    }
    #[inline]
    pub fn src_port(&self) -> u16 {
        self.v(rollup_idx::SRC_PORT) as u16
    }
    #[inline]
    pub fn dst_port(&self) -> u16 {
        self.v(rollup_idx::DST_PORT) as u16
    }
    #[inline]
    pub fn exporter(&self) -> u128 {
        self.v(rollup_idx::EXPORTER)
    }
    #[inline]
    pub fn src_asn(&self) -> u32 {
        self.v(rollup_idx::SRC_ASN) as u32
    }
    #[inline]
    pub fn dst_asn(&self) -> u32 {
        self.v(rollup_idx::DST_ASN) as u32
    }
    #[inline]
    pub fn src_country(&self) -> u16 {
        self.v(rollup_idx::SRC_COUNTRY) as u16
    }
    #[inline]
    pub fn dst_country(&self) -> u16 {
        self.v(rollup_idx::DST_COUNTRY) as u16
    }
    #[inline]
    pub fn src_org(&self) -> u32 {
        self.v(rollup_idx::SRC_ORG) as u32
    }
    #[inline]
    pub fn dst_org(&self) -> u32 {
        self.v(rollup_idx::DST_ORG) as u32
    }
    #[inline]
    pub fn label_id(&self) -> u32 {
        self.v(rollup_idx::LABEL_ID) as u32
    }
}

/// Shared rollup filter built from API query params.
#[derive(Debug, Default, Clone)]
pub struct RollupFilter {
    /// Exporter allowlist — empty = all exporters. Multi-valued so several
    /// exporters can be included (or everything-but via the UI).
    pub exporters: Vec<u128>,
    pub proto: Option<u8>,
    pub src_asn: Option<u32>,
    pub dst_asn: Option<u32>,
    /// (masked base, mask) — mask=0 matches everything. See parse_ip_filter.
    pub src_ip: Option<(u128, u128)>,
    pub dst_ip: Option<(u128, u128)>,
    /// IP version per endpoint: 4 or 6.
    pub src_ipver: Option<u8>,
    pub dst_ipver: Option<u8>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub src_country: Option<u16>,
    pub dst_country: Option<u16>,
    pub src_org: Option<u32>,
    pub dst_org: Option<u32>,
    pub label: Option<u32>,
}

impl RollupFilter {
    pub fn matches(&self, r: &RollupRow) -> bool {
        if !self.exporters.is_empty() && !self.exporters.contains(&r.exporter()) {
            return false;
        }
        if let Some(v) = self.proto {
            if r.protocol() != v {
                return false;
            }
        }
        if let Some(v) = self.src_asn {
            if r.src_asn() != v {
                return false;
            }
        }
        if let Some(v) = self.dst_asn {
            if r.dst_asn() != v {
                return false;
            }
        }
        if let Some((base, mask)) = self.src_ip {
            if (r.src_ip() & mask) != base {
                return false;
            }
        }
        if let Some((base, mask)) = self.dst_ip {
            if (r.dst_ip() & mask) != base {
                return false;
            }
        }
        if let Some(v) = self.src_ipver {
            if (if is_v4_mapped(r.src_ip()) { 4 } else { 6 }) != v {
                return false;
            }
        }
        if let Some(v) = self.dst_ipver {
            if (if is_v4_mapped(r.dst_ip()) { 4 } else { 6 }) != v {
                return false;
            }
        }
        if let Some(v) = self.src_port {
            if r.src_port() != v {
                return false;
            }
        }
        if let Some(v) = self.dst_port {
            if r.dst_port() != v {
                return false;
            }
        }
        if let Some(v) = self.src_country {
            if r.src_country() != v {
                return false;
            }
        }
        if let Some(v) = self.dst_country {
            if r.dst_country() != v {
                return false;
            }
        }
        if let Some(v) = self.src_org {
            if r.src_org() != v {
                return false;
            }
        }
        if let Some(v) = self.dst_org {
            if r.dst_org() != v {
                return false;
            }
        }
        if let Some(v) = self.label {
            if r.label_id() != v {
                return false;
            }
        }
        true
    }

    /// Schema columns this filter may read — feeds `rollup_needed`.
    fn cols_used(&self) -> Vec<usize> {
        use rollup_idx as ix;
        let mut v = Vec::new();
        if !self.exporters.is_empty() {
            v.push(ix::EXPORTER);
        }
        if self.proto.is_some() {
            v.push(ix::PROTOCOL);
        }
        if self.src_asn.is_some() {
            v.push(ix::SRC_ASN);
        }
        if self.dst_asn.is_some() {
            v.push(ix::DST_ASN);
        }
        if self.src_ip.is_some() || self.src_ipver.is_some() {
            v.push(ix::SRC_IP);
        }
        if self.dst_ip.is_some() || self.dst_ipver.is_some() {
            v.push(ix::DST_IP);
        }
        if self.src_port.is_some() {
            v.push(ix::SRC_PORT);
        }
        if self.dst_port.is_some() {
            v.push(ix::DST_PORT);
        }
        if self.src_country.is_some() {
            v.push(ix::SRC_COUNTRY);
        }
        if self.dst_country.is_some() {
            v.push(ix::DST_COUNTRY);
        }
        if self.src_org.is_some() {
            v.push(ix::SRC_ORG);
        }
        if self.dst_org.is_some() {
            v.push(ix::DST_ORG);
        }
        if self.label.is_some() {
            v.push(ix::LABEL_ID);
        }
        v
    }
}

/// Schema column feeding a top-N dimension (computed dims return the column
/// their value derives from).
pub fn dim_col(by: &str) -> Option<usize> {
    use rollup_idx as ix;
    Some(match by {
        "src_ip" | "src_ipver" => ix::SRC_IP,
        "dst_ip" | "dst_ipver" => ix::DST_IP,
        "src_asn" => ix::SRC_ASN,
        "dst_asn" => ix::DST_ASN,
        "src_port" => ix::SRC_PORT,
        "dst_port" => ix::DST_PORT,
        "proto" | "protocol" => ix::PROTOCOL,
        "exporter" => ix::EXPORTER,
        "src_country" => ix::SRC_COUNTRY,
        "dst_country" => ix::DST_COUNTRY,
        "src_org" => ix::SRC_ORG,
        "dst_org" => ix::DST_ORG,
        "label" | "label_id" => ix::LABEL_ID,
        _ => return None,
    })
}

/// Columns a rollup query must decompress: bucket + metrics + whatever the
/// filter and requested dims actually read.
pub fn rollup_needed(f: &RollupFilter, dims: &[&str]) -> Vec<usize> {
    use rollup_idx as ix;
    let mut s = std::collections::BTreeSet::new();
    s.insert(ix::BUCKET_MS);
    s.insert(ix::BYTES);
    s.insert(ix::PACKETS);
    s.insert(ix::FLOWS);
    for c in f.cols_used() {
        s.insert(c);
    }
    for d in dims {
        if let Some(c) = dim_col(d) {
            s.insert(c);
        }
    }
    s.into_iter().collect()
}

/// Scan rollup rows in [from,to] on `set`, decoding only `needed` columns.
/// The callback receives a RollupRow; return ControlFlow::Break to stop.
pub fn rollup_scan(
    ctx: &Ctx,
    set: RollupSet,
    from_ms: u64,
    to_ms: u64,
    needed: &[usize],
    mut f: impl FnMut(&RollupRow) -> ControlFlow<()>,
) -> Result<()> {
    let infos = match set {
        RollupSet::Minute => ctx.rollup_index.read().unwrap().clone(),
        RollupSet::Hourly => ctx.hourly_index.read().unwrap().clone(),
    };
    let period = set.period_ms();
    bgflow_store::for_each_segment_cols(
        &infos,
        RollupRecord::schema(),
        needed,
        from_ms,
        to_ms,
        false,
        |columns, rows| {
            let mut arr: Vec<Option<&ColumnData>> = vec![None; RollupRecord::schema().columns.len()];
            for (ci, data) in columns {
                arr[*ci] = Some(data);
            }
            for i in 0..rows {
                let row = RollupRow { arr: &arr, i };
                if row.bucket_ms() + period < from_ms || row.bucket_ms() > to_ms {
                    continue;
                }
                if f(&row).is_break() {
                    return ControlFlow::Break(());
                }
            }
            ControlFlow::Continue(())
        },
    )
}

/// Parallel rollup aggregation. Partitions the overlapping segments
/// across worker threads; each thread decodes its segments and feeds
/// rows into its own `T` via `add`, then partial states are merged with
/// `merge` on the calling thread. Only valid for order-insensitive
/// aggregates (sums/counts) — there is no early-break.
///
/// `init` produces an empty accumulator per worker and for the merge
/// target; `add` receives `(state, row)` and should apply the row's
/// filter check itself (the filter is `Sync` and shared).
pub fn rollup_scan_par<T>(
    ctx: &Ctx,
    set: RollupSet,
    from_ms: u64,
    to_ms: u64,
    needed: &[usize],
    init: impl Fn() -> T + Sync,
    add: impl Fn(&mut T, &RollupRow) + Sync,
    merge: impl Fn(&mut T, T),
) -> Result<T>
where
    T: Send,
{
    let infos = match set {
        RollupSet::Minute => ctx.rollup_index.read().unwrap().clone(),
        RollupSet::Hourly => ctx.hourly_index.read().unwrap().clone(),
    };
    let period = set.period_ms();
    let idx: Vec<usize> = infos
        .iter()
        .enumerate()
        .filter(|(_, s)| s.overlaps(from_ms, to_ms))
        .map(|(i, _)| i)
        .collect();

    let nth = bgflow_store::scan_threads().min(idx.len().max(1));
    let chunk_size = idx.len().div_ceil(nth).max(1);
    let ncols = RollupRecord::schema().columns.len();

    let results: Vec<Result<T>> = std::thread::scope(|s| {
        let mut handles = Vec::new();
        for chunk in idx.chunks(chunk_size) {
            let infos = Arc::clone(&infos);
            let chunk: Vec<usize> = chunk.to_vec();
            let needed = needed.to_vec();
            let init = &init;
            let add = &add;
            handles.push(s.spawn(move || -> Result<T> {
                let mut state = init();
                for &i in &chunk {
                    let info = &infos[i];
                    let reader = bgflow_store::segment::SegmentReader::open(&info.path)?;
                    let columns = reader.decode_columns(&needed)?;
                    let mut arr: Vec<Option<&ColumnData>> = vec![None; ncols];
                    for (ci, data) in &columns {
                        arr[*ci] = Some(data);
                    }
                    for ri in 0..reader.header.row_count as usize {
                        let row = RollupRow {
                            arr: &arr,
                            i: ri,
                        };
                        if row.bucket_ms() + period < from_ms || row.bucket_ms() > to_ms {
                            continue;
                        }
                        add(&mut state, &row);
                    }
                }
                Ok(state)
            }));
        }
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("rollup scan worker panicked")))
            })
            .collect()
    });

    let mut out = init();
    for r in results {
        merge(&mut out, r?);
    }
    Ok(out)
}

/// Shard map type used by `rollup_scan_sharded` — FxHash keeps per-row
/// hashing ~5x cheaper than SipHash on multi-million-row scans.
pub type ShardMap<K, V> = HashMap<K, V, rustc_hash::FxBuildHasher>;

/// Parallel rollup aggregation for HIGH-cardinality groupings (e.g.
/// conversations, top-N over IPs). Like `rollup_scan_par`, segments are
/// decoded on worker threads — but instead of each worker building a
/// private map over every key (which multiplies memory by the worker
/// count), rows are routed by key hash into `shards` disjoint maps behind
/// mutexes. Each key's complete aggregate therefore lives in exactly one
/// shard: total memory equals a single sequential map, while decode and
/// aggregation both run in parallel.
///
/// `extract` pushes `(key, value)` pairs for a row into `out` (usually
/// one; overview pushes one per top dimension); `add` merges a buffered
/// value into the shard's entry for that key. `bounded_*` accumulate a
/// small caller-defined state per worker (merged at the end) for
/// aggregates that don't fit the key/value map — pass no-ops for `()`.
/// Workers buffer per-shard batches so mutex acquisitions stay rare.
/// Returns the shard maps (keys partitioned, never duplicated) plus the
/// merged bounded state.
pub fn rollup_scan_sharded<K, V, B>(
    ctx: &Ctx,
    set: RollupSet,
    from_ms: u64,
    to_ms: u64,
    needed: &[usize],
    filter: &RollupFilter,
    shards: usize,
    extract: impl Fn(&RollupRow, &mut Vec<(K, V)>) + Sync,
    add: impl Fn(&mut V, V) + Sync,
    bounded_init: impl Fn() -> B + Sync,
    bounded_add: impl Fn(&mut B, &RollupRow) + Sync,
    bounded_merge: impl Fn(&mut B, B),
) -> Result<(Vec<ShardMap<K, V>>, B)>
where
    K: Eq + std::hash::Hash + Send,
    V: Send,
    B: Send,
{
    use std::hash::Hasher;

    let infos = match set {
        RollupSet::Minute => ctx.rollup_index.read().unwrap().clone(),
        RollupSet::Hourly => ctx.hourly_index.read().unwrap().clone(),
    };
    let period = set.period_ms();
    let idx: Vec<usize> = infos
        .iter()
        .enumerate()
        .filter(|(_, s)| s.overlaps(from_ms, to_ms))
        .map(|(i, _)| i)
        .collect();

    let nth = bgflow_store::scan_threads().min(idx.len().max(1));
    let shards = shards.max(1);
    let chunk_size = idx.len().div_ceil(nth).max(1);
    let ncols = RollupRecord::schema().columns.len();
    let maps: Vec<std::sync::Mutex<ShardMap<K, V>>> = (0..shards)
        .map(|_| std::sync::Mutex::new(ShardMap::default()))
        .collect();

    let scan_res: Result<B> = std::thread::scope(|s| {
        let mut handles = Vec::new();
        for chunk in idx.chunks(chunk_size) {
            let infos = Arc::clone(&infos);
            let chunk: Vec<usize> = chunk.to_vec();
            let needed = needed.to_vec();
            let maps = &maps;
            let filter = filter;
            let extract = &extract;
            let add = &add;
            let bounded_init = &bounded_init;
            let bounded_add = &bounded_add;
            handles.push(s.spawn(move || -> Result<B> {
                // Per-shard buffers: flushed into the shared maps in
                // batches so lock hold time stays tiny.
                const FLUSH_AT: usize = 8192;
                let mut bstate = bounded_init();
                let mut tmp: Vec<(K, V)> = Vec::with_capacity(8);
                let mut bufs: Vec<Vec<(K, V)>> =
                    (0..shards).map(|_| Vec::new()).collect();
                let flush = |bufs: &mut Vec<Vec<(K, V)>>| {
                    for (si, buf) in bufs.iter_mut().enumerate() {
                        if buf.is_empty() {
                            continue;
                        }
                        let mut g = maps[si].lock().unwrap();
                        for (k, v) in buf.drain(..) {
                            match g.entry(k) {
                                std::collections::hash_map::Entry::Occupied(mut e) => {
                                    add(e.get_mut(), v);
                                }
                                std::collections::hash_map::Entry::Vacant(e) => {
                                    e.insert(v);
                                }
                            }
                        }
                    }
                };
                for &i in &chunk {
                    let info = &infos[i];
                    let reader = bgflow_store::segment::SegmentReader::open(&info.path)?;
                    let columns = reader.decode_columns(&needed)?;
                    let mut arr: Vec<Option<&ColumnData>> = vec![None; ncols];
                    for (ci, data) in &columns {
                        arr[*ci] = Some(data);
                    }
                    for ri in 0..reader.header.row_count as usize {
                        let row = RollupRow {
                            arr: &arr,
                            i: ri,
                        };
                        if row.bucket_ms() + period < from_ms || row.bucket_ms() > to_ms {
                            continue;
                        }
                        if !filter.matches(&row) {
                            continue;
                        }
                        bounded_add(&mut bstate, &row);
                        tmp.clear();
                        extract(&row, &mut tmp);
                        for (k, v) in tmp.drain(..) {
                            let mut h = rustc_hash::FxHasher::default();
                            k.hash(&mut h);
                            let si = (h.finish() as usize) % shards;
                            bufs[si].push((k, v));
                            if bufs[si].len() >= FLUSH_AT {
                                flush(&mut bufs);
                            }
                        }
                    }
                }
                flush(&mut bufs);
                Ok(bstate)
            }));
        }
        let mut bstate = bounded_init();
        for h in handles {
            let partial = h
                .join()
                .unwrap_or_else(|_| Err(anyhow::anyhow!("rollup scan worker panicked")))?;
            bounded_merge(&mut bstate, partial);
        }
        Ok(bstate)
    });
    let bstate = scan_res?;

    Ok((
        maps.into_iter()
            .map(|m| m.into_inner().unwrap_or_else(|e| e.into_inner()))
            .collect(),
        bstate,
    ))
}

// ---------------------------------------------------------------------------
// JSON serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a FlowRecord to JSON, resolving org ids to names and label ids
/// to rule names.
pub fn flow_json(ctx: &Ctx, f: &FlowRecord) -> serde_json::Value {
    let label = ctx.rules.name_of(f.label_id);
    let mut out = serde_json::json!({
        "ts": f.ts_ms / 1000,
        "ts_ms": f.ts_ms,
        "duration_ms": f.duration_ms,
        "src_ip": ip_string(f.src_ip),
        "dst_ip": ip_string(f.dst_ip),
        // PTR names resolve in the background — a miss returns null now and
        // fills the cache for subsequent requests.
        "src_ptr": ctx.ptr.get(f.src_ip).flatten().map_or(serde_json::Value::Null, |s| serde_json::json!(s)),
        "dst_ptr": ctx.ptr.get(f.dst_ip).flatten().map_or(serde_json::Value::Null, |s| serde_json::json!(s)),
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
        "ip_ttl": f.ip_ttl,
        "flow_end_reason": f.flow_end_reason,
        "icmp_type": f.icmp_type,
        "icmp_code": f.icmp_code,
        "post_nat_src": if f.post_nat_src != 0 { serde_json::json!(ip_string(f.post_nat_src)) } else { serde_json::Value::Null },
        "post_nat_dst": if f.post_nat_dst != 0 { serde_json::json!(ip_string(f.post_nat_dst)) } else { serde_json::Value::Null },
        "label": label,
        "label_id": f.label_id,
    });
    // MMDB city geo (schema ≥4 segments only; 0 = unknown) — merged in
    // separately to keep the json! macro under its recursion limit.
    let geo = serde_json::json!({
        "src_city": ctx.cities.name(f.src_city),
        "dst_city": ctx.cities.name(f.dst_city),
        "src_region": ctx.cities.name(f.src_region),
        "dst_region": ctx.cities.name(f.dst_region),
        "src_lat": if f.src_lat != 0 { serde_json::json!(f.src_lat as f64 / 100000.0 - 90.0) } else { serde_json::Value::Null },
        "dst_lat": if f.dst_lat != 0 { serde_json::json!(f.dst_lat as f64 / 100000.0 - 90.0) } else { serde_json::Value::Null },
        "src_lon": if f.src_lon != 0 { serde_json::json!(f.src_lon as f64 / 100000.0 - 180.0) } else { serde_json::Value::Null },
        "dst_lon": if f.dst_lon != 0 { serde_json::json!(f.dst_lon as f64 / 100000.0 - 180.0) } else { serde_json::Value::Null },
    });
    if let (Some(dst), Some(src)) = (out.as_object_mut(), geo.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    out
}

/// Grouping key for a top-N dimension.
pub fn dim_key(by: &str, r: &RollupRow) -> u128 {
    match by {
        "src_ip" => r.src_ip(),
        "dst_ip" => r.dst_ip(),
        "src_asn" => r.src_asn() as u128,
        "dst_asn" => r.dst_asn() as u128,
        "src_port" => r.src_port() as u128,
        "dst_port" => r.dst_port() as u128,
        "proto" | "protocol" => r.protocol() as u128,
        "exporter" => r.exporter(),
        "src_country" => r.src_country() as u128,
        "dst_country" => r.dst_country() as u128,
        "src_org" => r.src_org() as u128,
        "dst_org" => r.dst_org() as u128,
        "label" | "label_id" => r.label_id() as u128,
        "src_ipver" => {
            if is_v4_mapped(r.src_ip()) { 4 } else { 6 }
        }
        "dst_ipver" => {
            if is_v4_mapped(r.dst_ip()) { 4 } else { 6 }
        }
        _ => 0,
    }
}

/// Format a grouped u128 dimension key for top-N output.
pub fn format_key(ctx: &Ctx, by: &str, key: u128) -> serde_json::Value {
    // Dimensions where 0 means "unset/unknown" display as "-".
    match by {
        "src_asn" | "dst_asn" | "src_country" | "dst_country" | "src_org"
        | "dst_org" | "label" | "label_id" if key == 0 => {
            return serde_json::json!("-");
        }
        _ => {}
    }
    match by {
        "src_ip" => serde_json::json!(ip_string(key)),
        "dst_ip" => serde_json::json!(ip_string(key)),
        "src_asn" => serde_json::json!(key as u32),
        "dst_asn" => serde_json::json!(key as u32),
        "src_port" => serde_json::json!(key as u16),
        "dst_port" => serde_json::json!(key as u16),
        "proto" | "protocol" => serde_json::json!(protocol_name(key as u8)),
        "exporter" => {
            let g = ctx.exporter_names.read().unwrap();
            match g.name_of(key) {
                Some(n) => serde_json::json!(format!("{} ({})", n, ip_string(key))),
                None => serde_json::json!(ip_string(key)),
            }
        }
        "src_country" => {
            let s = country_str(key as u16);
            serde_json::json!(if s.is_empty() { "-" } else { s.as_str() })
        }
        "dst_country" => {
            let s = country_str(key as u16);
            serde_json::json!(if s.is_empty() { "-" } else { s.as_str() })
        }
        "src_org" => ctx
            .orgs
            .name(key as u32)
            .map(|s| serde_json::json!(s))
            .unwrap_or_else(|| serde_json::json!(key as u32)),
        "dst_org" => ctx
            .orgs
            .name(key as u32)
            .map(|s| serde_json::json!(s))
            .unwrap_or_else(|| serde_json::json!(key as u32)),
        "label" | "label_id" => ctx
            .rules
            .name_of(key as u32)
            .map(|s| serde_json::json!(s))
            .unwrap_or_else(|| serde_json::json!(key as u32)),
        "src_ipver" | "dst_ipver" => {
            serde_json::json!(if key == 4 { "IPv4" } else { "IPv6" })
        }
        _ => serde_json::json!(key),
    }
}

/// Parse an IP filter param (plain IP or CIDR) into (masked_base, mask).
///
/// IMPORTANT: `ip_to_u128` stores IPv4 in the LOW 32 bits (::ffff:a.b.c.d),
/// so v4 prefix masks apply to the low word, not the top bits of the u128.
/// We precompute the mask here so matching is a single AND+compare per row.
/// mask=0 matches everything ("0.0.0.0/0" or "::/0").
pub fn parse_ip_filter(s: &str) -> Option<(u128, u128)> {
    let (addr, bits) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l.parse::<u8>().ok()?)),
        None => (s, None),
    };
    let ip: std::net::IpAddr = addr.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let bits = bits.unwrap_or(max);
    if bits > max {
        return None;
    }
    let base = ip_to_u128(&ip);
    let mask = if bits == 0 {
        0
    } else if ip.is_ipv4() {
        // Keep the top `bits` of the low 32 bits (plus the constant
        // ::ffff: marker region, which is identical for all v4 addrs).
        0xFFFF_FFFFu128 << (32 - bits)
    } else {
        u128::MAX << (128 - bits)
    };
    Some((base & mask, mask))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgflow_types::ip_to_u128;
    use std::net::IpAddr;

    fn matches(flt: (u128, u128), ip: &str) -> bool {
        let ip: IpAddr = ip.parse().unwrap();
        (ip_to_u128(&ip) & flt.1) == flt.0
    }

    #[test]
    fn v4_prefixes() {
        let f8 = parse_ip_filter("10.0.0.0/8").unwrap();
        assert!(matches(f8, "10.1.2.3"));
        assert!(matches(f8, "10.255.255.255"));
        assert!(!matches(f8, "11.0.0.1"));
        assert!(!matches(f8, "100.64.0.1"));
        assert!(!matches(f8, "172.16.0.1"));

        let f24 = parse_ip_filter("192.168.1.0/24").unwrap();
        assert!(matches(f24, "192.168.1.250"));
        assert!(!matches(f24, "192.168.2.1"));
        assert!(!matches(f24, "10.0.0.1"));

        // Plain IP = exact match
        let exact = parse_ip_filter("10.1.2.3").unwrap();
        assert!(matches(exact, "10.1.2.3"));
        assert!(!matches(exact, "10.1.2.4"));

        // /32 exact, /0 match-all
        let f32 = parse_ip_filter("1.2.3.4/32").unwrap();
        assert!(matches(f32, "1.2.3.4") && !matches(f32, "1.2.3.5"));
        let all = parse_ip_filter("0.0.0.0/0").unwrap();
        assert!(matches(all, "8.8.8.8"));
    }

    #[test]
    fn v6_prefixes() {
        let f = parse_ip_filter("2001:db8::/32").unwrap();
        assert!(matches(f, "2001:db8::1"));
        assert!(matches(f, "2001:db8:ffff::dead:beef"));
        assert!(!matches(f, "2001:db9::1"));
        assert!(!matches(f, "::1"));

        let exact6 = parse_ip_filter("2001:db8::1").unwrap();
        assert!(matches(exact6, "2001:db8::1"));
        assert!(!matches(exact6, "2001:db8::2"));

        // v4 must not match v6 filters and vice versa
        let v6f = parse_ip_filter("::ffff:10.0.0.0/104").unwrap();
        assert!(matches(v6f, "10.1.2.3")); // v4-mapped IS ::ffff:a.b.c.d
        assert!(!matches(v6f, "2001:db8::1"));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_ip_filter("not-an-ip").is_none());
        assert!(parse_ip_filter("10.0.0.0/33").is_none());
        assert!(parse_ip_filter("2001:db8::/129").is_none());
        assert!(parse_ip_filter("10.0.0.0/abc").is_none());
    }
}

