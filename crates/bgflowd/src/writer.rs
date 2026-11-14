//! Writer task: the single owner of all Datasets. Ingest sends parsed
//! FlowRecords over a channel; this task batches them into the raw dataset,
//! feeds the minute and coarse (hourly, /24·/48-masked) rollup aggregators,
//! drains finished buckets into their datasets, runs retention, and
//! publishes segment-index snapshots that the HTTP query path reads
//! directly from segment files.

use crate::config::StorageConfig;
use crate::hot::{HotRec, HotStats};
use crate::metrics::{now_ms, Metrics};
use bgflow_store::{Dataset, DatasetOpts, GeoAggregator, RollupAggregator, SegmentInfo};
use bgflow_types::{FlowRecord, GeoRecord, RollupRecord};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;

/// Shared read-only view of on-disk segments, refreshed by the writer.
pub type SegmentIndex = Arc<RwLock<Arc<Vec<SegmentInfo>>>>;

/// Shared status snapshot for the API/UI.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct StatusSnapshot {
    pub started_ms: u64,
    pub uptime_secs: u64,
    pub writer_alive: bool,
    pub last_flush_ms: u64,
    pub buffered_rows: usize,
    pub flow_segments: usize,
    pub flow_rows: u64,
    pub flow_bytes: u64,
    pub flow_buffered: usize,
    pub rollup_segments: usize,
    pub rollup_rows: u64,
    pub rollup_bytes: u64,
    pub rollup_buffered: usize,
    pub rollup_pending_buckets: usize,
    pub hourly_segments: usize,
    pub hourly_rows: u64,
    pub hourly_bytes: u64,
    pub hourly_buffered: usize,
    pub hourly_pending_buckets: usize,
    pub geo_segments: usize,
    pub geo_rows: u64,
    pub geo_bytes: u64,
    pub geo_buffered: usize,
    pub geo_pending_buckets: usize,
}

#[derive(Clone)]
pub struct WriterShared {
    pub flow_index: SegmentIndex,
    pub rollup_index: SegmentIndex,
    pub hourly_index: SegmentIndex,
    /// Geo-bubble rollup index — backs /api/v1/geo.
    pub geo_index: SegmentIndex,
    pub status: Arc<RwLock<StatusSnapshot>>,
    /// Live flow tail for the SSE endpoint. Receivers that fall behind
    /// get `RecvError::Lagged` and skip — ingest is never blocked.
    pub live_tx: tokio::sync::broadcast::Sender<bgflow_types::FlowRecord>,
}

impl WriterShared {
    pub fn new() -> Self {
        WriterShared {
            flow_index: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            rollup_index: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            hourly_index: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            geo_index: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            status: Arc::new(RwLock::new(StatusSnapshot::default())),
            live_tx: tokio::sync::broadcast::channel(8192).0,
        }
    }
}

const BATCH: usize = 8192;
/// Live-tuple caps for the rollup aggregators (~200B/entry incl.
/// hashmap overhead → ≈60MB / ≈120MB worst case). A cardinality
/// explosion — e.g. a DDoS with spoofed sources — would otherwise grow
/// the maps without bound until the daemon OOMs. Normal operation sits
/// far below these (tens of thousands of live keys).
const AGG_MAP_CAP: usize = 300_000;
/// Coarse buckets hold a whole hour of tuples in memory — a tight cap
/// makes `drain_over` flush partials throughout the hour, bounding both
/// memory and crash-loss (an unflushed map is gone on SIGKILL).
const COARSE_AGG_MAP_CAP: usize = 200_000;

/// Fold drained minute-rollup records into the hot tier — this is what
/// lets dashboard queries skip segment scans entirely.
fn feed_hot(hot: &RwLock<HotStats>, local: &RwLock<Vec<u32>>, recs: &[RollupRecord]) {
    if recs.is_empty() {
        return;
    }
    let local_set: HashSet<u32> = local.read().unwrap().iter().copied().collect();
    let now = now_ms();
    let hot_recs: Vec<HotRec> = recs
        .iter()
        .map(|r| HotRec {
            bucket_ms: r.bucket_ms,
            protocol: r.protocol,
            src_asn: r.src_asn,
            dst_asn: r.dst_asn,
            src_ip: r.src_ip,
            dst_ip: r.dst_ip,
            dst_port: r.dst_port,
            src_country: r.src_country,
            dst_country: r.dst_country,
            bytes: r.bytes,
            packets: r.packets,
            flows: r.flows,
        })
        .collect();
    hot.write().unwrap().add_batch(&hot_recs, &local_set, now);
}

pub async fn run(
    cfg: Arc<RwLock<StorageConfig>>,
    shared: WriterShared,
    metrics: Arc<Metrics>,
    mut rx: mpsc::Receiver<FlowRecord>,
    hot: Arc<RwLock<HotStats>>,
    local_asns: Arc<RwLock<Vec<u32>>>,
) -> anyhow::Result<()> {
    // Open-time settings snapshot — dataset dirs/segment sizing are
    // fixed for the process lifetime. Retention knobs are re-read from
    // the shared cell on every sweep so UI changes apply live.
    let cfg0 = cfg.read().unwrap().clone();
    let opts = DatasetOpts {
        segment_rows: cfg0.segment_rows,
        segment_interval: Duration::from_secs(cfg0.segment_interval_secs),
    };
    let mut flows =
        Dataset::<FlowRecord>::open(cfg0.dataset_dir("flows", &cfg0.flows_dir), opts.clone())?;
    let mut rollups = Dataset::<RollupRecord>::open(
        cfg0.dataset_dir("rollups", &cfg0.rollups_dir),
        opts.clone(),
    )?;
    // Coarse dataset: hourly buckets with /24·/48-masked IPs — the
    // long-retention, low-cardinality stats layer.
    let mut hourly =
        Dataset::<RollupRecord>::open(cfg0.dataset_dir("hourly", &cfg0.hourly_dir), opts.clone())?;
    // Geo dataset: minute-bucketed lat/lon bubbles — backs /api/v1/geo
    // without scanning raw flows.
    let mut geos =
        Dataset::<GeoRecord>::open(cfg0.dataset_dir("geo", &cfg0.geo_dir), opts)?;
    let mut agg = RollupAggregator::new().with_sampling(cfg0.sample_weighting);
    let mut coarse_agg = RollupAggregator::coarse().with_sampling(cfg0.sample_weighting);
    let mut geo_agg = GeoAggregator::new().with_sampling(cfg0.sample_weighting);
    let coarse_on = cfg0.coarse_rollup;

    // Publish initial indexes (picks up segments from previous runs).
    publish(&shared, &flows, &rollups, &hourly, &geos, &agg, &coarse_agg, &geo_agg, now_ms());

    let started = now_ms();
    let mut pending: Vec<FlowRecord> = Vec::with_capacity(BATCH);
    let mut tick = interval(Duration::from_secs(1));
    let mut last_retention = now_ms();
    let retention_iv = Duration::from_secs(cfg0.retention_interval_secs.max(30));
    // Rollup buckets only become drainable at minute/hour boundaries — skip
    // the full-map scan on ticks that stay inside the same period.
    let mut last_drain_min = u64::MAX;
    let mut last_drain_hour = u64::MAX;

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(rec) => {
                        // Live tail for /flows/stream — Copy send is cheap;
                        // skipped entirely when nobody is listening.
                        if shared.live_tx.receiver_count() > 0 {
                            let _ = shared.live_tx.send(rec);
                        }
                        pending.push(rec);
                        if pending.len() >= BATCH {
                            ingest_batch(&mut pending, &mut flows, &mut agg, &mut coarse_agg, &mut geo_agg, coarse_on, &metrics);
                        }
                    }
                    None => {
                        // All senders gone: flush everything and exit.
                        ingest_batch(&mut pending, &mut flows, &mut agg, &mut coarse_agg, &mut geo_agg, coarse_on, &metrics);
                        // drain_all: keep the still-open buckets too — their
                        // raw flows exist, so rollups shouldn't lose them.
                        let recs = agg.drain_all();
                        feed_hot(&hot, &local_asns, &recs);
                        push_all(&mut rollups, recs.into_iter(), &metrics, "rollups");
                        push_all(&mut hourly, coarse_agg.drain_all().into_iter(), &metrics, "hourly");
                        push_all(&mut geos, geo_agg.drain_all().into_iter(), &metrics, "geo");
                        flows.flush()?;
                        rollups.flush()?;
                        hourly.flush()?;
                        geos.flush()?;
                        publish(&shared, &flows, &rollups, &hourly, &geos, &agg, &coarse_agg, &geo_agg, started);
                        return Ok(());
                    }
                }
            }
            _ = tick.tick() => {
                ingest_batch(&mut pending, &mut flows, &mut agg, &mut coarse_agg, &mut geo_agg, coarse_on, &metrics);
                // Cardinality circuit-breaker: drain a subset of live
                // tuples early when a map exceeds its cap. Records land
                // in the still-open bucket; readers sum duplicate
                // (bucket, tuple) rows so totals stay correct.
                if agg.len() > AGG_MAP_CAP {
                    tracing::warn!(
                        "rollup map over cap ({} > {}), emergency drain",
                        agg.len(), AGG_MAP_CAP
                    );
                    let recs = agg.drain_over(AGG_MAP_CAP);
                    feed_hot(&hot, &local_asns, &recs);
                    push_all(&mut rollups, recs.into_iter(), &metrics, "rollups");
                }
                if coarse_agg.len() > COARSE_AGG_MAP_CAP {
                    tracing::warn!(
                        "coarse rollup map over cap ({} > {}), emergency drain",
                        coarse_agg.len(), COARSE_AGG_MAP_CAP
                    );
                    push_all(&mut hourly, coarse_agg.drain_over(COARSE_AGG_MAP_CAP).into_iter(), &metrics, "hourly");
                }
                if geo_agg.len() > AGG_MAP_CAP {
                    tracing::warn!(
                        "geo map over cap ({} > {}), emergency drain",
                        geo_agg.len(), AGG_MAP_CAP
                    );
                    push_all(&mut geos, geo_agg.drain_over(AGG_MAP_CAP).into_iter(), &metrics, "geo");
                }
                let now = now_ms();
                let cur_min = bgflow_store::timeutil::minute_floor(now);
                if cur_min != last_drain_min {
                    last_drain_min = cur_min;
                    let recs = agg.drain_finished(now);
                    feed_hot(&hot, &local_asns, &recs);
                    push_all(&mut rollups, recs.into_iter(), &metrics, "rollups");
                    push_all(&mut geos, geo_agg.drain_finished(now).into_iter(), &metrics, "geo");
                }
                let cur_hour = bgflow_store::timeutil::hour_floor(now);
                if cur_hour != last_drain_hour {
                    last_drain_hour = cur_hour;
                    push_all(&mut hourly, coarse_agg.drain_finished(now).into_iter(), &metrics, "hourly");
                }

                // Periodic explicit flush + retention.
                let fb = flows.segment_count();
                let rb = rollups.segment_count();
                let hb = hourly.segment_count();
                let gb = geos.segment_count();
                let fbytes = flows.total_bytes();
                let rbytes = rollups.total_bytes();
                let hbytes = hourly.total_bytes();
                let gbytes = geos.total_bytes();
                // Flush errors are counted + logged but don't kill the
                // writer — the next tick retries. Only a dead dataset
                // (open failure at startup) is fatal.
                if let Err(e) = flows.flush() {
                    write_err(&metrics, "flows flush", &e);
                }
                if let Err(e) = rollups.flush() {
                    write_err(&metrics, "rollups flush", &e);
                }
                if let Err(e) = hourly.flush() {
                    write_err(&metrics, "hourly flush", &e);
                }
                if let Err(e) = geos.flush() {
                    write_err(&metrics, "geo flush", &e);
                }
                let segs = (flows.segment_count() - fb)
                    + (rollups.segment_count() - rb)
                    + (hourly.segment_count() - hb)
                    + (geos.segment_count() - gb);
                if segs > 0 {
                    metrics.flushes.fetch_add(segs as u64, std::sync::atomic::Ordering::Relaxed);
                    let written = (flows.total_bytes() - fbytes)
                        + (rollups.total_bytes() - rbytes)
                        + (hourly.total_bytes() - hbytes)
                        + (geos.total_bytes() - gbytes);
                    metrics.bytes_stored.fetch_add(written, std::sync::atomic::Ordering::Relaxed);
                }
                if now.saturating_sub(last_retention) >= retention_iv.as_millis() as u64 {
                    last_retention = now;
                    let sc = cfg.read().unwrap().clone();
                    if let Err(e) = retention(&mut flows, &mut rollups, &mut hourly, &mut geos, &sc, &metrics) {
                        write_err(&metrics, "retention", &e);
                    }
                }
                if flows.segment_count() != fb
                    || rollups.segment_count() != rb
                    || hourly.segment_count() != hb
                    || geos.segment_count() != gb
                {
                    publish(&shared, &flows, &rollups, &hourly, &geos, &agg, &coarse_agg, &geo_agg, started);
                }
                update_status(&shared, &flows, &rollups, &hourly, &geos, &agg, &coarse_agg, &geo_agg, started);
            }
        }
    }
}

/// Push a batch of flow records. Storage errors are counted and logged
/// but never propagate — a transient IO failure must not kill the writer
/// (which would silently drop every subsequent flow). The rollup
/// aggregators only see records that were actually stored, keeping raw
/// and rollup data consistent.
fn ingest_batch(
    pending: &mut Vec<FlowRecord>,
    flows: &mut Dataset<FlowRecord>,
    agg: &mut RollupAggregator,
    coarse_agg: &mut RollupAggregator,
    geo_agg: &mut GeoAggregator,
    coarse_on: bool,
    metrics: &Metrics,
) {
    if pending.is_empty() {
        return;
    }
    let mut stored = 0u64;
    let mut errs = 0u64;
    let mut first_err: Option<String> = None;
    for rec in pending.drain(..) {
        match flows.push(&rec) {
            Ok(()) => {
                stored += 1;
                agg.add(&rec);
                if coarse_on {
                    coarse_agg.add(&rec);
                }
                geo_agg.add(&rec);
            }
            Err(e) => {
                errs += 1;
                if first_err.is_none() {
                    first_err = Some(format!("{:#}", e));
                }
            }
        }
    }
    metrics.rows_stored.fetch_add(stored, std::sync::atomic::Ordering::Relaxed);
    if errs > 0 {
        metrics.write_errors.fetch_add(errs, std::sync::atomic::Ordering::Relaxed);
        tracing::error!(
            "writer: {} flow record(s) failed to store ({} stored); first error: {}",
            errs,
            stored,
            first_err.unwrap_or_default()
        );
    }
}

/// Push rollup records, tolerating per-record errors (see ingest_batch).
fn push_all<R: bgflow_store::Record>(
    ds: &mut Dataset<R>,
    recs: impl Iterator<Item = R>,
    metrics: &Metrics,
    what: &str,
) {
    let mut errs = 0u64;
    for rec in recs {
        if ds.push(&rec).is_err() {
            errs += 1;
        }
    }
    if errs > 0 {
        metrics.write_errors.fetch_add(errs, std::sync::atomic::Ordering::Relaxed);
        tracing::error!("writer: {} {} record(s) failed to store", errs, what);
    }
}

/// Count + log a storage error without killing the writer.
fn write_err(metrics: &Metrics, what: &str, e: &anyhow::Error) {
    metrics.write_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tracing::error!("writer: {} failed: {:#}", what, e);
}

fn retention(
    flows: &mut Dataset<FlowRecord>,
    rollups: &mut Dataset<RollupRecord>,
    hourly: &mut Dataset<RollupRecord>,
    geos: &mut Dataset<GeoRecord>,
    cfg: &StorageConfig,
    metrics: &Metrics,
) -> anyhow::Result<()> {
    let now = now_ms();
    if cfg.raw_retention_days > 0 {
        let cutoff = now.saturating_sub(cfg.raw_retention_days as u64 * 86_400_000);
        let freed = flows.retain(cutoff)?;
        metrics.bytes_freed.fetch_add(freed, std::sync::atomic::Ordering::Relaxed);
        if freed > 0 {
            tracing::info!("retention: freed {} bytes of raw flows", freed);
        }
    }
    if cfg.rollup_retention_days > 0 {
        let cutoff = now.saturating_sub(cfg.rollup_retention_days as u64 * 86_400_000);
        let freed = rollups.retain(cutoff)?;
        metrics.bytes_freed.fetch_add(freed, std::sync::atomic::Ordering::Relaxed);
        if freed > 0 {
            tracing::info!("retention: freed {} bytes of rollups", freed);
        }
    }
    if cfg.coarse_retention_days > 0 {
        let cutoff = now.saturating_sub(cfg.coarse_retention_days as u64 * 86_400_000);
        let freed = hourly.retain(cutoff)?;
        metrics.bytes_freed.fetch_add(freed, std::sync::atomic::Ordering::Relaxed);
        if freed > 0 {
            tracing::info!("retention: freed {} bytes of hourly rollups", freed);
        }
    }
    // Geo bubbles mirror raw-flow coverage — same retention window.
    if cfg.raw_retention_days > 0 {
        let cutoff = now.saturating_sub(cfg.raw_retention_days as u64 * 86_400_000);
        let freed = geos.retain(cutoff)?;
        metrics.bytes_freed.fetch_add(freed, std::sync::atomic::Ordering::Relaxed);
        if freed > 0 {
            tracing::info!("retention: freed {} bytes of geo rollups", freed);
        }
    }
    if cfg.max_bytes > 0 {
        let freed = disk_cap(flows, rollups, hourly, geos, cfg.max_bytes)?;
        metrics.bytes_freed.fetch_add(freed, std::sync::atomic::Ordering::Relaxed);
        if freed > 0 {
            tracing::info!("disk cap: evicted oldest segments, freed {} bytes", freed);
        }
    }
    Ok(())
}

/// Enforce `max_bytes` across all datasets: evict globally oldest
/// segments (by data end time) until usage drops under 90% of the cap,
/// leaving headroom so we don't evict on every sweep. Time-based
/// retention runs first, so this only kicks in when the cap is tighter
/// than the retention windows.
fn disk_cap(
    flows: &mut Dataset<FlowRecord>,
    rollups: &mut Dataset<RollupRecord>,
    hourly: &mut Dataset<RollupRecord>,
    geos: &mut Dataset<GeoRecord>,
    cap: u64,
) -> anyhow::Result<u64> {
    let total = flows.total_bytes() + rollups.total_bytes() + hourly.total_bytes() + geos.total_bytes();
    if total <= cap {
        return Ok(0);
    }
    let need = total.saturating_sub(cap.saturating_mul(9) / 10);

    // Rank every indexed segment oldest-first, take victims until the
    // planned free space covers `need`.
    let mut all: Vec<(u64, u8, usize, u64)> = Vec::new();
    for (tag, snap) in [
        (0u8, flows.segment_snapshot()),
        (1u8, rollups.segment_snapshot()),
        (2u8, hourly.segment_snapshot()),
        (3u8, geos.segment_snapshot()),
    ] {
        for (i, s) in snap.iter().enumerate() {
            all.push((s.header.max_ts_ms, tag, i, s.file_size));
        }
    }
    all.sort_by_key(|e| e.0);
    let mut plan: [Vec<usize>; 4] = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let mut planned = 0u64;
    for &(_, tag, i, size) in &all {
        if planned >= need {
            break;
        }
        plan[tag as usize].push(i);
        planned += size;
    }

    // Drop per dataset, indices descending so earlier removals don't
    // shift the positions of later victims.
    let mut freed = 0u64;
    for (tag, idxs) in plan.iter().enumerate() {
        let mut idxs = idxs.clone();
        idxs.sort_unstable_by(|a, b| b.cmp(a));
        let ds_freed = match tag {
            0 => idxs.iter().map(|&i| flows.drop_segment(i)).sum::<u64>(),
            1 => idxs.iter().map(|&i| rollups.drop_segment(i)).sum::<u64>(),
            2 => idxs.iter().map(|&i| hourly.drop_segment(i)).sum::<u64>(),
            _ => idxs.iter().map(|&i| geos.drop_segment(i)).sum::<u64>(),
        };
        freed += ds_freed;
    }
    Ok(freed)
}

fn publish(
    shared: &WriterShared,
    flows: &Dataset<FlowRecord>,
    rollups: &Dataset<RollupRecord>,
    hourly: &Dataset<RollupRecord>,
    geos: &Dataset<GeoRecord>,
    agg: &RollupAggregator,
    coarse_agg: &RollupAggregator,
    geo_agg: &GeoAggregator,
    started: u64,
) {
    *shared.flow_index.write().unwrap() = Arc::new(flows.segment_snapshot());
    *shared.rollup_index.write().unwrap() = Arc::new(rollups.segment_snapshot());
    *shared.hourly_index.write().unwrap() = Arc::new(hourly.segment_snapshot());
    *shared.geo_index.write().unwrap() = Arc::new(geos.segment_snapshot());
    update_status(shared, flows, rollups, hourly, geos, agg, coarse_agg, geo_agg, started);
}

#[allow(clippy::too_many_arguments)]
fn update_status(
    shared: &WriterShared,
    flows: &Dataset<FlowRecord>,
    rollups: &Dataset<RollupRecord>,
    hourly: &Dataset<RollupRecord>,
    geos: &Dataset<GeoRecord>,
    agg: &RollupAggregator,
    coarse_agg: &RollupAggregator,
    geo_agg: &GeoAggregator,
    started: u64,
) {
    let mut s = shared.status.write().unwrap();
    if s.started_ms == 0 {
        s.started_ms = started;
    }
    s.uptime_secs = now_ms().saturating_sub(s.started_ms) / 1000;
    s.writer_alive = true;
    s.last_flush_ms = now_ms();
    s.buffered_rows = flows.buffered_rows() + rollups.buffered_rows() + hourly.buffered_rows() + geos.buffered_rows();
    s.flow_segments = flows.segment_count();
    s.flow_rows = flows.total_rows();
    s.flow_bytes = flows.total_bytes();
    s.flow_buffered = flows.buffered_rows();
    s.rollup_segments = rollups.segment_count();
    s.rollup_rows = rollups.total_rows();
    s.rollup_bytes = rollups.total_bytes();
    s.rollup_buffered = rollups.buffered_rows();
    s.rollup_pending_buckets = agg.len();
    s.hourly_segments = hourly.segment_count();
    s.hourly_rows = hourly.total_rows();
    s.hourly_bytes = hourly.total_bytes();
    s.hourly_buffered = hourly.buffered_rows();
    s.hourly_pending_buckets = coarse_agg.len();
    s.geo_segments = geos.segment_count();
    s.geo_rows = geos.total_rows();
    s.geo_bytes = geos.total_bytes();
    s.geo_buffered = geos.buffered_rows();
    s.geo_pending_buckets = geo_agg.len();
}
