//! Writer task: the single owner of all Datasets. Ingest sends parsed
//! FlowRecords over a channel; this task batches them into the raw dataset,
//! feeds the minute and coarse (hourly, /24·/48-masked) rollup aggregators,
//! drains finished buckets into their datasets, runs retention, and
//! publishes segment-index snapshots that the HTTP query path reads
//! directly from segment files.

use crate::config::StorageConfig;
use crate::metrics::{now_ms, Metrics};
use bgflow_store::{Dataset, DatasetOpts, RollupAggregator, SegmentInfo};
use bgflow_types::{FlowRecord, RollupRecord};
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
}

#[derive(Clone)]
pub struct WriterShared {
    pub flow_index: SegmentIndex,
    pub rollup_index: SegmentIndex,
    pub hourly_index: SegmentIndex,
    pub status: Arc<RwLock<StatusSnapshot>>,
}

impl WriterShared {
    pub fn new() -> Self {
        WriterShared {
            flow_index: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            rollup_index: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            hourly_index: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            status: Arc::new(RwLock::new(StatusSnapshot::default())),
        }
    }
}

const BATCH: usize = 8192;

pub async fn run(
    cfg: Arc<RwLock<StorageConfig>>,
    shared: WriterShared,
    metrics: Arc<Metrics>,
    mut rx: mpsc::Receiver<FlowRecord>,
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
        Dataset::<RollupRecord>::open(cfg0.dataset_dir("hourly", &cfg0.hourly_dir), opts)?;
    let mut agg = RollupAggregator::new().with_sampling(cfg0.sample_weighting);
    let mut coarse_agg = RollupAggregator::coarse().with_sampling(cfg0.sample_weighting);
    let coarse_on = cfg0.coarse_rollup;

    // Publish initial indexes (picks up segments from previous runs).
    publish(&shared, &flows, &rollups, &hourly, &agg, &coarse_agg, now_ms());

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
                        pending.push(rec);
                        if pending.len() >= BATCH {
                            ingest_batch(&mut pending, &mut flows, &mut agg, &mut coarse_agg, coarse_on, &metrics);
                        }
                    }
                    None => {
                        // All senders gone: flush everything and exit.
                        ingest_batch(&mut pending, &mut flows, &mut agg, &mut coarse_agg, coarse_on, &metrics);
                        // drain_all: keep the still-open buckets too — their
                        // raw flows exist, so rollups shouldn't lose them.
                        push_all(&mut rollups, agg.drain_all().into_iter(), &metrics, "rollups");
                        push_all(&mut hourly, coarse_agg.drain_all().into_iter(), &metrics, "hourly");
                        flows.flush()?;
                        rollups.flush()?;
                        hourly.flush()?;
                        publish(&shared, &flows, &rollups, &hourly, &agg, &coarse_agg, started);
                        return Ok(());
                    }
                }
            }
            _ = tick.tick() => {
                ingest_batch(&mut pending, &mut flows, &mut agg, &mut coarse_agg, coarse_on, &metrics);
                let now = now_ms();
                let cur_min = bgflow_store::timeutil::minute_floor(now);
                if cur_min != last_drain_min {
                    last_drain_min = cur_min;
                    push_all(&mut rollups, agg.drain_finished(now).into_iter(), &metrics, "rollups");
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
                let fbytes = flows.total_bytes();
                let rbytes = rollups.total_bytes();
                let hbytes = hourly.total_bytes();
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
                let segs = (flows.segment_count() - fb)
                    + (rollups.segment_count() - rb)
                    + (hourly.segment_count() - hb);
                if segs > 0 {
                    metrics.flushes.fetch_add(segs as u64, std::sync::atomic::Ordering::Relaxed);
                    let written = (flows.total_bytes() - fbytes)
                        + (rollups.total_bytes() - rbytes)
                        + (hourly.total_bytes() - hbytes);
                    metrics.bytes_stored.fetch_add(written, std::sync::atomic::Ordering::Relaxed);
                }
                if now.saturating_sub(last_retention) >= retention_iv.as_millis() as u64 {
                    last_retention = now;
                    let sc = cfg.read().unwrap().clone();
                    if let Err(e) = retention(&mut flows, &mut rollups, &mut hourly, &sc, &metrics) {
                        write_err(&metrics, "retention", &e);
                    }
                }
                if flows.segment_count() != fb
                    || rollups.segment_count() != rb
                    || hourly.segment_count() != hb
                {
                    publish(&shared, &flows, &rollups, &hourly, &agg, &coarse_agg, started);
                }
                update_status(&shared, &flows, &rollups, &hourly, &agg, &coarse_agg, started);
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
    if cfg.max_bytes > 0 {
        let freed = disk_cap(flows, rollups, hourly, cfg.max_bytes)?;
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
    cap: u64,
) -> anyhow::Result<u64> {
    let total = flows.total_bytes() + rollups.total_bytes() + hourly.total_bytes();
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
    ] {
        for (i, s) in snap.iter().enumerate() {
            all.push((s.header.max_ts_ms, tag, i, s.file_size));
        }
    }
    all.sort_by_key(|e| e.0);
    let mut plan: [Vec<usize>; 3] = [Vec::new(), Vec::new(), Vec::new()];
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
            _ => idxs.iter().map(|&i| hourly.drop_segment(i)).sum::<u64>(),
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
    agg: &RollupAggregator,
    coarse_agg: &RollupAggregator,
    started: u64,
) {
    *shared.flow_index.write().unwrap() = Arc::new(flows.segment_snapshot());
    *shared.rollup_index.write().unwrap() = Arc::new(rollups.segment_snapshot());
    *shared.hourly_index.write().unwrap() = Arc::new(hourly.segment_snapshot());
    update_status(shared, flows, rollups, hourly, agg, coarse_agg, started);
}

fn update_status(
    shared: &WriterShared,
    flows: &Dataset<FlowRecord>,
    rollups: &Dataset<RollupRecord>,
    hourly: &Dataset<RollupRecord>,
    agg: &RollupAggregator,
    coarse_agg: &RollupAggregator,
    started: u64,
) {
    let mut s = shared.status.write().unwrap();
    if s.started_ms == 0 {
        s.started_ms = started;
    }
    s.uptime_secs = now_ms().saturating_sub(s.started_ms) / 1000;
    s.writer_alive = true;
    s.last_flush_ms = now_ms();
    s.buffered_rows = flows.buffered_rows() + rollups.buffered_rows() + hourly.buffered_rows();
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
}
