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
    cfg: StorageConfig,
    shared: WriterShared,
    metrics: Arc<Metrics>,
    mut rx: mpsc::Receiver<FlowRecord>,
) -> anyhow::Result<()> {
    let opts = DatasetOpts {
        segment_rows: cfg.segment_rows,
        segment_interval: Duration::from_secs(cfg.segment_interval_secs),
    };
    let mut flows = Dataset::<FlowRecord>::open(cfg.data_dir.join("flows"), opts.clone())?;
    let mut rollups = Dataset::<RollupRecord>::open(cfg.data_dir.join("rollups"), opts.clone())?;
    // Coarse dataset: hourly buckets with /24·/48-masked IPs — the
    // long-retention, low-cardinality stats layer.
    let mut hourly = Dataset::<RollupRecord>::open(cfg.data_dir.join("hourly"), opts)?;
    let mut agg = RollupAggregator::new();
    let mut coarse_agg = RollupAggregator::coarse();
    let coarse_on = cfg.coarse_rollup;

    // Publish initial indexes (picks up segments from previous runs).
    publish(&shared, &flows, &rollups, &hourly, &agg, &coarse_agg, now_ms());

    let started = now_ms();
    let mut pending: Vec<FlowRecord> = Vec::with_capacity(BATCH);
    let mut tick = interval(Duration::from_secs(1));
    let mut last_retention = now_ms();
    let retention_iv = Duration::from_secs(cfg.retention_interval_secs.max(30));
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
                            ingest_batch(&mut pending, &mut flows, &mut agg, &mut coarse_agg, coarse_on, &metrics)?;
                        }
                    }
                    None => {
                        // All senders gone: flush everything and exit.
                        ingest_batch(&mut pending, &mut flows, &mut agg, &mut coarse_agg, coarse_on, &metrics)?;
                        // drain_all: keep the still-open buckets too — their
                        // raw flows exist, so rollups shouldn't lose them.
                        for rec in agg.drain_all() {
                            rollups.push(&rec)?;
                        }
                        for rec in coarse_agg.drain_all() {
                            hourly.push(&rec)?;
                        }
                        flows.flush()?;
                        rollups.flush()?;
                        hourly.flush()?;
                        publish(&shared, &flows, &rollups, &hourly, &agg, &coarse_agg, started);
                        return Ok(());
                    }
                }
            }
            _ = tick.tick() => {
                ingest_batch(&mut pending, &mut flows, &mut agg, &mut coarse_agg, coarse_on, &metrics)?;
                let now = now_ms();
                let cur_min = bgflow_store::timeutil::minute_floor(now);
                if cur_min != last_drain_min {
                    last_drain_min = cur_min;
                    for rec in agg.drain_finished(now) {
                        rollups.push(&rec)?;
                    }
                }
                let cur_hour = bgflow_store::timeutil::hour_floor(now);
                if cur_hour != last_drain_hour {
                    last_drain_hour = cur_hour;
                    for rec in coarse_agg.drain_finished(now) {
                        hourly.push(&rec)?;
                    }
                }

                // Periodic explicit flush + retention.
                let fb = flows.segment_count();
                let rb = rollups.segment_count();
                let hb = hourly.segment_count();
                let fbytes = flows.total_bytes();
                let rbytes = rollups.total_bytes();
                let hbytes = hourly.total_bytes();
                flows.flush()?;
                rollups.flush()?;
                hourly.flush()?;
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
                    retention(&mut flows, &mut rollups, &mut hourly, &cfg, &metrics)?;
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

fn ingest_batch(
    pending: &mut Vec<FlowRecord>,
    flows: &mut Dataset<FlowRecord>,
    agg: &mut RollupAggregator,
    coarse_agg: &mut RollupAggregator,
    coarse_on: bool,
    metrics: &Metrics,
) -> anyhow::Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let n = pending.len() as u64;
    for rec in pending.drain(..) {
        agg.add(&rec);
        if coarse_on {
            coarse_agg.add(&rec);
        }
        flows.push(&rec)?;
    }
    metrics
        .rows_stored
        .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    Ok(())
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
    Ok(())
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
