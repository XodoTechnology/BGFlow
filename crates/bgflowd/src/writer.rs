//! Writer task: the single owner of both Datasets. Ingest sends parsed
//! FlowRecords over a channel; this task batches them into the raw dataset,
//! feeds the rollup aggregator, drains finished buckets into the rollup
//! dataset, runs retention, and publishes segment-index snapshots that the
//! HTTP query path reads directly from segment files.

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
    pub flow_segments: usize,
    pub flow_rows: u64,
    pub flow_bytes: u64,
    pub flow_buffered: usize,
    pub rollup_segments: usize,
    pub rollup_rows: u64,
    pub rollup_bytes: u64,
    pub rollup_buffered: usize,
    pub rollup_pending_buckets: usize,
}

#[derive(Clone)]
pub struct WriterShared {
    pub flow_index: SegmentIndex,
    pub rollup_index: SegmentIndex,
    pub status: Arc<RwLock<StatusSnapshot>>,
}

impl WriterShared {
    pub fn new() -> Self {
        WriterShared {
            flow_index: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            rollup_index: Arc::new(RwLock::new(Arc::new(Vec::new()))),
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
    let mut rollups = Dataset::<RollupRecord>::open(cfg.data_dir.join("rollups"), opts)?;
    let mut agg = RollupAggregator::new();

    // Publish initial indexes (picks up segments from previous runs).
    publish(&shared, &flows, &rollups, &agg, now_ms());

    let started = now_ms();
    let mut pending: Vec<FlowRecord> = Vec::with_capacity(BATCH);
    let mut tick = interval(Duration::from_secs(1));
    let mut last_retention = now_ms();
    let retention_iv = Duration::from_secs(cfg.retention_interval_secs.max(30));

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(rec) => {
                        pending.push(rec);
                        if pending.len() >= BATCH {
                            ingest_batch(&mut pending, &mut flows, &mut agg, &metrics)?;
                        }
                    }
                    None => {
                        // All senders gone: flush everything and exit.
                        ingest_batch(&mut pending, &mut flows, &mut agg, &metrics)?;
                        drain_rollup(&mut agg, &mut rollups)?;
                        flows.flush()?;
                        rollups.flush()?;
                        publish(&shared, &flows, &rollups, &agg, started);
                        return Ok(());
                    }
                }
            }
            _ = tick.tick() => {
                ingest_batch(&mut pending, &mut flows, &mut agg, &metrics)?;
                drain_rollup(&mut agg, &mut rollups)?;

                // Periodic explicit flush + retention.
                let fb = flows.segment_count();
                let rb = rollups.segment_count();
                flows.flush()?;
                rollups.flush()?;
                if now_ms().saturating_sub(last_retention) >= retention_iv.as_millis() as u64 {
                    last_retention = now_ms();
                    retention(&mut flows, &mut rollups, &cfg, &metrics)?;
                }
                if flows.segment_count() != fb || rollups.segment_count() != rb {
                    publish(&shared, &flows, &rollups, &agg, started);
                }
                update_status(&shared, &flows, &rollups, &agg, started);
            }
        }
    }
}

fn ingest_batch(
    pending: &mut Vec<FlowRecord>,
    flows: &mut Dataset<FlowRecord>,
    agg: &mut RollupAggregator,
    metrics: &Metrics,
) -> anyhow::Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let n = pending.len() as u64;
    for rec in pending.drain(..) {
        agg.add(&rec);
        flows.push(&rec)?;
    }
    metrics
        .rows_stored
        .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

fn drain_rollup(
    agg: &mut RollupAggregator,
    rollups: &mut Dataset<RollupRecord>,
) -> anyhow::Result<()> {
    for rec in agg.drain_finished(now_ms()) {
        rollups.push(&rec)?;
    }
    Ok(())
}

fn retention(
    flows: &mut Dataset<FlowRecord>,
    rollups: &mut Dataset<RollupRecord>,
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
    Ok(())
}

fn publish(
    shared: &WriterShared,
    flows: &Dataset<FlowRecord>,
    rollups: &Dataset<RollupRecord>,
    agg: &RollupAggregator,
    started: u64,
) {
    *shared.flow_index.write().unwrap() = Arc::new(flows.segment_snapshot());
    *shared.rollup_index.write().unwrap() = Arc::new(rollups.segment_snapshot());
    update_status(shared, flows, rollups, agg, started);
}

fn update_status(
    shared: &WriterShared,
    flows: &Dataset<FlowRecord>,
    rollups: &Dataset<RollupRecord>,
    agg: &RollupAggregator,
    started: u64,
) {
    let mut s = shared.status.write().unwrap();
    if s.started_ms == 0 {
        s.started_ms = started;
    }
    s.uptime_secs = now_ms().saturating_sub(s.started_ms) / 1000;
    s.flow_segments = flows.segment_count();
    s.flow_rows = flows.total_rows();
    s.flow_bytes = flows.total_bytes();
    s.flow_buffered = flows.buffered_rows();
    s.rollup_segments = rollups.segment_count();
    s.rollup_rows = rollups.total_rows();
    s.rollup_bytes = rollups.total_bytes();
    s.rollup_buffered = rollups.buffered_rows();
    s.rollup_pending_buckets = agg.len();
}
