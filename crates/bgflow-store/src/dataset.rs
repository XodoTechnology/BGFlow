//! Dataset: a time-partitioned collection of segments with an in-memory
//! columnar write buffer.
//!
//! Two datasets exist in practice: raw flows and rollups. `Dataset<R>` is
//! generic over the record type; the schema comes from `R::schema()`.

use crate::encode::{encode_column, ColumnData};
use crate::schema::Schema;
use crate::segment::{self, SegmentInfo};
use crate::timeutil;
use anyhow::Result;
use bgflow_types::{FlowRecord, RollupRecord};
use std::marker::PhantomData;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Record trait
// ---------------------------------------------------------------------------

/// A record type that can be stored in a Dataset.
pub trait Record: Sized {
    fn schema() -> &'static Schema;
    /// Timestamp used for partitioning / range filtering.
    fn ts_ms(&self) -> u64;
    /// Append this record's fields as little-endian bytes, one `Vec<u8>`
    /// per schema column, in schema column order.
    fn append_le(&self, cols: &mut [Vec<u8>]);
    /// Reconstruct a record from a decoded ScanResult at row `i`.
    fn from_scan(scan: &ScanResult, i: usize) -> Self;
}

/// Decoded columns for one segment, aligned with `schema.columns` order.
pub struct ScanResult {
    pub schema: &'static Schema,
    pub columns: Vec<ColumnData>,
    pub rows: usize,
    /// Source segment file name — stable identity for keyset cursors.
    pub seg: String,
}

impl ScanResult {
    pub fn col(&self, idx: usize) -> &ColumnData {
        &self.columns[idx]
    }
}

// ---------------------------------------------------------------------------
// Record impls
// ---------------------------------------------------------------------------

impl Record for FlowRecord {
    fn schema() -> &'static Schema {
        &crate::schema::RAW_SCHEMA
    }

    fn ts_ms(&self) -> u64 {
        self.ts_ms
    }

    fn append_le(&self, cols: &mut [Vec<u8>]) {
        use crate::schema::raw_idx as ix;
        cols[ix::TS_MS].extend_from_slice(&self.ts_ms.to_le_bytes());
        cols[ix::DURATION_MS].extend_from_slice(&self.duration_ms.to_le_bytes());
        cols[ix::SRC_IP].extend_from_slice(&self.src_ip.to_le_bytes());
        cols[ix::DST_IP].extend_from_slice(&self.dst_ip.to_le_bytes());
        cols[ix::SRC_PORT].extend_from_slice(&self.src_port.to_le_bytes());
        cols[ix::DST_PORT].extend_from_slice(&self.dst_port.to_le_bytes());
        cols[ix::PROTOCOL].push(self.protocol);
        cols[ix::TCP_FLAGS].push(self.tcp_flags);
        cols[ix::INGRESS_IF].extend_from_slice(&self.ingress_if.to_le_bytes());
        cols[ix::EGRESS_IF].extend_from_slice(&self.egress_if.to_le_bytes());
        cols[ix::NEXT_HOP].extend_from_slice(&self.next_hop.to_le_bytes());
        cols[ix::SRC_ASN].extend_from_slice(&self.src_asn.to_le_bytes());
        cols[ix::DST_ASN].extend_from_slice(&self.dst_asn.to_le_bytes());
        cols[ix::SRC_COUNTRY].extend_from_slice(&self.src_country.to_le_bytes());
        cols[ix::DST_COUNTRY].extend_from_slice(&self.dst_country.to_le_bytes());
        cols[ix::SRC_ORG].extend_from_slice(&self.src_org.to_le_bytes());
        cols[ix::DST_ORG].extend_from_slice(&self.dst_org.to_le_bytes());
        cols[ix::VLAN].extend_from_slice(&self.vlan.to_le_bytes());
        cols[ix::BYTES].extend_from_slice(&self.bytes.to_le_bytes());
        cols[ix::PACKETS].extend_from_slice(&self.packets.to_le_bytes());
        cols[ix::EXPORTER].extend_from_slice(&self.exporter.to_le_bytes());
        cols[ix::ENGINE_ID].push(self.engine_id);
        cols[ix::ENGINE_TYPE].push(self.engine_type);
        cols[ix::SAMPLER_INTERVAL].extend_from_slice(&self.sampler_interval.to_le_bytes());
        cols[ix::TCP_STATE].push(self.tcp_state);
        cols[ix::LABEL_ID].extend_from_slice(&self.label_id.to_le_bytes());
        cols[ix::IP_TTL].push(self.ip_ttl);
        cols[ix::FLOW_END_REASON].push(self.flow_end_reason);
        cols[ix::ICMP_TYPE].push(self.icmp_type);
        cols[ix::ICMP_CODE].push(self.icmp_code);
        cols[ix::POST_NAT_SRC].extend_from_slice(&self.post_nat_src.to_le_bytes());
        cols[ix::POST_NAT_DST].extend_from_slice(&self.post_nat_dst.to_le_bytes());
        cols[ix::SRC_CITY].extend_from_slice(&self.src_city.to_le_bytes());
        cols[ix::DST_CITY].extend_from_slice(&self.dst_city.to_le_bytes());
        cols[ix::SRC_REGION].extend_from_slice(&self.src_region.to_le_bytes());
        cols[ix::DST_REGION].extend_from_slice(&self.dst_region.to_le_bytes());
        cols[ix::SRC_LAT].extend_from_slice(&self.src_lat.to_le_bytes());
        cols[ix::DST_LAT].extend_from_slice(&self.dst_lat.to_le_bytes());
        cols[ix::SRC_LON].extend_from_slice(&self.src_lon.to_le_bytes());
        cols[ix::DST_LON].extend_from_slice(&self.dst_lon.to_le_bytes());
    }

    fn from_scan(scan: &ScanResult, i: usize) -> Self {
        use crate::schema::raw_idx as ix;
        let c = &scan.columns;
        FlowRecord {
            ts_ms: c[ix::TS_MS].value_at(i) as u64,
            duration_ms: c[ix::DURATION_MS].value_at(i) as u32,
            src_ip: c[ix::SRC_IP].value_at(i),
            dst_ip: c[ix::DST_IP].value_at(i),
            src_port: c[ix::SRC_PORT].value_at(i) as u16,
            dst_port: c[ix::DST_PORT].value_at(i) as u16,
            protocol: c[ix::PROTOCOL].value_at(i) as u8,
            tcp_flags: c[ix::TCP_FLAGS].value_at(i) as u8,
            ingress_if: c[ix::INGRESS_IF].value_at(i) as u32,
            egress_if: c[ix::EGRESS_IF].value_at(i) as u32,
            next_hop: c[ix::NEXT_HOP].value_at(i),
            src_asn: c[ix::SRC_ASN].value_at(i) as u32,
            dst_asn: c[ix::DST_ASN].value_at(i) as u32,
            src_country: c[ix::SRC_COUNTRY].value_at(i) as u16,
            dst_country: c[ix::DST_COUNTRY].value_at(i) as u16,
            src_org: c[ix::SRC_ORG].value_at(i) as u32,
            dst_org: c[ix::DST_ORG].value_at(i) as u32,
            vlan: c[ix::VLAN].value_at(i) as u16,
            bytes: c[ix::BYTES].value_at(i) as u64,
            packets: c[ix::PACKETS].value_at(i) as u64,
            exporter: c[ix::EXPORTER].value_at(i),
            engine_id: c[ix::ENGINE_ID].value_at(i) as u8,
            engine_type: c[ix::ENGINE_TYPE].value_at(i) as u8,
            sampler_interval: c[ix::SAMPLER_INTERVAL].value_at(i) as u32,
            tcp_state: c[ix::TCP_STATE].value_at(i) as u8,
            label_id: c[ix::LABEL_ID].value_at(i) as u32,
            ip_ttl: c[ix::IP_TTL].value_at(i) as u8,
            flow_end_reason: c[ix::FLOW_END_REASON].value_at(i) as u8,
            icmp_type: c[ix::ICMP_TYPE].value_at(i) as u8,
            icmp_code: c[ix::ICMP_CODE].value_at(i) as u8,
            post_nat_src: c[ix::POST_NAT_SRC].value_at(i),
            post_nat_dst: c[ix::POST_NAT_DST].value_at(i),
            // Geo columns exist only in schema id ≥4 — older segments
            // decode them as 0.
            src_city: c.get(ix::SRC_CITY).map(|col| col.value_at(i) as u32).unwrap_or(0),
            dst_city: c.get(ix::DST_CITY).map(|col| col.value_at(i) as u32).unwrap_or(0),
            src_region: c.get(ix::SRC_REGION).map(|col| col.value_at(i) as u32).unwrap_or(0),
            dst_region: c.get(ix::DST_REGION).map(|col| col.value_at(i) as u32).unwrap_or(0),
            src_lat: c.get(ix::SRC_LAT).map(|col| col.value_at(i) as u32).unwrap_or(0),
            dst_lat: c.get(ix::DST_LAT).map(|col| col.value_at(i) as u32).unwrap_or(0),
            src_lon: c.get(ix::SRC_LON).map(|col| col.value_at(i) as u32).unwrap_or(0),
            dst_lon: c.get(ix::DST_LON).map(|col| col.value_at(i) as u32).unwrap_or(0),
        }
    }
}

impl Record for RollupRecord {
    fn schema() -> &'static Schema {
        &crate::schema::ROLLUP_SCHEMA
    }

    fn ts_ms(&self) -> u64 {
        self.bucket_ms
    }

    fn append_le(&self, cols: &mut [Vec<u8>]) {
        use crate::schema::rollup_idx as ix;
        cols[ix::BUCKET_MS].extend_from_slice(&self.bucket_ms.to_le_bytes());
        cols[ix::EXPORTER].extend_from_slice(&self.exporter.to_le_bytes());
        cols[ix::PROTOCOL].push(self.protocol);
        cols[ix::SRC_ASN].extend_from_slice(&self.src_asn.to_le_bytes());
        cols[ix::DST_ASN].extend_from_slice(&self.dst_asn.to_le_bytes());
        cols[ix::SRC_IP].extend_from_slice(&self.src_ip.to_le_bytes());
        cols[ix::DST_IP].extend_from_slice(&self.dst_ip.to_le_bytes());
        cols[ix::SRC_PORT].extend_from_slice(&self.src_port.to_le_bytes());
        cols[ix::DST_PORT].extend_from_slice(&self.dst_port.to_le_bytes());
        cols[ix::SRC_COUNTRY].extend_from_slice(&self.src_country.to_le_bytes());
        cols[ix::DST_COUNTRY].extend_from_slice(&self.dst_country.to_le_bytes());
        cols[ix::BYTES].extend_from_slice(&self.bytes.to_le_bytes());
        cols[ix::PACKETS].extend_from_slice(&self.packets.to_le_bytes());
        cols[ix::FLOWS].extend_from_slice(&self.flows.to_le_bytes());
        cols[ix::MIN_TS].extend_from_slice(&self.min_ts_ms.to_le_bytes());
        cols[ix::MAX_TS].extend_from_slice(&self.max_ts_ms.to_le_bytes());
        cols[ix::SRC_ORG].extend_from_slice(&self.src_org.to_le_bytes());
        cols[ix::DST_ORG].extend_from_slice(&self.dst_org.to_le_bytes());
        cols[ix::LABEL_ID].extend_from_slice(&self.label_id.to_le_bytes());
        cols[ix::VLAN].extend_from_slice(&self.vlan.to_le_bytes());
        cols[ix::INGRESS_IF].extend_from_slice(&self.ingress_if.to_le_bytes());
        cols[ix::EGRESS_IF].extend_from_slice(&self.egress_if.to_le_bytes());
    }

    fn from_scan(scan: &ScanResult, i: usize) -> Self {
        use crate::schema::rollup_idx as ix;
        let c = &scan.columns;
        RollupRecord {
            bucket_ms: c[ix::BUCKET_MS].value_at(i) as u64,
            exporter: c[ix::EXPORTER].value_at(i),
            protocol: c[ix::PROTOCOL].value_at(i) as u8,
            src_asn: c[ix::SRC_ASN].value_at(i) as u32,
            dst_asn: c[ix::DST_ASN].value_at(i) as u32,
            src_ip: c[ix::SRC_IP].value_at(i),
            dst_ip: c[ix::DST_IP].value_at(i),
            src_port: c[ix::SRC_PORT].value_at(i) as u16,
            dst_port: c[ix::DST_PORT].value_at(i) as u16,
            src_country: c[ix::SRC_COUNTRY].value_at(i) as u16,
            dst_country: c[ix::DST_COUNTRY].value_at(i) as u16,
            bytes: c[ix::BYTES].value_at(i) as u64,
            packets: c[ix::PACKETS].value_at(i) as u64,
            flows: c[ix::FLOWS].value_at(i) as u64,
            min_ts_ms: c[ix::MIN_TS].value_at(i) as u64,
            max_ts_ms: c[ix::MAX_TS].value_at(i) as u64,
            src_org: c[ix::SRC_ORG].value_at(i) as u32,
            dst_org: c[ix::DST_ORG].value_at(i) as u32,
            label_id: c[ix::LABEL_ID].value_at(i) as u32,
            // vlan/ifindexes exist only in schema id ≥5/≥6 — older
            // segments decode them as 0.
            vlan: c.get(ix::VLAN).map(|col| col.value_at(i) as u16).unwrap_or(0),
            ingress_if: c.get(ix::INGRESS_IF).map(|col| col.value_at(i) as u32).unwrap_or(0),
            egress_if: c.get(ix::EGRESS_IF).map(|col| col.value_at(i) as u32).unwrap_or(0),
        }
    }
}

impl Record for bgflow_types::GeoRecord {
    fn schema() -> &'static Schema {
        &crate::schema::GEO_SCHEMA
    }

    fn ts_ms(&self) -> u64 {
        self.bucket_ms
    }

    fn append_le(&self, cols: &mut [Vec<u8>]) {
        use crate::schema::geo_idx as ix;
        cols[ix::BUCKET_MS].extend_from_slice(&self.bucket_ms.to_le_bytes());
        cols[ix::LAT_CELL].push(self.lat_cell);
        cols[ix::LON_CELL].extend_from_slice(&self.lon_cell.to_le_bytes());
        cols[ix::CITY].extend_from_slice(&self.city.to_le_bytes());
        cols[ix::SRC_CC].extend_from_slice(&self.src_cc.to_le_bytes());
        cols[ix::DST_CC].extend_from_slice(&self.dst_cc.to_le_bytes());
        cols[ix::BYTES].extend_from_slice(&self.bytes.to_le_bytes());
        cols[ix::PACKETS].extend_from_slice(&self.packets.to_le_bytes());
        cols[ix::FLOWS].extend_from_slice(&self.flows.to_le_bytes());
        cols[ix::LAT_SUM].extend_from_slice(&self.lat_sum.to_le_bytes());
        cols[ix::LON_SUM].extend_from_slice(&self.lon_sum.to_le_bytes());
        cols[ix::DST_W].extend_from_slice(&self.dst_w.to_le_bytes());
        cols[ix::SRC_W].extend_from_slice(&self.src_w.to_le_bytes());
    }

    fn from_scan(scan: &ScanResult, i: usize) -> Self {
        use crate::schema::geo_idx as ix;
        let c = &scan.columns;
        bgflow_types::GeoRecord {
            bucket_ms: c[ix::BUCKET_MS].value_at(i) as u64,
            lat_cell: c[ix::LAT_CELL].value_at(i) as u8,
            lon_cell: c[ix::LON_CELL].value_at(i) as u16,
            city: c[ix::CITY].value_at(i) as u32,
            src_cc: c[ix::SRC_CC].value_at(i) as u16,
            dst_cc: c[ix::DST_CC].value_at(i) as u16,
            bytes: c[ix::BYTES].value_at(i) as u64,
            packets: c[ix::PACKETS].value_at(i) as u64,
            flows: c[ix::FLOWS].value_at(i) as u64,
            lat_sum: c[ix::LAT_SUM].value_at(i) as u64,
            lon_sum: c[ix::LON_SUM].value_at(i) as u64,
            dst_w: c[ix::DST_W].value_at(i) as u64,
            src_w: c[ix::SRC_W].value_at(i) as u64,
        }
    }
}

// ---------------------------------------------------------------------------
// Columnar write buffer
// ---------------------------------------------------------------------------

struct ColumnBuf {
    cols: Vec<Vec<u8>>,
    rows: usize,
}

impl ColumnBuf {
    fn new(ncols: usize) -> Self {
        ColumnBuf {
            cols: vec![Vec::new(); ncols],
            rows: 0,
        }
    }

    fn clear(&mut self) {
        for c in &mut self.cols {
            c.clear();
        }
        self.rows = 0;
    }

    /// Drop the oldest `k` rows (used to bound the buffer when segment
    /// writes keep failing — better a bounded loss than unbounded RAM).
    fn drop_front(&mut self, schema: &Schema, k: usize) {
        if k == 0 {
            return;
        }
        if k >= self.rows {
            self.clear();
            return;
        }
        for (ci, col) in self.cols.iter_mut().enumerate() {
            let w = schema.columns[ci].ty.width();
            col.drain(..k * w);
        }
        self.rows -= k;
    }

    /// Sort all columns by the timestamp column (stable, by ts only).
    fn sort_by_ts(&mut self, schema: &Schema) {
        let n = self.rows;
        if n <= 1 {
            return;
        }
        let ts_idx = schema.ts_column();
        let width = schema.columns[ts_idx].ty.width();
        debug_assert_eq!(width, 8);
        let ts_bytes = &self.cols[ts_idx];

        let mut order: Vec<u32> = (0..n as u32).collect();
        order.sort_by_key(|&i| {
            let off = i as usize * 8;
            u64::from_le_bytes(ts_bytes[off..off + 8].try_into().unwrap())
        });

        for (ci, col) in self.cols.iter_mut().enumerate() {
            let w = schema.columns[ci].ty.width();
            let mut new = vec![0u8; col.len()];
            for (new_i, &src_i) in order.iter().enumerate() {
                let s = src_i as usize * w;
                new[new_i * w..new_i * w + w].copy_from_slice(&col[s..s + w]);
            }
            *col = new;
        }
    }
}

// ---------------------------------------------------------------------------
// Dataset
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DatasetOpts {
    /// Flush a segment after this many buffered rows.
    pub segment_rows: usize,
    /// Flush a segment after this much time has elapsed since first row.
    pub segment_interval: Duration,
}

impl Default for DatasetOpts {
    fn default() -> Self {
        DatasetOpts {
            segment_rows: 100_000,
            segment_interval: Duration::from_secs(60),
        }
    }
}

pub struct Dataset<R: Record> {
    root: PathBuf,
    schema: &'static Schema,
    segments: Vec<SegmentInfo>,
    buf: ColumnBuf,
    buf_started: Instant,
    opts: DatasetOpts,
    _m: PhantomData<R>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl<R: Record> Dataset<R> {
    /// Open (or create) a dataset rooted at `root`.
    pub fn open(root: impl AsRef<Path>, opts: DatasetOpts) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        let schema = R::schema();

        // Accept every schema version of this dataset family ("flows",
        // "rollup") — readers resolve each segment's own layout and sparse
        // rows read appended columns as 0. Filtering by name (not id)
        // keeps schema-evolved history visible after upgrades.
        let mut segments = segment::scan_segments(&root)?
            .into_iter()
            .filter(|s| {
                crate::schema::schema_by_id(s.header.schema_id)
                    .map(|sc| sc.name == schema.name)
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        segments.sort_by_key(|s| s.header.min_ts_ms);

        Ok(Dataset {
            root,
            schema,
            segments,
            buf: ColumnBuf::new(schema.columns.len()),
            buf_started: Instant::now(),
            opts,
            _m: PhantomData,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn schema(&self) -> &'static Schema {
        self.schema
    }

    /// Number of segments currently indexed.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Snapshot of the segment index. Cheap to clone; used to hand read-only
    /// query access to segment files without locking the writer.
    pub fn segment_snapshot(&self) -> Vec<SegmentInfo> {
        self.segments.clone()
    }

    /// Buffered (not yet flushed) row count.
    pub fn buffered_rows(&self) -> usize {
        self.buf.rows
    }

    /// Push a record; flushes automatically when thresholds are hit.
    pub fn push(&mut self, rec: &R) -> Result<()> {
        if self.buf.rows == 0 {
            self.buf_started = Instant::now();
        }
        rec.append_le(&mut self.buf.cols);
        self.buf.rows += 1;

        if self.buf.rows >= self.opts.segment_rows
            || self.buf_started.elapsed() >= self.opts.segment_interval
        {
            if let Err(e) = self.flush() {
                // A failing flush leaves rows buffered; without a bound
                // the columnar buffer grows forever and OOMs the daemon.
                // Cap it: past 8x segment_rows, drop the oldest half of
                // the excess — the error is still reported to the caller.
                let cap = self.opts.segment_rows.saturating_mul(8);
                if self.buf.rows > cap {
                    let drop = self.buf.rows - self.opts.segment_rows.saturating_mul(4);
                    self.buf.drop_front(self.schema, drop);
                    tracing::warn!(
                        "dataset: dropped {} buffered rows after repeated flush failures",
                        drop
                    );
                }
                return Err(e);
            }
        }
        Ok(())
    }

    /// Force-flush the buffer into a new segment.
    pub fn flush(&mut self) -> Result<()> {
        if self.buf.rows == 0 {
            return Ok(());
        }
        self.buf.sort_by_ts(self.schema);

        let n = self.buf.rows;
        // Segment time bounds drive query-time pruning (`overlaps`).
        // For rollup records the ts column is `bucket_ms` — all rows in
        // an hourly segment share one bucket, collapsing bounds to a
        // point and making mid-range queries skip the whole segment.
        // Prefer the real flow-time columns when the schema has them.
        let (first_ts, last_ts) = match (
            self.schema.col_index("min_ts_ms"),
            self.schema.col_index("max_ts_ms"),
        ) {
            (Some(mi), Some(ma)) => {
                let lo_col = &self.buf.cols[mi];
                let hi_col = &self.buf.cols[ma];
                let mut lo = u64::MAX;
                let mut hi = 0u64;
                for i in 0..n {
                    lo = lo.min(u64::from_le_bytes(lo_col[i * 8..i * 8 + 8].try_into().unwrap()));
                    hi = hi.max(u64::from_le_bytes(hi_col[i * 8..i * 8 + 8].try_into().unwrap()));
                }
                (lo, hi)
            }
            _ => {
                let ts_idx = self.schema.ts_column();
                let ts_col = &self.buf.cols[ts_idx];
                (
                    u64::from_le_bytes(ts_col[0..8].try_into().unwrap()),
                    u64::from_le_bytes(ts_col[(n - 1) * 8..n * 8].try_into().unwrap()),
                )
            }
        };

        // Encode every column.
        let mut chunks = Vec::with_capacity(self.schema.columns.len());
        for (ci, def) in self.schema.columns.iter().enumerate() {
            chunks.push(encode_column(def, &self.buf.cols[ci], n));
        }

        // Time-partitioned path: root/YYYY/MM/DD/HH/.
        let (y, mo, d, h) = timeutil::ymd_h_from_ms(first_ts);
        let dir = self
            .root
            .join(format!("{:04}/{:02}/{:02}/{:02}", y, mo, d, h));
        std::fs::create_dir_all(&dir)?;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let fname = format!("seg-{}-{}-{:x}.bfs", first_ts, n, nanos);
        let path = dir.join(fname);

        segment::write_segment(
            &path,
            self.schema,
            &chunks,
            n as u64,
            first_ts,
            last_ts,
            now_ms(),
        )?;

        let header = segment::read_header(&path)?;
        let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        self.segments.push(SegmentInfo { path, header, file_size });
        self.buf.clear();
        self.segments.sort_by_key(|s| s.header.min_ts_ms);
        Ok(())
    }

    /// Iterate over segments overlapping [from_ms, to_ms], decoding each.
    /// `newest_first` reverses segment order (useful for LIMIT queries).
    /// The callback returns `ControlFlow::Break` to stop early.
    pub fn for_each_segment(
        &self,
        from_ms: u64,
        to_ms: u64,
        newest_first: bool,
        mut f: impl FnMut(&ScanResult) -> ControlFlow<()>,
    ) -> Result<()> {
        let mut idx: Vec<usize> = self
            .segments
            .iter()
            .enumerate()
            .filter(|(_, s)| s.overlaps(from_ms, to_ms))
            .map(|(i, _)| i)
            .collect();
        if newest_first {
            idx.reverse();
        }

        for i in idx {
            let info = &self.segments[i];
            let reader = segment::SegmentReader::open(&info.path)?;
            let columns = reader.decode_all()?;
            let scan = ScanResult {
                schema: self.schema,
                rows: reader.header.row_count as usize,
                columns,
                seg: info
                    .path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            };
            if f(&scan).is_break() {
                break;
            }
        }
        Ok(())
    }

    /// Collect all records in [from_ms, to_ms]. Prefer `for_each_segment`
    /// for large ranges.
    pub fn scan(&self, from_ms: u64, to_ms: u64) -> Result<Vec<R>> {
        let mut out = Vec::new();
        self.for_each_segment(from_ms, to_ms, false, |scan| {
            for i in 0..scan.rows {
                let rec = R::from_scan(scan, i);
                if rec.ts_ms() >= from_ms && rec.ts_ms() <= to_ms {
                    out.push(rec);
                }
            }
            ControlFlow::Continue(())
        })?;
        Ok(out)
    }

    /// Delete segments whose data ends before `before_ms`.
    /// Returns bytes freed.
    pub fn retain(&mut self, before_ms: u64) -> Result<u64> {
        let mut freed = 0u64;
        let mut kept = Vec::with_capacity(self.segments.len());
        for s in self.segments.drain(..) {
            if s.header.max_ts_ms < before_ms {
                if let Err(e) = std::fs::remove_file(&s.path) {
                    tracing::warn!("retention: cannot remove {:?}: {}", s.path, e);
                } else {
                    freed += s.file_size;
                    // best-effort cleanup of empty partition dirs
                    if let Some(parent) = s.path.parent() {
                        let _ = std::fs::remove_dir(parent);
                    }
                }
            } else {
                kept.push(s);
            }
        }
        self.segments = kept;
        Ok(freed)
    }

    /// Remove the indexed segment at `idx` — used by oldest-first
    /// disk-cap eviction. Only flushed segments are indexed, so the
    /// active write buffer is never touched. Returns bytes freed
    /// (0 if the index is stale or the file can't be removed).
    pub fn drop_segment(&mut self, idx: usize) -> u64 {
        if idx >= self.segments.len() {
            return 0;
        }
        let s = self.segments.remove(idx);
        match std::fs::remove_file(&s.path) {
            Ok(()) => {
                if let Some(parent) = s.path.parent() {
                    let _ = std::fs::remove_dir(parent);
                }
                s.file_size
            }
            Err(e) => {
                tracing::warn!("drop_segment: cannot remove {:?}: {}", s.path, e);
                // Keep the index honest — the file still exists.
                self.segments.insert(idx, s);
                0
            }
        }
    }

    /// Total on-disk bytes across indexed segments.
    pub fn total_bytes(&self) -> u64 {
        self.segments.iter().map(|s| s.file_size).sum()
    }

    /// Total rows across indexed segments (headers only, cheap).
    pub fn total_rows(&self) -> u64 {
        self.segments.iter().map(|s| s.header.row_count).sum()
    }
}

/// Decode worker count for parallel segment scans.
pub fn scan_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(2, 8)
}

/// Scan segments whose indices are in `idx` (positions into `infos`),
/// decoding each with `decode` on a small thread pool and invoking `f`
/// strictly in `idx` order. Decoding (file read + decompression) is the
/// expensive part of a scan and is per-segment independent, so it runs
/// `scan_threads()`-wide; aggregation stays sequential on the caller.
///
/// Segments are processed in batches so peak memory stays bounded
/// (~batch_size decoded segments alive at once) and an early `Break`
/// only wastes the remainder of the current batch.
fn parallel_scan<T, D>(
    infos: &[SegmentInfo],
    idx: &[usize],
    decode: D,
    mut f: impl FnMut(T) -> ControlFlow<()>,
) -> Result<()>
where
    T: Send,
    D: Fn(&SegmentInfo) -> Result<T> + Sync,
{
    const BATCH: usize = 32;
    let nthreads = scan_threads();
    for chunk in idx.chunks(BATCH) {
        let next = std::sync::atomic::AtomicUsize::new(0);
        let results: Vec<Option<Result<T>>> = std::thread::scope(|s| {
            let (tx, rx) = std::sync::mpsc::channel();
            for _ in 0..nthreads.min(chunk.len()) {
                let tx = tx.clone();
                let next = &next;
                let decode = &decode;
                s.spawn(move || loop {
                    let p = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if p >= chunk.len() {
                        break;
                    }
                    let _ = tx.send((p, decode(&infos[chunk[p]])));
                });
            }
            drop(tx);
            let mut slots: Vec<Option<Result<T>>> = (0..chunk.len()).map(|_| None).collect();
            for _ in 0..chunk.len() {
                if let Ok((p, res)) = rx.recv() {
                    slots[p] = Some(res);
                }
            }
            slots
        });
        for slot in results {
            match slot {
                Some(Ok(v)) => {
                    if f(v).is_break() {
                        return Ok(());
                    }
                }
                Some(Err(e)) => return Err(e),
                None => {}
            }
        }
    }
    Ok(())
}

/// Like `for_each_segment_info` but decodes only the requested columns.
/// The callback receives `(col_idx, ColumnData)` pairs (in request order)
/// plus the row count — callers index columns by `col_idx`.
pub fn for_each_segment_cols(
    infos: &[SegmentInfo],
    _schema: &'static Schema,
    cols: &[usize],
    from_ms: u64,
    to_ms: u64,
    newest_first: bool,
    mut f: impl FnMut(&[(usize, ColumnData)], usize) -> ControlFlow<()>,
) -> Result<()> {
    let mut idx: Vec<usize> = infos
        .iter()
        .enumerate()
        .filter(|(_, s)| s.overlaps(from_ms, to_ms))
        .map(|(i, _)| i)
        .collect();
    if newest_first {
        idx.reverse();
    }
    parallel_scan(infos, &idx, |info| {
        let reader = segment::SegmentReader::open(&info.path)?;
        let columns = reader.decode_columns(cols)?;
        Ok((columns, reader.header.row_count as usize))
    }, |(columns, rows)| {
        f(&columns, rows)
    })
}

/// Scan a caller-provided segment index (e.g. a snapshot taken from a
/// `Dataset`) without needing the `Dataset` itself. This lets query paths
/// read segment files concurrently with the writer task.
pub fn for_each_segment_info<R: Record>(
    infos: &[SegmentInfo],
    schema: &'static Schema,
    from_ms: u64,
    to_ms: u64,
    newest_first: bool,
    mut f: impl FnMut(&ScanResult) -> ControlFlow<()>,
) -> Result<()> {
    let mut idx: Vec<usize> = infos
        .iter()
        .enumerate()
        .filter(|(_, s)| s.overlaps(from_ms, to_ms))
        .map(|(i, _)| i)
        .collect();
    if newest_first {
        idx.reverse();
    }
    parallel_scan(infos, &idx, |info| {
        let reader = segment::SegmentReader::open(&info.path)?;
        Ok(ScanResult {
            schema,
            rows: reader.header.row_count as usize,
            columns: reader.decode_all()?,
            seg: info
                .path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
        })
    }, |scan| f(&scan))
}
