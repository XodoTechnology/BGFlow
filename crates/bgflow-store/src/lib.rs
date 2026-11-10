//! BGFlow storage engine: custom columnar, time-partitioned segment files
//! with per-column dictionary/delta encoding and ZSTD compression.
//!
//! No external database server required — segments are plain files that can
//! be copied, archived, or inspected directly.

pub mod dataset;
pub mod encode;
pub mod rollup;
pub mod schema;
pub mod segment;
pub mod timeutil;

pub use dataset::{for_each_segment_cols, for_each_segment_info, Dataset, DatasetOpts, Record, ScanResult};
pub use encode::ColumnData;
pub use rollup::RollupAggregator;
pub use schema::{schema_by_id, RAW_SCHEMA, ROLLUP_SCHEMA};
pub use segment::{read_header, scan_segments, verify_crc, SegmentInfo, SegmentReader};
