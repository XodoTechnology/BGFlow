//! Debug helper: sum `bytes` per hour bucket directly from .bfs segment
//! files, bypassing all query-path logic. Usage:
//!   dumpbytes <dataset_dir> <rollup|flow>
use bgflow_store::encode::ColumnData;
use bgflow_store::schema::{raw_idx, rollup_idx};
use bgflow_store::segment::{scan_segments, SegmentReader};
use std::collections::BTreeMap;
use std::path::Path;

fn hour(ms: u64) -> u64 {
    ms / 3_600_000 * 3_600_000
}

fn main() -> anyhow::Result<()> {
    let dir = std::env::args().nth(1).expect("dataset dir");
    let kind = std::env::args().nth(2).unwrap_or_else(|| "rollup".into());
    let infos = scan_segments(Path::new(&dir))?;
    eprintln!("{} segments", infos.len());
    let mut per_hour: BTreeMap<u64, u128> = BTreeMap::new();
    let (ts_idx, bytes_idx) = if kind == "flow" {
        (raw_idx::TS_MS, raw_idx::BYTES)
    } else {
        (rollup_idx::BUCKET_MS, rollup_idx::BYTES)
    };
    for info in &infos {
        let r = SegmentReader::open(&info.path)?;
        let cols = r.decode_columns(&[ts_idx, bytes_idx])?;
        let mut arr: Vec<Option<&ColumnData>> = vec![None; 32];
        for (ci, d) in &cols {
            arr[*ci] = Some(d);
        }
        for i in 0..r.header.row_count as usize {
            let ts = arr[ts_idx].map(|c| c.value_at(i) as u64).unwrap_or(0);
            let b = arr[bytes_idx].map(|c| c.value_at(i)).unwrap_or(0);
            *per_hour.entry(hour(ts)).or_default() += b;
        }
    }
    let mut tot = 0u128;
    for (h, b) in &per_hour {
        println!("{} {}", h, b);
        tot += b;
    }
    eprintln!("TOTAL {}", tot);
    Ok(())
}
