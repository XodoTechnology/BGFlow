//! Prometheus metrics + internal counters.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Default)]
pub struct ExporterStat {
    pub datagrams: u64,
    pub records: u64,
    pub bytes_in: u64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Default)]
pub struct Metrics {
    pub datagrams: AtomicU64,
    pub records: AtomicU64,
    pub bytes_in: AtomicU64,
    pub parse_errors: AtomicU64,
    pub channel_dropped: AtomicU64,
    pub unknown_proto: AtomicU64,
    pub flushes: AtomicU64,
    pub bytes_stored: AtomicU64,
    pub rows_stored: AtomicU64,
    pub bytes_freed: AtomicU64,
    pub mmdb_hits: AtomicU64,
    pub http_hits: AtomicU64,
    pub http_misses: AtomicU64,
    pub http_lookups: AtomicU64,
    pub http_errors: AtomicU64,
    pub exporters: Mutex<HashMap<IpAddr, ExporterStat>>,
}

impl Metrics {
    pub fn note_datagram(&self, src: IpAddr, payload_len: usize, records: usize) {
        self.datagrams.fetch_add(1, Ordering::Relaxed);
        self.records.fetch_add(records as u64, Ordering::Relaxed);
        self.bytes_in.fetch_add(payload_len as u64, Ordering::Relaxed);
        let mut map = self.exporters.lock().unwrap();
        // Bound per-exporter cardinality: spoofed UDP sources must not grow
        // this map (and the /metrics label set) without limit.
        const MAX_EXPORTERS: usize = 10_000;
        if !map.contains_key(&src) && map.len() >= MAX_EXPORTERS {
            return;
        }
        let e = map.entry(src).or_default();
        e.datagrams += 1;
        e.records += records as u64;
        e.bytes_in += payload_len as u64;
        e.last_seen_ms = now_ms();
    }

    pub fn render(&self) -> String {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut s = String::with_capacity(4096);
        s.push_str("# HELP bgflow_datagrams_total Flow datagrams received\n# TYPE bgflow_datagrams_total counter\n");
        s.push_str(&format!("bgflow_datagrams_total {}\n", g(&self.datagrams)));
        s.push_str("# HELP bgflow_flow_records_total Flow records parsed\n# TYPE bgflow_flow_records_total counter\n");
        s.push_str(&format!("bgflow_flow_records_total {}\n", g(&self.records)));
        s.push_str("# HELP bgflow_bytes_in_total Payload bytes received\n# TYPE bgflow_bytes_in_total counter\n");
        s.push_str(&format!("bgflow_bytes_in_total {}\n", g(&self.bytes_in)));
        s.push_str("# HELP bgflow_parse_errors_total Undecodable datagrams\n# TYPE bgflow_parse_errors_total counter\n");
        s.push_str(&format!("bgflow_parse_errors_total {}\n", g(&self.parse_errors)));
        s.push_str("# HELP bgflow_channel_dropped_total Records dropped (channel full)\n# TYPE bgflow_channel_dropped_total counter\n");
        s.push_str(&format!("bgflow_channel_dropped_total {}\n", g(&self.channel_dropped)));
        s.push_str("# HELP bgflow_unknown_proto_total Datagrams with unknown protocol\n# TYPE bgflow_unknown_proto_total counter\n");
        s.push_str(&format!("bgflow_unknown_proto_total {}\n", g(&self.unknown_proto)));
        s.push_str("# HELP bgflow_enrich_http_lookups_total HTTP enrichment lookups\n# TYPE bgflow_enrich_http_lookups_total counter\n");
        s.push_str(&format!("bgflow_enrich_http_lookups_total {}\n", g(&self.http_lookups)));
        s.push_str("# HELP bgflow_enrich_http_errors_total HTTP enrichment errors\n# TYPE bgflow_enrich_http_errors_total counter\n");
        s.push_str(&format!("bgflow_enrich_http_errors_total {}\n", g(&self.http_errors)));
        s.push_str("# HELP bgflow_stored_bytes_total Bytes flushed to segments\n# TYPE bgflow_stored_bytes_total counter\n");
        s.push_str(&format!("bgflow_stored_bytes_total {}\n", g(&self.bytes_stored)));
        s.push_str("# HELP bgflow_stored_rows_total Rows flushed to segments\n# TYPE bgflow_stored_rows_total counter\n");
        s.push_str(&format!("bgflow_stored_rows_total {}\n", g(&self.rows_stored)));
        s.push_str("# HELP bgflow_retention_freed_bytes_total Bytes freed by retention\n# TYPE bgflow_retention_freed_bytes_total counter\n");
        s.push_str(&format!("bgflow_retention_freed_bytes_total {}\n", g(&self.bytes_freed)));

        let map = self.exporters.lock().unwrap();
        s.push_str("# HELP bgflow_exporter_datagrams_total Datagrams per exporter\n# TYPE bgflow_exporter_datagrams_total counter\n");
        for (ip, e) in map.iter() {
            s.push_str(&format!(
                "bgflow_exporter_datagrams_total{{exporter=\"{}\"}} {}\n",
                ip, e.datagrams
            ));
        }
        s.push_str("# HELP bgflow_exporter_records_total Records per exporter\n# TYPE bgflow_exporter_records_total counter\n");
        for (ip, e) in map.iter() {
            s.push_str(&format!(
                "bgflow_exporter_records_total{{exporter=\"{}\"}} {}\n",
                ip, e.records
            ));
        }
        s.push_str("# HELP bgflow_exporter_last_seen_ms Last datagram time per exporter\n# TYPE bgflow_exporter_last_seen_ms gauge\n");
        for (ip, e) in map.iter() {
            s.push_str(&format!(
                "bgflow_exporter_last_seen_ms{{exporter=\"{}\"}} {}\n",
                ip, e.last_seen_ms
            ));
        }
        s
    }
}
