//! Prometheus metrics + internal counters.

use std::collections::{BTreeMap, HashMap};
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
    /// Storage write/flush failures (dataset push, segment flush,
    /// retention). The writer survives these — this counter is the signal.
    pub write_errors: AtomicU64,
    pub unknown_proto: AtomicU64,
    /// Datagrams dropped by the exporter admission policy (pending,
    /// suspended, rejected senders).
    pub exporter_drops: AtomicU64,
    pub flushes: AtomicU64,
    pub bytes_stored: AtomicU64,
    pub rows_stored: AtomicU64,
    pub bytes_freed: AtomicU64,
    /// Free bytes on the data filesystem, sampled on retention sweeps
    /// (0 until the first sample).
    pub disk_free_bytes: AtomicU64,
    pub mmdb_hits: AtomicU64,
    pub http_hits: AtomicU64,
    pub http_misses: AtomicU64,
    pub http_lookups: AtomicU64,
    pub http_errors: AtomicU64,
    pub table_hits: AtomicU64,
    pub alerts_fired: AtomicU64,
    /// SWR query-cache outcomes.
    pub qcache_hit: AtomicU64,
    pub qcache_stale: AtomicU64,
    pub qcache_miss: AtomicU64,
    /// Outbound NetFlow/IPFIX export counters.
    pub export_flows: AtomicU64,
    pub export_datagrams: AtomicU64,
    pub export_errors: AtomicU64,
    pub export_dropped: AtomicU64,
    /// Per-path HTTP stats: count, total handler ms, 5xx count.
    pub http: Mutex<HashMap<String, HttpStat>>,
    pub exporters: Mutex<HashMap<IpAddr, ExporterStat>>,
    /// Flow-input listener state, keyed "proto/listen" (e.g.
    /// "udp/0.0.0.0:2055"): starting → up, or "failed: <err>" /
    /// "skipped". Written by ingest tasks, read by /status + /metrics.
    pub input_state: Mutex<BTreeMap<String, String>>,
    /// Bumped on every successful config reload or naming/policy
    /// mutation — query caches fold it into their keys so stale
    /// pre-change responses are never served afterwards.
    pub config_gen: AtomicU64,
}

#[derive(Debug, Default)]
pub struct HttpStat {
    pub count: u64,
    pub total_ms: u64,
    pub err5xx: u64,
}

impl Metrics {
    /// Invalidate query/overview caches: anything that changes what a
    /// cached response would contain (config reload, renames, policy).
    pub fn bump_config_gen(&self) {
        self.config_gen.fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_datagram(&self, src: IpAddr, payload_len: usize, records: usize) {
        self.datagrams.fetch_add(1, Ordering::Relaxed);
        self.records.fetch_add(records as u64, Ordering::Relaxed);
        self.bytes_in
            .fetch_add(payload_len as u64, Ordering::Relaxed);
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

    pub fn set_input_state(&self, key: &str, state: &str) {
        self.input_state
            .lock()
            .unwrap()
            .insert(key.to_string(), state.to_string());
    }

    pub fn input_states(&self) -> BTreeMap<String, String> {
        self.input_state.lock().unwrap().clone()
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
        s.push_str(&format!(
            "bgflow_parse_errors_total {}\n",
            g(&self.parse_errors)
        ));
        s.push_str("# HELP bgflow_channel_dropped_total Records dropped (channel full)\n# TYPE bgflow_channel_dropped_total counter\n");
        s.push_str(&format!(
            "bgflow_channel_dropped_total {}\n",
            g(&self.channel_dropped)
        ));
        s.push_str("# HELP bgflow_write_errors_total Storage write/flush errors (writer keeps running)\n# TYPE bgflow_write_errors_total counter\n");
        s.push_str(&format!(
            "bgflow_write_errors_total {}\n",
            g(&self.write_errors)
        ));
        s.push_str("# HELP bgflow_unknown_proto_total Datagrams with unknown protocol\n# TYPE bgflow_unknown_proto_total counter\n");
        s.push_str(&format!(
            "bgflow_unknown_proto_total {}\n",
            g(&self.unknown_proto)
        ));
        s.push_str("# HELP bgflow_exporter_drops_total Datagrams dropped by exporter policy\n# TYPE bgflow_exporter_drops_total counter\n");
        s.push_str(&format!(
            "bgflow_exporter_drops_total {}\n",
            g(&self.exporter_drops)
        ));
        s.push_str("# HELP bgflow_enrich_http_lookups_total HTTP enrichment lookups\n# TYPE bgflow_enrich_http_lookups_total counter\n");
        s.push_str(&format!(
            "bgflow_enrich_http_lookups_total {}\n",
            g(&self.http_lookups)
        ));
        s.push_str("# HELP bgflow_enrich_http_errors_total HTTP enrichment errors\n# TYPE bgflow_enrich_http_errors_total counter\n");
        s.push_str(&format!(
            "bgflow_enrich_http_errors_total {}\n",
            g(&self.http_errors)
        ));
        s.push_str("# HELP bgflow_enrich_table_hits_total Table-enricher cache hits\n# TYPE bgflow_enrich_table_hits_total counter\n");
        s.push_str(&format!(
            "bgflow_enrich_table_hits_total {}\n",
            g(&self.table_hits)
        ));
        s.push_str("# HELP bgflow_alerts_fired_total Alert rule fires\n# TYPE bgflow_alerts_fired_total counter\n");
        s.push_str(&format!(
            "bgflow_alerts_fired_total {}\n",
            g(&self.alerts_fired)
        ));
        s.push_str("# HELP bgflow_qcache_hit_total Query-cache fresh hits\n# TYPE bgflow_qcache_hit_total counter\n");
        s.push_str(&format!(
            "bgflow_qcache_hit_total {}\n",
            g(&self.qcache_hit)
        ));
        s.push_str("# HELP bgflow_qcache_stale_total Query-cache stale serves (refresh spawned)\n# TYPE bgflow_qcache_stale_total counter\n");
        s.push_str(&format!(
            "bgflow_qcache_stale_total {}\n",
            g(&self.qcache_stale)
        ));
        s.push_str("# HELP bgflow_qcache_miss_total Query-cache misses\n# TYPE bgflow_qcache_miss_total counter\n");
        s.push_str(&format!(
            "bgflow_qcache_miss_total {}\n",
            g(&self.qcache_miss)
        ));
        s.push_str("# HELP bgflow_export_flows_total Flow records exported\n# TYPE bgflow_export_flows_total counter\n");
        s.push_str(&format!(
            "bgflow_export_flows_total {}\n",
            g(&self.export_flows)
        ));
        s.push_str("# HELP bgflow_export_datagrams_total Export datagrams sent\n# TYPE bgflow_export_datagrams_total counter\n");
        s.push_str(&format!(
            "bgflow_export_datagrams_total {}\n",
            g(&self.export_datagrams)
        ));
        s.push_str("# HELP bgflow_export_errors_total Export send errors\n# TYPE bgflow_export_errors_total counter\n");
        s.push_str(&format!(
            "bgflow_export_errors_total {}\n",
            g(&self.export_errors)
        ));
        s.push_str("# HELP bgflow_export_dropped_total Flow batches dropped (export queue full)\n# TYPE bgflow_export_dropped_total counter\n");
        s.push_str(&format!(
            "bgflow_export_dropped_total {}\n",
            g(&self.export_dropped)
        ));
        {
            let http = self.http.lock().unwrap();
            s.push_str("# HELP bgflow_http_requests_total HTTP requests by path\n# TYPE bgflow_http_requests_total counter\n");
            for (p, h) in http.iter() {
                s.push_str(&format!(
                    "bgflow_http_requests_total{{path=\"{}\"}} {}\n",
                    p, h.count
                ));
            }
            s.push_str("# HELP bgflow_http_request_duration_ms_total Summed handler time by path\n# TYPE bgflow_http_request_duration_ms_total counter\n");
            for (p, h) in http.iter() {
                s.push_str(&format!(
                    "bgflow_http_request_duration_ms_total{{path=\"{}\"}} {}\n",
                    p, h.total_ms
                ));
            }
            s.push_str("# HELP bgflow_http_5xx_total Server errors by path\n# TYPE bgflow_http_5xx_total counter\n");
            for (p, h) in http.iter() {
                s.push_str(&format!(
                    "bgflow_http_5xx_total{{path=\"{}\"}} {}\n",
                    p, h.err5xx
                ));
            }
        }
        s.push_str("# HELP bgflow_stored_bytes_total Bytes flushed to segments\n# TYPE bgflow_stored_bytes_total counter\n");
        s.push_str(&format!(
            "bgflow_stored_bytes_total {}\n",
            g(&self.bytes_stored)
        ));
        s.push_str("# HELP bgflow_stored_rows_total Rows flushed to segments\n# TYPE bgflow_stored_rows_total counter\n");
        s.push_str(&format!(
            "bgflow_stored_rows_total {}\n",
            g(&self.rows_stored)
        ));
        s.push_str("# HELP bgflow_retention_freed_bytes_total Bytes freed by retention\n# TYPE bgflow_retention_freed_bytes_total counter\n");
        s.push_str(&format!(
            "bgflow_retention_freed_bytes_total {}\n",
            g(&self.bytes_freed)
        ));
        s.push_str("# HELP bgflow_disk_free_bytes Free bytes on the data filesystem\n# TYPE bgflow_disk_free_bytes gauge\n");
        s.push_str(&format!(
            "bgflow_disk_free_bytes {}\n",
            g(&self.disk_free_bytes)
        ));
        {
            let esc = |v: &str| v.replace('\\', "\\\\").replace('"', "\\\"");
            let inputs = self.input_state.lock().unwrap();
            s.push_str("# HELP bgflow_ingest_input_up 1 when the flow-input listener is bound and reading\n# TYPE bgflow_ingest_input_up gauge\n");
            for (k, v) in inputs.iter() {
                s.push_str(&format!(
                    "bgflow_ingest_input_up{{input=\"{}\"}} {}\n",
                    esc(k),
                    if v == "up" { 1 } else { 0 }
                ));
            }
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn render_includes_query_and_http_metrics() {
        let m = Metrics::default();
        m.qcache_hit.store(3, Ordering::Relaxed);
        m.qcache_miss.store(7, Ordering::Relaxed);
        m.http.lock().unwrap().insert(
            "/api/v1/top".to_string(),
            HttpStat {
                count: 2,
                total_ms: 50,
                err5xx: 1,
            },
        );
        let s = m.render();
        assert!(s.contains("bgflow_qcache_hit_total 3"));
        assert!(s.contains("bgflow_qcache_miss_total 7"));
        assert!(s.contains("bgflow_http_requests_total{path=\"/api/v1/top\"} 2"));
        assert!(s.contains("bgflow_http_request_duration_ms_total{path=\"/api/v1/top\"} 50"));
        assert!(s.contains("bgflow_http_5xx_total{path=\"/api/v1/top\"} 1"));
    }
}
