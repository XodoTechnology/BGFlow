//! HTTP API (axum) + embedded UI serving.

use crate::config::Config;
use crate::enrich::{HttpEnrichers, MmdbGeo};
use crate::metrics::Metrics;
use crate::query::{self, Ctx, FlowQuery, RollupFilter, RollupSet};
use crate::writer::StatusSnapshot;
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use bgflow_types::ip_to_u128;
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::sync::{Arc, RwLock};

pub struct AppState {
    pub ctx: Ctx,
    pub status: Arc<RwLock<StatusSnapshot>>,
    pub metrics: Arc<Metrics>,
    pub http_enrich: Arc<HttpEnrichers>,
    pub geo: Arc<MmdbGeo>,
    pub config: Arc<Config>,
}

type Q = HashMap<String, String>;

fn err(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": msg.into()})),
    )
}

fn range(q: &Q) -> (u64, u64) {
    let (df, dt) = query::default_range();
    (
        query::parse_time(q.get("from").map(|s| s.as_str()), df),
        query::parse_time(q.get("to").map(|s| s.as_str()), dt),
    )
}

/// Which rollup dataset a stats query reads: `granularity=hourly` selects
/// the coarse long-retention dataset (masked /24·/48 IPs, hour buckets).
fn rollup_set(q: &Q) -> RollupSet {
    match q.get("granularity").or_else(|| q.get("dataset")).map(|s| s.as_str()) {
        Some("hourly") | Some("hour") | Some("coarse") | Some("1h") => RollupSet::Hourly,
        _ => RollupSet::Minute,
    }
}

fn parse_ipver(s: &str) -> Result<u8, (StatusCode, Json<serde_json::Value>)> {
    match s.to_ascii_lowercase().as_str() {
        "4" | "v4" | "ipv4" => Ok(4),
        "6" | "v6" | "ipv6" => Ok(6),
        _ => Err(err("bad ipver (4|6)")),
    }
}

fn resolve_label(ctx: &Ctx, s: &str) -> Option<u32> {
    if let Ok(id) = s.parse::<u32>() {
        return Some(id);
    }
    ctx.rules
        .names()
        .into_iter()
        .find(|(_, n)| n.eq_ignore_ascii_case(s))
        .map(|(id, _)| id)
}

fn rollup_filter(
    q: &Q,
    ctx: &Ctx,
) -> Result<RollupFilter, (StatusCode, Json<serde_json::Value>)> {
    let mut f = RollupFilter::default();
    if let Some(s) = q.get("exporter") {
        // Comma-separated allowlist: exporter=1.2.3.4,5.6.7.8
        for part in s.split(',') {
            let ip: IpAddr = part
                .trim()
                .parse()
                .map_err(|_| err("bad exporter"))?;
            f.exporters.push(ip_to_u128(&ip));
        }
    }
    if let Some(s) = q.get("proto") {
        f.proto = Some(parse_proto(s)?);
    }
    if let Some(s) = q.get("src_asn") {
        f.src_asn = Some(s.parse().map_err(|_| err("bad src_asn"))?);
    }
    if let Some(s) = q.get("dst_asn") {
        f.dst_asn = Some(s.parse().map_err(|_| err("bad dst_asn"))?);
    }
    if let Some(s) = q.get("src_ip").or_else(|| q.get("src")) {
        f.src_ip = Some(query::parse_ip_filter(s).ok_or_else(|| err("bad src_ip"))?);
    }
    if let Some(s) = q.get("dst_ip").or_else(|| q.get("dst")) {
        f.dst_ip = Some(query::parse_ip_filter(s).ok_or_else(|| err("bad dst_ip"))?);
    }
    if let Some(s) = q.get("src_ipver") {
        f.src_ipver = Some(parse_ipver(s)?);
    }
    if let Some(s) = q.get("dst_ipver") {
        f.dst_ipver = Some(parse_ipver(s)?);
    }
    if let Some(s) = q.get("src_port").or_else(|| q.get("sport")) {
        f.src_port = Some(s.parse().map_err(|_| err("bad src_port"))?);
    }
    if let Some(s) = q.get("dst_port").or_else(|| q.get("dport")) {
        f.dst_port = Some(s.parse().map_err(|_| err("bad dst_port"))?);
    }
    if let Some(s) = q.get("src_country") {
        f.src_country = Some(bgflow_types::country_pack(s));
    }
    if let Some(s) = q.get("dst_country") {
        f.dst_country = Some(bgflow_types::country_pack(s));
    }
    if let Some(s) = q.get("src_org") {
        f.src_org = Some(s.parse().map_err(|_| err("bad src_org"))?);
    }
    if let Some(s) = q.get("dst_org") {
        f.dst_org = Some(s.parse().map_err(|_| err("bad dst_org"))?);
    }
    if let Some(s) = q.get("label") {
        f.label = resolve_label(ctx, s);
    }
    Ok(f)
}

fn parse_proto(s: &str) -> Result<u8, (StatusCode, Json<serde_json::Value>)> {
    if let Ok(n) = s.parse::<u8>() {
        return Ok(n);
    }
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" | "icmpv4" => Ok(1),
        "icmpv6" => Ok(58),
        "gre" => Ok(47),
        "esp" => Ok(50),
        _ => Err(err("unknown protocol")),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let s = st.status.read().unwrap().clone();
    // Deep health: writer lag, buffered rows, last flush age.
    let age_ms = if s.last_flush_ms == 0 {
        None
    } else {
        Some(crate::metrics::now_ms().saturating_sub(s.last_flush_ms))
    };
    let healthy = s.writer_alive
        && s.buffered_rows < 1_000_000
        && age_ms.map(|a| a < 300_000).unwrap_or(true);
    Json(serde_json::json!({
        "status": if healthy { "ok" } else { "degraded" },
        "writer_alive": s.writer_alive,
        "buffered_rows": s.buffered_rows,
        "last_flush_age_ms": age_ms,
        "flow_segments": s.flow_segments,
        "rollup_segments": s.rollup_segments,
        "hourly_segments": s.hourly_segments,
        "uptime_secs": s.uptime_secs,
    }))
}

async fn status(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let s = st.status.read().unwrap().clone();
    Json(serde_json::json!({
        "status": s,
        "orgs": st.ctx.orgs.len(),
        "rules": st.ctx.rules.len(),
        "inputs": st.config.inputs.iter().map(|i| i.listen.to_string()).collect::<Vec<_>>(),
    }))
}

async fn metrics_handler(State(st): State<Arc<AppState>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        st.metrics.render(),
    )
        .into_response()
}

async fn flows(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let mut fq = FlowQuery {
        from_ms: from,
        to_ms: to,
        limit: q
            .get("limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(500)
            .min(10_000),
        offset: q.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0),
        newest_first: q.get("order").map(|s| s != "asc").unwrap_or(true),
        ..Default::default()
    };
    if let Some(s) = q.get("src") {
        fq.src = Some(query::parse_ip_filter(s).ok_or_else(|| err("bad src"))?);
    }
    if let Some(s) = q.get("dst") {
        fq.dst = Some(query::parse_ip_filter(s).ok_or_else(|| err("bad dst"))?);
    }
    if let Some(s) = q.get("proto") {
        fq.proto = Some(parse_proto(s)?);
    }
    if let Some(s) = q.get("sport") {
        fq.sport = Some(s.parse().map_err(|_| err("bad sport"))?);
    }
    if let Some(s) = q.get("dport") {
        fq.dport = Some(s.parse().map_err(|_| err("bad dport"))?);
    }
    if let Some(s) = q.get("exporter") {
        // Comma-separated allowlist, same as rollup_filter.
        for part in s.split(',') {
            let ip: IpAddr = part.trim().parse().map_err(|_| err("bad exporter"))?;
            fq.exporters.push(ip_to_u128(&ip));
        }
    }
    if let Some(s) = q.get("src_ipver") {
        fq.src_ipver = Some(parse_ipver(s)?);
    }
    if let Some(s) = q.get("dst_ipver") {
        fq.dst_ipver = Some(parse_ipver(s)?);
    }
    if let Some(s) = q.get("src_org") {
        fq.src_org = Some(s.parse().map_err(|_| err("bad src_org"))?);
    }
    if let Some(s) = q.get("dst_org") {
        fq.dst_org = Some(s.parse().map_err(|_| err("bad dst_org"))?);
    }
    if let Some(s) = q.get("src_asn") {
        fq.src_asn = Some(s.parse().map_err(|_| err("bad src_asn"))?);
    }
    if let Some(s) = q.get("dst_asn") {
        fq.dst_asn = Some(s.parse().map_err(|_| err("bad dst_asn"))?);
    }
    if let Some(s) = q.get("label") {
        fq.label = resolve_label(&st.ctx, s);
    }

    let mut recs = query::flows(&st.ctx, &fq).map_err(|e| err(e.to_string()))?;
    // Enrich-at-read: fills org/country/asn fields the ingest-time pipeline
    // missed (pre-enrichment data, cold caches, table lookups).
    for f in recs.iter_mut() {
        crate::enrich::enrich_record(f, &st.geo, &st.http_enrich);
    }

    if q.get("format").map(|s| s.as_str()) == Some("csv") {
        return csv_response(&recs);
    }
    let out: Vec<_> = recs.iter().map(|f| query::flow_json(&st.ctx, f)).collect();
    Ok(Json(serde_json::json!({
        "count": out.len(),
        "offset": fq.offset,
        "flows": out,
    })))
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn csv_response(recs: &[bgflow_types::FlowRecord]) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // CSV export — returned as JSON {"csv": "..."} so the UI can download it
    // without a second content-type path; API clients can also request
    // format=csv&raw=1 for a text body (see below).
    let mut s = String::from(
        "ts,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,exporter,src_asn,dst_asn,label_id\n",
    );
    for f in recs {
        s.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{}\n",
            f.ts_ms,
            csv_escape(&bgflow_types::ip_string(f.src_ip)),
            csv_escape(&bgflow_types::ip_string(f.dst_ip)),
            f.src_port,
            f.dst_port,
            f.protocol,
            f.bytes,
            f.packets,
            csv_escape(&bgflow_types::ip_string(f.exporter)),
            f.src_asn,
            f.dst_asn,
            f.label_id,
        ));
    }
    Ok(Json(serde_json::json!({"count": recs.len(), "csv": s})))
}

#[derive(Default)]
struct Agg {
    bytes: u64,
    packets: u64,
    flows: u64,
}

async fn summary(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let set = rollup_set(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let needed = query::rollup_needed(&f, &["proto"]);
    let mut total = Agg::default();
    let mut by_proto: HashMap<u8, Agg> = HashMap::new();
    query::rollup_scan(&st.ctx, set, from, to, &needed, |r| {
        if !f.matches(r) {
            return ControlFlow::Continue(());
        }
        total.bytes += r.bytes();
        total.packets += r.packets();
        total.flows += r.flows();
        let p = by_proto.entry(r.protocol()).or_default();
        p.bytes += r.bytes();
        p.packets += r.packets();
        p.flows += r.flows();
        ControlFlow::Continue(())
    })
    .map_err(|e| err(e.to_string()))?;

    let mut protos: Vec<_> = by_proto
        .into_iter()
        .map(|(p, a)| {
            serde_json::json!({
                "protocol": p,
                "name": bgflow_types::protocol_name(p),
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    protos.sort_by_key(|v| std::cmp::Reverse(v["bytes"].as_u64().unwrap_or(0)));

    Ok(Json(serde_json::json!({
        "from": from, "to": to,
        "bytes": total.bytes, "packets": total.packets, "flows": total.flows,
        "by_protocol": protos,
    })))
}

fn bucket_ms(s: Option<&str>) -> u64 {
    match s.unwrap_or("1m") {
        "1m" => 60_000,
        "5m" => 300_000,
        "15m" => 900_000,
        "1h" => 3_600_000,
        "6h" => 21_600_000,
        "1d" => 86_400_000,
        _ => 60_000,
    }
}

async fn timeseries(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let set = rollup_set(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let size = bucket_ms(q.get("bucket").map(|s| s.as_str()));
    let needed = query::rollup_needed(&f, &[]);
    let mut buckets: HashMap<u64, Agg> = HashMap::new();
    query::rollup_scan(&st.ctx, set, from, to, &needed, |r| {
        if !f.matches(r) {
            return ControlFlow::Continue(());
        }
        let b = (r.bucket_ms() / size) * size;
        let a = buckets.entry(b).or_default();
        a.bytes += r.bytes();
        a.packets += r.packets();
        a.flows += r.flows();
        ControlFlow::Continue(())
    })
    .map_err(|e| err(e.to_string()))?;

    let mut rows: Vec<_> = buckets
        .into_iter()
        .map(|(t, a)| {
            serde_json::json!({
                "t": t / 1000, "bucket_ms": t,
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    rows.sort_by_key(|v| v["t"].as_u64().unwrap_or(0));
    Ok(Json(serde_json::json!({"bucket_ms": size, "series": rows})))
}

const TOP_DIMS: &[&str] = &[
    "src_ip", "dst_ip", "src_ipver", "dst_ipver", "src_asn", "dst_asn",
    "src_org", "dst_org", "src_port", "dst_port", "proto",
    "exporter", "src_country", "dst_country", "label",
];

async fn top(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let by = q.get("by").map(|s| s.as_str()).unwrap_or("src_ip");
    if !TOP_DIMS.contains(&by) {
        return Err(err(format!("unknown dimension '{}'; valid: {}", by, TOP_DIMS.join(", "))));
    }
    let (from, to) = range(&q);
    let set = rollup_set(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let limit: usize = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(10).min(1000);

    let mut map: HashMap<u128, Agg> = HashMap::new();
    let needed = query::rollup_needed(&f, &[by]);
    query::rollup_scan(&st.ctx, set, from, to, &needed, |r| {
        if !f.matches(r) {
            return ControlFlow::Continue(());
        }
        let k = query::dim_key(by, r);
        let a = map.entry(k).or_default();
        a.bytes += r.bytes();
        a.packets += r.packets();
        a.flows += r.flows();
        ControlFlow::Continue(())
    })
    .map_err(|e| err(e.to_string()))?;

    let mut rows: Vec<(u128, Agg)> = map.into_iter().collect();
    rows.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then(b.1.flows.cmp(&a.1.flows)));
    rows.truncate(limit);
    let out: Vec<_> = rows
        .into_iter()
        .map(|(k, a)| {
            serde_json::json!({
                "key": query::format_key(&st.ctx, by, k),
                "key_raw": k,
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({"by": by, "set": match set { RollupSet::Minute => "minute", RollupSet::Hourly => "hourly" }, "items": out})))
}

async fn conversations(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let set = rollup_set(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let limit: usize = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(20).min(500);
    type ConvKey = (u128, u128, u16, u16, u8);
    let mut map: HashMap<ConvKey, Agg> = HashMap::new();
    let needed = query::rollup_needed(&f, &["src_ip", "dst_ip", "src_port", "dst_port", "proto"]);
    query::rollup_scan(&st.ctx, set, from, to, &needed, |r| {
        if !f.matches(r) {
            return ControlFlow::Continue(());
        }
        let k = (r.src_ip(), r.dst_ip(), r.src_port(), r.dst_port(), r.protocol());
        let a = map.entry(k).or_default();
        a.bytes += r.bytes();
        a.packets += r.packets();
        a.flows += r.flows();
        ControlFlow::Continue(())
    })
    .map_err(|e| err(e.to_string()))?;

    let mut rows: Vec<(ConvKey, Agg)> = map.into_iter().collect();
    rows.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));
    rows.truncate(limit);
    let out: Vec<_> = rows
        .into_iter()
        .map(|((s, d, sp, dp, p), a)| {
            serde_json::json!({
                "src_ip": bgflow_types::ip_string(s),
                "dst_ip": bgflow_types::ip_string(d),
                "src_port": sp, "dst_port": dp,
                "protocol": p, "protocol_name": bgflow_types::protocol_name(p),
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({"items": out})))
}

async fn exporters(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let map = st.metrics.exporters.lock().unwrap();
    let items: Vec<_> = map
        .iter()
        .map(|(ip, e)| {
            serde_json::json!({
                "ip": ip.to_string(),
                "datagrams": e.datagrams,
                "records": e.records,
                "bytes_in": e.bytes_in,
                "last_seen_ms": e.last_seen_ms,
            })
        })
        .collect();
    Json(serde_json::json!({"items": items}))
}

async fn labels(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let items: Vec<_> = st
        .ctx
        .rules
        .list()
        .into_iter()
        .map(|(id, name)| serde_json::json!({"id": id, "name": name}))
        .collect();
    Json(serde_json::json!({"items": items}))
}

async fn enrichers(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(st.http_enrich.status())
}

/// Anomaly detection: per-key bytes-per-bucket series over the window;
/// flags buckets whose value exceeds mean + `sigma`·stddev of the series.
async fn anomalies(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let set = rollup_set(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let by = q.get("by").map(|s| s.as_str()).unwrap_or("src_ip");
    if !TOP_DIMS.contains(&by) {
        return Err(err(format!("unknown dimension '{}'", by)));
    }
    let sigma: f64 = q.get("sigma").and_then(|s| s.parse().ok()).unwrap_or(3.0);
    let top_n: usize = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(10).min(100);
    let needed = query::rollup_needed(&f, &[by]);

    // key -> bucket -> bytes
    let mut series: HashMap<u128, HashMap<u64, u64>> = HashMap::new();
    query::rollup_scan(&st.ctx, set, from, to, &needed, |r| {
        if !f.matches(r) {
            return ControlFlow::Continue(());
        }
        let k = query::dim_key(by, r);
        *series
            .entry(k)
            .or_default()
            .entry(r.bucket_ms())
            .or_insert(0) += r.bytes();
        ControlFlow::Continue(())
    })
    .map_err(|e| err(e.to_string()))?;

    struct Anom {
        key: u128,
        bucket: u64,
        bytes: u64,
        z: f64,
    }
    let mut out: Vec<Anom> = Vec::new();
    for (k, buckets) in &series {
        if buckets.len() < 3 {
            continue; // need a baseline
        }
        let vals: Vec<f64> = buckets.values().map(|v| *v as f64).collect();
        let mean = vals.iter().sum::<f64>() / vals.len() as f64;
        let var = vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / vals.len() as f64;
        let std = var.sqrt();
        if std < 1.0 {
            continue; // flat series — nothing anomalous
        }
        for (b, bytes) in buckets {
            let z = (*bytes as f64 - mean) / std;
            if z >= sigma {
                out.push(Anom { key: *k, bucket: *b, bytes: *bytes, z });
            }
        }
    }
    out.sort_by(|a, b| b.z.partial_cmp(&a.z).unwrap_or(std::cmp::Ordering::Equal));
    out.truncate(top_n);
    let items: Vec<_> = out
        .into_iter()
        .map(|a| {
            serde_json::json!({
                "key": query::format_key(&st.ctx, by, a.key),
                "key_raw": a.key,
                "bucket_ms": a.bucket,
                "t": a.bucket / 1000,
                "bytes": a.bytes,
                "zscore": (a.z * 100.0).round() / 100.0,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({"by": by, "sigma": sigma, "items": items})))
}

/// Traffic grouped by label (uses the label dimension).
async fn label_stats(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let set = rollup_set(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let needed = query::rollup_needed(&f, &["label"]);
    let mut map: HashMap<u128, Agg> = HashMap::new();
    query::rollup_scan(&st.ctx, set, from, to, &needed, |r| {
        if !f.matches(r) {
            return ControlFlow::Continue(());
        }
        let k = r.label_id() as u128;
        let a = map.entry(k).or_default();
        a.bytes += r.bytes();
        a.packets += r.packets();
        a.flows += r.flows();
        ControlFlow::Continue(())
    })
    .map_err(|e| err(e.to_string()))?;
    let mut rows: Vec<(u128, Agg)> = map.into_iter().collect();
    rows.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));
    let items: Vec<_> = rows
        .into_iter()
        .map(|(k, a)| {
            serde_json::json!({
                "label_id": k as u32,
                "label": query::format_key(&st.ctx, "label", k),
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({"items": items})))
}

/// Effective config for the UI settings view — secrets redacted.
async fn config_view(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mut v = serde_json::to_value(&*st.config).unwrap_or(serde_json::json!({}));
    if let Some(srv) = v.get_mut("server").and_then(|s| s.as_object_mut()) {
        if srv.contains_key("auth") {
            srv.insert("auth".into(), serde_json::json!("***"));
        }
    }
    if let Some(arr) = v.get_mut("enrichers").and_then(|e| e.as_array_mut()) {
        for e in arr.iter_mut() {
            if let Some(o) = e.as_object_mut() {
                if let Some(h) = o.get_mut("headers") {
                    *h = serde_json::json!("***");
                }
            }
        }
    }
    Json(v)
}

async fn openapi() -> Json<serde_json::Value> {
    Json(openapi_spec())
}

/// Compact OpenAPI 3.0 spec covering the query endpoints.
fn openapi_spec() -> serde_json::Value {
    serde_json::json!({
        "openapi": "3.0.3",
        "info": {"title": "BGFlow API", "version": "0.2.0"},
        "paths": {
            "/api/v1/health": {"get": {"summary": "Health + writer status"}},
            "/api/v1/status": {"get": {"summary": "Daemon status snapshot"}},
            "/api/v1/flows": {"get": {"summary": "Raw flow records", "parameters": [
                {"name": "from", "in": "query"}, {"name": "to", "in": "query"},
                {"name": "src", "in": "query", "description": "IP or CIDR"},
                {"name": "dst", "in": "query", "description": "IP or CIDR"},
                {"name": "proto", "in": "query"}, {"name": "sport", "in": "query"},
                {"name": "dport", "in": "query"},
                {"name": "exporter", "in": "query", "description": "comma-separated IPs"},
                {"name": "src_asn", "in": "query"}, {"name": "dst_asn", "in": "query"},
                {"name": "src_ipver", "in": "query", "description": "4|6"},
                {"name": "dst_ipver", "in": "query", "description": "4|6"},
                {"name": "src_org", "in": "query"}, {"name": "dst_org", "in": "query"},
                {"name": "label", "in": "query", "description": "label name or id"},
                {"name": "limit", "in": "query"}, {"name": "offset", "in": "query"},
                {"name": "order", "in": "query", "description": "asc|desc"},
                {"name": "format", "in": "query", "description": "csv"},
            ]}},
            "/api/v1/summary": {"get": {"summary": "Totals + per-protocol breakdown"}},
            "/api/v1/timeseries": {"get": {"summary": "Bytes/packets/flows per bucket", "parameters": [
                {"name": "bucket", "in": "query", "description": "1m|5m|15m|1h|6h|1d"},
                {"name": "granularity", "in": "query", "description": "minute|hourly"},
            ]}},
            "/api/v1/top": {"get": {"summary": "Top-N by dimension", "parameters": [
                {"name": "by", "in": "query", "description": "src_ip|dst_ip|src_ipver|dst_ipver|src_asn|dst_asn|src_org|dst_org|src_port|dst_port|proto|exporter|src_country|dst_country|label"},
                {"name": "granularity", "in": "query", "description": "minute|hourly"},
                {"name": "limit", "in": "query"},
            ]}},
            "/api/v1/conversations": {"get": {"summary": "Top conversations"}},
            "/api/v1/anomalies": {"get": {"summary": "Statistical anomalies (z-score)", "parameters": [
                {"name": "by", "in": "query"}, {"name": "sigma", "in": "query"},
                {"name": "granularity", "in": "query"},
            ]}},
            "/api/v1/label_stats": {"get": {"summary": "Traffic per label"}},
            "/api/v1/exporters": {"get": {"summary": "Exporter ingest stats"}},
            "/api/v1/labels": {"get": {"summary": "Configured label rules"}},
            "/api/v1/enrichers": {"get": {"summary": "Enricher status"}},
            "/api/v1/lookup": {"get": {"summary": "Manual enrichment lookup", "parameters": [
                {"name": "ip", "in": "query"},
            ]}},
            "/api/v1/config": {"get": {"summary": "Effective config (redacted)"}},
            "/metrics": {"get": {"summary": "Prometheus metrics"}},
        }
    })
}

async fn lookup(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let s = q.get("ip").ok_or_else(|| err("missing ip"))?;
    let ip: IpAddr = s.parse().map_err(|_| err("bad ip"))?;
    Ok(Json(st.http_enrich.lookup_ip(ip)))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

const UI_HTML: &str = include_str!("../ui/index.html");

async fn index() -> Html<&'static str> {
    Html(UI_HTML)
}

/// Optional HTTP basic auth ("user:pass" in config).
async fn auth_mw(
    State(st): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(expected) = &st.config.server.auth else {
        return Ok(next.run(req).await);
    };
    // Exempt health + metrics for scrapers/monitors.
    let path = req.uri().path();
    if path == "/api/v1/health" || path == "/metrics" {
        return Ok(next.run(req).await);
    }
    let ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b64| decode_b64(b64).ok())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned() == *expected)
        .unwrap_or(false);
    if ok {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn decode_b64(s: &str) -> Result<Vec<u8>, ()> {
    const T: &[u8; 256] = &{
        let mut t = [255u8; 256];
        let mut i = 0u8;
        while i < 26 {
            t[b'A' as usize + i as usize] = i;
            t[b'a' as usize + i as usize] = 26 + i;
            i += 1;
        }
        let mut j = 0u8;
        while j < 10 {
            t[b'0' as usize + j as usize] = 52 + j;
            j += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc = 0u32;
    let mut nbits = 0u32;
    for &b in bytes {
        if b == b'=' || b == b'\n' || b == b'\r' {
            continue;
        }
        let v = T[b as usize];
        if v == 255 {
            return Err(());
        }
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Ok(out)
}

pub fn router(st: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/status", get(status))
        .route("/api/v1/flows", get(flows))
        .route("/api/v1/summary", get(summary))
        .route("/api/v1/timeseries", get(timeseries))
        .route("/api/v1/top", get(top))
        .route("/api/v1/conversations", get(conversations))
        .route("/api/v1/exporters", get(exporters))
        .route("/api/v1/labels", get(labels))
        .route("/api/v1/enrichers", get(enrichers))
        .route("/api/v1/lookup", get(lookup))
        .route("/api/v1/anomalies", get(anomalies))
        .route("/api/v1/label_stats", get(label_stats))
        .route("/api/v1/config", get(config_view))
        .route("/api/v1/openapi.json", get(openapi))
        .route("/metrics", get(metrics_handler));

    let cors_enabled = st.config.server.cors;
    let app = Router::new()
        .merge(api)
        .route("/", get(index))
        .with_state(st.clone())
        .layer(middleware::from_fn_with_state(st, auth_mw));

    if cors_enabled {
        app.layer(tower_http::cors::CorsLayer::permissive())
    } else {
        app
    }
}
