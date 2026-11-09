//! HTTP API (axum) + embedded UI serving.

use crate::config::Config;
use crate::enrich::HttpEnrichers;
use crate::metrics::Metrics;
use crate::query::{self, Ctx, FlowQuery, RollupFilter};
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
use std::sync::{Arc, RwLock};

pub struct AppState {
    pub ctx: Ctx,
    pub status: Arc<RwLock<StatusSnapshot>>,
    pub metrics: Arc<Metrics>,
    pub http_enrich: Arc<HttpEnrichers>,
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

fn rollup_filter(q: &Q) -> Result<RollupFilter, (StatusCode, Json<serde_json::Value>)> {
    let mut f = RollupFilter::default();
    if let Some(s) = q.get("exporter") {
        let ip: IpAddr = s.parse().map_err(|_| err("bad exporter"))?;
        f.exporter = Some(ip_to_u128(&ip));
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
    if let Some(s) = q.get("src_ip") {
        let (base, _) = query::parse_ip_filter(s).ok_or_else(|| err("bad src_ip"))?;
        f.src_ip = Some(base);
    }
    if let Some(s) = q.get("dst_ip") {
        let (base, _) = query::parse_ip_filter(s).ok_or_else(|| err("bad dst_ip"))?;
        f.dst_ip = Some(base);
    }
    if let Some(s) = q.get("src_port") {
        f.src_port = Some(s.parse().map_err(|_| err("bad src_port"))?);
    }
    if let Some(s) = q.get("dst_port") {
        f.dst_port = Some(s.parse().map_err(|_| err("bad dst_port"))?);
    }
    if let Some(s) = q.get("src_country") {
        f.src_country = Some(bgflow_types::country_pack(s));
    }
    if let Some(s) = q.get("dst_country") {
        f.dst_country = Some(bgflow_types::country_pack(s));
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

async fn health() -> &'static str {
    "ok"
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
        newest_first: q.get("order").map(|s| s != "asc").unwrap_or(true),
        ..Default::default()
    };
    if let Some(s) = q.get("src") {
        let (base, bits) = query::parse_ip_filter(s).ok_or_else(|| err("bad src"))?;
        // Prefix filters on raw flows: exact match only for now unless /0.
        if bits == 0 {
            // match-all: leave unset
        } else {
            fq.src = Some(base);
        }
    }
    if let Some(s) = q.get("dst") {
        let (base, bits) = query::parse_ip_filter(s).ok_or_else(|| err("bad dst"))?;
        if bits != 0 {
            fq.dst = Some(base);
        }
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
        let ip: IpAddr = s.parse().map_err(|_| err("bad exporter"))?;
        fq.exporter = Some(ip_to_u128(&ip));
    }
    if let Some(s) = q.get("src_asn") {
        fq.src_asn = Some(s.parse().map_err(|_| err("bad src_asn"))?);
    }
    if let Some(s) = q.get("dst_asn") {
        fq.dst_asn = Some(s.parse().map_err(|_| err("bad dst_asn"))?);
    }
    if let Some(s) = q.get("label") {
        // label name or numeric id
        if let Ok(id) = s.parse::<u32>() {
            fq.label = Some(id);
        } else {
            let id = st
                .ctx
                .label_names
                .iter()
                .find(|(_, n)| n.eq_ignore_ascii_case(s))
                .map(|(id, _)| *id);
            fq.label = id;
        }
    }

    let recs = query::flows(&st.ctx, &fq).map_err(|e| err(e.to_string()))?;
    let out: Vec<_> = recs.iter().map(|f| query::flow_json(&st.ctx, f)).collect();
    Ok(Json(serde_json::json!({"count": out.len(), "flows": out})))
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
    let f = rollup_filter(&q)?;
    let mut total = Agg::default();
    let mut by_proto: HashMap<u8, Agg> = HashMap::new();
    query::rollup_each(&st.ctx, from, to, |r| f.matches(r), |r| {
        total.bytes += r.bytes;
        total.packets += r.packets;
        total.flows += r.flows;
        let p = by_proto.entry(r.protocol).or_default();
        p.bytes += r.bytes;
        p.packets += r.packets;
        p.flows += r.flows;
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
    let f = rollup_filter(&q)?;
    let size = bucket_ms(q.get("bucket").map(|s| s.as_str()));
    let mut buckets: HashMap<u64, Agg> = HashMap::new();
    query::rollup_each(&st.ctx, from, to, |r| f.matches(r), |r| {
        let b = (r.bucket_ms / size) * size;
        let a = buckets.entry(b).or_default();
        a.bytes += r.bytes;
        a.packets += r.packets;
        a.flows += r.flows;
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
    "src_ip", "dst_ip", "src_asn", "dst_asn", "src_port", "dst_port", "proto",
    "exporter", "src_country", "dst_country",
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
    let f = rollup_filter(&q)?;
    let limit: usize = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(10).min(1000);

    let mut map: HashMap<u128, Agg> = HashMap::new();
    query::rollup_each(&st.ctx, from, to, |r| f.matches(r), |r| {
        let k = query::dim_key(by, &r);
        let a = map.entry(k).or_default();
        a.bytes += r.bytes;
        a.packets += r.packets;
        a.flows += r.flows;
    })
    .map_err(|e| err(e.to_string()))?;

    let mut rows: Vec<(u128, Agg)> = map.into_iter().collect();
    rows.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then(b.1.flows.cmp(&a.1.flows)));
    rows.truncate(limit);
    let out: Vec<_> = rows
        .into_iter()
        .map(|(k, a)| {
            serde_json::json!({
                "key": query::format_key(by, k),
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({"by": by, "items": out})))
}

async fn conversations(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let f = rollup_filter(&q)?;
    let limit: usize = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(20).min(500);
    type ConvKey = (u128, u128, u16, u16, u8);
    let mut map: HashMap<ConvKey, Agg> = HashMap::new();
    query::rollup_each(&st.ctx, from, to, |r| f.matches(r), |r| {
        let k = (r.src_ip, r.dst_ip, r.src_port, r.dst_port, r.protocol);
        let a = map.entry(k).or_default();
        a.bytes += r.bytes;
        a.packets += r.packets;
        a.flows += r.flows;
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
