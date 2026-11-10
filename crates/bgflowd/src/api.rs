//! HTTP API (axum) + embedded UI serving.

use crate::admin::AdminShared;
use crate::auth::AuthState;
use crate::config::Config;
use crate::enrich::{HttpEnrichers, MmdbGeo};
use crate::metrics::Metrics;
use crate::query::{self, Ctx, FlowQuery, RollupFilter, RollupSet};
use crate::writer::StatusSnapshot;
use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bgflow_types::ip_to_u128;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

pub struct AppState {
    pub ctx: Ctx,
    pub status: Arc<RwLock<StatusSnapshot>>,
    pub metrics: Arc<Metrics>,
    pub http_enrich: Arc<HttpEnrichers>,
    pub geo: Arc<MmdbGeo>,
    pub config: Arc<Config>,
    pub auth: Arc<AuthState>,
    pub admin: Arc<AdminShared>,
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
        // Comma-separated allowlist: IPs or configured exporter names.
        let names = ctx.exporter_names.read().unwrap();
        for part in s.split(',') {
            match names.resolve(part) {
                Some(u) => f.exporters.push(u),
                None => return Err(err(format!("bad exporter '{}'", part.trim()))),
            }
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
    let system = crate::sys::sample(&st.config.storage.data_dir);
    Json(serde_json::json!({
        "version": env!("BGFLOW_VERSION_DISPLAY"),
        "git": env!("BGFLOW_GIT_DESCRIBE"),
        "system": system,
        "status": s,
        "orgs": st.ctx.orgs.len(),
        "rules": st.ctx.rules.len(),
        "inputs": st.config.inputs.iter().map(|i| i.listen.to_string()).collect::<Vec<_>>(),
        "auth": {
            "enabled": !st.auth.is_open(),
            "users": st.auth.user_count(),
        },
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
        let names = st.ctx.exporter_names.read().unwrap();
        for part in s.split(',') {
            match names.resolve(part) {
                Some(u) => fq.exporters.push(u),
                None => return Err(err(format!("bad exporter '{}'", part.trim()))),
            }
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

fn agg_add(a: &mut Agg, b: &Agg) {
    a.bytes += b.bytes;
    a.packets += b.packets;
    a.flows += b.flows;
}

/// Reduce key-sharded rollup maps to the global top-`limit` by
/// (bytes, flows). Keys are partitioned across shards with complete
/// aggregates, so every global top-`limit` member is within its own
/// shard's local top-`limit` — collecting per-shard candidates and
/// re-sorting yields the exact global top-`limit` without materializing
/// or sorting the full key space.
fn shard_top<K>(
    shards: Vec<query::ShardMap<K, Agg>>,
    limit: usize,
) -> Vec<(K, Agg)>
where
    K: Send,
{
    if limit == 0 {
        return Vec::new();
    }
    let cmp = |a: &(K, Agg), b: &(K, Agg)| {
        b.1.bytes.cmp(&a.1.bytes).then(b.1.flows.cmp(&a.1.flows))
    };
    // Per-shard select+truncate+sort in parallel — each shard's candidate
    // list is independent.
    let per_shard: Vec<Vec<(K, Agg)>> = std::thread::scope(|s| {
        let handles: Vec<_> = shards
            .into_iter()
            .map(|map| {
                s.spawn(move || {
                    let mut v: Vec<(K, Agg)> = map.into_iter().collect();
                    if v.len() > limit {
                        v.select_nth_unstable_by(limit - 1, cmp);
                        v.truncate(limit);
                    }
                    v.sort_by(cmp);
                    v
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut cand: Vec<(K, Agg)> = per_shard.into_iter().flatten().collect();
    cand.sort_by(cmp);
    cand.truncate(limit);
    cand
}

/// No-op bounded accumulator for `rollup_scan_sharded` callers that only
/// need the key/value maps.
fn unit_init() -> () {}
fn unit_add(_: &mut (), _: &query::RollupRow) {}
fn unit_merge(_: &mut (), _: ()) {}

/// Merge one worker's `HashMap<K, Agg>` partial into the combined map.
fn merge_agg_map<K>(a: &mut HashMap<K, Agg>, b: HashMap<K, Agg>)
where
    K: Eq + std::hash::Hash + Clone,
{
    for (k, v) in b {
        agg_add(a.entry(k).or_default(), &v);
    }
}

/// Overview endpoint bounded accumulator — totals + protocol +
/// timeseries. The top-dim maps are NOT here: they go through the
/// key-sharded maps so per-worker memory stays flat regardless of IP
/// cardinality. Merged from per-worker partials.
#[derive(Default)]
struct OvAcc {
    total: Agg,
    by_proto: HashMap<u8, Agg>,
    series: HashMap<u64, Agg>,
}

impl OvAcc {
    fn merge(&mut self, o: Self) {
        agg_add(&mut self.total, &o.total);
        merge_agg_map(&mut self.by_proto, o.by_proto);
        merge_agg_map(&mut self.series, o.series);
    }
}

async fn summary(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let set = rollup_set(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let needed = query::rollup_needed(&f, &["proto"]);
    let (total, by_proto) = query::rollup_scan_par(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        || (Agg::default(), HashMap::<u8, Agg>::new()),
        |(total, by_proto), r| {
            if !f.matches(r) {
                return;
            }
            total.bytes += r.bytes();
            total.packets += r.packets();
            total.flows += r.flows();
            let p = by_proto.entry(r.protocol()).or_default();
            p.bytes += r.bytes();
            p.packets += r.packets();
            p.flows += r.flows();
        },
        |(t, p), (t2, p2)| {
            agg_add(t, &t2);
            merge_agg_map(p, p2);
        },
    )
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

/// Combined dashboard payload: totals + protocol breakdown + timeseries +
/// top-N for the overview dims — all from ONE rollup scan (vs ~7 separate
/// scans when the UI calls each endpoint individually).
async fn overview(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let set = rollup_set(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let size = bucket_ms(q.get("bucket").map(|s| s.as_str()));
    let limit: usize = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
        .min(100);
    const TOP_DIMS_OV: [&str; 5] = ["src_ip", "dst_ip", "src_asn", "dst_asn", "dst_port"];
    let needed = query::rollup_needed(&f, &["proto", "src_ip", "dst_ip", "src_asn", "dst_asn", "dst_port"]);

    // One sharded scan: bounded state (totals/proto/series) accumulates
    // per worker; each top dim emits (dim_idx, key) pairs routed into
    // disjoint shard maps — exact top-N at one-map memory cost even for
    // the high-cardinality IP dims.
    let (shards, acc) = query::rollup_scan_sharded(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        &f,
        // 4 shards per worker keeps mutex convoying rare on big maps.
        bgflow_store::scan_threads() * 4,
        |r, out| {
            for (i, d) in TOP_DIMS_OV.iter().enumerate() {
                out.push((
                    (i as u8, query::dim_key(d, r)),
                    Agg {
                        bytes: r.bytes(),
                        packets: r.packets(),
                        flows: r.flows(),
                    },
                ));
            }
        },
        |a: &mut Agg, b: Agg| agg_add(a, &b),
        || OvAcc::default(),
        |acc: &mut OvAcc, r: &query::RollupRow| {
            acc.total.bytes += r.bytes();
            acc.total.packets += r.packets();
            acc.total.flows += r.flows();
            let p = acc.by_proto.entry(r.protocol()).or_default();
            p.bytes += r.bytes();
            p.packets += r.packets();
            p.flows += r.flows();
            let b = (r.bucket_ms() / size) * size;
            let s = acc.series.entry(b).or_default();
            s.bytes += r.bytes();
            s.packets += r.packets();
            s.flows += r.flows();
        },
        |a: &mut OvAcc, b: OvAcc| a.merge(b),
    )
    .map_err(|e| err(e.to_string()))?;
    let OvAcc {
        total,
        by_proto,
        series,
    } = acc;

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

    let mut ts_rows: Vec<_> = series
        .into_iter()
        .map(|(t, a)| {
            serde_json::json!({
                "t": t / 1000, "bucket_ms": t,
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    ts_rows.sort_by_key(|v| v["t"].as_u64().unwrap_or(0));

    // Partition shard entries by dimension index, then exact top-N per
    // dim via select_nth (no full sort of the IP-sized key spaces).
    let mut dim_rows: Vec<Vec<(u128, Agg)>> =
        (0..TOP_DIMS_OV.len()).map(|_| Vec::new()).collect();
    for map in shards {
        for ((di, k), a) in map {
            dim_rows[di as usize].push((k, a));
        }
    }
    let cmp = |a: &(u128, Agg), b: &(u128, Agg)| {
        b.1.bytes.cmp(&a.1.bytes).then(b.1.flows.cmp(&a.1.flows))
    };
    let mut top_out = serde_json::Map::new();
    for (i, &d) in TOP_DIMS_OV.iter().enumerate() {
        let mut rows = std::mem::take(&mut dim_rows[i]);
        if limit > 0 {
            if rows.len() > limit {
                rows.select_nth_unstable_by(limit - 1, cmp);
            }
            rows.truncate(limit);
            rows.sort_by(cmp);
        } else {
            rows.clear();
        }
        top_out.insert(
            d.to_string(),
            serde_json::json!(rows
                .into_iter()
                .map(|(k, a)| serde_json::json!({
                    "key": query::format_key(&st.ctx, d, k),
                    "key_raw": k.to_string(),
                    "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
                }))
                .collect::<Vec<_>>()),
        );
    }

    Ok(Json(serde_json::json!({
        "from": from, "to": to,
        "bytes": total.bytes, "packets": total.packets, "flows": total.flows,
        "by_protocol": protos,
        "bucket_ms": size,
        "series": ts_rows,
        "top": top_out,
        "set": match set { RollupSet::Minute => "minute", RollupSet::Hourly => "hourly" },
    })))
}

/// Pair aggregation for the flow-map view: groups rollups by (src_dim, dst_dim).
/// IP/exporter dims are excluded — pair cardinality would explode.
const MATRIX_DIMS: &[&str] = &[
    "src_ipver", "dst_ipver", "src_asn", "dst_asn", "src_org", "dst_org",
    "src_country", "dst_country", "proto", "label", "src_port", "dst_port",
];

async fn matrix(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let set = rollup_set(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    // NB: params are src_dim/dst_dim — bare `src`/`dst` are flow-filter aliases.
    let sd = q.get("src_dim").map(|s| s.as_str()).unwrap_or("src_country");
    let dd = q.get("dst_dim").map(|s| s.as_str()).unwrap_or("dst_country");
    if !MATRIX_DIMS.contains(&sd) || !MATRIX_DIMS.contains(&dd) {
        return Err(err(format!(
            "bad matrix dim; src/dst must be one of {}",
            MATRIX_DIMS.join(", ")
        )));
    }
    let limit: usize = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
        .min(1000);
    let needed = query::rollup_needed(&f, &[sd, dd]);
    // Pair map can be large — key-sharded parallel aggregation keeps
    // memory at one global map's size while decoding in parallel.
    let (shards, _) = query::rollup_scan_sharded(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        &f,
        // 4 shards per worker keeps mutex convoying rare on big maps.
        bgflow_store::scan_threads() * 4,
        |r, out| {
            out.push((
                (query::dim_key(sd, r), query::dim_key(dd, r)),
                Agg {
                    bytes: r.bytes(),
                    packets: r.packets(),
                    flows: r.flows(),
                },
            ));
        },
        |a: &mut Agg, b: Agg| agg_add(a, &b),
        unit_init,
        unit_add,
        unit_merge,
    )
    .map_err(|e| err(e.to_string()))?;

    let rows = shard_top(shards, limit);
    let items: Vec<_> = rows
        .into_iter()
        .map(|((s, d), a)| {
            serde_json::json!({
                "src": query::format_key(&st.ctx, sd, s),
                "src_raw": s.to_string(),
                "dst": query::format_key(&st.ctx, dd, d),
                "dst_raw": d.to_string(),
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "src_dim": sd, "dst_dim": dd,
        "set": match set { RollupSet::Minute => "minute", RollupSet::Hourly => "hourly" },
        "items": items,
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
    let buckets: HashMap<u64, Agg> = query::rollup_scan_par::<HashMap<u64, Agg>>(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        Default::default,
        |buckets, r| {
            if !f.matches(r) {
                return;
            }
            let b = (r.bucket_ms() / size) * size;
            let a = buckets.entry(b).or_default();
            a.bytes += r.bytes();
            a.packets += r.packets();
            a.flows += r.flows();
        },
        |a, b| merge_agg_map(a, b),
    )
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

    // Full-cardinality dim map (ports/IPs can be huge) — key-sharded
    // parallel aggregation: memory stays at one map's size.
    let needed = query::rollup_needed(&f, &[by]);
    let (shards, _) = query::rollup_scan_sharded(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        &f,
        // 4 shards per worker keeps mutex convoying rare on big maps.
        bgflow_store::scan_threads() * 4,
        |r, out| {
            out.push((
                query::dim_key(by, r),
                Agg {
                    bytes: r.bytes(),
                    packets: r.packets(),
                    flows: r.flows(),
                },
            ));
        },
        |a: &mut Agg, b: Agg| agg_add(a, &b),
        unit_init,
        unit_add,
        unit_merge,
    )
    .map_err(|e| err(e.to_string()))?;

    let rows = shard_top(shards, limit);
    let out: Vec<_> = rows
        .into_iter()
        .map(|(k, a)| {
            serde_json::json!({
                "key": query::format_key(&st.ctx, by, k),
                // u128 doesn't fit JSON numbers — emit as string. UI only
                // consumes it for small dims (org id, ipver), which parse fine.
                "key_raw": k.to_string(),
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
    // Conversation keys are near-unique per flow — millions of entries.
    // Key-sharded parallel aggregation: each key lives in exactly one
    // shard, so memory equals a single map (not one per worker).
    let needed = query::rollup_needed(&f, &["src_ip", "dst_ip", "src_port", "dst_port", "proto"]);
    let (shards, _) = query::rollup_scan_sharded(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        &f,
        // 4 shards per worker keeps mutex convoying rare on big maps.
        bgflow_store::scan_threads() * 4,
        |r, out| {
            out.push((
                (
                    r.src_ip(),
                    r.dst_ip(),
                    r.src_port(),
                    r.dst_port(),
                    r.protocol(),
                ),
                Agg {
                    bytes: r.bytes(),
                    packets: r.packets(),
                    flows: r.flows(),
                },
            ));
        },
        |a: &mut Agg, b: Agg| agg_add(a, &b),
        unit_init,
        unit_add,
        unit_merge,
    )
    .map_err(|e| err(e.to_string()))?;

    let rows = shard_top(shards, limit);
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
    let names = st.ctx.exporter_names.read().unwrap();
    let items: Vec<_> = map
        .iter()
        .map(|(ip, e)| {
            let u = ip_to_u128(ip);
            serde_json::json!({
                "ip": ip.to_string(),
                "name": names.name_of(u),
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

    // key -> bucket -> bytes. Flattened to (key, bucket) pairs so the
    // scan can run key-sharded in parallel; regrouped below. Each pair's
    // complete aggregate lives in exactly one shard.
    let (shards, _) = query::rollup_scan_sharded(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        &f,
        // 4 shards per worker keeps mutex convoying rare on big maps.
        bgflow_store::scan_threads() * 4,
        |r, out| {
            out.push((
                (query::dim_key(by, r), r.bucket_ms()),
                Agg {
                    bytes: r.bytes(),
                    packets: r.packets(),
                    flows: r.flows(),
                },
            ));
        },
        |a: &mut Agg, b: Agg| agg_add(a, &b),
        unit_init,
        unit_add,
        unit_merge,
    )
    .map_err(|e| err(e.to_string()))?;

    let mut series: HashMap<u128, HashMap<u64, u64>> = HashMap::new();
    for map in shards {
        for ((k, b), a) in map {
            *series.entry(k).or_default().entry(b).or_insert(0) += a.bytes;
        }
    }

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
                "key_raw": a.key.to_string(),
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
    // Label count is bounded by the ruleset — small state, parallel-safe.
    let map: HashMap<u128, Agg> = query::rollup_scan_par::<HashMap<u128, Agg>>(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        Default::default,
        |map, r| {
            if !f.matches(r) {
                return;
            }
            let k = r.label_id() as u128;
            let a = map.entry(k).or_default();
            a.bytes += r.bytes();
            a.packets += r.packets();
            a.flows += r.flows();
        },
        |a, b| merge_agg_map(a, b),
    )
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
        if srv.contains_key("session_secret") {
            srv.insert("session_secret".into(), serde_json::json!("***"));
        }
    }
    // [[users]] password hashes must never leave the process.
    if let Some(users) = v.get_mut("users").and_then(|u| u.as_array_mut()) {
        for u in users.iter_mut() {
            if let Some(o) = u.as_object_mut() {
                if o.contains_key("password_hash") {
                    o.insert("password_hash".into(), serde_json::json!("***"));
                }
            }
        }
    }
    // Alert webhook URLs can embed tokens.
    if let Some(url) = v
        .get_mut("alerts")
        .and_then(|a| a.get_mut("webhook_url"))
    {
        if !url.is_null() {
            *url = serde_json::json!("***");
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
            "/api/v1/overview": {"get": {"summary": "Combined dashboard payload (one scan): totals, by_protocol, series, top dims"}},
            "/api/v1/matrix": {"get": {"summary": "Src→dst pair aggregation for flow maps", "parameters": [
                {"name": "src_dim", "in": "query", "description": "src dim (asn/org/country/ipver/proto/port/label)"},
                {"name": "dst_dim", "in": "query", "description": "dst dim"},
                {"name": "limit", "in": "query", "description": "max pairs (default 100)"},
            ]}},
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
            "/api/v1/config": {"get": {"summary": "Effective config (redacted, admin only)"}},
            "/api/v1/auth/login": {"post": {"summary": "Login → session cookie", "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"username": {"type": "string"}, "password": {"type": "string"}}}}}}}},
            "/api/v1/auth/logout": {"post": {"summary": "Logout (clears session cookie)"}},
            "/api/v1/auth/me": {"get": {"summary": "Current identity or 401"}},
            "/api/v1/admin/reload": {"post": {"summary": "Hot-reload rules/enrichers/users/alerts (admin)"}},
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
    let mut v = st.http_enrich.lookup_ip(ip);
    if let Some(det) = st.geo.lookup_detail(ip) {
        if let Some(arr) = v.get_mut("results").and_then(|r| r.as_array_mut()) {
            arr.insert(
                0,
                serde_json::json!({"backend": "mmdb", "type": "mmdb", "result": det}),
            );
        }
    }
    Ok(Json(v))
}

// ---------------------------------------------------------------------------
// Auth + admin endpoints
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

/// POST /api/v1/auth/login — JSON {username, password} → session cookie.
async fn auth_login(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginBody>,
) -> Response {
    let ip = peer.ip();
    match st.auth.login(ip, &body.username, &body.password) {
        Some(role) => {
            let user = body.username.clone();
            let token = st.auth.issue_token(&user, role);
            let cookie = format!(
                "bgflow_session={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
                token,
                st.auth.session_ttl()
            ) + if st.auth.secure_cookie { "; Secure" } else { "" };
            (
                StatusCode::OK,
                [
                    (header::SET_COOKIE, cookie),
                    (header::CONTENT_TYPE, "application/json".to_string()),
                ],
                Json(serde_json::json!({"ok": true, "user": user, "role": role.as_str()})),
            )
                .into_response()
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid credentials"})),
        )
            .into_response(),
    }
}

/// POST /api/v1/auth/logout — expire the session cookie.
async fn auth_logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    // Revoke the token server-side — stateless tokens stay valid until
    // expiry otherwise, so "logout" would be cosmetic for a stolen cookie.
    if let Some(cookie) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie.split(';') {
            if let Some(tok) = part.trim().strip_prefix("bgflow_session=") {
                st.auth.revoke_token(tok);
            }
        }
    }
    let cookie = format!(
        "bgflow_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        if st.auth.secure_cookie { "; Secure" } else { "" }
    );
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({"ok": true})),
    )
        .into_response()
}

/// GET /api/v1/auth/me — current identity. Exempt from middleware so the UI
/// can probe auth state: {"auth":true,...} when logged in,
/// {"auth":false,"open":true} when no auth is configured at all.
async fn auth_me(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if st.auth.is_open() {
        return Json(serde_json::json!({"auth": false, "open": true})).into_response();
    }
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok());
    let authz = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    match st.auth.identity_from_headers(cookie, authz) {
        Some((user, role)) => Json(serde_json::json!({
            "user": user, "role": role.as_str(), "auth": true,
        }))
        .into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"auth": false})),
        )
            .into_response(),
    }
}

/// POST /api/v1/admin/reload — hot-reload rules/enrichers/users/alerts.
/// Admin role only (enforced by middleware path check).
async fn admin_reload(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rep = st.admin.reload();
    Json(serde_json::to_value(&rep).unwrap_or(serde_json::json!({})))
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// Paths reachable without authentication: health probes, metrics
/// scrapers, the UI shell (it renders its own login form), and the auth
/// endpoints themselves.
fn auth_exempt(path: &str) -> bool {
    matches!(
        path,
        "/" | "/api/v1/health" | "/metrics" | "/api/v1/auth/login" | "/api/v1/auth/logout"
            | "/api/v1/auth/me"
    )
}

async fn auth_mw(
    State(st): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    if auth_exempt(&path) {
        return next.run(req).await;
    }
    // Open mode: no users and no legacy auth configured.
    if st.auth.is_open() {
        return next.run(req).await;
    }

    let cookie = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let authz = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let ident = st.auth.identity_from_headers(cookie.as_deref(), authz.as_deref());

    let Some((_user, role)) = ident else {
        // No WWW-Authenticate header: advertising Basic here makes browsers
        // pop their native credential dialog on top of the SPA login form.
        // curl -u and friends send credentials preemptively regardless.
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "authentication required"})),
        )
            .into_response();
    };

    // Role checks: viewers are read-only; admin paths need admin.
    let method = req.method().as_str().to_string();
    if !AuthState::method_allowed(role, &method) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "viewer role is read-only"})),
        )
            .into_response();
    }
    if !role.is_admin() && AuthState::requires_admin(&path) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin role required"})),
        )
            .into_response();
    }

    // CSRF hardening: mutating requests carrying a session cookie must come
    // from our own origin (SameSite=Strict already blocks cross-site sends;
    // this catches same-site subdomain tricks and non-browser clients that
    // replay a stolen cookie).
    if method != "GET" && method != "HEAD" && method != "OPTIONS" {
        if let Some(origin) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            let host = req
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let host_only = host.split(':').next().unwrap_or(host);
            let origin_host = origin
                .trim_end_matches('/')
                .split("://")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("");
            if !origin_host.is_empty() && !origin_host.eq_ignore_ascii_case(host_only) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "cross-origin request rejected"})),
                )
                    .into_response();
            }
        }
    }

    next.run(req).await
}

/// Baseline security headers on every response.
async fn security_headers(req: axum::extract::Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    h.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    h.insert(
        header::REFERRER_POLICY,
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    // The UI is a single embedded file with inline script/style, so CSP
    // allows 'unsafe-inline' — its real value is blocking external loads.
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    res
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

const UI_HTML: &str = include_str!("../ui/index.html");

async fn index() -> Html<&'static str> {
    Html(UI_HTML)
}

pub fn router(st: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/status", get(status))
        // Expensive scan endpoints get a stale-while-revalidate cache:
        // the UI polls these on an interval, so serving the previous
        // response while a background recompute runs keeps the dashboard
        // instant instead of pinning a core for seconds per refresh.
        .merge(
            Router::new()
                .route("/api/v1/flows", get(flows))
                .route("/api/v1/summary", get(summary))
                .route("/api/v1/overview", get(overview))
                .route("/api/v1/matrix", get(matrix))
                .route("/api/v1/timeseries", get(timeseries))
                .route("/api/v1/top", get(top))
                .route("/api/v1/conversations", get(conversations))
                .route("/api/v1/anomalies", get(anomalies))
                .route("/api/v1/label_stats", get(label_stats))
                .layer(crate::qcache::SwrCacheLayer::new()),
        )
        .route("/api/v1/exporters", get(exporters))
        .route("/api/v1/labels", get(labels))
        .route("/api/v1/enrichers", get(enrichers))
        .route("/api/v1/lookup", get(lookup))
        .route("/api/v1/config", get(config_view))
        .route("/api/v1/openapi.json", get(openapi))
        .route("/api/v1/auth/login", post(auth_login))
        .route("/api/v1/auth/logout", post(auth_logout))
        .route("/api/v1/auth/me", get(auth_me))
        .route("/api/v1/admin/reload", post(admin_reload))
        .route("/metrics", get(metrics_handler));

    let cors_enabled = st.config.server.cors;
    let app = Router::new()
        .merge(api)
        .route("/", get(index))
        .with_state(st.clone())
        // Order matters: last .layer() is outermost. security_headers wraps
        // auth_mw so even 401/403 responses carry the baseline headers; CORS
        // is outermost so preflights bypass auth entirely.
        .layer(middleware::from_fn_with_state(st.clone(), auth_mw))
        .layer(middleware::from_fn(security_headers));

    if cors_enabled {
        if st.config.server.cors_origins.is_empty() {
            tracing::warn!("server.cors=true with no cors_origins — wide-open CORS (dev only!)");
            app.layer(tower_http::cors::CorsLayer::permissive())
        } else {
            let origins: Vec<_> = st
                .config
                .server
                .cors_origins
                .iter()
                .filter_map(|o| o.parse().ok())
                .collect();
            app.layer(
                tower_http::cors::CorsLayer::new()
                    .allow_origin(origins)
                    .allow_methods([
                        Method::GET,
                        Method::POST,
                        Method::OPTIONS,
                        Method::HEAD,
                    ])
                    .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
                    .allow_credentials(true),
            )
        }
    } else {
        app
    }
}
