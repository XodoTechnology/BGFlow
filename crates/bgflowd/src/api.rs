//! HTTP API (axum) + embedded UI serving.

use crate::admin::AdminShared;
use crate::auth::AuthState;
use crate::config::Config;
use crate::enrich::{HttpEnrichers, MmdbGeo};
use crate::metrics::Metrics;
use crate::query::{self, Ctx, FlowQuery, RollupFilter, RollupSet};
use crate::writer::StatusSnapshot;
use axum::{
    extract::{ConnectInfo, Path, Query, RawQuery, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{sse::Sse, Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bgflow_store::Record;
use bgflow_types::{country_str, ip_to_u128};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

mod adminapi;
mod agg;
mod flows;
mod meta;
mod system;

// hot.rs aggregates dashboard stats with the same shapes the API emits.
pub(crate) use agg::{Agg, SeriesPt};

pub struct AppState {
    pub ctx: Ctx,
    pub status: Arc<RwLock<StatusSnapshot>>,
    pub metrics: Arc<Metrics>,
    pub http_enrich: Arc<HttpEnrichers>,
    pub geo: Arc<MmdbGeo>,
    /// Live effective config — swapped by AdminShared::reload so reads
    /// always reflect the last successfully loaded config.
    pub config: Arc<RwLock<Config>>,
    pub auth: Arc<AuthState>,
    pub admin: Arc<AdminShared>,
    pub exporter_policy: Arc<crate::exporter_policy::ExporterPolicy>,
    /// SNMP-learned interface/VLAN names + device info per exporter.
    pub snmp: crate::snmp::SnmpStore,
    /// AS registry lookups (BGPView), asn → (fetched_at, payload).
    pub asn_cache: Mutex<HashMap<u32, (Instant, serde_json::Value)>>,
    /// Single-slot TTL cache for /overview — the dashboard polls every
    /// ~15s while a long-range scan can take longer; without coalescing,
    /// polls overlap into back-to-back full scans. Keyed by the raw
    /// query string; entries older than OV_CACHE_TTL recompute.
    pub ov_cache: Mutex<Option<(String, Instant, serde_json::Value)>>,
    /// Incremental per-bucket aggregates — serves unfiltered in-window
    /// dashboard queries without touching segment files.
    pub hot: Arc<RwLock<crate::hot::HotStats>>,
    /// Alert suppression state + webhook delivery stats.
    pub alert_rt: Arc<crate::alerts::AlertRuntime>,
    /// Live flow broadcast — source for the /flows/stream SSE tail.
    pub live_tx: tokio::sync::broadcast::Sender<bgflow_types::FlowRecord>,
}

type Q = HashMap<String, String>;

/// Queue for a global segment-scan slot — heavy endpoints wait here
/// rather than running unbounded concurrent scans.
async fn scan_permit(ctx: &query::Ctx) -> tokio::sync::OwnedSemaphorePermit {
    ctx.scan_sem
        .clone()
        .acquire_owned()
        .await
        .expect("scan semaphore closed")
}

fn err(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    let msg = msg.into();
    // Scan timeouts are server-side saturation, not bad input — 503 so
    // clients/backoff treat it as retryable rather than a 4xx.
    let code = if msg.contains("scan timeout") {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_REQUEST
    };
    (code, Json(serde_json::json!({"error": msg})))
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

/// True when an IP filter's prefix is at least as broad as the coarse
/// rollup mask (/24 IPv4, /48 IPv6). Only then can /24·/48-masked hourly
/// rows answer it — narrower prefixes and exact IPs need full-IP minute
/// data or they silently match nothing.
fn ip_filter_coarse_safe(flt: (u128, u128)) -> bool {
    let (_, mask) = flt;
    if mask == 0 {
        return true;
    }
    let tz = mask.trailing_zeros();
    if mask >> 63 != 0 {
        // v6-style mask (u128::MAX << (128-bits)): prefix_len = 128 - tz
        128 - tz <= 48
    } else {
        // v4-style mask (0xFFFFFFFF << (32-bits)): prefix_len = 32 - tz
        32 - tz <= 24
    }
}

/// Dataset choice for aggregate endpoints: past ~2h, minute rollups mean
/// decoding tens of millions of rows and building huge top-dim maps, so
/// promote to the hourly dataset whose IPs are already /24·/48-masked.
/// The UI always sends granularity=minute as its default detail level, so
/// promotion applies even when the param is present — `hourly` is still
/// honored (never demoted). IP filters narrower than the coarse mask
/// block promotion: masked rows can't match them.
fn auto_rollup_set(q: &Q, from: u64, to: u64, f: &RollupFilter) -> RollupSet {
    let set = rollup_set(q);
    let coarse_ok = f.src_ip.map_or(true, ip_filter_coarse_safe)
        && f.dst_ip.map_or(true, ip_filter_coarse_safe);
    if set == RollupSet::Minute && coarse_ok && to.saturating_sub(from) > 7_200_000 {
        RollupSet::Hourly
    } else {
        set
    }
}

/// Hot-tier fast path: serves unfiltered in-window queries from the
/// incremental per-bucket aggregates instead of scanning segments.
/// `set` is the rollup dataset the caller's scan path would read —
/// the hot tier must mirror its bucket granularity or range-edge
/// semantics diverge (whole-bucket overlap differs ~2x between minute
/// and hour buckets on unaligned windows).
/// Returns the merged view plus the effective series bucket width
/// (hour-tier responses floor at 1h like the hourly dataset does).
/// `None` → caller falls back to the segment scan.
fn hot_view(
    st: &AppState,
    f: &RollupFilter,
    q: &Q,
    set: RollupSet,
    from: u64,
    to: u64,
    size: u64,
    strict: bool,
) -> Option<(crate::hot::HotView, u64)> {
    // ?hot=0|off|false forces the segment-scan path — escape hatch for
    // debugging and correctness comparisons.
    if matches!(q.get("hot").map(|s| s.as_str()), Some("0") | Some("off") | Some("false")) {
        return None;
    }
    if !f.is_empty() {
        return None;
    }
    let g = st.hot.read().unwrap();
    // Direction splits are stamped with the local_asns they were built
    // against — a changed set with a pending rebuild means stale
    // in/out/transit, so don't serve.
    let cur = crate::hot::asns_stamp(&st.ctx.local_asns.read().unwrap());
    if g.asns_stamp != cur {
        return None;
    }
    // Serve the tier matching the scan's granularity. `strict` callers
    // (aggregate endpoints whose set already mirrors the span) get no
    // cross-tier fallback — a wider-bucket tier would shift range-edge
    // semantics vs their scan. Non-strict callers (dimension endpoints
    // defaulting to the minute set even for long ranges) may fall back
    // to the hour tier: bounded edge approximation in exchange for
    // skipping a multi-10s scan.
    let prefer_min = set == RollupSet::Minute;
    // Mask IP keys only when the caller explicitly asked for the coarse
    // dataset — auto-promoted requests still get full-IP keys because the
    // hot hour buckets were built from full-IP minute records. This keeps
    // dashboard talkers showing real addresses on long ranges.
    let explicit_coarse = matches!(
        q.get("granularity")
            .or_else(|| q.get("dataset"))
            .map(|s| s.as_str()),
        Some("hourly") | Some("hour") | Some("coarse") | Some("1h")
    );
    let (use_min, mask_ips) = if prefer_min {
        if g.covers(from, true) {
            (true, false)
        } else if !strict && g.covers(from, false) {
            (false, false)
        } else {
            return None;
        }
    } else if g.covers(from, false) {
        (false, explicit_coarse)
    } else {
        return None;
    };
    let mut size = size.max(60_000);
    if !use_min {
        size = size.max(3_600_000);
    }
    Some((g.view(from, to, size, use_min, mask_ips), size))
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
    if let Some(s) = q.get("vlan") {
        f.vlan = Some(s.parse().map_err(|_| err("bad vlan"))?);
    }
    if let Some(s) = q.get("ingress_if") {
        f.ingress_if = Some(s.parse().map_err(|_| err("bad ingress_if"))?);
    }
    if let Some(s) = q.get("egress_if") {
        f.egress_if = Some(s.parse().map_err(|_| err("bad egress_if"))?);
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
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
    let api_key = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let ident = st.auth.identity_from_headers(
        peer.ip(),
        cookie.as_deref(),
        authz.as_deref(),
        api_key.as_deref(),
    );

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

    // Sliding session renewal: cookie-authed GET/HEAD requests past half
    // their TTL get a fresh Set-Cookie, so active users never hit the
    // fixed expiry. Safe methods only — mutating endpoints set their own
    // cookies (login/logout) and shouldn't get a second one appended.
    let mut renew_cookie: Option<String> = None;
    if matches!(req.method().as_str(), "GET" | "HEAD") {
        if let Some(c) = cookie.as_deref() {
            for part in c.split(';') {
                let part = part.trim();
                if let Some(tok) = part.strip_prefix("bgflow_session=") {
                    if let Some((u, r, left)) = st.auth.verify_token(tok) {
                        if left.saturating_mul(2) < st.auth.session_ttl() {
                            let nt = st.auth.issue_token(&u, r);
                            renew_cookie = Some(format!(
                                "bgflow_session={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
                                nt,
                                st.auth.session_ttl(),
                                if st.auth.secure_cookie { "; Secure" } else { "" }
                            ));
                        }
                    }
                    break;
                }
            }
        }
    }

    let mut resp = next.run(req).await;
    if let Some(c) = renew_cookie {
        if let Ok(v) = header::HeaderValue::from_str(&c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

/// Baseline security headers on every response.
/// Per-path request count + summed handler time + 5xx tally, rendered
/// into /metrics. Outermost app layer so auth rejections are counted too.
async fn metrics_mw(
    State(st): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let t = Instant::now();
    let resp = next.run(req).await;
    let ms = t.elapsed().as_millis() as u64;
    let mut m = st.metrics.http.lock().unwrap();
    // Unknown paths (404s, scanners) must not grow the label set.
    if m.contains_key(&path) || m.len() < 256 {
        let e = m.entry(path).or_default();
        e.count += 1;
        e.total_ms += ms;
        if resp.status().is_server_error() {
            e.err5xx += 1;
        }
    }
    resp
}

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
        .route("/api/v1/health", get(system::health))
        .route("/api/v1/status", get(system::status))
        .route("/api/v1/stream", get(system::stream))
        // Expensive scan endpoints get a stale-while-revalidate cache:
        // the UI polls these on an interval, so serving the previous
        // response while a background recompute runs keeps the dashboard
        // instant instead of pinning a core for seconds per refresh.
        .merge(
            Router::new()
                .route("/api/v1/flows", get(flows::flows))
                .route("/api/v1/flows/stream", get(system::flow_stream))
                .route("/api/v1/geo", get(flows::geo))
                .route("/api/v1/summary", get(agg::summary))
                .route("/api/v1/overview", get(agg::overview))
                .route("/api/v1/matrix", get(agg::matrix))
                .route("/api/v1/timeseries", get(agg::timeseries))
                .route("/api/v1/top", get(agg::top))
                .route("/api/v1/conversations", get(agg::conversations))
                .route("/api/v1/anomalies", get(agg::anomalies))
                .route("/api/v1/label_stats", get(agg::label_stats))
                .layer(crate::qcache::SwrCacheLayer::new(st.metrics.clone())),
        )
        .route("/api/v1/exporters", get(meta::exporters))
        .route("/api/v1/exporters/:ip/name", post(meta::exporter_rename))
        .route("/api/v1/exporters/:ip/vlans", post(meta::exporter_vlans))
        .route("/api/v1/exporters/:ip/interfaces", post(meta::exporter_interfaces))
        .route("/api/v1/exporters/:ip/snmp", post(meta::exporter_snmp))
        .route("/api/v1/exporters/:ip/:action", post(meta::exporter_action))
        .route("/api/v1/interfaces", get(meta::interfaces))
        .route("/api/v1/vlans", get(meta::vlans))
        .route("/api/v1/labels", get(meta::labels))
        .route("/api/v1/enrichers", get(meta::enrichers))
        .route("/api/v1/alerts", get(meta::alerts_status))
        .route("/api/v1/asn", get(adminapi::asn_lookup))
        .route("/api/v1/lookup", get(adminapi::lookup))
        .route("/api/v1/config", get(meta::config_view))
        .route("/api/v1/openapi.json", get(adminapi::openapi))
        .route("/api/v1/auth/login", post(adminapi::auth_login))
        .route("/api/v1/auth/logout", post(adminapi::auth_logout))
        .route("/api/v1/auth/me", get(adminapi::auth_me))
        .route("/api/v1/admin/reload", post(adminapi::admin_reload))
    .route("/api/v1/admin/settings", get(adminapi::admin_settings_get).put(adminapi::admin_settings_put))
        .route("/metrics", get(system::metrics_handler));

    // CORS is baked into the router at startup — snapshot once. Changes
    // via settings apply on restart (listed under restart-required).
    let (cors_enabled, cors_origins, cors_wildcard) = {
        let c = st.config.read().unwrap();
        (
            c.server.cors,
            c.server.cors_origins.clone(),
            c.server.cors_origins.is_empty(),
        )
    };
    let app = Router::new()
        .merge(api)
        .route("/", get(index))
        .with_state(st.clone())
        // Order matters: last .layer() is outermost. security_headers wraps
        // auth_mw so even 401/403 responses carry the baseline headers; CORS
        // is outermost so preflights bypass auth entirely.
        .layer(middleware::from_fn_with_state(st.clone(), auth_mw))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn_with_state(st.clone(), metrics_mw));

    if cors_enabled {
        if cors_wildcard {
            tracing::warn!("server.cors=true with no cors_origins — wide-open CORS (dev only!)");
            app.layer(tower_http::cors::CorsLayer::permissive())
        } else {
            let origins: Vec<_> = cors_origins.iter().filter_map(|o| o.parse().ok()).collect();
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