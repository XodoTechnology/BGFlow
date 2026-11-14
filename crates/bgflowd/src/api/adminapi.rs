//! OpenAPI spec, lookups, auth endpoints and admin settings.

use super::*;

pub(super) async fn openapi() -> Json<serde_json::Value> {
    Json(openapi_spec())
}

/// Compact OpenAPI 3.0 spec covering the query endpoints.
pub(super) fn openapi_spec() -> serde_json::Value {
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
                {"name": "src_city", "in": "query", "description": "city name (exact)"},
                {"name": "dst_city", "in": "query", "description": "city name (exact)"},
                {"name": "label", "in": "query", "description": "label name or id"},
                {"name": "vlan", "in": "query", "description": "VLAN id (rollups need schema ≥5)"},
                {"name": "ingress_if", "in": "query", "description": "ingress ifIndex (rollups need schema ≥6)"},
                {"name": "egress_if", "in": "query", "description": "egress ifIndex (rollups need schema ≥6)"},
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
                {"name": "by", "in": "query", "description": "src_ip|dst_ip|src_ipver|dst_ipver|src_asn|dst_asn|src_org|dst_org|src_port|dst_port|proto|exporter|src_country|dst_country|label|vlan|ingress_if|egress_if"},
                {"name": "granularity", "in": "query", "description": "minute|hourly"},
                {"name": "limit", "in": "query"},
            ]}},
            "/api/v1/conversations": {"get": {"summary": "Top conversations"}},
            "/api/v1/anomalies": {"get": {"summary": "Statistical anomalies (z-score)", "parameters": [
                {"name": "by", "in": "query"}, {"name": "sigma", "in": "query"},
                {"name": "granularity", "in": "query"},
            ]}},
            "/api/v1/label_stats": {"get": {"summary": "Traffic per label"}},
            "/api/v1/exporters": {"get": {"summary": "Exporter ingest stats + admission state (pending/approved/suspended/rejected)", "parameters": [
                {"name": "require_approval", "in": "query", "description": "returned in payload"},
            ]}},
            "/api/v1/exporters/{ip}/{action}": {"post": {"summary": "Exporter admission action (admin): approve|suspend|reject|remove"}},
            "/api/v1/exporters/{ip}/name": {"post": {"summary": "Set exporter display name (admin)"}},
            "/api/v1/exporters/{ip}/vlans": {"post": {"summary": "Replace exporter VLAN name map (admin): {\"vlans\":{\"250\":\"Cogent\"}}"}},
            "/api/v1/exporters/{ip}/interfaces": {"post": {"summary": "Replace exporter interface name map (admin): {\"interfaces\":{\"1\":\"xe-0/0/0\"}}"}},
            "/api/v1/exporters/{ip}/snmp": {"post": {"summary": "Replace exporter SNMP overrides (admin): {\"community\":\"…\",\"port\":1161,\"disabled\":false} — empty clears to global"}},
            "/api/v1/labels": {"get": {"summary": "Configured label rules"}},
            "/api/v1/vlans": {"get": {"summary": "Configured VLAN names ([vlan_names])"}},
            "/api/v1/enrichers": {"get": {"summary": "Enricher status"}},
            "/api/v1/geo": {"get": {"summary": "Geo bubbles: lat/lon aggregates from the geo rollup (raw-flow fallback for pre-rollup history; needs city MMDB)", "parameters": [
                {"name": "from", "in": "query"}, {"name": "to", "in": "query"},
                {"name": "limit", "in": "query", "description": "max bubbles (default 300)"},
            ]}},
            "/api/v1/asn": {"get": {"summary": "AS registry lookup (BGPView): name/description/country/prefixes", "parameters": [
                {"name": "asn", "in": "query", "description": "AS number"},
            ]}},
            "/api/v1/lookup": {"get": {"summary": "Manual enrichment lookup", "parameters": [
                {"name": "ip", "in": "query"},
            ]}},
            "/api/v1/config": {"get": {"summary": "Effective config (redacted, admin only)"}},
            "/api/v1/auth/login": {"post": {"summary": "Login → session cookie", "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"username": {"type": "string"}, "password": {"type": "string"}}}}}}}},
            "/api/v1/auth/logout": {"post": {"summary": "Logout (clears session cookie)"}},
            "/api/v1/auth/me": {"get": {"summary": "Current identity or 401"}},
            "/api/v1/admin/reload": {"post": {"summary": "Hot-reload rules/enrichers/users/alerts (admin)"}},
            "/api/v1/admin/settings": {"get": {"summary": "Effective config JSON, secrets redacted (admin)"}, "put": {"summary": "Save settings → settings.json + hot-apply (admin)"}},
            "/metrics": {"get": {"summary": "Prometheus metrics"}},
        }
    })
}

pub(super) async fn lookup(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let s = q.get("ip").ok_or_else(|| err("missing ip"))?;
    let ip: IpAddr = s.parse().map_err(|_| err("bad ip"))?;
    let mut v = st.http_enrich.lookup_ip(ip);
    if let Some(ptr) = st.ctx.ptr.resolve(ip).await {
        v["ptr"] = serde_json::json!(ptr);
    }
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

/// GET /api/v1/asn?asn=61138 — AS registry info via IRR whois
/// (irrd3.net, with RIPEstat fallback). Cached ~6h; private/reserved
/// ASNs answer locally. Returns 502 when upstreams are unreachable so
/// the UI can fall back to the bare AS number.
pub(super) async fn asn_lookup(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let s = q.get("asn").ok_or_else(|| err("missing asn"))?;
    let asn: u32 = s
        .trim()
        .trim_start_matches("AS")
        .trim_start_matches("as")
        .parse()
        .map_err(|_| err("bad asn"))?;
    // Private/reserved ASN ranges have no registry entry.
    if asn == 0 || (64512..=65534).contains(&asn) || asn >= 4200000000 {
        return Ok(Json(serde_json::json!({"asn": asn, "private": true})));
    }
    {
        let c = st.asn_cache.lock().unwrap();
        if let Some((t, v)) = c.get(&asn) {
            if t.elapsed() < Duration::from_secs(6 * 3600) {
                return Ok(Json(v.clone()));
            }
        }
    }
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .user_agent("bgflowd/0.1")
            .build()
            .expect("reqwest client")
    });
    // Primary: IRR aut-num object from irrd3.net (plain-text whois).
    let mut out: Option<serde_json::Value> = None;
    if let Ok(resp) = client
        .get(format!("https://irrd3.net/api/whois?q=AS{}", asn))
        .send()
        .await
    {
        if resp.status().is_success() {
            if let Ok(text) = resp.text().await {
                let mut as_name = String::new();
                let mut descr = String::new();
                for line in text.lines() {
                    let l = line.trim();
                    if let Some(v) = l.strip_prefix("as-name:") {
                        as_name = v.trim().to_string();
                    } else if descr.is_empty() {
                        if let Some(v) = l.strip_prefix("descr:") {
                            let v = v.trim();
                            if !v.is_empty() {
                                descr = v.to_string();
                            }
                        }
                    }
                }
                if !as_name.is_empty() || !descr.is_empty() {
                    out = Some(serde_json::json!({
                        "asn": asn,
                        "name": as_name,
                        "description": descr,
                        "source": "irrd3",
                    }));
                }
            }
        }
    }
    // Fallback: RIPEstat as-overview holder string.
    if out.is_none() {
        if let Ok(resp) = client
            .get(format!(
                "https://stat.ripe.net/data/as-overview/data.json?resource=AS{}",
                asn
            ))
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    let holder = body["data"]["holder"].as_str().unwrap_or("");
                    if !holder.is_empty() {
                        out = Some(serde_json::json!({
                            "asn": asn,
                            "name": holder,
                            "description": "",
                            "source": "ripestat",
                        }));
                    }
                }
            }
        }
    }
    let out = out.ok_or_else(|| err("asn lookup failed (upstream unreachable)"))?;
    let mut c = st.asn_cache.lock().unwrap();
    if c.len() > 5000 {
        c.clear();
    }
    c.insert(asn, (Instant::now(), out.clone()));
    Ok(Json(out))
}

// ---------------------------------------------------------------------------
// Auth + admin endpoints
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub(super) struct LoginBody {
    username: String,
    password: String,
}

/// POST /api/v1/auth/login — JSON {username, password} → session cookie.
pub(super) async fn auth_login(
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
pub(super) async fn auth_logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
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
pub(super) async fn auth_me(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
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
    let api_key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok());
    match st.auth.identity_from_headers(peer.ip(), cookie, authz, api_key) {
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

/// Reload live config, then rebuild the hot tier when anything it
/// bakes in changed (local_asns → direction splits, window sizes).
/// Shared by POST /admin/reload and the settings PUT path.
fn reload_and_rebuild_hot(st: &AppState) -> crate::admin::ReloadReport {
    let sig = |c: &Config| {
        (
            crate::hot::asns_stamp(&c.analytics.local_asns),
            c.analytics.hot_window_hours,
            c.analytics.hot_detail_minutes,
        )
    };
    let before = sig(&st.config.read().unwrap());
    let rep = st.admin.reload();
    if rep.ok {
        let after = sig(&st.config.read().unwrap());
        if before != after {
            {
                let mut h = st.hot.write().unwrap();
                h.set_windows(
                    after.1.saturating_mul(3_600_000),
                    after.2.saturating_mul(60_000),
                );
            }
            let ctx = st.ctx.clone();
            let h = st.hot.clone();
            let la = st.ctx.local_asns.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = crate::hot::rebuild(&ctx, &h, &la) {
                    tracing::warn!("hot tier rebuild after reload failed: {}", e);
                }
            });
        }
    }
    rep
}

/// POST /api/v1/admin/reload — hot-reload rules/enrichers/users/alerts.
/// Admin role only (enforced by middleware path check).
pub(super) async fn admin_reload(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rep = reload_and_rebuild_hot(&st);
    Json(serde_json::to_value(&rep).unwrap_or(serde_json::json!({})))
}

// ---------------------------------------------------------------------------
// Runtime settings (settings.json overlay)
// ---------------------------------------------------------------------------

/// Marker the GET endpoint emits in place of real password hashes; PUT
/// maps it back to the existing hash so round-trips don't wipe passwords.
const REDACTED: &str = "•••";

/// Config keys the hot-reload path cannot apply — they take effect on
/// the next daemon start. Surfaced to the UI so editors can badge them.
const RESTART_KEYS: &[&str] = &[
    "server",
    "inputs",
    "snmp",
    "demo",
    "storage.data_dir",
    "storage.flows_dir",
    "storage.rollups_dir",
    "storage.hourly_dir",
    "storage.segment_rows",
    "storage.segment_interval_secs",
    "storage.channel_capacity",
    "storage.retention_interval_secs",
    "storage.sample_weighting",
    "storage.coarse_rollup",
];

/// Config paths whose scalar value is a credential — redacted in GET
/// and restored from the live config when a PUT echoes the marker back.
const SECRET_PATHS: &[&str] = &[
    "/snmp/community",
    "/session_secret",
    "/alerts/webhook_url",
];

pub(super) fn raw_settings(st: &AppState) -> serde_json::Value {
    serde_json::to_value(&*st.config.read().unwrap()).unwrap_or(serde_json::json!({}))
}

pub(super) fn effective_settings(st: &AppState) -> serde_json::Value {
    let mut v = raw_settings(st);
    redact_secrets(&mut v);
    v
}

pub(super) fn redact_secrets(v: &mut serde_json::Value) {
    if let Some(users) = v.get_mut("users").and_then(|u| u.as_array_mut()) {
        for u in users.iter_mut() {
            if let Some(o) = u.as_object_mut() {
                o.insert("password_hash".into(), serde_json::json!(REDACTED));
            }
        }
    }
    for ptr in SECRET_PATHS {
        if let Some(slot) = v.pointer_mut(ptr) {
            if !slot.is_null() {
                *slot = serde_json::json!(REDACTED);
            }
        }
    }
    // Enricher headers can carry API keys/Authorization — redact each
    // value but keep the key names visible.
    if let Some(enrs) = v.get_mut("enrichers").and_then(|e| e.as_array_mut()) {
        for e in enrs.iter_mut() {
            if let Some(h) = e.get_mut("headers").and_then(|h| h.as_object_mut()) {
                for val in h.values_mut() {
                    *val = serde_json::json!(REDACTED);
                }
            }
        }
    }
}

/// Before deep-merging a PUT body, replace every REDACTED marker with
/// the real value from `merged` (the current effective config), so a
/// GET→edit→PUT round-trip never persists "•••" literally.
pub(super) fn restore_secrets(body: &mut serde_json::Value, merged: &serde_json::Value) {
    for ptr in SECRET_PATHS {
        if let Some(slot) = body.pointer_mut(ptr) {
            if slot.as_str() == Some(REDACTED) {
                if let Some(real) = merged.pointer(ptr) {
                    *slot = real.clone();
                }
            }
        }
    }
    // Enricher headers: match by enricher `name`, restore per header key.
    let (Some(bb), Some(mb)) = (
        body.get_mut("enrichers").and_then(|e| e.as_array_mut()),
        merged.get("enrichers").and_then(|e| e.as_array()),
    ) else {
        return;
    };
    for b in bb.iter_mut() {
        let name = b.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
        let Some(m) = mb
            .iter()
            .find(|x| x.get("name").and_then(|n| n.as_str()) == Some(name.as_str()))
        else {
            continue;
        };
        let (Some(bh), Some(mh)) = (
            b.get_mut("headers").and_then(|h| h.as_object_mut()),
            m.get("headers").and_then(|h| h.as_object()),
        ) else {
            continue;
        };
        for (k, v) in bh.iter_mut() {
            if v.as_str() == Some(REDACTED) {
                if let Some(real) = mh.get(k) {
                    *v = real.clone();
                }
            }
        }
    }
}

/// GET /api/v1/admin/settings — effective config (bgflow.toml +
/// settings.json + env) with password hashes redacted.
pub(super) async fn admin_settings_get(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "config": effective_settings(&st),
        "settings_path": crate::config::settings_path(st.admin.config_path.as_ref()),
        "restart_required": RESTART_KEYS,
    }))
}

/// PUT /api/v1/admin/settings — body is a partial or full config object,
/// deep-merged onto the effective config, validated, persisted to
/// <data_dir>/settings.json, then hot-applied via the reload path.
pub(super) async fn admin_settings_put(
    State(st): State<Arc<AppState>>,
    Json(mut body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !body.is_object() {
        return Err(err("settings body must be a JSON object"));
    }
    // Merge onto the REAL config — the redacted view is GET-only;
    // merging onto it would persist "•••" as literal password hashes.
    let mut merged = raw_settings(&st);
    // Users: plaintext `password` becomes a hash; the redaction marker
    // restores the existing hash by name so GET→PUT round-trips are safe.
    if let Some(ov_users) = body.get_mut("users").and_then(|u| u.as_array_mut()) {
        for u in ov_users.iter_mut() {
            let Some(o) = u.as_object_mut() else { continue };
            if let Some(pw) = o.remove("password") {
                if let Some(p) = pw.as_str().filter(|s| !s.is_empty()) {
                    o.insert(
                        "password_hash".into(),
                        serde_json::json!(crate::auth::hash_password(p)),
                    );
                }
            }
            if o.get("password_hash").and_then(|h| h.as_str()) == Some(REDACTED) {
                let name = o.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let old = merged
                    .get("users")
                    .and_then(|us| us.as_array())
                    .and_then(|us| {
                        us.iter().find(|x| {
                            x.get("name").and_then(|n| n.as_str()) == Some(name)
                        })
                    })
                    .and_then(|x| x.get("password_hash"))
                    .cloned();
                if let Some(h) = old {
                    o.insert("password_hash".into(), h);
                }
            }
        }
    }
    restore_secrets(&mut body, &merged);
    crate::config::deep_merge(&mut merged, body);
    // Validate the merged result before touching disk.
    serde_json::from_value::<crate::config::Config>(merged.clone())
        .map_err(|e| err(format!("invalid settings: {}", e)))?;
    // Write where config::load will look on the next boot — resolved
    // from the pre-overlay data_dir, not the (possibly overridden) live one.
    let path = crate::config::settings_path(st.admin.config_path.as_ref());
    let text = serde_json::to_string_pretty(&merged).map_err(|e| err(e.to_string()))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &text).map_err(|e| err(format!("cannot write {}: {}", tmp.display(), e)))?;
    // settings.json carries password hashes + secrets — owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &path)
        .map_err(|e| err(format!("cannot install {}: {}", path.display(), e)))?;
    // Same path as SIGHUP — reload() re-reads config::load which now
    // includes the overlay, so everything hot-appliable applies live.
    let rep = reload_and_rebuild_hot(&st);
    Ok(Json(serde_json::json!({
        "ok": rep.ok,
        "settings_path": path,
        "report": rep,
    })))
}
