//! Daemon status, SSE streams and the Prometheus endpoint.

use super::*;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub(super) async fn health(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
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

/// Displayed version: BGFLOW_VERSION env > [server] version > compile-time
/// git-derived string. Lets operators stamp distro/custom builds without
/// rebuilding (e.g. when .git wasn't present at build time).
pub(super) fn version_display(cfg: &crate::config::Config) -> String {
    if let Ok(v) = std::env::var("BGFLOW_VERSION") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    if !cfg.server.version.is_empty() {
        return cfg.server.version.clone();
    }
    env!("BGFLOW_VERSION_DISPLAY").to_string()
}

/// Git-describe string for the status tooltip: BGFLOW_GIT_DESCRIBE env >
/// [server] git_describe > compile-time value.
pub(super) fn git_describe(cfg: &crate::config::Config) -> String {
    if let Ok(v) = std::env::var("BGFLOW_GIT_DESCRIBE") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    if !cfg.server.git_describe.is_empty() {
        return cfg.server.git_describe.clone();
    }
    env!("BGFLOW_GIT_DESCRIBE").to_string()
}

pub(super) fn status_payload(st: &AppState) -> serde_json::Value {
    let s = st.status.read().unwrap().clone();
    let cfg = st.config.read().unwrap();
    let system = crate::sys::sample(&cfg.storage.data_dir);
    serde_json::json!({
        "version": version_display(&cfg),
        "git": git_describe(&cfg),
        "system": system,
        "status": s,
        "storage": {
            "bytes": s.flow_bytes + s.rollup_bytes + s.hourly_bytes,
            "cap_bytes": cfg.storage.max_bytes,
        },
        "orgs": st.ctx.orgs.len(),
        "rules": st.ctx.rules.len(),
        "inputs": cfg.inputs.iter().map(|i| i.listen.to_string()).collect::<Vec<_>>(),
        "auth": {
            "enabled": !st.auth.is_open(),
            "users": st.auth.user_count(),
        },
    })
}

pub(super) async fn status(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(status_payload(&st))
}

/// SSE stream of status payloads — the UI's live channel for sys stats,
/// uptime and writer health (2s cadence, one computation shared by all
/// connected clients).
pub(super) async fn stream(
    State(st): State<Arc<AppState>>,
) -> Sse<tokio_stream::wrappers::ReceiverStream<Result<axum::response::sse::Event, std::convert::Infallible>>> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(8);
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            iv.tick().await;
            let payload = status_payload(&st);
            let ev = Event::default().event("status").json_data(payload);
            match ev {
                Ok(ev) => {
                    if tx.send(Ok(ev)).await.is_err() {
                        break; // client gone
                    }
                }
                Err(_) => break,
            }
        }
    });
    Sse::new(tokio_stream::wrappers::ReceiverStream::new(rx))
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)).text("ping"))
}

/// SSE tail of incoming flows — each record is broadcast by the writer
/// as it arrives (pre-flush), filtered by the same params as /flows.
/// Lagged clients skip bursts rather than stalling ingest.
pub(super) async fn flow_stream(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<
    Sse<tokio_stream::wrappers::ReceiverStream<Result<axum::response::sse::Event, std::convert::Infallible>>>,
    (StatusCode, Json<serde_json::Value>),
> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    #[derive(Default)]
    struct F {
        src: Option<(u128, u128)>,
        dst: Option<(u128, u128)>,
        proto: Option<u8>,
        sport: Option<u16>,
        dport: Option<u16>,
    }
    impl F {
        fn matches(&self, r: &bgflow_types::FlowRecord) -> bool {
            if let Some((b, m)) = self.src {
                if (r.src_ip & m) != b {
                    return false;
                }
            }
            if let Some((b, m)) = self.dst {
                if (r.dst_ip & m) != b {
                    return false;
                }
            }
            if let Some(p) = self.proto {
                if r.protocol != p {
                    return false;
                }
            }
            if let Some(p) = self.sport {
                if r.src_port != p {
                    return false;
                }
            }
            if let Some(p) = self.dport {
                if r.dst_port != p {
                    return false;
                }
            }
            true
        }
    }
    let mut f = F::default();
    if let Some(s) = q.get("src") {
        f.src = Some(query::parse_ip_filter(s).ok_or_else(|| err("bad src"))?);
    }
    if let Some(s) = q.get("dst") {
        f.dst = Some(query::parse_ip_filter(s).ok_or_else(|| err("bad dst"))?);
    }
    if let Some(s) = q.get("proto") {
        f.proto = Some(parse_proto(s)?);
    }
    if let Some(s) = q.get("sport") {
        f.sport = Some(s.parse().map_err(|_| err("bad sport"))?);
    }
    if let Some(s) = q.get("dport") {
        f.dport = Some(s.parse().map_err(|_| err("bad dport"))?);
    }

    let mut rx = st.live_tx.subscribe();
    let ctx = st.ctx.clone();
    let (tx, out_rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(256);
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(rec) => {
                    if !f.matches(&rec) {
                        continue;
                    }
                    match Event::default().json_data(query::flow_json(&ctx, &rec)) {
                        Ok(ev) => {
                            if tx.send(Ok(ev)).await.is_err() {
                                break; // client gone
                            }
                        }
                        Err(_) => break,
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    Ok(Sse::new(tokio_stream::wrappers::ReceiverStream::new(out_rx))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("ping")))
}

pub(super) async fn metrics_handler(State(st): State<Arc<AppState>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        st.metrics.render(),
    )
        .into_response()
}

