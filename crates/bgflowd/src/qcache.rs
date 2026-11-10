//! Stale-while-revalidate HTTP cache for expensive read-only GET endpoints.
//!
//! Rollup queries scan on-disk columnar segments; at scale a single
//! `/overview` call can take seconds of CPU. The UI polls on an interval,
//! so we serve the previous response instantly and recompute in the
//! background — data is at most ~one poll interval stale, which matches
//! the minute-granularity of the rollup data anyway.
//!
//! The layer sits inside the auth middleware (per-route, applied before
//! `auth_mw` wraps the app), so every request is still authenticated;
//! cached payloads are only produced by authorized requests.

use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, Method, Request, StatusCode, Uri},
    response::Response,
};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::future::Future;
use tower::{Layer, Service};

/// Serve a cached entry without refresh while younger than this.
const FRESH_MS: u64 = 4_000;
/// Serve stale entries (while a background refresh runs) up to this age.
const MAX_STALE_MS: u64 = 600_000;
/// If a background refresh appears stuck, allow another after this.
const REFRESH_RETRY_MS: u64 = 30_000;
const MAX_ENTRIES: usize = 256;
/// Responses larger than this bypass the cache entirely.
const MAX_CACHE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
struct CachedResp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    fetched_ms: u64,
    refreshing: bool,
    refresh_started_ms: u64,
}

impl CachedResp {
    fn into_response(self, cache_state: &str) -> Response {
        let mut b = Response::builder().status(self.status);
        for (k, v) in &self.headers {
            b = b.header(k.as_str(), v.as_str());
        }
        b = b.header("x-bgflow-cache", cache_state);
        b.body(Body::from(self.body))
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }
}

#[derive(Default)]
pub struct QueryCache {
    map: Mutex<HashMap<String, CachedResp>>,
}

pub enum Lookup {
    Hit(CachedResp),
    /// Stale but servable; caller should kick a background refresh.
    Stale(CachedResp),
    Miss,
}

impl QueryCache {
    fn lookup(&self, key: &str) -> Lookup {
        let now = crate::metrics::now_ms();
        let mut m = self.map.lock().unwrap();
        match m.get_mut(key) {
            Some(e) => {
                let age = now.saturating_sub(e.fetched_ms);
                if age > MAX_STALE_MS {
                    Lookup::Miss
                } else if age > FRESH_MS
                    && (!e.refreshing
                        || now.saturating_sub(e.refresh_started_ms) > REFRESH_RETRY_MS)
                {
                    e.refreshing = true;
                    e.refresh_started_ms = now;
                    Lookup::Stale(e.clone())
                } else {
                    Lookup::Hit(e.clone())
                }
            }
            None => Lookup::Miss,
        }
    }

    fn store(&self, key: &str, status: u16, headers: &HeaderMap, body: &[u8]) {
        let hdrs: Vec<(String, String)> = headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_string(), s.to_string()))
            })
            .collect();
        let mut m = self.map.lock().unwrap();
        if m.len() >= MAX_ENTRIES {
            m.clear();
        }
        m.insert(
            key.to_string(),
            CachedResp {
                status,
                headers: hdrs,
                body: body.to_vec(),
                fetched_ms: crate::metrics::now_ms(),
                refreshing: false,
                refresh_started_ms: 0,
            },
        );
    }

    fn clear_refreshing(&self, key: &str) {
        if let Some(e) = self.map.lock().unwrap().get_mut(key) {
            e.refreshing = false;
        }
    }
}

/// GET endpoints worth caching: the rollup/raw scan endpoints. Cheap
/// endpoints (status, health, exporters, labels, enrichers, config,
/// lookup, auth, metrics) and CSV exports are excluded.
fn cacheable(uri: &Uri) -> bool {
    if !matches!(
        uri.path(),
        "/api/v1/flows"
            | "/api/v1/summary"
            | "/api/v1/overview"
            | "/api/v1/matrix"
            | "/api/v1/timeseries"
            | "/api/v1/top"
            | "/api/v1/conversations"
            | "/api/v1/anomalies"
            | "/api/v1/label_stats"
    ) {
        return false;
    }
    // CSV exports are large one-off downloads — never cache.
    !uri
        .query()
        .map(|q| q.contains("format=csv"))
        .unwrap_or(false)
}

fn clone_request(req: &Request<Body>) -> Request<Body> {
    let mut b = Request::builder().method(Method::GET).uri(req.uri().clone());
    if let Some(h) = b.headers_mut() {
        *h = req.headers().clone();
    }
    b.body(Body::empty()).unwrap_or_else(|_| Request::new(Body::empty()))
}

/// Buffer a fresh response, store it if cacheable, and return it.
async fn buffer_store(resp: Response, cache: &Arc<QueryCache>, key: &str) -> Response {
    let (parts, body) = resp.into_parts();
    // Pre-check content-length: huge responses bypass the cache entirely
    // rather than paying the buffer cost.
    let too_big = parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| n > MAX_CACHE_BYTES)
        .unwrap_or(false);
    if too_big {
        return Response::from_parts(parts, body);
    }
    match to_bytes(body, MAX_CACHE_BYTES).await {
        Ok(bytes) => {
            if parts.status == StatusCode::OK {
                cache.store(key, parts.status.as_u16(), &parts.headers, &bytes);
            }
            Response::from_parts(parts, Body::from(bytes))
        }
        // Over the limit (or body error): the response is already consumed,
        // so all we can do is fail the request.
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("response too large to cache"))
            .unwrap(),
    }
}

fn spawn_refresh<S>(mut svc: S, req: Request<Body>, cache: Arc<QueryCache>, key: String)
where
    S: Service<Request<Body>, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    tokio::spawn(async move {
        // Ensure the inner service is ready before calling (tower contract).
        let _ = std::future::poll_fn(|cx| svc.poll_ready(cx)).await;
        match svc.call(req).await {
            Ok(resp) => {
                let (parts, body) = resp.into_parts();
                if parts.status == StatusCode::OK {
                    if let Ok(bytes) = to_bytes(body, MAX_CACHE_BYTES).await {
                        let headers: Vec<(String, String)> = parts
                            .headers
                            .iter()
                            .filter_map(|(k, v)| {
                                v.to_str()
                                    .ok()
                                    .map(|s| (k.as_str().to_string(), s.to_string()))
                            })
                            .collect();
                        // Store directly to avoid re-filtering header names.
                        let mut m = cache.map.lock().unwrap();
                        if m.len() >= MAX_ENTRIES {
                            m.clear();
                        }
                        m.insert(
                            key,
                            CachedResp {
                                status: parts.status.as_u16(),
                                headers,
                                body: bytes.to_vec(),
                                fetched_ms: crate::metrics::now_ms(),
                                refreshing: false,
                                refresh_started_ms: 0,
                            },
                        );
                    }
                }
            }
            Err(_) => cache.clear_refreshing(&key),
        }
    });
}

#[derive(Clone)]
pub struct SwrCache<S> {
    inner: S,
    cache: Arc<QueryCache>,
}

impl<S> Service<Request<Body>> for SwrCache<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let cache = Arc::clone(&self.cache);
        Box::pin(async move {
            if req.method() != Method::GET || !cacheable(req.uri()) {
                return inner.call(req).await;
            }
            let key = req.uri().to_string();
            match cache.lookup(&key) {
                Lookup::Miss => {
                    let resp = inner.call(req).await?;
                    Ok(buffer_store(resp, &cache, &key).await)
                }
                Lookup::Hit(c) => Ok(c.into_response("hit")),
                Lookup::Stale(c) => {
                    let req2 = clone_request(&req);
                    spawn_refresh(inner, req2, Arc::clone(&cache), key);
                    Ok(c.into_response("stale"))
                }
            }
        })
    }
}

#[derive(Clone)]
pub struct SwrCacheLayer {
    cache: Arc<QueryCache>,
}

impl SwrCacheLayer {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(QueryCache::default()),
        }
    }
}

impl<S> Layer<S> for SwrCacheLayer {
    type Service = SwrCache<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SwrCache {
            inner,
            cache: Arc::clone(&self.cache),
        }
    }
}
