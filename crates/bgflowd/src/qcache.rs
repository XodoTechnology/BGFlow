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
use std::sync::atomic::Ordering;
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
/// Total bytes across all cached bodies — bounds worst-case memory
/// (was implicitly ~2GB at 8MB × 256 entries).
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
/// Responses larger than this bypass the cache entirely.
const MAX_CACHE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct CachedResp {
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

struct CacheInner {
    map: HashMap<String, CachedResp>,
    /// Sum of cached body lengths — kept in lockstep with `map`.
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
}

pub struct QueryCache {
    inner: Mutex<CacheInner>,
    /// Bound concurrent background recomputes — each scan can use every
    /// core, so unbounded refreshes would starve ingest and each other.
    refresh_sem: tokio::sync::Semaphore,
    metrics: Arc<crate::metrics::Metrics>,
}

impl QueryCache {
    pub fn new(metrics: Arc<crate::metrics::Metrics>) -> Self {
        Self::with_limits(metrics, MAX_ENTRIES, MAX_TOTAL_BYTES)
    }

    fn with_limits(
        metrics: Arc<crate::metrics::Metrics>,
        max_entries: usize,
        max_bytes: usize,
    ) -> Self {
        Self {
            inner: Mutex::new(CacheInner {
                map: HashMap::new(),
                bytes: 0,
                max_entries,
                max_bytes,
            }),
            refresh_sem: tokio::sync::Semaphore::new(2),
            metrics,
        }
    }
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
        let mut m = self.inner.lock().unwrap();
        match m.map.get_mut(key) {
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
        self.insert(
            key,
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

    /// Insert/replace an entry, evicting oldest-first until both the
    /// entry-count and total-byte budgets fit. Replaces the old
    /// clear-entire-map policy which thrashed under diverse query params.
    fn insert(&self, key: &str, e: CachedResp) {
        let incoming = e.body.len();
        let mut m = self.inner.lock().unwrap();
        let is_new = !m.map.contains_key(key);
        let mut bytes = m.bytes;
        if let Some(old) = m.map.remove(key) {
            bytes = bytes.saturating_sub(old.body.len());
        }
        while (m.map.len() + usize::from(is_new)) > m.max_entries
            || bytes + incoming > m.max_bytes
        {
            let Some(oldest) = m
                .map
                .iter()
                .min_by_key(|(_, v)| v.fetched_ms)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(v) = m.map.remove(&oldest) {
                bytes = bytes.saturating_sub(v.body.len());
            }
        }
        m.bytes = bytes + incoming;
        m.map.insert(key.to_string(), e);
    }

    fn clear_refreshing(&self, key: &str) {
        if let Some(e) = self.inner.lock().unwrap().map.get_mut(key) {
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
        // Queue behind other refreshes — scans are CPU-hungry.
        let Ok(_permit) = cache.refresh_sem.acquire().await else {
            return;
        };
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
                        cache.insert(
                            &key,
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
                    cache.metrics.qcache_miss.fetch_add(1, Ordering::Relaxed);
                    let resp = inner.call(req).await?;
                    Ok(buffer_store(resp, &cache, &key).await)
                }
                Lookup::Hit(c) => {
                    cache.metrics.qcache_hit.fetch_add(1, Ordering::Relaxed);
                    Ok(c.into_response("hit"))
                }
                Lookup::Stale(c) => {
                    cache.metrics.qcache_stale.fetch_add(1, Ordering::Relaxed);
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
    pub fn new(metrics: Arc<crate::metrics::Metrics>) -> Self {
        Self {
            cache: Arc::new(QueryCache::new(metrics)),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(entries: usize, bytes: usize) -> QueryCache {
        QueryCache::with_limits(Arc::new(crate::metrics::Metrics::default()), entries, bytes)
    }

    fn resp(body: &[u8]) -> CachedResp {
        CachedResp {
            status: 200,
            headers: vec![],
            body: body.to_vec(),
            fetched_ms: crate::metrics::now_ms(),
            refreshing: false,
            refresh_started_ms: 0,
        }
    }

    #[test]
    fn hit_and_miss() {
        let c = cache(8, 1 << 20);
        assert!(matches!(c.lookup("/a"), Lookup::Miss));
        c.insert("/a", resp(b"hello"));
        assert!(matches!(c.lookup("/a"), Lookup::Hit(_)));
    }

    #[test]
    fn entry_cap_evicts_oldest() {
        let c = cache(2, 1 << 20);
        c.insert("/a", resp(b"1"));
        // Age /a so /b is strictly newer.
        std::thread::sleep(std::time::Duration::from_millis(2));
        c.insert("/b", resp(b"2"));
        std::thread::sleep(std::time::Duration::from_millis(2));
        c.insert("/c", resp(b"3")); // exceeds cap → evicts /a
        assert!(matches!(c.lookup("/a"), Lookup::Miss));
        assert!(matches!(c.lookup("/b"), Lookup::Hit(_)));
        assert!(matches!(c.lookup("/c"), Lookup::Hit(_)));
    }

    #[test]
    fn byte_budget_evicts_oldest() {
        let c = cache(8, 10);
        c.insert("/a", resp(b"12345"));
        std::thread::sleep(std::time::Duration::from_millis(2));
        c.insert("/b", resp(b"12345")); // 10 bytes total = budget
        std::thread::sleep(std::time::Duration::from_millis(2));
        c.insert("/c", resp(b"1")); // over budget → evict oldest (/a)
        assert!(matches!(c.lookup("/a"), Lookup::Miss));
        assert!(matches!(c.lookup("/b"), Lookup::Hit(_)));
        assert!(matches!(c.lookup("/c"), Lookup::Hit(_)));
        let m = c.inner.lock().unwrap();
        assert!(m.bytes <= 10, "bytes {} exceeds budget", m.bytes);
    }

    #[test]
    fn replace_keeps_accounting() {
        let c = cache(8, 100);
        c.insert("/a", resp(b"1234567890"));
        c.insert("/a", resp(b"1")); // replace shrinks accounting
        let m = c.inner.lock().unwrap();
        assert_eq!(m.bytes, 1);
        assert_eq!(m.map.len(), 1);
    }

    #[test]
    fn stale_then_miss_by_age() {
        let c = cache(8, 1 << 20);
        let mut e = resp(b"x");
        e.fetched_ms = crate::metrics::now_ms() - MAX_STALE_MS - 1;
        c.insert("/old", e);
        assert!(matches!(c.lookup("/old"), Lookup::Miss));
    }
}
