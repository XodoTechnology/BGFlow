//! Enrichment: GeoIP/ASN via MaxMind MMDB plus pluggable HTTP backends
//! (e.g. irrd3.net, local whois/RDAP proxies).
//!
//! HTTP enrichment is asynchronous: the ingest path checks a cache and, on a
//! miss, enqueues the prefix for a background worker. Flows arriving before
//! the first lookup completes are stored with whatever MMDB provided —
//! subsequent flows for the same prefix are enriched. This keeps ingest
//! latency flat regardless of backend speed.

use crate::config::{EnricherConfig, GeoIpConfig};
use crate::metrics::Metrics;
use bgflow_types::{country_pack, country_str, ip_string, ip_to_u128, u128_to_ip, FlowRecord};
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Organization string table (interning + persistence)
// ---------------------------------------------------------------------------

/// Maps organization names <-> u32 ids. id 0 = unknown. Persisted as
/// tab-separated `id\tname` lines so ids stay stable across restarts.
pub struct StringTable {
    inner: Mutex<Inner>,
    path: PathBuf,
}

struct Inner {
    names: Vec<String>, // index i -> id i+1
    ids: HashMap<String, u32>,
}

impl StringTable {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        let mut inner = Inner {
            names: Vec::new(),
            ids: HashMap::new(),
        };
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                if let Some((id_s, name)) = line.split_once('\t') {
                    if let (Ok(id), false) = (id_s.parse::<u32>(), name.is_empty()) {
                        let idx = id.saturating_sub(1) as usize;
                        if idx >= inner.names.len() {
                            inner.names.resize(idx + 1, String::new());
                        }
                        inner.names[idx] = name.to_string();
                        inner.ids.insert(name.to_string(), id);
                    }
                }
            }
        }
        Ok(StringTable {
            inner: Mutex::new(inner),
            path,
        })
    }

    /// Intern a name; returns its id (0 for empty input).
    pub fn intern(&self, name: &str) -> u32 {
        if name.is_empty() {
            return 0;
        }
        let mut g = self.inner.lock().unwrap();
        if let Some(&id) = g.ids.get(name) {
            return id;
        }
        let id = (g.names.len() + 1) as u32;
        g.names.push(name.to_string());
        g.ids.insert(name.to_string(), id);
        // Persist immediately — orgs are rare, a flush per new name is fine.
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            use std::io::Write;
            let _ = writeln!(f, "{}\t{}", id, name);
        }
        id
    }

    pub fn name(&self, id: u32) -> Option<String> {
        if id == 0 {
            return None;
        }
        let g = self.inner.lock().unwrap();
        g.names
            .get(id as usize - 1)
            .filter(|s| !s.is_empty())
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().names.len()
    }
}

// ---------------------------------------------------------------------------
// Synchronous MMDB enrichment
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AsnRecord {
    #[serde(rename = "autonomous_system_number")]
    asn: Option<u64>,
    organization: Option<String>,
}

#[derive(Deserialize)]
struct CountryRecord {
    country: Option<CountryCode>,
    registered_country: Option<CountryCode>,
}

#[derive(Deserialize)]
struct CountryCode {
    #[serde(rename = "iso_code")]
    iso_code: Option<String>,
}

pub struct MmdbGeo {
    asn: Option<maxminddb::Reader<Vec<u8>>>,
    country: Option<maxminddb::Reader<Vec<u8>>>,
    orgs: Arc<StringTable>,
}

impl MmdbGeo {
    pub fn open(cfg: &GeoIpConfig, orgs: Arc<StringTable>) -> Self {
        let asn = if cfg.asn_db.is_empty() {
            None
        } else {
            match maxminddb::Reader::open_readfile(&cfg.asn_db) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!("geoip: cannot open ASN db {}: {}", cfg.asn_db, e);
                    None
                }
            }
        };
        let country = if cfg.country_db.is_empty() {
            None
        } else {
            match maxminddb::Reader::open_readfile(&cfg.country_db) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!(
                        "geoip: cannot open country db {}: {}",
                        cfg.country_db,
                        e
                    );
                    None
                }
            }
        };
        MmdbGeo { asn, country, orgs }
    }

    pub fn enabled(&self) -> bool {
        self.asn.is_some() || self.country.is_some()
    }

    /// Enrich one IP's fields in the record. Only fills fields that are
    /// still unset (0), so exporter-provided values win.
    fn enrich_ip(&self, ip_u128: u128, is_src: bool, rec: &mut FlowRecord) {
        let ip = u128_to_ip(ip_u128);
        if let Some(r) = &self.asn {
            if let Ok(Some(a)) = r.lookup::<Option<AsnRecord>>(ip) {
                let asn = a.asn.unwrap_or(0) as u32;
                let org = a.organization.map(|o| self.orgs.intern(&o)).unwrap_or(0);
                if is_src {
                    if rec.src_asn == 0 && asn != 0 {
                        rec.src_asn = asn;
                    }
                    if rec.src_org == 0 && org != 0 {
                        rec.src_org = org;
                    }
                } else {
                    if rec.dst_asn == 0 && asn != 0 {
                        rec.dst_asn = asn;
                    }
                    if rec.dst_org == 0 && org != 0 {
                        rec.dst_org = org;
                    }
                }
            }
        }
        if let Some(r) = &self.country {
            if let Ok(Some(c)) = r.lookup::<Option<CountryRecord>>(ip) {
                let code = c
                    .country
                    .as_ref()
                    .or(c.registered_country.as_ref())
                    .and_then(|cc| cc.iso_code.as_deref())
                    .unwrap_or("");
                let packed = country_pack(code);
                if packed != 0 {
                    if is_src && rec.src_country == 0 {
                        rec.src_country = packed;
                    } else if !is_src && rec.dst_country == 0 {
                        rec.dst_country = packed;
                    }
                }
            }
        }
    }

    /// Enrich both endpoints of a record.
    pub fn enrich(&self, rec: &mut FlowRecord) {
        if !self.enabled() {
            return;
        }
        self.enrich_ip(rec.src_ip, true, rec);
        self.enrich_ip(rec.dst_ip, false, rec);
    }
}

// ---------------------------------------------------------------------------
// HTTP enrichment backends
// ---------------------------------------------------------------------------

/// Result of one HTTP lookup, before interning.
#[derive(Debug, Clone, Default)]
pub struct LookupResult {
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub country: Option<u16>,
    pub extra: Vec<(String, String)>,
}

/// Cache granularity: v4 /24, v6 /48.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PrefixKey {
    V4(u32),  // a.b.c (top 24 bits)
    V6(u64),  // top 48 bits
}

fn prefix_key(ip: IpAddr) -> PrefixKey {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            PrefixKey::V4(((o[0] as u32) << 16) | ((o[1] as u32) << 8) | o[2] as u32)
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let mut k = 0u64;
            for i in 0..6 {
                k = (k << 8) | o[i] as u64;
            }
            PrefixKey::V6(k)
        }
    }
}

fn prefix_str(key: PrefixKey) -> String {
    match key {
        PrefixKey::V4(k) => format!(
            "{}.{}.{}.0/24",
            (k >> 16) & 0xff,
            (k >> 8) & 0xff,
            k & 0xff
        ),
        PrefixKey::V6(k) => {
            let o = k.to_be_bytes();
            let mut full = [0u8; 16];
            full[..6].copy_from_slice(&o[..6]);
            format!("{}/48", IpAddr::V6(std::net::Ipv6Addr::from(full)))
        }
    }
}

struct CacheEntry {
    result: LookupResult,
    expires_ms: u64,
}

pub struct HttpEnricher {
    pub name: String,
    url: String,
    fields: crate::config::HttpFields,
    client: reqwest::Client,
    ttl: Duration,
    neg_ttl: Duration,
    cache: Mutex<HashMap<PrefixKey, CacheEntry>>,
    order: Mutex<VecDeque<PrefixKey>>,
    pending: Mutex<HashSet<PrefixKey>>,
    cap: usize,
}

impl HttpEnricher {
    fn new(cfg: &EnricherConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms.max(100)))
            .user_agent("bgflowd/0.1 (+https://github.com/XodoTechnology/BGFlow)")
            .build()?;
        Ok(HttpEnricher {
            name: cfg.name.clone(),
            url: cfg.url.clone(),
            fields: cfg.fields.clone(),
            client,
            ttl: Duration::from_secs(cfg.cache_ttl_secs.max(60)),
            neg_ttl: Duration::from_secs(300),
            cache: Mutex::new(HashMap::new()),
            order: Mutex::new(VecDeque::new()),
            pending: Mutex::new(HashSet::new()),
            cap: 200_000,
        })
    }

    /// Synchronous cache lookup for the ingest path.
    pub fn cached(&self, ip: IpAddr) -> Option<LookupResult> {
        let key = prefix_key(ip);
        let now = crate::metrics::now_ms();
        let g = self.cache.lock().unwrap();
        match g.get(&key) {
            Some(e) if e.expires_ms > now => Some(e.result.clone()),
            _ => None,
        }
    }

    /// Mark a prefix for background lookup; returns true if newly enqueued.
    pub(crate) fn enqueue(&self, ip: IpAddr, tx: &tokio::sync::mpsc::Sender<(usize, PrefixKey)>, idx: usize) {
        let key = prefix_key(ip);
        {
            let mut p = self.pending.lock().unwrap();
            if !p.insert(key) {
                return; // already pending
            }
        }
        if tx.try_send((idx, key)).is_err() {
            self.pending.lock().unwrap().remove(&key);
        }
    }

    fn store(&self, key: PrefixKey, result: LookupResult, negative: bool) {
        let ttl = if negative { self.neg_ttl } else { self.ttl };
        let expires = crate::metrics::now_ms() + ttl.as_millis() as u64;
        {
            let mut g = self.cache.lock().unwrap();
            if g.len() >= self.cap {
                // FIFO evict ~10% to amortize.
                let mut order = self.order.lock().unwrap();
                for _ in 0..(self.cap / 10) {
                    if let Some(old) = order.pop_front() {
                        g.remove(&old);
                    }
                }
            }
            g.insert(key, CacheEntry { result, expires_ms: expires });
        }
        self.order.lock().unwrap().push_back(key);
        self.pending.lock().unwrap().remove(&key);
    }

    async fn lookup(&self, key: PrefixKey) -> LookupResult {
        let ip = match key {
            PrefixKey::V4(k) => IpAddr::V4(std::net::Ipv4Addr::new(
                (k >> 16) as u8,
                (k >> 8) as u8,
                (k & 0xff) as u8,
                1, // representative host; server resolves covering prefix
            )),
            PrefixKey::V6(k) => {
                let o = k.to_be_bytes();
                let mut full = [0u8; 16];
                full[..6].copy_from_slice(&o[..6]);
                full[15] = 1;
                IpAddr::V6(std::net::Ipv6Addr::from(full))
            }
        };
        let url = self
            .url
            .replace("{ip}", &ip.to_string())
            .replace("{prefix}", &prefix_str(key));
        let mut out = LookupResult::default();
        let resp = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("enricher '{}': request failed: {}", self.name, e);
                return out; // negative-cached by caller path
            }
        };
        if !resp.status().is_success() {
            return out;
        }
        let json: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => return out,
        };
        out.asn = self
            .fields
            .asn
            .as_deref()
            .and_then(|p| json_path(&json, p))
            .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()))
            .map(|n| n as u32);
        out.org = self
            .fields
            .org
            .as_deref()
            .and_then(|p| json_path(&json, p))
            .and_then(|v| v.as_str().map(|s| s.to_string()));
        out.country = self
            .fields
            .country
            .as_deref()
            .and_then(|p| json_path(&json, p))
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .map(|s| country_pack(&s));
        for (k, p) in &self.fields.extra {
            if let Some(v) = json_path(&json, p) {
                let s = v
                    .as_str()
                    .map(|x| x.to_string())
                    .or_else(|| v.as_u64().map(|n| n.to_string()))
                    .unwrap_or_default();
                if !s.is_empty() {
                    out.extra.push((k.clone(), s));
                }
            }
        }
        out
    }

    /// Apply a cached result to a record (fills only unset fields).
    pub fn apply(&self, res: &LookupResult, orgs: &StringTable, rec: &mut FlowRecord, is_src: bool) {
        let (asn_f, org_f, ctry_f) = if is_src {
            (&mut rec.src_asn, &mut rec.src_org, &mut rec.src_country)
        } else {
            (&mut rec.dst_asn, &mut rec.dst_org, &mut rec.dst_country)
        };
        if let Some(a) = res.asn {
            if *asn_f == 0 {
                *asn_f = a;
            }
        }
        if let Some(o) = &res.org {
            if *org_f == 0 {
                *org_f = orgs.intern(o);
            }
        }
        if let Some(c) = res.country {
            if *ctry_f == 0 && c != 0 {
                *ctry_f = c;
            }
        }
    }
}

/// Minimal JSON dot-path: "$.a.b.c", "a.b.c", with numeric array indices.
fn json_path<'a>(v: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = v;
    let p = path.strip_prefix("$.").unwrap_or(path.strip_prefix('$').unwrap_or(path));
    for part in p.split('.') {
        if part.is_empty() {
            continue;
        }
        cur = match cur {
            serde_json::Value::Object(m) => m.get(part)?,
            serde_json::Value::Array(a) => a.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Owns all HTTP enrichers + the background lookup worker.
pub struct HttpEnrichers {
    pub items: Vec<HttpEnricher>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(usize, PrefixKey)>>,
    tx: tokio::sync::mpsc::Sender<(usize, PrefixKey)>,
    metrics: Arc<Metrics>,
    orgs: Arc<StringTable>,
}

impl HttpEnrichers {
    pub fn new(cfgs: &[EnricherConfig], metrics: Arc<Metrics>, orgs: Arc<StringTable>) -> anyhow::Result<Self> {
        let mut items = Vec::new();
        for c in cfgs.iter().filter(|c| c.kind == "http") {
            items.push(HttpEnricher::new(c)?);
            tracing::info!("enricher '{}' -> {}", c.name, c.url);
        }
        let (tx, rx) = tokio::sync::mpsc::channel(4096);
        Ok(HttpEnrichers {
            items,
            rx: tokio::sync::Mutex::new(rx),
            tx,
            metrics,
            orgs,
        })
    }

    pub fn enabled(&self) -> bool {
        !self.items.is_empty()
    }

    /// Ingest-path hook: apply cached results and enqueue misses.
    /// Called per flow record, per endpoint.
    pub fn enrich_record(&self, rec: &mut FlowRecord) {
        for (i, e) in self.items.iter().enumerate() {
            for (ip_u128, is_src) in [(rec.src_ip, true), (rec.dst_ip, false)] {
                let ip = u128_to_ip(ip_u128);
                if let Some(res) = e.cached(ip) {
                    self.metrics.http_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    e.apply(&res, &self.orgs, rec, is_src);
                } else {
                    self.metrics.http_misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    e.enqueue(ip, &self.tx, i);
                }
            }
        }
    }

    /// Background worker: performs HTTP lookups and fills caches.
    pub async fn run(&self) {
        loop {
            let msg = self.rx.lock().await.recv().await;
            let Some((idx, key)) = msg else { break };
            let e = &self.items[idx];
            self.metrics.http_lookups.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let res = e.lookup(key).await;
            let empty = res.asn.is_none() && res.org.is_none() && res.country.is_none() && res.extra.is_empty();
            e.store(key, res, empty);
        }
    }

    /// Status for the API.
    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled(),
            "backends": self.items.iter().map(|e| serde_json::json!({
                "name": e.name,
                "url": e.url,
                "cache_entries": e.cache.lock().unwrap().len(),
                "pending": e.pending.lock().unwrap().len(),
            })).collect::<Vec<_>>(),
        })
    }

    /// Cached detail for one IP (for the UI lookup tool).
    pub fn lookup_ip(&self, ip: IpAddr) -> serde_json::Value {
        let key = prefix_key(ip);
        serde_json::json!({
            "ip": ip_string(ip_to_u128(&ip)),
            "prefix": prefix_str(key),
            "results": self.items.iter().map(|e| {
                let g = e.cache.lock().unwrap();
                let v = g.get(&key).map(|en| serde_json::json!({
                    "asn": en.result.asn,
                    "org": en.result.org,
                    "country": en.result.country.map(|c| country_str(c)),
                    "extra": en.result.extra,
                }));
                serde_json::json!({"backend": e.name, "result": v})
            }).collect::<Vec<_>>(),
        })
    }
}

/// Convenience: apply all synchronous enrichment to a record.
pub fn enrich_record(
    rec: &mut FlowRecord,
    geo: &MmdbGeo,
    http: &HttpEnrichers,
) {
    geo.enrich(rec);
    http.enrich_record(rec);
}
