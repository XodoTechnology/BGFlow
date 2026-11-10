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
use bgflow_types::{country_pack, country_str, ip_string, ip_to_u128, is_v4_mapped, u128_to_ip, FlowRecord};
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
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
    // GeoLite2 uses "autonomous_system_organization"; DB-IP Lite uses
    // "organization" — accept either.
    #[serde(alias = "autonomous_system_organization")]
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
    metrics: Arc<Metrics>,
}

impl MmdbGeo {
    pub fn open(cfg: &GeoIpConfig, orgs: Arc<StringTable>, metrics: Arc<Metrics>) -> Self {
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
        MmdbGeo { asn, country, orgs, metrics }
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
                self.metrics.mmdb_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                self.metrics.mmdb_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
pub(crate) enum PrefixKey {
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
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms.max(100)))
            .user_agent("bgflowd/0.1 (+https://github.com/XodoTechnology/BGFlow)");
        // Optional auth/API-key headers for private backends (irrd3.net etc).
        if !cfg.headers.is_empty() {
            let mut hdrs = reqwest::header::HeaderMap::new();
            for (k, v) in &cfg.headers {
                match (
                    reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                    reqwest::header::HeaderValue::from_str(v),
                ) {
                    (Ok(name), Ok(val)) => {
                        hdrs.insert(name, val);
                    }
                    _ => tracing::warn!("enricher '{}': skipping bad header {:?}", cfg.name, k),
                }
            }
            builder = builder.default_headers(hdrs);
        }
        let client = builder.build()?;
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
    /// The message carries this enricher's Arc so in-flight lookups stay
    /// valid across config reloads.
    pub(crate) fn enqueue(
        self: &Arc<Self>,
        ip: IpAddr,
        tx: &tokio::sync::mpsc::Sender<(Arc<HttpEnricher>, PrefixKey)>,
    ) {
        let key = prefix_key(ip);
        {
            let mut p = self.pending.lock().unwrap();
            if !p.insert(key) {
                return; // already pending
            }
        }
        if tx.try_send((self.clone(), key)).is_err() {
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

    /// Perform the backend request. Returns `None` on transport/HTTP/JSON
    /// failure (caller counts an error and negative-caches); `Some` holds the
    /// parsed result, which may legitimately be empty (nothing found).
    async fn lookup(&self, key: PrefixKey) -> Option<LookupResult> {
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
                return None;
            }
        };
        if !resp.status().is_success() {
            return None;
        }
        let json: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => return None,
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
        Some(out)
    }

    /// Apply a cached result to a record (fills only unset fields).
    pub fn apply(&self, res: &LookupResult, orgs: &StringTable, rec: &mut FlowRecord, is_src: bool) {
        apply_result(res, orgs, rec, is_src);
    }
}

/// Fill unset asn/org/country fields from a lookup result.
fn apply_result(res: &LookupResult, orgs: &StringTable, rec: &mut FlowRecord, is_src: bool) {
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

// ---------------------------------------------------------------------------
// Table enricher: prefix -> ASN/org/country from a file or URL dump.
// Exact longest-prefix-match via per-length hash lookups — fast enough for
// ingest (a handful of lookups per flow) and needs no external service.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct TableRow {
    asn: Option<u32>,
    org: Option<String>,
    country: Option<u16>,
}

struct TableData {
    /// (masked_base, prefix_len, is_v4) -> row. The family flag prevents
    /// v4/v6 keys colliding and lets lookups skip the wrong family entirely.
    map: HashMap<(u128, u8, bool), TableRow>,
    /// Distinct (prefix_len, is_v4) present, sorted by len descending
    /// (early-exit LPM).
    lens: Vec<(u8, bool)>,
    rows: usize,
}

/// Mask keeping the top `bits` of an address. `is_v4` addresses live in the
/// low 32 bits of the u128 (v4-mapped form). Returns all-ones for an
/// out-of-range v4 length so it can never match a stored key.
fn prefix_mask(bits: u8, is_v4: bool) -> u128 {
    if is_v4 {
        if bits == 0 {
            0
        } else if bits > 32 {
            u128::MAX
        } else {
            ((u32::MAX << (32 - bits)) as u128) & 0xFFFF_FFFF
        }
    } else if bits == 0 {
        0
    } else if bits > 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - bits)
    }
}

/// Parse one dump line. Accepted forms (whitespace separated):
///   1.2.3.0/24 13335 "Acme LLC" US
///   2001:db8::/32 AS64496 Acme  GB
///   route: 1.2.3.0/24 origin: AS13335   (RPSL-ish, best effort)
/// asn may be bare digits or AS-prefixed; country is a 2-letter code.
fn parse_table_line(line: &str) -> Option<((u128, u8, bool), TableRow)> {
    let line = line.split('#').next()?.trim();
    if line.is_empty() {
        return None;
    }
    let toks: Vec<&str> = line.split_whitespace().collect();
    // Find the prefix token (first token containing '/', skipping "route:").
    let (pfx_idx, pfx) = toks.iter().enumerate().find(|(_, t)| t.contains('/'))?;
    let (addr_s, bits_s) = pfx.split_once('/')?;
    let addr: IpAddr = addr_s.parse().ok()?;
    let bits: u8 = bits_s.parse().ok()?;
    let is_v4 = addr.is_ipv4();
    if (is_v4 && bits > 32) || (!is_v4 && bits > 128) {
        return None;
    }
    let base = ip_to_u128(&addr) & prefix_mask(bits, is_v4);

    let mut row = TableRow::default();
    let mut org_parts: Vec<&str> = Vec::new();
    for t in toks.iter().skip(pfx_idx + 1) {
        let t = t.trim_end_matches(|c: char| ".,;".contains(c));
        if t.is_empty() || t == "origin:" || t == "route:" {
            continue;
        }
        let up = t.to_ascii_uppercase();
        if row.asn.is_none() {
            let digits = up.strip_prefix("AS").unwrap_or(&up);
            if let Ok(n) = digits.parse::<u32>() {
                if n > 0 && n < 4_000_000_000 {
                    row.asn = Some(n);
                    continue;
                }
            }
        }
        if row.country.is_none() && t.len() == 2 && t.chars().all(|c| c.is_ascii_alphabetic()) {
            let packed = country_pack(t);
            if packed != 0 {
                row.country = Some(packed);
                continue;
            }
        }
        org_parts.push(t);
    }
    if !org_parts.is_empty() {
        row.org = Some(org_parts.join(" "));
    }
    Some(((base, bits, is_v4), row))
}

fn parse_table(text: &str) -> TableData {
    let mut map = HashMap::new();
    let mut lens_set = std::collections::BTreeSet::new();
    for line in text.lines() {
        if let Some((k, row)) = parse_table_line(line) {
            lens_set.insert((k.1, k.2));
            map.insert(k, row);
        }
    }
    // Sort by prefix length descending so LPM tries longest first.
    let mut lens: Vec<(u8, bool)> = lens_set.into_iter().collect();
    lens.sort_by(|a, b| b.0.cmp(&a.0));
    let rows = map.len();
    TableData { map, lens, rows }
}

/// Prefix table enricher. `kind = "table"` in config; `path` is a local
/// file or http(s) URL, re-read every `refresh_secs` (0 = load once).
pub struct TableEnricher {
    pub name: String,
    source: TableSource,
    refresh: Duration,
    data: RwLock<TableData>,
    loaded_ms: AtomicU64,
}

enum TableSource {
    File(PathBuf),
    Url { url: String, client: reqwest::Client },
}

impl TableEnricher {
    fn new(cfg: &EnricherConfig) -> anyhow::Result<Self> {
        let src = cfg.path.clone().unwrap_or_default();
        let source = if src.starts_with("http://") || src.starts_with("https://") {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("bgflowd/0.1 (+https://github.com/XodoTechnology/BGFlow)")
                .build()?;
            TableSource::Url { url: src, client }
        } else {
            TableSource::File(PathBuf::from(src))
        };
        let t = TableEnricher {
            name: cfg.name.clone(),
            source,
            refresh: Duration::from_secs(cfg.refresh_secs.max(60)),
            data: RwLock::new(TableData { map: HashMap::new(), lens: vec![], rows: 0 }),
            loaded_ms: AtomicU64::new(0),
        };
        // Synchronous first load for file sources (fast, local).
        if matches!(t.source, TableSource::File(_)) {
            if let Ok(text) = t.fetch_text() {
                *t.data.write().unwrap() = parse_table(&text);
                t.loaded_ms.store(crate::metrics::now_ms(), Ordering::Relaxed);
            }
        }
        Ok(t)
    }

    /// Spawn the periodic refresh loop (call once after construction).
    pub fn spawn_refresh(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            // First refresh immediately covers URL sources.
            loop {
                this.refresh().await;
                tokio::time::sleep(this.refresh).await;
            }
        });
    }

    async fn refresh(&self) {
        match self.fetch_text_async().await {
            Some(text) => {
                let d = parse_table(&text);
                tracing::info!(
                    "table enricher '{}': loaded {} prefixes",
                    self.name,
                    d.rows
                );
                *self.data.write().unwrap() = d;
                self.loaded_ms.store(crate::metrics::now_ms(), Ordering::Relaxed);
            }
            None => tracing::warn!("table enricher '{}': refresh failed", self.name),
        }
    }

    fn fetch_text(&self) -> std::io::Result<String> {
        match &self.source {
            TableSource::File(p) => std::fs::read_to_string(p),
            TableSource::Url { .. } => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "url source needs async fetch",
            )),
        }
    }

    async fn fetch_text_async(&self) -> Option<String> {
        match &self.source {
            TableSource::File(p) => std::fs::read_to_string(p).ok(),
            TableSource::Url { url, client } => {
                let resp = client.get(url).send().await.ok()?;
                if !resp.status().is_success() {
                    return None;
                }
                resp.text().await.ok()
            }
        }
    }

    /// Exact longest-prefix-match lookup. Returns a LookupResult so the
    /// shared apply path works unchanged.
    pub fn lookup(&self, ip_u128: u128) -> Option<LookupResult> {
        let is_v4 = is_v4_mapped(ip_u128);
        let g = self.data.read().unwrap();
        for &(len, fam_v4) in &g.lens {
            if fam_v4 != is_v4 {
                continue;
            }
            let key = (ip_u128 & prefix_mask(len, is_v4), len, is_v4);
            if let Some(row) = g.map.get(&key) {
                if row.asn.is_none() && row.org.is_none() && row.country.is_none() {
                    return None;
                }
                return Some(LookupResult {
                    asn: row.asn,
                    org: row.org.clone(),
                    country: row.country,
                    extra: vec![],
                });
            }
        }
        None
    }

    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "prefixes": self.data.read().unwrap().rows,
            "loaded_ms": self.loaded_ms.load(Ordering::Relaxed),
        })
    }
}

/// The full enricher set — swapped atomically on config reload.
struct EnricherSet {
    http: Vec<Arc<HttpEnricher>>,
    tables: Vec<Arc<TableEnricher>>,
}

/// Owns all enrichers + the background lookup worker. `set` is an
/// `Arc`-swapped snapshot so reloads are race-free: in-flight lookups keep
/// their old enricher, new flows see the new set.
pub struct HttpEnrichers {
    set: RwLock<Arc<EnricherSet>>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(Arc<HttpEnricher>, PrefixKey)>>,
    tx: tokio::sync::mpsc::Sender<(Arc<HttpEnricher>, PrefixKey)>,
    metrics: Arc<Metrics>,
    orgs: Arc<StringTable>,
}

fn build_set(cfgs: &[EnricherConfig]) -> anyhow::Result<EnricherSet> {
    let mut http = Vec::new();
    let mut tables = Vec::new();
    for c in cfgs {
        match c.kind.as_str() {
            "http" => {
                http.push(Arc::new(HttpEnricher::new(c)?));
                tracing::info!("enricher '{}' -> {}", c.name, c.url);
            }
            "table" => {
                let t = Arc::new(TableEnricher::new(c)?);
                tracing::info!(
                    "table enricher '{}' <- {}",
                    t.name,
                    c.path.as_deref().unwrap_or("?")
                );
                tables.push(t);
            }
            other => tracing::warn!("unknown enricher type '{}' (skipped)", other),
        }
    }
    Ok(EnricherSet { http, tables })
}

impl HttpEnrichers {
    pub fn new(cfgs: &[EnricherConfig], metrics: Arc<Metrics>, orgs: Arc<StringTable>) -> anyhow::Result<Self> {
        let set = Arc::new(build_set(cfgs)?);
        // Kick off table refresh loops.
        for t in &set.tables {
            t.spawn_refresh();
        }
        let (tx, rx) = tokio::sync::mpsc::channel(4096);
        Ok(HttpEnrichers {
            set: RwLock::new(set),
            rx: tokio::sync::Mutex::new(rx),
            tx,
            metrics,
            orgs,
        })
    }

    /// Hot-reload: rebuild the enricher set from new config (SIGHUP).
    /// In-flight HTTP lookups complete against the old set harmlessly.
    pub fn reload(&self, cfgs: &[EnricherConfig]) -> anyhow::Result<()> {
        let set = Arc::new(build_set(cfgs)?);
        for t in &set.tables {
            t.spawn_refresh();
        }
        *self.set.write().unwrap() = set;
        tracing::info!("enrichers reloaded");
        Ok(())
    }

    pub fn enabled(&self) -> bool {
        let s = self.set.read().unwrap();
        !s.http.is_empty() || !s.tables.is_empty()
    }

    pub fn backend_count(&self) -> usize {
        let s = self.set.read().unwrap();
        s.http.len() + s.tables.len()
    }

    /// Ingest-path hook: apply cached/table results and enqueue misses.
    /// Called per flow record, per endpoint.
    pub fn enrich_record(&self, rec: &mut FlowRecord) {
        let set = self.set.read().unwrap().clone();
        for (ip_u128, is_src) in [(rec.src_ip, true), (rec.dst_ip, false)] {
            let ip = u128_to_ip(ip_u128);
            // Table enrichers: synchronous, exact LPM, fill unset fields.
            for t in &set.tables {
                if let Some(res) = t.lookup(ip_u128) {
                    self.metrics.table_hits.fetch_add(1, Ordering::Relaxed);
                    apply_result(&res, &self.orgs, rec, is_src);
                }
            }
            // HTTP enrichers: cache hit applies, miss enqueues.
            for e in &set.http {
                if let Some(res) = e.cached(ip) {
                    self.metrics.http_hits.fetch_add(1, Ordering::Relaxed);
                    e.apply(&res, &self.orgs, rec, is_src);
                } else {
                    self.metrics.http_misses.fetch_add(1, Ordering::Relaxed);
                    e.enqueue(ip, &self.tx);
                }
            }
        }
    }

    /// Background worker: performs HTTP lookups and fills caches.
    pub async fn run(&self) {
        loop {
            let msg = self.rx.lock().await.recv().await;
            let Some((e, key)) = msg else { break };
            self.metrics.http_lookups.fetch_add(1, Ordering::Relaxed);
            match e.lookup(key).await {
                Some(res) => {
                    let empty = res.asn.is_none() && res.org.is_none() && res.country.is_none() && res.extra.is_empty();
                    e.store(key, res, empty);
                }
                None => {
                    // Backend failure: count it and negative-cache briefly so
                    // a down backend doesn't get hammered per flow.
                    self.metrics.http_errors.fetch_add(1, Ordering::Relaxed);
                    e.store(key, LookupResult::default(), true);
                }
            }
        }
    }

    /// Status for the API.
    pub fn status(&self) -> serde_json::Value {
        let s = self.set.read().unwrap();
        serde_json::json!({
            "enabled": self.enabled(),
            "backends": s.http.iter().map(|e| serde_json::json!({
                "name": e.name,
                "type": "http",
                "url": e.url,
                "cache_entries": e.cache.lock().unwrap().len(),
                "pending": e.pending.lock().unwrap().len(),
            })).collect::<Vec<_>>(),
            "tables": s.tables.iter().map(|t| serde_json::json!({
                "name": t.name,
                "type": "table",
                "stats": t.stats(),
            })).collect::<Vec<_>>(),
        })
    }

    /// Cached detail for one IP (for the UI lookup tool).
    pub fn lookup_ip(&self, ip: IpAddr) -> serde_json::Value {
        let key = prefix_key(ip);
        let set = self.set.read().unwrap();
        let mut backends: Vec<serde_json::Value> = set
            .http
            .iter()
            .map(|e| {
                let g = e.cache.lock().unwrap();
                let v = g.get(&key).map(|en| serde_json::json!({
                    "asn": en.result.asn,
                    "org": en.result.org,
                    "country": en.result.country.map(|c| country_str(c)),
                    "extra": en.result.extra,
                }));
                serde_json::json!({"backend": e.name, "type": "http", "result": v})
            })
            .collect();
        for t in &set.tables {
            let v = t.lookup(ip_to_u128(&ip)).map(|r| serde_json::json!({
                "asn": r.asn,
                "org": r.org,
                "country": r.country.map(|c| country_str(c)),
            }));
            backends.push(serde_json::json!({"backend": t.name, "type": "table", "result": v}));
        }
        serde_json::json!({
            "ip": ip_string(ip_to_u128(&ip)),
            "prefix": prefix_str(key),
            "results": backends,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_parse_and_lpm() {
        let text = r#"
# comment
1.2.3.0/24 64512 "Acme Corp" US
1.2.3.0/24 64512 Acme Corp US
10.0.0.0/8 AS65000 BigNet
2001:db8::/32 64496 v6net GB
route: 9.9.9.0/24 origin: AS13335
"#;
        let d = parse_table(text);
        assert_eq!(d.rows, 4);
        // direct hit
        let ip = ip_to_u128(&"1.2.3.99".parse::<IpAddr>().unwrap());
        let r = d
            .map
            .get(&(ip & prefix_mask(24, true), 24, true))
            .unwrap();
        assert_eq!(r.asn, Some(64512));
        // LPM: /8 covers 10.x
        let ip8 = ip_to_u128(&"10.9.8.7".parse::<IpAddr>().unwrap());
        assert!(d.map.contains_key(&(ip8 & prefix_mask(8, true), 8, true)));
        // v6
        let ip6 = ip_to_u128(&"2001:db8::1".parse::<IpAddr>().unwrap());
        assert!(d
            .map
            .contains_key(&(ip6 & prefix_mask(32, false), 32, false)));
    }

    #[test]
    fn table_enricher_lookup() {
        let cfg = EnricherConfig {
            kind: "table".into(),
            name: "t".into(),
            path: None,
            url: String::new(),
            timeout_ms: 1000,
            cache_ttl_secs: 60,
            fields: crate::config::HttpFields::default(),
            headers: Default::default(),
            refresh_secs: 0,
        };
        let t = TableEnricher::new(&cfg).unwrap();
        *t.data.write().unwrap() = parse_table(
            "1.2.3.0/24 64512 Acme US\n2001:db8::/32 64496 v6net GB\n",
        );
        let hit = t.lookup(ip_to_u128(&"1.2.3.77".parse::<IpAddr>().unwrap())).unwrap();
        assert_eq!(hit.asn, Some(64512));
        assert_eq!(hit.org.as_deref(), Some("Acme"));
        assert_eq!(hit.country, Some(country_pack("US")));
        // no match outside prefix
        assert!(t.lookup(ip_to_u128(&"9.9.9.9".parse::<IpAddr>().unwrap())).is_none());
        // regression: v4 lookup with v6 prefixes in the table must not panic
        // (previously prefix_mask underflowed on len>32) and must still hit.
        assert!(t.lookup(ip_to_u128(&"1.2.3.200".parse::<IpAddr>().unwrap())).is_some());
        let v6hit = t
            .lookup(ip_to_u128(&"2001:db8::5".parse::<IpAddr>().unwrap()))
            .unwrap();
        assert_eq!(v6hit.asn, Some(64496));
    }
}
