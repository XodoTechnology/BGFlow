//! Enrichment: GeoIP/ASN via MaxMind MMDB plus pluggable HTTP backends
//! (e.g. irrd3.net, local whois/RDAP proxies).
//!
//! HTTP enrichment is asynchronous: the ingest path checks a cache and, on a
//! miss, enqueues the prefix for a background worker. Flows arriving before
//! the first lookup completes are stored with whatever MMDB provided —
//! subsequent flows for the same prefix are enriched. This keeps ingest
//! latency flat regardless of backend speed.

use crate::config::{DbPaths, EnricherConfig, GeoIpConfig};
use crate::metrics::Metrics;
use bgflow_types::{country_pack, country_str, ip_string, ip_to_u128, is_v4_mapped, u128_to_ip, FlowRecord};
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

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

    /// Look up a name's id (exact match). Used to resolve API filter
    /// params like `src_city=Frankfurt`.
    pub fn id_of(&self, name: &str) -> Option<u32> {
        self.inner.lock().unwrap().ids.get(name).copied()
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
    /// DB-IP flat schema (the ip-database/mmdb "city" files use
    /// `country_code` at top level instead of nested `country.iso_code`).
    #[serde(rename = "country_code")]
    country_code: Option<String>,
    // City-level geo — present in *-city-*.mmdb databases. DB-IP uses flat
    // `city`/`state1`/`latitude`/`longitude` scalars; MaxMind nests
    // `city.names.en`, `subdivisions[].iso_code`, and
    // `location.{latitude,longitude}`. Accept both layouts.
    city: Option<serde_json::Value>,
    #[serde(rename = "state1")]
    state1: Option<String>,
    subdivisions: Option<Vec<Subdivision>>,
    location: Option<Location>,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(Deserialize)]
struct Subdivision {
    #[serde(rename = "iso_code")]
    iso_code: Option<String>,
    names: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Location {
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(Deserialize)]
struct CountryCode {
    #[serde(rename = "iso_code")]
    iso_code: Option<String>,
}

impl CountryRecord {
    fn iso_code(&self) -> &str {
        self.country
            .as_ref()
            .or(self.registered_country.as_ref())
            .and_then(|cc| cc.iso_code.as_deref())
            .or(self.country_code.as_deref())
            .unwrap_or("")
    }

    /// City name: DB-IP flat string, or MaxMind `city.names.en`.
    fn city_name(&self) -> Option<&str> {
        match self.city.as_ref()? {
            serde_json::Value::String(s) => Some(s.as_str()),
            v => v.pointer("/names/en").and_then(|n| n.as_str()),
        }
    }

    /// Region/subdivision display name: DB-IP `state1` (already a name like
    /// "Hesse"), else first MaxMind subdivision's `names.en`, else its
    /// `iso_code` (e.g. "CA").
    fn region_name(&self) -> Option<&str> {
        self.state1
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                let sub = self.subdivisions.as_ref()?.first()?;
                sub.names
                    .as_ref()
                    .and_then(|n| n.pointer("/en"))
                    .and_then(|n| n.as_str())
                    .filter(|s| !s.is_empty())
                    .or(sub.iso_code.as_deref().filter(|s| !s.is_empty()))
            })
    }

    fn lat(&self) -> Option<f64> {
        self.latitude.or_else(|| self.location.as_ref()?.latitude)
    }

    fn lon(&self) -> Option<f64> {
        self.longitude.or_else(|| self.location.as_ref()?.longitude)
    }
}

/// An open MMDB plus its declared IP version. Family-specific databases
/// (e.g. the ip-database/mmdb IPv4/IPv6 split files) must never see
/// cross-family queries: the crate happily walks the wrong tree and
/// returns *plausible-looking garbage* instead of an error.
struct GeoReader {
    // mmap-backed: DB pages live in the kernel page cache and are
    // reclaimable under memory pressure, instead of ~57MB of anonymous
    // heap per open database (which also doubled during hot-swaps).
    r: maxminddb::Reader<maxminddb::Mmap>,
    /// `metadata.ip_version` — 4 or 6. IPv6 databases also contain the
    /// IPv4 space, so they answer both families.
    ip_version: u16,
}

impl GeoReader {
    /// May this database answer a query for `ip`?
    fn serves(&self, ip: &IpAddr) -> bool {
        match ip {
            // v4 queries are safe against any tree (v4 DBs directly, v6
            // DBs via their embedded v4 section).
            IpAddr::V4(_) => true,
            // v6 queries only against v6 trees — a v4 tree misinterprets
            // the address bits and returns wrong data.
            IpAddr::V6(_) => self.ip_version == 6,
        }
    }
}

/// The set of open MMDB readers — replaced atomically on reload so
/// in-flight lookups never see a half-built set.
#[derive(Default)]
struct GeoReaders {
    /// One reader per configured path — split IPv4/IPv6 databases are
    /// tried in order; first hit wins.
    asn: Vec<GeoReader>,
    country: Vec<GeoReader>,
}

/// Fingerprint of a database file at load time: (mtime, len), or `None`
/// when the file was absent. Lets the refresh loop detect externally
/// replaced files (e.g. `bgflowd geoip-update`, package upgrades).
type FileStamp = Option<(Option<SystemTime>, u64)>;

pub struct MmdbGeo {
    readers: RwLock<GeoReaders>,
    /// Configured path → stamp recorded at the last reader build.
    stamps: RwLock<HashMap<PathBuf, FileStamp>>,
    orgs: Arc<StringTable>,
    /// City names interned separately from org names.
    cities: Arc<StringTable>,
    metrics: Arc<Metrics>,
    /// Bumped on every reader swap so cached per-IP results can detect
    /// stale MMDB data without a TTL-only wait.
    gen: AtomicU64,
}

/// Build readers + file stamps for a geoip config. Shared by `open` and
/// `swap`.
fn build_readers(cfg: &GeoIpConfig) -> (GeoReaders, HashMap<PathBuf, FileStamp>) {
    let mut stamps = HashMap::new();
    // Stamp every configured path (even unreadable/missing ones) so
    // files_changed() only fires on real differences.
    for p in cfg.all_db_paths() {
        let stamp = std::fs::metadata(&p)
            .ok()
            .map(|md| (md.modified().ok(), md.len()));
        stamps.insert(p, stamp);
    }
    let open_all = |paths: DbPaths| -> Vec<GeoReader> {
        paths
            .paths()
            .into_iter()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .filter_map(|p| match maxminddb::Reader::open_mmap(p) {
                Ok(r) => {
                    let ip_version = r.metadata.ip_version;
                    Some(GeoReader { r, ip_version })
                }
                Err(e) => {
                    tracing::warn!("geoip: cannot open {}: {}", p, e);
                    None
                }
            })
            .collect()
    };
    (
        GeoReaders {
            asn: open_all(cfg.asn_db.clone()),
            country: open_all(cfg.country_db.clone()),
        },
        stamps,
    )
}

impl MmdbGeo {
    pub fn open(
        cfg: &GeoIpConfig,
        orgs: Arc<StringTable>,
        cities: Arc<StringTable>,
        metrics: Arc<Metrics>,
    ) -> Self {
        let (readers, stamps) = build_readers(cfg);
        let n = readers.asn.len() + readers.country.len();
        if n == 0 {
            tracing::info!("geoip: no MMDB databases loaded");
        } else {
            tracing::info!(
                "geoip enrichment enabled ({} asn db(s), {} country db(s))",
                readers.asn.len(),
                readers.country.len()
            );
        }
        MmdbGeo {
            readers: RwLock::new(readers),
            stamps: RwLock::new(stamps),
            orgs,
            cities,
            metrics,
            gen: AtomicU64::new(1),
        }
    }

    /// Reader generation — increments on every `swap`. Cached enrichment
    /// results tagged with an older generation are recomputed.
    pub fn generation(&self) -> u64 {
        self.gen.load(Ordering::Relaxed)
    }

    /// Rebuild readers from `cfg` and swap them in atomically. Old
    /// readers stay alive until the last in-flight lookup finishes.
    pub fn swap(&self, cfg: &GeoIpConfig) {
        let (readers, stamps) = build_readers(cfg);
        let n = readers.asn.len() + readers.country.len();
        *self.readers.write().unwrap() = readers;
        *self.stamps.write().unwrap() = stamps;
        self.gen.fetch_add(1, Ordering::Relaxed);
        if n == 0 {
            tracing::warn!("geoip: no MMDB readers after reload — geo enrichment disabled");
        } else {
            tracing::info!("geoip: {} MMDB reader(s) (re)loaded", n);
        }
    }

    /// True when any configured file's mtime/size differs from the stamp
    /// recorded at the last build, or the configured path set changed.
    pub fn files_changed(&self, cfg: &GeoIpConfig) -> bool {
        let configured: HashSet<PathBuf> = cfg.all_db_paths().into_iter().collect();
        let stamps = self.stamps.read().unwrap();
        // A stamped path no longer configured means the config changed.
        if stamps.keys().any(|k| !configured.contains(k)) {
            return true;
        }
        for p in &configured {
            let cur: FileStamp = std::fs::metadata(p)
                .ok()
                .map(|md| (md.modified().ok(), md.len()));
            if stamps.get(p) != Some(&cur) {
                return true;
            }
        }
        false
    }

    /// Total open readers (for the admin reload report).
    pub fn db_count(&self) -> usize {
        let r = self.readers.read().unwrap();
        r.asn.len() + r.country.len()
    }

    pub fn enabled(&self) -> bool {
        self.db_count() > 0
    }

    /// Per-IP detail for the /api/v1/lookup endpoint — same field shape as
    /// the HTTP/table backends so results merge cleanly.
    pub fn lookup_detail(&self, ip: IpAddr) -> Option<serde_json::Value> {
        if !self.enabled() {
            return None;
        }
        let readers = self.readers.read().unwrap();
        // v4-mapped v6 input (::ffff:a.b.c.d) is really a v4 lookup.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            v => v,
        };
        let mut asn_v = serde_json::Value::Null;
        let mut org_v = serde_json::Value::Null;
        let mut country_v = serde_json::Value::Null;
        let mut city_v = serde_json::Value::Null;
        let mut region_v = serde_json::Value::Null;
        let mut lat_v = serde_json::Value::Null;
        let mut lon_v = serde_json::Value::Null;
        for g in readers.asn.iter().filter(|g| g.serves(&ip)) {
            if let Ok(Some(a)) = g.r.lookup::<Option<AsnRecord>>(ip) {
                self.metrics.mmdb_hits.fetch_add(1, Ordering::Relaxed);
                if let Some(n) = a.asn {
                    asn_v = serde_json::json!(n);
                }
                if let Some(o) = a.organization {
                    org_v = serde_json::json!(o);
                }
                break;
            }
        }
        for g in readers.country.iter().filter(|g| g.serves(&ip)) {
            if let Ok(Some(c)) = g.r.lookup::<Option<CountryRecord>>(ip) {
                self.metrics.mmdb_hits.fetch_add(1, Ordering::Relaxed);
                let code = c.iso_code();
                if !code.is_empty() {
                    country_v = serde_json::json!(code);
                }
                if let Some(ci) = c.city_name().map(str::trim).filter(|s| !s.is_empty()) {
                    city_v = serde_json::json!(ci);
                }
                if let Some(s1) = c.region_name() {
                    region_v = serde_json::json!(s1);
                }
                if let Some(la) = c.lat() {
                    lat_v = serde_json::json!(la);
                }
                if let Some(lo) = c.lon() {
                    lon_v = serde_json::json!(lo);
                }
                break;
            }
        }
        if asn_v.is_null()
            && org_v.is_null()
            && country_v.is_null()
            && city_v.is_null()
            && lat_v.is_null()
        {
            return None;
        }
        Some(serde_json::json!({
            "asn": asn_v, "org": org_v, "country": country_v,
            "city": city_v, "region": region_v, "lat": lat_v, "lon": lon_v,
        }))
    }

    /// Enrich one IP's fields in the record. Only fills fields that are
    /// still unset (0), so exporter-provided values win.
    /// MMDB fields for one IP, side-agnostic (caller picks src/dst).
    /// Locks readers briefly; returns default when geoip is disabled.
    pub(crate) fn ip_fields(&self, ip_u128: u128) -> IpFields {
        let readers = self.readers.read().unwrap();
        if readers.asn.is_empty() && readers.country.is_empty() {
            return IpFields::default();
        }
        self.ip_fields_in(&readers, ip_u128)
    }

    /// Lookup half of `enrich_ip`: resolve one IP against the readers and
    /// intern names, returning raw field values (0 = unset).
    fn ip_fields_in(&self, readers: &GeoReaders, ip_u128: u128) -> IpFields {
        let mut f = IpFields::default();
        let ip = u128_to_ip(ip_u128);
        for g in readers.asn.iter().filter(|g| g.serves(&ip)) {
            if let Ok(Some(a)) = g.r.lookup::<Option<AsnRecord>>(ip) {
                self.metrics.mmdb_hits.fetch_add(1, Ordering::Relaxed);
                f.asn = a.asn.unwrap_or(0) as u32;
                f.org = a.organization.map(|o| self.orgs.intern(&o)).unwrap_or(0);
                break;
            }
        }
        for g in readers.country.iter().filter(|g| g.serves(&ip)) {
            if let Ok(Some(c)) = g.r.lookup::<Option<CountryRecord>>(ip) {
                self.metrics.mmdb_hits.fetch_add(1, Ordering::Relaxed);
                f.country = country_pack(c.iso_code());
                // City-level geo — only *-city-*.mmdb databases carry these.
                f.city = c
                    .city_name()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| self.cities.intern(s))
                    .unwrap_or(0);
                f.region = c
                    .region_name()
                    .map(|s| self.cities.intern(s))
                    .unwrap_or(0);
                f.lat = c
                    .lat()
                    .map(|v| ((v + 90.0) * 100000.0).clamp(0.0, u32::MAX as f64) as u32)
                    .unwrap_or(0);
                f.lon = c
                    .lon()
                    .map(|v| ((v + 180.0) * 100000.0).clamp(0.0, u32::MAX as f64) as u32)
                    .unwrap_or(0);
                break;
            }
        }
        f
    }

}

/// Side-agnostic enrichment outcome for one IP: MMDB geo fields merged
/// with table/HTTP enricher results (first-wins per field, 0 = unset).
/// Cached per-IP by `HttpEnrichers` so ingest and flow reads don't
/// repeat MMDB/table lookups for every record.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct IpFields {
    pub asn: u32,
    /// Interned org id (0 = none).
    pub org: u32,
    /// Packed country code.
    pub country: u16,
    /// Interned city/region name ids.
    pub city: u32,
    pub region: u32,
    /// Scaled lat/lon ((v+90|180)*1e5).
    pub lat: u32,
    pub lon: u32,
}

impl IpFields {
    /// Write nonzero fields into unset record fields on one side.
    fn apply(&self, rec: &mut FlowRecord, is_src: bool) {
        let (asn_f, org_f, ctry_f, city_f, region_f, lat_f, lon_f) = if is_src {
            (
                &mut rec.src_asn,
                &mut rec.src_org,
                &mut rec.src_country,
                &mut rec.src_city,
                &mut rec.src_region,
                &mut rec.src_lat,
                &mut rec.src_lon,
            )
        } else {
            (
                &mut rec.dst_asn,
                &mut rec.dst_org,
                &mut rec.dst_country,
                &mut rec.dst_city,
                &mut rec.dst_region,
                &mut rec.dst_lat,
                &mut rec.dst_lon,
            )
        };
        if *asn_f == 0 && self.asn != 0 {
            *asn_f = self.asn;
        }
        if *org_f == 0 && self.org != 0 {
            *org_f = self.org;
        }
        if *ctry_f == 0 && self.country != 0 {
            *ctry_f = self.country;
        }
        if *city_f == 0 && self.city != 0 {
            *city_f = self.city;
        }
        if *region_f == 0 && self.region != 0 {
            *region_f = self.region;
        }
        if *lat_f == 0 && self.lat != 0 {
            *lat_f = self.lat;
        }
        if *lon_f == 0 && self.lon != 0 {
            *lon_f = self.lon;
        }
    }
}

/// Merge an enricher `LookupResult` into per-IP fields, first-wins per
/// field — mirrors `apply_result`'s fill-unset precedence.
fn merge_lookup(f: &mut IpFields, res: &LookupResult, orgs: &StringTable) {
    if f.asn == 0 {
        if let Some(a) = res.asn {
            f.asn = a;
        }
    }
    if f.org == 0 {
        if let Some(o) = &res.org {
            let id = orgs.intern(o);
            if id != 0 {
                f.org = id;
            }
        }
    }
    if f.country == 0 {
        if let Some(c) = res.country {
            if c != 0 {
                f.country = c;
            }
        }
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
        // Only queue keys that are new to the cache — TTL refreshes of an
        // existing key must not grow `order` (it would leak unboundedly).
        let is_new = {
            let mut g = self.cache.lock().unwrap();
            let is_new = !g.contains_key(&key);
            if g.len() >= self.cap && is_new {
                // FIFO evict ~10% to amortize.
                let mut order = self.order.lock().unwrap();
                for _ in 0..(self.cap / 10) {
                    if let Some(old) = order.pop_front() {
                        g.remove(&old);
                    }
                }
            }
            g.insert(key, CacheEntry { result, expires_ms: expires });
            is_new
        };
        if is_new {
            self.order.lock().unwrap().push_back(key);
        }
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

/// TTL for merged per-IP enrichment results. Short enough that table
/// refreshes, HTTP enricher TTLs and MMDB swaps propagate quickly;
/// long enough that repeated IPs (the common case) never re-lookup.
const IP_CACHE_TTL_MS: u64 = 120_000;
/// Bound on cached IPs (~30MB worst case at ~110B/entry).
const IP_CACHE_MAX: usize = 262_144;

struct IpCacheEntry {
    fields: IpFields,
    /// MmdbGeo generation at compute time — a geo swap invalidates.
    geo_gen: u64,
    expires_ms: u64,
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
    /// Merged per-IP enrichment (geo+tables+http cached results) — turns
    /// per-flow MMDB/table lookups into one hashmap hit per IP.
    ip_cache: RwLock<HashMap<u128, IpCacheEntry>>,
    ip_order: Mutex<VecDeque<u128>>,
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
            ip_cache: RwLock::new(HashMap::new()),
            ip_order: Mutex::new(VecDeque::new()),
        })
    }

    /// Hot-reload: rebuild the enricher set from new config (SIGHUP).
    /// In-flight HTTP lookups complete against the old set harmlessly.
    /// The per-IP cache is dropped — merged results embed the old set's
    /// table/http output.
    pub fn reload(&self, cfgs: &[EnricherConfig]) -> anyhow::Result<()> {
        let set = Arc::new(build_set(cfgs)?);
        for t in &set.tables {
            t.spawn_refresh();
        }
        *self.set.write().unwrap() = set;
        self.ip_cache.write().unwrap().clear();
        self.ip_order.lock().unwrap().clear();
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

    /// Ingest/query-path hook: geo + table + cached-HTTP enrichment per
    /// endpoint, backed by the per-IP cache. Called per flow record.
    pub fn enrich_record(&self, rec: &mut FlowRecord, geo: &MmdbGeo) {
        let src = self.ip_fields(rec.src_ip, geo);
        src.apply(rec, true);
        let dst = self.ip_fields(rec.dst_ip, geo);
        dst.apply(rec, false);
    }

    /// Merged enrichment fields for one IP: MMDB geo + table lookups +
    /// cached HTTP results, cached for IP_CACHE_TTL_MS. Cache misses
    /// compute live — which also enqueues HTTP backend lookups — then
    /// store the merged outcome.
    fn ip_fields(&self, ip_u128: u128, geo: &MmdbGeo) -> IpFields {
        let now = crate::metrics::now_ms();
        let gen = geo.generation();
        {
            let g = self.ip_cache.read().unwrap();
            if let Some(e) = g.get(&ip_u128) {
                if e.expires_ms > now && e.geo_gen == gen {
                    return e.fields;
                }
            }
        }
        let mut f = geo.ip_fields(ip_u128);
        let ip = u128_to_ip(ip_u128);
        let set = self.set.read().unwrap().clone();
        for t in &set.tables {
            if let Some(res) = t.lookup(ip_u128) {
                self.metrics.table_hits.fetch_add(1, Ordering::Relaxed);
                merge_lookup(&mut f, &res, &self.orgs);
            }
        }
        for e in &set.http {
            if let Some(res) = e.cached(ip) {
                self.metrics.http_hits.fetch_add(1, Ordering::Relaxed);
                merge_lookup(&mut f, &res, &self.orgs);
            } else {
                self.metrics.http_misses.fetch_add(1, Ordering::Relaxed);
                e.enqueue(ip, &self.tx);
            }
        }
        // Store: bounded FIFO. Refresh of a live key keeps its original
        // queue slot (no order-queue growth on TTL refreshes).
        let mut g = self.ip_cache.write().unwrap();
        let is_new = !g.contains_key(&ip_u128);
        if is_new && g.len() >= IP_CACHE_MAX {
            let mut order = self.ip_order.lock().unwrap();
            for _ in 0..(IP_CACHE_MAX / 10) {
                if let Some(old) = order.pop_front() {
                    g.remove(&old);
                }
            }
        }
        g.insert(
            ip_u128,
            IpCacheEntry {
                fields: f,
                geo_gen: gen,
                expires_ms: now + IP_CACHE_TTL_MS,
            },
        );
        drop(g);
        if is_new {
            self.ip_order.lock().unwrap().push_back(ip_u128);
        }
        f
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
            "ip_cache_entries": self.ip_cache.read().unwrap().len(),
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

// ---------------------------------------------------------------------------
// PTR (reverse DNS) cache — async, non-blocking, TTL'd
// ---------------------------------------------------------------------------

struct PtrEntry {
    /// None = known-negative (NXDOMAIN/no PTR), Some = hostname.
    name: Option<String>,
    at: std::time::Instant,
}

const PTR_POS_TTL: std::time::Duration = std::time::Duration::from_secs(3600);
const PTR_NEG_TTL: std::time::Duration = std::time::Duration::from_secs(600);
/// Don't queue more than this many in-flight lookups.
const PTR_PENDING_MAX: usize = 50_000;
/// Bound on cached PTR entries (~15MB worst case) — without it the map
/// grows forever on busy long-lived deployments.
const PTR_MAP_MAX: usize = 262_144;

/// Reverse-DNS cache. `get` is a cheap sync read — misses enqueue a
/// background `getnameinfo` and return "unknown" so query paths never
/// block on DNS. `resolve` does one bounded blocking lookup (for the
/// manual /lookup endpoint) and populates the cache.
pub struct PtrCache {
    map: Arc<RwLock<HashMap<u128, PtrEntry>>>,
    pending: Arc<Mutex<HashSet<u128>>>,
    tx: tokio::sync::mpsc::UnboundedSender<u128>,
}

impl PtrCache {
    pub fn new() -> Arc<Self> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<u128>();
        let this = Arc::new(PtrCache {
            map: Arc::new(RwLock::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashSet::new())),
            tx,
        });
        let worker = PtrWorker {
            map: this.map.clone(),
            pending: this.pending.clone(),
        };
        tokio::spawn(async move {
            while let Some(ip) = rx.recv().await {
                worker.resolve_one(ip).await;
            }
        });
        this
    }

    /// Sync cache read. `Some(Some(name))` = hostname, `Some(None)` =
    /// known no-PTR, `None` = unknown (enqueued for background resolve).
    pub fn get(&self, ip_u128: u128) -> Option<Option<String>> {
        let g = self.map.read().unwrap();
        if let Some(e) = g.get(&ip_u128) {
            let ttl = if e.name.is_some() { PTR_POS_TTL } else { PTR_NEG_TTL };
            if e.at.elapsed() < ttl {
                return Some(e.name.clone());
            }
        }
        drop(g);
        // Miss/expired → enqueue once.
        {
            let mut p = self.pending.lock().unwrap();
            if p.len() >= PTR_PENDING_MAX {
                return None;
            }
            if p.insert(ip_u128) {
                let _ = self.tx.send(ip_u128);
            }
        }
        None
    }

    /// Bounded blocking resolve for interactive lookups; fills the cache.
    pub async fn resolve(&self, ip: IpAddr) -> Option<String> {
        let u = ip_to_u128(&ip);
        if let Some(v) = self.get(u) {
            return v;
        }
        let name = match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok()),
        )
        .await
        {
            Ok(Ok(n)) => n,
            _ => None,
        };
        self.insert(u, name.clone());
        name
    }

    fn insert(&self, ip_u128: u128, name: Option<String>) {
        ptr_insert(&self.map, ip_u128, name);
        self.pending.lock().unwrap().remove(&ip_u128);
    }
}

/// Bounded insert shared by the cache and the resolve worker. When the
/// map is full, expired entries are reclaimed; if everything is still
/// fresh the new entry is skipped (callers still got their answer — it
/// just isn't remembered).
fn ptr_insert(map: &RwLock<HashMap<u128, PtrEntry>>, ip_u128: u128, name: Option<String>) {
    let mut g = map.write().unwrap();
    if g.len() >= PTR_MAP_MAX && !g.contains_key(&ip_u128) {
        g.retain(|_, e| e.at.elapsed() < PTR_POS_TTL);
        if g.len() >= PTR_MAP_MAX {
            return;
        }
    }
    g.insert(
        ip_u128,
        PtrEntry { name, at: std::time::Instant::now() },
    );
}

/// Worker-side state (shares the Arc'd maps with the cache).
struct PtrWorker {
    map: Arc<RwLock<HashMap<u128, PtrEntry>>>,
    pending: Arc<Mutex<HashSet<u128>>>,
}

impl PtrWorker {
    async fn resolve_one(&self, ip_u128: u128) {
        let ip = u128_to_ip(ip_u128);
        let name = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok())
            .await
            .ok()
            .flatten();
        ptr_insert(&self.map, ip_u128, name);
        self.pending.lock().unwrap().remove(&ip_u128);
    }
}

/// Convenience: apply all synchronous enrichment to a record. Per-IP
/// results are cached inside `HttpEnrichers` (geo generation + TTL
/// guarded), so repeated IPs cost one hashmap hit.
pub fn enrich_record(
    rec: &mut FlowRecord,
    geo: &MmdbGeo,
    http: &HttpEnrichers,
) {
    http.enrich_record(rec, geo);
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

    #[test]
    fn country_record_both_geo_layouts() {
        // DB-IP flat layout (ip-database/mmdb "city" files).
        let flat: CountryRecord = serde_json::from_value(serde_json::json!({
            "country_code": "US",
            "state1": "CA",
            "city": "Mountain View",
            "latitude": 37.4192,
            "longitude": -122.0574
        }))
        .unwrap();
        assert_eq!(flat.iso_code(), "US");
        assert_eq!(flat.city_name(), Some("Mountain View"));
        assert_eq!(flat.region_name(), Some("CA"));
        assert_eq!(flat.lat(), Some(37.4192));
        assert_eq!(flat.lon(), Some(-122.0574));

        // MaxMind GeoLite2 nested layout.
        let mm: CountryRecord = serde_json::from_value(serde_json::json!({
            "country": {"iso_code": "DE"},
            "city": {"names": {"en": "Berlin", "de": "Berlin"}},
            "subdivisions": [{"iso_code": "BE", "names": {"en": "Berlin"}}],
            "location": {"latitude": 52.52, "longitude": 13.405, "time_zone": "Europe/Berlin"}
        }))
        .unwrap();
        assert_eq!(mm.iso_code(), "DE");
        assert_eq!(mm.city_name(), Some("Berlin"));
        // names.en preferred over iso_code for display.
        assert_eq!(mm.region_name(), Some("Berlin"));
        assert_eq!(mm.lat(), Some(52.52));
        assert_eq!(mm.lon(), Some(13.405));

        // ASN-only record (no city fields) still parses.
        let bare: CountryRecord = serde_json::from_value(serde_json::json!({
            "country": {"iso_code": "FR"}
        }))
        .unwrap();
        assert_eq!(bare.iso_code(), "FR");
        assert!(bare.city_name().is_none());
        assert!(bare.lat().is_none());
    }

    #[test]
    fn files_changed_detects_replaced_and_new_files() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("test.mmdb");
        std::fs::write(&db, b"v1").unwrap();
        let cfg = GeoIpConfig {
            asn_db: crate::config::DbPaths::One(db.to_string_lossy().into()),
            ..Default::default()
        };
        let geo = MmdbGeo {
            readers: RwLock::new(GeoReaders::default()),
            stamps: RwLock::new(HashMap::new()),
            orgs: Arc::new(StringTable::open(dir.path().join("orgs.txt")).unwrap()),
            cities: Arc::new(StringTable::open(dir.path().join("cities.txt")).unwrap()),
            metrics: Arc::new(Metrics::default()),
            gen: std::sync::atomic::AtomicU64::new(0),
        };
        geo.swap(&cfg);
        assert!(!geo.files_changed(&cfg));

        // Content change → detected.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(&db, b"v2-longer").unwrap();
        assert!(geo.files_changed(&cfg));
        geo.swap(&cfg);
        assert!(!geo.files_changed(&cfg));

        // File removed → detected; re-added → detected.
        std::fs::remove_file(&db).unwrap();
        assert!(geo.files_changed(&cfg));
        geo.swap(&cfg);
        assert!(!geo.files_changed(&cfg));
        std::fs::write(&db, b"v3").unwrap();
        assert!(geo.files_changed(&cfg));
    }

    fn bare_geo(dir: &std::path::Path) -> MmdbGeo {
        MmdbGeo {
            readers: RwLock::new(GeoReaders::default()),
            stamps: RwLock::new(HashMap::new()),
            orgs: Arc::new(StringTable::open(dir.join("orgs.txt")).unwrap()),
            cities: Arc::new(StringTable::open(dir.join("cities.txt")).unwrap()),
            metrics: Arc::new(Metrics::default()),
            gen: AtomicU64::new(0),
        }
    }

    #[tokio::test]
    async fn ip_cache_reuses_and_invalidates_on_geo_swap() {
        let dir = tempfile::tempdir().unwrap();
        let geo = bare_geo(dir.path());
        let http = HttpEnrichers::new(
            &[],
            Arc::new(Metrics::default()),
            geo.orgs.clone(),
        )
        .unwrap();
        let mut f = FlowRecord::default();
        f.src_ip = ip_to_u128(&"10.1.2.3".parse::<IpAddr>().unwrap());
        f.dst_ip = ip_to_u128(&"2001:db8::1".parse::<IpAddr>().unwrap());

        http.enrich_record(&mut f, &geo);
        assert_eq!(http.status()["ip_cache_entries"], 2);
        // Repeat enrichment of the same IPs: cache hits, no growth.
        http.enrich_record(&mut f, &geo);
        http.enrich_record(&mut f, &geo);
        assert_eq!(http.status()["ip_cache_entries"], 2);

        // MMDB reader swap bumps the generation → cached entries are
        // stale and recomputed (count stays bounded at 2 IPs).
        geo.swap(&GeoIpConfig::default());
        http.enrich_record(&mut f, &geo);
        assert_eq!(http.status()["ip_cache_entries"], 2);
    }
}
