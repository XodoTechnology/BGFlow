//! bgflowd configuration: `bgflow.toml` with sane defaults.

use anyhow::{Context, Result};
use bgflow_netflow::ProtoHint;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub geoip: GeoIpConfig,
    pub inputs: Vec<InputConfig>,
    pub enrichers: Vec<EnricherConfig>,
    pub rules: Vec<RuleConfig>,
    pub demo: DemoConfig,
    /// Threshold alerting over rollup data.
    pub alerts: AlertsConfig,
    /// Friendly names for exporters, keyed by exporter IP:
    /// [exporter_names] "10.0.0.1" = "edge-rtr"
    pub exporter_names: std::collections::BTreeMap<String, String>,
    /// Interface names, keyed by ifIndex (as carried in flow records):
    /// [interface_names] "2" = "ae0"
    #[serde(default)]
    pub interface_names: std::collections::BTreeMap<String, String>,
    /// VLAN names, keyed by VLAN id:
    /// [vlan_names] "10" = "Devoli"
    #[serde(default)]
    pub vlan_names: std::collections::BTreeMap<String, String>,
    /// Multi-user accounts for the UI/API.
    /// [[users]] name = "admin" password_hash = "pbkdf2-sha256$..." role = "admin"
    /// Generate hashes with `bgflowd hash-password`. Roles: admin | viewer.
    #[serde(default)]
    pub users: Vec<crate::auth::UserConfig>,
    /// Exporter admission policy ([exporters] section).
    #[serde(default)]
    pub exporters: ExportersConfig,
    /// Optional SNMP polling of exporters for interface/VLAN names and
    /// device info ([snmp] section). Disabled unless enabled = true.
    #[serde(default)]
    pub snmp: SnmpConfig,
    /// Analytics/direction settings ([analytics] section).
    #[serde(default)]
    pub analytics: AnalyticsConfig,
}

/// [analytics] — traffic analytics settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AnalyticsConfig {
    /// "Our" ASNs for direction analytics: a flow whose dst_asn is local is
    /// inbound, src_asn local is outbound, neither is transit/other.
    pub local_asns: Vec<u32>,
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self { local_asns: vec![] }
    }
}

/// Exporter admission control. New senders can be required to wait for
/// admin approval before their flows are accepted; decisions persist in
/// <data_dir>/exporters.json and can also be managed via the API/UI.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ExportersConfig {
    /// When true, an exporter IP not seen before starts as "pending" and
    /// its datagrams are dropped (counted) until approved via
    /// POST /api/v1/exporters/{ip}/approve or the UI. Suspended/rejected
    /// exporters are always dropped. Default false = accept everyone
    /// (pre-feature behavior).
    pub require_approval: bool,
    /// Exporter IPs/CIDRs always accepted, bypassing approval
    /// (e.g. "10.0.0.1", "192.168.0.0/16"). An explicit suspend/reject
    /// entry still wins over trusted.
    pub trusted: Vec<String>,
}

impl Default for ExportersConfig {
    fn default() -> Self {
        Self {
            require_approval: false,
            trusted: vec![],
        }
    }
}

/// Synthetic demo traffic (NetFlow v5) — for trying out the UI.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DemoConfig {
    pub enabled: bool,
    /// Send to this address; defaults to 127.0.0.1:<first input port>.
    pub target: Option<SocketAddr>,
    /// Datagrams per second.
    pub pps: u64,
    /// Flow records per datagram.
    pub flows_per_pkt: usize,
    /// Loopback source IPs to spread demo traffic across (exporter dim).
    pub exporters: usize,
    /// Seconds to run; 0 = forever.
    pub duration_secs: u64,
}

impl Default for DemoConfig {
    fn default() -> Self {
        DemoConfig {
            enabled: false,
            target: None,
            pps: 20,
            flows_per_pkt: 20,
            exporters: 3,
            duration_secs: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    /// HTTP API + UI listen address.
    pub http_listen: SocketAddr,
    /// Optional basic-auth for the UI/API: "user:password".
    /// Legacy single-credential mode — prefer [[users]] for multi-user
    /// auth with roles. When [[users]] is set it takes precedence for
    /// logins; this still works as an admin credential if both are set.
    pub auth: Option<String>,
    /// Allow CORS on the API (off by default; UI is same-origin).
    pub cors: bool,
    /// When set, CORS is restricted to these origins (with credentials).
    /// Empty + cors=true keeps the old wide-open permissive mode.
    #[serde(default)]
    pub cors_origins: Vec<String>,
    /// TLS cert + key paths (PEM). Both set = serve HTTPS; empty = HTTP.
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// Session-cookie signing secret. Empty = random per boot (sessions
    /// invalidate on restart). Set a long random string to persist sessions
    /// across restarts.
    pub session_secret: Option<String>,
    /// Session lifetime in seconds (default 86400 = 24h).
    pub session_ttl_secs: Option<u64>,
    /// Override the version string shown in the UI/status footer.
    /// Empty = the compile-time git-derived value. The BGFLOW_VERSION
    /// environment variable takes precedence over this.
    pub version: String,
    /// Override the git-describe string shown in the status tooltip.
    /// Empty = compile-time value. BGFLOW_GIT_DESCRIBE env wins.
    pub git_describe: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Root data directory.
    pub data_dir: PathBuf,
    /// Flush a raw-flow segment after this many rows.
    pub segment_rows: usize,
    /// Flush a segment after this many seconds.
    pub segment_interval_secs: u64,
    /// Channel capacity between ingest and writer.
    pub channel_capacity: usize,
    /// Raw flow retention in days (0 = keep forever).
    pub raw_retention_days: u32,
    /// Rollup retention in days (0 = keep forever).
    pub rollup_retention_days: u32,
    /// How often the retention sweep runs, in seconds.
    pub retention_interval_secs: u64,
    /// Maintain the coarse hourly dataset (masked /24·/48 IPs) for
    /// long-retention stats.
    pub coarse_rollup: bool,
    /// Coarse rollup retention in days (0 = keep forever).
    pub coarse_retention_days: u32,
    /// When true, rollup bytes/packets are multiplied by each flow's
    /// sampler_interval (1-in-N sampling correction). Enable only if your
    /// exporters report raw sampled counts — exporters that pre-scale
    /// would be double-counted. Default off.
    pub sample_weighting: bool,
    /// Hard cap on total segment bytes across flows/rollups/hourly
    /// (0 = unlimited). When exceeded, the oldest segments are evicted
    /// first until usage drops under 90% of the cap. Accepts plain
    /// bytes or strings like "50GiB", "51200M". Checked on the
    /// retention sweep interval.
    #[serde(default, deserialize_with = "de_size")]
    pub max_bytes: u64,
    /// Optional per-dataset directory overrides — e.g. point bulk raw
    /// flows at one mount and rollup stats at another. Each defaults
    /// to <data_dir>/{flows,rollups,hourly}.
    pub flows_dir: Option<PathBuf>,
    pub rollups_dir: Option<PathBuf>,
    pub hourly_dir: Option<PathBuf>,
}

impl StorageConfig {
    /// Resolve a dataset directory: explicit override or <data_dir>/<name>.
    pub fn dataset_dir(&self, name: &str, override_dir: &Option<PathBuf>) -> PathBuf {
        override_dir.clone().unwrap_or_else(|| self.data_dir.join(name))
    }
}

/// Deserialize a byte size: integer bytes, or a string with an optional
/// K/M/G/T suffix (binary, 'i'/'B' tolerated): "50GiB", "51200M", "1.5g".
fn de_size<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Repr {
        N(u64),
        S(String),
    }
    match Repr::deserialize(d)? {
        Repr::N(n) => Ok(n),
        Repr::S(s) => parse_size(&s)
            .ok_or_else(|| D::Error::custom(format!("bad byte size '{}'", s))),
    }
}

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase().replace(['_', ' '], "");
    let pos = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (num, suf) = s.split_at(pos);
    let v: f64 = num.parse().ok()?;
    let suf = suf.trim_end_matches('b');
    let mult = match suf {
        "" => 1.0,
        "k" | "ki" => 1024f64,
        "m" | "mi" => 1024f64.powi(2),
        "g" | "gi" => 1024f64.powi(3),
        "t" | "ti" => 1024f64.powi(4),
        _ => return None,
    };
    Some((v * mult) as u64)
}

/// `[snmp]` — optional polling of exporters (SNMPv2c) for interface
/// names, VLAN names and device info. Learned names only fill gaps;
/// config/UI-set names always win.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SnmpConfig {
    pub enabled: bool,
    /// v2c community string (required when enabled).
    pub community: String,
    pub port: u16,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    /// GETBULK/GET retries per request.
    pub retries: u32,
}

impl Default for SnmpConfig {
    fn default() -> Self {
        SnmpConfig {
            enabled: false,
            community: String::new(),
            port: 161,
            interval_secs: 300,
            timeout_secs: 2,
            retries: 1,
        }
    }
}

/// One MMDB path or several (e.g. separate IPv4/IPv6 databases — lookups
/// try each in order). Serializes back as a plain string when single.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DbPaths {
    One(String),
    Many(Vec<String>),
}

impl Default for DbPaths {
    fn default() -> Self {
        DbPaths::One(String::new())
    }
}

impl DbPaths {
    pub fn paths(&self) -> Vec<&str> {
        match self {
            DbPaths::One(s) => vec![s.as_str()],
            DbPaths::Many(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct GeoIpConfig {
    /// MaxMind ASN database path(s) (mmdb). Empty disables.
    pub asn_db: DbPaths,
    /// MaxMind Country database path(s) (mmdb). Empty disables.
    pub country_db: DbPaths,
    /// Auto-download source: "" (off, default) | "dbip" | "github".
    /// Downloads land in `update_dir` every `update_secs` and the daemon
    /// hot-swaps its readers — no restart needed.
    pub update_source: String,
    /// Seconds between auto-downloads. 0 = weekly (only used when
    /// `update_source` is set).
    pub update_secs: u64,
    /// Download directory. Empty = parent directory of the first
    /// configured database path.
    pub update_dir: String,
}

impl GeoIpConfig {
    /// Every configured database path (asn + country), trimmed, non-empty.
    pub fn all_db_paths(&self) -> Vec<std::path::PathBuf> {
        self.asn_db
            .paths()
            .into_iter()
            .chain(self.country_db.paths())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(std::path::PathBuf::from)
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct InputConfig {
    /// Listen address, e.g. "0.0.0.0:2055".
    pub listen: SocketAddr,
    /// auto | netflow5 | netflow9 | ipfix | sflow
    pub protocol: String,
    /// udp | tcp | both. TCP transport supports IPFIX only.
    pub transport: String,
    /// Only accept datagrams/connections from these exporter IPs (empty = all).
    pub allowed_exporters: Vec<std::net::IpAddr>,
    /// UDP socket receive buffer in bytes (SO_RCVBUF). 0 = OS default
    /// (~200KB — too small for busy routers; 4-16MB recommended).
    pub udp_buffer_bytes: usize,
    /// Max concurrent TCP connections on this input (0 = unlimited).
    /// Only applies to transport tcp/both.
    pub max_connections: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct EnricherConfig {
    /// "mmdb" is handled by [geoip]; only "http" enrichers appear here.
    /// e.g. irrd3.net, a local whois/RDAP proxy, etc.
    #[serde(rename = "type")]
    pub kind: String,
    /// Human-readable name shown in the UI.
    pub name: String,
    /// URL template; "{ip}" is replaced with the queried address.
    /// "{prefix}" replaced with CIDR (v4 /24, v6 /48 cache granularity).
    pub url: String,
    /// HTTP timeout in milliseconds.
    pub timeout_ms: u64,
    /// How long a lookup result is cached, in seconds.
    pub cache_ttl_secs: u64,
    /// Dot-path into the JSON response for each field.
    /// e.g. asn = "$.data.asn", org = "$.data.org", country = "$.data.country"
    pub fields: HttpFields,
    /// Extra HTTP headers sent with every request, e.g.
    /// `Authorization = "Bearer ..."` or an API key header for your backend.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// kind = "table": local file path or file:// URL with prefix lines
    /// ("1.2.3.0/24 13335 AS13335 OrgName US" — asn/org/country optional).
    /// Re-read every `refresh_secs`.
    pub path: Option<String>,
    /// kind = "table"/"http": seconds between refreshes (0 = once).
    pub refresh_secs: u64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct HttpFields {
    pub asn: Option<String>,
    pub org: Option<String>,
    pub country: Option<String>,
    /// Extra arbitrary fields stored for display, e.g. `handle = "$.handle"`.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, String>,
}

impl Default for EnricherConfig {
    fn default() -> Self {
        EnricherConfig {
            kind: "http".into(),
            name: String::new(),
            url: String::new(),
            timeout_ms: 2000,
            cache_ttl_secs: 86400,
            fields: HttpFields::default(),
            headers: std::collections::HashMap::new(),
            path: None,
            refresh_secs: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleConfig {
    /// Label name applied when the rule matches.
    pub name: String,
    /// IP protocol number (6=TCP, 17=UDP, ...).
    pub proto: Option<u8>,
    /// Matches when EITHER src_port or dst_port equals this (service
    /// labels like dns/https that must catch both directions).
    pub port: Option<u16>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// CIDR prefixes, e.g. "10.0.0.0/8" or "2001:db8::/32".
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_asn: Option<u32>,
    pub dst_asn: Option<u32>,
    /// ISO alpha-2 country codes, e.g. "US".
    pub src_country: Option<String>,
    pub dst_country: Option<String>,
    /// Exporter IP address.
    pub exporter: Option<std::net::IpAddr>,
    /// Organization substring match (case-insensitive) on src or dst org name.
    pub org: Option<String>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        RuleConfig {
            name: String::new(),
            proto: None,
            port: None,
            src_port: None,
            dst_port: None,
            src_ip: None,
            dst_ip: None,
            src_asn: None,
            dst_asn: None,
            src_country: None,
            dst_country: None,
            exporter: None,
            org: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            geoip: GeoIpConfig::default(),
            inputs: vec![InputConfig {
                listen: "0.0.0.0:2055".parse().unwrap(),
                protocol: "auto".into(),
                transport: "udp".into(),
                allowed_exporters: vec![],
                udp_buffer_bytes: 0,
                max_connections: 1024,
            }],
            enrichers: vec![],
            rules: vec![],
            demo: DemoConfig::default(),
            alerts: AlertsConfig::default(),
            exporter_names: Default::default(),
            interface_names: Default::default(),
            vlan_names: Default::default(),
            users: vec![],
            exporters: ExportersConfig::default(),
            analytics: AnalyticsConfig::default(),
            snmp: SnmpConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            http_listen: "0.0.0.0:8080".parse().unwrap(),
            auth: None,
            cors: false,
            cors_origins: vec![],
            tls_cert: None,
            tls_key: None,
            session_secret: None,
            session_ttl_secs: None,
            version: String::new(),
            git_describe: String::new(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            data_dir: PathBuf::from("/var/lib/bgflow"),
            segment_rows: 100_000,
            segment_interval_secs: 60,
            channel_capacity: 65_536,
            raw_retention_days: 7,
            rollup_retention_days: 90,
            retention_interval_secs: 300,
            coarse_rollup: true,
            coarse_retention_days: 365,
            sample_weighting: false,
            max_bytes: 0,
            flows_dir: None,
            rollups_dir: None,
            hourly_dir: None,
        }
    }
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        GeoIpConfig {
            asn_db: DbPaths::One("/usr/share/GeoIP/GeoLite2-ASN.mmdb".into()),
            country_db: DbPaths::One("/usr/share/GeoIP/GeoLite2-Country.mmdb".into()),
            update_source: String::new(),
            update_secs: 0,
            update_dir: String::new(),
        }
    }
}

impl Default for InputConfig {
    fn default() -> Self {
        InputConfig {
            listen: "0.0.0.0:2055".parse().unwrap(),
            protocol: "auto".into(),
            transport: "udp".into(),
            allowed_exporters: vec![],
            udp_buffer_bytes: 0,
            max_connections: 1024,
        }
    }
}

/// `[alerts]` section: eval loop + rule list.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AlertsConfig {
    /// How often alert rules are evaluated, in seconds.
    pub eval_secs: u64,
    /// Minimum seconds between repeat fires of the same alert+group.
    pub cooldown_secs: u64,
    /// Optional webhook URL POSTed on every alert fire (JSON body).
    pub webhook_url: Option<String>,
    #[serde(rename = "rules")]
    pub items: Vec<AlertConfig>,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        AlertsConfig {
            eval_secs: 60,
            cooldown_secs: 900,
            webhook_url: None,
            items: vec![],
        }
    }
}

/// One threshold alert over rollup data.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AlertConfig {
    /// Alert name (used in logs/metrics/webhook).
    pub name: String,
    /// What to measure: bytes | packets | flows | pps | mbps.
    pub metric: String,
    /// Comparison: gt | lt | gte | lte.
    pub op: String,
    /// Threshold on the per-second rate over the window.
    pub threshold: f64,
    /// Evaluation window in seconds (rate = total/window).
    pub window_secs: u64,
    /// Group-by dimension (same names as /top?by=); empty = whole set.
    pub group_by: Option<String>,
    /// Optional rollup dataset: minute (default) | hourly.
    pub granularity: Option<String>,
    /// Optional filters — same names as the query API.
    pub proto: Option<u8>,
    pub src_asn: Option<u32>,
    pub dst_asn: Option<u32>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_country: Option<String>,
    pub dst_country: Option<String>,
    pub exporter: Option<String>,
    pub label: Option<String>,
    /// Only alert when the rate jumps this much vs. the previous window
    /// (fold-change). 0 = disabled.
    pub min_change_pct: f64,
}

impl Default for AlertConfig {
    fn default() -> Self {
        AlertConfig {
            name: String::new(),
            metric: "mbps".into(),
            op: "gt".into(),
            threshold: 100.0,
            window_secs: 300,
            group_by: None,
            granularity: None,
            proto: None,
            src_asn: None,
            dst_asn: None,
            src_ip: None,
            dst_ip: None,
            src_country: None,
            dst_country: None,
            exporter: None,
            label: None,
            min_change_pct: 0.0,
        }
    }
}

/// Helper to map the protocol string to ProtoHint.
pub fn proto_hint(s: &str) -> ProtoHint {
    match s.to_ascii_lowercase().as_str() {
        "netflow5" | "v5" | "nf5" => ProtoHint::NetFlow5,
        "netflow9" | "v9" | "nf9" => ProtoHint::NetFlow9,
        "ipfix" => ProtoHint::Ipfix,
        "sflow" => ProtoHint::SFlow,
        _ => ProtoHint::Auto,
    }
}

/// Resolve which config file would be loaded (for hot-reload on SIGHUP).
pub fn resolve_path(arg: Option<&PathBuf>) -> Option<PathBuf> {
    match arg {
        Some(p) => Some(p.clone()),
        None => [
            PathBuf::from("bgflow.toml"),
            PathBuf::from("/etc/bgflow/bgflow.toml"),
        ]
        .into_iter()
        .find(|c| c.exists()),
    }
}

pub fn load(path: Option<&PathBuf>) -> Result<Config> {
    let mut cfg = match resolve_path(path) {
        Some(p) => {
            let text = std::fs::read_to_string(&p)
                .with_context(|| format!("cannot read config {}", p.display()))?;
            toml::from_str(&text).with_context(|| format!("cannot parse {}", p.display()))?
        }
        None => Config::default(),
    };
    apply_env_overrides(&mut cfg);
    apply_settings_overlay(&mut cfg)?;
    // Env vars are deployment-level intent — they win over UI settings too.
    apply_env_overrides(&mut cfg);
    Ok(cfg)
}

/// Path of the runtime settings overlay. Resolved from the
/// *pre-overlay* data_dir (toml + env) exactly as `load` does, so the
/// admin API always writes where the next `load` will look — even if a
/// previous settings save changed `storage.data_dir` itself.
pub fn settings_path(config_path: Option<&PathBuf>) -> PathBuf {
    let mut cfg = match resolve_path(config_path) {
        Some(p) => std::fs::read_to_string(&p)
            .ok()
            .and_then(|t| toml::from_str::<Config>(&t).ok())
            .unwrap_or_default(),
        None => Config::default(),
    };
    apply_env_overrides(&mut cfg);
    cfg.storage.data_dir.join("settings.json")
}

/// Runtime settings saved from the admin UI live in
/// `<data_dir>/settings.json` and deep-merge over bgflow.toml: objects
/// merge key-by-key, scalars/arrays replace. Once the file exists it is
/// authoritative for every key it contains — delete it to return to
/// pure file configuration.
fn apply_settings_overlay(cfg: &mut Config) -> Result<()> {
    let p = cfg.storage.data_dir.join("settings.json");
    if !p.exists() {
        return Ok(());
    }
    let text = std::fs::read_to_string(&p)
        .with_context(|| format!("cannot read {}", p.display()))?;
    let ov: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("cannot parse {}", p.display()))?;
    let mut base = serde_json::to_value(cfg.clone()).context("cannot serialize config")?;
    deep_merge(&mut base, ov);
    *cfg = serde_json::from_value(base)
        .context("settings.json produced an invalid config")?;
    Ok(())
}

pub(crate) fn deep_merge(base: &mut serde_json::Value, ov: serde_json::Value) {
    match (base, ov) {
        (serde_json::Value::Object(b), serde_json::Value::Object(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(bv) => deep_merge(bv, v),
                    None => {
                        b.insert(k, v);
                    }
                }
            }
        }
        (b, o) => *b = o,
    }
}

/// Environment overrides (handy for containers): BGFLOW_HTTP_LISTEN,
/// BGFLOW_DATA_DIR. Applied after file parsing so env always wins.
fn apply_env_overrides(cfg: &mut Config) {
    if let Ok(v) = std::env::var("BGFLOW_HTTP_LISTEN") {
        match v.parse::<std::net::SocketAddr>() {
            Ok(a) => cfg.server.http_listen = a,
            Err(_) => tracing::warn!("BGFLOW_HTTP_LISTEN '{}' is not a valid socket addr — ignored", v),
        }
    }
    if let Ok(v) = std::env::var("BGFLOW_DATA_DIR") {
        if !v.is_empty() {
            cfg.storage.data_dir = std::path::PathBuf::from(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deep_merge_objects_recursive() {
        let mut base = json!({"a": {"x": 1, "y": 2}, "b": [1, 2], "c": "old"});
        deep_merge(&mut base, json!({"a": {"y": 3, "z": 4}, "b": [9], "d": true}));
        assert_eq!(base["a"]["x"], 1);
        assert_eq!(base["a"]["y"], 3);
        assert_eq!(base["a"]["z"], 4);
        assert_eq!(base["b"], json!([9])); // arrays replace wholesale
        assert_eq!(base["c"], "old");       // untouched keys survive
        assert_eq!(base["d"], true);
    }

    #[test]
    fn settings_overlay_merges_and_validates() {
        let dir = std::env::temp_dir().join(format!("bgflow-cfg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sp = dir.join("settings.json");
        std::fs::write(
            &sp,
            r#"{"analytics":{"local_asns":[64512]},"storage":{"max_bytes":1073741824}}"#,
        )
        .unwrap();

        let mut cfg = Config::default();
        cfg.storage.data_dir = dir.clone();
        // Simulate the overlay step directly (load() resolves the path
        // from data_dir, which we just set).
        let p = cfg.storage.data_dir.join("settings.json");
        let ov: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        let mut base = serde_json::to_value(cfg.clone()).unwrap();
        deep_merge(&mut base, ov);
        let merged: Config = serde_json::from_value(base).unwrap();
        assert_eq!(merged.analytics.local_asns, vec![64512]);
        assert_eq!(merged.storage.max_bytes, 1073741824);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn settings_overlay_rejects_invalid() {
        let dir = std::env::temp_dir().join(format!("bgflow-cfg-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("settings.json"), r#"{"storage":{"max_bytes":"junk"}}"#).unwrap();
        let mut cfg = Config::default();
        cfg.storage.data_dir = dir.clone();
        let ov: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("settings.json")).unwrap()).unwrap();
        let mut base = serde_json::to_value(cfg.clone()).unwrap();
        deep_merge(&mut base, ov);
        assert!(serde_json::from_value::<Config>(base).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
