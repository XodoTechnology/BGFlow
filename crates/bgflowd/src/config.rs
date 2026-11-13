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
    /// Multi-user accounts for the UI/API.
    /// [[users]] name = "admin" password_hash = "pbkdf2-sha256$..." role = "admin"
    /// Generate hashes with `bgflowd hash-password`. Roles: admin | viewer.
    #[serde(default)]
    pub users: Vec<crate::auth::UserConfig>,
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
#[serde(default)]
pub struct RuleConfig {
    /// Label name applied when the rule matches.
    pub name: String,
    /// IP protocol number (6=TCP, 17=UDP, ...).
    pub proto: Option<u8>,
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
            users: vec![],
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
    Ok(cfg)
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
