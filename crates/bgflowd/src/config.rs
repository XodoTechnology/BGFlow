//! bgflowd configuration: `bgflow.toml` with sane defaults.

use anyhow::{Context, Result};
use bgflow_netflow::ProtoHint;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub geoip: GeoIpConfig,
    pub inputs: Vec<InputConfig>,
    pub enrichers: Vec<EnricherConfig>,
    pub rules: Vec<RuleConfig>,
    pub demo: DemoConfig,
}

/// Synthetic demo traffic (NetFlow v5) — for trying out the UI.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DemoConfig {
    pub enabled: bool,
    /// Send to this address; defaults to 127.0.0.1:<first input port>.
    pub target: Option<SocketAddr>,
    /// Datagrams per second.
    pub pps: u64,
    /// Flow records per datagram.
    pub flows_per_pkt: usize,
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
            duration_secs: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// HTTP API + UI listen address.
    pub http_listen: SocketAddr,
    /// Optional basic-auth for the UI/API: "user:password".
    pub auth: Option<String>,
    /// Allow CORS on the API (off by default; UI is same-origin).
    pub cors: bool,
}

#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GeoIpConfig {
    /// MaxMind ASN database path (mmdb). Empty disables.
    pub asn_db: String,
    /// MaxMind Country database path (mmdb). Empty disables.
    pub country_db: String,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Default, Deserialize)]
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
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
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
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            http_listen: "0.0.0.0:8080".parse().unwrap(),
            auth: None,
            cors: false,
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
        }
    }
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        GeoIpConfig {
            asn_db: "/usr/share/GeoIP/GeoLite2-ASN.mmdb".into(),
            country_db: "/usr/share/GeoIP/GeoLite2-Country.mmdb".into(),
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

pub fn load(path: Option<&PathBuf>) -> Result<Config> {
    match path {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("cannot read config {}", p.display()))?;
            toml::from_str(&text).with_context(|| format!("cannot parse {}", p.display()))
        }
        None => {
            // Look for bgflow.toml next to the binary / in cwd / /etc/bgflow.
            for cand in [
                PathBuf::from("bgflow.toml"),
                PathBuf::from("/etc/bgflow/bgflow.toml"),
            ] {
                if cand.exists() {
                    return load(Some(&cand));
                }
            }
            Ok(Config::default())
        }
    }
}
