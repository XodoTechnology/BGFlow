//! Label rules engine: match flow records against configured rules and tag
//! them with a `label_id` (rule index + 1). First match wins — order in the
//! config file is the priority order.

use bgflow_types::{country_pack, ip_to_u128, u128_to_ip, FlowRecord};
use crate::config::RuleConfig;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    proto: Option<u8>,
    /// Either-side port match (src_port == p || dst_port == p).
    port: Option<u16>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    /// (masked base, mask) — see crate::query::parse_ip_filter for why the
    /// mask is precomputed (v4 lives in the low 32 bits of the u128).
    src_net: Option<(u128, u128)>,
    dst_net: Option<(u128, u128)>,
    src_asn: Option<u32>,
    dst_asn: Option<u32>,
    src_country: Option<u16>,
    dst_country: Option<u16>,
    exporter: Option<u128>,
    org: Option<String>,
}

pub struct Ruleset {
    /// RwLock so SIGHUP config reload can swap rules without restarting
    /// ingest; readers only hold the lock for the match scan.
    rules: std::sync::RwLock<Vec<Rule>>,
}

/// Parse "a.b.c.d/n" or "addr" into (masked_base, mask). mask=0 matches all.
fn parse_prefix(s: &str) -> Option<(u128, u128)> {
    crate::query::parse_ip_filter(s)
}

fn ip_in_net(ip: u128, net: (u128, u128)) -> bool {
    (ip & net.1) == net.0
}

fn build_rules(items: &[RuleConfig]) -> Vec<Rule> {
    items
            .iter()
            .filter_map(|r| {
                let src_net = r.src_ip.as_deref().and_then(parse_prefix);
                let dst_net = r.dst_ip.as_deref().and_then(parse_prefix);
                if r.src_ip.is_some() && src_net.is_none() {
                    tracing::warn!("rule '{}': bad src_ip prefix {:?}", r.name, r.src_ip);
                    return None;
                }
                if r.dst_ip.is_some() && dst_net.is_none() {
                    tracing::warn!("rule '{}': bad dst_ip prefix {:?}", r.name, r.dst_ip);
                    return None;
                }
                Some(Rule {
                    name: r.name.clone(),
                    proto: r.proto,
                    port: r.port,
                    src_port: r.src_port,
                    dst_port: r.dst_port,
                    src_net,
                    dst_net,
                    src_asn: r.src_asn,
                    dst_asn: r.dst_asn,
                    src_country: r.src_country.as_deref().map(country_pack),
                    dst_country: r.dst_country.as_deref().map(country_pack),
                    exporter: r.exporter.map(|ip| ip_to_u128(&ip)),
                    org: r.org.as_ref().map(|s| s.to_lowercase()),
                })
            })
            .collect()
}

impl Ruleset {
    pub fn from_toml(items: &[RuleConfig]) -> Self {
        Ruleset {
            rules: std::sync::RwLock::new(build_rules(items)),
        }
    }

    /// Hot-reload rules from new config (SIGHUP).
    pub fn reload(&self, items: &[RuleConfig]) {
        *self.rules.write().unwrap() = build_rules(items);
        tracing::info!("rules reloaded: {} rule(s)", self.len());
    }

    /// Evaluate rules; returns label_id (1-based rule index) or 0.
    /// `org_name` resolves org ids to names (may be None if table unavailable).
    pub fn label(&self, f: &FlowRecord, org_name: impl Fn(u32) -> Option<String>) -> u32 {
        let rules = self.rules.read().unwrap();
        for (i, r) in rules.iter().enumerate() {
            if r.matches(f, &org_name) {
                return (i + 1) as u32;
            }
        }
        0
    }

    /// List rules for the API/UI: (id, name).
    pub fn list(&self) -> Vec<(u32, String)> {
        self.rules
            .read()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, r)| ((i + 1) as u32, r.name.clone()))
            .collect()
    }

    /// label_id -> rule name (None if unknown).
    pub fn name_of(&self, id: u32) -> Option<String> {
        if id == 0 {
            return None;
        }
        self.rules
            .read()
            .unwrap()
            .get(id as usize - 1)
            .map(|r| r.name.clone())
    }

    /// All label names as a map (for name->id resolution).
    pub fn names(&self) -> std::collections::HashMap<u32, String> {
        self.rules
            .read()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, r)| ((i + 1) as u32, r.name.clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.rules.read().unwrap().len()
    }
}

impl Rule {
    fn matches(&self, f: &FlowRecord, org_name: &impl Fn(u32) -> Option<String>) -> bool {
        if let Some(p) = self.proto {
            if f.protocol != p {
                return false;
            }
        }
        if let Some(p) = self.port {
            if f.src_port != p && f.dst_port != p {
                return false;
            }
        }
        if let Some(p) = self.src_port {
            if f.src_port != p {
                return false;
            }
        }
        if let Some(p) = self.dst_port {
            if f.dst_port != p {
                return false;
            }
        }
        if let Some(net) = self.src_net {
            if !ip_in_net(f.src_ip, net) {
                return false;
            }
        }
        if let Some(net) = self.dst_net {
            if !ip_in_net(f.dst_ip, net) {
                return false;
            }
        }
        if let Some(a) = self.src_asn {
            if f.src_asn != a {
                return false;
            }
        }
        if let Some(a) = self.dst_asn {
            if f.dst_asn != a {
                return false;
            }
        }
        if let Some(c) = self.src_country {
            if f.src_country != c {
                return false;
            }
        }
        if let Some(c) = self.dst_country {
            if f.dst_country != c {
                return false;
            }
        }
        if let Some(e) = self.exporter {
            if f.exporter != e {
                return false;
            }
        }
        if let Some(org) = &self.org {
            let hit = |id: u32| {
                org_name(id)
                    .map(|n| n.to_lowercase().contains(org.as_str()))
                    .unwrap_or(false)
            };
            if !hit(f.src_org) && !hit(f.dst_org) {
                return false;
            }
        }
        true
    }
}

/// Helper for tests / debugging.
#[allow(dead_code)]
pub fn ip_debug(v: u128) -> IpAddr {
    u128_to_ip(v)
}
