//! Dynamic exporter admission policy.
//!
//! Exporters are whatever IPs send flow data to our listeners. With
//! `[exporters] require_approval = true`, an unknown sender is registered
//! as `pending` and its datagrams are dropped (counted) until an admin
//! approves it via the API. `suspended` and `rejected` senders are always
//! dropped. State persists to `<data_dir>/exporters.json`.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExporterState {
    /// Seen but not yet approved — traffic dropped.
    Pending,
    /// Allowed to send flows.
    Approved,
    /// Manually blocked — traffic dropped until re-approved.
    Suspended,
    /// Blocked; stays blocked across restarts. Remove the entry to let it
    /// re-appear as pending on its next datagram.
    Rejected,
}

impl ExporterState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Suspended => "suspended",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyEntry {
    pub state: ExporterState,
    #[serde(default)]
    pub first_seen_ms: u64,
    #[serde(default)]
    pub last_seen_ms: u64,
    #[serde(default)]
    pub approved_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// UI-set display name (overrides [exporter_names] config).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Per-exporter VLAN names (VID → label). Device-local meaning, so
    /// these live per exporter rather than in global [vlan_names].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vlans: BTreeMap<u16, String>,
    /// Per-exporter interface names (ifIndex → label).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub interfaces: BTreeMap<u32, String>,
    /// Per-exporter SNMPv2c community — overrides the global [snmp]
    /// community for this device only. None = use global.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snmp_community: Option<String>,
    /// Per-exporter SNMP port override (non-161 agents).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snmp_port: Option<u16>,
    /// Skip SNMP polling for this exporter even when globally enabled.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub snmp_disabled: bool,
    /// Datagrams/bytes dropped by this policy since process start
    /// (not persisted — informational only).
    #[serde(skip)]
    pub dropped_datagrams: u64,
    #[serde(skip)]
    pub dropped_bytes: u64,
}

/// What to do with traffic from an IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Accept,
    /// Drop, and this is the state that caused it.
    Drop(ExporterState),
}

pub struct ExporterPolicy {
    inner: Mutex<Inner>,
    path: PathBuf,
}

struct Inner {
    map: HashMap<IpAddr, PolicyEntry>,
    require_approval: bool,
    /// (masked base, mask) pairs — exact IPs are just /32·/128 entries.
    /// Parsed from config strings like "10.0.0.1" or "192.168.0.0/16".
    trusted: Vec<(u128, u128)>,
}

#[derive(Serialize, Deserialize, Default)]
struct FileRepr {
    version: u32,
    #[serde(default)]
    exporters: HashMap<IpAddr, PolicyEntry>,
}

impl ExporterPolicy {
    pub fn open(path: PathBuf, require_approval: bool, trusted: Vec<String>) -> Self {
        let map = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<FileRepr>(&b).ok())
            .map(|f| f.exporters)
            .unwrap_or_default();
        Self {
            inner: Mutex::new(Inner {
                map,
                require_approval,
                trusted: parse_trusted(&trusted),
            }),
            path,
        }
    }

    /// Called for every inbound datagram/connection. Registers unknown
    /// senders as pending when approval is required.
    ///
    /// Precedence: explicit suspended/rejected entries always drop;
    /// trusted IPs/CIDRs accept (even over a stale pending entry);
    /// approved accepts; pending drops; unknown pends when required.
    pub fn decide(&self, ip: IpAddr, now_ms: u64) -> Decision {
        let mut g = self.inner.lock().unwrap();
        let trusted = Self::is_trusted_locked(&g, ip);
        match g.map.get_mut(&ip) {
            Some(e) => {
                e.last_seen_ms = now_ms;
                match e.state {
                    ExporterState::Suspended | ExporterState::Rejected => {
                        Decision::Drop(e.state)
                    }
                    ExporterState::Approved => Decision::Accept,
                    ExporterState::Pending => {
                        if trusted {
                            Decision::Accept
                        } else {
                            Decision::Drop(ExporterState::Pending)
                        }
                    }
                }
            }
            None => {
                if trusted {
                    return Decision::Accept;
                }
                if g.require_approval {
                    g.map.insert(
                        ip,
                        PolicyEntry {
                            state: ExporterState::Pending,
                            first_seen_ms: now_ms,
                            last_seen_ms: now_ms,
                            ..Default::default()
                        },
                    );
                    self.save_locked(&g);
                    Decision::Drop(ExporterState::Pending)
                } else {
                    Decision::Accept
                }
            }
        }
    }

    /// Record a dropped datagram against the sender's entry (best effort —
    /// creates a minimal entry so the drop is visible in the API).
    pub fn note_drop(&self, ip: IpAddr, datagrams: u64, bytes: u64, now_ms: u64) {
        let mut g = self.inner.lock().unwrap();
        let default_state = if g.require_approval {
            ExporterState::Pending
        } else {
            ExporterState::Approved
        };
        let e = g.map.entry(ip).or_insert_with(|| PolicyEntry {
            state: default_state,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            ..Default::default()
        });
        e.dropped_datagrams += datagrams;
        e.dropped_bytes += bytes;
    }

    /// Current policy state for an IP, if it has an entry.
    pub fn state_of(&self, ip: IpAddr) -> Option<ExporterState> {
        self.inner.lock().unwrap().map.get(&ip).map(|e| e.state)
    }

    /// Snapshot of all policy entries (ip → entry clone).
    pub fn entries(&self) -> HashMap<IpAddr, PolicyEntry> {
        self.inner.lock().unwrap().map.clone()
    }

    /// Whether the IP matches a configured trusted entry (IP or CIDR).
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        let g = self.inner.lock().unwrap();
        Self::is_trusted_locked(&g, ip)
    }

    fn is_trusted_locked(g: &Inner, ip: IpAddr) -> bool {
        let v = bgflow_types::ip_to_u128(&ip);
        g.trusted.iter().any(|(b, m)| v & m == *b)
    }

    pub fn require_approval(&self) -> bool {
        self.inner.lock().unwrap().require_approval
    }

    /// Set approve/suspend/reject. Creates the entry if absent.
    /// Returns the resulting state.
    pub fn set_state(&self, ip: IpAddr, state: ExporterState, now_ms: u64, note: Option<String>) -> ExporterState {
        let mut g = self.inner.lock().unwrap();
        let e = g.map.entry(ip).or_insert_with(|| PolicyEntry {
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            ..Default::default()
        });
        e.state = state;
        if state == ExporterState::Approved {
            e.approved_at_ms = now_ms;
        }
        if note.is_some() {
            e.note = note;
        }
        let st = e.state;
        drop(g);
        self.save();
        st
    }

    /// Set/clear the display name (None clears). Creates the entry if the
    /// IP has never been seen — naming alone doesn't admit traffic.
    pub fn set_name(&self, ip: IpAddr, name: Option<String>, now_ms: u64) {
        let mut g = self.inner.lock().unwrap();
        let e = g.map.entry(ip).or_insert_with(|| PolicyEntry {
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            ..Default::default()
        });
        e.name = name.filter(|n| !n.trim().is_empty());
        drop(g);
        self.save();
    }

    /// Replace the VLAN name map for an exporter (empty clears). Creates
    /// the entry if absent — labels alone don't admit traffic.
    pub fn set_vlans(&self, ip: IpAddr, vlans: BTreeMap<u16, String>, now_ms: u64) {
        let mut g = self.inner.lock().unwrap();
        let e = g.map.entry(ip).or_insert_with(|| PolicyEntry {
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            ..Default::default()
        });
        e.vlans = vlans;
        drop(g);
        self.save();
    }

    /// Replace the interface name map for an exporter (empty clears).
    pub fn set_interfaces(&self, ip: IpAddr, ifs: BTreeMap<u32, String>, now_ms: u64) {
        let mut g = self.inner.lock().unwrap();
        let e = g.map.entry(ip).or_insert_with(|| PolicyEntry {
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            ..Default::default()
        });
        e.interfaces = ifs;
        drop(g);
        self.save();
    }

    /// Replace this exporter's SNMP overrides. `community: None` and
    /// `port: None` fall back to the global [snmp] settings; an empty
    /// community string is treated as None. `disabled` skips polling.
    pub fn set_snmp(
        &self,
        ip: IpAddr,
        community: Option<String>,
        port: Option<u16>,
        disabled: bool,
        now_ms: u64,
    ) {
        let mut g = self.inner.lock().unwrap();
        let e = g.map.entry(ip).or_insert_with(|| PolicyEntry {
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            ..Default::default()
        });
        e.snmp_community = community.filter(|s| !s.trim().is_empty());
        e.snmp_port = port.filter(|p| *p > 0);
        e.snmp_disabled = disabled;
        drop(g);
        self.save();
    }

    /// All per-exporter VLAN names (ip → vid → name), for name merging.
    pub fn vlan_labels(&self) -> HashMap<IpAddr, BTreeMap<u16, String>> {
        self.inner
            .lock()
            .unwrap()
            .map
            .iter()
            .filter(|(_, e)| !e.vlans.is_empty())
            .map(|(ip, e)| (*ip, e.vlans.clone()))
            .collect()
    }

    /// All per-exporter interface names (ip → ifindex → name).
    pub fn interface_labels(&self) -> HashMap<IpAddr, BTreeMap<u32, String>> {
        self.inner
            .lock()
            .unwrap()
            .map
            .iter()
            .filter(|(_, e)| !e.interfaces.is_empty())
            .map(|(ip, e)| (*ip, e.interfaces.clone()))
            .collect()
    }

    /// Remove an entry entirely — next datagram re-registers it (as
    /// pending when approval is required, invisible otherwise).
    pub fn remove(&self, ip: IpAddr) -> bool {
        let mut g = self.inner.lock().unwrap();
        let removed = g.map.remove(&ip).is_some();
        drop(g);
        if removed {
            self.save();
        }
        removed
    }

    /// Update runtime knobs (config reload). Does not touch entries.
    pub fn set_knobs(&self, require_approval: bool, trusted: Vec<String>) {
        let mut g = self.inner.lock().unwrap();
        g.require_approval = require_approval;
        g.trusted = parse_trusted(&trusted);
    }

    fn save(&self) {
        let g = self.inner.lock().unwrap();
        self.save_locked(&g);
    }

    fn save_locked(&self, g: &Inner) {
        // Only persist entries with a non-default lifecycle — approved
        // entries created implicitly shouldn't spam the file. But once an
        // admin acts (approve/suspend/reject/note) or it pends, keep it.
        let exporters: HashMap<IpAddr, PolicyEntry> = g
            .map
            .iter()
            .filter(|(_, e)| {
                e.state != ExporterState::Approved
                    || e.note.is_some()
                    || e.name.is_some()
                    || !e.vlans.is_empty()
                    || !e.interfaces.is_empty()
                    || e.snmp_community.is_some()
                    || e.snmp_port.is_some()
                    || e.snmp_disabled
                    || e.approved_at_ms > 0
            })
            .map(|(k, v)| {
                let mut c = v.clone();
                c.dropped_datagrams = 0;
                c.dropped_bytes = 0;
                (*k, c)
            })
            .collect();
        let f = FileRepr {
            version: 1,
            exporters,
        };
        if let Ok(bytes) = serde_json::to_vec_pretty(&f) {
            let tmp = self.path.with_extension("json.tmp");
            if std::fs::write(&tmp, bytes).is_ok() {
                // May contain per-exporter SNMP communities — owner-only.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &tmp,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }
}

/// Parse trusted entries: plain IPs and CIDRs ("10.0.0.0/8").
/// Invalid entries are skipped.
fn parse_trusted(entries: &[String]) -> Vec<(u128, u128)> {
    entries
        .iter()
        .filter_map(|s| crate::query::parse_ip_filter(s.trim()))
        .collect()
}

impl Default for ExporterState {
    fn default() -> Self {
        Self::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_flow() {
        let dir = std::env::temp_dir().join(format!("bgflow-pol-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = ExporterPolicy::open(dir.join("exporters.json"), true, vec![]);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(p.decide(ip, 1000), Decision::Drop(ExporterState::Pending));
        assert_eq!(p.decide(ip, 1001), Decision::Drop(ExporterState::Pending));
        p.set_state(ip, ExporterState::Approved, 2000, None);
        assert_eq!(p.decide(ip, 2001), Decision::Accept);
        p.set_state(ip, ExporterState::Suspended, 3000, None);
        assert_eq!(p.decide(ip, 3001), Decision::Drop(ExporterState::Suspended));
        p.set_state(ip, ExporterState::Approved, 4000, None);
        assert_eq!(p.decide(ip, 4001), Decision::Accept);
    }

    #[test]
    fn auto_accept_when_not_required() {
        let dir = std::env::temp_dir().join(format!("bgflow-pol2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = ExporterPolicy::open(dir.join("exporters.json"), false, vec![]);
        let ip: IpAddr = "192.0.2.2".parse().unwrap();
        assert_eq!(p.decide(ip, 1000), Decision::Accept);
        assert!(p.entries().is_empty());
        // But manual suspension still applies.
        p.set_state(ip, ExporterState::Suspended, 1001, None);
        assert_eq!(p.decide(ip, 1002), Decision::Drop(ExporterState::Suspended));
    }

    #[test]
    fn trusted_bypasses() {
        let dir = std::env::temp_dir().join(format!("bgflow-pol3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = ExporterPolicy::open(
            dir.join("exporters.json"),
            true,
            vec!["10.0.0.1".into(), "192.168.0.0/16".into()],
        );
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(p.decide(ip, 1000), Decision::Accept);
        assert!(p.entries().is_empty());
        assert!(p.is_trusted(ip));
        let in_cidr: IpAddr = "192.168.5.9".parse().unwrap();
        assert!(p.is_trusted(in_cidr));
        assert_eq!(p.decide(in_cidr, 1000), Decision::Accept);
        let out: IpAddr = "192.167.5.9".parse().unwrap();
        assert!(!p.is_trusted(out));
        // Explicit suspend beats trusted.
        p.set_state(ip, ExporterState::Suspended, 1001, None);
        assert_eq!(p.decide(ip, 1002), Decision::Drop(ExporterState::Suspended));
    }

    #[test]
    fn persists_across_restart() {
        let dir = std::env::temp_dir().join(format!("bgflow-pol4-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("exporters.json");
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        {
            let p = ExporterPolicy::open(path.clone(), true, vec![]);
            p.decide(ip, 1000);
            p.set_state(ip, ExporterState::Suspended, 1001, Some("test".into()));
        }
        let p2 = ExporterPolicy::open(path, true, vec![]);
        assert_eq!(p2.state_of(ip), Some(ExporterState::Suspended));
        assert_eq!(p2.decide(ip, 2000), Decision::Drop(ExporterState::Suspended));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
