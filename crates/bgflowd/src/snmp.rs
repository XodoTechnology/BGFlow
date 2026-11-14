//! Optional SNMP enrichment: polls exporters for interface names
//! (IF-MIB/ifXTable), VLAN names (Q-BRIDGE-MIB) and basic device info.
//! Learned names only fill gaps — `[interface_names]`/`[vlan_names]`
//! config and UI-set per-exporter labels always take precedence.
//!
//! Enabled via `[snmp]` in bgflow.toml; uses SNMPv2c community auth.

use crate::config::SnmpConfig;
use crate::exporter_policy::ExporterPolicy;
use crate::metrics::now_ms;
use snmp2::{Oid, SyncSession, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Learned SNMP data per exporter IP.
pub type SnmpStore = Arc<RwLock<HashMap<IpAddr, ExporterSnmp>>>;

pub fn new_store() -> SnmpStore {
    Arc::new(RwLock::new(HashMap::new()))
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct IfaceInfo {
    pub name: String,
    /// ifOperStatus: 1=up, 2=down, 3=testing.
    pub oper_status: u8,
    pub speed_mbps: u64,
    pub in_errors: u64,
    pub out_errors: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ExporterSnmp {
    pub sys_descr: String,
    /// sysUpTime in milliseconds (0 = unknown).
    pub sys_uptime_ms: u64,
    pub polled_ms: u64,
    /// Last poll error, if any (cleared on success).
    pub error: Option<String>,
    pub interfaces: BTreeMap<u32, IfaceInfo>,
    pub vlans: BTreeMap<u16, String>,
}

// Column OIDs (u64 subids — asn1-rs Oid::from takes u64).
const IF_NAME_COL: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1]; // ifXTable.ifName
const IF_DESCR_COL: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2]; // ifTable.ifDescr
const IF_ALIAS_COL: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18]; // ifXTable.ifAlias
const IF_OPER_COL: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 8]; // ifTable.ifOperStatus
const IF_HISPEED_COL: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 15]; // ifXTable.ifHighSpeed
const IF_INERR_COL: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 14]; // ifTable.ifInErrors
const IF_OUTERR_COL: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 19]; // ifTable.ifOutErrors
const VLAN_NAME_COL: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 5, 1, 3]; // dot1qVlanStaticName
const SYS_DESCR: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
const SYS_UPTIME: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];

/// Poll loop: every `interval_secs`, SNMP-poll approved+pending
/// exporters in one blocking task (sync socket API) and refresh the
/// shared store the API/UI reads.
pub async fn run(store: SnmpStore, policy: Arc<ExporterPolicy>, cfg: SnmpConfig) {
    let mut tick = tokio::time::interval(Duration::from_secs(cfg.interval_secs.max(60)));
    tick.tick().await; // skip the immediate first tick — give exporters a moment
    loop {
        tick.tick().await;
        // Resolve credentials per exporter: entry overrides win over the
        // global [snmp] community/port; snmp_disabled opts out entirely.
        let targets: Vec<(IpAddr, String, u16)> = policy
            .entries()
            .iter()
            .filter(|(_, e)| {
                matches!(
                    e.state,
                    crate::exporter_policy::ExporterState::Approved
                        | crate::exporter_policy::ExporterState::Pending
                ) && !e.snmp_disabled
            })
            .map(|(ip, e)| {
                (
                    *ip,
                    e.snmp_community
                        .clone()
                        .unwrap_or_else(|| cfg.community.clone()),
                    e.snmp_port.unwrap_or(cfg.port),
                )
            })
            .collect();
        if targets.is_empty() {
            continue;
        }
        let st = store.clone();
        let c = cfg.clone();
        // Whole-sweep deadline: parallel polls mean the sweep lasts about
        // as long as the slowest single agent (≤30s each), not the sum —
        // dead exporters can no longer stall the loop for many minutes.
        let sweep_deadline = Instant::now() + Duration::from_secs(cfg.interval_secs.max(60));
        // Bound concurrent blocking SNMP sessions.
        let sem = Arc::new(tokio::sync::Semaphore::new(32));
        let mut handles = Vec::with_capacity(targets.len());
        for (ip, community, port) in targets {
            let st = st.clone();
            let c = c.clone();
            let sem = sem.clone();
            handles.push(tokio::spawn(async move {
                let Ok(_permit) = sem.acquire().await else {
                    return;
                };
                let res = tokio::task::spawn_blocking(move || {
                    poll_exporter(ip, &community, port, &c, sweep_deadline)
                })
                .await;
                if let Ok(mut info) = res {
                    info.polled_ms = now_ms();
                    st.write().unwrap().insert(ip, info);
                }
            }));
        }
        for h in handles {
            let _ = h.await;
        }
    }
}

fn oid(subids: &[u64]) -> Oid<'static> {
    Oid::from(subids).expect("static OID")
}

fn val_str(v: &Value) -> Option<String> {
    if let Value::OctetString(b) = v {
        let s = String::from_utf8_lossy(b).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    } else {
        None
    }
}

fn val_num(v: &Value) -> Option<u64> {
    match v {
        Value::Integer(i) => u64::try_from(*i).ok(),
        Value::Unsigned32(n) => Some(u64::from(*n)),
        Value::Counter32(n) => Some(u64::from(*n)),
        Value::Counter64(n) => Some(*n),
        Value::Timeticks(t) => Some(u64::from(*t)),
        _ => None,
    }
}

/// GETBULK-walk one column subtree; `f` receives (last_subid, value)
/// for each varbind inside the column. Stops at the subtree boundary,
/// end-of-mib, or the overall deadline.
fn walk_col<F: FnMut(u64, &Value)>(
    sess: &mut SyncSession,
    col: &Oid<'static>,
    deadline: Instant,
    f: &mut F,
) -> Result<(), String> {
    let mut next = col.clone();
    loop {
        if Instant::now() > deadline {
            return Ok(());
        }
        let pdu = sess
            .getbulk(&[&next], 0, 25)
            .map_err(|e| format!("getbulk: {}", e))?;
        let mut last: Option<Oid<'static>> = None;
        let mut inside = 0usize;
        for (oid_v, val) in pdu.varbinds {
            if !oid_v.starts_with(col)
                || matches!(
                    val,
                    Value::EndOfMibView | Value::NoSuchObject | Value::NoSuchInstance
                )
            {
                return Ok(());
            }
            let idx = oid_v.iter().and_then(|it| it.last()).unwrap_or(0);
            f(idx, &val);
            last = Some(oid_v.to_owned());
            inside += 1;
        }
        if inside == 0 {
            return Ok(());
        }
        match last {
            Some(o) => next = o,
            None => return Ok(()),
        }
    }
}

fn poll_exporter(
    ip: IpAddr,
    community: &str,
    port: u16,
    cfg: &SnmpConfig,
    sweep_deadline: Instant,
) -> ExporterSnmp {
    let mut info = ExporterSnmp::default();
    let addr = if ip.is_ipv6() {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    };
    let mut sess = match SyncSession::new_v2c(
        &addr,
        community.as_bytes(),
        Some(Duration::from_secs(cfg.timeout_secs.max(1))),
        0,
    ) {
        Ok(s) => s,
        Err(e) => {
            info.error = Some(format!("session: {}", e));
            return info;
        }
    };
    // Whole-poll deadline — a dead/blackholed agent shouldn't stall the
    // poller (each request already has the session timeout), and the
    // sweep deadline keeps one slow agent from eating the whole budget.
    let deadline = (Instant::now() + Duration::from_secs(30)).min(sweep_deadline);
    // Track whether the agent answered at all — an unreachable host or
    // wrong community otherwise looks identical to "device has no
    // interfaces", which is confusing in the UI.
    let mut req_ok = false;
    let mut req_fail = 0u32;

    // Scalars: sysDescr + sysUpTime (best-effort).
    for (col, is_up) in [(oid(SYS_DESCR), false), (oid(SYS_UPTIME), true)] {
        match sess.get(&col) {
            Ok(mut pdu) => {
                req_ok = true;
                if let Some((_, v)) = pdu.varbinds.next() {
                    if is_up {
                        info.sys_uptime_ms = val_num(&v).unwrap_or(0).saturating_mul(10);
                    } else if let Some(s) = val_str(&v) {
                        info.sys_descr = s;
                    }
                }
            }
            Err(_) => req_fail += 1,
        }
    }

    // Interface names: alias > name > descr (per ifIndex).
    let mut alias: BTreeMap<u32, String> = BTreeMap::new();
    let mut name: BTreeMap<u32, String> = BTreeMap::new();
    let mut descr: BTreeMap<u32, String> = BTreeMap::new();
    for (col, dst) in [
        (oid(IF_ALIAS_COL), &mut alias),
        (oid(IF_NAME_COL), &mut name),
        (oid(IF_DESCR_COL), &mut descr),
    ] {
        match walk_col(&mut sess, &col, deadline, &mut |i, v| {
            if let (Ok(i), Some(s)) = (u32::try_from(i), val_str(v)) {
                dst.insert(i, s);
            }
        }) {
            Ok(()) => req_ok = true,
            Err(_) => req_fail += 1,
        }
    }
    let mut oper: BTreeMap<u32, u64> = BTreeMap::new();
    let mut speed: BTreeMap<u32, u64> = BTreeMap::new();
    let mut in_err: BTreeMap<u32, u64> = BTreeMap::new();
    let mut out_err: BTreeMap<u32, u64> = BTreeMap::new();
    for (col, dst) in [
        (oid(IF_OPER_COL), &mut oper),
        (oid(IF_HISPEED_COL), &mut speed),
        (oid(IF_INERR_COL), &mut in_err),
        (oid(IF_OUTERR_COL), &mut out_err),
    ] {
        match walk_col(&mut sess, &col, deadline, &mut |i, v| {
            if let Ok(i) = u32::try_from(i) {
                if let Some(n) = val_num(v) {
                    dst.insert(i, n);
                }
            }
        }) {
            Ok(()) => req_ok = true,
            Err(_) => req_fail += 1,
        }
    }
    // Merge name sources + stats into per-interface records.
    let keys: std::collections::BTreeSet<u32> = alias
        .keys()
        .chain(name.keys())
        .chain(descr.keys())
        .chain(oper.keys())
        .chain(speed.keys())
        .copied()
        .collect();
    for i in keys {
        let n = alias
            .get(&i)
            .or_else(|| name.get(&i))
            .or_else(|| descr.get(&i))
            .cloned()
            .unwrap_or_default();
        info.interfaces.insert(
            i,
            IfaceInfo {
                name: n,
                oper_status: oper.get(&i).map(|v| *v as u8).unwrap_or(0),
                speed_mbps: speed.get(&i).copied().unwrap_or(0),
                in_errors: in_err.get(&i).copied().unwrap_or(0),
                out_errors: out_err.get(&i).copied().unwrap_or(0),
            },
        );
    }

    // VLAN names (Q-BRIDGE-MIB dot1qVlanStaticName; index = VLAN id).
    let mut vlans: BTreeMap<u16, String> = BTreeMap::new();
    match walk_col(&mut sess, &oid(VLAN_NAME_COL), deadline, &mut |i, v| {
        if let (Ok(i), Some(s)) = (u16::try_from(i), val_str(v)) {
            vlans.insert(i, s);
        }
    }) {
        Ok(()) => req_ok = true,
        Err(_) => req_fail += 1,
    }
    info.vlans = vlans;

    // Surface reachability problems instead of an empty-but-quiet result.
    if !req_ok && req_fail > 0 {
        info.error = Some(format!(
            "no SNMP response ({} request(s) failed) — check community, ACLs, agent",
            req_fail
        ));
    } else if req_ok
        && info.sys_descr.is_empty()
        && info.interfaces.is_empty()
        && info.vlans.is_empty()
    {
        info.error = Some("agent responded but returned no interface/VLAN data".into());
    }
    info
}
