//! Entity and config views: exporters, interfaces, VLANs, labels, enrichers, alerts, config.

use super::*;

pub(super) async fn exporters(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let map = st.metrics.exporters.lock().unwrap();
    let names = st.ctx.exporter_names.read().unwrap();
    let policy = st.exporter_policy.entries();
    let snmp_map = st.snmp.read().unwrap();
    let naming = st.ctx.naming.read().unwrap();
    let require = st.exporter_policy.require_approval();
    // Union of observed senders (metrics) and policy-known IPs — pending
    // exporters appear here even though their traffic is dropped.
    let ips: std::collections::BTreeSet<IpAddr> =
        map.keys().chain(policy.keys()).copied().collect();
    let mut items: Vec<_> = ips
        .into_iter()
        .map(|ip| {
            let e = map.get(&ip);
            let p = policy.get(&ip);
            let u = ip_to_u128(&ip);
            // Same precedence as the ingest decision: explicit
            // suspend/reject wins, then trusted, then entry state.
            let state = match p.map(|p| p.state) {
                Some(crate::exporter_policy::ExporterState::Suspended) => "suspended",
                Some(crate::exporter_policy::ExporterState::Rejected) => "rejected",
                _ if st.exporter_policy.is_trusted(ip) => "trusted",
                Some(s) => s.as_str(),
                None if require => "pending",
                None => "active",
            };
            // Effective per-exporter names: `naming` config lines as
            // the base, UI-set policy labels overriding per-key (they
            // are the runtime source of truth). SNMP-learned names are
            // emitted separately under "snmp".
            let mut vlans: std::collections::BTreeMap<u16, String> = naming
                .vlans_for(u)
                .map(|h| h.iter().map(|(k, v)| (*k, v.clone())).collect())
                .unwrap_or_default();
            let mut ifs: std::collections::BTreeMap<u32, String> = naming
                .ifs_for(u)
                .map(|h| h.iter().map(|(k, v)| (*k, v.clone())).collect())
                .unwrap_or_default();
            if let Some(pe) = p {
                vlans.extend(pe.vlans.iter().map(|(k, v)| (*k, v.clone())));
                ifs.extend(pe.interfaces.iter().map(|(k, v)| (*k, v.clone())));
            }
            let name = p
                .and_then(|x| x.name.clone())
                .or_else(|| naming.exporter_name(u).map(str::to_string))
                .or_else(|| names.name_of(u).map(str::to_string));
            serde_json::json!({
                "ip": ip.to_string(),
                "name": name,
                "datagrams": e.map(|x| x.datagrams).unwrap_or(0),
                "records": e.map(|x| x.records).unwrap_or(0),
                "bytes_in": e.map(|x| x.bytes_in).unwrap_or(0),
                "last_seen_ms": e.map(|x| x.last_seen_ms)
                    .or_else(|| p.map(|x| x.last_seen_ms))
                    .unwrap_or(0),
                "state": state,
                "first_seen_ms": p.map(|x| x.first_seen_ms).unwrap_or(0),
                "approved_at_ms": p.map(|x| x.approved_at_ms).unwrap_or(0),
                "note": p.and_then(|x| x.note.clone()),
                "vlans": vlans,
                "interfaces": ifs,
                // SNMP overrides — community itself is never echoed,
                // only whether a per-exporter one is set.
                "snmp_community_set": p.map(|x| x.snmp_community.is_some()).unwrap_or(false),
                "snmp_port": p.and_then(|x| x.snmp_port),
                "snmp_disabled": p.map(|x| x.snmp_disabled).unwrap_or(false),
                "dropped_datagrams": p.map(|x| x.dropped_datagrams).unwrap_or(0),
                "dropped_bytes": p.map(|x| x.dropped_bytes).unwrap_or(0),
                "snmp": snmp_map.get(&ip),
            })
        })
        .collect();
    // Surface attention-needed senders first: pending, then suspended/
    // rejected, then active/approved by recent activity.
    items.sort_by(|a, b| {
        let rank = |s: &str| match s {
            "pending" => 0,
            "suspended" => 1,
            "rejected" => 2,
            _ => 3,
        };
        rank(a["state"].as_str().unwrap_or(""))
            .cmp(&rank(b["state"].as_str().unwrap_or("")))
            .then(b["last_seen_ms"].as_u64().cmp(&a["last_seen_ms"].as_u64()))
    });
    Json(serde_json::json!({
        "items": items,
        "require_approval": require,
    }))
}

/// POST /api/v1/exporters/{ip}/name — {"name": "edge-rtr"} sets a display
/// name (persisted in exporters.json, overrides [exporter_names]);
/// {"name": ""} clears the override. Admin only.
pub(super) async fn exporter_rename(
    State(st): State<Arc<AppState>>,
    Path(ip_s): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let ip: IpAddr = ip_s
        .parse()
        .map_err(|_| err(format!("bad exporter ip: {}", ip_s)))?;
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string());
    let now = crate::metrics::now_ms();
    st.exporter_policy.set_name(ip, name.clone(), now);
    // Mirror into the runtime name table so top dims / flow rows pick it
    // up immediately. Clearing falls back to the [exporter_names] config.
    let u = bgflow_types::ip_to_u128(&ip);
    let effective = match &name {
        Some(n) => Some(n.clone()),
        None => st.config.read().unwrap().exporter_names.get(&ip_s).cloned(),
    };
    st.ctx
        .exporter_names
        .write()
        .unwrap()
        .set_name(u, effective);
    st.metrics.bump_config_gen();
    tracing::info!("exporter {} renamed to {:?}", ip, name);
    Ok(Json(
        serde_json::json!({"ok": true, "ip": ip_s, "name": name}),
    ))
}

/// POST /api/v1/exporters/{ip}/vlans — {"vlans": {"250": "Cogent"}}
/// replaces the exporter's VLAN name map ({"vlans": {}} clears). Admin only.
pub(super) async fn exporter_vlans(
    State(st): State<Arc<AppState>>,
    Path(ip_s): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let ip: IpAddr = ip_s
        .parse()
        .map_err(|_| err(format!("bad exporter ip: {}", ip_s)))?;
    let mut map = std::collections::BTreeMap::new();
    if let Some(obj) = body.get("vlans").and_then(|v| v.as_object()) {
        for (k, v) in obj.iter().take(1024) {
            let vid: u16 = k.parse().map_err(|_| err(format!("bad vlan id: {}", k)))?;
            if let Some(name) = v.as_str() {
                let name = name.trim();
                if !name.is_empty() && name.len() <= 64 {
                    map.insert(vid, name.to_string());
                }
            }
        }
    }
    let now = crate::metrics::now_ms();
    st.exporter_policy.set_vlans(ip, map.clone(), now);
    st.metrics.bump_config_gen();
    Ok(Json(
        serde_json::json!({"ok": true, "ip": ip_s, "vlans": map}),
    ))
}

/// POST /api/v1/exporters/{ip}/interfaces — {"interfaces": {"1": "xe-0/0/0"}}
/// replaces the exporter's interface name map. Admin only.
pub(super) async fn exporter_interfaces(
    State(st): State<Arc<AppState>>,
    Path(ip_s): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let ip: IpAddr = ip_s
        .parse()
        .map_err(|_| err(format!("bad exporter ip: {}", ip_s)))?;
    let mut map = std::collections::BTreeMap::new();
    if let Some(obj) = body.get("interfaces").and_then(|v| v.as_object()) {
        for (k, v) in obj.iter().take(1024) {
            let idx: u32 = k.parse().map_err(|_| err(format!("bad ifindex: {}", k)))?;
            if let Some(name) = v.as_str() {
                let name = name.trim();
                if !name.is_empty() && name.len() <= 64 {
                    map.insert(idx, name.to_string());
                }
            }
        }
    }
    let now = crate::metrics::now_ms();
    st.exporter_policy.set_interfaces(ip, map.clone(), now);
    st.metrics.bump_config_gen();
    Ok(Json(
        serde_json::json!({"ok": true, "ip": ip_s, "interfaces": map}),
    ))
}

/// POST /api/v1/exporters/{ip}/snmp — PATCH-style SNMP overrides.
/// Each field is independent: absent = unchanged, null/"" = clear back
/// to the global [snmp] settings, value = set. The community is a
/// secret — it is never returned by the API, and an absent field
/// preserves whatever is stored without the caller needing to know it.
/// Admin only.
pub(super) async fn exporter_snmp(
    State(st): State<Arc<AppState>>,
    Path(ip_s): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let ip: IpAddr = ip_s
        .parse()
        .map_err(|_| err(format!("bad exporter ip: {}", ip_s)))?;
    // Current overrides — absent request fields inherit these so the
    // secret community survives PATCHes that don't mention it.
    let cur = st.exporter_policy.entries().remove(&ip);
    let (cur_comm, cur_port, cur_dis) = cur
        .map(|e| (e.snmp_community, e.snmp_port, e.snmp_disabled))
        .unwrap_or_default();

    let community = match body.get("community") {
        Some(serde_json::Value::String(s)) => Some(s.trim().to_string()),
        Some(serde_json::Value::Null) => None,
        None => cur_comm,
        _ => return Err(err("community must be a string")),
    };
    if let Some(c) = &community {
        if c.len() > 256 {
            return Err(err("community too long"));
        }
    }
    let port = match body.get("port") {
        Some(serde_json::Value::Null) => None,
        Some(v) => {
            let p = v
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .filter(|p| *p > 0)
                .ok_or_else(|| err("port must be 1-65535"))?;
            Some(p)
        }
        None => cur_port,
    };
    let disabled = match body.get("disabled") {
        Some(v) => v.as_bool().ok_or_else(|| err("disabled must be a bool"))?,
        None => cur_dis,
    };
    let comm_set = community.as_ref().is_some_and(|c| !c.is_empty());
    let now = crate::metrics::now_ms();
    st.exporter_policy
        .set_snmp(ip, community, port, disabled, now);
    st.metrics.bump_config_gen();
    Ok(Json(serde_json::json!({
        "ok": true,
        "ip": ip_s,
        "snmp_community_set": comm_set,
        "snmp_port": port,
        "snmp_disabled": disabled,
    })))
}

/// POST /api/v1/exporters/{ip}/{action} — approve|suspend|reject|remove.
/// Admin role only (enforced by middleware path check).
pub(super) async fn exporter_action(
    State(st): State<Arc<AppState>>,
    Path((ip_s, action)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    use crate::exporter_policy::ExporterState;
    let ip: IpAddr = ip_s
        .parse()
        .map_err(|_| err(format!("bad exporter ip: {}", ip_s)))?;
    let now = crate::metrics::now_ms();
    let st_out = match action.as_str() {
        "approve" => st
            .exporter_policy
            .set_state(ip, ExporterState::Approved, now, None),
        "suspend" => st
            .exporter_policy
            .set_state(ip, ExporterState::Suspended, now, None),
        "reject" => st
            .exporter_policy
            .set_state(ip, ExporterState::Rejected, now, None),
        "remove" => {
            let removed = st.exporter_policy.remove(ip);
            st.metrics.bump_config_gen();
            return Ok(Json(serde_json::json!({"ok": removed, "ip": ip_s})));
        }
        _ => return Err(err("action must be approve|suspend|reject|remove")),
    };
    st.metrics.bump_config_gen();
    tracing::info!("exporter {} -> {}", ip, st_out.as_str());
    Ok(Json(serde_json::json!({
        "ok": true,
        "ip": ip_s,
        "state": st_out.as_str(),
    })))
}

/// Merge per-exporter labels into a global name map: a key named
/// identically on every exporter that defines it is unambiguous and can
/// be shown in aggregated views (top dims, filters). Conflicting names
/// stay per-exporter only.
pub(super) fn merge_unanimous<V: Ord + Clone>(
    global: &std::collections::BTreeMap<V, String>,
    per_exporter: Vec<&std::collections::BTreeMap<V, String>>,
) -> std::collections::BTreeMap<V, String> {
    let mut map = global.clone();
    let mut votes: std::collections::BTreeMap<V, std::collections::BTreeMap<String, usize>> =
        Default::default();
    for m in per_exporter {
        for (k, n) in m {
            *votes
                .entry(k.clone())
                .or_default()
                .entry(n.clone())
                .or_default() += 1;
        }
    }
    for (k, names) in votes {
        if names.len() == 1 {
            if let Some(n) = names.keys().next() {
                map.insert(k, n.clone());
            }
        }
    }
    map
}

#[derive(Clone, Copy)]
enum NamingKind {
    Ifaces,
    Vlans,
}

/// Effective per-exporter interface/VLAN names:
/// `{"<exporter-ip>": {"<id>": "<name>", ...}, ...}` built from the
/// exporter-scoped sources only (UI labels > `naming` config > SNMP).
/// The legacy global maps are deliberately excluded — an ifIndex or
/// VLAN id is meaningless outside its exporting device.
fn per_exporter_names(st: &Arc<AppState>, kind: NamingKind) -> serde_json::Value {
    // Collect id sets per exporter first so no naming/snmp/policy lock
    // is held while the resolvers take their own read locks.
    let mut per_ids: std::collections::BTreeMap<u128, std::collections::BTreeSet<u32>> =
        std::collections::BTreeMap::new();
    {
        let policy_entries = st.exporter_policy.entries();
        let naming = st.ctx.naming.read().unwrap();
        let snmp = st.snmp.read().unwrap();
        let us: std::collections::BTreeSet<u128> = policy_entries
            .keys()
            .map(|ip| ip_to_u128(ip))
            .chain(snmp.keys().map(|ip| ip_to_u128(ip)))
            .chain(naming.ips())
            .collect();
        for u in us {
            let addr = u128_to_ip(u);
            let mut ids = std::collections::BTreeSet::new();
            match kind {
                NamingKind::Ifaces => {
                    if let Some(pe) = policy_entries.get(&addr) {
                        ids.extend(pe.interfaces.keys().copied());
                    }
                    if let Some(h) = naming.ifs_for(u) {
                        ids.extend(h.keys().copied());
                    }
                    if let Some(e) = snmp.get(&addr) {
                        ids.extend(e.interfaces.keys().copied());
                    }
                }
                NamingKind::Vlans => {
                    if let Some(pe) = policy_entries.get(&addr) {
                        ids.extend(pe.vlans.keys().map(|v| *v as u32));
                    }
                    if let Some(h) = naming.vlans_for(u) {
                        ids.extend(h.keys().map(|v| *v as u32));
                    }
                    if let Some(e) = snmp.get(&addr) {
                        ids.extend(e.vlans.keys().map(|v| *v as u32));
                    }
                }
            }
            if !ids.is_empty() {
                per_ids.insert(u, ids);
            }
        }
    }
    let mut out = serde_json::Map::new();
    for (u, ids) in per_ids {
        let m: serde_json::Map<String, serde_json::Value> = ids
            .into_iter()
            .filter_map(|i| {
                let name = match kind {
                    NamingKind::Ifaces => st.ctx.ifname_scoped(u, i),
                    NamingKind::Vlans => st.ctx.vlan_name_scoped(u, i as u16),
                };
                name.map(|n| (i.to_string(), serde_json::Value::String(n)))
            })
            .collect();
        if !m.is_empty() {
            out.insert(ip_string(u), serde_json::Value::Object(m));
        }
    }
    serde_json::Value::Object(out)
}

pub(super) async fn interfaces(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let g = st.ctx.interface_names.read().unwrap();
    let global: std::collections::BTreeMap<u32, String> =
        g.all().iter().map(|(k, v)| (*k, v.clone())).collect();
    let labels = st.exporter_policy.interface_labels();
    // UI-set labels + SNMP-learned + naming-config names vote; only
    // unanimous names surface in the global map (device-local names
    // differ per box — conflicts stay hidden, never guessed).
    let mut owned: Vec<std::collections::BTreeMap<u32, String>> =
        labels.values().cloned().collect();
    {
        let naming = st.ctx.naming.read().unwrap();
        for u in naming.ips() {
            if let Some(h) = naming.ifs_for(u) {
                owned.push(h.iter().map(|(k, v)| (*k, v.clone())).collect());
            }
        }
    }
    {
        let snmp = st.snmp.read().unwrap();
        for e in snmp.values() {
            let m: std::collections::BTreeMap<u32, String> = e
                .interfaces
                .iter()
                .filter(|(_, f)| !f.name.is_empty())
                .map(|(i, f)| (*i, f.name.clone()))
                .collect();
            if !m.is_empty() {
                owned.push(m);
            }
        }
    }
    let per: Vec<_> = owned.iter().collect();
    let merged = merge_unanimous(&global, per);
    let mut items: Vec<_> = merged.iter().collect();
    items.sort_by_key(|(k, _)| **k);
    // Per-exporter effective names — ifIndex is device-local, so the
    // unambiguous view is keyed by exporter IP. Scoped sources only
    // (UI labels > naming config > SNMP); the global map is never
    // borrowed for a specific exporter.
    let exporters = per_exporter_names(&st, NamingKind::Ifaces);
    Json(serde_json::json!({
        "items": items.iter().map(|(k, v)| serde_json::json!({"ifindex": k, "name": v})).collect::<Vec<_>>(),
        "exporters": exporters,
    }))
}

pub(super) async fn vlans(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let g = st.ctx.vlan_names.read().unwrap();
    let global: std::collections::BTreeMap<u16, String> =
        g.all().iter().map(|(k, v)| (*k, v.clone())).collect();
    let labels = st.exporter_policy.vlan_labels();
    let mut owned: Vec<std::collections::BTreeMap<u16, String>> =
        labels.values().cloned().collect();
    {
        let naming = st.ctx.naming.read().unwrap();
        for u in naming.ips() {
            if let Some(h) = naming.vlans_for(u) {
                owned.push(h.iter().map(|(k, v)| (*k, v.clone())).collect());
            }
        }
    }
    {
        let snmp = st.snmp.read().unwrap();
        for e in snmp.values() {
            if !e.vlans.is_empty() {
                owned.push(e.vlans.clone());
            }
        }
    }
    let per: Vec<_> = owned.iter().collect();
    let merged = merge_unanimous(&global, per);
    let mut items: Vec<_> = merged.iter().collect();
    items.sort_by_key(|(k, _)| **k);
    let exporters = per_exporter_names(&st, NamingKind::Vlans);
    Json(serde_json::json!({
        "items": items.iter().map(|(k, v)| serde_json::json!({"vlan": k, "name": v})).collect::<Vec<_>>(),
        "exporters": exporters,
    }))
}

pub(super) async fn labels(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let items: Vec<_> = st
        .ctx
        .rules
        .list()
        .into_iter()
        .map(|(id, name)| serde_json::json!({"id": id, "name": name}))
        .collect();
    Json(serde_json::json!({"items": items}))
}

pub(super) async fn enrichers(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(st.http_enrich.status())
}

/// Alert rules + live state: configured rules, currently-suppressed
/// (recently fired) groups, and webhook delivery stats.
pub(super) async fn alerts_status(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let cfg = st.admin.alerts.read().unwrap().clone();
    let now = crate::metrics::now_ms();
    let fired = st.alert_rt.fired.lock().unwrap();
    let rules: Vec<serde_json::Value> = cfg
        .items
        .iter()
        .enumerate()
        .map(|(idx, a)| {
            // Groups currently inside cooldown for this rule.
            let mut active: Vec<serde_json::Value> = fired
                .iter()
                .filter(|((i, _), _)| *i == idx)
                .map(|((_, k), t)| {
                    serde_json::json!({
                        "group": a.group_by.as_deref().map(|d| query::format_key(&st.ctx, d, *k)),
                        "last_fired_ms": t,
                        "cooldown_remaining_ms": cfg.cooldown_secs.max(1).saturating_mul(1000).saturating_sub(now.saturating_sub(*t)),
                    })
                })
                .collect();
            active.sort_by_key(|v| v["last_fired_ms"].as_u64().unwrap_or(0));
            serde_json::json!({
                "name": a.name,
                "metric": a.metric,
                "op": a.op,
                "threshold": a.threshold,
                "window_secs": a.window_secs,
                "group_by": a.group_by,
                "granularity": a.granularity,
                "active": active,
            })
        })
        .collect();
    let hooks: serde_json::Map<String, serde_json::Value> = st
        .alert_rt
        .hooks
        .lock()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::to_value(v).unwrap_or_default()))
        .collect();
    Json(serde_json::json!({
        "eval_secs": cfg.eval_secs,
        "cooldown_secs": cfg.cooldown_secs,
        "webhook_configured": cfg.webhook_url.is_some(),
        "rules": rules,
        "webhook": hooks,
    }))
}

/// Effective config for the UI settings view — secrets redacted.
/// Shares adminapi::redact_secrets so /api/v1/config and
/// /api/v1/admin/settings can never diverge on what is hidden.
pub(super) async fn config_view(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(adminapi::effective_settings(&st))
}
