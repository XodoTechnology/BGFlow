//! Threshold alerting over rollup data. Each rule measures a rate
//! (bytes/packets/flows/mbps per second) over a sliding window, optionally
//! grouped by a dimension, and fires when the comparison holds. Actions:
//! log line, Prometheus counter, optional webhook POST. Cooldown prevents
//! alert storms.

use crate::config::{AlertConfig, AlertsConfig};
use crate::metrics::{now_ms, Metrics};
use crate::query::{self, Ctx, RollupFilter, RollupSet};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// (alert_idx, group_key) -> last fire time ms.
type FiredMap = HashMap<(usize, u128), u64>;

/// Webhook delivery outcome for one alert name.
#[derive(Debug, Default, serde::Serialize)]
pub struct HookStat {
    pub last_ok_ms: u64,
    pub last_err_ms: u64,
    pub last_err: String,
    pub failures: u32,
}

/// Shared alert runtime state — fired/suppression map plus webhook
/// delivery stats, exposed to the API for the alerts status view.
#[derive(Default)]
pub struct AlertRuntime {
    pub fired: Mutex<FiredMap>,
    pub hooks: Mutex<HashMap<String, HookStat>>,
}

impl AlertRuntime {
    /// Drop fired entries older than the cooldown horizon — past that
    /// age they can no longer suppress a refire, so they're dead weight.
    /// Without this the map grows for the daemon's lifetime.
    pub fn gc_fired(&self, cooldown_ms: u64, now: u64) {
        self.fired
            .lock()
            .unwrap()
            .retain(|_, t| now.saturating_sub(*t) < cooldown_ms);
    }
}

/// Cap on per-alert group cardinality during evaluation. High-cardinality
/// group_by dims (src_ip over a busy window) would otherwise build
/// multi-million-entry maps per rule per eval tick.
const GROUP_MAP_MAX: usize = 262_144;
/// Webhook delivery attempts before giving up (exponential backoff).
const HOOK_ATTEMPTS: u32 = 3;

/// Build a RollupFilter from an AlertConfig's optional filter fields.
fn alert_filter(ctx: &Ctx, a: &AlertConfig) -> Result<RollupFilter, String> {
    let mut f = RollupFilter::default();
    if let Some(p) = &a.proto {
        f.proto = Some(*p);
    }
    f.src_asn = a.src_asn;
    f.dst_asn = a.dst_asn;
    if let Some(s) = &a.src_ip {
        f.src_ip = Some(query::parse_ip_filter(s).ok_or("bad src_ip")?);
    }
    if let Some(s) = &a.dst_ip {
        f.dst_ip = Some(query::parse_ip_filter(s).ok_or("bad dst_ip")?);
    }
    if let Some(s) = &a.src_country {
        f.src_country = Some(bgflow_types::country_pack(s));
    }
    if let Some(s) = &a.dst_country {
        f.dst_country = Some(bgflow_types::country_pack(s));
    }
    if let Some(s) = &a.exporter {
        // Same resolution as the query API: IPs, "name (ip)", or
        // configured exporter names — not just raw IP literals.
        let names = ctx.exporter_names.read().unwrap();
        for part in s.split(',') {
            match names.resolve(part) {
                Some(u) => f.exporters.push(u),
                None => return Err(format!("bad exporter '{}'", part.trim())),
            }
        }
    }
    if let Some(s) = &a.label {
        f.label = query_label(ctx, s);
    }
    Ok(f)
}

fn query_label(ctx: &Ctx, s: &str) -> Option<u32> {
    if let Ok(id) = s.parse::<u32>() {
        return Some(id);
    }
    ctx.rules
        .names()
        .into_iter()
        .find(|(_, n)| n.eq_ignore_ascii_case(s))
        .map(|(id, _)| id)
}

/// Which numeric column a metric reads.
fn metric_col(metric: &str) -> usize {
    use bgflow_store::schema::rollup_idx as ix;
    match metric {
        "packets" | "pps" => ix::PACKETS,
        "flows" => ix::FLOWS,
        _ => ix::BYTES, // bytes | mbps | anything else
    }
}

/// Rate value in "metric units per second".
fn rate_of(metric: &str, total: u64, window_secs: u64) -> f64 {
    let w = window_secs.max(1) as f64;
    match metric {
        "mbps" => total as f64 * 8.0 / 1e6 / w,
        _ => total as f64 / w,
    }
}

fn op_holds(op: &str, value: f64, threshold: f64) -> bool {
    match op {
        "gt" => value > threshold,
        "gte" => value >= threshold,
        "lt" => value < threshold,
        "lte" => value <= threshold,
        _ => value > threshold,
    }
}

/// Spawn the evaluation loop. Runs until the process exits.
/// `cfg` is shared so admin reload / SIGHUP can swap rules live; the loop
/// re-reads it every tick (1s granularity, eval gated by eval_secs).
pub async fn run(
    cfg: Arc<std::sync::RwLock<AlertsConfig>>,
    ctx: Ctx,
    metrics: Arc<Metrics>,
    rt: Arc<AlertRuntime>,
) {
    let n = cfg.read().unwrap().items.len();
    if n == 0 {
        tracing::info!("alerts: no rules configured (reloadable via SIGHUP/admin API)");
    } else {
        tracing::info!("alerts: {} rule(s) configured", n);
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    let mut last_run = 0u64;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let snap = cfg.read().unwrap().clone();
        let iv = snap.eval_secs.max(10) * 1000;
        let now = now_ms();
        if now.saturating_sub(last_run) < iv {
            continue;
        }
        last_run = now;
        evaluate(&snap, &ctx, &metrics, &rt, &client).await;
    }
}

async fn evaluate(
    cfg: &AlertsConfig,
    ctx: &Ctx,
    metrics: &Metrics,
    rt: &Arc<AlertRuntime>,
    client: &reqwest::Client,
) {
    let now = now_ms();
    rt.gc_fired(cfg.cooldown_secs.max(1).saturating_mul(1000), now);
    for (idx, a) in cfg.items.iter().enumerate() {
        if a.name.is_empty() {
            continue;
        }
        let window_ms = a.window_secs.max(1).saturating_mul(1000);
        // Scan 2 windows back-to-front in one pass: [now-2w, now].
        let from = now.saturating_sub(window_ms.saturating_mul(2));
        let Ok(f) = alert_filter(ctx, a) else {
            tracing::warn!("alert '{}': bad filter, skipped", a.name);
            continue;
        };
        let set = match a.granularity.as_deref() {
            Some("hourly") | Some("hour") | Some("coarse") => RollupSet::Hourly,
            _ => RollupSet::Minute,
        };
        let group_dim: Option<&str> = a.group_by.as_deref().filter(|d| !d.is_empty());
        let dims: &[&str] = match group_dim {
            Some(d) => &[d],
            None => &[],
        };
        // Sanity: dim must be a known rollup dim.
        if let Some(d) = group_dim {
            if query::dim_col(d).is_none() {
                tracing::warn!("alert '{}': unknown group_by '{}'", a.name, d);
                continue;
            }
        }
        let needed = query::rollup_needed(&f, dims);
        let mcol = metric_col(&a.metric);
        if !needed.contains(&mcol) {
            // rollup_needed only adds filter+dim+fixed cols; add metric col.
            let mut n2 = needed.clone();
            n2.push(mcol);
            n2.sort_unstable();
            n2.dedup();
            eval_alert(
                ctx, set, from, now, window_ms, &f, dims, group_dim, mcol, &n2, a, idx, cfg,
                metrics, rt, client,
            )
            .await;
            continue;
        }
        eval_alert(
            ctx, set, from, now, window_ms, &f, dims, group_dim, mcol, &needed, a, idx, cfg,
            metrics, rt, client,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn eval_alert(
    ctx: &Ctx,
    set: RollupSet,
    from: u64,
    now: u64,
    window_ms: u64,
    f: &RollupFilter,
    _dims: &[&str],
    group_dim: Option<&str>,
    mcol: usize,
    needed: &[usize],
    a: &AlertConfig,
    idx: usize,
    cfg: &AlertsConfig,
    metrics: &Metrics,
    rt: &Arc<AlertRuntime>,
    client: &reqwest::Client,
) {
    // Per group: (current_window_total, previous_window_total)
    let mut sums: HashMap<u128, (u64, u64)> = HashMap::new();
    let mut group_overflow = false;
    let cur_start = now.saturating_sub(window_ms);
    // Share the global scan budget with API queries.
    let _scan = ctx.scan_sem.clone().acquire_owned().await.unwrap();
    let _ = query::rollup_scan(ctx, set, from, now, needed, |r| {
        if !f.matches(r) {
            return std::ops::ControlFlow::Continue(());
        }
        let key = group_dim.map(|d| query::dim_key(d, r)).unwrap_or(0);
        // Bound group cardinality — beyond the cap, new keys are skipped
        // (existing keys keep accumulating) rather than growing unbounded.
        if group_dim.is_some() && !sums.contains_key(&key) && sums.len() >= GROUP_MAP_MAX {
            group_overflow = true;
            return std::ops::ControlFlow::Continue(());
        }
        let v = r.v(mcol) as u64;
        let e = sums.entry(key).or_default();
        if r.bucket_ms() + set.period_ms() > cur_start {
            e.0 += v;
        } else {
            e.1 += v;
        }
        std::ops::ControlFlow::Continue(())
    });
    if group_overflow {
        tracing::warn!(
            "alert '{}': group_by cardinality exceeded {} — light groups dropped this eval",
            a.name,
            GROUP_MAP_MAX
        );
    }

    let cooldown = cfg.cooldown_secs.max(1).saturating_mul(1000);
    let w_secs = a.window_secs.max(1);
    let mut to_fire: Vec<(u128, f64, f64, f64)> = Vec::new(); // key, value, prev_rate, change_pct
    for (key, (cur, prev)) in &sums {
        let value = rate_of(&a.metric, *cur, w_secs);
        if !op_holds(&a.op, value, a.threshold) {
            continue;
        }
        let prev_rate = rate_of(&a.metric, *prev, w_secs);
        let change_pct = if prev_rate > 0.0 {
            (value - prev_rate) / prev_rate * 100.0
        } else {
            f64::INFINITY
        };
        if a.min_change_pct > 0.0 && change_pct < a.min_change_pct {
            continue;
        }
        to_fire.push((*key, value, prev_rate, change_pct));
    }
    if to_fire.is_empty() {
        return;
    }
    to_fire.sort_by(|x, y| y.1.partial_cmp(&x.1).unwrap_or(std::cmp::Ordering::Equal));

    for (key, value, prev_rate, change_pct) in to_fire {
        let fkey = (idx, key);
        let last = rt.fired.lock().unwrap().get(&fkey).copied().unwrap_or(0);
        if now.saturating_sub(last) < cooldown {
            continue;
        }
        rt.fired.lock().unwrap().insert(fkey, now);
        metrics
            .alerts_fired
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let key_json = group_dim
            .map(|d| query::format_key(ctx, d, key))
            .unwrap_or(serde_json::json!(null));
        tracing::warn!(
            "ALERT {} group={} value={:.2} threshold={} prev={:.2}",
            a.name,
            key_json,
            value,
            a.threshold,
            prev_rate
        );
        if let Some(url) = &cfg.webhook_url {
            let body = serde_json::json!({
                "alert": a.name,
                "group_by": group_dim,
                "group": key_json,
                "metric": a.metric,
                "value": value,
                "threshold": a.threshold,
                "op": a.op,
                "window_secs": a.window_secs,
                "prev_rate": prev_rate,
                "change_pct": if change_pct.is_finite() { serde_json::json!(change_pct) } else { serde_json::json!("new") },
                "ts_ms": now,
            });
            let c = client.clone();
            let u = url.clone();
            let name = a.name.clone();
            let rt2 = rt.clone();
            tokio::spawn(async move {
                // Bounded retries with backoff; delivery outcome is
                // recorded per alert name for the status endpoint.
                let mut last_err = String::new();
                for attempt in 0..HOOK_ATTEMPTS {
                    if attempt > 0 {
                        // ~1s, ~2s backoff between the 3 delivery attempts.
                        tokio::time::sleep(Duration::from_millis(500 * (1 << attempt))).await;
                    }
                    match c.post(&u).json(&body).send().await {
                        Ok(r) if r.status().is_success() => {
                            rt2.hooks
                                .lock()
                                .unwrap()
                                .entry(name.clone())
                                .or_default()
                                .last_ok_ms = now_ms();
                            return;
                        }
                        Ok(r) => last_err = format!("HTTP {}", r.status()),
                        Err(e) => last_err = e.to_string(),
                    }
                }
                let mut g = rt2.hooks.lock().unwrap();
                let st = g.entry(name.clone()).or_default();
                st.last_err_ms = now_ms();
                st.last_err = last_err;
                st.failures += 1;
                tracing::warn!("alert '{}': webhook delivery failed: {}", name, st.last_err);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_and_ops() {
        assert_eq!(rate_of("bytes", 1000, 10), 100.0);
        assert_eq!(rate_of("mbps", 1_000_000, 1), 8.0);
        assert!(op_holds("gt", 5.0, 4.0));
        assert!(!op_holds("gt", 4.0, 4.0));
        assert!(op_holds("gte", 4.0, 4.0));
        assert!(op_holds("lt", 3.0, 4.0));
        assert!(op_holds("lte", 4.0, 4.0));
        assert!(op_holds("bogus", 5.0, 4.0)); // defaults to gt
    }

    #[test]
    fn metric_col_mapping() {
        use bgflow_store::schema::rollup_idx as ix;
        assert_eq!(metric_col("bytes"), ix::BYTES);
        assert_eq!(metric_col("packets"), ix::PACKETS);
        assert_eq!(metric_col("pps"), ix::PACKETS);
        assert_eq!(metric_col("flows"), ix::FLOWS);
        assert_eq!(metric_col("mbps"), ix::BYTES);
    }

    #[test]
    fn fired_gc_drops_only_expired() {
        let rt = AlertRuntime::default();
        let now = 1_000_000u64;
        {
            let mut m = rt.fired.lock().unwrap();
            m.insert((0, 1), now - 500); // within cooldown → kept
            m.insert((0, 2), now - 5000); // expired → dropped
            m.insert((1, 3), now); // fresh → kept
        }
        rt.gc_fired(1000, now);
        let m = rt.fired.lock().unwrap();
        assert_eq!(m.len(), 2);
        assert!(m.contains_key(&(0, 1)));
        assert!(m.contains_key(&(1, 3)));
    }
}
