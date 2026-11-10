//! Threshold alerting over rollup data. Each rule measures a rate
//! (bytes/packets/flows/mbps per second) over a sliding window, optionally
//! grouped by a dimension, and fires when the comparison holds. Actions:
//! log line, Prometheus counter, optional webhook POST. Cooldown prevents
//! alert storms.

use crate::config::{AlertConfig, AlertsConfig};
use crate::metrics::{now_ms, Metrics};
use crate::query::{self, Ctx, RollupFilter, RollupSet};
use bgflow_types::ip_to_u128;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// (alert_idx, group_key) -> last fire time ms.
type FiredMap = HashMap<(usize, u128), u64>;

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
        for part in s.split(',') {
            let ip: IpAddr = part.trim().parse().map_err(|_| "bad exporter")?;
            f.exporters.push(ip_to_u128(&ip));
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
pub async fn run(cfg: AlertsConfig, ctx: Ctx, metrics: Arc<Metrics>) {
    if cfg.items.is_empty() {
        return;
    }
    tracing::info!("alerts: {} rule(s), eval every {}s", cfg.items.len(), cfg.eval_secs);
    let fired: Arc<Mutex<FiredMap>> = Arc::new(Mutex::new(HashMap::new()));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    let mut tick = tokio::time::interval(Duration::from_secs(cfg.eval_secs.max(10)));
    loop {
        tick.tick().await;
        evaluate(&cfg, &ctx, &metrics, &fired, &client).await;
    }
}

async fn evaluate(
    cfg: &AlertsConfig,
    ctx: &Ctx,
    metrics: &Metrics,
    fired: &Arc<Mutex<FiredMap>>,
    client: &reqwest::Client,
) {
    let now = now_ms();
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
            eval_alert(ctx, set, from, now, window_ms, &f, dims, group_dim, mcol, &n2, a, idx, cfg, metrics, fired, client).await;
            continue;
        }
        eval_alert(ctx, set, from, now, window_ms, &f, dims, group_dim, mcol, &needed, a, idx, cfg, metrics, fired, client).await;
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
    fired: &Arc<Mutex<FiredMap>>,
    client: &reqwest::Client,
) {
    // Per group: (current_window_total, previous_window_total)
    let mut sums: HashMap<u128, (u64, u64)> = HashMap::new();
    let cur_start = now.saturating_sub(window_ms);
    let _ = query::rollup_scan(ctx, set, from, now, needed, |r| {
        if !f.matches(r) {
            return std::ops::ControlFlow::Continue(());
        }
        let key = group_dim.map(|d| query::dim_key(d, r)).unwrap_or(0);
        let v = r.v(mcol) as u64;
        let e = sums.entry(key).or_default();
        if r.bucket_ms() + set.period_ms() > cur_start {
            e.0 += v;
        } else {
            e.1 += v;
        }
        std::ops::ControlFlow::Continue(())
    });

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
        let last = fired.lock().unwrap().get(&fkey).copied().unwrap_or(0);
        if now.saturating_sub(last) < cooldown {
            continue;
        }
        fired.lock().unwrap().insert(fkey, now);
        metrics.alerts_fired.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

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
            tokio::spawn(async move {
                let _ = c.post(u).json(&body).send().await;
            });
        }
    }
}
