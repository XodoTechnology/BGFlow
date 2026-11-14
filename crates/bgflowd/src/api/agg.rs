//! Aggregate analytics: summary, overview, matrix, timeseries, top, conversations, anomalies, label stats.

use super::*;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Agg {
    pub(crate) bytes: u64,
    pub(crate) packets: u64,
    pub(crate) flows: u64,
}

pub(super) fn agg_add(a: &mut Agg, b: &Agg) {
    a.bytes += b.bytes;
    a.packets += b.packets;
    a.flows += b.flows;
}

/// Reduce key-sharded rollup maps to the global top-`limit` by
/// (bytes, flows). Keys are partitioned across shards with complete
/// aggregates, so every global top-`limit` member is within its own
/// shard's local top-`limit` — collecting per-shard candidates and
/// re-sorting yields the exact global top-`limit` without materializing
/// or sorting the full key space.
pub(super) fn shard_top<K>(
    shards: Vec<query::ShardMap<K, Agg>>,
    limit: usize,
) -> Vec<(K, Agg)>
where
    K: Send,
{
    if limit == 0 {
        return Vec::new();
    }
    let cmp = |a: &(K, Agg), b: &(K, Agg)| {
        b.1.bytes.cmp(&a.1.bytes).then(b.1.flows.cmp(&a.1.flows))
    };
    // Per-shard select+truncate+sort in parallel — each shard's candidate
    // list is independent.
    let per_shard: Vec<Vec<(K, Agg)>> = std::thread::scope(|s| {
        let handles: Vec<_> = shards
            .into_iter()
            .map(|map| {
                s.spawn(move || {
                    let mut v: Vec<(K, Agg)> = map.into_iter().collect();
                    if v.len() > limit {
                        v.select_nth_unstable_by(limit - 1, cmp);
                        v.truncate(limit);
                    }
                    v.sort_by(cmp);
                    v
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut cand: Vec<(K, Agg)> = per_shard.into_iter().flatten().collect();
    cand.sort_by(cmp);
    cand.truncate(limit);
    cand
}

/// No-op bounded accumulator for `rollup_scan_sharded` callers that only
/// need the key/value maps.
fn unit_init() -> () {}
fn unit_add(_: &mut (), _: &query::RollupRow) {}
fn unit_merge(_: &mut (), _: ()) {}

/// Merge one worker's `HashMap<K, Agg>` partial into the combined map.
pub(super) fn merge_agg_map<K>(a: &mut HashMap<K, Agg>, b: HashMap<K, Agg>)
where
    K: Eq + std::hash::Hash + Clone,
{
    for (k, v) in b {
        agg_add(a.entry(k).or_default(), &v);
    }
}

/// Per-bucket traffic split by direction relative to `local_asns`:
/// dst local → in, src local → out, neither/both → transit.
#[derive(Default, Clone, Copy)]
pub(crate) struct SeriesPt {
    pub(crate) total: Agg,
    pub(crate) inn: Agg,
    pub(crate) out: Agg,
    pub(crate) tr: Agg,
}

/// Overview endpoint bounded accumulator — totals + protocol +
/// timeseries. The top-dim maps are NOT here: they go through the
/// key-sharded maps so per-worker memory stays flat regardless of IP
/// cardinality. Merged from per-worker partials.
#[derive(Default)]
pub(super) struct OvAcc {
    total: Agg,
    by_proto: HashMap<u8, Agg>,
    series: HashMap<u64, SeriesPt>,
}

impl OvAcc {
    fn merge(&mut self, o: Self) {
        agg_add(&mut self.total, &o.total);
        merge_agg_map(&mut self.by_proto, o.by_proto);
        for (k, p) in o.series {
            let e = self.series.entry(k).or_default();
            agg_add(&mut e.total, &p.total);
            agg_add(&mut e.inn, &p.inn);
            agg_add(&mut e.out, &p.out);
            agg_add(&mut e.tr, &p.tr);
        }
    }
}

pub(super) async fn summary(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let set = auto_rollup_set(&q, from, to, &f);
    if let Some((v, _)) = hot_view(&st, &f, &q, set, from, to, 3_600_000, true) {
        let mut protos: Vec<_> = v
            .by_proto
            .into_iter()
            .map(|(p, a)| {
                serde_json::json!({
                    "protocol": p,
                    "name": bgflow_types::protocol_name(p),
                    "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
                })
            })
            .collect();
        protos.sort_by_key(|v| std::cmp::Reverse(v["bytes"].as_u64().unwrap_or(0)));
        return Ok(Json(serde_json::json!({
            "from": from, "to": to,
            "bytes": v.total.bytes, "packets": v.total.packets, "flows": v.total.flows,
            "by_protocol": protos,
            "set": "hot",
        })));
    }
    let needed = query::rollup_needed(&f, &["proto"]);
    let _scan = scan_permit(&st.ctx).await;
    let (total, by_proto) = query::rollup_scan_par(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        || (Agg::default(), HashMap::<u8, Agg>::new()),
        |(total, by_proto), r| {
            if !f.matches(r) {
                return;
            }
            total.bytes += r.bytes();
            total.packets += r.packets();
            total.flows += r.flows();
            let p = by_proto.entry(r.protocol()).or_default();
            p.bytes += r.bytes();
            p.packets += r.packets();
            p.flows += r.flows();
        },
        |(t, p), (t2, p2)| {
            agg_add(t, &t2);
            merge_agg_map(p, p2);
        },
    )
    .map_err(|e| err(e.to_string()))?;

    let mut protos: Vec<_> = by_proto
        .into_iter()
        .map(|(p, a)| {
            serde_json::json!({
                "protocol": p,
                "name": bgflow_types::protocol_name(p),
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    protos.sort_by_key(|v| std::cmp::Reverse(v["bytes"].as_u64().unwrap_or(0)));

    Ok(Json(serde_json::json!({
        "from": from, "to": to,
        "bytes": total.bytes, "packets": total.packets, "flows": total.flows,
        "by_protocol": protos,
        "set": set_name(set),
    })))
}

/// Combined dashboard payload: totals + protocol breakdown + timeseries +
/// top-N for the overview dims — all from ONE rollup scan (vs ~7 separate
/// scans when the UI calls each endpoint individually).
/// /overview responses younger than this are served from cache — the
/// UI refreshes every ~15s, so anything under ~one refresh interval is
/// effectively live while halving scan load on slow ranges.
const OV_CACHE_TTL: Duration = Duration::from_secs(12);

pub(super) async fn overview(
    State(st): State<Arc<AppState>>,
    raw: RawQuery,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let key = raw.0.unwrap_or_default();
    {
        let g = st.ov_cache.lock().unwrap();
        if let Some((k, at, v)) = g.as_ref() {
            if *k == key && at.elapsed() < OV_CACHE_TTL {
                return Ok(Json(v.clone()));
            }
        }
    }
    let (from, to) = range(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let set = auto_rollup_set(&q, from, to, &f);
    let mut size = bucket_ms(q.get("bucket").map(|s| s.as_str()));
    // Hourly rollup rows are hour-granular — finer buckets would only
    // scatter each row into its hour's first sub-slot.
    if set == RollupSet::Hourly && size < 3_600_000 {
        size = 3_600_000;
    }
    let limit: usize = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
        .min(100);
    const TOP_DIMS_OV: [&str; 5] = ["src_ip", "dst_ip", "src_asn", "dst_asn", "dst_port"];
    if let Some(resp) = hot_overview(&st, &f, &q, set, from, to, size, limit) {
        return Ok(resp);
    }
    let needed = query::rollup_needed(&f, &["proto", "src_ip", "dst_ip", "src_asn", "dst_asn", "dst_port"]);
    let local_asns = Arc::new(st.ctx.local_asns.read().unwrap().clone());

    // One sharded scan: bounded state (totals/proto/series) accumulates
    // per worker; each top dim emits (dim_idx, key) pairs routed into
    // disjoint shard maps — exact top-N at one-map memory cost even for
    // the high-cardinality IP dims.
    let _scan = scan_permit(&st.ctx).await;
    let (shards, acc) = query::rollup_scan_sharded(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        &f,
        // 4 shards per worker keeps mutex convoying rare on big maps.
        bgflow_store::scan_threads() * 4,
        |r, out| {
            for (i, d) in TOP_DIMS_OV.iter().enumerate() {
                out.push((
                    (i as u8, query::dim_key(d, r)),
                    Agg {
                        bytes: r.bytes(),
                        packets: r.packets(),
                        flows: r.flows(),
                    },
                ));
            }
        },
        |a: &mut Agg, b: Agg| agg_add(a, &b),
        || OvAcc::default(),
        {
            let local = local_asns.clone();
            move |acc: &mut OvAcc, r: &query::RollupRow| {
                acc.total.bytes += r.bytes();
                acc.total.packets += r.packets();
                acc.total.flows += r.flows();
                let p = acc.by_proto.entry(r.protocol()).or_default();
                p.bytes += r.bytes();
                p.packets += r.packets();
                p.flows += r.flows();
                let b = (r.bucket_ms() / size) * size;
                let s = acc.series.entry(b).or_default();
                let a = Agg {
                    bytes: r.bytes(),
                    packets: r.packets(),
                    flows: r.flows(),
                };
                agg_add(&mut s.total, &a);
                let sa = local.contains(&r.src_asn());
                let da = local.contains(&r.dst_asn());
                let d = match (sa, da) {
                    (true, false) => &mut s.out,
                    (false, true) => &mut s.inn,
                    _ => &mut s.tr,
                };
                agg_add(d, &a);
            }
        },
        |a: &mut OvAcc, b: OvAcc| a.merge(b),
    )
    .map_err(|e| err(e.to_string()))?;
    let OvAcc {
        total,
        by_proto,
        series,
    } = acc;

    let mut protos: Vec<_> = by_proto
        .into_iter()
        .map(|(p, a)| {
            serde_json::json!({
                "protocol": p,
                "name": bgflow_types::protocol_name(p),
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    protos.sort_by_key(|v| std::cmp::Reverse(v["bytes"].as_u64().unwrap_or(0)));

    // Zero-fill the selected window so the chart's time axis spans the
    // whole range instead of compressing to buckets that have data.
    // Capped so wide range + tiny bucket combos can't emit unbounded
    // points; beyond the cap we emit populated buckets only.
    let emit = |t: u64, p: &SeriesPt| {
        serde_json::json!({
            "t": t / 1000, "bucket_ms": t,
            "bytes": p.total.bytes, "packets": p.total.packets, "flows": p.total.flows,
            "in_bytes": p.inn.bytes, "in_packets": p.inn.packets, "in_flows": p.inn.flows,
            "out_bytes": p.out.bytes, "out_packets": p.out.packets, "out_flows": p.out.flows,
            "tr_bytes": p.tr.bytes, "tr_packets": p.tr.packets, "tr_flows": p.tr.flows,
        })
    };
    let start = (from / size) * size;
    let end = (to / size) * size;
    let n_pts = if end >= start { (end - start) / size + 1 } else { 0 };
    let mut ts_rows: Vec<serde_json::Value> = Vec::new();
    if n_pts <= 8192 {
        let mut keys: Vec<u64> = series.keys().copied().collect();
        keys.sort_unstable();
        let mut ki = 0;
        while ki < keys.len() && keys[ki] < start {
            ki += 1;
        }
        let zero = SeriesPt::default();
        let mut t = start;
        while t <= end {
            if ki < keys.len() && keys[ki] == t {
                ts_rows.push(emit(t, &series[&t]));
                ki += 1;
            } else {
                ts_rows.push(emit(t, &zero));
            }
            t += size;
        }
    } else {
        let mut kv: Vec<_> = series.iter().collect();
        kv.sort_by_key(|(t, _)| *t);
        ts_rows = kv.into_iter().map(|(t, p)| emit(*t, p)).collect();
    }

    // Partition shard entries by dimension index, then exact top-N per
    // dim via select_nth (no full sort of the IP-sized key spaces).
    let mut dim_rows: Vec<Vec<(u128, Agg)>> =
        (0..TOP_DIMS_OV.len()).map(|_| Vec::new()).collect();
    for map in shards {
        for ((di, k), a) in map {
            dim_rows[di as usize].push((k, a));
        }
    }
    let cmp = |a: &(u128, Agg), b: &(u128, Agg)| {
        b.1.bytes.cmp(&a.1.bytes).then(b.1.flows.cmp(&a.1.flows))
    };
    let mut top_out = serde_json::Map::new();
    for (i, &d) in TOP_DIMS_OV.iter().enumerate() {
        let mut rows = std::mem::take(&mut dim_rows[i]);
        if limit > 0 {
            if rows.len() > limit {
                rows.select_nth_unstable_by(limit - 1, cmp);
            }
            rows.truncate(limit);
            rows.sort_by(cmp);
        } else {
            rows.clear();
        }
        top_out.insert(
            d.to_string(),
            serde_json::json!(rows
                .into_iter()
                .map(|(k, a)| serde_json::json!({
                    "key": query::format_key(&st.ctx, d, k),
                    "key_raw": k.to_string(),
                    "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
                }))
                .collect::<Vec<_>>()),
        );
    }

    // Optional period-over-period: totals for the preceding equal-length
    // window under the same filters — powers "vs previous" deltas in the UI.
    let prev = if q.contains_key("compare") {
        let span = to.saturating_sub(from);
        let pfrom = from.saturating_sub(span);
        let pneed = query::rollup_needed(&f, &[]);
        let _scan = scan_permit(&st.ctx).await;
        let pt = query::rollup_scan_par(
            &st.ctx,
            set,
            pfrom,
            from,
            &pneed,
            Agg::default,
            |acc: &mut Agg, r: &query::RollupRow| {
                if f.matches(r) {
                    acc.bytes += r.bytes();
                    acc.packets += r.packets();
                    acc.flows += r.flows();
                }
            },
            |a: &mut Agg, b: Agg| agg_add(a, &b),
        )
        .map_err(|e| err(e.to_string()))?;
        Some(serde_json::json!({
            "from": pfrom, "to": from,
            "bytes": pt.bytes, "packets": pt.packets, "flows": pt.flows,
        }))
    } else {
        None
    };

    let out = serde_json::json!({
        "from": from, "to": to,
        "bytes": total.bytes, "packets": total.packets, "flows": total.flows,
        "prev": prev,
        "by_protocol": protos,
        "bucket_ms": size,
        "series": ts_rows,
        "top": top_out,
        "set": match set { RollupSet::Minute => "minute", RollupSet::Hourly => "hourly" },
    });
    *st.ov_cache.lock().unwrap() = Some((key, Instant::now(), out.clone()));
    Ok(Json(out))
}

/// Serve /overview entirely from the hot tier when eligible — produces
/// the identical JSON shape as the scan path with `"set":"hot"`.
/// `compare` is honored only when the preceding window is covered too;
/// otherwise returns None so the caller scans.
fn hot_overview(
    st: &AppState,
    f: &RollupFilter,
    q: &Q,
    set: RollupSet,
    from: u64,
    to: u64,
    size: u64,
    limit: usize,
) -> Option<Json<serde_json::Value>> {
    let (mut v, esize) = hot_view(st, f, q, set, from, to, size, true)?;
    let prev = if q.contains_key("compare") {
        let span = to.saturating_sub(from);
        let pfrom = from.saturating_sub(span);
        let (pv, _) = hot_view(st, f, q, set, pfrom, from, esize, true)?;
        Some(serde_json::json!({
            "from": pfrom, "to": from,
            "bytes": pv.total.bytes, "packets": pv.total.packets, "flows": pv.total.flows,
        }))
    } else {
        None
    };

    let mut protos: Vec<_> = v
        .by_proto
        .drain()
        .map(|(p, a)| {
            serde_json::json!({
                "protocol": p,
                "name": bgflow_types::protocol_name(p),
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    protos.sort_by_key(|v| std::cmp::Reverse(v["bytes"].as_u64().unwrap_or(0)));

    // Zero-fill the window exactly like the scan path so the chart axis
    // spans the full range.
    let emit = |t: u64, p: &SeriesPt| {
        serde_json::json!({
            "t": t / 1000, "bucket_ms": t,
            "bytes": p.total.bytes, "packets": p.total.packets, "flows": p.total.flows,
            "in_bytes": p.inn.bytes, "in_packets": p.inn.packets, "in_flows": p.inn.flows,
            "out_bytes": p.out.bytes, "out_packets": p.out.packets, "out_flows": p.out.flows,
            "tr_bytes": p.tr.bytes, "tr_packets": p.tr.packets, "tr_flows": p.tr.flows,
        })
    };
    let start = (from / esize) * esize;
    let end = (to / esize) * esize;
    let n_pts = if end >= start { (end - start) / esize + 1 } else { 0 };
    let mut ts_rows: Vec<serde_json::Value> = Vec::new();
    if n_pts <= 8192 {
        let zero = SeriesPt::default();
        let mut t = start;
        while t <= end {
            match v.series.get(&t) {
                Some(p) => ts_rows.push(emit(t, p)),
                None => ts_rows.push(emit(t, &zero)),
            }
            t += esize;
        }
    } else {
        ts_rows = v.series.iter().map(|(t, p)| emit(*t, p)).collect();
    }

    // TOP_DIMS_OV order matches HOT_DIMS[0..5] — index directly.
    let cmp = |a: &(u128, Agg), b: &(u128, Agg)| {
        b.1.bytes.cmp(&a.1.bytes).then(b.1.flows.cmp(&a.1.flows))
    };
    let mut top_out = serde_json::Map::new();
    for (i, d) in ["src_ip", "dst_ip", "src_asn", "dst_asn", "dst_port"].iter().enumerate() {
        let mut rows: Vec<(u128, Agg)> = std::mem::take(&mut v.tops[i]).into_iter().collect();
        if limit > 0 {
            if rows.len() > limit {
                rows.select_nth_unstable_by(limit - 1, cmp);
            }
            rows.truncate(limit);
            rows.sort_by(cmp);
        } else {
            rows.clear();
        }
        top_out.insert(
            d.to_string(),
            serde_json::json!(rows
                .into_iter()
                .map(|(k, a)| serde_json::json!({
                    "key": query::format_key(&st.ctx, d, k),
                    "key_raw": k.to_string(),
                    "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
                }))
                .collect::<Vec<_>>()),
        );
    }

    Some(Json(serde_json::json!({
        "from": from, "to": to,
        "bytes": v.total.bytes, "packets": v.total.packets, "flows": v.total.flows,
        "prev": prev,
        "by_protocol": protos,
        "bucket_ms": esize,
        "series": ts_rows,
        "top": top_out,
        "set": "hot",
    })))
}

/// Pair aggregation for the flow-map view: groups rollups by (src_dim, dst_dim).
/// IP/exporter dims are excluded — pair cardinality would explode.
const MATRIX_DIMS: &[&str] = &[
    "src_ipver", "dst_ipver", "src_asn", "dst_asn", "src_org", "dst_org",
    "src_country", "dst_country", "proto", "label", "src_port", "dst_port",
];

pub(super) async fn matrix(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let set = auto_rollup_set(&q, from, to, &f);
    // NB: params are src_dim/dst_dim — bare `src`/`dst` are flow-filter aliases.
    let sd = q.get("src_dim").map(|s| s.as_str()).unwrap_or("src_country");
    let dd = q.get("dst_dim").map(|s| s.as_str()).unwrap_or("dst_country");
    if !MATRIX_DIMS.contains(&sd) || !MATRIX_DIMS.contains(&dd) {
        return Err(err(format!(
            "bad matrix dim; src/dst must be one of {}",
            MATRIX_DIMS.join(", ")
        )));
    }
    let limit: usize = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
        .min(1000);
    let needed = query::rollup_needed(&f, &[sd, dd]);
    // Pair map can be large — key-sharded parallel aggregation keeps
    // memory at one global map's size while decoding in parallel.
    let _scan = scan_permit(&st.ctx).await;
    let (shards, _) = query::rollup_scan_sharded(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        &f,
        // 4 shards per worker keeps mutex convoying rare on big maps.
        bgflow_store::scan_threads() * 4,
        |r, out| {
            out.push((
                (query::dim_key(sd, r), query::dim_key(dd, r)),
                Agg {
                    bytes: r.bytes(),
                    packets: r.packets(),
                    flows: r.flows(),
                },
            ));
        },
        |a: &mut Agg, b: Agg| agg_add(a, &b),
        unit_init,
        unit_add,
        unit_merge,
    )
    .map_err(|e| err(e.to_string()))?;

    let rows = shard_top(shards, limit);
    let items: Vec<_> = rows
        .into_iter()
        .map(|((s, d), a)| {
            serde_json::json!({
                "src": query::format_key(&st.ctx, sd, s),
                "src_raw": s.to_string(),
                "dst": query::format_key(&st.ctx, dd, d),
                "dst_raw": d.to_string(),
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "src_dim": sd, "dst_dim": dd,
        "set": match set { RollupSet::Minute => "minute", RollupSet::Hourly => "hourly" },
        "items": items,
    })))
}

pub(super) fn set_name(set: RollupSet) -> &'static str {
    match set {
        RollupSet::Minute => "minute",
        RollupSet::Hourly => "hourly",
    }
}

pub(super) fn bucket_ms(s: Option<&str>) -> u64 {
    match s.unwrap_or("1m") {
        "1m" => 60_000,
        "5m" => 300_000,
        "15m" => 900_000,
        "1h" => 3_600_000,
        "6h" => 21_600_000,
        "1d" => 86_400_000,
        _ => 60_000,
    }
}

pub(super) async fn timeseries(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let set = auto_rollup_set(&q, from, to, &f);
    let mut size = bucket_ms(q.get("bucket").map(|s| s.as_str()));
    if set == RollupSet::Hourly && size < 3_600_000 {
        size = 3_600_000;
    }
    if let Some((v, hsize)) = hot_view(&st, &f, &q, set, from, to, size, true) {
        let mut rows: Vec<_> = v
            .series
            .into_iter()
            .map(|(t, p)| {
                serde_json::json!({
                    "t": t / 1000, "bucket_ms": t,
                    "bytes": p.total.bytes, "packets": p.total.packets, "flows": p.total.flows,
                })
            })
            .collect();
        rows.sort_by_key(|v| v["t"].as_u64().unwrap_or(0));
        return Ok(Json(serde_json::json!({"bucket_ms": hsize, "series": rows, "set": "hot"})));
    }
    let needed = query::rollup_needed(&f, &[]);
    let buckets: HashMap<u64, Agg> = {
        let _scan = scan_permit(&st.ctx).await;
        query::rollup_scan_par::<HashMap<u64, Agg>>(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        Default::default,
        |buckets, r| {
            if !f.matches(r) {
                return;
            }
            let b = (r.bucket_ms() / size) * size;
            let a = buckets.entry(b).or_default();
            a.bytes += r.bytes();
            a.packets += r.packets();
            a.flows += r.flows();
        },
        |a, b| merge_agg_map(a, b),
    )
    .map_err(|e| err(e.to_string()))?
    };

    let mut rows: Vec<_> = buckets
        .into_iter()
        .map(|(t, a)| {
            serde_json::json!({
                "t": t / 1000, "bucket_ms": t,
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    rows.sort_by_key(|v| v["t"].as_u64().unwrap_or(0));
    Ok(Json(serde_json::json!({"bucket_ms": size, "series": rows, "set": set_name(set)})))
}

const TOP_DIMS: &[&str] = &[
    "src_ip", "dst_ip", "src_ipver", "dst_ipver", "src_asn", "dst_asn",
    "src_org", "dst_org", "src_port", "dst_port", "proto",
    "exporter", "src_country", "dst_country", "label", "vlan",
    "ingress_if", "egress_if",
];

pub(super) async fn top(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let by = q.get("by").map(|s| s.as_str()).unwrap_or("src_ip");
    if !TOP_DIMS.contains(&by) {
        return Err(err(format!("unknown dimension '{}'; valid: {}", by, TOP_DIMS.join(", "))));
    }
    let (from, to) = range(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    // Hot-tracked dims keep the caller's granularity (the hot tier serves
    // both minute and hour views, preserving full-IP fidelity); untracked
    // dims get auto-promotion so long ranges scan the smaller hourly set.
    let set = if crate::hot::hot_dim_idx(by).is_some() {
        rollup_set(&q)
    } else {
        auto_rollup_set(&q, from, to, &f)
    };
    let limit: usize = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(10).min(1000);

    // Hot tier serves the dims it tracks; everything else scans.
    if let Some(di) = crate::hot::hot_dim_idx(by) {
        if let Some((v, _)) = hot_view(&st, &f, &q, set, from, to, 3_600_000, false) {
            let mut rows: Vec<(u128, Agg)> = v
                .tops
                .into_iter()
                .nth(di)
                .unwrap_or_default()
                .into_iter()
                .collect();
            rows.sort_by(|a, b| {
                b.1.bytes.cmp(&a.1.bytes).then(b.1.flows.cmp(&a.1.flows))
            });
            rows.truncate(limit);
            let out: Vec<_> = rows
                .into_iter()
                .map(|(k, a)| {
                    serde_json::json!({
                        "key": query::format_key(&st.ctx, by, k),
                        "key_raw": k.to_string(),
                        "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
                    })
                })
                .collect();
            return Ok(Json(
                serde_json::json!({"by": by, "set": "hot", "items": out}),
            ));
        }
    }

    // Full-cardinality dim map (ports/IPs can be huge) — key-sharded
    // parallel aggregation: memory stays at one map's size.
    let needed = query::rollup_needed(&f, &[by]);
    let _scan = scan_permit(&st.ctx).await;
    let (shards, _) = query::rollup_scan_sharded(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        &f,
        // 4 shards per worker keeps mutex convoying rare on big maps.
        bgflow_store::scan_threads() * 4,
        |r, out| {
            out.push((
                query::dim_key(by, r),
                Agg {
                    bytes: r.bytes(),
                    packets: r.packets(),
                    flows: r.flows(),
                },
            ));
        },
        |a: &mut Agg, b: Agg| agg_add(a, &b),
        unit_init,
        unit_add,
        unit_merge,
    )
    .map_err(|e| err(e.to_string()))?;

    let rows = shard_top(shards, limit);
    let out: Vec<_> = rows
        .into_iter()
        .map(|(k, a)| {
            serde_json::json!({
                "key": query::format_key(&st.ctx, by, k),
                // u128 doesn't fit JSON numbers — emit as string. UI only
                // consumes it for small dims (org id, ipver), which parse fine.
                "key_raw": k.to_string(),
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({"by": by, "set": set_name(set), "items": out,
        // Hourly rows mask IPs to /24·/48 — IP-dim top lists are approximate.
        "approximate": set == RollupSet::Hourly && matches!(by, "src_ip" | "dst_ip"),
    })))
}

pub(super) async fn conversations(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let set = auto_rollup_set(&q, from, to, &f);
    let limit: usize = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(20).min(500);
    // Conversation keys are near-unique per flow — millions of entries.
    // Key-sharded parallel aggregation: each key lives in exactly one
    // shard, so memory equals a single map (not one per worker).
    let needed = query::rollup_needed(
        &f,
        &[
            "src_ip", "dst_ip", "src_port", "dst_port", "proto", "src_asn", "dst_asn",
        ],
    );
    let _scan = scan_permit(&st.ctx).await;
    let (shards, _) = query::rollup_scan_sharded(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        &f,
        // 4 shards per worker keeps mutex convoying rare on big maps.
        bgflow_store::scan_threads() * 4,
        |r, out| {
            out.push((
                (
                    r.src_ip(),
                    r.dst_ip(),
                    r.src_port(),
                    r.dst_port(),
                    r.protocol(),
                    r.src_asn(),
                    r.dst_asn(),
                ),
                Agg {
                    bytes: r.bytes(),
                    packets: r.packets(),
                    flows: r.flows(),
                },
            ));
        },
        |a: &mut Agg, b: Agg| agg_add(a, &b),
        unit_init,
        unit_add,
        unit_merge,
    )
    .map_err(|e| err(e.to_string()))?;

    let rows = shard_top(shards, limit);
    let out: Vec<_> = rows
        .into_iter()
        .map(|((s, d, sp, dp, p, sa, da), a)| {
            serde_json::json!({
                "src_ip": bgflow_types::ip_string(s),
                "dst_ip": bgflow_types::ip_string(d),
                "src_port": sp, "dst_port": dp,
                "src_asn": sa, "dst_asn": da,
                "protocol": p, "protocol_name": bgflow_types::protocol_name(p),
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "items": out,
        "set": set_name(set),
        // Hourly rows mask IPs to /24·/48 — conversation endpoints are
        // approximate at that granularity.
        "approximate": set == RollupSet::Hourly,
    })))
}


/// Anomaly detection: per-key bytes-per-bucket series over the window;
/// flags buckets whose value exceeds mean + `sigma`·stddev of the series.
pub(super) async fn anomalies(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let set = auto_rollup_set(&q, from, to, &f);
    let by = q.get("by").map(|s| s.as_str()).unwrap_or("src_ip");
    if !TOP_DIMS.contains(&by) {
        return Err(err(format!("unknown dimension '{}'", by)));
    }
    let sigma: f64 = q.get("sigma").and_then(|s| s.parse().ok()).unwrap_or(3.0);
    let top_n: usize = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(10).min(100);
    let needed = query::rollup_needed(&f, &[by]);

    // key -> bucket -> bytes. Flattened to (key, bucket) pairs so the
    // scan can run key-sharded in parallel; regrouped below. Each pair's
    // complete aggregate lives in exactly one shard.
    let _scan = scan_permit(&st.ctx).await;
    let (shards, _) = query::rollup_scan_sharded(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        &f,
        // 4 shards per worker keeps mutex convoying rare on big maps.
        bgflow_store::scan_threads() * 4,
        |r, out| {
            out.push((
                (query::dim_key(by, r), r.bucket_ms()),
                Agg {
                    bytes: r.bytes(),
                    packets: r.packets(),
                    flows: r.flows(),
                },
            ));
        },
        |a: &mut Agg, b: Agg| agg_add(a, &b),
        unit_init,
        unit_add,
        unit_merge,
    )
    .map_err(|e| err(e.to_string()))?;

    let mut series: HashMap<u128, HashMap<u64, u64>> = HashMap::new();
    for map in shards {
        for ((k, b), a) in map {
            *series.entry(k).or_default().entry(b).or_insert(0) += a.bytes;
        }
    }

    // Optional "new in window" marking: with compare=1, keys absent from
    // the preceding equal-length window get is_new=true.
    let prev_keys: Option<std::collections::HashSet<u128>> = if q.contains_key("compare") {
        let span = to.saturating_sub(from);
        let (shards2, _) = query::rollup_scan_sharded(
            &st.ctx,
            set,
            from.saturating_sub(span),
            from,
            &needed,
            &f,
            bgflow_store::scan_threads() * 4,
            |r, out| {
                out.push((query::dim_key(by, r), 1u8));
            },
            |a: &mut u8, b: u8| *a |= b,
            unit_init,
            unit_add,
            unit_merge,
        )
        .map_err(|e| err(e.to_string()))?;
        let mut s = std::collections::HashSet::new();
        for m in shards2 {
            for (k, _) in m {
                s.insert(k);
            }
        }
        Some(s)
    } else {
        None
    };

    struct Anom {
        key: u128,
        bucket: u64,
        bytes: u64,
        z: f64,
    }
    let mut out: Vec<Anom> = Vec::new();
    for (k, buckets) in &series {
        if buckets.len() < 3 {
            continue; // need a baseline
        }
        let vals: Vec<f64> = buckets.values().map(|v| *v as f64).collect();
        let mean = vals.iter().sum::<f64>() / vals.len() as f64;
        let var = vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / vals.len() as f64;
        let std = var.sqrt();
        if std < 1.0 {
            continue; // flat series — nothing anomalous
        }
        for (b, bytes) in buckets {
            let z = (*bytes as f64 - mean) / std;
            if z >= sigma {
                out.push(Anom { key: *k, bucket: *b, bytes: *bytes, z });
            }
        }
    }
    out.sort_by(|a, b| b.z.partial_cmp(&a.z).unwrap_or(std::cmp::Ordering::Equal));
    out.truncate(top_n);
    let items: Vec<_> = out
        .into_iter()
        .map(|a| {
            serde_json::json!({
                "key": query::format_key(&st.ctx, by, a.key),
                "key_raw": a.key.to_string(),
                "bucket_ms": a.bucket,
                "t": a.bucket / 1000,
                "bytes": a.bytes,
                "zscore": (a.z * 100.0).round() / 100.0,
                "is_new": prev_keys.as_ref().map(|s| !s.contains(&a.key)),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "by": by,
        "sigma": sigma,
        "items": items,
        "set": set_name(set),
        "approximate": set == RollupSet::Hourly && matches!(by, "src_ip" | "dst_ip"),
    })))
}

/// Traffic grouped by label (uses the label dimension).
pub(super) async fn label_stats(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let f = rollup_filter(&q, &st.ctx)?;
    let set = auto_rollup_set(&q, from, to, &f);
    let needed = query::rollup_needed(&f, &["label"]);
    // Label count is bounded by the ruleset — small state, parallel-safe.
    let map: HashMap<u128, Agg> = {
        let _scan = scan_permit(&st.ctx).await;
        query::rollup_scan_par::<HashMap<u128, Agg>>(
        &st.ctx,
        set,
        from,
        to,
        &needed,
        Default::default,
        |map, r| {
            if !f.matches(r) {
                return;
            }
            let k = r.label_id() as u128;
            let a = map.entry(k).or_default();
            a.bytes += r.bytes();
            a.packets += r.packets();
            a.flows += r.flows();
        },
        |a, b| merge_agg_map(a, b),
    )
    .map_err(|e| err(e.to_string()))?
    };
    let mut rows: Vec<(u128, Agg)> = map.into_iter().collect();
    rows.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));
    let items: Vec<_> = rows
        .into_iter()
        .map(|(k, a)| {
            serde_json::json!({
                "label_id": k as u32,
                "label": query::format_key(&st.ctx, "label", k),
                "bytes": a.bytes, "packets": a.packets, "flows": a.flows,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({"items": items, "set": set_name(set)})))
}

