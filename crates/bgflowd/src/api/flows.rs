//! Raw-flow listing with cursor pagination, geo bubbles and CSV export.

use super::*;

pub(super) async fn flows(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    // Probe one row past the page size — `has_more` tells the UI whether
    // a Next page exists without a separate count scan.
    let want: usize = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(500)
        .min(10_000);
    // Keyset cursor ("<segment>:<row>") resumes where the previous page
    // stopped — deep pages don't re-scan skipped rows. `offset` remains
    // for backwards compatibility but is ignored when `cursor` is given.
    let resume = if let Some(c) = q.get("cursor") {
        let (seg, row) = c
            .rsplit_once(':')
            .and_then(|(s, r)| r.parse::<u64>().ok().map(|r| (s.to_string(), r)))
            .ok_or_else(|| err("bad cursor"))?;
        if seg.is_empty() || seg.contains(['/', '\\']) {
            return Err(err("bad cursor"));
        }
        Some((seg, row))
    } else {
        None
    };
    let mut fq = FlowQuery {
        from_ms: from,
        to_ms: to,
        limit: want + 1,
        offset: if resume.is_some() {
            0
        } else {
            q.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0)
        },
        resume,
        // Probe row (limit = want+1) decides has_more; the cursor still
        // resumes right after the `want`-th returned row.
        cursor_after: want,
        newest_first: q.get("order").map(|s| s != "asc").unwrap_or(true),
        ..Default::default()
    };
    if let Some(s) = q.get("src") {
        fq.src = Some(query::parse_ip_filter(s).ok_or_else(|| err("bad src"))?);
    }
    if let Some(s) = q.get("dst") {
        fq.dst = Some(query::parse_ip_filter(s).ok_or_else(|| err("bad dst"))?);
    }
    if let Some(s) = q.get("proto") {
        fq.proto = Some(parse_proto(s)?);
    }
    if let Some(s) = q.get("sport") {
        fq.sport = Some(s.parse().map_err(|_| err("bad sport"))?);
    }
    if let Some(s) = q.get("dport") {
        fq.dport = Some(s.parse().map_err(|_| err("bad dport"))?);
    }
    if let Some(s) = q.get("exporter") {
        // Comma-separated allowlist, same as rollup_filter.
        let names = st.ctx.exporter_names.read().unwrap();
        for part in s.split(',') {
            match names.resolve(part) {
                Some(u) => fq.exporters.push(u),
                None => return Err(err(format!("bad exporter '{}'", part.trim()))),
            }
        }
    }
    if let Some(s) = q.get("src_ipver") {
        fq.src_ipver = Some(parse_ipver(s)?);
    }
    if let Some(s) = q.get("dst_ipver") {
        fq.dst_ipver = Some(parse_ipver(s)?);
    }
    if let Some(s) = q.get("src_org") {
        fq.src_org = Some(s.parse().map_err(|_| err("bad src_org"))?);
    }
    if let Some(s) = q.get("dst_org") {
        fq.dst_org = Some(s.parse().map_err(|_| err("bad dst_org"))?);
    }
    if let Some(s) = q.get("src_asn") {
        fq.src_asn = Some(s.parse().map_err(|_| err("bad src_asn"))?);
    }
    if let Some(s) = q.get("dst_asn") {
        fq.dst_asn = Some(s.parse().map_err(|_| err("bad dst_asn"))?);
    }
    if let Some(s) = q.get("label") {
        fq.label = resolve_label(&st.ctx, s);
    }
    if let Some(s) = q.get("vlan") {
        fq.vlan = Some(s.parse().map_err(|_| err("bad vlan"))?);
    }
    if let Some(s) = q.get("ingress_if") {
        fq.ingress_if = Some(s.parse().map_err(|_| err("bad ingress_if"))?);
    }
    if let Some(s) = q.get("egress_if") {
        fq.egress_if = Some(s.parse().map_err(|_| err("bad egress_if"))?);
    }
    // City filters accept a string-table id or an exact city name.
    for (param, slot) in [("src_city", &mut fq.src_city), ("dst_city", &mut fq.dst_city)] {
        if let Some(s) = q.get(param) {
            let v = s
                .parse::<u32>()
                .ok()
                .or_else(|| st.ctx.cities.id_of(s.trim()))
                .ok_or_else(|| err(format!("unknown {} '{}'", param, s)))?;
            *slot = Some(v);
        }
    }

    let _scan = scan_permit(&st.ctx).await;
    let (mut recs, next_cursor) = query::flows(&st.ctx, &fq).map_err(|e| err(e.to_string()))?;
    let has_more = recs.len() > want || next_cursor.is_some();
    recs.truncate(want);
    // Enrich-at-read: fills org/country/asn fields the ingest-time pipeline
    // missed (pre-enrichment data, cold caches, table lookups).
    for f in recs.iter_mut() {
        crate::enrich::enrich_record(f, &st.geo, &st.http_enrich);
    }

    if q.get("format").map(|s| s.as_str()) == Some("csv") {
        let s = csv_string(&st.ctx, &recs);
        // raw=1 → a real text/csv body for downloads/scripts; default
        // stays JSON {"csv": ...} for the UI's fetch+blob path.
        if q.get("raw").map(|s| s.as_str()) == Some("1") {
            return Ok((
                [(header::CONTENT_TYPE, "text/csv; charset=utf-8")],
                s,
            )
                .into_response());
        }
        return Ok(Json(serde_json::json!({"count": recs.len(), "csv": s})).into_response());
    }
    let out: Vec<_> = recs.iter().map(|f| query::flow_json(&st.ctx, f)).collect();
    Ok(Json(serde_json::json!({
        "count": out.len(),
        "offset": fq.offset,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "flows": out,
    }))
    .into_response())
}

/// One ~1° geo bubble accumulator — shared by the geo-rollup fast path
/// and the raw-flow fallback scan.
#[derive(Default)]
pub(super) struct GeoCell {
    bytes: u64,
    packets: u64,
    flows: u64,
    lat_sum: f64,
    lon_sum: f64,
    city: u32,
    // country code + byte weight per endpoint side, so a bubble can be
    // tied back to a src_country/dst_country filter.
    dst_cc: u16,
    dst_w: u64,
    src_cc: u16,
    src_w: u64,
}

#[allow(clippy::too_many_arguments)]
fn geo_cell_add(
    cells: &mut std::collections::HashMap<(i32, i32), GeoCell>,
    la: i32,
    lo: i32,
    bytes: u64,
    packets: u64,
    flows: u64,
    lat_sum: f64,
    lon_sum: f64,
    city: u32,
    dst_cc: u16,
    src_cc: u16,
    dst_w: u64,
    src_w: u64,
) {
    let c = cells.entry((la, lo)).or_default();
    c.bytes += bytes;
    c.packets += packets;
    c.flows += flows;
    c.lat_sum += lat_sum;
    c.lon_sum += lon_sum;
    if c.city == 0 {
        c.city = city;
    }
    if c.dst_cc == 0 {
        c.dst_cc = dst_cc;
    }
    if c.src_cc == 0 {
        c.src_cc = src_cc;
    }
    c.dst_w += dst_w;
    c.src_w += src_w;
}

/// GET /api/v1/geo — aggregate flows into lat/lon bubbles for the geo
/// map view. Reads the minute-bucketed geo rollup dataset for covered
/// ranges (fast); falls back to scanning raw flows for history that
/// predates the geo dataset (raw flows only carry geo on schema ≥4 and
/// have short retention, so this is a "recent hotspots" view).
pub(super) async fn geo(
    State(st): State<Arc<AppState>>,
    Query(q): Query<Q>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (from, to) = range(&q);
    let limit = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(300).min(1000);
    let mut cells: std::collections::HashMap<(i32, i32), GeoCell> = std::collections::HashMap::new();
    let _scan = scan_permit(&st.ctx).await;
    let deadline = query::scan_deadline(&st.ctx);
    let mut timed_out = false;
    let deadline_hit = |i: usize, timed_out: &mut bool| -> bool {
        if let Some(d) = deadline {
            if i & 0x3FFF == 0 && std::time::Instant::now() > d {
                *timed_out = true;
                return true;
            }
        }
        false
    };

    // Geo rollup fast path. geo_min is the earliest surviving geo bucket
    // — itself minute-aligned, so it partitions time cleanly: flows with
    // ts >= geo_min are in the geo dataset, older ones only in raw.
    let geo_infos = st.ctx.geo_index.read().unwrap().clone();
    let geo_min = geo_infos.iter().map(|s| s.header.min_ts_ms).min();
    let mut used_geo = false;
    let mut used_raw = false;
    if let Some(g0) = geo_min {
        if g0 <= to {
            used_geo = true;
            let g_from = from.max(g0);
            bgflow_store::for_each_segment_info::<bgflow_types::GeoRecord>(
                &geo_infos,
                bgflow_types::GeoRecord::schema(),
                g_from,
                to,
                false,
                |scan| {
                    for i in 0..scan.rows {
                        if deadline_hit(i, &mut timed_out) {
                            return std::ops::ControlFlow::Break(());
                        }
                        let r = bgflow_types::GeoRecord::from_scan(scan, i);
                        if r.bucket_ms < g_from || r.bucket_ms > to {
                            continue;
                        }
                        let fl = r.flows.max(1) as f64;
                        geo_cell_add(
                            &mut cells,
                            r.lat_cell as i32 - 90,
                            r.lon_cell as i32 - 180,
                            r.bytes,
                            r.packets,
                            r.flows,
                            r.lat_sum as f64 / 100_000.0 - 90.0 * fl,
                            r.lon_sum as f64 / 100_000.0 - 180.0 * fl,
                            r.city,
                            r.dst_cc,
                            r.src_cc,
                            r.dst_w,
                            r.src_w,
                        );
                    }
                    std::ops::ControlFlow::Continue(())
                },
            )
            .map_err(|e| err(e.to_string()))?;
        }
    }
    if timed_out {
        return Err(err("query exceeded scan timeout"));
    }

    // Raw-flow fallback: everything before the geo dataset starts (or the
    // whole range when no geo data exists yet).
    let raw_to = match geo_min {
        Some(g0) if g0 <= to => to.min(g0.saturating_sub(1)),
        _ => to,
    };
    if from <= raw_to {
        used_raw = true;
        let infos = st.ctx.flow_index.read().unwrap().clone();
        // Column-subset decode: geo needs 11 of 40 columns — ~3-4x less
        // decompression work than decode_all. Segments written under older
        // schemas simply lack the geo columns (read as 0).
        use bgflow_store::schema::raw_idx as ix;
        const GEO_COLS: &[usize] = &[
            ix::TS_MS,
            ix::BYTES,
            ix::PACKETS,
            ix::SRC_COUNTRY,
            ix::DST_COUNTRY,
            ix::SRC_CITY,
            ix::DST_CITY,
            ix::SRC_LAT,
            ix::DST_LAT,
            ix::SRC_LON,
            ix::DST_LON,
        ];
        bgflow_store::for_each_segment_cols(
            &infos,
            bgflow_types::FlowRecord::schema(),
            GEO_COLS,
            from,
            raw_to,
            false,
            |columns, rows| {
                let mut arr: Vec<Option<&bgflow_store::ColumnData>> =
                    vec![None; bgflow_types::FlowRecord::schema().columns.len()];
                for (ci, data) in columns {
                    arr[*ci] = Some(data);
                }
                let get = |ci: usize, i: usize| -> u128 {
                    arr.get(ci)
                        .and_then(|o| *o)
                        .map(|c| c.value_at(i))
                        .unwrap_or(0)
                };
                for i in 0..rows {
                    if deadline_hit(i, &mut timed_out) {
                        return std::ops::ControlFlow::Break(());
                    }
                    let ts = get(ix::TS_MS, i) as u64;
                    if ts < from || ts > raw_to {
                        continue;
                    }
                    let bytes = get(ix::BYTES, i) as u64;
                    let packets = get(ix::PACKETS, i) as u64;
                    // Weight each endpoint's geo by its share — simpler: count
                    // dst geo for outbound-ish and src for the rest? Use dst
                    // when present else src (matches "where traffic goes").
                    let dst_lat = get(ix::DST_LAT, i) as u32;
                    let dst_lon = get(ix::DST_LON, i) as u32;
                    let dst_city = get(ix::DST_CITY, i) as u32;
                    let (lat, lon, city, cc, is_dst) = if dst_lat != 0 || dst_lon != 0 || dst_city != 0 {
                        (
                            dst_lat,
                            dst_lon,
                            dst_city,
                            get(ix::DST_COUNTRY, i) as u16,
                            true,
                        )
                    } else {
                        (
                            get(ix::SRC_LAT, i) as u32,
                            get(ix::SRC_LON, i) as u32,
                            get(ix::SRC_CITY, i) as u32,
                            get(ix::SRC_COUNTRY, i) as u16,
                            false,
                        )
                    };
                    if lat == 0 && lon == 0 {
                        continue;
                    }
                    let la = (lat as f64 / 100000.0 - 90.0).round() as i32;
                    let lo = (lon as f64 / 100000.0 - 180.0).round() as i32;
                    geo_cell_add(
                        &mut cells,
                        la,
                        lo,
                        bytes,
                        packets,
                        1,
                        lat as f64 / 100000.0 - 90.0,
                        lon as f64 / 100000.0 - 180.0,
                        city,
                        if is_dst { cc } else { 0 },
                        if is_dst { 0 } else { cc },
                        if is_dst { bytes } else { 0 },
                        if is_dst { 0 } else { bytes },
                    );
                }
                std::ops::ControlFlow::Continue(())
            },
        )
        .map_err(|e| err(e.to_string()))?;
    }
    if timed_out {
        return Err(err("query exceeded scan timeout"));
    }
    let set = match (used_geo, used_raw) {
        (true, true) => "geo+flows",
        (true, false) => "geo",
        _ => "flows",
    };

    let mut pts: Vec<_> = cells
        .into_iter()
        .map(|((_, _), c)| {
            // Dominant side wins; fall back to whichever has a country code.
            let (cc, side) = if c.dst_w >= c.src_w {
                if c.dst_cc != 0 {
                    (c.dst_cc, "dst")
                } else {
                    (c.src_cc, "src")
                }
            } else if c.src_cc != 0 {
                (c.src_cc, "src")
            } else {
                (c.dst_cc, "dst")
            };
            serde_json::json!({
                "lat": c.lat_sum / c.flows.max(1) as f64,
                "lon": c.lon_sum / c.flows.max(1) as f64,
                "bytes": c.bytes,
                "packets": c.packets,
                "flows": c.flows,
                "city": st.ctx.cities.name(c.city),
                "country": country_str(cc),
                "side": side,
            })
        })
        .collect();
    pts.sort_by(|a, b| b["bytes"].as_u64().cmp(&a["bytes"].as_u64()));
    pts.truncate(limit);
    Ok(Json(serde_json::json!({
        "points": pts,
        "from": from,
        "to": to,
        "set": set,
    })))
}

pub(super) fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub(super) fn csv_string(ctx: &query::Ctx, recs: &[bgflow_types::FlowRecord]) -> String {
    let mut s = String::from(
        "ts,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,exporter,src_asn,dst_asn,src_city,dst_city,src_region,dst_region,src_lat,src_lon,dst_lat,dst_lon,label_id\n",
    );
    for f in recs {
        let coord = |v: u32, bias: f64| {
            if v == 0 { String::new() } else { format!("{:.5}", v as f64 / 100000.0 - bias) }
        };
        s.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            f.ts_ms,
            csv_escape(&bgflow_types::ip_string(f.src_ip)),
            csv_escape(&bgflow_types::ip_string(f.dst_ip)),
            f.src_port,
            f.dst_port,
            f.protocol,
            f.bytes,
            f.packets,
            csv_escape(&bgflow_types::ip_string(f.exporter)),
            f.src_asn,
            f.dst_asn,
            csv_escape(ctx.cities.name(f.src_city).as_deref().unwrap_or("")),
            csv_escape(ctx.cities.name(f.dst_city).as_deref().unwrap_or("")),
            csv_escape(ctx.cities.name(f.src_region).as_deref().unwrap_or("")),
            csv_escape(ctx.cities.name(f.dst_region).as_deref().unwrap_or("")),
            coord(f.src_lat, 90.0),
            coord(f.src_lon, 180.0),
            coord(f.dst_lat, 90.0),
            coord(f.dst_lon, 180.0),
            f.label_id,
        ));
    }
    s
}

