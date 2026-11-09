//! UDP ingest listeners: bind, receive datagrams, auto-detect protocol,
//! parse, enrich, label, and forward FlowRecords to the writer.

use crate::config::{proto_hint, InputConfig};
use crate::enrich::{enrich_record, HttpEnrichers, MmdbGeo, StringTable};
use crate::metrics::{now_ms, Metrics};
use crate::rules::Ruleset;
use bgflow_netflow::{parse_datagram, ProtoHint, SessionState};
use bgflow_types::FlowRecord;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub struct IngestShared {
    pub geo: Arc<MmdbGeo>,
    pub http: Arc<HttpEnrichers>,
    pub rules: Arc<Ruleset>,
    pub orgs: Arc<StringTable>,
    pub metrics: Arc<Metrics>,
}

/// Spawn one listener task per configured input.
pub fn spawn_all(
    inputs: Vec<InputConfig>,
    tx: mpsc::Sender<FlowRecord>,
    shared: IngestShared,
) -> Vec<tokio::task::JoinHandle<()>> {
    inputs
        .into_iter()
        .map(|cfg| {
            let tx = tx.clone();
            let sh = IngestShared {
                geo: shared.geo.clone(),
                http: shared.http.clone(),
                rules: shared.rules.clone(),
                orgs: shared.orgs.clone(),
                metrics: shared.metrics.clone(),
            };
            tokio::spawn(async move {
                if let Err(e) = run_input(cfg, tx, sh).await {
                    tracing::error!("ingest listener failed: {}", e);
                }
            })
        })
        .collect()
}

async fn run_input(
    cfg: InputConfig,
    tx: mpsc::Sender<FlowRecord>,
    shared: IngestShared,
) -> anyhow::Result<()> {
    let hint: ProtoHint = proto_hint(&cfg.protocol);
    let sock = UdpSocket::bind(cfg.listen).await?;
    tracing::info!(
        "ingest: listening on {} (protocol={})",
        cfg.listen,
        cfg.protocol
    );

    let mut buf = vec![0u8; 65535];
    let mut state = SessionState::default();
    let allowed: Vec<IpAddr> = cfg.allowed_exporters.clone();

    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("ingest recv error: {}", e);
                continue;
            }
        };
        if !allowed.is_empty() && !allowed.contains(&src.ip()) {
            continue;
        }
        let payload = &buf[..n];
        let now = now_ms();
        let records = parse_datagram(&mut state, hint, payload, src.ip(), now);

        if records.is_empty() {
            // Could be a template-only datagram (v9/IPFIX) — not an error.
            // Count only truly undecodable payloads.
            if payload.len() >= 4 {
                let v = u16::from_be_bytes([payload[0], payload[1]]);
                if !matches!(v, 5 | 9 | 10) {
                    shared.metrics.unknown_proto.fetch_add(1, Ordering::Relaxed);
                }
            }
            continue;
        }

        shared.metrics.note_datagram(src.ip(), n, records.len());

        for mut rec in records {
            // Synchronous enrichment: MMDB, then cached HTTP results.
            enrich_record(&mut rec, &shared.geo, &shared.http);
            // Label rules (needs org names for `org` substring matches).
            rec.label_id = shared
                .rules
                .label(&rec, |id| shared.orgs.name(id));
            if tx.try_send(rec).is_err() {
                shared.metrics.channel_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
