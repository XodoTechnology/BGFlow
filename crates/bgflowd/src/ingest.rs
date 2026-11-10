//! Flow ingest listeners: UDP (all protocols, auto-detected) and TCP
//! (IPFIX stream transport). Both feed parsed+enriched records to the writer.

use crate::config::{proto_hint, InputConfig};
use crate::enrich::{enrich_record, HttpEnrichers, MmdbGeo, StringTable};
use crate::metrics::{now_ms, Metrics};
use crate::rules::Ruleset;
use bgflow_netflow::{parse_datagram, IpfixTcpDecoder, ProtoHint, SessionState};
use bgflow_types::FlowRecord;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};

pub struct IngestShared {
    pub geo: Arc<MmdbGeo>,
    pub http: Arc<HttpEnrichers>,
    pub rules: Arc<Ruleset>,
    pub orgs: Arc<StringTable>,
    pub metrics: Arc<Metrics>,
}

/// Spawn listener tasks per configured input (UDP and/or TCP per `transport`).
pub fn spawn_all(
    inputs: Vec<InputConfig>,
    tx: mpsc::Sender<FlowRecord>,
    shared: IngestShared,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();
    for cfg in inputs {
        let t = cfg.transport.to_ascii_lowercase();
        let want_udp = t == "udp" || t == "both" || t.is_empty();
        let want_tcp = t == "tcp" || t == "both";

        if want_udp {
            let tx = tx.clone();
            let sh = shared.clone_sh();
            let c = cfg.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = run_udp(c, tx, sh).await {
                    tracing::error!("udp ingest failed: {}", e);
                }
            }));
        }
        if want_tcp {
            // TCP transport only supports IPFIX stream framing.
            let proto = proto_hint(&cfg.protocol);
            if !matches!(proto, ProtoHint::Auto | ProtoHint::Ipfix) {
                tracing::warn!(
                    "input {}: tcp transport only supports ipfix/auto, skipping tcp listener",
                    cfg.listen
                );
                continue;
            }
            let tx = tx.clone();
            let sh = shared.clone_sh();
            let c = cfg.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = run_tcp(c, tx, sh).await {
                    tracing::error!("tcp ingest failed: {}", e);
                }
            }));
        }
    }
    handles
}

impl IngestShared {
    fn clone_sh(&self) -> IngestShared {
        IngestShared {
            geo: self.geo.clone(),
            http: self.http.clone(),
            rules: self.rules.clone(),
            orgs: self.orgs.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

/// Enrich + label + forward a single record (or count a drop).
fn emit(rec: FlowRecord, tx: &mpsc::Sender<FlowRecord>, shared: &IngestShared) {
    let mut rec = rec;
    enrich_record(&mut rec, &shared.geo, &shared.http);
    rec.label_id = shared.rules.label(&rec, |id| shared.orgs.name(id));
    if tx.try_send(rec).is_err() {
        shared.metrics.channel_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

async fn run_udp(
    cfg: InputConfig,
    tx: mpsc::Sender<FlowRecord>,
    shared: IngestShared,
) -> anyhow::Result<()> {
    let hint: ProtoHint = proto_hint(&cfg.protocol);
    let sock = if cfg.udp_buffer_bytes > 0 {
        // Flow exports can arrive in bursts far above the OS default
        // (~200KB) socket buffer — give the kernel room to absorb them.
        let s = socket2::Socket::new(
            socket2::Domain::for_address(cfg.listen),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        s.set_recv_buffer_size(cfg.udp_buffer_bytes)?;
        s.bind(&cfg.listen.into())?;
        s.set_nonblocking(true)?;
        UdpSocket::from_std(s.into())?
    } else {
        UdpSocket::bind(cfg.listen).await?
    };
    tracing::info!(
        "ingest: udp listening on {} (protocol={}, rcvbuf={}B)",
        cfg.listen,
        cfg.protocol,
        if cfg.udp_buffer_bytes > 0 { cfg.udp_buffer_bytes } else { 0 }
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
            if payload.len() >= 4 {
                let v = u16::from_be_bytes([payload[0], payload[1]]);
                if !matches!(v, 5 | 9 | 10) {
                    shared.metrics.unknown_proto.fetch_add(1, Ordering::Relaxed);
                }
            }
            continue;
        }

        shared.metrics.note_datagram(src.ip(), n, records.len());
        for rec in records {
            emit(rec, &tx, &shared);
        }
    }
}

async fn run_tcp(
    cfg: InputConfig,
    tx: mpsc::Sender<FlowRecord>,
    shared: IngestShared,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    tracing::info!("ingest: tcp listening on {} (ipfix)", cfg.listen);
    let allowed: Vec<IpAddr> = cfg.allowed_exporters.clone();
    // Bound concurrent connections so a hostile/buggy peer can't exhaust
    // tasks+memory. 0 = unlimited.
    let conn_sem = Arc::new(Semaphore::new(if cfg.max_connections == 0 {
        usize::MAX
    } else {
        cfg.max_connections
    }));

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("tcp accept error: {}", e);
                continue;
            }
        };
        if !allowed.is_empty() && !allowed.contains(&peer.ip()) {
            drop(sock);
            continue;
        }
        // try_acquire: shed load instantly rather than queueing accepts.
        let Ok(permit) = Arc::clone(&conn_sem).try_acquire_owned() else {
            tracing::warn!("tcp {}: connection limit reached, dropping {}", cfg.listen, peer);
            continue;
        };
        let tx = tx.clone();
        let sh = shared.clone_sh();
        tokio::spawn(async move {
            let _permit = permit; // held until the connection task ends
            if let Err(e) = handle_tcp_conn(sock, peer.ip(), tx, sh).await {
                tracing::debug!("tcp conn {} ended: {}", peer, e);
            }
        });
    }
}

async fn handle_tcp_conn(
    mut sock: TcpStream,
    exporter: IpAddr,
    tx: mpsc::Sender<FlowRecord>,
    shared: IngestShared,
) -> anyhow::Result<()> {
    let mut dec = IpfixTcpDecoder::new(exporter);
    let mut buf = vec![0u8; 65536];
    loop {
        let n = sock.read(&mut buf).await?;
        if n == 0 {
            return Ok(()); // peer closed
        }
        let now = now_ms();
        let records = dec.feed(&buf[..n], now);
        shared.metrics.note_datagram(exporter, n, records.len());
        for rec in records {
            emit(rec, &tx, &shared);
        }
    }
}
