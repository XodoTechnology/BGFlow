//! Outbound NetFlow v9 / IPFIX export.
//!
//! The writer taps stored FlowRecords into a bounded channel; this task
//! re-encodes each batch per configured target and sends UDP datagrams.
//! Export is strictly best-effort: a full queue or send error drops data
//! and bumps metrics — it never blocks or fails ingestion/storage.

use crate::config::ExportTargetConfig;
use crate::metrics::{now_ms, Metrics};
use bgflow_netflow::export::{ExportProto, FlowExporter};
use bgflow_types::FlowRecord;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// One resolved export destination.
pub struct ExportTarget {
    pub name: String,
    pub addr: SocketAddr,
    pub exporter: FlowExporter,
    pub max_datagram: usize,
}

/// Parse + validate [[export]] configs into runnable targets. Bad
/// addresses/protocols are logged and skipped rather than fatal.
pub fn resolve(cfgs: &[ExportTargetConfig], boot_ms: i64) -> Vec<ExportTarget> {
    let mut out = Vec::new();
    for (i, c) in cfgs.iter().enumerate() {
        let addr: SocketAddr = match c.address.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("export[{}] '{}': bad address: {}", i, c.address, e);
                continue;
            }
        };
        let proto = match c.protocol.to_ascii_lowercase().as_str() {
            "netflow9" | "v9" | "netflow" => ExportProto::NetFlow9,
            "ipfix" => ExportProto::Ipfix,
            other => {
                tracing::warn!("export[{}] '{}': unknown protocol '{}', skipping", i, c.address, other);
                continue;
            }
        };
        // Stable sourceId per destination (FNV-1a of the address) so a
        // collector can tell exporters apart across restarts.
        let mut h: u32 = 0x811c_9dc5;
        for b in c.address.as_bytes() {
            h = (h ^ *b as u32).wrapping_mul(0x0100_0193);
        }
        let name = c
            .name
            .clone()
            .unwrap_or_else(|| format!("{}#{}", c.address, i + 1));
        out.push(ExportTarget {
            name,
            addr,
            exporter: FlowExporter::new(proto, h | 1, boot_ms),
            max_datagram: c.max_datagram.clamp(256, 65535),
        });
    }
    out
}

/// Receive stored-flow batches and fan them out to every target.
/// UDP sockets are per address family so v4/v6 targets both work.
pub async fn run(
    mut targets: Vec<ExportTarget>,
    mut rx: mpsc::Receiver<Vec<FlowRecord>>,
    metrics: Arc<Metrics>,
) {
    let need_v4 = targets.iter().any(|t| t.addr.is_ipv4());
    let need_v6 = targets.iter().any(|t| t.addr.is_ipv6());
    let v4 = if need_v4 {
        match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::error!("export: cannot bind IPv4 UDP socket: {}", e);
                None
            }
        }
    } else {
        None
    };
    let v6 = if need_v6 {
        match UdpSocket::bind("[::]:0").await {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::error!("export: cannot bind IPv6 UDP socket: {}", e);
                None
            }
        }
    } else {
        None
    };
    tracing::info!(
        "export: {} target(s) active: {}",
        targets.len(),
        targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join(", ")
    );

    while let Some(batch) = rx.recv().await {
        if batch.is_empty() {
            continue;
        }
        let now = now_ms();
        for t in &mut targets {
            let dgrams = t.exporter.encode(&batch, now, t.max_datagram);
            let sock = if t.addr.is_ipv4() { v4.as_ref() } else { v6.as_ref() };
            let Some(sock) = sock else { continue };
            for d in dgrams {
                match sock.send_to(&d, t.addr).await {
                    Ok(_) => {
                        metrics.export_datagrams.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        metrics.export_errors.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!("export '{}': send failed: {}", t.name, e);
                    }
                }
            }
        }
        metrics
            .export_flows
            .fetch_add(batch.len() as u64, Ordering::Relaxed);
    }
    tracing::info!("export: input channel closed, task exiting");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_validates_and_names() {
        let cfgs = vec![
            ExportTargetConfig {
                address: "127.0.0.1:2055".into(),
                protocol: "ipfix".into(),
                name: Some("collector".into()),
                max_datagram: 9000,
            },
            ExportTargetConfig {
                address: "not-an-addr".into(),
                ..Default::default()
            },
            ExportTargetConfig {
                address: "10.0.0.2:4739".into(),
                protocol: "bogus".into(),
                ..Default::default()
            },
        ];
        let t = resolve(&cfgs, 0);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].name, "collector");
        assert_eq!(t[0].max_datagram, 9000);
    }
}
