//! Flow protocol parsers: NetFlow v5/v9, IPFIX, sFlow v5.
//!
//! `parse_datagram` auto-detects the protocol from the packet header, so a
//! single UDP listener can accept mixed exporters.

mod cursor;
pub mod export;
mod ipfix;
mod netflow_v5;
mod netflow_v9;
mod sflow;
mod stream;
mod template;

pub use export::{ExportProto, FlowExporter};
pub use ipfix::BootEstimator;
pub use netflow_v9::{DomainTemplates, TemplateKey};
pub use stream::IpfixTcpDecoder;

use bgflow_types::FlowRecord;
use std::collections::HashMap;
use std::net::IpAddr;

/// Per-exporter session state: template caches and boot-time estimators.
/// Owned by the ingest task; not shared across threads.
#[derive(Debug, Default)]
pub struct SessionState {
    /// (exporter ip, domain id, version) -> template id -> Template
    pub templates: HashMap<TemplateKey, DomainTemplates>,
    /// IPFIX sysUpTime boot-epoch estimators per (exporter, obs domain).
    pub ipfix_boots: BootEstimator,
}

/// Explicit protocol selection (for listeners pinned to one format).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoHint {
    Auto,
    NetFlow5,
    NetFlow9,
    Ipfix,
    SFlow,
}

/// Parse one export datagram into flow records.
///
/// `exporter` is the UDP source address of the datagram (used as the
/// exporter identity and template-cache key). `now_ms` is the local receipt
/// time, used for protocols without per-flow timestamps (sFlow).
pub fn parse_datagram(
    state: &mut SessionState,
    hint: ProtoHint,
    payload: &[u8],
    exporter: IpAddr,
    now_ms: u64,
) -> Vec<FlowRecord> {
    if payload.len() < 4 {
        return Vec::new();
    }

    let detected = match hint {
        ProtoHint::NetFlow5 => 5u16,
        ProtoHint::NetFlow9 => 9,
        ProtoHint::Ipfix => 10,
        ProtoHint::SFlow => 0,
        ProtoHint::Auto => detect(payload),
    };

    match detected {
        5 => netflow_v5::parse(payload, exporter, now_ms),
        9 => netflow_v9::parse(payload, exporter, &mut state.templates, now_ms),
        10 => ipfix::parse(
            payload,
            exporter,
            &mut state.templates,
            &mut state.ipfix_boots,
            now_ms,
        ),
        0 => sflow::parse(payload, exporter, now_ms),
        _ => Vec::new(),
    }
}

/// Auto-detect protocol from the datagram header.
/// Returns 5/9/10 for NetFlow/IPFIX, 0 for sFlow, 0xFFFF for unknown.
fn detect(payload: &[u8]) -> u16 {
    // sFlow: version is a u32 BE == 5 -> bytes 00 00 00 05.
    if payload.len() >= 4 && u32::from_be_bytes(payload[0..4].try_into().unwrap()) == 5 {
        return 0;
    }
    // NetFlow v5/v9 and IPFIX start with u16 version.
    let v = u16::from_be_bytes(payload[0..2].try_into().unwrap());
    match v {
        5 | 9 | 10 => v,
        _ => 0xffff,
    }
}
