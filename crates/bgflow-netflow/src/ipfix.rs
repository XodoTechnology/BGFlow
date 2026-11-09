//! IPFIX (RFC 7011) parser — version 10, template-based like NetFlow v9
//! but with enterprise-specific fields, variable-length fields, and
//! options template sets.
//!
//! Message header is 16 bytes: version(2) length(2) exportTime(4)
//! sequenceNumber(4) observationDomainId(4). All integers big-endian.

use crate::cursor::Cursor;
use crate::netflow_v9::{DomainTemplates, TemplateKey};
use crate::template::{
    decode_record, ip_u128, parse_template_fields, record_is_meaningful, FlowBuilder, TimeCtx,
};
use bgflow_types::FlowRecord;
use std::collections::HashMap;
use std::net::IpAddr;

pub const HEADER_LEN: usize = 16;

/// Persistent per-(exporter, obs-domain) boot-epoch estimate for resolving
/// sysUpTime-based timestamps. Boot time is ~constant; we resync only on
/// large drift (device reboot or clock step).
#[derive(Debug, Default)]
pub struct BootEstimator {
    map: HashMap<(u128, u32), i64>,
}

impl BootEstimator {
    /// Update the estimate with this packet's max sysUpTime and return the
    /// boot epoch ms to use for timestamp resolution.
    pub fn observe(&mut self, exporter: &IpAddr, domain: u32, export_ms: u64, pkt_sysup_max: u64) -> i64 {
        if pkt_sysup_max == 0 {
            // No sysUpTime fields in this packet; return existing estimate
            // (or a sane default) without updating.
            return self
                .map
                .get(&(ip_u128(exporter), domain))
                .copied()
                .unwrap_or(export_ms as i64);
        }
        let cand = export_ms as i64 - pkt_sysup_max as i64;
        let key = (ip_u128(exporter), domain);
        let entry = self.map.entry(key).or_insert(cand);
        // Resync if drift > 2 minutes (reboot, NTP step, first contact).
        if (*entry - cand).abs() > 120_000 {
            *entry = cand;
        }
        *entry
    }
}

pub fn parse(
    payload: &[u8],
    exporter: IpAddr,
    templates: &mut HashMap<TemplateKey, DomainTemplates>,
    boots: &mut BootEstimator,
    _now_ms: u64,
) -> Vec<FlowRecord> {
    if payload.len() < HEADER_LEN {
        return Vec::new();
    }
    let mut cur = Cursor::new(payload);
    let version = match cur.u16() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    debug_assert_eq!(version, 10);
    let msg_len = match cur.u16() {
        Ok(v) => v as usize,
        Err(_) => return Vec::new(),
    };
    let export_secs = match cur.u32() {
        Ok(v) => v as u64,
        Err(_) => return Vec::new(),
    };
    let _seq = match cur.u32() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let obs_domain = match cur.u32() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    // Clamp message length to actual payload.
    let msg_end = msg_len.min(payload.len()).max(HEADER_LEN);

    let export_ms = export_secs * 1000;
    let ctx = TimeCtx {
        export_ms,
        boot_ms: None,
    };

    // Template namespace: (exporter ip, obs domain, version=10 for IPFIX).
    let key = (ip_u128(&exporter), obs_domain, 10u8);
    let domain = templates.entry(key).or_default();

    let mut builders: Vec<FlowBuilder> = Vec::new();
    let mut pkt_sysup_max = 0u64;

    // Walk sets until message end.
    while cur.position() + 4 <= msg_end {
        let set_id = match cur.u16() {
            Ok(v) => v,
            Err(_) => break,
        };
        let set_len = match cur.u16() {
            Ok(v) => v as usize,
            Err(_) => break,
        };
        if set_len < 4 || cur.position() + set_len - 4 > msg_end {
            break;
        }
        let body_len = set_len - 4;
        let body = match cur.slice(body_len) {
            Ok(b) => b,
            Err(_) => break,
        };

        match set_id {
            2 => parse_template_set(body, domain),
            3 => {} // Options Template Set — skip
            id if id >= 256 => {
                if let Some(tpl) = domain.get(&id) {
                    parse_data_set(body, tpl, &mut pkt_sysup_max, &mut builders);
                }
            }
            _ => {}
        }
    }

    // Resolve boot epoch once per packet (uniform for all its records).
    let boot_ms = boots.observe(&exporter, obs_domain, export_ms, pkt_sysup_max);

    builders
        .into_iter()
        .filter(record_is_meaningful)
        .map(|b| b.finish(&ctx, boot_ms, exporter))
        .collect()
}

fn parse_template_set(body: &[u8], domain: &mut DomainTemplates) {
    let mut cur = Cursor::new(body);
    while cur.remaining() >= 4 {
        let template_id = match cur.u16() {
            Ok(v) => v,
            Err(_) => return,
        };
        let field_count = match cur.u16() {
            Ok(v) => v as usize,
            Err(_) => return,
        };
        match parse_template_fields(&mut cur, field_count, true) {
            Ok(fields) => {
                domain.insert(template_id, crate::template::Template { fields });
            }
            Err(_) => return,
        }
    }
}

/// Parse an IPFIX Data Set: records are variable-length (fields may be
/// variable-length), so we walk the body record by record using the
/// template. Trailing padding (zero bytes) ends the set.
fn parse_data_set(
    body: &[u8],
    tpl: &crate::template::Template,
    sysup_max: &mut u64,
    out: &mut Vec<FlowBuilder>,
) {
    let mut pos = 0usize;
    while pos < body.len() {
        let remaining = &body[pos..];
        // Padding: all-zero tail.
        if remaining.iter().all(|&b| b == 0) {
            break;
        }
        match decode_record(tpl, remaining, sysup_max) {
            Ok((b, consumed)) => {
                if consumed == 0 {
                    break;
                }
                pos += consumed;
                out.push(b);
            }
            Err(e) => {
                tracing::debug!("ipfix record decode error: {}", e);
                break; // can't resync — abandon rest of set
            }
        }
    }
}
