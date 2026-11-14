//! NetFlow v9 parser — template-based flow records.
//!
//! Packet header is 20 bytes: version(2) count(2) sysUpTime(4) unixSecs(4)
//! flowSequence(4) sourceId(4). FlowSets follow: id(2) length(2) body.
//! Set id 0 = template, 1 = options template, >=256 = data (id = template id).

use crate::cursor::Cursor;
use crate::template::{
    decode_record, parse_template_fields, record_is_meaningful, ip_u128, FlowBuilder,
    Template, TimeCtx,
};
use bgflow_types::FlowRecord;
use std::collections::HashMap;
use std::net::IpAddr;

pub const HEADER_LEN: usize = 24;

/// Templates for one observation domain, keyed by template id.
pub type DomainTemplates = HashMap<u16, Template>;

/// Key for the template cache: (exporter ip, domain id, protocol version).
pub type TemplateKey = (u128, u32, u8);

pub fn templates_key(exporter: &IpAddr, domain: u32) -> TemplateKey {
    (ip_u128(exporter), domain, 9)
}

pub fn parse(
    payload: &[u8],
    exporter: IpAddr,
    templates: &mut HashMap<TemplateKey, DomainTemplates>,
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
    // Hint-forced dispatch (ProtoHint::NetFlow9) bypasses auto-detect —
    // validate the version here since the payload is untrusted.
    if version != 9 {
        return Vec::new();
    }
    let count = match cur.u16() {
        Ok(v) => v as usize,
        Err(_) => return Vec::new(),
    };
    let sys_uptime = match cur.u32() {
        Ok(v) => v as u64,
        Err(_) => return Vec::new(),
    };
    let unix_secs = match cur.u32() {
        Ok(v) => v as u64,
        Err(_) => return Vec::new(),
    };
    // RFC 3954 header: unixNsecs sits between unixSecs and flowSequence —
    // skipping it misaligns every subsequent field (and the first
    // flowset) by 4 bytes.
    let _unix_nsecs = match cur.u32() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let _seq = match cur.u32() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let source_id = match cur.u32() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let key = templates_key(&exporter, source_id);
    let domain = templates.entry(key).or_default();

    // boot epoch estimate from header: unix time minus uptime
    let export_ms = unix_secs * 1000;
    let boot_ms = export_ms as i64 - sys_uptime as i64;
    let ctx = TimeCtx {
        export_ms,
        boot_ms: Some(boot_ms),
    };
    let mut sysup_max = 0u64; // boot time comes from the header; unused here

    let mut builders: Vec<FlowBuilder> = Vec::new();

    for _ in 0..count {
        if cur.remaining() < 4 {
            break;
        }
        let set_id = match cur.u16() {
            Ok(v) => v,
            Err(_) => break,
        };
        let set_len = match cur.u16() {
            Ok(v) => v as usize,
            Err(_) => break,
        };
        if set_len < 4 || set_len > cur.remaining() + 4 {
            break; // corrupt set length — stop parsing this packet
        }
        let body_len = set_len - 4;
        let body = match cur.slice(body_len) {
            Ok(b) => b,
            Err(_) => break,
        };

        match set_id {
            0 => {
                // Template FlowSet
                parse_template_set(body, domain);
            }
            1 => {
                // Options Template FlowSet — skip contents
            }
            id if id >= 256 => {
                // Data FlowSet: id is the template id
                if let Some(tpl) = domain.get(&id) {
                    parse_data_set(body, tpl, &mut sysup_max, &mut builders);
                }
                // unknown template: drop records (can't decode)
            }
            _ => {}
        }
    }

    builders
        .into_iter()
        .filter(record_is_meaningful)
        .map(|b| b.finish(&ctx, boot_ms, exporter))
        .collect()
}

/// Parse a NetFlow v9 Template FlowSet body: sequence of
/// {template_id u16, field_count u16, fields...}.
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
        match parse_template_fields(&mut cur, field_count, false) {
            Ok(fields) => {
                domain.insert(template_id, Template { fields });
            }
            Err(_) => return, // malformed — stop this set
        }
    }
}

/// Parse a Data FlowSet body into FlowBuilders.
/// NetFlow v9 has no variable-length fields, so records are fixed-size.
fn parse_data_set(
    body: &[u8],
    tpl: &Template,
    sysup_max: &mut u64,
    out: &mut Vec<FlowBuilder>,
) {
    let rec_len = tpl.fixed_len();
    if rec_len == 0 || body.len() < rec_len {
        return;
    }
    let n = body.len() / rec_len;
    for i in 0..n {
        let rec = &body[i * rec_len..(i + 1) * rec_len];
        match decode_record(tpl, rec, sysup_max) {
            Ok((b, _)) => out.push(b),
            Err(e) => {
                tracing::debug!("nfv9 record decode error: {}", e);
            }
        }
    }
    // trailing bytes < rec_len are padding — ignored
}
