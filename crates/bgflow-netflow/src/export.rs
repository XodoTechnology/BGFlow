//! Flow export encoder: NetFlow v9 and IPFIX (RFC 7011) datagrams built
//! from stored FlowRecords. Templates are emitted ahead of data and
//! refreshed periodically so receivers always have field layouts.
//!
//! Two templates per protocol — IPv4 (id 256) and IPv6 (id 257) — since
//! address fields differ in width. Mixed-family flows go out on the v6
//! template with the v4 side written as an IPv4-mapped IPv6 address.
//!
//! Timestamps: records carry flowEnd/StartSysUpTime relative to a boot
//! epoch supplied at construction; the datagram header carries absolute
//! unix time + uptime so receivers can reconstruct wall-clock time.

use bgflow_types::{u128_to_ip, FlowRecord};
use std::net::IpAddr;

/// Wire protocol for exported datagrams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportProto {
    NetFlow9,
    Ipfix,
}

impl ExportProto {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "netflow9" | "netflow_v9" | "v9" | "9" => Some(ExportProto::NetFlow9),
            "ipfix" | "10" => Some(ExportProto::Ipfix),
            _ => None,
        }
    }
    /// IPFIX Information Element ids for byte/packet counters (v9 uses
    /// the delta-count ids 1/2 instead).
    fn octet_ie(self) -> u16 {
        match self {
            ExportProto::NetFlow9 => 1,
            ExportProto::Ipfix => 85,
        }
    }
    fn packet_ie(self) -> u16 {
        match self {
            ExportProto::NetFlow9 => 2,
            ExportProto::Ipfix => 86,
        }
    }
    /// Template flowset id (v9: 0, IPFIX: 2).
    fn template_set_id(self) -> u16 {
        match self {
            ExportProto::NetFlow9 => 0,
            ExportProto::Ipfix => 2,
        }
    }
}

// IANA IPFIX / NetFlow v9 information element ids used below.
const IE_SRC_V4: u16 = 8;
const IE_DST_V4: u16 = 12;
const IE_SRC_V6: u16 = 27;
const IE_DST_V6: u16 = 28;
const IE_SRC_PORT: u16 = 7;
const IE_DST_PORT: u16 = 11;
const IE_PROTO: u16 = 4;
const IE_TCP_FLAGS: u16 = 6;
const IE_INGRESS_IF: u16 = 10;
const IE_EGRESS_IF: u16 = 14;
const IE_NEXT_HOP_V4: u16 = 15;
const IE_NEXT_HOP_V6: u16 = 62;
const IE_BGP_SRC_AS: u16 = 16;
const IE_BGP_DST_AS: u16 = 17;
const IE_END_SYSUP: u16 = 21;
const IE_START_SYSUP: u16 = 22;
const IE_SAMPLING: u16 = 34;
const IE_ENGINE_TYPE: u16 = 38;
const IE_ENGINE_ID: u16 = 39;
const IE_VLAN: u16 = 58;
const IE_FLOW_END_REASON: u16 = 136;
const IE_IP_TTL: u16 = 192;
const IE_IP_VERSION: u16 = 60;

const TEMPLATE_ID_V4: u16 = 256;
const TEMPLATE_ID_V6: u16 = 257;
/// Re-send templates at least this often (RFC 3954 recommends periodic
/// refresh; receivers also re-learn on restart).
const TEMPLATE_REFRESH_MS: u64 = 3_600_000;

#[derive(Debug, Clone, Copy)]
struct ExField {
    ie: u16,
    len: u16,
}

/// Ordered template fields for one address family.
fn fields(proto: ExportProto, v6: bool) -> Vec<ExField> {
    let f = |ie: u16, len: u16| ExField { ie, len };
    vec![
        f(if v6 { IE_SRC_V6 } else { IE_SRC_V4 }, if v6 { 16 } else { 4 }),
        f(if v6 { IE_DST_V6 } else { IE_DST_V4 }, if v6 { 16 } else { 4 }),
        f(IE_SRC_PORT, 2),
        f(IE_DST_PORT, 2),
        f(IE_PROTO, 1),
        f(IE_TCP_FLAGS, 1),
        f(proto.octet_ie(), 4),
        f(proto.packet_ie(), 4),
        f(IE_END_SYSUP, 4),
        f(IE_START_SYSUP, 4),
        f(IE_INGRESS_IF, 4),
        f(IE_EGRESS_IF, 4),
        f(IE_BGP_SRC_AS, 4),
        f(IE_BGP_DST_AS, 4),
        f(if v6 { IE_NEXT_HOP_V6 } else { IE_NEXT_HOP_V4 }, if v6 { 16 } else { 4 }),
        f(IE_SAMPLING, 4),
        f(IE_ENGINE_TYPE, 1),
        f(IE_ENGINE_ID, 1),
        f(IE_VLAN, 2),
        f(IE_FLOW_END_REASON, 1),
        f(IE_IP_TTL, 1),
        f(IE_IP_VERSION, 1),
    ]
}

/// 16-byte wire form of a stored IP (v4 as IPv4-mapped IPv6).
fn ip16(ip: u128) -> [u8; 16] {
    match u128_to_ip(ip) {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Stateful encoder for one export target.
pub struct FlowExporter {
    proto: ExportProto,
    source_id: u32,
    /// Boot epoch (unix ms) for sysUpTime computation.
    boot_ms: i64,
    seq: u32,
    last_template_ms: u64,
    templates_sent: bool,
    fields_v4: Vec<ExField>,
    fields_v6: Vec<ExField>,
    /// Cached encoded template flowsets (with set headers).
    tmpl_v4: Vec<u8>,
    tmpl_v6: Vec<u8>,
    rec_len_v4: usize,
    rec_len_v6: usize,
}

impl FlowExporter {
    pub fn new(proto: ExportProto, source_id: u32, boot_ms: i64) -> Self {
        let fields_v4 = fields(proto, false);
        let fields_v6 = fields(proto, true);
        let rec_len_v4: usize = fields_v4.iter().map(|f| f.len as usize).sum();
        let rec_len_v6: usize = fields_v6.iter().map(|f| f.len as usize).sum();
        let tmpl_v4 = Self::template_flowset(proto, TEMPLATE_ID_V4, &fields_v4);
        let tmpl_v6 = Self::template_flowset(proto, TEMPLATE_ID_V6, &fields_v6);
        FlowExporter {
            proto,
            source_id,
            boot_ms,
            seq: 0,
            last_template_ms: 0,
            templates_sent: false,
            fields_v4,
            fields_v6,
            tmpl_v4,
            tmpl_v6,
            rec_len_v4,
            rec_len_v6,
        }
    }

    fn template_flowset(proto: ExportProto, id: u16, fields: &[ExField]) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + fields.len() * 4);
        body.extend_from_slice(&id.to_be_bytes());
        body.extend_from_slice(&(fields.len() as u16).to_be_bytes());
        for f in fields {
            body.extend_from_slice(&f.ie.to_be_bytes());
            body.extend_from_slice(&f.len.to_be_bytes());
        }
        // pad body to 4-byte boundary (zeros; < record size so receivers
        // never mistake padding for a record)
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let mut set = Vec::with_capacity(4 + body.len());
        set.extend_from_slice(&proto.template_set_id().to_be_bytes());
        set.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        set.extend_from_slice(&body);
        set
    }

    /// Whether template flowsets should be prepended to the next datagram.
    fn templates_due(&self, now_ms: u64) -> bool {
        !self.templates_sent || now_ms.saturating_sub(self.last_template_ms) >= TEMPLATE_REFRESH_MS
    }

    /// Family decision: genuine IPv6 endpoints use the v6 template;
    /// next_hop is excluded (0/unspecified is common and would misfire).
    /// Mixed-family flows take v6 — the v4 side encodes as v4-mapped.
    fn is_v6(f: &FlowRecord) -> bool {
        matches!(u128_to_ip(f.src_ip), IpAddr::V6(_))
            || matches!(u128_to_ip(f.dst_ip), IpAddr::V6(_))
    }

    fn sysup(&self, ts_ms: u64) -> u32 {
        (ts_ms as i64 - self.boot_ms).clamp(0, u32::MAX as i64) as u32
    }

    /// Encode one record into `out` per the given field layout.
    #[allow(clippy::too_many_arguments)]
    fn encode_record(
        &self,
        f: &FlowRecord,
        v6: bool,
        out: &mut Vec<u8>,
    ) {
        let fields = if v6 { &self.fields_v6 } else { &self.fields_v4 };
        let src_ip = ip16(f.src_ip);
        let dst_ip = ip16(f.dst_ip);
        let nh = ip16(f.next_hop);
        let end_ms = self.sysup(f.ts_ms);
        let start_ms = self.sysup(f.ts_ms.saturating_sub(f.duration_ms as u64));
        let bytes32 = f.bytes.min(u32::MAX as u64) as u32;
        let pkts32 = f.packets.min(u32::MAX as u64) as u32;
        for fld in fields {
            match fld.ie {
                IE_SRC_V4 | IE_SRC_V6 => {
                    if v6 {
                        out.extend_from_slice(&src_ip);
                    } else {
                        out.extend_from_slice(&src_ip[12..]);
                    }
                }
                IE_DST_V4 | IE_DST_V6 => {
                    if v6 {
                        out.extend_from_slice(&dst_ip);
                    } else {
                        out.extend_from_slice(&dst_ip[12..]);
                    }
                }
                IE_SRC_PORT => out.extend_from_slice(&f.src_port.to_be_bytes()),
                IE_DST_PORT => out.extend_from_slice(&f.dst_port.to_be_bytes()),
                IE_PROTO => out.push(f.protocol),
                IE_TCP_FLAGS => out.push(f.tcp_flags),
                x if x == self.proto.octet_ie() => out.extend_from_slice(&bytes32.to_be_bytes()),
                x if x == self.proto.packet_ie() => out.extend_from_slice(&pkts32.to_be_bytes()),
                IE_END_SYSUP => out.extend_from_slice(&end_ms.to_be_bytes()),
                IE_START_SYSUP => out.extend_from_slice(&start_ms.to_be_bytes()),
                IE_INGRESS_IF => out.extend_from_slice(&f.ingress_if.to_be_bytes()),
                IE_EGRESS_IF => out.extend_from_slice(&f.egress_if.to_be_bytes()),
                IE_BGP_SRC_AS => out.extend_from_slice(&f.src_asn.to_be_bytes()),
                IE_BGP_DST_AS => out.extend_from_slice(&f.dst_asn.to_be_bytes()),
                IE_NEXT_HOP_V4 => out.extend_from_slice(&nh[12..]),
                IE_NEXT_HOP_V6 => out.extend_from_slice(&nh),
                IE_SAMPLING => out.extend_from_slice(&f.sampler_interval.to_be_bytes()),
                IE_ENGINE_TYPE => out.push(f.engine_type),
                IE_ENGINE_ID => out.push(f.engine_id),
                IE_VLAN => out.extend_from_slice(&f.vlan.to_be_bytes()),
                IE_FLOW_END_REASON => out.push(f.flow_end_reason),
                IE_IP_TTL => out.push(f.ip_ttl),
                IE_IP_VERSION => out.push(if v6 { 6 } else { 4 }),
                _ => {}
            }
        }
    }

    /// Build complete datagrams for `flows`, each ≤ `max_datagram` bytes
    /// (payload). Returns empty vec for empty input.
    pub fn encode(&mut self, flows: &[FlowRecord], now_ms: u64, max_datagram: usize) -> Vec<Vec<u8>> {
        if flows.is_empty() {
            return Vec::new();
        }
        let want_templates = self.templates_due(now_ms);
        let mut templates_pending = want_templates;
        let tmpl_bytes = if want_templates { self.tmpl_v4.len() + self.tmpl_v6.len() } else { 0 };
        let hdr_len = if self.proto == ExportProto::NetFlow9 { 24 } else { 16 };
        let mut out: Vec<Vec<u8>> = Vec::new();
        // Greedy pack: v4 and v6 records go into separate data flowsets
        // within each datagram. `body_used` tracks bytes committed to all
        // sets so far (set header + records + ≤3B pad reserve per set).
        let mut i = 0;
        while i < flows.len() {
            let mut dgram = Vec::with_capacity(max_datagram);
            let mut sets: Vec<(u16, Vec<u8>)> = Vec::new(); // (template id, record bytes)
            let mut body_used = 0usize;
            // Only the first datagram of a refresh carries the template
            // flowsets; later ones pack tighter.
            let overhead = hdr_len + if templates_pending { tmpl_bytes } else { 0 };

            while i < flows.len() {
                let f = &flows[i];
                let v6 = Self::is_v6(f);
                let rec_len = if v6 { self.rec_len_v6 } else { self.rec_len_v4 };
                let tid = if v6 { TEMPLATE_ID_V6 } else { TEMPLATE_ID_V4 };
                let set_ix = sets.iter().position(|(t, _)| *t == tid);
                // new set costs 4B header + up to 3B pad; existing: rec_len
                let add = rec_len + if set_ix.is_none() { 7 } else { 0 };
                if overhead + body_used + add > max_datagram && !sets.is_empty() {
                    break; // datagram full — flush what we have
                }
                if set_ix.is_none() {
                    sets.push((tid, Vec::new()));
                }
                let ix = sets.iter().position(|(t, _)| *t == tid).unwrap();
                self.encode_record(f, v6, &mut sets[ix].1);
                body_used += add;
                i += 1;
            }
            if sets.is_empty() {
                break; // couldn't fit even one record — avoid infinite loop
            }
            // assemble: header + optional templates + data sets
            let with_tmpl = templates_pending;
            self.write_header(&mut dgram, now_ms, sets.len() + if with_tmpl { 2 } else { 0 });
            if with_tmpl {
                dgram.extend_from_slice(&self.tmpl_v4);
                dgram.extend_from_slice(&self.tmpl_v6);
                templates_pending = false;
            }
            for (tid, mut recs) in sets {
                while recs.len() % 4 != 0 {
                    recs.push(0);
                }
                dgram.extend_from_slice(&tid.to_be_bytes());
                dgram.extend_from_slice(&((4 + recs.len()) as u16).to_be_bytes());
                dgram.extend_from_slice(&recs);
            }
            // IPFIX header carries total message length; patch it now.
            if self.proto == ExportProto::Ipfix {
                let l = (dgram.len() as u16).to_be_bytes();
                dgram[2..4].copy_from_slice(&l);
            }
            debug_assert!(dgram.len() <= max_datagram + 8);
            out.push(dgram);
            if i >= flows.len() {
                break;
            }
        }
        if want_templates {
            self.templates_sent = true;
            self.last_template_ms = now_ms;
        }
        out
    }

    fn write_header(&mut self, dgram: &mut Vec<u8>, now_ms: u64, set_count: usize) {
        match self.proto {
            ExportProto::NetFlow9 => {
                dgram.extend_from_slice(&9u16.to_be_bytes());
                dgram.extend_from_slice(&(set_count as u16).to_be_bytes());
                let uptime = (now_ms as i64 - self.boot_ms).clamp(0, u32::MAX as i64) as u32;
                dgram.extend_from_slice(&uptime.to_be_bytes());
                let unix_s = (now_ms / 1000).min(u32::MAX as u64) as u32;
                dgram.extend_from_slice(&unix_s.to_be_bytes());
                dgram.extend_from_slice(&0u32.to_be_bytes()); // nsecs
                self.seq = self.seq.wrapping_add(1);
                dgram.extend_from_slice(&self.seq.to_be_bytes());
                dgram.extend_from_slice(&self.source_id.to_be_bytes());
            }
            ExportProto::Ipfix => {
                dgram.extend_from_slice(&10u16.to_be_bytes());
                dgram.extend_from_slice(&0u16.to_be_bytes()); // length patched later
                let unix_s = (now_ms / 1000).min(u32::MAX as u64) as u32;
                dgram.extend_from_slice(&unix_s.to_be_bytes());
                self.seq = self.seq.wrapping_add(1);
                dgram.extend_from_slice(&self.seq.to_be_bytes());
                dgram.extend_from_slice(&self.source_id.to_be_bytes()); // obs domain
            }
        }
    }
}
