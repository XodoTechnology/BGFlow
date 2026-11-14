//! Fuzz-ish robustness tests for the flow parsers: pseudo-random garbage,
//! structure-aware mutations of valid datagrams, and TCP stream feeding.
//! Deterministic xorshift PRNG — no external deps. The contract under
//! test is "never panic"; parsers return Vec/Result and may legitimately
//! produce zero records.

use bgflow_netflow::{parse_datagram, IpfixTcpDecoder, ProtoHint, SessionState};
use std::net::{IpAddr, Ipv4Addr};

const EXPORTER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const NOW_MS: u64 = 1_700_000_000_000;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

// ---------------------------------------------------------------------------
// Fixtures (mirrors parsers.rs — kept self-contained)
// ---------------------------------------------------------------------------

fn nfv5_datagram() -> Vec<u8> {
    let mut p = Vec::new();
    let now_s = 1_700_000_000u32;
    p.extend_from_slice(&5u16.to_be_bytes());
    p.extend_from_slice(&2u16.to_be_bytes());
    p.extend_from_slice(&60_000u32.to_be_bytes());
    p.extend_from_slice(&now_s.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.push(1);
    p.push(0);
    p.extend_from_slice(&0u16.to_be_bytes());
    let mut r = Vec::new();
    r.extend_from_slice(&[192, 168, 1, 10]);
    r.extend_from_slice(&[8, 8, 8, 8]);
    r.extend_from_slice(&[10, 0, 0, 1]);
    r.extend_from_slice(&1u16.to_be_bytes());
    r.extend_from_slice(&2u16.to_be_bytes());
    r.extend_from_slice(&10u32.to_be_bytes());
    r.extend_from_slice(&840u32.to_be_bytes());
    r.extend_from_slice(&59_000u32.to_be_bytes());
    r.extend_from_slice(&60_000u32.to_be_bytes());
    r.extend_from_slice(&12345u16.to_be_bytes());
    r.extend_from_slice(&53u16.to_be_bytes());
    r.push(0);
    r.push(0);
    r.push(17);
    r.push(0);
    r.extend_from_slice(&65001u16.to_be_bytes());
    r.extend_from_slice(&15169u16.to_be_bytes());
    r.push(24);
    r.push(24);
    r.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&r);
    let mut r2 = r.clone();
    r2[0..4].copy_from_slice(&[10, 0, 0, 5]);
    r2[4..8].copy_from_slice(&[1, 1, 1, 1]);
    r2[32..34].copy_from_slice(&443u16.to_be_bytes());
    r2[34..36].copy_from_slice(&8443u16.to_be_bytes());
    r2[36] = 0;
    r2[37] = 0x12;
    r2[38] = 6;
    r2[16..20].copy_from_slice(&3u32.to_be_bytes());
    r2[20..24].copy_from_slice(&2920u32.to_be_bytes());
    p.extend_from_slice(&r2);
    p
}

fn fld(ie: u16, len: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ie.to_be_bytes());
    v.extend_from_slice(&len.to_be_bytes());
    v
}

fn nfv9_datagram() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&9u16.to_be_bytes());
    p.extend_from_slice(&2u16.to_be_bytes()); // count: template + data
    p.extend_from_slice(&5_000u32.to_be_bytes());
    p.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes()); // unixNsecs
    p.extend_from_slice(&1u32.to_be_bytes()); // flowSequence
    p.extend_from_slice(&0u32.to_be_bytes()); // domain
    // template flowset (id 0)
    let mut tb = Vec::new();
    tb.extend_from_slice(&256u16.to_be_bytes());
    let fields: &[(u16, u16)] = &[
        (8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4), (21, 4), (22, 4),
        (16, 4), (17, 4),
    ];
    tb.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for (ie, l) in fields {
        tb.extend_from_slice(&fld(*ie, *l));
    }
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&((tb.len() + 4) as u16).to_be_bytes());
    p.extend_from_slice(&tb);
    // data flowset (id 256)
    let mut rec = Vec::new();
    rec.extend_from_slice(&[10, 1, 2, 3]);
    rec.extend_from_slice(&[8, 8, 4, 4]);
    rec.extend_from_slice(&51000u16.to_be_bytes());
    rec.extend_from_slice(&443u16.to_be_bytes());
    rec.push(6);
    rec.extend_from_slice(&1_000_000u32.to_be_bytes());
    rec.extend_from_slice(&500u32.to_be_bytes());
    rec.extend_from_slice(&5_000u32.to_be_bytes()); // end sysup
    rec.extend_from_slice(&4_000u32.to_be_bytes()); // start sysup
    rec.extend_from_slice(&64512u32.to_be_bytes());
    rec.extend_from_slice(&15169u32.to_be_bytes());
    p.extend_from_slice(&256u16.to_be_bytes());
    p.extend_from_slice(&((rec.len() + 4) as u16).to_be_bytes());
    p.extend_from_slice(&rec);
    p
}

fn ipfix_ent_field(ie: u16, len: u16, pen: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(ie | 0x8000).to_be_bytes());
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(&pen.to_be_bytes());
    v
}

fn ipfix_datagram() -> Vec<u8> {
    let mut tb = Vec::new();
    tb.extend_from_slice(&300u16.to_be_bytes());
    tb.extend_from_slice(&8u16.to_be_bytes());
    tb.extend_from_slice(&fld(8, 4));
    tb.extend_from_slice(&fld(12, 4));
    tb.extend_from_slice(&fld(7, 2));
    tb.extend_from_slice(&fld(11, 2));
    tb.extend_from_slice(&fld(4, 1));
    tb.extend_from_slice(&fld(85, 4));
    tb.extend_from_slice(&ipfix_ent_field(999, 8, 29305));
    tb.extend_from_slice(&fld(230, 0xffff));

    let mut rec = Vec::new();
    rec.extend_from_slice(&[192, 0, 2, 1]);
    rec.extend_from_slice(&[203, 0, 113, 9]);
    rec.extend_from_slice(&40000u16.to_be_bytes());
    rec.extend_from_slice(&443u16.to_be_bytes());
    rec.push(6);
    rec.extend_from_slice(&5000u32.to_be_bytes());
    rec.extend_from_slice(&[0xAA; 8]);
    rec.push(5);
    rec.extend_from_slice(b"hello");

    let tset = {
        let mut v = Vec::new();
        v.extend_from_slice(&2u16.to_be_bytes());
        v.extend_from_slice(&((tb.len() + 4) as u16).to_be_bytes());
        v.extend_from_slice(&tb);
        v
    };
    let dset = {
        let mut v = Vec::new();
        v.extend_from_slice(&300u16.to_be_bytes());
        v.extend_from_slice(&((rec.len() + 4) as u16).to_be_bytes());
        v.extend_from_slice(&rec);
        v
    };
    let msg_len = 16 + tset.len() + dset.len();
    let mut p = Vec::new();
    p.extend_from_slice(&10u16.to_be_bytes());
    p.extend_from_slice(&(msg_len as u16).to_be_bytes());
    p.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    p.extend_from_slice(&7u32.to_be_bytes());
    p.extend_from_slice(&9u32.to_be_bytes());
    p.extend_from_slice(&tset);
    p.extend_from_slice(&dset);
    p
}

fn sflow_datagram() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&5u32.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes()); // agent AF ipv4
    p.extend_from_slice(&[10, 0, 0, 1]);
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&42u32.to_be_bytes());
    p.extend_from_slice(&1_000_000u32.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&100u32.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&1u32.to_be_bytes());
    let mut rec = Vec::new();
    rec.extend_from_slice(&500u32.to_be_bytes());
    rec.extend_from_slice(&6u32.to_be_bytes());
    rec.extend_from_slice(&[192, 168, 1, 5]);
    rec.extend_from_slice(&[93, 184, 216, 34]);
    rec.extend_from_slice(&51000u32.to_be_bytes());
    rec.extend_from_slice(&443u32.to_be_bytes());
    rec.extend_from_slice(&0x12u32.to_be_bytes());
    rec.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&3u32.to_be_bytes());
    body.extend_from_slice(&(rec.len() as u32).to_be_bytes());
    body.extend_from_slice(&rec);
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(&(body.len() as u32).to_be_bytes());
    p.extend_from_slice(&body);
    p
}

// ---------------------------------------------------------------------------
// Fuzz drivers
// ---------------------------------------------------------------------------

const HINTS: [ProtoHint; 5] = [
    ProtoHint::Auto,
    ProtoHint::NetFlow5,
    ProtoHint::NetFlow9,
    ProtoHint::Ipfix,
    ProtoHint::SFlow,
];

/// Random garbage, sometimes prefixed with a plausible version header so
/// deeper decode paths get exercised.
#[test]
fn fuzz_random_datagrams_never_panic() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut st = SessionState::default();
    let mut dec = IpfixTcpDecoder::new(EXPORTER);
    for _ in 0..20000 {
        let len = rng.below(1500);
        let mut p = rng.bytes(len);
        let hdr: &[u8] = match rng.below(6) {
            0 => &5u16.to_be_bytes(),
            1 => &9u16.to_be_bytes(),
            2 => &10u16.to_be_bytes(),
            3 => &5u32.to_be_bytes(),
            _ => &[],
        };
        p.splice(0..0, hdr.iter().copied());
        let hint = HINTS[rng.below(HINTS.len())];
        let _ = parse_datagram(&mut st, hint, &p, EXPORTER, NOW_MS);
        // Also feed through the TCP decoder in random-sized chunks.
        if !p.is_empty() {
            let cut = rng.below(p.len() + 1);
            let _ = dec.feed(&p[..cut], NOW_MS);
            let _ = dec.feed(&p[cut..], NOW_MS);
        }
    }
}

/// Mutate valid datagrams: random byte flips, truncations, extensions.
/// Keeps the protocol version intact most of the time so record-level
/// decode paths run on corrupted field values.
#[test]
fn fuzz_mutations_never_panic() {
    let fixtures: Vec<(Vec<u8>, ProtoHint)> = vec![
        (nfv5_datagram(), ProtoHint::NetFlow5),
        (nfv9_datagram(), ProtoHint::NetFlow9),
        (ipfix_datagram(), ProtoHint::Ipfix),
        (sflow_datagram(), ProtoHint::SFlow),
    ];
    let mut rng = Rng(0xD1B54A32D192ED03);
    for (base, hint) in &fixtures {
        let mut st = SessionState::default();
        // Learn templates first so data-set decode runs.
        let _ = parse_datagram(&mut st, *hint, base, EXPORTER, NOW_MS);
        for _ in 0..6000 {
            let mut p = base.clone();
            match rng.below(5) {
                // byte flips (skip first 2 bytes = version most of the time)
                0 | 1 | 2 => {
                    for _ in 0..1 + rng.below(8) {
                        if p.len() > 2 {
                            let i = 2 + rng.below(p.len() - 2);
                            p[i] = rng.next() as u8;
                        }
                    }
                }
                // truncate
                3 => p.truncate(rng.below(p.len() + 1)),
                // extend with garbage
                _ => {
                    let extra = rng.below(64);
                    p.extend_from_slice(&rng.bytes(extra));
                }
            }
            let _ = parse_datagram(&mut st, *hint, &p, EXPORTER, NOW_MS);
            let _ = parse_datagram(&mut st, ProtoHint::Auto, &p, EXPORTER, NOW_MS);
        }
    }
}

/// Feed the valid fixtures through the TCP reassembler in adversarial
/// chunkings — partial headers, mid-message splits, garbage prefixes.
#[test]
fn fuzz_ipfix_tcp_stream_never_panics() {
    let mut rng = Rng(0x2545F4914F6CDD1D);
    let base = ipfix_datagram();
    for _ in 0..2000 {
        let mut dec = IpfixTcpDecoder::new(EXPORTER);
        // random garbage prefix, then the message in random chunks
        let plen = rng.below(32);
        let prefix = rng.bytes(plen);
        let _ = dec.feed(&prefix, NOW_MS);
        let mut off = 0;
        while off < base.len() {
            let n = 1 + rng.below(48);
            let end = (off + n).min(base.len());
            let _ = dec.feed(&base[off..end], NOW_MS);
            off = end;
        }
        // trailing garbage
        let tlen = rng.below(64);
        let tail = rng.bytes(tlen);
        let _ = dec.feed(&tail, NOW_MS);
    }
}
