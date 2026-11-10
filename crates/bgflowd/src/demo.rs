//! Synthetic NetFlow v5 traffic generator for demos and smoke tests.
//! Sends real UDP datagrams so the full ingest->store->query path is exercised.

use anyhow::Result;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::time::{interval, sleep};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A pool of "interesting" endpoints so rollups/top-N have structure.
/// (net prefix, src_asn) — private ranges get plausible ASNs.
const SRC_NETS: &[(u8, u8, u8, u32)] = &[
    (10, 0, 0, 64512),
    (10, 1, 0, 64600),
    (192, 168, 1, 64700),
    (172, 16, 0, 64800),
    (100, 64, 0, 64900),
];
/// (ip, asn) — dst_asn lands in the flow record, driving ASN dims + rules.
const DST_PUBLIC: &[(u8, u8, u8, u8, u32)] = &[
    (8, 8, 8, 8, 15169),          // Google DNS
    (8, 8, 4, 4, 15169),          // Google DNS secondary
    (1, 1, 1, 1, 13335),          // Cloudflare
    (1, 0, 0, 1, 13335),          // Cloudflare
    (9, 9, 9, 9, 19281),          // Quad9
    (151, 101, 1, 69, 22443),     // Reddit
    (104, 16, 0, 1, 13414),       // Twitter/X
    (140, 82, 121, 4, 8075),      // Microsoft
    (13, 107, 42, 14, 16509),     // AWS
    (185, 199, 108, 153, 36459),  // GitHub Pages/Fastly
    (20, 205, 243, 166, 8075),    // Microsoft
    (142, 250, 80, 46, 54113),    // Fastly
];
const PROTOS: &[(u8, u16, u16)] = &[
    // (proto, src_port, dst_port) — TCP 443/80 heavy like real traffic
    (6, 0, 443),
    (6, 0, 443),
    (6, 0, 443),
    (6, 0, 443),
    (6, 0, 80),
    (6, 0, 80),
    (17, 0, 53),
    (17, 123, 0),          // NTP
    (1, 0, 0),             // ICMP
    (6, 0, 22),
    (6, 0, 25),
    (6, 0, 587),           // mail submission
    (17, 0, 123),          // NTP back
];

fn pick_src_net(rng: &mut Rng) -> (u8, u8, u8, u32) {
    SRC_NETS[rng.below(SRC_NETS.len() as u64) as usize]
}

fn pick_src_ip(rng: &mut Rng) -> ([u8; 4], u32) {
    let n = pick_src_net(rng);
    ([n.0, n.1, n.2, rng.below(254) as u8 + 1], n.3)
}

fn pick_dst(rng: &mut Rng) -> ([u8; 4], u32) {
    if rng.below(10) < 7 {
        let d = DST_PUBLIC[rng.below(DST_PUBLIC.len() as u64) as usize];
        (
            [d.0, d.1, d.2, if d.3 == 0 { rng.below(254) as u8 + 1 } else { d.3 }],
            d.4,
        )
    } else {
        // internal traffic — still gets the net's ASN
        let n = pick_src_net(rng);
        ([n.0, n.1, n.2, rng.below(254) as u8 + 1], n.3)
    }
}

fn build_datagram(rng: &mut Rng, flows: usize, seq: &mut u32, uptime_ms: u64) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(24 + flows * 48);
    let now = now_secs();
    // Header: version=5, count, sysUpTime(ms since boot), unixSecs, unixNsecs,
    // flowSeq, engineType=1, engineId=0, samplingInterval=0.
    // uptime_ms is elapsed since the demo started; first/last are ms-since-boot
    // offsets so boot+offset lands at ~now.
    pkt.extend_from_slice(&5u16.to_be_bytes());
    pkt.extend_from_slice(&(flows as u16).to_be_bytes());
    pkt.extend_from_slice(&(uptime_ms as u32).to_be_bytes()); // sysUpTime ms
    pkt.extend_from_slice(&(now as u32).to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes()); // nsecs
    pkt.extend_from_slice(&seq.to_be_bytes());
    *seq = seq.wrapping_add(flows as u32);
    pkt.push(1); // engine type
    pkt.push(0); // engine id
    pkt.extend_from_slice(&0u16.to_be_bytes()); // sampling interval

    for _ in 0..flows {
        let (src, src_asn) = pick_src_ip(rng);
        let (dst, dst_asn) = pick_dst(rng);
        let (proto, sport_t, dport_t) = PROTOS[rng.below(PROTOS.len() as u64) as usize];
        let sport = if sport_t == 0 {
            (1024 + rng.below(60000)) as u16
        } else {
            sport_t
        };
        let dport = if dport_t == 0 {
            (1024 + rng.below(60000)) as u16
        } else {
            dport_t
        };
        let packets = 1 + rng.below(500);
        let bytes = packets * (40 + rng.below(1400));
        let first = (uptime_ms as u64).saturating_sub(rng.below(60_000)) as u32;
        let last = uptime_ms as u32;

        pkt.extend_from_slice(&src);
        pkt.extend_from_slice(&dst);
        pkt.extend_from_slice(&[10, 0, 0, 1]); // nexthop
        pkt.extend_from_slice(&1u16.to_be_bytes()); // input
        pkt.extend_from_slice(&2u16.to_be_bytes()); // output
        pkt.extend_from_slice(&(packets as u32).to_be_bytes());
        pkt.extend_from_slice(&(bytes as u32).to_be_bytes());
        pkt.extend_from_slice(&first.to_be_bytes());
        pkt.extend_from_slice(&last.to_be_bytes());
        pkt.extend_from_slice(&sport.to_be_bytes());
        pkt.extend_from_slice(&dport.to_be_bytes());
        pkt.push(0); // pad
        pkt.push(if proto == 6 { 0x12 } else { 0 }); // tcp_flags
        pkt.push(proto);
        pkt.push(0); // tos
        pkt.extend_from_slice(&(src_asn as u16).to_be_bytes()); // src_as
        pkt.extend_from_slice(&(dst_asn as u16).to_be_bytes()); // dst_as
        pkt.push(24); // src mask
        pkt.push(24); // dst mask
        pkt.extend_from_slice(&0u16.to_be_bytes()); // pad
    }
    pkt
}

// ---------------------------------------------------------------------------
// IPFIX demo — IPv6 flows so the ipver dims and v6 parsers get exercised.
// Sent to the same UDP port; auto-detect dispatches on the version field.
// ---------------------------------------------------------------------------

const IPFIX_TEMPLATE_ID: u16 = 256;

/// (ie, length) — all standard information elements, no enterprise bit.
const IPFIX_FIELDS: &[(u16, u16)] = &[
    (27, 16), // sourceIPv6Address
    (28, 16), // destinationIPv6Address
    (4, 1),   // protocolIdentifier
    (7, 2),   // sourceTransportPort
    (11, 2),  // destinationTransportPort
    (1, 4),   // octetDeltaCount
    (2, 4),   // packetDeltaCount
    (150, 4), // flowStartSeconds (epoch s — fits u32 until 2106)
    (151, 4), // flowEndSeconds (epoch s)
    (16, 4),  // bgpSourceASNumber
    (17, 4),  // bgpDestinationASNumber
];

/// IPv6 source /48s -> (prefix bytes[6], asn). Host bits are randomized.
const V6_SRC_NETS: &[([u8; 6], u32)] = &[
    ([0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01], 64600), // 2001:db8:1::/48
    ([0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02], 64700), // 2001:db8:2::/48
];

/// Public IPv6 destinations: (addr, asn). Parser infers v6 from the 16-byte IE.
const V6_DST: &[(&str, u32)] = &[
    ("2606:4700:4700::1111", 13335), // Cloudflare
    ("2606:4700:4700::1001", 13335), // Cloudflare
    ("2001:4860:4860::8888", 15169), // Google
    ("2001:4860:4860::8844", 15169), // Google
    ("2620:119:35::35", 19281),      // Quad9
    ("2a00:1450:4001::1", 15169),    // Google
];

const V6_PROTOS: &[(u8, u16, u16)] = &[
    (6, 0, 443),
    (6, 0, 443),
    (6, 0, 443),
    (6, 0, 80),
    (17, 0, 53),
    (17, 0, 123),
    (58, 0, 0),  // ICMPv6
    (6, 0, 22),
];

fn v6_addr(s: &str) -> [u8; 16] {
    s.parse::<Ipv6Addr>().map(|a| a.octets()).unwrap_or([0; 16])
}

fn ipfix_template_set() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&2u16.to_be_bytes()); // Template Set ID
    s.extend_from_slice(&((4 + 4 + IPFIX_FIELDS.len() * 4) as u16).to_be_bytes());
    s.extend_from_slice(&IPFIX_TEMPLATE_ID.to_be_bytes());
    s.extend_from_slice(&(IPFIX_FIELDS.len() as u16).to_be_bytes());
    for &(ie, len) in IPFIX_FIELDS {
        s.extend_from_slice(&ie.to_be_bytes());
        s.extend_from_slice(&len.to_be_bytes());
    }
    s
}

/// Build one IPFIX message: header + template set + one data set of `flows`
/// IPv6 records (61 bytes each, fixed layout).
fn build_ipfix_datagram(rng: &mut Rng, flows: usize, seq: &mut u64) -> Vec<u8> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut data = Vec::with_capacity(4 + flows * 61);
    data.extend_from_slice(&IPFIX_TEMPLATE_ID.to_be_bytes()); // Data Set ID = template id
    data.extend_from_slice(&((4 + flows * 61) as u16).to_be_bytes()); // length, patched below
    let len_pos = data.len() - 2;

    for _ in 0..flows {
        // src: pick a /48, randomize the low 80 bits
        let n = V6_SRC_NETS[rng.below(V6_SRC_NETS.len() as u64) as usize];
        let mut src = [0u8; 16];
        src[..6].copy_from_slice(&n.0);
        for b in &mut src[6..] {
            *b = rng.next() as u8;
        }
        // dst
        let d = V6_DST[rng.below(V6_DST.len() as u64) as usize];
        let mut dst = v6_addr(d.0);
        // jitter last byte on ~half the destinations for cardinality
        if rng.below(2) == 0 {
            dst[15] = (dst[15].wrapping_add(rng.below(200) as u8)).max(1);
        }
        let (proto, sport_t, dport_t) = V6_PROTOS[rng.below(V6_PROTOS.len() as u64) as usize];
        let sport = if sport_t == 0 { (1024 + rng.below(60000)) as u16 } else { sport_t };
        let dport = if dport_t == 0 { (1024 + rng.below(60000)) as u16 } else { dport_t };
        let packets = 1 + rng.below(500);
        let bytes = packets * (40 + rng.below(1400));
        let start = (now_ms / 1000).saturating_sub(rng.below(60));
        let end = now_ms / 1000;

        data.extend_from_slice(&src);
        data.extend_from_slice(&dst);
        data.push(proto);
        data.extend_from_slice(&sport.to_be_bytes());
        data.extend_from_slice(&dport.to_be_bytes());
        data.extend_from_slice(&(bytes as u32).to_be_bytes());
        data.extend_from_slice(&(packets as u32).to_be_bytes());
        data.extend_from_slice(&(start as u32).to_be_bytes());
        data.extend_from_slice(&(end as u32).to_be_bytes());
        data.extend_from_slice(&(n.1 as u32).to_be_bytes());
        data.extend_from_slice(&(d.1 as u32).to_be_bytes());
    }
    let set_len = data.len() as u16;
    data[len_pos..len_pos + 2].copy_from_slice(&set_len.to_be_bytes());

    let template = ipfix_template_set();
    let mut msg = Vec::with_capacity(16 + template.len() + data.len());
    msg.extend_from_slice(&10u16.to_be_bytes()); // IPFIX version
    let msg_len = (16 + template.len() + data.len()) as u16;
    msg.extend_from_slice(&msg_len.to_be_bytes());
    msg.extend_from_slice(&(now_secs() as u32).to_be_bytes()); // exportTime
    msg.extend_from_slice(&(*seq as u32).to_be_bytes());
    *seq = seq.wrapping_add(flows as u64);
    msg.extend_from_slice(&0u32.to_be_bytes()); // observationDomainId
    msg.extend_from_slice(&template);
    msg.extend_from_slice(&data);
    msg
}

/// Send demo NetFlow v5 + IPFIX(IPv6) traffic to `target`.
/// `pps` = packets per second, `flows_per_pkt` = records per datagram.
/// `exporters` = number of loopback source IPs to spread traffic across.
/// Runs until `duration` elapses or forever if None.
pub async fn run(
    target: SocketAddr,
    pps: u64,
    flows_per_pkt: usize,
    duration: Option<u64>,
    exporters: usize,
) -> Result<()> {
    // Bind one socket per exporter IP (127.0.0.0/8 is all-local on Linux).
    // Falls back to a wildcard socket if an alias isn't bindable.
    let mut socks = Vec::new();
    for i in 0..exporters.max(1) {
        let bind_ip = format!("127.0.0.{}", i + 1);
        match UdpSocket::bind((bind_ip.as_str(), 0)).await {
            Ok(s) => socks.push(s),
            Err(e) => {
                tracing::debug!("demo: cannot bind {}: {}", bind_ip, e);
                break;
            }
        }
    }
    if socks.is_empty() {
        socks.push(UdpSocket::bind("0.0.0.0:0").await?);
    }
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut seq = 1u32;
    let mut ipfix_seq = 1u64;
    let mut tick = interval(Duration::from_millis((1000 / pps.max(1)).max(1)));
    let start = std::time::Instant::now();
    let mut sent = 0u64;

    loop {
        if let Some(d) = duration {
            if start.elapsed() >= Duration::from_secs(d) {
                break;
            }
        }
        tick.tick().await;
        let sock = &socks[rng.below(socks.len() as u64) as usize];
        let uptime_ms = start.elapsed().as_millis() as u64;
        // ~1 in 5 datagrams is IPFIX/IPv6
        let pkt = if rng.below(5) == 0 {
            build_ipfix_datagram(&mut rng, (flows_per_pkt / 3).max(2), &mut ipfix_seq)
        } else {
            build_datagram(&mut rng, flows_per_pkt, &mut seq, uptime_ms)
        };
        if sock.send_to(&pkt, target).await.is_ok() {
            sent += 1;
        }
        if sent % 100 == 0 {
            tracing::info!("demo: sent {} datagrams to {}", sent, target);
        }
    }
    tracing::info!("demo: done, sent {} datagrams", sent);
    let _ = sleep(Duration::from_millis(100)).await;
    Ok(())
}
