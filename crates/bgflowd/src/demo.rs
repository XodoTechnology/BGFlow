//! Synthetic NetFlow v5 traffic generator for demos and smoke tests.
//! Sends real UDP datagrams so the full ingest->store->query path is exercised.

use anyhow::Result;
use std::net::SocketAddr;
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
const SRC_NETS: &[(u8, u8, u8)] = &[
    (10, 0, 0),
    (10, 1, 0),
    (192, 168, 1),
    (172, 16, 0),
    (100, 64, 0),
];
const DST_PUBLIC: &[(u8, u8, u8, u8)] = &[
    (8, 8, 8, 8),          // Google-ish
    (1, 1, 1, 1),          // Cloudflare-ish
    (9, 9, 9, 9),
    (151, 101, 1, 69),     // Reddit-ish
    (104, 16, 0, 1),       // Twitter-ish
    (140, 82, 121, 4),     // Microsoft-ish
    (13, 107, 42, 14),     // AWS-ish
    (185, 199, 108, 153),  // GitHub Pages-ish
];
const PROTOS: &[(u8, u16, u16)] = &[
    // (proto, src_port, dst_port) — TCP 443/80 heavy like real traffic
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
];

fn pick_src_ip(rng: &mut Rng) -> [u8; 4] {
    let n = SRC_NETS[rng.below(SRC_NETS.len() as u64) as usize];
    [n.0, n.1, n.2, rng.below(254) as u8 + 1]
}

fn pick_dst_ip(rng: &mut Rng) -> [u8; 4] {
    if rng.below(10) < 7 {
        let d = DST_PUBLIC[rng.below(DST_PUBLIC.len() as u64) as usize];
        [d.0, d.1, d.2, if d.3 == 0 { rng.below(254) as u8 + 1 } else { d.3 }]
    } else {
        // internal traffic
        let n = SRC_NETS[rng.below(SRC_NETS.len() as u64) as usize];
        [n.0, n.1, n.2, rng.below(254) as u8 + 1]
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
        let src = pick_src_ip(rng);
        let dst = pick_dst_ip(rng);
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
        pkt.extend_from_slice(&65000u16.to_be_bytes()); // src_as placeholder
        pkt.extend_from_slice(&174u16.to_be_bytes()); // dst_as placeholder (Google-ish)
        pkt.push(24); // src mask
        pkt.push(24); // dst mask
        pkt.extend_from_slice(&0u16.to_be_bytes()); // pad
    }
    pkt
}

/// Send demo NetFlow v5 traffic to `target`.
/// `pps` = packets per second, `flows_per_pkt` = records per datagram.
/// Runs until `duration` elapses or forever if None.
pub async fn run(target: SocketAddr, pps: u64, flows_per_pkt: usize, duration: Option<u64>) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut seq = 1u32;
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
        let uptime_ms = start.elapsed().as_millis() as u64;
        let pkt = build_datagram(&mut rng, flows_per_pkt, &mut seq, uptime_ms);
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
