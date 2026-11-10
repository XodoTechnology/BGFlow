use bgflow_store::{Dataset, DatasetOpts, RollupAggregator};
use bgflow_types::{FlowRecord, RollupRecord};
use std::ops::ControlFlow;

fn sample_flow(i: u64) -> FlowRecord {
    FlowRecord {
        ts_ms: 1_700_000_000_000 + i * 37,
        duration_ms: (i % 500) as u32,
        src_ip: 0xffff_0a00_0001u128 + (i % 50) as u128, // ::ffff:10.0.0.x
        dst_ip: 0xffff_c0a8_0001u128 + (i % 200) as u128,
        src_port: 1024 + (i % 60000) as u16,
        dst_port: if i % 3 == 0 { 443 } else { 80 },
        protocol: if i % 4 == 0 { 17 } else { 6 },
        tcp_flags: (i % 256) as u8,
        ingress_if: (i % 4) as u32,
        egress_if: (i % 8) as u32,
        next_hop: 0xffff_0a00_0001u128,
        src_asn: 64512 + (i % 100) as u32,
        dst_asn: 13335,
        src_country: 840,
        dst_country: 36,
        src_org: 0,
        dst_org: 0,
        vlan: (i % 3) as u16,
        bytes: 100 + i * 13,
        packets: 1 + i % 40,
        exporter: 0xffff_0a00_0001u128,
        engine_id: 0,
        engine_type: 1,
        sampler_interval: if i % 10 == 0 { 0 } else { 1000 },
        tcp_state: (i % 12) as u8,
        label_id: 0,
        ip_ttl: (i % 255) as u8,
        flow_end_reason: (i % 4) as u8,
        icmp_type: (i % 256) as u8,
        icmp_code: (i % 256) as u8,
        post_nat_src: 0,
        post_nat_dst: 0,
    }
}

#[test]
fn flow_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let mut ds = Dataset::<FlowRecord>::open(
        dir.path().join("flows"),
        DatasetOpts { segment_rows: 500, segment_interval: std::time::Duration::from_secs(3600) },
    )
    .unwrap();

    let n = 1200u64;
    // push slightly out of order to exercise the sort
    for i in (0..n).rev() {
        ds.push(&sample_flow(i)).unwrap();
    }
    ds.flush().unwrap();
    assert!(ds.segment_count() >= 1);

    let got = ds.scan(0, u64::MAX).unwrap();
    assert_eq!(got.len() as u64, n);
    // sorted by ts
    for w in got.windows(2) {
        assert!(w[0].ts_ms <= w[1].ts_ms);
    }
    // spot-check values survived the columnar roundtrip
    let f = &got[7];
    let orig = sample_flow(7);
    assert_eq!(f.src_ip, orig.src_ip);
    assert_eq!(f.dst_port, orig.dst_port);
    assert_eq!(f.bytes, orig.bytes);
    assert_eq!(f.protocol, orig.protocol);
    assert_eq!(f.sampler_interval, orig.sampler_interval);
}

#[test]
fn rollup_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let mut ds = Dataset::<RollupRecord>::open(
        dir.path().join("rollup"),
        DatasetOpts::default(),
    )
    .unwrap();

    let mut agg = RollupAggregator::new();
    let base = 1_700_000_000_000u64;
    for i in 0..500u64 {
        agg.add(&sample_flow(base + i * 100));
    }
    for rec in agg.drain_all() {
        ds.push(&rec).unwrap();
    }
    ds.flush().unwrap();

    let got = ds.scan(0, u64::MAX).unwrap();
    assert!(!got.is_empty());
    let total_flows: u64 = got.iter().map(|r| r.flows).sum();
    assert_eq!(total_flows, 500);
}

#[test]
fn segment_overlap_and_retention() {
    let dir = tempfile::tempdir().unwrap();
    let mut ds = Dataset::<FlowRecord>::open(dir.path().join("flows"), DatasetOpts::default()).unwrap();

    let base = 1_700_000_000_000u64;
    for i in 0..100u64 {
        let mut f = sample_flow(i);
        f.ts_ms = base + i * 1000;
        ds.push(&f).unwrap();
    }
    ds.flush().unwrap();

    // range that covers only the first half
    let half = ds.scan(base, base + 50_000).unwrap();
    assert_eq!(half.len(), 51);

    // retention: segment spans base..base+99s; cut off after it ends
    let freed = ds.retain(base + 200_000).unwrap();
    assert!(freed > 0);
    assert_eq!(ds.segment_count(), 0);
}

#[test]
fn for_each_segment_early_exit() {
    let dir = tempfile::tempdir().unwrap();
    let mut ds = Dataset::<FlowRecord>::open(
        dir.path().join("flows"),
        DatasetOpts { segment_rows: 100, segment_interval: std::time::Duration::from_secs(3600) },
    )
    .unwrap();
    for i in 0..1000u64 {
        ds.push(&sample_flow(i)).unwrap();
    }
    ds.flush().unwrap();
    assert!(ds.segment_count() >= 5);

    let mut seen = 0usize;
    ds.for_each_segment(0, u64::MAX, true, |scan| {
        seen += scan.rows;
        ControlFlow::Break(())
    })
    .unwrap();
    // newest_first + break after first segment => only one segment decoded
    assert!(seen <= 1000);
    assert!(seen < 1000 || ds.segment_count() == 1);
}
