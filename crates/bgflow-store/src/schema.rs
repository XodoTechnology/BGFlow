//! Column schema definitions for the two datasets BGFlow stores:
//! raw flows and pre-aggregated rollups.

/// On-disk / in-memory column types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColType {
    U8,
    U16,
    U32,
    U64,
    U128,
}

impl ColType {
    pub fn width(self) -> usize {
        match self {
            ColType::U8 => 1,
            ColType::U16 => 2,
            ColType::U32 => 4,
            ColType::U64 => 8,
            ColType::U128 => 16,
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(ColType::U8),
            2 => Some(ColType::U16),
            3 => Some(ColType::U32),
            4 => Some(ColType::U64),
            5 => Some(ColType::U128),
            _ => None,
        }
    }

    pub fn id(self) -> u8 {
        match self {
            ColType::U8 => 1,
            ColType::U16 => 2,
            ColType::U32 => 3,
            ColType::U64 => 4,
            ColType::U128 => 5,
        }
    }
}

/// Per-column encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Raw little-endian values, zstd-compressed as a block.
    Plain = 0,
    /// Dictionary: unique values + u16/u32 indices.
    Dict = 1,
    /// Delta from previous value (sorted input only), u64 columns.
    Delta = 2,
}

impl Encoding {
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Encoding::Plain),
            1 => Some(Encoding::Dict),
            2 => Some(Encoding::Delta),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ColumnDef {
    pub name: &'static str,
    pub ty: ColType,
    pub enc: Encoding,
    /// Column holds the row timestamp; buffer is sorted by it before flush.
    pub is_ts: bool,
}

#[derive(Debug)]
pub struct Schema {
    pub id: u16,
    pub name: &'static str,
    pub columns: &'static [ColumnDef],
}

impl Schema {
    pub fn col_index(&self, name: &str) -> Option<usize> {
        self.columns.iter().position(|c| c.name == name)
    }

    pub fn ts_column(&self) -> usize {
        self.columns.iter().position(|c| c.is_ts).unwrap_or(0)
    }
}

macro_rules! col {
    ($name:literal, $ty:expr, $enc:expr) => {
        ColumnDef { name: $name, ty: $ty, enc: $enc, is_ts: false }
    };
    ($name:literal, $ty:expr, $enc:expr, ts) => {
        ColumnDef { name: $name, ty: $ty, enc: $enc, is_ts: true }
    };
}

use ColType::*;
use Encoding::*;

/// Schema id 4: raw flow records (36 columns). Appended geo columns keep
/// indices 0..31 identical to id 2 so old segments decode with zeroed geo.
pub const RAW_SCHEMA: Schema = Schema {
    id: 4,
    name: "flows",
    columns: &[
        col!("ts_ms", U64, Delta, ts),
        col!("duration_ms", U32, Plain),
        col!("src_ip", U128, Plain),
        col!("dst_ip", U128, Plain),
        col!("src_port", U16, Plain),
        col!("dst_port", U16, Plain),
        col!("protocol", U8, Dict),
        col!("tcp_flags", U8, Plain),
        col!("ingress_if", U32, Dict),
        col!("egress_if", U32, Dict),
        col!("next_hop", U128, Plain),
        col!("src_asn", U32, Dict),
        col!("dst_asn", U32, Dict),
        col!("src_country", U16, Dict),
        col!("dst_country", U16, Dict),
        col!("src_org", U32, Dict),
        col!("dst_org", U32, Dict),
        col!("vlan", U16, Dict),
        col!("bytes", U64, Plain),
        col!("packets", U64, Plain),
        col!("exporter", U128, Dict),
        col!("engine_id", U8, Dict),
        col!("engine_type", U8, Dict),
        col!("sampler_interval", U32, Dict),
        col!("tcp_state", U8, Dict),
        col!("label_id", U32, Dict),
        col!("ip_ttl", U8, Dict),
        col!("flow_end_reason", U8, Dict),
        col!("icmp_type", U8, Dict),
        col!("icmp_code", U8, Dict),
        col!("post_nat_src", U128, Dict),
        col!("post_nat_dst", U128, Dict),
        col!("src_city", U32, Dict),
        col!("dst_city", U32, Dict),
        col!("src_region", U32, Dict),
        col!("dst_region", U32, Dict),
        col!("src_lat", U32, Plain),
        col!("dst_lat", U32, Plain),
        col!("src_lon", U32, Plain),
        col!("dst_lon", U32, Plain),
    ],
};

/// Schema id 2: raw flow records before geo columns (32 columns). Kept so
/// existing segments remain readable — geo fields decode as 0.
pub const RAW_SCHEMA_V1: Schema = Schema {
    id: 2,
    name: "flows",
    columns: &[
        col!("ts_ms", U64, Delta, ts),
        col!("duration_ms", U32, Plain),
        col!("src_ip", U128, Plain),
        col!("dst_ip", U128, Plain),
        col!("src_port", U16, Plain),
        col!("dst_port", U16, Plain),
        col!("protocol", U8, Dict),
        col!("tcp_flags", U8, Plain),
        col!("ingress_if", U32, Dict),
        col!("egress_if", U32, Dict),
        col!("next_hop", U128, Plain),
        col!("src_asn", U32, Dict),
        col!("dst_asn", U32, Dict),
        col!("src_country", U16, Dict),
        col!("dst_country", U16, Dict),
        col!("src_org", U32, Dict),
        col!("dst_org", U32, Dict),
        col!("vlan", U16, Dict),
        col!("bytes", U64, Plain),
        col!("packets", U64, Plain),
        col!("exporter", U128, Dict),
        col!("engine_id", U8, Dict),
        col!("engine_type", U8, Dict),
        col!("sampler_interval", U32, Dict),
        col!("tcp_state", U8, Dict),
        col!("label_id", U32, Dict),
        col!("ip_ttl", U8, Dict),
        col!("flow_end_reason", U8, Dict),
        col!("icmp_type", U8, Dict),
        col!("icmp_code", U8, Dict),
        col!("post_nat_src", U128, Dict),
        col!("post_nat_dst", U128, Dict),
    ],
};

/// Column indices into RAW_SCHEMA (keep in sync with the table above).
pub mod raw_idx {
    pub const TS_MS: usize = 0;
    pub const DURATION_MS: usize = 1;
    pub const SRC_IP: usize = 2;
    pub const DST_IP: usize = 3;
    pub const SRC_PORT: usize = 4;
    pub const DST_PORT: usize = 5;
    pub const PROTOCOL: usize = 6;
    pub const TCP_FLAGS: usize = 7;
    pub const INGRESS_IF: usize = 8;
    pub const EGRESS_IF: usize = 9;
    pub const NEXT_HOP: usize = 10;
    pub const SRC_ASN: usize = 11;
    pub const DST_ASN: usize = 12;
    pub const SRC_COUNTRY: usize = 13;
    pub const DST_COUNTRY: usize = 14;
    pub const SRC_ORG: usize = 15;
    pub const DST_ORG: usize = 16;
    pub const VLAN: usize = 17;
    pub const BYTES: usize = 18;
    pub const PACKETS: usize = 19;
    pub const EXPORTER: usize = 20;
    pub const ENGINE_ID: usize = 21;
    pub const ENGINE_TYPE: usize = 22;
    pub const SAMPLER_INTERVAL: usize = 23;
    pub const TCP_STATE: usize = 24;
    pub const LABEL_ID: usize = 25;
    pub const IP_TTL: usize = 26;
    pub const FLOW_END_REASON: usize = 27;
    pub const ICMP_TYPE: usize = 28;
    pub const ICMP_CODE: usize = 29;
    pub const POST_NAT_SRC: usize = 30;
    pub const POST_NAT_DST: usize = 31;
    pub const SRC_CITY: usize = 32;
    pub const DST_CITY: usize = 33;
    pub const SRC_REGION: usize = 34;
    pub const DST_REGION: usize = 35;
    pub const SRC_LAT: usize = 36;
    pub const DST_LAT: usize = 37;
    pub const SRC_LON: usize = 38;
    pub const DST_LON: usize = 39;
}

/// Schema id 3: rollup records (19 columns). id 1 was the v1 layout.
pub const ROLLUP_SCHEMA_V1: Schema = Schema {
    id: 3,
    name: "rollup",
    columns: &[
        col!("bucket_ms", U64, Delta, ts),
        col!("exporter", U128, Dict),
        col!("protocol", U8, Dict),
        col!("src_asn", U32, Dict),
        col!("dst_asn", U32, Dict),
        col!("src_ip", U128, Plain),
        col!("dst_ip", U128, Plain),
        col!("src_port", U16, Plain),
        col!("dst_port", U16, Plain),
        col!("src_country", U16, Dict),
        col!("dst_country", U16, Dict),
        col!("bytes", U64, Plain),
        col!("packets", U64, Plain),
        col!("flows", U64, Plain),
        col!("min_ts_ms", U64, Plain),
        col!("max_ts_ms", U64, Plain),
        col!("src_org", U32, Dict),
        col!("dst_org", U32, Dict),
        col!("label_id", U32, Dict),
    ],
};

/// Schema id 5: rollup records + `vlan`.
pub const ROLLUP_SCHEMA_V2: Schema = Schema {
    id: 5,
    name: "rollup",
    columns: &[
        col!("bucket_ms", U64, Delta, ts),
        col!("exporter", U128, Dict),
        col!("protocol", U8, Dict),
        col!("src_asn", U32, Dict),
        col!("dst_asn", U32, Dict),
        col!("src_ip", U128, Plain),
        col!("dst_ip", U128, Plain),
        col!("src_port", U16, Plain),
        col!("dst_port", U16, Plain),
        col!("src_country", U16, Dict),
        col!("dst_country", U16, Dict),
        col!("bytes", U64, Plain),
        col!("packets", U64, Plain),
        col!("flows", U64, Plain),
        col!("min_ts_ms", U64, Plain),
        col!("max_ts_ms", U64, Plain),
        col!("src_org", U32, Dict),
        col!("dst_org", U32, Dict),
        col!("label_id", U32, Dict),
        col!("vlan", U16, Dict),
    ],
};

/// Schema id 6: rollup records + `vlan`, `ingress_if`, `egress_if`
/// (appended — older segments decode them as 0 via the sparse row view).
pub const ROLLUP_SCHEMA: Schema = Schema {
    id: 6,
    name: "rollup",
    columns: &[
        col!("bucket_ms", U64, Delta, ts),
        col!("exporter", U128, Dict),
        col!("protocol", U8, Dict),
        col!("src_asn", U32, Dict),
        col!("dst_asn", U32, Dict),
        col!("src_ip", U128, Plain),
        col!("dst_ip", U128, Plain),
        col!("src_port", U16, Plain),
        col!("dst_port", U16, Plain),
        col!("src_country", U16, Dict),
        col!("dst_country", U16, Dict),
        col!("bytes", U64, Plain),
        col!("packets", U64, Plain),
        col!("flows", U64, Plain),
        col!("min_ts_ms", U64, Plain),
        col!("max_ts_ms", U64, Plain),
        col!("src_org", U32, Dict),
        col!("dst_org", U32, Dict),
        col!("label_id", U32, Dict),
        col!("vlan", U16, Dict),
        col!("ingress_if", U32, Dict),
        col!("egress_if", U32, Dict),
    ],
};

/// Column indices into ROLLUP_SCHEMA.
pub mod rollup_idx {
    pub const BUCKET_MS: usize = 0;
    pub const EXPORTER: usize = 1;
    pub const PROTOCOL: usize = 2;
    pub const SRC_ASN: usize = 3;
    pub const DST_ASN: usize = 4;
    pub const SRC_IP: usize = 5;
    pub const DST_IP: usize = 6;
    pub const SRC_PORT: usize = 7;
    pub const DST_PORT: usize = 8;
    pub const SRC_COUNTRY: usize = 9;
    pub const DST_COUNTRY: usize = 10;
    pub const BYTES: usize = 11;
    pub const PACKETS: usize = 12;
    pub const FLOWS: usize = 13;
    pub const MIN_TS: usize = 14;
    pub const MAX_TS: usize = 15;
    pub const SRC_ORG: usize = 16;
    pub const DST_ORG: usize = 17;
    pub const LABEL_ID: usize = 18;
    /// Only in schema id ≥5 — absent (reads 0) on id-3 segments.
    pub const VLAN: usize = 19;
    /// Only in schema id ≥6 — absent (reads 0) on older segments.
    pub const INGRESS_IF: usize = 20;
    pub const EGRESS_IF: usize = 21;
}

pub fn schema_by_id(id: u16) -> Option<&'static Schema> {
    match id {
        2 => Some(&RAW_SCHEMA_V1),
        3 => Some(&ROLLUP_SCHEMA_V1),
        4 => Some(&RAW_SCHEMA),
        5 => Some(&ROLLUP_SCHEMA_V2),
        6 => Some(&ROLLUP_SCHEMA),
        _ => None,
    }
}
