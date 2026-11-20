//! Column encodings and compression for segment chunks.
//!
//! Three encodings are supported per column (chosen by schema, with
//! dictionary columns falling back to plain when dict does not pay off):
//!
//! - `Plain`: raw little-endian values.
//! - `Dict`:   `[u32 num_unique][u8 index_width][unique values][indices]`
//!             where indices are u16 (num_unique <= 65535) or u32.
//! - `Delta`:  `[u64 base][u64 delta * (n-1)]`, requires non-decreasing input.
//!
//! Every chunk is then ZSTD-compressed (level 3) when that actually shrinks it.

use crate::schema::{ColType, ColumnDef, Encoding};
use anyhow::{bail, Result};
use std::collections::HashMap;

pub const ZSTD_LEVEL: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    None = 0,
    Zstd = 1,
}

impl Codec {
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Codec::None),
            1 => Some(Codec::Zstd),
            _ => None,
        }
    }
}

/// A fully encoded column chunk ready to be written into a segment.
#[derive(Debug)]
pub struct EncodedChunk {
    pub encoding: Encoding,
    pub codec: Codec,
    /// Length of the payload before compression.
    pub raw_len: usize,
    pub data: Vec<u8>,
}

/// Decoded columnar data, typed by column width.
#[derive(Debug)]
pub enum ColumnData {
    U8(Vec<u8>),
    U16(Vec<u16>),
    U32(Vec<u32>),
    U64(Vec<u64>),
    U128(Vec<u128>),
}

impl ColumnData {
    pub fn len(&self) -> usize {
        match self {
            ColumnData::U8(v) => v.len(),
            ColumnData::U16(v) => v.len(),
            ColumnData::U32(v) => v.len(),
            ColumnData::U64(v) => v.len(),
            ColumnData::U128(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Numeric value at row `i`, widened to u128. Panics if `i` is out of
    /// bounds or the variant does not match expectations — callers must know
    /// the column type from the schema.
    pub fn value_at(&self, i: usize) -> u128 {
        match self {
            ColumnData::U8(v) => v[i] as u128,
            ColumnData::U16(v) => v[i] as u128,
            ColumnData::U32(v) => v[i] as u128,
            ColumnData::U64(v) => v[i] as u128,
            ColumnData::U128(v) => v[i],
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn read_u128_le(buf: &[u8], width: usize) -> u128 {
    let mut b = [0u8; 16];
    b[..width].copy_from_slice(&buf[..width]);
    u128::from_le_bytes(b)
}

fn put_u128_le(out: &mut Vec<u8>, v: u128, width: usize) {
    out.extend_from_slice(&v.to_le_bytes()[..width]);
}

fn get_u64s(raw: &[u8], n: usize) -> Vec<u64> {
    raw.chunks_exact(8)
        .take(n)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

// ---------------------------------------------------------------------------
// encoders (raw LE bytes -> chunk bytes, pre-compression)
// ---------------------------------------------------------------------------

fn encode_plain(raw: &[u8]) -> Vec<u8> {
    raw.to_vec()
}

fn encode_dict(raw: &[u8], width: usize, nrows: usize) -> Vec<u8> {
    let mut map: HashMap<u128, u32> = HashMap::with_capacity(1024);
    let mut uniques: Vec<u128> = Vec::new();
    let mut indices: Vec<u32> = Vec::with_capacity(nrows);

    for row in raw.chunks_exact(width).take(nrows) {
        let v = read_u128_le(row, width);
        let idx = *map.entry(v).or_insert_with(|| {
            uniques.push(v);
            (uniques.len() - 1) as u32
        });
        indices.push(idx);
    }

    let nunique = uniques.len();
    let idx_width: usize = if nunique <= u16::MAX as usize { 2 } else { 4 };

    let mut out = Vec::with_capacity(5 + nunique * width + nrows * idx_width);
    out.extend_from_slice(&(nunique as u32).to_le_bytes());
    out.push(idx_width as u8);
    for &u in &uniques {
        put_u128_le(&mut out, u, width);
    }
    for &i in &indices {
        if idx_width == 2 {
            out.extend_from_slice(&(i as u16).to_le_bytes());
        } else {
            out.extend_from_slice(&i.to_le_bytes());
        }
    }
    out
}

fn encode_delta_u64(raw: &[u8], nrows: usize) -> Vec<u8> {
    if nrows == 0 {
        return Vec::new();
    }
    let vals = get_u64s(raw, nrows);
    let mut out = Vec::with_capacity(8 + (nrows - 1) * 8);
    out.extend_from_slice(&vals[0].to_le_bytes());
    for w in vals.windows(2) {
        out.extend_from_slice(&w[1].wrapping_sub(w[0]).to_le_bytes());
    }
    out
}

fn maybe_compress(chunk: Vec<u8>) -> (Codec, Vec<u8>) {
    match zstd::stream::encode_all(chunk.as_slice(), ZSTD_LEVEL) {
        Ok(c) if c.len() < chunk.len() => (Codec::Zstd, c),
        _ => (Codec::None, chunk),
    }
}

/// Encode one column. `raw` must contain exactly `nrows * width` LE bytes,
/// already sorted by timestamp when the column is the ts column.
pub fn encode_column(def: &ColumnDef, raw: &[u8], nrows: usize) -> EncodedChunk {
    let width = def.ty.width();
    debug_assert_eq!(raw.len(), nrows * width);

    // Build candidate encodings and keep the smallest pre-compression.
    let (encoding, plain_chunk) = match def.enc {
        Encoding::Dict => {
            let dict = encode_dict(raw, width, nrows);
            let plain = encode_plain(raw);
            if dict.len() < plain.len() {
                (Encoding::Dict, dict)
            } else {
                (Encoding::Plain, plain)
            }
        }
        Encoding::Delta if def.ty == ColType::U64 => {
            let delta = encode_delta_u64(raw, nrows);
            let plain = encode_plain(raw);
            if delta.len() < plain.len() {
                (Encoding::Delta, delta)
            } else {
                (Encoding::Plain, plain)
            }
        }
        _ => (Encoding::Plain, encode_plain(raw)),
    };

    let raw_len = plain_chunk.len();
    let (codec, data) = maybe_compress(plain_chunk);
    EncodedChunk {
        encoding,
        codec,
        raw_len,
        data,
    }
}

// ---------------------------------------------------------------------------
// decoders
// ---------------------------------------------------------------------------

/// Upper bound on bytes a single decompressed chunk may occupy.
/// Legit chunks are ~nrows*width (dict adds uniques+indices, still
/// <2x); the multiplier is generous headroom, the 512MiB ceiling stops
/// a corrupt header from forcing a giant allocation.
fn max_raw_bytes(nrows: usize, width: usize) -> u64 {
    (nrows as u64)
        .saturating_mul(width as u64)
        .saturating_mul(16)
        .saturating_add(1 << 20)
        .min(512 << 20)
}

fn decompress(codec: Codec, data: &[u8], max_raw: u64) -> Result<Vec<u8>> {
    match codec {
        Codec::None => {
            if data.len() as u64 > max_raw {
                bail!(
                    "uncompressed chunk {} bytes exceeds bound {}",
                    data.len(),
                    max_raw
                );
            }
            Ok(data.to_vec())
        }
        Codec::Zstd => {
            use std::io::Read;
            // take(max+1) lets us distinguish "exactly max" from
            // "stream had more" — overflow is a corrupt segment.
            let mut out = Vec::new();
            zstd::stream::read::Decoder::new(data)?
                .take(max_raw + 1)
                .read_to_end(&mut out)?;
            if out.len() as u64 > max_raw {
                bail!("decompressed chunk exceeds bound {} bytes", max_raw);
            }
            Ok(out)
        }
    }
}

fn decode_plain(def: &ColumnDef, raw: &[u8], nrows: usize) -> Result<ColumnData> {
    let width = def.ty.width();
    let need = nrows
        .checked_mul(width)
        .ok_or_else(|| anyhow::anyhow!("plain chunk size overflow"))?;
    if raw.len() < need {
        bail!("plain chunk too short: {} < {}", raw.len(), need);
    }
    let rows = raw[..need].chunks_exact(width);
    Ok(match def.ty {
        ColType::U8 => ColumnData::U8(rows.map(|c| c[0]).collect()),
        ColType::U16 => ColumnData::U16(
            rows.map(|c| u16::from_le_bytes(c.try_into().unwrap()))
                .collect(),
        ),
        ColType::U32 => ColumnData::U32(
            rows.map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect(),
        ),
        ColType::U64 => ColumnData::U64(
            rows.map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                .collect(),
        ),
        ColType::U128 => ColumnData::U128(rows.map(|c| read_u128_le(c, 16)).collect()),
    })
}

fn decode_dict(def: &ColumnDef, raw: &[u8], nrows: usize) -> Result<ColumnData> {
    let width = def.ty.width();
    if raw.len() < 5 {
        bail!("dict chunk too short");
    }
    let nunique = u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize;
    let idx_width = raw[4] as usize;
    if idx_width != 2 && idx_width != 4 {
        bail!("bad dict index width {}", idx_width);
    }
    let uniques_start = 5;
    let uniques_len = nunique
        .checked_mul(width)
        .ok_or_else(|| anyhow::anyhow!("dict uniques size overflow"))?;
    let uniques_end = uniques_start + uniques_len;
    let indices_start = uniques_end;
    let indices_len = nrows
        .checked_mul(idx_width)
        .ok_or_else(|| anyhow::anyhow!("dict indices size overflow"))?;
    let indices_end = indices_start
        .checked_add(indices_len)
        .ok_or_else(|| anyhow::anyhow!("dict chunk size overflow"))?;
    if raw.len() < indices_end {
        bail!("dict chunk truncated");
    }

    let mut uniques: Vec<u128> = Vec::with_capacity(nunique);
    for chunk in raw[uniques_start..uniques_end].chunks_exact(width) {
        uniques.push(read_u128_le(chunk, width));
    }

    let indices = &raw[indices_start..indices_end];
    let lookup = |i: usize| -> Option<u128> {
        let idx = if idx_width == 2 {
            u16::from_le_bytes(indices[i * 2..i * 2 + 2].try_into().unwrap()) as usize
        } else {
            u32::from_le_bytes(indices[i * 4..i * 4 + 4].try_into().unwrap()) as usize
        };
        uniques.get(idx).copied()
    };

    // Expand through plain path by materializing values then decoding.
    let mut buf = Vec::with_capacity(nrows * width);
    for i in 0..nrows {
        let v =
            lookup(i).ok_or_else(|| anyhow::anyhow!("dict index out of bounds at row {}", i))?;
        put_u128_le(&mut buf, v, width);
    }
    decode_plain(def, &buf, nrows)
}

fn decode_delta_u64(raw: &[u8], nrows: usize) -> Result<ColumnData> {
    if nrows == 0 {
        return Ok(ColumnData::U64(Vec::new()));
    }
    if raw.len() < 8 {
        bail!("delta chunk too short");
    }
    let mut vals = Vec::with_capacity(nrows);
    let mut cur = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    vals.push(cur);
    for i in 1..nrows {
        let off = 8 + (i - 1) * 8;
        if raw.len() < off + 8 {
            bail!("delta chunk truncated");
        }
        let d = u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
        cur = cur.wrapping_add(d);
        vals.push(cur);
    }
    Ok(ColumnData::U64(vals))
}

/// Decode a chunk back into typed column data.
pub fn decode_column(
    def: &ColumnDef,
    encoding: Encoding,
    codec: Codec,
    data: &[u8],
    nrows: usize,
) -> Result<ColumnData> {
    let raw = decompress(codec, data, max_raw_bytes(nrows, def.ty.width()))?;
    match encoding {
        Encoding::Plain => decode_plain(def, &raw, nrows),
        Encoding::Dict => decode_dict(def, &raw, nrows),
        Encoding::Delta => {
            if def.ty != ColType::U64 {
                bail!("delta encoding on non-u64 column");
            }
            decode_delta_u64(&raw, nrows)
        }
    }
}
