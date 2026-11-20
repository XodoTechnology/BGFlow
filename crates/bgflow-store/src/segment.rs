//! `.bfs` segment file format.
//!
//! Layout:
//! ```text
//! [0..64)     fixed header (magic "BGFS", version, schema id, time range,
//!             row count, crc32)
//! [64..)      column directory: 32-byte entries, one per schema column
//! [..)        column chunks back-to-back (encoded + optionally zstd)
//! ```

use crate::encode::{decode_column, Codec, ColumnData, EncodedChunk};
use crate::schema::{schema_by_id, ColType, Encoding, Schema};
use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

pub const MAGIC: &[u8; 4] = b"BGFS";
pub const VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 64;
pub const DIR_ENTRY_SIZE: usize = 32;

#[derive(Debug, Clone)]
pub struct SegmentHeader {
    pub schema_id: u16,
    pub flags: u32,
    pub created_ms: u64,
    pub min_ts_ms: u64,
    pub max_ts_ms: u64,
    pub row_count: u64,
    pub column_count: u16,
    pub crc32: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ColDir {
    pub col_idx: u16,
    pub encoding: u8,
    pub codec: u8,
    pub ty: u8,
    pub offset: u64,
    pub comp_len: u64,
    pub raw_len: u64,
}

impl ColDir {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.col_idx.to_le_bytes());
        out.push(self.encoding);
        out.push(self.codec);
        out.push(self.ty);
        out.push(0); // reserved
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&self.comp_len.to_le_bytes());
        out.extend_from_slice(&self.raw_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // reserved
        debug_assert_eq!(out.len() % DIR_ENTRY_SIZE, 0);
    }

    fn read(buf: &[u8]) -> Result<Self> {
        if buf.len() < DIR_ENTRY_SIZE {
            bail!("short dir entry");
        }
        Ok(ColDir {
            col_idx: u16::from_le_bytes(buf[0..2].try_into().unwrap()),
            encoding: buf[2],
            codec: buf[3],
            ty: buf[4],
            offset: u64::from_le_bytes(buf[6..14].try_into().unwrap()),
            comp_len: u64::from_le_bytes(buf[14..22].try_into().unwrap()),
            raw_len: u64::from_le_bytes(buf[22..30].try_into().unwrap()),
        })
    }
}

/// Metadata about a segment, cheap to obtain (header only).
#[derive(Debug, Clone)]
pub struct SegmentInfo {
    pub path: PathBuf,
    pub header: SegmentHeader,
    pub file_size: u64,
}

impl SegmentInfo {
    pub fn overlaps(&self, from_ms: u64, to_ms: u64) -> bool {
        self.header.max_ts_ms >= from_ms && self.header.min_ts_ms <= to_ms
    }
}

// ---------------------------------------------------------------------------
// writing
// ---------------------------------------------------------------------------

/// Write a complete segment file. `chunks` must have one entry per schema
/// column, in column order.
pub fn write_segment(
    path: &Path,
    schema: &Schema,
    chunks: &[EncodedChunk],
    row_count: u64,
    min_ts_ms: u64,
    max_ts_ms: u64,
    created_ms: u64,
) -> Result<()> {
    if chunks.len() != schema.columns.len() {
        bail!(
            "chunk count {} != schema columns {}",
            chunks.len(),
            schema.columns.len()
        );
    }

    let ncols = schema.columns.len() as u16;
    let chunks_start = HEADER_SIZE + schema.columns.len() * DIR_ENTRY_SIZE;

    // Compute absolute offsets for each chunk.
    let mut offsets = Vec::with_capacity(chunks.len());
    let mut cursor = chunks_start as u64;
    for c in chunks {
        offsets.push(cursor);
        cursor += c.data.len() as u64;
    }

    let mut buf = Vec::with_capacity(cursor as usize);

    // Header (crc patched at the end).
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&schema.id.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // flags
    buf.extend_from_slice(&created_ms.to_le_bytes());
    buf.extend_from_slice(&min_ts_ms.to_le_bytes());
    buf.extend_from_slice(&max_ts_ms.to_le_bytes());
    buf.extend_from_slice(&row_count.to_le_bytes());
    buf.extend_from_slice(&ncols.to_le_bytes());
    buf.extend_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
    buf.extend_from_slice(&(HEADER_SIZE as u64).to_le_bytes()); // dir_offset
    buf.extend_from_slice(&0u32.to_le_bytes()); // crc placeholder
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
    debug_assert_eq!(buf.len(), HEADER_SIZE);

    // Directory.
    for (i, c) in chunks.iter().enumerate() {
        let def = &schema.columns[i];
        let dir = ColDir {
            col_idx: i as u16,
            encoding: c.encoding as u8,
            codec: c.codec as u8,
            ty: def.ty.id(),
            offset: offsets[i],
            comp_len: c.data.len() as u64,
            raw_len: c.raw_len as u64,
        };
        dir.write(&mut buf);
    }
    debug_assert_eq!(buf.len(), chunks_start);

    // Chunks.
    for c in chunks {
        buf.extend_from_slice(&c.data);
    }

    // CRC over everything except the crc field itself (bytes 56..60).
    let mut crc_input = Vec::with_capacity(buf.len());
    crc_input.extend_from_slice(&buf[..56]);
    crc_input.extend_from_slice(&buf[60..]);
    let crc = crc32fast::hash(&crc_input);
    buf[56..60].copy_from_slice(&crc.to_le_bytes());

    let mut f = File::create(path).with_context(|| format!("create {}", path.display()))?;
    f.write_all(&buf)?;
    f.sync_data()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// reading
// ---------------------------------------------------------------------------

fn parse_header(buf: &[u8]) -> Result<SegmentHeader> {
    if buf.len() < HEADER_SIZE {
        bail!("short segment header");
    }
    if &buf[0..4] != MAGIC {
        bail!("bad magic (not a BGFS segment)");
    }
    let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    if version != VERSION {
        bail!("unsupported segment version {}", version);
    }
    Ok(SegmentHeader {
        schema_id: u16::from_le_bytes(buf[6..8].try_into().unwrap()),
        flags: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        created_ms: u64::from_le_bytes(buf[12..20].try_into().unwrap()),
        min_ts_ms: u64::from_le_bytes(buf[20..28].try_into().unwrap()),
        max_ts_ms: u64::from_le_bytes(buf[28..36].try_into().unwrap()),
        row_count: u64::from_le_bytes(buf[36..44].try_into().unwrap()),
        column_count: u16::from_le_bytes(buf[44..46].try_into().unwrap()),
        crc32: u32::from_le_bytes(buf[56..60].try_into().unwrap()),
    })
}

/// Read just the header of a segment file (64 bytes).
pub fn read_header(path: &Path) -> Result<SegmentHeader> {
    let mut f = File::open(path)?;
    let mut buf = [0u8; HEADER_SIZE];
    f.read_exact(&mut buf)?;
    parse_header(&buf)
}

/// Full read access to one segment.
pub struct SegmentReader {
    file: File,
    file_len: u64,
    pub header: SegmentHeader,
    pub schema: &'static Schema,
    dir: Vec<ColDir>,
}

impl SegmentReader {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut hbuf = [0u8; HEADER_SIZE];
        file.read_exact(&mut hbuf)?;
        let header = parse_header(&hbuf)?;
        let schema = schema_by_id(header.schema_id)
            .with_context(|| format!("unknown schema id {}", header.schema_id))?;
        if header.column_count as usize != schema.columns.len() {
            bail!(
                "segment column count {} != schema {} columns",
                header.column_count,
                schema.columns.len()
            );
        }

        let mut dbuf = vec![0u8; schema.columns.len() * DIR_ENTRY_SIZE];
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
        file.read_exact(&mut dbuf)?;
        let mut dir = Vec::with_capacity(schema.columns.len());
        for i in 0..schema.columns.len() {
            dir.push(ColDir::read(
                &dbuf[i * DIR_ENTRY_SIZE..(i + 1) * DIR_ENTRY_SIZE],
            )?);
        }

        let file_len = file.metadata()?.len();
        Ok(SegmentReader {
            file,
            file_len,
            header,
            schema,
            dir,
        })
    }

    /// Decode every column.
    pub fn decode_all(&self) -> Result<Vec<ColumnData>> {
        self.decode_columns(&(0..self.schema.columns.len()).collect::<Vec<_>>())
            .map(|v| v.into_iter().map(|(_, d)| d).collect())
    }

    /// Decode a subset of columns; returns (col_idx, data) pairs in request order.
    pub fn decode_columns(&self, cols: &[usize]) -> Result<Vec<(usize, ColumnData)>> {
        let mut out = Vec::with_capacity(cols.len());
        let mut buf = Vec::new();
        for &ci in cols {
            // Segments written under an older schema lack appended columns
            // (e.g. rollup vlan on id-3 files) — skip them; sparse row views
            // read missing columns as 0.
            let Some(d) = self.dir.get(ci) else { continue };
            let def = &self.schema.columns[ci];
            let encoding = Encoding::from_id(d.encoding).context("bad encoding id")?;
            let codec = Codec::from_id(d.codec).context("bad codec id")?;
            let ty = ColType::from_id(d.ty).context("bad column type id")?;
            if ty != def.ty {
                bail!("segment column {} type mismatch", ci);
            }

            // Validate the chunk extent against the real file size before
            // allocating — a corrupt dir entry could claim exabytes.
            let chunk_end = d
                .offset
                .checked_add(d.comp_len)
                .ok_or_else(|| anyhow::anyhow!("column {} chunk offset overflow", ci))?;
            if chunk_end > self.file_len {
                bail!(
                    "column {} chunk (offset {} + {} bytes) exceeds file size {}",
                    ci,
                    d.offset,
                    d.comp_len,
                    self.file_len
                );
            }

            buf.clear();
            buf.resize(d.comp_len as usize, 0);
            self.file.read_exact_at(&mut buf, d.offset)?;

            let data = decode_column(def, encoding, codec, &buf, self.header.row_count as usize)?;
            out.push((ci, data));
        }
        Ok(out)
    }
}

/// List all `.bfs` files under `root` recursively with their headers.
pub fn scan_segments(root: &Path) -> Result<Vec<SegmentInfo>> {
    let mut out = Vec::new();
    scan_dir(root, &mut out)?;
    out.sort_by_key(|s| s.header.min_ts_ms);
    Ok(out)
}

fn scan_dir(dir: &Path, out: &mut Vec<SegmentInfo>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, out)?;
        } else if path.extension().map(|e| e == "bfs").unwrap_or(false) {
            match (read_header(&path), entry.metadata()) {
                (Ok(header), Ok(meta)) => out.push(SegmentInfo {
                    path,
                    header,
                    file_size: meta.len(),
                }),
                (Err(e), _) => {
                    tracing::warn!("skipping unreadable segment {:?}: {}", path, e);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Sanity check used by tests / `bgflowd doctor`: recompute crc.
pub fn verify_crc(path: &Path) -> Result<bool> {
    let mut f = File::open(path)?;
    let mut all = Vec::new();
    f.read_to_end(&mut all)?;
    if all.len() < HEADER_SIZE {
        return Ok(false);
    }
    let stored = u32::from_le_bytes(all[56..60].try_into().unwrap());
    let mut input = Vec::with_capacity(all.len());
    input.extend_from_slice(&all[..56]);
    input.extend_from_slice(&all[60..]);
    Ok(crc32fast::hash(&input) == stored)
}
