//! Consistent-ish backups of the data directory.
//!
//! BGFlow segments are immutable once written (each flush creates a new
//! complete `.bfs` file, fsync'd before the path is visible to readers), so
//! a file-level copy is safe *provided* we verify each copied segment's CRC
//! — a file caught mid-write fails verification and is retried. Non-segment
//! files (orgs.txt etc.) are copied as-is.
//!
//! The instance lock file is excluded (it belongs to the running daemon).

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub struct BackupReport {
    pub dest: PathBuf,
    pub files: usize,
    pub bytes: u64,
    pub verified: usize,
    pub retried: usize,
    pub skipped: usize,
}

/// Copy `src` data dir into `dest` (created if needed). Returns a report.
pub fn run_backup(src: &Path, dest: &Path) -> Result<BackupReport> {
    if !src.is_dir() {
        anyhow::bail!("data dir {} does not exist", src.display());
    }
    fs::create_dir_all(dest)?;

    let mut files = Vec::new();
    collect_files(src, src, &mut files)?;

    let mut rep = BackupReport {
        dest: dest.to_path_buf(),
        files: 0,
        bytes: 0,
        verified: 0,
        retried: 0,
        skipped: 0,
    };

    for rel in files {
        let s = src.join(&rel);
        let d = dest.join(&rel);
        if let Some(parent) = d.parent() {
            fs::create_dir_all(parent)?;
        }
        let is_seg = rel.extension().map(|e| e == "bfs").unwrap_or(false);
        if is_seg {
            // Copy + CRC-verify, retrying races with in-flight flushes.
            let mut ok = false;
            let mut attempts = 0;
            while attempts < 3 && !ok {
                attempts += 1;
                fs::copy(&s, &d).with_context(|| format!("copy {}", rel.display()))?;
                match bgflow_store::verify_crc(&d) {
                    Ok(true) => ok = true,
                    _ => {
                        if attempts == 3 {
                            rep.skipped += 1;
                            let _ = fs::remove_file(&d);
                            tracing::warn!("backup: {} failed CRC after 3 tries — skipped", rel.display());
                        }
                    }
                }
            }
            if ok {
                rep.verified += 1;
                if attempts > 1 {
                    rep.retried += 1;
                }
            }
        } else {
            fs::copy(&s, &d).with_context(|| format!("copy {}", rel.display()))?;
        }
        rep.files += 1;
        rep.bytes += fs::metadata(&d).map(|m| m.len()).unwrap_or(0);
    }

    // Manifest for restore reference.
    let info = format!(
        "bgflow backup\nsource: {}\ncreated_unix: {}\nfiles: {}\nbytes: {}\nverified_segments: {}\nskipped: {}\n",
        src.display(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        rep.files,
        rep.bytes,
        rep.verified,
        rep.skipped,
    );
    fs::write(dest.join("backup-info.txt"), info)?;
    Ok(rep)
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for e in fs::read_dir(dir)? {
        let e = e?;
        let p = e.path();
        let name = e.file_name();
        if name == "bgflowd.lock" {
            continue; // live instance lock — meaningless in a backup
        }
        let ft = e.file_type()?;
        if ft.is_dir() {
            collect_files(root, &p, out)?;
        } else if ft.is_file() {
            out.push(p.strip_prefix(root).unwrap().to_path_buf());
        }
    }
    Ok(())
}

/// Default backup destination: ./bgflow-backup-<utc timestamp>
pub fn default_dest() -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // YYYYMMDD-HHMMSS UTC without chrono.
    let days = ts / 86_400;
    let secs = ts % 86_400;
    // civil-from-days algorithm (Howard Hinnant)
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    PathBuf::from(format!(
        "bgflow-backup-{:04}{:02}{:02}-{:02}{:02}{:02}",
        y, m, d, hh, mm, ss
    ))
}

