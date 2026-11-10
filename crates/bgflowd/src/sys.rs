//! Host resource stats for the UI topbar: CPU%, memory, disk (data-dir
//! filesystem), load average. Reads /proc + statvfs — cheap enough to poll
//! every few seconds. CPU% is computed from /proc/stat deltas between calls.

use serde::Serialize;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct SysStats {
    pub cpu_pct: Option<f32>,
    pub cpu_count: usize,
    pub mem_total_mb: u64,
    pub mem_used_mb: u64,
    pub mem_pct: Option<f32>,
    pub disk_total_gb: u64,
    pub disk_avail_gb: u64,
    pub disk_pct: Option<f32>,
    pub disk_path: String,
    pub load1: Option<f32>,
    pub load5: Option<f32>,
    pub load15: Option<f32>,
    /// False when the platform doesn't expose the data (non-Linux etc.).
    pub ok: bool,
}

#[derive(Clone, Copy)]
struct CpuSample {
    total: u64,
    idle: u64,
}

static LAST_CPU: Mutex<Option<CpuSample>> = Mutex::new(None);

fn read_file(p: &str) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

/// Aggregate cpu line from /proc/stat → (total jiffies, idle jiffies).
fn cpu_jiffies() -> Option<(u64, u64)> {
    let s = read_file("/proc/stat")?;
    let line = s.lines().next()?;
    if !line.starts_with("cpu ") {
        return None;
    }
    let vals: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse().ok())
        .collect();
    if vals.is_empty() {
        return None;
    }
    let idle = vals.get(3).copied().unwrap_or(0) + vals.get(4).copied().unwrap_or(0); // idle+iowait
    let total: u64 = vals.iter().sum();
    Some((total, idle))
}

fn cpu_count() -> usize {
    read_file("/proc/stat")
        .map(|s| {
            s.lines()
                .filter(|l| l.starts_with("cpu") && l.as_bytes().get(3) == Some(&b' '))
                .count()
        })
        .unwrap_or(0)
        .max(1)
}

fn meminfo() -> Option<(u64, u64)> {
    let s = read_file("/proc/meminfo")?;
    let mut total = None;
    let mut avail = None;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = rest.split_whitespace().next()?.parse::<u64>().ok();
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail = rest.split_whitespace().next()?.parse::<u64>().ok();
        }
        if total.is_some() && avail.is_some() {
            break;
        }
    }
    // kB → MB
    Some((total? / 1024, avail? / 1024))
}

fn loadavg() -> Option<(f32, f32, f32)> {
    let s = read_file("/proc/loadavg")?;
    let mut it = s.split_whitespace();
    let a: f32 = it.next()?.parse().ok()?;
    let b: f32 = it.next()?.parse().ok()?;
    let c: f32 = it.next()?.parse().ok()?;
    Some((a, b, c))
}

/// statvfs on `path` → (total_bytes, avail_bytes).
fn disk_usage(path: &std::path::Path) -> Option<(u64, u64)> {
    let c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).ok()?;
    // SAFETY: statvfs writes into a valid, properly-sized struct; `c` is
    // NUL-terminated and outlives the call.
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut st) != 0 {
            return None;
        }
        let frsize = st.f_frsize.max(1) as u64;
        Some((st.f_blocks as u64 * frsize, st.f_bavail as u64 * frsize))
    }
}

/// Sample everything. Call periodically; CPU% needs a prior sample.
pub fn sample(data_dir: &std::path::Path) -> SysStats {
    let mut st = SysStats {
        cpu_pct: None,
        cpu_count: cpu_count(),
        mem_total_mb: 0,
        mem_used_mb: 0,
        mem_pct: None,
        disk_total_gb: 0,
        disk_avail_gb: 0,
        disk_pct: None,
        disk_path: data_dir.display().to_string(),
        load1: None,
        load5: None,
        load15: None,
        ok: false,
    };

    // CPU delta.
    if let Some((total, idle)) = cpu_jiffies() {
        let mut last = LAST_CPU.lock().unwrap();
        if let Some(prev) = *last {
            let dt = total.saturating_sub(prev.total);
            let di = idle.saturating_sub(prev.idle);
            if dt > 0 {
                st.cpu_pct = Some(((dt - di) as f32 / dt as f32 * 100.0 * 10.0).round() / 10.0);
            }
        }
        *last = Some(CpuSample { total, idle });
    }

    if let Some((total_kb, avail_kb)) = meminfo() {
        st.mem_total_mb = total_kb;
        st.mem_used_mb = total_kb.saturating_sub(avail_kb);
        if total_kb > 0 {
            st.mem_pct = Some((st.mem_used_mb as f32 / total_kb as f32 * 1000.0).round() / 10.0);
        }
    }

    if let Some((t, a)) = disk_usage(data_dir) {
        st.disk_total_gb = t / 1_000_000_000;
        st.disk_avail_gb = a / 1_000_000_000;
        if t > 0 {
            st.disk_pct = Some(((t - a) as f32 / t as f32 * 1000.0).round() / 10.0);
        }
    }

    if let Some((a, b, c)) = loadavg() {
        st.load1 = Some(a);
        st.load5 = Some(b);
        st.load15 = Some(c);
    }

    st.ok = st.cpu_pct.is_some() || st.mem_total_mb > 0 || st.disk_total_gb > 0;
    st
}
