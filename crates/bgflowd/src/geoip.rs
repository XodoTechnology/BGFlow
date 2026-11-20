//! `bgflowd geoip-update` — download GeoIP MMDB databases.
//!
//! Sources:
//!   dbip    (default) DB-IP Lite combined files — one mmdb per family,
//!           covers IPv4+IPv6, free with no account. Monthly updates.
//!   github            ip-database/mmdb mirror — per-family files incl.
//!           GeoLite2 without a MaxMind license. IPv4/IPv6 are separate
//!           files, so the config snippet uses list syntax.

use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DBIP_BASE: &str = "https://download.db-ip.com/free";
const GH_BASE: &str = "https://raw.githubusercontent.com/ip-database/mmdb/master";

/// Current UTC year-month ("2026-11") for DB-IP's monthly file names.
fn ym_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // civil-from-days (Howard Hinnant's algorithm)
    let z = secs / 86_400 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}", yr, m)
}

struct Target {
    url: String,
    /// File name to write inside the target dir.
    name: String,
}

fn plan(source: &str) -> Result<Vec<Target>> {
    let ym = ym_now();
    Ok(match source {
        "dbip" => vec![
            Target {
                url: format!("{}/dbip-asn-lite-{}.mmdb.gz", DBIP_BASE, ym),
                name: "dbip-asn.mmdb".into(),
            },
            Target {
                url: format!("{}/dbip-country-lite-{}.mmdb.gz", DBIP_BASE, ym),
                name: "dbip-country.mmdb".into(),
            },
        ],
        "github" => ["asn", "city"]
            .iter()
            .flat_map(|fam| ["ipv4", "ipv6"].iter().map(move |v| (fam, v)))
            .map(|(fam, v)| Target {
                url: format!("{}/geolite2-{}-{}.mmdb.gz", GH_BASE, fam, v),
                name: format!("geolite2-{}-{}.mmdb", fam, v),
            })
            .collect(),
        other => bail!("unknown geoip source '{}'; use dbip or github", other),
    })
}

async fn fetch_gunzip(client: &reqwest::Client, t: &Target, dir: &Path) -> Result<PathBuf> {
    tracing::info!("geoip: downloading {}", t.url);
    let resp = client
        .get(&t.url)
        .send()
        .await
        .with_context(|| format!("download {}", t.url))?;
    let mut resp = resp.error_for_status()?;
    // Bound both the compressed download and the gunzipped output — a
    // corrupted or malicious mirror must not exhaust memory. Real MMDBs
    // are tens of MiB; 512MiB is generous headroom.
    const MAX_DOWNLOAD: u64 = 512 << 20;
    const MAX_MMDB: u64 = 512 << 20;
    let mut gz = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if gz.len() as u64 + chunk.len() as u64 > MAX_DOWNLOAD {
            bail!(
                "geoip download from {} exceeds {} MiB cap",
                t.url,
                MAX_DOWNLOAD >> 20
            );
        }
        gz.extend_from_slice(&chunk);
    }
    let dec = flate2::read::GzDecoder::new(&gz[..]);
    let mut mmdb = Vec::new();
    dec.take(MAX_MMDB + 1)
        .read_to_end(&mut mmdb)
        .context("gunzip mmdb payload")?;
    if mmdb.len() as u64 > MAX_MMDB {
        bail!("decompressed mmdb exceeds {} MiB cap", MAX_MMDB >> 20);
    }
    let out = dir.join(&t.name);
    let tmp = out.with_extension("mmdb.tmp");
    std::fs::write(&tmp, &mmdb)?;
    std::fs::rename(&tmp, &out)?;
    tracing::info!(
        "geoip: wrote {} ({:.1} MiB)",
        out.display(),
        mmdb.len() as f64 / 1048576.0
    );
    Ok(out)
}

/// Download + gunzip all files for `source` into `dir`. Returns the
/// written paths. Shared by the CLI and the daemon's auto-update loop.
pub async fn download(source: &str, dir: &Path) -> Result<Vec<PathBuf>> {
    let targets = plan(source)?;
    std::fs::create_dir_all(dir)?;
    let client = reqwest::Client::builder()
        .user_agent("bgflowd/geoip-update")
        .timeout(std::time::Duration::from_secs(300))
        .build()?;
    let mut outs = Vec::with_capacity(targets.len());
    for t in &targets {
        outs.push(fetch_gunzip(&client, t, dir).await?);
    }
    Ok(outs)
}

/// `bgflowd geoip-update [--source dbip|github] [--dir PATH]`
pub async fn run(source: &str, dir: &Path) -> Result<()> {
    println!(
        "geoip-update: downloading {} file(s) → {}",
        plan(source)?.len(),
        dir.display()
    );
    let outs = download(source, dir).await?;
    for p in &outs {
        println!("  {}", p.display());
    }
    println!();
    match source {
        "dbip" => println!(
            "Config (defaults already match if installed to /usr/share/GeoIP):\n\
             [geoip]\n\
             asn_db = \"{}/dbip-asn.mmdb\"\n\
             country_db = \"{}/dbip-country.mmdb\"\n",
            dir.display(),
            dir.display()
        ),
        "github" => println!(
            "Config — files are split per IP version, use list syntax:\n\
             [geoip]\n\
             asn_db = [\"{}/geolite2-asn-ipv4.mmdb\", \"{}/geolite2-asn-ipv6.mmdb\"]\n\
             country_db = [\"{}/geolite2-city-ipv4.mmdb\", \"{}/geolite2-city-ipv6.mmdb\"]\n",
            dir.display(),
            dir.display(),
            dir.display(),
            dir.display()
        ),
        _ => {}
    }
    println!(
        "The daemon picks up changed files automatically (~60s); \
              kill -HUP <bgflowd pid> applies instantly."
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Daemon-side maintenance loop
// ---------------------------------------------------------------------------

/// Periodic MMDB maintenance, spawned once at startup:
///   * every tick (~60s) checks configured file mtimes/sizes and hot-swaps
///     readers when databases were replaced externally;
///   * when `[geoip] update_source` is set, downloads fresh databases every
///     `update_secs` (default weekly) into `update_dir` and swaps readers.
///
/// Config is re-read each tick so `[geoip]` changes apply without restart.
pub async fn refresh_loop(
    geo: std::sync::Arc<crate::enrich::MmdbGeo>,
    config_path: Option<PathBuf>,
    fallback: crate::config::GeoIpConfig,
) {
    use std::time::{Duration, Instant};
    const TICK: Duration = Duration::from_secs(60);
    const DEFAULT_EVERY: Duration = Duration::from_secs(7 * 86_400);
    const RETRY: Duration = Duration::from_secs(3600);

    let mut next_dl: Option<Instant> = None;
    let mut dl_key: Option<(String, PathBuf, u64)> = None;
    let mut dir_warned = false;

    loop {
        tokio::time::sleep(TICK).await;

        let gcfg = config_path
            .as_ref()
            .and_then(|p| crate::config::load(Some(p)).ok())
            .map(|c| c.geoip)
            .unwrap_or_else(|| fallback.clone());

        // 1) Hot-swap when database files changed on disk.
        if geo.files_changed(&gcfg) {
            tracing::info!("geoip: database file(s) changed — reloading readers");
            geo.swap(&gcfg);
        }

        // 2) Scheduled auto-download.
        let source = gcfg.update_source.trim().to_string();
        if source.is_empty() {
            next_dl = None;
            dl_key = None;
            dir_warned = false;
            continue;
        }
        let dir = resolve_update_dir(&gcfg);
        let Some(dir) = dir else {
            if !dir_warned {
                tracing::warn!(
                    "geoip: update_source set but no update_dir and no configured \
                     db path to derive one from — auto-update disabled"
                );
                dir_warned = true;
            }
            next_dl = None;
            dl_key = None;
            continue;
        };
        dir_warned = false;

        let every = if gcfg.update_secs == 0 {
            DEFAULT_EVERY
        } else {
            Duration::from_secs(gcfg.update_secs)
        };
        // First run — and any change to source/dir/interval — schedules
        // `every` out. Databases were just loaded at boot, so there's no
        // reason to download immediately.
        let key = (source.clone(), dir.clone(), every.as_secs());
        if dl_key.as_ref() != Some(&key) {
            dl_key = Some(key);
            next_dl = Some(Instant::now() + every);
        }
        if next_dl.is_some_and(|t| Instant::now() >= t) {
            match download(&source, &dir).await {
                Ok(files) => {
                    tracing::info!(
                        "geoip: auto-update downloaded {} file(s) → {}",
                        files.len(),
                        dir.display()
                    );
                    geo.swap(&gcfg);
                    next_dl = Some(Instant::now() + every);
                }
                Err(e) => {
                    tracing::warn!("geoip: auto-update failed: {:#}", e);
                    next_dl = Some(Instant::now() + RETRY);
                }
            }
        }
    }
}

/// `update_dir` if configured, else the parent directory of the first
/// configured database path.
fn resolve_update_dir(g: &crate::config::GeoIpConfig) -> Option<PathBuf> {
    let explicit = g.update_dir.trim();
    if !explicit.is_empty() {
        return Some(PathBuf::from(explicit));
    }
    g.all_db_paths().into_iter().find_map(|p| {
        p.parent()
            .filter(|d| !d.as_os_str().is_empty())
            .map(|d| d.to_path_buf())
            .or_else(|| Some(PathBuf::from(".")))
    })
}
