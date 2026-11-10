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
    eprint!("  {} … ", t.url);
    let resp = client
        .get(&t.url)
        .send()
        .await
        .with_context(|| format!("download {}", t.url))?;
    let resp = resp.error_for_status()?;
    let gz = resp.bytes().await?;
    let mut dec = flate2::read::GzDecoder::new(&gz[..]);
    let mut mmdb = Vec::with_capacity(gz.len() * 2);
    dec.read_to_end(&mut mmdb)
        .context("gunzip mmdb payload")?;
    let out = dir.join(&t.name);
    let tmp = out.with_extension("mmdb.tmp");
    std::fs::write(&tmp, &mmdb)?;
    std::fs::rename(&tmp, &out)?;
    println!("{} ({:.1} MiB)", out.display(), mmdb.len() as f64 / 1048576.0);
    Ok(out)
}

/// `bgflowd geoip-update [--source dbip|github] [--dir PATH]`
pub async fn run(source: &str, dir: &Path) -> Result<()> {
    let targets = plan(source)?;
    std::fs::create_dir_all(dir)?;
    println!("geoip-update: {} file(s) → {}", targets.len(), dir.display());
    let client = reqwest::Client::builder()
        .user_agent("bgflowd/geoip-update")
        .timeout(std::time::Duration::from_secs(300))
        .build()?;
    for t in &targets {
        fetch_gunzip(&client, t, dir).await?;
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
    println!("Reload to apply: kill -HUP <bgflowd pid>  (or restart)");
    Ok(())
}
