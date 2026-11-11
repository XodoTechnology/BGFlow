//! bgflowd — BGFlow daemon: flow collector, storage engine, API, UI.

mod admin;
mod alerts;
mod api;
mod auth;
mod backup;
mod config;
mod demo;
mod enrich;
mod geoip;
mod ingest;
mod metrics;
mod qcache;
mod query;
mod rules;
mod sys;
mod writer;

use anyhow::Result;
use api::AppState;
use auth::{AuthState, User};
use clap::{Parser, Subcommand};
use enrich::{HttpEnrichers, MmdbGeo, StringTable};
use metrics::Metrics;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use writer::WriterShared;

#[derive(Subcommand)]
enum Commands {
    /// Verify integrity of all stored .bfs segments (CRC check).
    Doctor,
    /// Validate the config file and print a summary (no daemon start).
    ConfigCheck,
    /// Copy the data directory to a backup location (CRC-verified).
    Backup {
        /// Destination directory (default: ./bgflow-backup-<timestamp>).
        #[arg(long)]
        dest: Option<PathBuf>,
    },
    /// Generate a PBKDF2 password hash for [[users]] config.
    /// Reads the password from --password or stdin.
    HashPassword {
        /// Password to hash (prefer stdin to keep it out of shell history).
        #[arg(long)]
        password: Option<String>,
    },
    /// Download GeoIP MMDB databases (DB-IP Lite or the ip-database/mmdb
    /// mirror with GeoLite2). Prints the [geoip] config to use.
    GeoipUpdate {
        /// Source: dbip (default, combined files) or github (per-family).
        #[arg(long, default_value = "dbip")]
        source: String,
        /// Install directory (default: /usr/share/GeoIP).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Parser)]
#[command(name = "bgflowd", version, about = "BGFlow flow analyzer daemon")]
struct Args {
    /// Path to bgflow.toml (default: ./bgflow.toml, /etc/bgflow/bgflow.toml)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Send synthetic demo NetFlow traffic to this address (e.g. 127.0.0.1:2055)
    #[arg(long)]
    demo: Option<SocketAddr>,

    /// Demo packets per second
    #[arg(long, default_value_t = 20)]
    demo_pps: u64,

    /// Demo duration in seconds (0 = forever)
    #[arg(long, default_value_t = 0)]
    demo_secs: u64,

    /// Demo flows per datagram
    #[arg(long, default_value_t = 20)]
    demo_flows: usize,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    // hash-password and geoip-update need no config — handle before loading.
    if let Some(Commands::HashPassword { password }) = &args.command {
        return hash_password_cmd(password.clone());
    }
    if let Some(Commands::GeoipUpdate { source, dir }) = &args.command {
        let dir = dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/usr/share/GeoIP"));
        return geoip::run(source, &dir).await;
    }

    let cfg = config::load(args.config.as_ref())?;

    match args.command {
        Some(Commands::Doctor) => return doctor(&cfg),
        Some(Commands::ConfigCheck) => return config_check(&cfg),
        Some(Commands::Backup { dest }) => return backup_cmd(&cfg, dest),
        _ => {}
    }

    std::fs::create_dir_all(&cfg.storage.data_dir)?;
    // Single-instance lock: two daemons on one data dir would interleave
    // segment writes and double-count rollups. Lock file holds the pid;
    // staleness is detected via /proc so crashes don't wedge restarts.
    let _instance_lock = acquire_instance_lock(&cfg.storage.data_dir)?;
    tracing::info!("config loaded; data dir {}", cfg.storage.data_dir.display());

    // --- Shared state ---
    let metrics = Arc::new(Metrics::default());
    let orgs = Arc::new(StringTable::open(cfg.storage.data_dir.join("orgs.txt"))?);
    let cities = Arc::new(StringTable::open(cfg.storage.data_dir.join("cities.txt"))?);
    let geo = Arc::new(MmdbGeo::open(&cfg.geoip, orgs.clone(), cities.clone(), metrics.clone()));
    let http_enrich = Arc::new(HttpEnrichers::new(
        &cfg.enrichers,
        metrics.clone(),
        orgs.clone(),
    )?);
    if http_enrich.enabled() {
        tracing::info!("{} enricher backend(s) configured", http_enrich.backend_count());
        let h = http_enrich.clone();
        tokio::spawn(async move { h.run().await });
    }

    let rules = Arc::new(rules::Ruleset::from_toml(&cfg.rules));
    if rules.len() > 0 {
        tracing::info!("{} label rule(s) loaded", rules.len());
    }

    // --- Auth ---
    let tls_enabled = cfg.server.tls_cert.is_some() && cfg.server.tls_key.is_some();
    let mut users = Vec::with_capacity(cfg.users.len());
    for u in &cfg.users {
        match User::from_config(u) {
            Ok(user) => users.push(user),
            Err(e) => tracing::warn!("auth: {} — skipped", e),
        }
    }
    if !users.is_empty() {
        tracing::info!("auth: {} user(s) configured", users.len());
    }
    let auth = Arc::new(AuthState::new(
        users,
        cfg.server.auth.clone(),
        cfg.server.session_secret.clone(),
        cfg.server.session_ttl_secs,
        tls_enabled,
    ));
    // Loud warnings for risky public deployments.
    let loopback = cfg.server.http_listen.ip().is_loopback();
    if auth.is_open() && !loopback {
        tracing::warn!(
            "SECURITY: no auth configured ([[users]] or server.auth) and http_listen={} is not loopback — \
             all flow data is world-readable. Configure users or bind to 127.0.0.1 behind a reverse proxy.",
            cfg.server.http_listen
        );
    }
    if !auth.is_open() && !tls_enabled && !loopback {
        tracing::warn!(
            "SECURITY: auth enabled but TLS is off — credentials and session cookies cross the network in plaintext. \
             Set server.tls_cert/tls_key or terminate TLS at a reverse proxy."
        );
    }

    // --- Writer + ingest channel ---
    let (tx, rx) = tokio::sync::mpsc::channel::<bgflow_types::FlowRecord>(
        cfg.storage.channel_capacity,
    );
    let shared = WriterShared::new();
    {
        let cfg_s = cfg.storage.clone();
        let sh = shared.clone();
        let m = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = writer::run(cfg_s, sh, m, rx).await {
                tracing::error!("writer failed: {}", e);
            }
        });
    }

    ingest::spawn_all(
        cfg.inputs.clone(),
        tx.clone(),
        ingest::IngestShared {
            geo: geo.clone(),
            http: http_enrich.clone(),
            rules: rules.clone(),
            orgs: orgs.clone(),
            metrics: metrics.clone(),
        },
    );

    // Exporter/interface names + alert rules are reloadable shared state.
    let exporter_names =
        Arc::new(RwLock::new(query::ExporterNames::build(
            &cfg.exporter_names,
        )));
    let interface_names =
        Arc::new(RwLock::new(query::InterfaceNames::build(
            &cfg.interface_names,
        )));
    let ptr = enrich::PtrCache::new();
    let alerts_cfg = Arc::new(RwLock::new(cfg.alerts.clone()));

    // Admin operations shared by SIGHUP and POST /api/v1/admin/reload.
    let admin = Arc::new(admin::AdminShared {
        config_path: config::resolve_path(args.config.as_ref()),
        rules: rules.clone(),
        enrich: http_enrich.clone(),
        exporter_names: exporter_names.clone(),
        interface_names: interface_names.clone(),
        auth: auth.clone(),
        alerts: alerts_cfg.clone(),
        geo: geo.clone(),
    });

    // MMDB maintenance: hot-swap readers when .mmdb files change on disk,
    // and auto-download fresh databases when [geoip] update_source is set.
    {
        let g = geo.clone();
        let cp = config::resolve_path(args.config.as_ref());
        let fb = cfg.geoip.clone();
        tokio::spawn(async move { geoip::refresh_loop(g, cp, fb).await });
    }

    let app_state = Arc::new(AppState {
        ctx: query::Ctx {
            flow_index: shared.flow_index.clone(),
            rollup_index: shared.rollup_index.clone(),
            hourly_index: shared.hourly_index.clone(),
            orgs: orgs.clone(),
            cities: cities.clone(),
            rules: rules.clone(),
            exporter_names: exporter_names.clone(),
            interface_names: interface_names.clone(),
            ptr: ptr.clone(),
        },
        status: shared.status.clone(),
        metrics: metrics.clone(),
        http_enrich: http_enrich.clone(),
        geo: geo.clone(),
        config: Arc::new(cfg.clone()),
        auth: auth.clone(),
        admin: admin.clone(),
    });

    // Alert evaluation loop (reloadable; no-op scan when no rules configured).
    {
        let c = app_state.ctx.clone();
        let m = metrics.clone();
        tokio::spawn(async move { alerts::run(alerts_cfg, c, m).await });
    }

    // SIGHUP: same reload path as POST /api/v1/admin/reload.
    {
        tokio::spawn(async move {
            let mut sig = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("SIGHUP handler unavailable: {}", e);
                    return;
                }
            };
            loop {
                sig.recv().await;
                let rep = admin.reload();
                if !rep.ok {
                    tracing::warn!("config reload had errors: {:?}", rep.errors);
                }
            }
        });
    }

    // Prime the CPU sampler so the first /status poll already has a delta.
    let _ = sys::sample(&cfg.storage.data_dir);

    let app = api::router(app_state);
    if let (Some(cert), Some(key)) = (&cfg.server.tls_cert, &cfg.server.tls_key) {
        // rustls 0.23 panics without a process-level CryptoProvider when
        // multiple providers are compiled in — install aws-lc-rs explicitly.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        tracing::info!("https: listening on {} (TLS)", cfg.server.http_listen);
        let rustls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .map_err(|e| anyhow::anyhow!("TLS config failed: {}", e))?;
        axum_server::bind_rustls(cfg.server.http_listen, rustls)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(cfg.server.http_listen).await?;
    tracing::info!("http: listening on {}", cfg.server.http_listen);
    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    );

    // Demo traffic: --demo flag wins, else [demo] config section.
    let demo_target = args.demo.or_else(|| {
        cfg.demo.enabled.then(|| {
            cfg.demo.target.unwrap_or_else(|| {
                let port = cfg.inputs.first().map(|i| i.listen.port()).unwrap_or(2055);
                format!("127.0.0.1:{}", port).parse().unwrap()
            })
        })
    });
    if let Some(target) = demo_target {
        let pps = if args.demo.is_some() { args.demo_pps } else { cfg.demo.pps };
        let flows = if args.demo.is_some() { args.demo_flows } else { cfg.demo.flows_per_pkt };
        let secs = if args.demo.is_some() { args.demo_secs } else { cfg.demo.duration_secs };
        let exporters = if args.demo.is_some() { 3 } else { cfg.demo.exporters };
        tokio::spawn(async move {
            let dur = if secs == 0 { None } else { Some(secs) };
            tracing::info!("demo: sending traffic to {}", target);
            if let Err(e) = demo::run(target, pps, flows, dur, exporters).await {
                tracing::error!("demo sender failed: {}", e);
            }
        });
    }

    serve.await?;
    Ok(())
}

/// `bgflowd hash-password`: PBKDF2 hash for [[users]] config.
fn hash_password_cmd(password: Option<String>) -> Result<()> {
    let pw = match password {
        Some(p) => p,
        None => {
            // Read one line from stdin (keeps the secret out of argv/history).
            use std::io::BufRead;
            let stdin = std::io::stdin();
            let mut line = String::new();
            stdin.lock().read_line(&mut line)?;
            line.trim_end().to_string()
        }
    };
    if pw.is_empty() {
        anyhow::bail!("empty password");
    }
    let hash = auth::hash_password(&pw);
    println!("{}", hash);
    eprintln!(
        "\nAdd to bgflow.toml:\n\n[[users]]\nname = \"admin\"\npassword_hash = \"{}\"\nrole = \"admin\"\n",
        hash
    );
    Ok(())
}

/// `bgflowd config-check`: validate config without starting the daemon.
fn config_check(cfg: &config::Config) -> Result<()> {
    let mut errors = 0usize;
    let mut warns = 0usize;
    let mut err = |m: String| {
        errors += 1;
        eprintln!("ERROR: {}", m);
    };
    let mut warn = |m: String| {
        warns += 1;
        eprintln!("warn:  {}", m);
    };

    // Users: valid hash format, unique names, known roles.
    let mut seen = std::collections::HashSet::new();
    for u in &cfg.users {
        match User::from_config(u) {
            Ok(user) => {
                if !seen.insert(user.name.clone()) {
                    err(format!("duplicate user name '{}'", user.name));
                }
            }
            Err(e) => err(e),
        }
    }
    if cfg.users.is_empty() && cfg.server.auth.is_none() {
        warn("no auth configured — UI/API will be world-readable if http_listen is not loopback".into());
    }

    // Inputs: protocol + transport sanity.
    for (i, inp) in cfg.inputs.iter().enumerate() {
        let proto_ok = matches!(
            inp.protocol.to_ascii_lowercase().as_str(),
            "auto" | "netflow5" | "netflow9" | "ipfix" | "sflow" | "v5" | "v9" | "nf5" | "nf9"
        );
        if !proto_ok {
            err(format!("input {}: unknown protocol '{}'", i, inp.protocol));
        }
        let tr = inp.transport.to_ascii_lowercase();
        if !matches!(tr.as_str(), "udp" | "tcp" | "both") {
            err(format!("input {}: unknown transport '{}'", i, inp.transport));
        }
        if (tr == "tcp" || tr == "both")
            && !matches!(
                inp.protocol.to_ascii_lowercase().as_str(),
                "auto" | "ipfix"
            )
        {
            err(format!(
                "input {}: tcp transport requires protocol ipfix/auto (got '{}')",
                i, inp.protocol
            ));
        }
        if inp.listen.port() == 0 {
            err(format!("input {}: port 0 is not a valid listen port", i));
        }
    }

    // TLS: cert+key must be a pair and files must exist.
    match (&cfg.server.tls_cert, &cfg.server.tls_key) {
        (Some(c), Some(k)) => {
            for p in [c, k] {
                if !std::path::Path::new(p).exists() {
                    err(format!("TLS file not found: {}", p));
                }
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            err("tls_cert and tls_key must both be set or both empty".into());
        }
        _ => {}
    }

    // Storage: data dir should be creatable.
    if let Err(e) = std::fs::create_dir_all(&cfg.storage.data_dir) {
        err(format!("cannot create data dir {}: {}", cfg.storage.data_dir.display(), e));
    }

    // Enrichers: http needs a URL; table needs a path.
    for (i, e) in cfg.enrichers.iter().enumerate() {
        match e.kind.as_str() {
            "http" => {
                if e.url.is_empty() {
                    err(format!("enricher {}: http type needs url", i));
                } else if !e.url.starts_with("http://") && !e.url.starts_with("https://") {
                    err(format!("enricher {}: url must start with http(s)://", i));
                }
            }
            "table" => {
                if e.path.as_deref().unwrap_or("").is_empty() {
                    err(format!("enricher {}: table type needs path", i));
                }
            }
            other => err(format!("enricher {}: unknown type '{}'", i, other)),
        }
    }

    // GeoIP: warn when configured DBs are missing (optional feature).
    for (name, p) in [
        ("geoip.asn_db", &cfg.geoip.asn_db),
        ("geoip.country_db", &cfg.geoip.country_db),
    ] {
        for path in p.paths() {
            if !path.is_empty() && !std::path::Path::new(path).exists() {
                warn(format!("{} not found: {} (geo enrichment for this DB disabled)", name, path));
            }
        }
    }

    // Alert rules: basic sanity.
    for (i, a) in cfg.alerts.items.iter().enumerate() {
        if a.name.is_empty() {
            warn(format!("alert rule {} has no name", i));
        }
        if !matches!(a.op.as_str(), "gt" | "lt" | "gte" | "lte") {
            err(format!("alert '{}': bad op '{}'", a.name, a.op));
        }
        if let Some(g) = &a.group_by {
            if bgflowd_query_dim(g).is_none() {
                warn(format!("alert '{}': unknown group_by '{}'", a.name, g));
            }
        }
    }

    // Demo target parse.
    if let Some(t) = cfg.demo.target {
        let _ = t; // SocketAddr already validated by serde
    }

    println!(
        "config check: {} error(s), {} warning(s) — {} input(s), {} user(s), {} enricher(s), {} rule(s), {} alert rule(s)",
        errors,
        warns,
        cfg.inputs.len(),
        cfg.users.len(),
        cfg.enrichers.len(),
        cfg.rules.len(),
        cfg.alerts.items.len(),
    );
    if errors > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Known rollup dims for alert group_by validation (mirrors query.rs).
fn bgflowd_query_dim(d: &str) -> Option<()> {
    const DIMS: &[&str] = &[
        "src_ip", "dst_ip", "src_ipver", "dst_ipver", "src_asn", "dst_asn",
        "src_org", "dst_org", "src_port", "dst_port", "proto",
        "exporter", "src_country", "dst_country", "label",
    ];
    DIMS.contains(&d).then_some(())
}

/// `bgflowd backup`: CRC-verified copy of the data directory.
fn backup_cmd(cfg: &config::Config, dest: Option<PathBuf>) -> Result<()> {
    let dest = dest.unwrap_or_else(|| backup::default_dest());
    println!("backing up {} → {}", cfg.storage.data_dir.display(), dest.display());
    let rep = backup::run_backup(&cfg.storage.data_dir, &dest)?;
    println!(
        "done: {} → {}: {} file(s), {:.1} MiB, {} segment(s) CRC-verified{}, {} skipped",
        cfg.storage.data_dir.display(),
        rep.dest.display(),
        rep.files,
        rep.bytes as f64 / 1_048_576.0,
        rep.verified,
        if rep.retried > 0 {
            format!(" ({} needed retry)", rep.retried)
        } else {
            String::new()
        },
        rep.skipped,
    );
    if rep.skipped > 0 {
        anyhow::bail!("{} segment(s) failed verification — backup may be incomplete", rep.skipped);
    }
    Ok(())
}

/// `bgflowd doctor`: walk the data dir and CRC-verify every segment.
fn doctor(cfg: &config::Config) -> Result<()> {
    let root = &cfg.storage.data_dir;
    if !root.exists() {
        println!("data dir {} does not exist", root.display());
        return Ok(());
    }
    let segs = bgflow_store::scan_segments(root)?;
    let mut ok = 0usize;
    let mut bad = 0usize;
    let mut bytes = 0u64;
    for s in &segs {
        bytes += s.file_size;
        match bgflow_store::verify_crc(&s.path) {
            Ok(true) => ok += 1,
            Ok(false) => {
                bad += 1;
                println!("CORRUPT: {}", s.path.display());
            }
            Err(e) => {
                bad += 1;
                println!("UNREADABLE: {} ({})", s.path.display(), e);
            }
        }
    }
    println!(
        "checked {} segments ({:.1} MiB): {} ok, {} bad",
        segs.len(),
        bytes as f64 / 1_048_576.0,
        ok,
        bad
    );
    if bad > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Acquire `<data_dir>/bgflowd.lock` containing our pid. A stale lock
/// (dead pid) is reclaimed; a live pid means another daemon owns the dir.
fn acquire_instance_lock(data_dir: &std::path::Path) -> Result<std::fs::File> {
    use std::io::Write;
    let lock = data_dir.join("bgflowd.lock");
    for _ in 0..2 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
        {
            Ok(mut f) => {
                writeln!(f, "{}", std::process::id())?;
                return Ok(f);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let alive = std::fs::read_to_string(&lock)
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .map(|pid| {
                        // pid == ours means a stale lock recycled our pid —
                        // we didn't write it (create_new failed), so reclaim.
                        pid != std::process::id() as u32
                            && std::path::Path::new(&format!("/proc/{}/exe", pid)).exists()
                    })
                    .unwrap_or(false);
                if alive {
                    anyhow::bail!(
                        "another bgflowd instance appears to be running \
                         ({} exists) — refusing to share data dir {}",
                        lock.display(),
                        data_dir.display()
                    );
                }
                let _ = std::fs::remove_file(&lock); // stale — retry
            }
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("could not acquire instance lock {}", lock.display())
}
