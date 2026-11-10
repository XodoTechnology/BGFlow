//! bgflowd — BGFlow daemon: flow collector, storage engine, API, UI.

mod alerts;
mod api;
mod config;
mod demo;
mod enrich;
mod ingest;
mod metrics;
mod query;
mod rules;
mod writer;

use anyhow::Result;
use api::AppState;
use clap::{Parser, Subcommand};
use enrich::{HttpEnrichers, MmdbGeo, StringTable};
use metrics::Metrics;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use writer::WriterShared;

#[derive(Subcommand)]
enum Commands {
    /// Verify integrity of all stored .bfs segments (CRC check).
    Doctor,
}

#[derive(Parser)]
#[command(name = "bgflowd", version, about = "BGFlow flow analyzer daemon")]
struct Args {
    /// Path to bgflow.toml (default: ./bgflow.toml, /etc/bgflow/bgflow.toml)
    #[arg(long)]
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
    let cfg = config::load(args.config.as_ref())?;

    if matches!(args.command, Some(Commands::Doctor)) {
        return doctor(&cfg);
    }

    std::fs::create_dir_all(&cfg.storage.data_dir)?;
    tracing::info!("config loaded; data dir {}", cfg.storage.data_dir.display());

    // --- Shared state ---
    let metrics = Arc::new(Metrics::default());
    let orgs = Arc::new(StringTable::open(cfg.storage.data_dir.join("orgs.txt"))?);
    let geo = Arc::new(MmdbGeo::open(&cfg.geoip, orgs.clone(), metrics.clone()));
    if geo.enabled() {
        tracing::info!("geoip enrichment enabled");
    }
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

    // --- HTTP API + UI ---
    let app_state = Arc::new(AppState {
        ctx: query::Ctx {
            flow_index: shared.flow_index.clone(),
            rollup_index: shared.rollup_index.clone(),
            hourly_index: shared.hourly_index.clone(),
            orgs: orgs.clone(),
            rules: rules.clone(),
        },
        status: shared.status.clone(),
        metrics: metrics.clone(),
        http_enrich: http_enrich.clone(),
        geo: geo.clone(),
        config: Arc::new(cfg.clone()),
    });

    // Alert evaluation loop (no-op when no rules configured).
    {
        let acfg = cfg.alerts.clone();
        let c = app_state.ctx.clone();
        let m = metrics.clone();
        tokio::spawn(async move { alerts::run(acfg, c, m).await });
    }

    // SIGHUP: reload rules + enrichers without dropping ingest.
    {
        let cfg_path = config::resolve_path(args.config.as_ref());
        let rules_h = rules.clone();
        let enrich_h = http_enrich.clone();
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
                match config::load(cfg_path.as_ref()) {
                    Ok(new_cfg) => {
                        rules_h.reload(&new_cfg.rules);
                        if let Err(e) = enrich_h.reload(&new_cfg.enrichers) {
                            tracing::warn!("enricher reload failed: {}", e);
                        }
                        tracing::info!("config reloaded (rules + enrichers)");
                    }
                    Err(e) => tracing::warn!("config reload failed: {}", e),
                }
            }
        });
    }

    let app = api::router(app_state);
    if let (Some(cert), Some(key)) = (&cfg.server.tls_cert, &cfg.server.tls_key) {
        tracing::info!("https: listening on {} (TLS)", cfg.server.http_listen);
        let rustls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .map_err(|e| anyhow::anyhow!("TLS config failed: {}", e))?;
        axum_server::bind_rustls(cfg.server.http_listen, rustls)
            .serve(app.into_make_service())
            .await?;
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(cfg.server.http_listen).await?;
    tracing::info!("http: listening on {}", cfg.server.http_listen);
    let serve = axum::serve(listener, app);

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
