//! bgflowd — BGFlow daemon: flow collector, storage engine, API, UI.

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
use clap::Parser;
use enrich::{HttpEnrichers, MmdbGeo, StringTable};
use metrics::Metrics;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use writer::WriterShared;

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
    std::fs::create_dir_all(&cfg.storage.data_dir)?;
    tracing::info!("config loaded; data dir {}", cfg.storage.data_dir.display());

    // --- Shared state ---
    let metrics = Arc::new(Metrics::default());
    let orgs = Arc::new(StringTable::open(cfg.storage.data_dir.join("orgs.txt"))?);
    let geo = Arc::new(MmdbGeo::open(&cfg.geoip, orgs.clone()));
    if geo.enabled() {
        tracing::info!("geoip enrichment enabled");
    }
    let http_enrich = Arc::new(HttpEnrichers::new(
        &cfg.enrichers,
        metrics.clone(),
        orgs.clone(),
    )?);
    if http_enrich.enabled() {
        tracing::info!("{} HTTP enricher(s) configured", http_enrich.items.len());
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
    let label_names: std::collections::HashMap<u32, String> = rules
        .list()
        .into_iter()
        .map(|(id, n)| (id, n.to_string()))
        .collect();
    let app_state = Arc::new(AppState {
        ctx: query::Ctx {
            flow_index: shared.flow_index.clone(),
            rollup_index: shared.rollup_index.clone(),
            orgs: orgs.clone(),
            rules: rules.clone(),
            label_names,
        },
        status: shared.status.clone(),
        metrics: metrics.clone(),
        http_enrich: http_enrich.clone(),
        config: Arc::new(cfg.clone()),
    });

    let app = api::router(app_state);
    let listener = tokio::net::TcpListener::bind(cfg.server.http_listen).await?;
    tracing::info!("http: listening on {}", cfg.server.http_listen);
    let serve = axum::serve(listener, app);

    // Demo sender runs in the background; daemon keeps serving regardless.
    if let Some(target) = args.demo {
        let pps = args.demo_pps;
        let flows = args.demo_flows;
        let secs = args.demo_secs;
        tokio::spawn(async move {
            let dur = if secs == 0 { None } else { Some(secs) };
            tracing::info!("demo: sending traffic to {}", target);
            if let Err(e) = demo::run(target, pps, flows, dur).await {
                tracing::error!("demo sender failed: {}", e);
            }
        });
    }

    serve.await?;
    Ok(())
}
