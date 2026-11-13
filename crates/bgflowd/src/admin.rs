//! Admin operations shared between the SIGHUP handler and the authenticated
//! `/api/v1/admin/*` endpoints: hot config reload.

use crate::auth::AuthState;
use crate::config::{self, AlertsConfig};
use crate::enrich::{HttpEnrichers, MmdbGeo};
use crate::query::{ExporterNames, InterfaceNames, VlanNames};
use crate::rules::Ruleset;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// Handles needed to apply a reloaded config without restarting.
#[derive(Clone)]
pub struct AdminShared {
    /// Config file path the daemon was started with (None = defaults/env).
    pub config_path: Option<PathBuf>,
    pub rules: Arc<Ruleset>,
    pub enrich: Arc<HttpEnrichers>,
    pub exporter_names: Arc<RwLock<ExporterNames>>,
    pub interface_names: Arc<RwLock<InterfaceNames>>,
    pub vlan_names: Arc<RwLock<VlanNames>>,
    pub local_asns: Arc<RwLock<Vec<u32>>>,
    pub auth: Arc<AuthState>,
    pub alerts: Arc<RwLock<AlertsConfig>>,
    /// MMDB geo readers — swapped on reload so geoip config/path changes
    /// and replaced database files apply without a restart.
    pub geo: Arc<MmdbGeo>,
    /// Exporter admission policy — knobs (require_approval, trusted)
    /// refresh on reload; learned entries are untouched.
    pub exporter_policy: Arc<crate::exporter_policy::ExporterPolicy>,
}

#[derive(Debug, serde::Serialize)]
pub struct ReloadReport {
    pub ok: bool,
    pub rules: usize,
    pub enrichers: usize,
    pub exporter_names: usize,
    pub users: usize,
    pub alert_rules: usize,
    /// MMDB readers loaded after the reload (0 = geoip disabled).
    pub geo_dbs: usize,
    pub errors: Vec<String>,
}

impl AdminShared {
    /// Reload rules, enrichers, exporter names, users and alert rules from
    /// the config file. Each subsystem is independent — one failure doesn't
    /// block the others; errors are collected into the report.
    pub fn reload(&self) -> ReloadReport {
        let mut rep = ReloadReport {
            ok: true,
            rules: 0,
            enrichers: 0,
            exporter_names: 0,
            users: 0,
            alert_rules: 0,
            geo_dbs: 0,
            errors: vec![],
        };
        let cfg = match config::load(self.config_path.as_ref()) {
            Ok(c) => c,
            Err(e) => {
                rep.ok = false;
                rep.errors.push(format!("config load: {}", e));
                return rep;
            }
        };

        self.rules.reload(&cfg.rules);
        rep.rules = cfg.rules.len();

        match self.enrich.reload(&cfg.enrichers) {
            Ok(()) => rep.enrichers = cfg.enrichers.len(),
            Err(e) => {
                rep.ok = false;
                rep.errors.push(format!("enrichers: {}", e));
            }
        }

        *self.exporter_names.write().unwrap() = ExporterNames::build(&cfg.exporter_names);
        rep.exporter_names = cfg.exporter_names.len();
        // Re-apply UI-set names persisted in the exporter policy.
        {
            let mut names = self.exporter_names.write().unwrap();
            for (ip, e) in self.exporter_policy.entries() {
                if let Some(n) = e.name {
                    names.set_name(bgflow_types::ip_to_u128(&ip), Some(n));
                }
            }
        }

        *self.interface_names.write().unwrap() = InterfaceNames::build(&cfg.interface_names);

        *self.vlan_names.write().unwrap() = VlanNames::build(&cfg.vlan_names);

        *self.local_asns.write().unwrap() = cfg.analytics.local_asns.clone();

        rep.users = self.auth.reload_users(&cfg.users);

        *self.alerts.write().unwrap() = cfg.alerts.clone();
        rep.alert_rules = cfg.alerts.items.len();

        // MMDB readers: rebuild from the (possibly new) geoip config.
        self.geo.swap(&cfg.geoip);
        rep.geo_dbs = self.geo.db_count();

        // Exporter policy knobs (entries themselves persist untouched).
        self.exporter_policy
            .set_knobs(cfg.exporters.require_approval, cfg.exporters.trusted.clone());

        tracing::info!(
            "config reloaded: {} rules, {} enrichers, {} exporter names, {} users, {} alert rules, {} geo db(s)",
            rep.rules, rep.enrichers, rep.exporter_names, rep.users, rep.alert_rules, rep.geo_dbs
        );
        rep
    }
}
