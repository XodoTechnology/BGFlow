# BGFlow

A lightweight, self-contained flow analyzer — NetFlow v5/v9, IPFIX, and sFlow —
with its own columnar storage engine, rollup aggregation, a REST API, and an
embedded web UI. Inspired by Elastiflow and Akvorado, designed to be leaner:
**one binary, one data directory, no database server.**

## Features

- **Single static binary** (`bgflowd`) — ingest, storage, API, and UI in one.
- **Custom storage engine** — time-partitioned `.bfs` columnar segments with
  per-column dictionary/delta encoding + ZSTD. No ClickHouse, no DuckDB, no
  external DB.
- **In-memory rollups** — 1-minute aggregates keep long-range queries fast and
  storage small; raw flows kept for a shorter retention window. A second
  **coarse dataset** (hourly buckets, /24·/48-masked IPs) provides
  year-scale stats at minimal cardinality — query with `granularity=hourly`.
- **Protocols**: NetFlow v5, NetFlow v9 (template cache), IPFIX (enterprise +
  variable-length fields, UDP **and TCP** stream transport), sFlow v5.
  Auto-detected per datagram on one port.
- **Rich flow metadata** — IPFIX/NetFlow IEs mapped to TTL, flow-end reason,
  ICMP type/code, post-NAT addresses, direction, DSCP, IP version, TCP state,
  sampler interval, observation domain.
- **Enrichment**: MaxMind MMDB (GeoLite2-ASN/Country) plus **pluggable
  backends** — HTTP services (e.g. `irrd3.net`) with JSON field mapping,
  auth headers, and prefix caching; **table enrichers** for bulk
  prefix→ASN/org/country dumps (BGP/IRR-scale, exact LPM, file or URL).
- **Label rules** — TOML-defined rules tag flows (ASN, port, prefix, org, …)
  for filtering and classification; hot-reloadable via SIGHUP.
- **Exporter names** — `[exporter_names]` maps exporter IPs to friendly
  names shown across the UI/API; filters accept IPs or names.
- **Exporter-scoped interface/VLAN naming** — `naming = ["ip|name|ifidx-iface|vlanid-vlan", ...]`
  lines map ifIndex/VLAN IDs *per exporter*, so conflicting identifiers
  across routers never collide. Editable live in Settings → Names.
- **NetFlow/IPFIX export** — `[[export]]` targets re-emit stored flows
  as NetFlow v9 or IPFIX (templates, per-family, UDP), for feeding
  downstream collectors.
- **Disk-usage guard** — `storage.min_free_pct`/`min_free_bytes` evict
  oldest segments when the data filesystem drops below a free-space
  floor (e.g. `20` ≈ keep usage under ~80%), independent of `max_bytes`.
- **Exporter admission control** — `[exporters] require_approval = true`
  makes unknown senders start as `pending`: their datagrams are dropped
  (and counted) until an admin approves them in the Exporters view or via
  `POST /api/v1/exporters/{ip}/{approve|suspend|reject|remove}`. Trusted
  IPs/CIDRs (`[exporters] trusted`) bypass approval; suspend/reject always
  wins. State persists in `<data_dir>/exporters.json`.
- **Threshold alerts** — rate-based rules over rollups (bytes/packets/flows/
  mbps per window, optional group-by + fold-change), log + metric + webhook.
- **Analytics** — top-N by 15 dimensions (IP, ASN, org, port, protocol,
  country, label, IP version, exporter), per-label stats, z-score anomaly
  detection, country heat view, CSV export, OpenAPI spec.
- **Prometheus metrics** at `/metrics` (incl. per-exporter stats and
  `bgflow_ingest_input_up` listener health).
- **Multi-user auth** — `[[users]]` with PBKDF2 password hashes, `admin`/
  `viewer` roles, session-cookie login UI, HTTP Basic for API clients,
  per-IP login throttling, security headers. Legacy `server.auth` basic
  auth still supported.
- **Embedded UI** — dark, Elastiflow-style SPA: dashboard, flow explorer with
  click-to-filter, top talkers, country heatmap with flags, **Sankey flow
  map**, conversations, anomalies, exporters, labels, metrics, saved filter
  presets, live auto-refresh, login page, host CPU/RAM/disk stats, git
  build version.
- **UX** — light/dark theme, shareable URLs (view+filters in the hash),
  SSE live status, PTR hostnames, interface names, period-over-period deltas
  and NEW-entity badges on anomalies.
- **Ops** — `bgflowd doctor` (segment CRC verification), `bgflowd backup`
  (CRC-verified data-dir snapshots), `bgflowd config-check`,
  `bgflowd geoip-update` (downloads free MMDB GeoIP databases),
  `bgflowd hash-password`, `POST /api/v1/admin/reload`, deep `/health`,
  SIGHUP config reload, optional TLS, UDP buffer sizing, TCP conn limits.
- **Low resource use** — a few % CPU and tens of MB RAM at moderate rates.

## Quickstart

```bash
# 1. Install (see INSTALL.md for all options)
curl -fsSL https://raw.githubusercontent.com/XodoTechnology/BGFlow/main/install.sh | sudo bash

# 2. Configure
sudo nano /etc/bgflow/bgflow.toml     # set data_dir, listen addrs, enrichers

# 3. Run
sudo systemctl enable --now bgflowd

# 4. Open the UI
xdg-open http://localhost:8080
```

Or run the demo to see it ingest synthetic NetFlow:

```bash
bgflowd --demo 127.0.0.1:2055 --demo-secs 60
# or enable [demo] in bgflow.toml — then just run bgflowd
# then browse http://localhost:8080
```

Verify stored segment integrity at any time:

```bash
bgflowd doctor    # CRC-checks every .bfs segment under data_dir
```

### Authentication & users

Protect the UI/API with `[[users]]` — PBKDF2-SHA256 password hashes and
roles. Generate a hash first:

```bash
bgflowd hash-password        # prompts for the password on stdin
# or: bgflowd hash-password --password 'secret'
```

```toml
[[users]]
name = "admin"
password_hash = "pbkdf2-sha256$600000$...."
role = "admin"               # admin | viewer
```

- **admin** — everything, including `/api/v1/config`,
  `/api/v1/enrichers`, and `POST /api/v1/admin/reload`.
- **viewer** — read-only access to all data endpoints (GET/HEAD only).
- The UI shows a login page when auth is configured; API clients can use
  the session cookie **or** HTTP Basic auth with the same credentials.
- Login attempts are throttled per source IP (5 failures → lockout).
- Session cookies are `HttpOnly` + `SameSite=Strict` (+ `Secure` under TLS)
  and renew sliding while in use. `server.session_secret` pins the signing
  key; unset = a generated key persisted in `<data_dir>/session.secret`,
  so sessions survive restarts.
- Legacy single-credential mode still works: `server.auth = "user:pass"`
  (always admin). Prefer `[[users]]` for anything beyond a toy deployment.
- `/api/v1/health` and `/metrics` stay unauthenticated for scrapers —
  keep them off the public internet or front them with your proxy.

**Public deployments:** the easiest path is a domain + the installer's
Caddy proxy — `install.sh --domain flows.example.com` installs Caddy,
which obtains and auto-renews a Let's Encrypt cert and proxies to
bgflowd on loopback:

```bash
sh install.sh --domain flows.example.com --start
# needs: DNS A/AAAA record -> this host, TCP 80+443 reachable
```

Alternatives: `server.tls_cert`/`tls_key` for native TLS (static cert
files, loaded once at startup), `--tls-selfsigned` for a quick self-signed
cert, or terminate TLS at your own reverse proxy. Without TLS, passwords
and session cookies cross the network in plaintext — `bgflowd` logs a
loud warning when auth is enabled on a non-loopback address without TLS.

### Backups & administration

```bash
bgflowd backup [--dest /path]   # CRC-verified copy of the data dir
bgflowd config-check            # validate bgflow.toml without starting
bgflowd doctor                  # verify segment integrity
```

`backup` copies all `.bfs` segments and re-verifies each one's CRC,
retrying files caught mid-flush — safe to run while `bgflowd` is live.
To restore, stop the daemon, point `storage.data_dir` at the backup
(e.g. via `BGFLOW_DATA_DIR`), and start it. Rollups rebuild is *not*
needed — segments are the source of truth.

`POST /api/v1/admin/reload` (admin only) hot-reloads label rules,
enrichers, exporter names, users, and alert rules — same as `SIGHUP`.
The UI shows a `⟳ cfg` button for admins.

## Build from source

```bash
git clone https://github.com/XodoTechnology/BGFlow.git
cd BGFlow
cargo build --release -p bgflowd
# binary: target/release/bgflowd
```

Requires Rust 1.88+ (developed on 1.99).

## Configuration

`bgflow.toml` (searched in `./`, `/etc/bgflow/`, or pass `--config`):

```toml
[server]
http_listen = "0.0.0.0:8080"
# Multi-user auth (recommended for anything beyond localhost):
# [[users]]
# name = "admin"
# password_hash = "pbkdf2-sha256$600000$...."   # bgflowd hash-password
# role = "admin"                                # admin | viewer
# Legacy single credential (admin-only):
# auth = "user:password"
# cors = true                   # optional CORS for API access
# cors_origins = ["https://flows.example.com"]  # restrict + credentials
# session_secret = "long-random-string"         # pin session keys
# tls_cert = "/etc/bgflow/tls.crt"              # HTTPS
# tls_key  = "/etc/bgflow/tls.key"

[storage]
data_dir = "/var/lib/bgflow"
segment_rows = 100000           # flush raw segment at N rows
segment_interval_secs = 60      # ...or after N seconds
raw_retention_days = 7          # raw flow retention
rollup_retention_days = 90      # rollup retention (long-range queries)
min_free_pct = 20               # evict oldest segments below this % fs free
min_free_bytes = "5GiB"         # ...or absolute floor (whichever is larger)

[geoip]
asn_db = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"      # optional — any MaxMind MMDB
country_db = "/usr/share/GeoIP/GeoLite2-Country.mmdb"  # (DB-IP Lite works too)
# each also accepts a list for per-family DBs: asn_db = ["...-ipv4.mmdb", "...-ipv6.mmdb"]
# `bgflowd geoip-update` fetches free DBs and prints this config.

[[inputs]]
listen = "0.0.0.0:2055"
protocol = "auto"               # auto|netflow5|netflow9|ipfix|sflow
# transport = "udp"             # udp | tcp | both (tcp = IPFIX only)
# allowed_exporters = ["10.0.0.1"]
# udp_buffer_bytes = 8388608    # SO_RCVBUF — raise for busy routers
# max_connections = 1024        # TCP conn cap (tcp/both only)

# IPFIX over TCP:
# [[inputs]]
# listen = "0.0.0.0:4739"
# protocol = "ipfix"
# transport = "tcp"

# Export stored flows onward as NetFlow v9 / IPFIX:
# [[export]]
# address = "10.0.0.9:2055"
# protocol = "netflow9"         # netflow9 | ipfix
# name = "upstream-collector"

# Exporter-scoped interface/VLAN names (ifIndex/VLAN IDs only make
# sense per exporter — conflicts across routers can't collide):
# naming = [
#   "10.0.0.1|core-rtr-01|2-ae0|250-cogent",
#   "10.0.0.2|core-rtr-02|2-eth0|250-ixp1",
# ]

# --- HTTP enrichment backends (whois/RDAP/IRR, e.g. irrd3.net) ---
[[enrichers]]
type = "http"
name = "irrd3"
url = "https://irrd3.net/api/lookup?ip={ip}"   # {ip} or {prefix} placeholders
timeout_ms = 2000
cache_ttl_secs = 86400
[enrichers.fields]
asn = "$.asn"
org = "$.org"
country = "$.country"
handle = "$.handle"             # extra fields -> lookup API
# Optional auth/API-key headers for private backends:
# [enrichers.headers]
# Authorization = "Bearer token"

# --- Label rules (first match wins) ---
[[rules]]
name = "google"
dst_asn = 15169
dst_port = 443

[[rules]]
name = "internal"
src_ip = "10.0.0.0/8"
```

Rule match fields (all ANDed): `proto`, `src_port`, `dst_port`, `src_ip`,
`dst_ip` (CIDR), `src_asn`, `dst_asn`, `src_country`, `dst_country` (alpha-2),
`exporter`, `org` (substring match on org name).

## API

| Endpoint | Description |
|---|---|
| `GET /api/v1/flows` | Raw flows — `from,to,src,dst,proto,sport,dport,exporter` (comma list),`src_asn,dst_asn,src_ipver,dst_ipver,src_org,dst_org,label,limit,offset,order,format=csv` |
| `GET /api/v1/summary` | Totals + per-protocol breakdown over rollups |
| `GET /api/v1/overview` | Combined dashboard payload — totals, protocol, series, top dims in **one** rollup scan |
| `GET /api/v1/matrix` | `src_dim`/`dst_dim` pair aggregation for flow maps (asn/org/country/ipver/proto/port/label) |
| `GET /api/v1/timeseries` | `bucket=1m|5m|15m|1h|6h|1d` bytes/packets/flows series |
| `GET /api/v1/top` | `by=` any of `src_ip,dst_ip,src_ipver,dst_ipver,src_asn,dst_asn,src_org,dst_org,src_port,dst_port,proto,exporter,src_country,dst_country,label`; filters same as summary + `granularity=minute|hourly` |
| `GET /api/v1/conversations` | Top 5-tuple conversations |
| `GET /api/v1/anomalies` | z-score outliers, `by=`, `sigma=`, `granularity=` |
| `GET /api/v1/label_stats` | Traffic totals per label |
| `GET /api/v1/exporters` | Seen exporters + counters |
| `GET /api/v1/labels` | Configured label rules |
| `GET /api/v1/enrichers` | Enricher backends + cache/table stats |
| `GET /api/v1/lookup?ip=` | Cached enrichment detail for an IP |
| `GET /api/v1/config` | Effective config (secrets redacted, admin only) |
| `GET /api/v1/openapi.json` | OpenAPI 3.0 spec |
| `GET /api/v1/status` | Daemon/storage status + version + host CPU/RAM/disk + per-input listener state |
| `GET /api/v1/health` | Deep health: writer liveness, buffers, flush age (unauthenticated) |
| `POST /api/v1/auth/login` | Login → session cookie (throttled per IP) |
| `POST /api/v1/auth/logout` | Clear session cookie |
| `GET /api/v1/auth/me` | Current identity / auth state probe |
| `POST /api/v1/admin/reload` | Hot-reload rules/enrichers/users/alerts (admin) |
| `GET /metrics` | Prometheus exposition (unauthenticated) |

Rollup-backed endpoints (`summary`, `timeseries`, `top`, `conversations`,
`anomalies`, `label_stats`) accept `granularity=hourly` to query the coarse
long-retention dataset (hour buckets, /24·/48-masked IPs). Filters:
`from,to,src,dst` (IP or CIDR), `proto`, `sport,dport` (or `src_port,
dst_port`), `exporter` (comma-separated allowlist), `src_asn,dst_asn`,
`src_country,dst_country` (alpha-2), `src_ipver,dst_ipver` (4|6),
`src_org,dst_org` (org id), `label` (name or id).

Time params accept epoch seconds, epoch millis, or relative `-15m`, `-1h`,
`-7d`. `to` defaults to now.

## Architecture

```
UDP :2055 ──► bgflowd
               ├─ parse (auto-detect v5/v9/IPFIX/sFlow, template caches)
               ├─ enrich (MMDB sync; HTTP backends async+cached)
               ├─ label rules
               └─► writer task ──► .bfs segments (raw) + rollups (1-min)
                                          │
                          REST API ──► reads segment files directly
                          UI (embedded SPA) ──► same API
```

- `crates/bgflow-types` — shared `FlowRecord`/`RollupRecord` schema
- `crates/bgflow-store` — columnar segment engine (encoders, segments,
  datasets, rollup aggregator)
- `crates/bgflow-netflow` — protocol parsers
- `crates/bgflowd` — daemon, enrichment, rules, API, UI

## License

MIT
