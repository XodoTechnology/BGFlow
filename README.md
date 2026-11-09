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
  storage small; raw flows kept for a shorter retention window.
- **Protocols**: NetFlow v5, NetFlow v9 (template cache), IPFIX (enterprise +
  variable-length fields), sFlow v5. Auto-detected per datagram on one port.
- **Enrichment**: MaxMind MMDB (GeoLite2-ASN/Country) plus **pluggable HTTP
  backends** — point it at your own whois/RDAP/IRR services (e.g. `irrd3.net`)
  with configurable JSON field mapping and prefix-granularity caching.
- **Label rules** — TOML-defined rules tag flows (ASN, port, prefix, org, …)
  for filtering and classification.
- **Prometheus metrics** at `/metrics`.
- **Embedded UI** — dark, Elastiflow-style SPA: overview dashboard, flow
  explorer, top talkers, conversations, exporters, labels, metrics.
- **Low resource use** — a few % CPU and tens of MB RAM at moderate rates.

## Quickstart

```bash
# 1. Install (see INSTALL.md for all options)
curl -fsSL https://raw.githubusercontent.com/XodoTechnology/BGFlow/main/install.sh | sudo bash

# 2. Configure
sudoedit /etc/bgflow/bgflow.toml     # set data_dir, listen addrs, enrichers

# 3. Run
sudo systemctl enable --now bgflowd

# 4. Open the UI
open http://localhost:8080
```

Or run the demo to see it ingest synthetic NetFlow:

```bash
bgflowd --demo 127.0.0.1:2055 --demo-secs 60
# then browse http://localhost:8080
```

## Build from source

```bash
git clone https://github.com/XodoTechnology/BGFlow.git
cd BGFlow
cargo build --release -p bgflowd
# binary: target/release/bgflowd
```

Requires Rust 1.85+ (developed on 1.99).

## Configuration

`bgflow.toml` (searched in `./`, `/etc/bgflow/`, or pass `--config`):

```toml
[server]
http_listen = "0.0.0.0:8080"
# auth = "user:password"        # optional HTTP basic auth
# cors = true                   # optional CORS for API access

[storage]
data_dir = "/var/lib/bgflow"
segment_rows = 100000           # flush raw segment at N rows
segment_interval_secs = 60      # ...or after N seconds
raw_retention_days = 7          # raw flow retention
rollup_retention_days = 90      # rollup retention (long-range queries)

[geoip]
asn_db = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"      # optional
country_db = "/usr/share/GeoIP/GeoLite2-Country.mmdb"

[[inputs]]
listen = "0.0.0.0:2055"
protocol = "auto"               # auto|netflow5|netflow9|ipfix|sflow
# allowed_exporters = ["10.0.0.1"]

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
| `GET /api/v1/flows` | Raw flows — `from,to,src,dst,proto,sport,dport,exporter,src_asn,dst_asn,label,limit,order` |
| `GET /api/v1/summary` | Totals + per-protocol breakdown over rollups |
| `GET /api/v1/timeseries` | `bucket=1m|5m|15m|1h|6h|1d` bytes/packets/flows series |
| `GET /api/v1/top` | `by=src_ip,dst_ip,src_asn,dst_asn,src_port,dst_port,proto,exporter,src_country,dst_country` |
| `GET /api/v1/conversations` | Top 5-tuple conversations |
| `GET /api/v1/exporters` | Seen exporters + counters |
| `GET /api/v1/labels` | Configured label rules |
| `GET /api/v1/enrichers` | Enricher backends + cache stats |
| `GET /api/v1/lookup?ip=` | Cached enrichment detail for an IP |
| `GET /api/v1/status` | Daemon/storage status |
| `GET /metrics` | Prometheus exposition |

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
