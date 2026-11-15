# Installing BGFlow

## Option 1: install script (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/XodoTechnology/BGFlow/main/install.sh | sudo bash
```

This downloads the latest release binary for your platform, installs it to
`/usr/local/bin/bgflowd`, creates the `bgflow` user and `/var/lib/bgflow`
data directory, installs a hardened systemd unit, generates an admin
password (printed once at the end), validates the config, and drops a
starter config at `/etc/bgflow/bgflow.toml`.

Options:

```bash
sh install.sh --start                 # also enable + start the service
sh install.sh --http 127.0.0.1:8080   # bind address for the UI/API
sh install.sh --admin-user netops     # admin username (default: admin)
sh install.sh --demo                  # enable the built-in traffic demo
sh install.sh --version v0.1.0        # pin a version
sh install.sh --prefix /opt/bgflow    # install prefix
sh install.sh --tls-selfsigned        # HTTPS with a self-signed cert
sh install.sh --tls-cert crt --tls-key key   # HTTPS with your own cert
sh install.sh --domain flows.example.com     # Caddy + Let's Encrypt
```

Or via environment: `BGFLOW_VERSION`, `BGFLOW_INSTALL_DIR`.

### Automatic HTTPS with a domain (`--domain`)

For a real public deployment, the simplest path to a trusted cert is a
domain + Caddy — no ACME code in bgflowd itself:

```bash
sh install.sh --domain flows.example.com --start
```

This installs [Caddy](https://caddyserver.com), writes
`/etc/caddy/Caddyfile` with a `reverse_proxy` to bgflowd on loopback,
and binds bgflowd to `127.0.0.1` only. Caddy obtains the Let's Encrypt
cert on first start and renews it automatically (~60 days before the
90-day expiry) — nothing else to maintain.

**Prerequisites:**

- A DNS `A`/`AAAA` record for the domain pointing at this host
- TCP **80** and **443** reachable from the internet (80 is required
  for the ACME challenge *and* the HTTP→HTTPS redirect — the installer
  warns if something already owns them)
- UDP 2055 + TCP 4739 open for your flow exporters (unchanged)

First cert issuance happens when Caddy first serves the domain — allow
a few minutes and check `journalctl -u caddy` if the first visit hangs.
`--domain` cannot be combined with `--tls-*` (Caddy terminates TLS).
If you already run Caddy for other sites, the installer appends a site
block to your existing Caddyfile instead of overwriting it.

Then:

```bash
sudo systemctl enable --now bgflowd    # unless you passed --start
# UI → http://<host>:8080 — log in with the generated admin password
```

## Option 2: Docker

```bash
git clone https://github.com/XodoTechnology/BGFlow.git
cd BGFlow
docker compose up -d --build
```

Or with an explicit compose file / image:

```bash
docker build -t bgflow .
docker run -d --name bgflow \
  -p 8080:8080 -p 2055:2055/udp \
  -v bgflow-data:/var/lib/bgflow \
  -v /path/to/bgflow.toml:/etc/bgflow/bgflow.toml:ro \
  bgflow
```

The container listens on UDP 2055 + TCP 4739 (flow inputs) and TCP 8080
(UI/API) by default. **Auth is OFF with the stock example config** —
`docker compose` mounts `bgflow.example.toml`, which has no users. For
anything beyond a throwaway test, create your own config with a
`[[users]]` entry (see "Securing a public deployment" below) and point
at it:

```bash
cp bgflow.example.toml bgflow.toml   # then add a [[users]] block
BGFLOW_CONFIG=./bgflow.toml docker compose up -d
```

Or with `docker run`, mount your config the same way. TLS inside the
container works via `server.tls_cert`/`tls_key` in your config — for
production, terminating TLS at a reverse proxy in front of the
container is equally fine.

Environment overrides (applied after the config file, env wins):

- `BGFLOW_HTTP_LISTEN` — e.g. `0.0.0.0:8080`
- `BGFLOW_DATA_DIR` — e.g. `/var/lib/bgflow`
- `RUST_LOG` — log filter (e.g. `info`, `bgflowd=debug`)

## Option 3: from source

```bash
git clone https://github.com/XodoTechnology/BGFlow.git
cd BGFlow
cargo build --release -p bgflowd
sudo install -m755 target/release/bgflowd /usr/local/bin/
sudo mkdir -p /etc/bgflow /var/lib/bgflow
sudo cp bgflow.example.toml /etc/bgflow/bgflow.toml
sudo nano /etc/bgflow/bgflow.toml
```

Then install the systemd unit (see `deploy/bgflowd.service`) or run
`bgflowd --config /etc/bgflow/bgflow.toml` directly.

## Pointing exporters at it

Any NetFlow/IPFIX/sFlow exporter can target BGFlow:

- **Host**: `bgflowd` host IP
- **Port**: whatever `[[inputs]] listen` is set to (default UDP 2055)
- **Protocol**: `auto` handles all supported formats on the same port

Example router config (Cisco-ish):

```
flow exporter BGflow
 export destination 10.0.0.5 2055
 transport udp 2055
 version 9
!
flow monitor BM
 record netflow ipv4 original-input octets
 exporter BGflow
!
```

## Verifying

```bash
curl http://localhost:8080/api/v1/health        # ok
curl http://localhost:8080/api/v1/status       # storage + host stats
curl http://localhost:8080/metrics | head      # prometheus
xdg-open http://localhost:8080                     # UI
```

Try the built-in demo while learning the UI:

```bash
bgflowd --demo 127.0.0.1:2055 --demo-pps 20 --demo-secs 300
```

## GeoIP enrichment (optional)

ASN/org/country lookup works out of the box for flows whose exporter
provides the fields, plus HTTP enrichers (e.g. `irrd3.net`) and table
dumps. **City/region/coordinates** come from *-city-*.mmdb databases —
point `country_db` at a city database (the `geoip-update --source
github` city files, DB-IP Lite city, or GeoLite2-City) and flows gain
`src_city`/`dst_city`, region names, and lat/lon in the API, CSV export,
and flow-row tooltips. For **MMDB-backed enrichment of everything else**,
the easiest path is the built-in downloader:

```sh
bgflowd geoip-update                    # DB-IP Lite → /usr/share/GeoIP
bgflowd geoip-update --source github    # per-family GeoLite2, no MaxMind key
```

Both print the `[geoip]` config snippet to paste into `bgflow.toml`.
`asn_db`/`country_db` accept a single path **or a list** — the GitHub
source ships separate IPv4/IPv6 files and the list form lets lookups
pick the right database per address family. Manual installs work too —
drop any MaxMind-compatible `.mmdb` at the configured paths:

- **DB-IP Lite** — free, no account:
  `https://db-ip.com/db/download/ip-to-asn-mmdb.html` and
  `https://db-ip.com/db/download/ip-to-country-mmdb.html`
  (monthly updates; gunzip into `/usr/share/GeoIP/`)
- **MaxMind GeoLite2** — free account + license key from maxmind.com
- **ip-database/mmdb** — community mirror of DB-IP + GeoLite2 as
  per-family `.mmdb.gz` files: https://github.com/ip-database/mmdb

Then `systemctl reload bgflow` (or restart) — the log shows
`geoip enrichment enabled` when the DBs load.

**Updates are automatic.** The daemon watches the configured `.mmdb`
files and hot-swaps readers within ~60s of any change — so a manual
`bgflowd geoip-update`, package upgrade, or `geoip-update` timer all
apply without a restart. For fully unattended updates, enable the
built-in downloader:

```toml
[geoip]
update_source = "github"    # or "dbip"
update_secs = 604800        # weekly (0 = weekly default)
# update_dir = "/usr/share/GeoIP"   # optional; defaults to the dir of
                                    # the first configured db path
```

A cron/systemd timer running `bgflowd geoip-update` works too — the
daemon notices the new files on its next tick.

## Changing settings

Most configuration is editable **live in the UI** — open **Settings**
(admin login). Saving writes `/var/lib/bgflow/settings.json`, which
overrides `bgflow.toml` key-by-key, and hot-applies everything except
fields tagged `↻ restart` (listeners, SNMP poller, storage layout).
Delete `settings.json` to return to pure file configuration. Secrets
(password hashes, SNMP community, API keys) are write-only in the UI —
they show as `•••` and are preserved unless you type a new value.

The same can be done by hand: edit `/etc/bgflow/bgflow.toml`, then
`sudo systemctl reload bgflowd` (SIGHUP) — rules, enrichers, names,
users, alerts, retention and the disk cap all apply without dropping
ingest.

## Securing a public deployment

If the UI/API will be reachable beyond localhost, **set up auth before
exposing it** — `bgflowd` logs a warning when it detects this. The
installer already creates an admin user; to add more or change
passwords, either use **Settings → Users** in the UI or:

```bash
# 1. Create a password hash (reads password from stdin):
bgflowd hash-password

# 2. Paste the printed hash into /etc/bgflow/bgflow.toml:
sudo nano /etc/bgflow/bgflow.toml
#   [[users]]
#   name = "admin"
#   password_hash = "pbkdf2-sha256$600000$...."
#   role = "admin"

# 3. Reload without restart:
sudo systemctl reload bgflowd     # or: sudo kill -HUP $(pidof bgflowd)
```

Then terminate TLS — easiest is reinstalling/re-running with
`--domain <your-domain>` (Caddy + automatic Let's Encrypt), or directly
via `server.tls_cert`/`tls_key`, or at your own reverse proxy
(Caddy/nginx/Traefik). Without TLS, passwords and session cookies are
plaintext on the wire.

## Backups

```bash
# Live-safe, CRC-verified snapshot of the data dir:
bgflowd backup --dest /mnt/backups/bgflow
# or: bgflowd backup            # ./bgflow-backup-<timestamp>

# Validate the config any time:
bgflowd config-check --config /etc/bgflow/bgflow.toml
```

Restore: stop `bgflowd`, point `storage.data_dir` (or `BGFLOW_DATA_DIR`)
at the backup directory, start it. Segments are self-describing — no
rebuild step needed.

## Uninstall

```bash
sudo systemctl disable --now bgflowd
sudo rm /etc/systemd/system/bgflowd.service /usr/local/bin/bgflowd
sudo rm -rf /etc/bgflow          # config (data kept in /var/lib/bgflow)
# If you installed with --domain, also remove the proxy:
sudo systemctl disable --now caddy && sudo apt remove caddy
sudo rm -f /etc/caddy/Caddyfile /etc/apt/sources.list.d/caddy-stable.list
```
