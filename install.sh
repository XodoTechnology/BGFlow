#!/bin/sh
# BGFlow installer — installs bgflowd binary + systemd unit + config,
# generates admin credentials, validates the config, prints a summary.
# Usage: curl -fsSL .../install.sh | sudo sh
#        sh install.sh [--version vX.Y.Z] [--prefix /usr/local]
#                       [--http 0.0.0.0:8080] [--admin-user admin] [--demo] [--start]
#                       [--tls-cert /path/tls.crt --tls-key /path/tls.key]
#                       [--tls-selfsigned]
#                       [--domain flows.example.com]   (Caddy + Let's Encrypt)
set -eu

REPO="XodoTechnology/BGFlow"
VERSION="${BGFLOW_VERSION:-latest}"
PREFIX="${BGFLOW_INSTALL_DIR:-/usr/local}"
HTTP_ADDR="0.0.0.0:8080"
DEMO=0
START=0
ADMIN_USER="admin"
TLS_CERT=""
TLS_KEY=""
TLS_SELFSIGNED=0
DOMAIN=""
HTTP_SET=0
SCHEME="http"

# --- args --------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --prefix)  PREFIX="$2";  shift 2 ;;
    --prefix=*) PREFIX="${1#*=}"; shift ;;
    --http)    HTTP_ADDR="$2"; HTTP_SET=1; shift 2 ;;
    --http=*)  HTTP_ADDR="${1#*=}"; HTTP_SET=1; shift ;;
    --admin-user) ADMIN_USER="$2"; shift 2 ;;
    --admin-user=*) ADMIN_USER="${1#*=}"; shift ;;
    --tls-cert) TLS_CERT="$2"; shift 2 ;;
    --tls-cert=*) TLS_CERT="${1#*=}"; shift ;;
    --tls-key) TLS_KEY="$2"; shift 2 ;;
    --tls-key=*) TLS_KEY="${1#*=}"; shift ;;
    --tls-selfsigned) TLS_SELFSIGNED=1; shift ;;
    --domain)   DOMAIN="$2"; shift 2 ;;
    --domain=*) DOMAIN="${1#*=}"; shift ;;
    --demo)    DEMO=1; shift ;;
    --start)   START=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Values land inside a TOML file — reject anything that could break
# out of the string literal.
case "$ADMIN_USER" in
  *[!A-Za-z0-9_.-]*|"") die "--admin-user must be [A-Za-z0-9_.-]+" ;;
esac
case "$HTTP_ADDR" in
  *[\"\\\`\$]*) die "--http contains unsafe characters" ;;
esac
HTTP_PORT="${HTTP_ADDR##*:}"

# TLS option sanity — fail before downloading anything.
if [ "$TLS_SELFSIGNED" = "1" ] && { [ -n "$TLS_CERT" ] || [ -n "$TLS_KEY" ]; }; then
  die "--tls-selfsigned cannot be combined with --tls-cert/--tls-key"
fi
if [ -n "$TLS_CERT" ] || [ -n "$TLS_KEY" ]; then
  if [ -z "$TLS_CERT" ] || [ -z "$TLS_KEY" ]; then
    die "--tls-cert and --tls-key must be given together"
  fi
  [ -f "$TLS_CERT" ] || die "tls cert not found: $TLS_CERT"
  [ -f "$TLS_KEY" ]  || die "tls key not found: $TLS_KEY"
fi

# --domain puts Caddy in front with automatic Let's Encrypt certs.
# bgflowd then speaks plain HTTP on loopback only — Caddy owns :80/:443.
if [ -n "$DOMAIN" ]; then
  case "$DOMAIN" in
    *[!A-Za-z0-9.-]*|.*|*..*|*.) \
      die "--domain must be a plain hostname (e.g. flows.example.com)" ;;
  esac
  if [ "$TLS_SELFSIGNED" = "1" ] || [ -n "$TLS_CERT" ] || [ -n "$TLS_KEY" ]; then
    die "--domain cannot be combined with --tls-* options (Caddy terminates TLS)"
  fi
  HTTP_PORT="${HTTP_ADDR##*:}"
  if [ "$HTTP_SET" = "1" ] && [ "${HTTP_ADDR%%:*}" != "127.0.0.1" ]; then
    info "note: --domain proxies via 127.0.0.1 — binding bgflowd to loopback, not $HTTP_ADDR"
  fi
  HTTP_ADDR="127.0.0.1:$HTTP_PORT"
fi

BINDIR="$PREFIX/bin"
SYSCONFDIR="/etc/bgflow"
DATADIR="/var/lib/bgflow"
USER_NAME="bgflow"

[ "$(id -u)" -eq 0 ] || die "run as root (or with sudo)"

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS/$ARCH" in
  Linux/x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
  Linux/aarch64|Linux/arm64) TARGET="aarch64-unknown-linux-gnu" ;;
  *) die "unsupported platform $OS/$ARCH (build from source instead)" ;;
esac

# --- resolve version ---------------------------------------------------------
if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)"
  [ -n "$VERSION" ] || die "could not resolve latest release"
fi
info "installing BGFlow $VERSION ($TARGET)"

# --- download ----------------------------------------------------------------
TARBALL="bgflow-${VERSION#v}-${TARGET}.tar.gz"
BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
URL="$BASE_URL/$TARBALL"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

info "downloading $URL"
curl -fsSL "$URL" -o "$TMP/$TARBALL" || \
  die "download failed — if this is a source-only release, build with: cargo build --release -p bgflowd"

# --- verify checksum ---------------------------------------------------------
if curl -fsSL "$BASE_URL/SHA256SUMS" -o "$TMP/SHA256SUMS" 2>/dev/null; then
  EXPECTED="$(awk -v f="$TARBALL" '$2==f{print $1}' "$TMP/SHA256SUMS")"
  if [ -n "$EXPECTED" ]; then
    ACTUAL="$(sha256sum "$TMP/$TARBALL" | awk '{print $1}')"
    [ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch for $TARBALL (expected $EXPECTED, got $ACTUAL)"
    info "checksum verified"
  else
    info "warn: $TARBALL not listed in SHA256SUMS — skipping verification"
  fi
else
  info "warn: SHA256SUMS not published for $VERSION — skipping verification"
fi

tar -xzf "$TMP/$TARBALL" -C "$TMP"
[ -f "$TMP/bgflowd" ] || die "tarball did not contain bgflowd binary"

# --- install binary ----------------------------------------------------------
mkdir -p "$BINDIR" "$SYSCONFDIR" "$DATADIR"
install -m 0755 "$TMP/bgflowd" "$BINDIR/bgflowd"
info "installed $BINDIR/bgflowd"

# --- user --------------------------------------------------------------------
if ! id "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --home "$DATADIR" --shell /usr/sbin/nologin "$USER_NAME" 2>/dev/null \
    || useradd --system --home "$DATADIR" --shell /sbin/nologin "$USER_NAME" \
    || die "could not create $USER_NAME user — create it manually and re-run"
fi
chown -R "$USER_NAME:$USER_NAME" "$DATADIR"

# --- config ------------------------------------------------------------------
if [ ! -f "$SYSCONFDIR/bgflow.toml" ]; then
  # Generate an admin password — printed once at the end, never stored
  # in plaintext anywhere.
  ADMIN_PASS="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)"
  HASH="$(printf '%s' "$ADMIN_PASS" | "$BINDIR/bgflowd" hash-password | head -1)"
  [ -n "$HASH" ] || die "could not generate password hash"

  # TLS material: user-supplied pair, or a self-signed cert for
  # homelab use (browsers will still warn — real certs belong behind
  # a reverse proxy or from a proper CA).
  TLS_LINES=""
  if [ "$TLS_SELFSIGNED" = "1" ]; then
    command -v openssl >/dev/null 2>&1 || \
      die "--tls-selfsigned needs openssl — install it or pass --tls-cert/--tls-key"
    TLS_DIR="$SYSCONFDIR/tls"
    mkdir -p "$TLS_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$TLS_DIR/tls.key" -out "$TLS_DIR/tls.crt" -days 3650 \
      -subj "/CN=bgflow" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 \
      || die "openssl cert generation failed"
    chown -R "$USER_NAME:$USER_NAME" "$TLS_DIR" 2>/dev/null || true
    chmod 0640 "$TLS_DIR/tls.key"; chmod 0644 "$TLS_DIR/tls.crt"
    TLS_CERT="$TLS_DIR/tls.crt"; TLS_KEY="$TLS_DIR/tls.key"
    info "generated self-signed cert in $TLS_DIR (valid 10y, browsers will warn)"
  fi
  if [ -n "$TLS_CERT" ]; then
    TLS_LINES="tls_cert = \"$TLS_CERT\"
tls_key = \"$TLS_KEY\""
    SCHEME="https"
  fi

  cat > "$SYSCONFDIR/bgflow.toml" <<EOF
[server]
http_listen = "$HTTP_ADDR"
$TLS_LINES

[storage]
data_dir = "$DATADIR"
raw_retention_days = 7
rollup_retention_days = 90
# Evict oldest segments when the data filesystem exceeds ~80% used
# (keeps 20% free). Also capped by max_bytes below if set.
min_free_pct = 20

# NetFlow v5/v9, IPFIX and sFlow over UDP — the common exporter target.
[[inputs]]
listen = "0.0.0.0:2055"
protocol = "auto"
udp_buffer_bytes = 4194304
# For IPv6 exporters use "[::]:2055" INSTEAD of the v4 socket above —
# do not bind both or v4 datagrams arrive twice.

# IPFIX over TCP — the standard port most routers/switches export to.
[[inputs]]
listen = "0.0.0.0:4739"
protocol = "ipfix"
transport = "tcp"

[[users]]
name = "$ADMIN_USER"
password_hash = "$HASH"
role = "admin"
EOF
  if [ "$DEMO" = "1" ]; then
    cat >> "$SYSCONFDIR/bgflow.toml" <<EOF

[demo]
enabled = true
EOF
  fi
  cat >> "$SYSCONFDIR/bgflow.toml" <<EOF

# Everything else (retention, disk cap, SNMP, GeoIP, names, rules,
# users) is editable live in the UI under Settings — no restart needed
# for most. See bgflow.example.toml for every option.
EOF
  chmod 0640 "$SYSCONFDIR/bgflow.toml"
  chown root:"$USER_NAME" "$SYSCONFDIR/bgflow.toml" 2>/dev/null || true
  info "wrote $SYSCONFDIR/bgflow.toml"
else
  info "keeping existing $SYSCONFDIR/bgflow.toml"
  ADMIN_PASS=""
fi
# Scheme for health check + summary — detect from the effective config
# so re-runs on a TLS-enabled install still report correctly.
if grep -q '^tls_cert' "$SYSCONFDIR/bgflow.toml" 2>/dev/null; then SCHEME="https"; fi

# --- caddy reverse proxy (--domain) -------------------------------------------
# Caddy obtains and renews the Let's Encrypt cert itself; bgflowd stays
# plain HTTP on loopback. Requires DNS for $DOMAIN pointing here and
# TCP 80+443 reachable — noted again in the final summary.
install_caddy() {
  command -v caddy >/dev/null 2>&1 && { info "caddy already installed"; return 0; }
  if command -v apt-get >/dev/null 2>&1; then
    info "installing caddy via apt"
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https >/dev/null 2>&1 || true
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
      | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg \
      || die "could not fetch caddy apt key"
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
      > /etc/apt/sources.list.d/caddy-stable.list \
      || die "could not fetch caddy apt repo"
    apt-get update -qq >/dev/null
    # Non-fatal: apt can fail on unrelated broken packages even when
    # caddy itself installed fine — the command -v check below decides.
    apt-get install -y -qq caddy >/dev/null 2>&1 \
      || info "warn: apt install returned an error — verifying caddy anyway"
  elif command -v dnf >/dev/null 2>&1; then
    info "installing caddy via dnf"
    dnf install -y -q caddy >/dev/null 2>&1 \
      || { dnf install -y -q 'dnf-command(copr)' >/dev/null 2>&1 \
           && copr enable -y @caddy/caddy >/dev/null 2>&1 \
           && dnf install -y -q caddy >/dev/null 2>&1; } \
      || die "could not install caddy — see caddyserver.com/docs/install"
  elif command -v yum >/dev/null 2>&1; then
    info "installing caddy via yum"
    yum install -y -q caddy >/dev/null 2>&1 \
      || die "could not install caddy — see caddyserver.com/docs/install"
  elif command -v apk >/dev/null 2>&1; then
    info "installing caddy via apk"
    apk add --no-cache caddy >/dev/null 2>&1 \
      || die "could not install caddy — see caddyserver.com/docs/install"
  else
    die "--domain needs caddy — install it yourself, write /etc/caddy/Caddyfile, and re-run without --domain"
  fi
  command -v caddy >/dev/null 2>&1 || die "caddy install failed"
}

if [ -n "$DOMAIN" ]; then
  # Caddy needs :80 (ACME HTTP-01 + redirects) and :443 (HTTPS). Warn
  # early if something already owns them — the install would otherwise
  # succeed while caddy silently fails to bind.
  for p in 80 443; do
    if curl -s --max-time 1 -o /dev/null "http://127.0.0.1:$p/" 2>/dev/null \
       || curl -sk --max-time 1 -o /dev/null "https://127.0.0.1:$p/" 2>/dev/null; then
      info "warn: something is already listening on port $p — caddy needs it for Let's Encrypt. Resolve the conflict or caddy will not start."
    fi
  done
  install_caddy
  CADDYFILE="/etc/caddy/Caddyfile"
  BLOCK="$(printf '%s {\n\tencode zstd gzip\n\treverse_proxy 127.0.0.1:%s\n}' \
    "$DOMAIN" "$HTTP_PORT")"
  # Match a site-address line, not just the hostname anywhere — the
  # stock Caddyfile mentions "localhost:8080" in a comment.
  DOMAIN_ESC="$(printf '%s' "$DOMAIN" | sed 's/\./\\./g')"
  if [ -f "$CADDYFILE" ] && grep -qiE "^${DOMAIN_ESC}([[:space:]]|\{)" "$CADDYFILE"; then
    info "keeping existing $CADDYFILE (already serves $DOMAIN)"
  elif [ -f "$CADDYFILE" ] && ! grep -q '/usr/share/caddy' "$CADDYFILE"; then
    # Real user config — append our site block, don't clobber it.
    printf '\n%s\n' "$BLOCK" >> "$CADDYFILE"
    info "appended $DOMAIN site to $CADDYFILE"
  else
    # Absent, or the untouched package placeholder (stock file serves
    # /usr/share/caddy on :80) — safe to write fresh.
    mkdir -p /etc/caddy
    printf '# BGFlow — automatic HTTPS via Let'"'"'s Encrypt (caddy renews itself).\n# Needs DNS for %s -> this host and TCP 80+443 reachable.\n%s\n' \
      "$DOMAIN" "$BLOCK" > "$CADDYFILE"
    info "wrote $CADDYFILE"
  fi
  # Pick up the new config if caddy is already running (package
  # postinst may have started it with a placeholder file).
  if [ -d /run/systemd/system ] || [ -d /etc/systemd/system ]; then
    systemctl reload-or-try-restart caddy >/dev/null 2>&1 || true
  fi
fi

# --- systemd -----------------------------------------------------------------
if [ -d /etc/systemd/system ]; then
  cat > /etc/systemd/system/bgflowd.service <<EOF
[Unit]
Description=BGFlow flow analyzer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER_NAME
Group=$USER_NAME
ExecStart=$BINDIR/bgflowd --config $SYSCONFDIR/bgflow.toml
Restart=on-failure
RestartSec=5
# SIGHUP reloads rules/enrichers/users/alerts without dropping ingest.
ExecReload=/bin/kill -HUP \$MAINPID
LimitNOFILE=1048576
# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$DATADIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  info "installed systemd unit bgflowd.service"
else
  info "no systemd detected — run: $BINDIR/bgflowd --config $SYSCONFDIR/bgflow.toml"
fi

# --- optional first start -----------------------------------------------------
if [ "$START" = "1" ] && [ -d /etc/systemd/system ]; then
  systemctl enable bgflowd >/dev/null 2>&1 || true
  if [ -n "$DOMAIN" ]; then
    systemctl enable caddy >/dev/null 2>&1 || true
  fi
  systemctl restart bgflowd
  if [ -n "$DOMAIN" ]; then
    systemctl restart caddy || true
  fi
  # Wait for the health endpoint (unauthenticated) — up to ~15s.
  HCURL="http://127.0.0.1:$HTTP_PORT/api/v1/health"
  [ "$SCHEME" = "https" ] && HCURL="https://127.0.0.1:$HTTP_PORT/api/v1/health"
  i=0
  while [ $i -lt 30 ]; do
    if curl -fsSk --max-time 2 "$HCURL" >/dev/null 2>&1; then
      info "bgflowd is up — health check passed"
      break
    fi
    i=$((i+1)); sleep 0.5
  done
  if [ $i -ge 30 ]; then
    info "warn: health check timed out — check: journalctl -u bgflowd -n 50"
  fi
fi

# --- validate + first-run summary --------------------------------------------
if "$BINDIR/bgflowd" --config "$SYSCONFDIR/bgflow.toml" config-check >/dev/null 2>&1; then
  info "config-check passed"
else
  info "warn: config-check reported issues — run: $BINDIR/bgflowd --config $SYSCONFDIR/bgflow.toml config-check"
fi

cat <<EOF

┌──────────────────────────────────────────────────────────────┐
│  BGFlow $VERSION installed                                    │
├──────────────────────────────────────────────────────────────┤
EOF
if [ -n "$DOMAIN" ]; then
cat <<EOF
│  UI:        https://$DOMAIN  (Caddy → 127.0.0.1:$HTTP_PORT)      │
│  Login:     $ADMIN_USER / ${ADMIN_PASS:-<existing password>}                │
│  Config:    $SYSCONFDIR/bgflow.toml                             │
│  Caddyfile: /etc/caddy/Caddyfile                                │
│  Data:      $DATADIR                                            │
│  Services:  systemctl enable --now bgflowd caddy               │
├──────────────────────────────────────────────────────────────┤
│  Flow ingest:  UDP 2055 (auto: NFv5/v9, IPFIX, sFlow)          │
│                TCP 4739 (IPFIX)                                │
│                                                              │
│  TLS:        Caddy + Let's Encrypt — auto-issued & renewed.   │
│              PREREQUISITES: DNS for $DOMAIN must point here,    │
│              and TCP 80+443 must be reachable from the internet│
│              (first cert issuance can take a few minutes).     │
│  Firewall: open TCP 80+443 (Caddy) + UDP 2055 + TCP 4739.      │
EOF
else
cat <<EOF
│  UI:        $SCHEME://<this-host>:$HTTP_PORT                    │
│  Login:     $ADMIN_USER / ${ADMIN_PASS:-<existing password>}                │
│  Config:    $SYSCONFDIR/bgflow.toml                             │
│  Data:      $DATADIR                                            │
│  Service:   systemctl enable --now bgflowd                     │
├──────────────────────────────────────────────────────────────┤
│  Flow ingest:  UDP 2055 (auto: NFv5/v9, IPFIX, sFlow)          │
│                TCP 4739 (IPFIX)                                │
│                                                              │
│  Most settings are editable live in the UI → Settings.        │
│  Firewall: open UDP 2055 + TCP 4739 from your exporters,      │
│  and $HTTP_PORT for the UI if remote.                           │
EOF
fi
cat <<EOF
└──────────────────────────────────────────────────────────────┘
EOF
if [ -n "$DOMAIN" ]; then
  info "first https visit may take a moment while caddy issues the cert — check: journalctl -u caddy -n 50"
fi
if [ -n "$ADMIN_PASS" ]; then
  info "save the admin password somewhere safe — it is not stored anywhere"
fi
