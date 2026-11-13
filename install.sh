#!/bin/sh
# BGFlow installer — installs bgflowd binary + systemd unit + config,
# generates admin credentials, validates the config, prints a summary.
# Usage: curl -fsSL .../install.sh | sudo sh
#        sh install.sh [--version vX.Y.Z] [--prefix /usr/local]
#                       [--http 0.0.0.0:8080] [--admin-user admin] [--demo] [--start]
set -eu

REPO="XodoTechnology/BGFlow"
VERSION="${BGFLOW_VERSION:-latest}"
PREFIX="${BGFLOW_INSTALL_DIR:-/usr/local}"
HTTP_ADDR="0.0.0.0:8080"
DEMO=0
START=0
ADMIN_USER="admin"

# --- args --------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --prefix)  PREFIX="$2";  shift 2 ;;
    --prefix=*) PREFIX="${1#*=}"; shift ;;
    --http)    HTTP_ADDR="$2"; shift 2 ;;
    --http=*)  HTTP_ADDR="${1#*=}"; shift ;;
    --admin-user) ADMIN_USER="$2"; shift 2 ;;
    --admin-user=*) ADMIN_USER="${1#*=}"; shift ;;
    --demo)    DEMO=1; shift ;;
    --start)   START=1; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Values land inside a TOML file — reject anything that could break
# out of the string literal.
case "$ADMIN_USER" in
  *[!A-Za-z0-9_.-]*|"") die "--admin-user must be [A-Za-z0-9_.-]+" ;;
esac
case "$HTTP_ADDR" in
  *[\"\\\`\$]*) die "--http contains unsafe characters" ;;
esac
HTTP_PORT="${HTTP_ADDR##*:}"

BINDIR="$PREFIX/bin"
SYSCONFDIR="/etc/bgflow"
DATADIR="/var/lib/bgflow"
USER_NAME="bgflow"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

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

  cat > "$SYSCONFDIR/bgflow.toml" <<EOF
[server]
http_listen = "$HTTP_ADDR"

[storage]
data_dir = "$DATADIR"
raw_retention_days = 7
rollup_retention_days = 90

[[inputs]]
listen = "0.0.0.0:2055"
protocol = "auto"

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

# Everything else (retention, disk cap, SNMP, names, rules, users) is
# editable live in the UI under Settings — no restart needed for most.
EOF
  chmod 0640 "$SYSCONFDIR/bgflow.toml"
  chown root:"$USER_NAME" "$SYSCONFDIR/bgflow.toml" 2>/dev/null || true
  info "wrote $SYSCONFDIR/bgflow.toml"
else
  info "keeping existing $SYSCONFDIR/bgflow.toml"
  ADMIN_PASS=""
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
  systemctl restart bgflowd
  # Wait for the health endpoint (unauthenticated) — up to ~15s.
  i=0
  while [ $i -lt 30 ]; do
    if curl -fsS --max-time 2 "http://127.0.0.1:$HTTP_PORT/api/v1/health" >/dev/null 2>&1; then
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
│  UI:        http://<this-host>:$HTTP_PORT                      │
│  Login:     $ADMIN_USER / ${ADMIN_PASS:-<existing password>}                │
│  Config:    $SYSCONFDIR/bgflow.toml                             │
│  Data:      $DATADIR                                            │
│  Service:   systemctl enable --now bgflowd                     │
├──────────────────────────────────────────────────────────────┤
│  Flow ingest:  UDP 2055 (auto: NFv5/v9, IPFIX, sFlow)          │
│                TCP 4739 (IPFIX) — add [[inputs]] as needed     │
│                                                              │
│  Most settings are editable live in the UI → Settings.        │
│  Firewall: open UDP 2055 (+ TCP 4739) from your exporters,    │
│  and $HTTP_PORT for the UI if remote.                           │
│                                                              │
│  Auth is on but TLS is off — put it behind a TLS reverse      │
│  proxy or set server.tls_cert/tls_key before exposing it.     │
└──────────────────────────────────────────────────────────────┘
EOF
if [ -n "$ADMIN_PASS" ]; then
  info "save the admin password somewhere safe — it is not stored anywhere"
fi
