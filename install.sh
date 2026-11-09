#!/bin/sh
# BGFlow installer — installs bgflowd binary + systemd unit + config.
# Usage: curl -fsSL .../install.sh | sudo sh
#        sh install.sh [--version vX.Y.Z] [--prefix /usr/local]
set -eu

REPO="XodoTechnology/BGFlow"
VERSION="${BGFLOW_VERSION:-latest}"
PREFIX="${BGFLOW_INSTALL_DIR:-/usr/local}"
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
URL="https://github.com/$REPO/releases/download/$VERSION/$TARBALL"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

info "downloading $URL"
curl -fsSL "$URL" -o "$TMP/$TARBALL" || \
  die "download failed — if this is a source-only release, build with: cargo build --release -p bgflowd"
tar -xzf "$TMP/$TARBALL" -C "$TMP"

# --- install binary ----------------------------------------------------------
mkdir -p "$BINDIR" "$SYSCONFDIR" "$DATADIR"
install -m 0755 "$TMP/bgflowd" "$BINDIR/bgflowd"
info "installed $BINDIR/bgflowd"

# --- user --------------------------------------------------------------------
if ! id "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --home "$DATADIR" --shell /usr/sbin/nologin "$USER_NAME" 2>/dev/null \
    || useradd --system --home "$DATADIR" --shell /sbin/nologin "$USER_NAME"
fi
chown -R "$USER_NAME:$USER_NAME" "$DATADIR"

# --- config ------------------------------------------------------------------
if [ ! -f "$SYSCONFDIR/bgflow.toml" ]; then
  cat > "$SYSCONFDIR/bgflow.toml" <<EOF
[server]
http_listen = "0.0.0.0:8080"

[storage]
data_dir = "$DATADIR"
raw_retention_days = 7
rollup_retention_days = 90

[[inputs]]
listen = "0.0.0.0:2055"
protocol = "auto"

# See bgflow.example.toml for enrichers/rules/geoip options.
EOF
  chmod 0640 "$SYSCONFDIR/bgflow.toml"
  chown root:"$USER_NAME" "$SYSCONFDIR/bgflow.toml" 2>/dev/null || true
  info "wrote $SYSCONFDIR/bgflow.toml"
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
  info "start with: systemctl enable --now bgflowd"
else
  info "no systemd detected — run: $BINDIR/bgflowd --config $SYSCONFDIR/bgflow.toml"
fi

info "done. UI will be at http://<host>:8080 once started."
