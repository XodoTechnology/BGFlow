#!/bin/sh
# BGFlow container entrypoint.
#
# Optional first-boot admin bootstrap: when BGFLOW_ADMIN_PASSWORD is set
# and no settings.json exists yet, an admin user is created and persisted
# to <data_dir>/settings.json (survives restarts/recreates of the
# container as long as the data volume does). Afterwards users are
# managed in the UI (Settings → Users) or via the admin API — env vars
# are only read on this first boot.
#
# BGFLOW_ADMIN_USER    — username (default: admin)
# BGFLOW_ADMIN_PASSWORD— password; if unset but BGFLOW_ADMIN_USER is
#                        set, a random one is generated and logged once.
set -eu

DATA_DIR="${BGFLOW_DATA_DIR:-/var/lib/bgflow}"
SETTINGS="$DATA_DIR/settings.json"

bootstrap_admin() {
  [ -f "$SETTINGS" ] && return 0   # already initialized — never clobber
  user="${BGFLOW_ADMIN_USER:-admin}"
  pass="${BGFLOW_ADMIN_PASSWORD:-}"
  generated=0
  if [ -z "$pass" ] && [ -n "${BGFLOW_ADMIN_USER:-}" ]; then
    pass="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)"
    generated=1
  fi
  [ -n "$pass" ] || return 0       # no env auth requested — stay open

  # Validate the username the same way bgflowd does.
  case "$user" in
    *[!A-Za-z0-9_.-]*|"") echo "docker-entrypoint: bad BGFLOW_ADMIN_USER '$user'" >&2; return 1 ;;
  esac

  hash="$(printf '%s' "$pass" | bgflowd hash-password 2>/dev/null | head -1)"
  [ -n "$hash" ] || { echo "docker-entrypoint: hash-password failed" >&2; return 1; }

  # printf args are not re-expanded — the pbkdf2 hash's '$' chars stay literal.
  printf '{"users":[{"name":"%s","password_hash":"%s","role":"admin"}]}\n' \
    "$user" "$hash" > "$SETTINGS"
  chmod 600 "$SETTINGS" 2>/dev/null || true

  echo "docker-entrypoint: created admin user '$user'"
  if [ "$generated" = "1" ]; then
    echo "docker-entrypoint: generated password: $pass"
    echo "docker-entrypoint: save it now — it is not stored anywhere else"
  else
    echo "docker-entrypoint: password taken from BGFLOW_ADMIN_PASSWORD"
  fi
}

bootstrap_admin || echo "docker-entrypoint: admin bootstrap failed — starting anyway" >&2

exec bgflowd --config /etc/bgflow/bgflow.toml "$@"
