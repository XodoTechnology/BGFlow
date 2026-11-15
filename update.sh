#!/bin/sh
# BGFlow Docker updater — pull a new image and recreate the deployment,
# preserving the data volume. Detects docker compose automatically.
#
# Usage:
#   sh update.sh [tag]        # e.g. sh update.sh 0.2.0 (default: latest)
#
# Env overrides:
#   BGFLOW_IMAGE   full image ref (default ghcr.io/xodotechnology/bgflow)
#   COMPOSE_FILE   alternate compose file
#
# For bare-metal installs, re-run install.sh --version <tag> instead.
set -eu

IMAGE_REPO="${BGFLOW_IMAGE:-ghcr.io/xodotechnology/bgflow}"
TAG="${1:-${BGFLOW_TAG:-latest}}"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found"

# --- docker compose path -----------------------------------------------------
COMPOSE_FILES=""
for f in "${COMPOSE_FILE:-}" docker-compose.yml compose.yml docker-compose.yaml compose.yaml; do
  [ -n "$f" ] && [ -f "$f" ] && COMPOSE_FILES="$f" && break
done

if [ -n "$COMPOSE_FILES" ] && docker compose version >/dev/null 2>&1; then
  info "compose project found ($COMPOSE_FILES) — updating to $IMAGE_REPO:$TAG"
  BGFLOW_TAG="$TAG" docker compose -f "$COMPOSE_FILES" pull
  BGFLOW_TAG="$TAG" docker compose -f "$COMPOSE_FILES" up -d

  # Wait for the container healthcheck (image HEALTHCHECK, ~45s max).
  CID="$(docker compose -f "$COMPOSE_FILES" ps -q bgflowd 2>/dev/null | head -1)"
  if [ -n "$CID" ]; then
    i=0
    while [ $i -lt 30 ]; do
      H="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CID" 2>/dev/null || echo unknown)"
      [ "$H" = "healthy" ] && { info "bgflowd is healthy"; break; }
      [ "$H" = "unhealthy" ] && { info "warn: healthcheck reports unhealthy — check: docker logs $CID"; break; }
      i=$((i+1)); sleep 3
    done
    [ "$i" -ge 30 ] && info "warn: still starting after 90s — check: docker logs $CID"
  fi
  info "done — UI on the published port (default :8080)"
  exit 0
fi

# --- plain docker path --------------------------------------------------------
CID="$(docker ps -aq --filter 'name=^/bgflow' --filter 'name=^/bgflowd' | head -1)"
if [ -n "$CID" ]; then
  die "found container $CID but no compose file — recreate it manually:
       docker pull $IMAGE_REPO:$TAG
       docker stop $CID && docker rm $CID
       docker run -d --name bgflowd --restart unless-stopped \\
         -p 8080:8080 -p 2055:2055/udp -p 4739:4739 \\
         -v bgflow-data:/var/lib/bgflow \\
         -e BGFLOW_ADMIN_PASSWORD=\\$BGFLOW_ADMIN_PASSWORD \\
         $IMAGE_REPO:$TAG"
fi

die "no docker compose project or bgflow container found here — nothing to update"
