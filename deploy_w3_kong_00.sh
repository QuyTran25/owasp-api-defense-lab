#!/usr/bin/env bash
# Deploy only W3-KONG-00: isolate VAmPI behind Kong without enabling plugins.
# An explicit flag is required because the previous VAmPI container contains the
# fixed W2 victim/attacker SQLite dataset. The script backs it up before removal.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${STATE_DIR:-$PROJECT_DIR/.state-b}"
VAMPI_CONTAINER="${VAMPI_CONTAINER:-vampi}"
KONG_CONTAINER="${KONG_CONTAINER:-kong-gateway}"
VAMPI_IMAGE="${VAMPI_IMAGE:-vampi:latest}"
NETWORK="${NETWORK:-lab-net}"

if [[ "${1:-}" != "--replace-containers" ]]; then
  echo "Review the database backup, then run: bash deploy_w3_kong_00.sh --replace-containers"
  exit 1
fi

mkdir -p "$STATE_DIR/database" "$STATE_DIR/backups" "$STATE_DIR/evidence"
chmod 700 "$STATE_DIR"

if docker inspect "$VAMPI_CONTAINER" >/dev/null 2>&1; then
  # Stop first so a SQLite file is never copied while VAmPI is writing it.
  docker stop "$VAMPI_CONTAINER" >/dev/null 2>&1 || true
  backup="$STATE_DIR/backups/database-$(date +%Y%m%d-%H%M%S).db"
  docker cp "$VAMPI_CONTAINER:/vampi/database/database.db" "$backup"
  cp "$backup" "$STATE_DIR/database/database.db"
  echo "Backed up the W2 database to $backup"
  docker rm "$VAMPI_CONTAINER" >/dev/null
elif [[ ! -f "$STATE_DIR/database/database.db" ]]; then
  echo "No VAmPI container or preserved database exists; refusing to create an empty lab."
  exit 1
fi

docker image inspect "$VAMPI_IMAGE" >/dev/null
docker image inspect kong:3.9.1 >/dev/null
docker network inspect "$NETWORK" >/dev/null 2>&1 || docker network create "$NETWORK" >/dev/null

docker run -d --name "$VAMPI_CONTAINER" \
  --network "$NETWORK" \
  -e vulnerable=1 \
  -v "$STATE_DIR/database:/vampi/database" \
  "$VAMPI_IMAGE" >/dev/null

docker rm -f "$KONG_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$KONG_CONTAINER" \
  --network "$NETWORK" \
  -p 8000:8000 \
  -e KONG_DATABASE=off \
  -e KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yml \
  -e KONG_PROXY_ACCESS_LOG=/dev/stdout \
  -e KONG_PROXY_ERROR_LOG=/dev/stderr \
  -e KONG_ADMIN_LISTEN=127.0.0.1:8001 \
  -v "$PROJECT_DIR/kong/kong.state-a.yml:/etc/kong/kong.yml:ro" \
  kong:3.9.1 >/dev/null

sleep 3
evidence="$STATE_DIR/evidence/w3-kong-00-host-$(date +%Y%m%d-%H%M%S).txt"
{
  echo "W3-KONG-00 host topology evidence"
  date --iso-8601=seconds
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
  echo
  echo "VAmPI published ports (must be empty):"
  docker port "$VAMPI_CONTAINER" || true
  echo
  echo "Kong published ports (must contain only 8000):"
  docker port "$KONG_CONTAINER"
  echo
  printf 'Kong proxy HTTP status: '
  curl --max-time 5 -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/
} | tee "$evidence"

echo "W3-KONG-00 deployed. Evidence saved to $evidence"
echo "Next: from Kali, verify :5000 fails and Kong :8000 succeeds; save a screenshot."
