#!/usr/bin/env bash
# Deploy W3-KONG State B. This script deliberately requires an explicit flag
# before replacing the existing VAmPI container because that container may hold
# the fixed victim/attacker dataset used by the W2 baseline.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${STATE_DIR:-$PROJECT_DIR/.state-b}"
ENV_FILE="${ENV_FILE:-$PROJECT_DIR/.env.state-b}"
VAMPI_CONTAINER="${VAMPI_CONTAINER:-vampi}"
KONG_CONTAINER="${KONG_CONTAINER:-kong-gateway}"
NETWORK="${NETWORK:-lab-net}"
REPLACE_VAMPI=false

if [[ "${1:-}" == "--replace-vampi" ]]; then
  REPLACE_VAMPI=true
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE. Copy .env.state-b.example, set a new secret, then rerun."
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"
: "${VAMPI_JWT_SECRET:?VAMPI_JWT_SECRET is required}"
: "${VAMPI_JWT_ISSUER:=vampi-state-b}"
: "${VAMPI_TOKEN_TTL:=900}"

if [[ "$VAMPI_JWT_SECRET" == REPLACE_WITH_* ]]; then
  echo "Replace the placeholder VAMPI_JWT_SECRET in $ENV_FILE before deployment."
  exit 1
fi
if ! [[ "$VAMPI_JWT_SECRET" =~ ^[A-Za-z0-9_-]{43,}$ ]]; then
  echo "VAMPI_JWT_SECRET must be a Base64URL value of at least 43 characters."
  exit 1
fi
if ! [[ "$VAMPI_JWT_ISSUER" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "VAMPI_JWT_ISSUER may only contain letters, numbers, dot, underscore, and dash."
  exit 1
fi

mkdir -p "$STATE_DIR/database" "$STATE_DIR/backups"
chmod 700 "$STATE_DIR"

sed "s/__VAMPI_JWT_SECRET__/$VAMPI_JWT_SECRET/g" \
  "$PROJECT_DIR/kong/kong.yml" > "$PROJECT_DIR/kong/kong.runtime.yml"
chmod 600 "$PROJECT_DIR/kong/kong.runtime.yml"

# Validate the DB-less file before touching the container that holds W2 data.
docker pull kong:3.9.1
docker run --rm --entrypoint kong \
  -v "$PROJECT_DIR/kong/kong.runtime.yml:/etc/kong/kong.yml:ro" \
  kong:3.9.1 config parse /etc/kong/kong.yml >/dev/null
echo "Kong declarative configuration validated."

if docker inspect "$VAMPI_CONTAINER" >/dev/null 2>&1; then
  if [[ "$REPLACE_VAMPI" != true ]]; then
    echo "Existing $VAMPI_CONTAINER detected. Review the database backup then rerun with --replace-vampi."
    exit 1
  fi
  # Stop first so the SQLite database is not copied while an application write is in flight.
  docker stop "$VAMPI_CONTAINER" >/dev/null
  backup="$STATE_DIR/backups/database-$(date +%Y%m%d-%H%M%S).db"
  docker cp "$VAMPI_CONTAINER:/vampi/database/database.db" "$backup"
  cp "$backup" "$STATE_DIR/database/database.db"
  echo "Saved existing VAmPI database to $backup"
  docker rm -f "$VAMPI_CONTAINER"
elif [[ ! -f "$STATE_DIR/database/database.db" ]]; then
  echo "No existing VAmPI container or preserved database was found. Refusing to create an empty lab."
  echo "Restore a known test database to $STATE_DIR/database/database.db, then rerun."
  exit 1
fi

docker network inspect "$NETWORK" >/dev/null 2>&1 || docker network create "$NETWORK"
docker build -t vampi:state-b "$PROJECT_DIR/VAmPI"

docker run -d --name "$VAMPI_CONTAINER" \
  --network "$NETWORK" \
  -e vulnerable=1 \
  -e tokentimetolive="$VAMPI_TOKEN_TTL" \
  -e VAMPI_JWT_SECRET="$VAMPI_JWT_SECRET" \
  -e VAMPI_JWT_ISSUER="$VAMPI_JWT_ISSUER" \
  -v "$STATE_DIR/database:/vampi/database" \
  vampi:state-b

docker rm -f "$KONG_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$KONG_CONTAINER" \
  --network "$NETWORK" \
  -p 8000:8000 \
  -e KONG_DATABASE=off \
  -e KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yml \
  -e KONG_PROXY_ACCESS_LOG=/dev/stdout \
  -e KONG_PROXY_ERROR_LOG=/dev/stderr \
  -e KONG_ADMIN_LISTEN=127.0.0.1:8001 \
  -v "$PROJECT_DIR/kong/kong.runtime.yml:/etc/kong/kong.yml:ro" \
  kong:3.9.1

echo "State B containers started. Wait for readiness, then run the W3-KONG-03/05 tests from Kali."
echo "Only Kong :8000 is published. VAmPI :5000 and Kong Admin :8001 are not published."
