#!/usr/bin/env bash
# Collect sanitized, structured State B runtime evidence on the Ubuntu host.
#
# This script never reads .env.state-b, the SQLite database, container
# environment variables, request bodies, or Authorization headers.  The only
# Kong configuration copy it writes has every `secret:` value redacted.
#
# Typical use (run after a Kali regression run):
#   bash scripts/w3_wrap_03_collect_ubuntu_evidence.sh \
#     --since '2026-11-18T04:00:00Z' --probe w3backend05-20261118-040010

set -euo pipefail

STATE_DIR="${STATE_DIR:-$PWD/.state-b}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-$STATE_DIR/evidence/w3-wrap-03}"
SINCE='30 minutes ago'
PROBE=''

usage() {
  cat <<'EOF'
Usage: bash scripts/w3_wrap_03_collect_ubuntu_evidence.sh [options]

Options:
  --since VALUE   Timestamp accepted by `docker logs --since` (recommended:
                  UTC start time recorded immediately before the Kali test).
  --probe VALUE   Regression probe prefix.  Adds a concise routing summary
                  showing which matching requests reached Kong and VAmPI.
  -h, --help      Show this help text.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --since)
      [[ $# -ge 2 ]] || { echo 'Missing value after --since' >&2; exit 2; }
      SINCE="$2"
      shift 2
      ;;
    --probe)
      [[ $# -ge 2 ]] || { echo 'Missing value after --probe' >&2; exit 2; }
      PROBE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_running() {
  [[ "$(docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null || true)" == 'true' ]] \
    || { echo "Required running container is absent: $1" >&2; exit 1; }
}

sanitize() {
  # Defence in depth: default logs do not contain these values, but redact any
  # accidental header/config secret before it reaches an evidence file.
  sed -E \
    -e 's/^([[:space:]]*secret:[[:space:]]*).*/\1<redacted>/I' \
    -e 's/(Authorization:[[:space:]]*Bearer)[[:space:]]+[^[:space:]]+/\1 <redacted>/Ig' \
    -e 's/(VAMPI_JWT_SECRET=)[^[:space:]]+/\1<redacted>/Ig'
}

require_running vampi
require_running kong-gateway

STAMP="$(date -u +%Y%m%d-%H%M%S)"
OUT="$EVIDENCE_ROOT/ubuntu-$STAMP"
mkdir -p "$OUT"
chmod 700 "$STATE_DIR" "$EVIDENCE_ROOT" "$OUT" 2>/dev/null || true

CONFIG="$OUT/kong-active-sanitized.yml"
SUMMARY="$OUT/runtime-summary.txt"
KONG_LOG="$OUT/kong-access.log"
VAMPI_LOG="$OUT/vampi.log"
ROUTING="$OUT/probe-routing-summary.txt"

# Do not first write an unredacted temporary file.  The stream is redacted
# before it is persisted on disk.
docker exec kong-gateway sh -c 'cat /etc/kong/kong.yml' | sanitize > "$CONFIG"

{
  echo '=== W3-WRAP-03 State B runtime snapshot ==='
  echo "collected_at_utc=$(date -u --iso-8601=seconds)"
  echo "logs_since=$SINCE"
  echo "probe_prefix=${PROBE:-not-specified}"
  echo
  echo '=== Running containers ==='
  docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
  echo
  echo '=== Published host ports ==='
  echo 'VAmPI (expected: none):'
  docker port vampi 2>/dev/null || true
  echo 'Kong (expected: proxy 8000 only):'
  docker port kong-gateway
  echo
  echo '=== Active security plugins (names only) ==='
  awk '/^[[:space:]]*-[[:space:]]+name:[[:space:]]+(jwt|acl|rate-limiting)[[:space:]]*$/{print $3}' "$CONFIG" | sort -u
  echo
  echo '=== Sanitization policy ==='
  echo 'Raw JWTs, passwords, request bodies, database data, and secret values are excluded.'
} > "$SUMMARY"

docker logs --since "$SINCE" kong-gateway 2>&1 | sanitize > "$KONG_LOG"
docker logs --since "$SINCE" vampi 2>&1 | sanitize > "$VAMPI_LOG"

{
  echo '=== W3-WRAP-03 probe routing summary ==='
  echo "probe_prefix=${PROBE:-not-specified}"
  if [[ -z "$PROBE" ]]; then
    echo 'No --probe value was supplied; inspect the two logs manually.'
  else
    echo
    echo '=== Matching Kong log lines ==='
    grep -F "$PROBE" "$KONG_LOG" || echo 'No matching Kong lines found.'
    echo
    echo '=== Matching VAmPI log lines ==='
    grep -F "$PROBE" "$VAMPI_LOG" || echo 'No matching VAmPI lines found.'
    echo
    echo 'Interpretation:'
    echo '- Present in Kong but absent in VAmPI: Kong rejected it before backend.'
    echo '- Present in both logs: request reached backend; use HTTP status and test assertion to identify backend enforcement.'
  fi
} > "$ROUTING"

(cd "$OUT" && sha256sum kong-active-sanitized.yml runtime-summary.txt kong-access.log vampi.log probe-routing-summary.txt > SHA256SUMS)
chmod 600 "$OUT"/*

printf 'W3-WRAP-03 Ubuntu evidence saved: %s\n' "$OUT"
printf 'Files: kong-active-sanitized.yml, runtime-summary.txt, kong-access.log, vampi.log, probe-routing-summary.txt, SHA256SUMS\n'
