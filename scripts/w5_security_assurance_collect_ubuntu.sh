#!/usr/bin/env bash
# Collect only sanitized, scoped Ubuntu evidence for a W5 assurance session.
# Run on the Ubuntu host after w5_security_assurance_kali.py has completed.

set -euo pipefail

STATE_DIR="${STATE_DIR:-$PWD/.state-b}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-$STATE_DIR/evidence/assurance}"
SINCE=''
PROBES=()

usage() {
  cat <<'EOF'
Usage: bash scripts/w5_security_assurance_collect_ubuntu.sh --since UTC [--probe PREFIX]...

Required:
  --since UTC       UTC start timestamp printed by the Kali assurance manifest.
  --probe PREFIX    A probe prefix printed by the Kali assurance runner. Repeat for every test.

This script never reads .env.state-b, SQLite data, request bodies, passwords,
JWTs, or unredacted Authorization headers.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --since) [[ $# -ge 2 ]] || { echo 'Missing --since value' >&2; exit 2; }; SINCE="$2"; shift 2 ;;
    --probe) [[ $# -ge 2 ]] || { echo 'Missing --probe value' >&2; exit 2; }; PROBES+=("$2"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$SINCE" ]] || { echo '--since is required' >&2; exit 2; }
[[ ${#PROBES[@]} -gt 0 ]] || { echo 'At least one --probe is required' >&2; exit 2; }

require_running() {
  [[ "$(docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null || true)" == 'true' ]] \
    || { echo "Required running container is absent: $1" >&2; exit 1; }
}

sanitize() {
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

KONG_LOG="$OUT/kong.log"
VAMPI_LOG="$OUT/vampi.log"
CONFIG="$OUT/kong-active-sanitized.yml"
VAMPI_PORTS="$OUT/vampi-ports.txt"
KONG_PORTS="$OUT/kong-ports.txt"
PLUGINS="$OUT/kong-plugins.txt"
RUNTIME="$OUT/runtime-assertions.json"
PROBE_LIST="$OUT/probes.txt"

printf '%s\n' "${PROBES[@]}" > "$PROBE_LIST"
docker logs --since "$SINCE" kong-gateway 2>&1 | sanitize > "$KONG_LOG"
docker logs --since "$SINCE" vampi 2>&1 | sanitize > "$VAMPI_LOG"
docker exec kong-gateway sh -c 'cat /etc/kong/kong.yml' | sanitize > "$CONFIG"
(docker port vampi 2>/dev/null || true) > "$VAMPI_PORTS"
docker port kong-gateway > "$KONG_PORTS"
awk '/^[[:space:]]*-[[:space:]]+name:[[:space:]]+(jwt|acl|rate-limiting)[[:space:]]*$/{print $3}' "$CONFIG" | sort -u > "$PLUGINS"

python3 - "$VAMPI_PORTS" "$KONG_PORTS" "$PLUGINS" "$RUNTIME" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

vampi_ports = Path(sys.argv[1]).read_text(encoding="utf-8").strip()
kong_ports = Path(sys.argv[2]).read_text(encoding="utf-8")
plugins = set(Path(sys.argv[3]).read_text(encoding="utf-8").split())
results = [
    {
        "id": "VAMPI-NO-HOST-PORT",
        "expected": "no published host port",
        "actual": "none" if not vampi_ports else "published host port detected",
        "passed": not bool(vampi_ports),
    },
    {
        "id": "KONG-PROXY-8000-ONLY",
        "expected": "proxy port 8000 published; admin port 8001 not published",
        "actual": "kong port mapping inspected",
        "passed": (":8000" in kong_ports or "-> 8000" in kong_ports) and ":8001" not in kong_ports,
    },
    {
        "id": "KONG-SECURITY-PLUGINS",
        "expected": "jwt, acl, rate-limiting active",
        "actual": ",".join(sorted(plugins)) or "none",
        "passed": {"jwt", "acl", "rate-limiting"}.issubset(plugins),
    },
]
payload = {
    "task": "W5-SECURITY-ASSURANCE-UBUNTU",
    "collected_at_utc": datetime.now(timezone.utc).isoformat(),
    "results": results,
    "note": "Runtime assertions contain no secrets, database data, JWTs, passwords, or Authorization values.",
}
Path(sys.argv[4]).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

{
  echo '=== W5 security assurance routing evidence ==='
  echo "collected_at_utc=$(date -u --iso-8601=seconds)"
  echo "logs_since=$SINCE"
  echo
  for probe in "${PROBES[@]}"; do
    echo "=== Probe: $probe ==="
    echo 'Kong lines:'
    grep -F "$probe" "$KONG_LOG" || echo 'ABSENT'
    echo 'VAmPI lines:'
    grep -F "$probe" "$VAMPI_LOG" || echo 'ABSENT'
    echo
  done
  echo 'Interpretation:'
  echo '- Kong present and VAmPI absent: gateway enforcement.'
  echo '- Kong and VAmPI present: request reached backend; backend policy must decide.'
} > "$OUT/routing-summary.txt"

(cd "$OUT" && sha256sum kong.log vampi.log kong-active-sanitized.yml runtime-assertions.json probes.txt routing-summary.txt > SHA256SUMS)
chmod 600 "$OUT"/*

printf 'W5 Ubuntu assurance evidence saved: %s\n' "$OUT"
printf 'Copy this folder together with the Kali manifest to one trusted workstation, then run w5_security_assurance_verify.py.\n'
