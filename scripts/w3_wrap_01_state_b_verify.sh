#!/usr/bin/env bash
# Verify that the currently running Ubuntu deployment is State B.
# Run on Ubuntu after the VAmPI and Kong containers are started.
# The evidence file contains only status/configuration facts; it never prints
# runtime secrets, JWTs, database records, or the declarative config content.

set -euo pipefail

STATE_DIR="${STATE_DIR:-$PWD/.state-b}"
EVIDENCE_DIR="${EVIDENCE_DIR:-$STATE_DIR/evidence}"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
EVIDENCE="$EVIDENCE_DIR/w3-wrap-01-$STAMP.txt"

mkdir -p "$EVIDENCE_DIR"
chmod 700 "$STATE_DIR" "$EVIDENCE_DIR" 2>/dev/null || true

pass_count=0

pass() {
  printf 'PASS: %s\n' "$1"
  pass_count=$((pass_count + 1))
}

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

require_container() {
  local name="$1"
  [[ "$(docker inspect --format '{{.State.Running}}' "$name" 2>/dev/null || true)" == "true" ]] \
    || fail "container $name is not running"
  pass "container $name is running"
}

require_plugin() {
  local plugin="$1"
  grep -Fxq "$plugin" <<<"$active_plugins" || fail "Kong plugin $plugin is absent from active config"
  pass "Kong plugin $plugin is active"
}

{
  echo '=== W3-WRAP-01 State B verification ==='
  date --iso-8601=seconds
  echo

  require_container vampi
  require_container kong-gateway

  echo
  echo '=== Topology and published ports ==='
  vampi_networks="$(docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}' vampi)"
  kong_networks="$(docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}' kong-gateway)"
  [[ "$vampi_networks" == *'lab-net'* ]] || fail 'VAmPI is not connected to lab-net'
  [[ "$kong_networks" == *'lab-net'* ]] || fail 'Kong is not connected to lab-net'
  pass 'VAmPI and Kong share the internal lab-net network'

  vampi_ports="$(docker port vampi 2>/dev/null || true)"
  [[ -z "$vampi_ports" ]] || fail 'VAmPI publishes a host port'
  pass 'VAmPI publishes no host port'

  kong_ports="$(docker port kong-gateway)"
  printf '%s\n' "$kong_ports"
  grep -q '^8000/tcp -> ' <<<"$kong_ports" || fail 'Kong proxy port 8000 is not published'
  ! grep -Eq '(^8001/tcp|:8001)' <<<"$kong_ports" || fail 'Kong Admin API port 8001 is published'
  pass 'only Kong proxy port 8000 is published'

  direct_status="$(curl --max-time 3 -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:5000/ || true)"
  [[ "$direct_status" == '000' ]] || fail "direct host access to VAmPI returned HTTP $direct_status"
  pass 'direct host access to VAmPI port 5000 is unavailable'

  proxy_status="$(curl --max-time 5 -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/ || true)"
  [[ "$proxy_status" == '401' ]] || fail "Kong protected root expected 401 without JWT, got HTTP $proxy_status"
  pass 'Kong proxy responds and enforces JWT on protected root'

  echo
  echo '=== Active Kong controls ==='
  docker exec kong-gateway kong config parse /etc/kong/kong.yml >/dev/null
  pass 'active Kong declarative config parses successfully'
  active_plugins="$(docker exec kong-gateway sh -c "awk '/^[[:space:]]*-[[:space:]]+name:[[:space:]]+(jwt|acl|rate-limiting)[[:space:]]*$/{print \$3}' /etc/kong/kong.yml | sort -u")"
  printf 'Active security plugins: %s\n' "$(tr '\n' ' ' <<<"$active_plugins")"
  require_plugin jwt
  require_plugin acl
  require_plugin rate-limiting

  echo
  echo '=== Active backend controls ==='
  backend_output="$(docker exec -i vampi python - <<'PY'
from pathlib import Path
import sqlite3

checks = {
    'BOLA ownership query': ('/vampi/api_views/books.py', 'user_id=user.id'),
    'DB-backed authorization helper': ('/vampi/api_views/users.py', 'def get_authenticated_user'),
    'token-version comparison': ('/vampi/api_views/users.py', 'token_version != user.token_version'),
    'retired debug route handling': ('/vampi/api_views/users.py', "username == '_debug'"),
    'profile DTO whitelist': ('/vampi/models/user_model.py', 'def profile_dto'),
}
for label, (filename, needle) in checks.items():
    if needle not in Path(filename).read_text(encoding='utf-8'):
        raise SystemExit(f'FAIL: active backend missing {label}')
    print(f'PASS: active backend has {label}')

spec = Path('/vampi/openapi_specs/openapi3.yml').read_text(encoding='utf-8')
for retired in ('/users/v1/_debug:', '/createdb:'):
    if retired in spec:
        raise SystemExit(f'FAIL: retired OpenAPI path remains: {retired}')
print('PASS: retired debug/reset paths are absent from active OpenAPI')

db = sqlite3.connect('/vampi/database/database.db')
columns = {row[1] for row in db.execute('PRAGMA table_info(users)')}
if 'token_version' not in columns:
    raise SystemExit('FAIL: active SQLite users table lacks token_version')
print('PASS: active SQLite users table has token_version')
print(f'__COUNT__={len(checks) + 2}')
PY
)"
  backend_passes="$(sed -n 's/^__COUNT__=//p' <<<"$backend_output")"
  [[ "$backend_passes" =~ ^[0-9]+$ ]] || fail 'could not count active backend checks'
  sed '/^__COUNT__=/d' <<<"$backend_output"
  pass_count=$((pass_count + backend_passes))

  echo
  echo "SUMMARY: PASS ($pass_count assertions)"
  echo "Evidence saved: $EVIDENCE"
} | tee "$EVIDENCE"
