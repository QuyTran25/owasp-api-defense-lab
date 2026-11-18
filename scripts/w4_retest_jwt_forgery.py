#!/usr/bin/env python3
"""Re-test the W2 forged-admin JWT scenario against State B through Kong.

The test intentionally signs an admin-looking HS256 JWT with a local dummy
secret, never with the runtime secret. Kong must reject it before VAmPI. A
normal attacker login and /me call prove that valid traffic still works.

Example:
    python3 scripts/w4_retest_jwt_forgery.py --api http://192.168.42.130:8000
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


class RetestFailure(RuntimeError):
    """Raised when a re-test expectation is not met."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="W4 forged-JWT re-test through Kong State B.")
    parser.add_argument("--api", required=True, help="Kong proxy URL, e.g. http://192.168.42.130:8000")
    parser.add_argument("--attacker", default="attacker", help="Existing non-admin account for valid-flow check.")
    parser.add_argument(
        "--issuer", default="vampi-state-b", help="Expected JWT issuer / Kong credential key (not secret)."
    )
    parser.add_argument(
        "--evidence-dir", default="evidence/retest/jwt-auth", help="Local directory for sanitized result JSON."
    )
    parser.add_argument("--non-interactive", action="store_true", help="Require W4_ATTACKER_PASSWORD.")
    return parser.parse_args()


def read_password(non_interactive: bool) -> str:
    value = os.getenv("W4_ATTACKER_PASSWORD")
    if value:
        return value
    if non_interactive:
        raise RetestFailure("Missing required environment variable W4_ATTACKER_PASSWORD.")
    value = getpass.getpass("Current password for attacker: ")
    if not value:
        raise RetestFailure("A required password was empty.")
    return value


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def forged_token(issuer: str, subject: str) -> str:
    """Create a validly formatted but deliberately wrongly signed admin JWT."""
    now = int(time.time())
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
    payload = b64url(
        json.dumps(
            {"iss": issuer, "sub": subject, "admin": True, "iat": now, "exp": now + 300},
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    # This is a fixed test value, explicitly not the runtime JWT secret.
    signature = b64url(hmac.new(b"W4-local-dummy-secret-not-runtime", signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def with_probe(api: str, path: str, probe: str) -> str:
    parsed = urlparse(api.rstrip("/") + path)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["probe"] = probe
    return urlunparse(parsed._replace(query=urlencode(query)))


def request_json(
    api: str, method: str, path: str, probe: str, token: str | None = None, payload: dict[str, Any] | None = None
) -> tuple[int, Any]:
    headers = {"Accept": "application/json"}
    body = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    request = Request(with_probe(api, path, probe), data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=15) as response:
            raw = response.read().decode("utf-8", errors="replace")
            status = response.status
    except HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        status = error.code
    except URLError as error:
        raise RetestFailure(f"Cannot reach Kong proxy: {error.reason}") from error
    try:
        return status, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return status, None


def add_result(results: list[dict[str, Any]], name: str, expected: str, actual: str, passed: bool) -> None:
    results.append({"name": name, "expected": expected, "actual": actual, "passed": passed})
    marker = "PASS" if passed else "FAIL"
    print(f"[{marker}] {name}: {actual} (expected {expected})")
    if not passed:
        raise RetestFailure(f"{name}: expected {expected}, got {actual}.")


def write_evidence(destination: Path, payload: dict[str, Any]) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / f"w4-retest-jwt-forgery-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


def main() -> int:
    args = parse_args()
    api = args.api.rstrip("/")
    started_at = datetime.now(timezone.utc)
    probe_prefix = f"w4jwtforge-{started_at.strftime('%Y%m%d-%H%M%S')}"
    results: list[dict[str, Any]] = []
    outcome = "FAIL"
    return_code = 1

    try:
        attacker_password = read_password(args.non_interactive)
        login_status, login_body = request_json(
            api,
            "POST",
            "/users/v1/login",
            f"{probe_prefix}-valid-login",
            payload={"username": args.attacker, "password": attacker_password},
        )
        valid_token = login_body.get("auth_token") if isinstance(login_body, dict) else None
        add_result(
            results,
            "Valid attacker login",
            "HTTP 200 with auth_token",
            f"HTTP {login_status}",
            login_status == 200 and isinstance(valid_token, str) and bool(valid_token),
        )

        status, _ = request_json(api, "GET", "/me", f"{probe_prefix}-valid-me", valid_token)
        add_result(results, "Valid JWT reaches protected route", "HTTP 200", f"HTTP {status}", status == 200)

        status, _ = request_json(api, "GET", "/users/v1", f"{probe_prefix}-no-token")
        add_result(results, "No JWT rejected at gateway", "HTTP 401", f"HTTP {status}", status == 401)

        wrong_token = forged_token(args.issuer, args.attacker)
        status, _ = request_json(api, "GET", "/users/v1", f"{probe_prefix}-forged-admin", wrong_token)
        add_result(
            results,
            "Forged admin JWT with dummy secret rejected at gateway",
            "HTTP 401",
            f"HTTP {status}",
            status == 401,
        )

        outcome = "PASS"
        return_code = 0
        print("\nW4-RETEST-JWT-A: PASS")
        print(f"Probe prefix for Ubuntu logs: {probe_prefix}")
    except RetestFailure as exc:
        print(f"\nW4-RETEST-JWT-A: FAIL - {exc}", file=sys.stderr)
    finally:
        evidence = {
            "task": "W4-RETEST-JWT-A",
            "outcome": outcome,
            "started_at_utc": started_at.isoformat(),
            "api": api,
            "probe_prefix": probe_prefix,
            "expected": {"valid_jwt": 200, "no_jwt": 401, "forged_admin_jwt": 401},
            "results": results,
            "note": (
                "Sanitized evidence: forged token was signed with a local dummy secret; no runtime secret, "
                "password, JWT value, or response body is recorded."
            ),
        }
        output = write_evidence(Path(args.evidence_dir), evidence)
        print(f"Sanitized evidence saved: {output}")
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
