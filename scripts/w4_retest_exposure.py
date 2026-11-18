#!/usr/bin/env python3
"""Re-test W2 excessive-data-exposure findings against State B through Kong.

Only HTTP statuses and field names are stored in local evidence.  The script
does not persist profile bodies, JWTs, passwords, or any sensitive values.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


FORBIDDEN = {"password", "admin", "secret", "auth_token", "token"}


class RetestFailure(RuntimeError):
    """Raised when an exposure re-test expectation is not met."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="W4 excessive-data-exposure re-test through Kong State B.")
    parser.add_argument("--api", required=True, help="Kong proxy URL, e.g. http://192.168.42.130:8000")
    parser.add_argument("--attacker", default="attacker", help="Authenticated non-admin account.")
    parser.add_argument("--victim", default="victim", help="Other user whose profile must remain inaccessible.")
    parser.add_argument("--evidence-dir", default="evidence/retest/exposure", help="Local sanitized evidence directory.")
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
    output = destination / f"w4-retest-exposure-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


def main() -> int:
    args = parse_args()
    api = args.api.rstrip("/")
    started_at = datetime.now(timezone.utc)
    probe_prefix = f"w4exposure-{started_at.strftime('%Y%m%d-%H%M%S')}"
    results: list[dict[str, Any]] = []
    outcome = "FAIL"
    return_code = 1

    try:
        password = read_password(args.non_interactive)
        login_status, login_body = request_json(
            api,
            "POST",
            "/users/v1/login",
            f"{probe_prefix}-login",
            payload={"username": args.attacker, "password": password},
        )
        token = login_body.get("auth_token") if isinstance(login_body, dict) else None
        add_result(results, "Attacker login", "HTTP 200 with auth_token", f"HTTP {login_status}", login_status == 200 and isinstance(token, str) and bool(token))

        status, profile = request_json(api, "GET", "/me", f"{probe_prefix}-me", token)
        profile_data = profile.get("data") if isinstance(profile, dict) else None
        fields = set(profile_data) if isinstance(profile_data, dict) else set()
        serialized = json.dumps(profile, sort_keys=True).lower() if profile is not None else ""
        forbidden_present = sorted(item for item in FORBIDDEN if item in serialized)
        profile_ok = status == 200 and fields == {"username", "email"} and not forbidden_present
        add_result(results, "Profile DTO whitelist", "HTTP 200; fields exactly username,email", f"HTTP {status}; fields={','.join(sorted(fields)) or '<none>'}", profile_ok)

        status, _ = request_json(api, "GET", "/users/v1", f"{probe_prefix}-directory", token)
        add_result(results, "User directory unavailable to non-admin", "HTTP 403", f"HTTP {status}", status == 403)

        status, _ = request_json(api, "GET", f"/users/v1/{args.victim}", f"{probe_prefix}-victim-profile", token)
        add_result(results, "Victim profile unavailable to attacker", "HTTP 403", f"HTTP {status}", status == 403)

        status, _ = request_json(api, "GET", "/users/v1/_debug", f"{probe_prefix}-debug", token)
        add_result(results, "Retired debug endpoint", "HTTP 404", f"HTTP {status}", status == 404)

        status, _ = request_json(api, "GET", "/createdb", f"{probe_prefix}-createdb", token)
        add_result(results, "Retired database-reset endpoint", "HTTP 404", f"HTTP {status}", status == 404)

        outcome = "PASS"
        return_code = 0
        print("\nW4-RETEST-EXPOSURE: PASS")
        print(f"Probe prefix for Ubuntu logs: {probe_prefix}")
    except RetestFailure as exc:
        print(f"\nW4-RETEST-EXPOSURE: FAIL - {exc}", file=sys.stderr)
    finally:
        evidence = {
            "task": "W4-RETEST-EXPOSURE",
            "outcome": outcome,
            "started_at_utc": started_at.isoformat(),
            "api": api,
            "probe_prefix": probe_prefix,
            "expected": {"me": 200, "directory": 403, "victim_profile": 403, "debug": 404, "createdb": 404},
            "results": results,
            "note": "Sanitized evidence: stores statuses and field names only; no password, JWT, response body, or sensitive value is recorded.",
        }
        output = write_evidence(Path(args.evidence_dir), evidence)
        print(f"Sanitized evidence saved: {output}")
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
