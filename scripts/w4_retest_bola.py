#!/usr/bin/env python3
"""Re-test W2 BOLA against State B through Kong only.

The script deliberately performs read-only requests. It verifies that the
victim can still read the target object while the attacker receives 404 for
the identical object identifier. Evidence is status/assertion metadata only:
no password, JWT, response body, or book secret is written to disk.

Example:
    python3 scripts/w4_retest_bola.py --api http://192.168.42.130:8000

Optional non-interactive inputs:
    W4_ATTACKER_PASSWORD, W4_VICTIM_PASSWORD
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


class RetestFailure(RuntimeError):
    """Raised when a re-test expectation is not met."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="W4 BOLA re-test through the Kong State B proxy.")
    parser.add_argument("--api", required=True, help="Kong proxy URL, e.g. http://192.168.42.130:8000")
    parser.add_argument("--attacker", default="attacker", help="Attacker username.")
    parser.add_argument("--victim", default="victim", help="Victim username.")
    parser.add_argument("--victim-book", default="VictimDiary", help="Victim-owned book title from W2 baseline.")
    parser.add_argument(
        "--evidence-dir",
        default="evidence/retest/bola",
        help="Local directory for sanitized result JSON (default: evidence/retest/bola).",
    )
    parser.add_argument("--non-interactive", action="store_true", help="Require password environment variables.")
    return parser.parse_args()


def read_password(env_name: str, prompt: str, non_interactive: bool) -> str:
    value = os.getenv(env_name)
    if value:
        return value
    if non_interactive:
        raise RetestFailure(f"Missing required environment variable {env_name}.")
    value = getpass.getpass(prompt)
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


def login(api: str, username: str, password: str, probe: str) -> tuple[int, str | None]:
    status, body = request_json(api, "POST", "/users/v1/login", probe, payload={"username": username, "password": password})
    token = body.get("auth_token") if isinstance(body, dict) else None
    return status, token if isinstance(token, str) and token else None


def add_result(results: list[dict[str, Any]], name: str, expected: int | str, actual: int | str, passed: bool) -> None:
    results.append({"name": name, "expected": expected, "actual": actual, "passed": passed})
    marker = "PASS" if passed else "FAIL"
    print(f"[{marker}] {name}: {actual} (expected {expected})")
    if not passed:
        raise RetestFailure(f"{name}: expected {expected}, got {actual}.")


def write_evidence(destination: Path, payload: dict[str, Any]) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / f"w4-retest-bola-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


def main() -> int:
    args = parse_args()
    api = args.api.rstrip("/")
    started_at = datetime.now(timezone.utc)
    probe_prefix = f"w4bola-{started_at.strftime('%Y%m%d-%H%M%S')}"
    results: list[dict[str, Any]] = []
    outcome = "FAIL"
    return_code = 1

    try:
        attacker_password = read_password("W4_ATTACKER_PASSWORD", f"Current password for {args.attacker}: ", args.non_interactive)
        victim_password = read_password("W4_VICTIM_PASSWORD", f"Current password for {args.victim}: ", args.non_interactive)

        status, attacker_token = login(api, args.attacker, attacker_password, f"{probe_prefix}-attacker-login")
        add_result(results, "Attacker login", "HTTP 200 with auth_token", f"HTTP {status}", status == 200 and attacker_token is not None)

        status, victim_token = login(api, args.victim, victim_password, f"{probe_prefix}-victim-login")
        add_result(results, "Victim login", "HTTP 200 with auth_token", f"HTTP {status}", status == 200 and victim_token is not None)

        status, victim_body = request_json(api, "GET", f"/books/v1/{args.victim_book}", f"{probe_prefix}-victim-own", victim_token)
        victim_owner = victim_body.get("owner") if isinstance(victim_body, dict) else None
        add_result(results, "Victim reads own object", "HTTP 200 and owner=victim", f"HTTP {status}", status == 200 and victim_owner == args.victim)

        status, attacker_body = request_json(api, "GET", f"/books/v1/{args.victim_book}", f"{probe_prefix}-attacker-foreign", attacker_token)
        body_has_book_data = isinstance(attacker_body, dict) and any(key in attacker_body for key in ("book_title", "owner", "secret"))
        add_result(results, "Attacker denied victim object", "HTTP 404 without object data", f"HTTP {status}", status == 404 and not body_has_book_data)

        outcome = "PASS"
        return_code = 0
        print("\nW4-RETEST-BOLA: PASS")
        print(f"Probe prefix for Ubuntu logs: {probe_prefix}")
    except RetestFailure as exc:
        print(f"\nW4-RETEST-BOLA: FAIL - {exc}", file=sys.stderr)
    finally:
        evidence = {
            "task": "W4-RETEST-BOLA",
            "outcome": outcome,
            "started_at_utc": started_at.isoformat(),
            "api": api,
            "probe_prefix": probe_prefix,
            "expected": {"victim_own": 200, "attacker_foreign": 404},
            "results": results,
            "note": "Sanitized evidence: no passwords, JWTs, response bodies, or object secrets are recorded.",
        }
        output = write_evidence(Path(args.evidence_dir), evidence)
        print(f"Sanitized evidence saved: {output}")
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
