#!/usr/bin/env python3
"""Re-test W2 JWT replay after password change through Kong State B.

The test changes only the attacker password temporarily, verifies that the
pre-change token is rejected, then restores the original password before a
successful run returns. Evidence contains statuses/assertions only.
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
    parser = argparse.ArgumentParser(description="W4 JWT replay re-test through Kong State B.")
    parser.add_argument("--api", required=True, help="Kong proxy URL, e.g. http://192.168.42.130:8000")
    parser.add_argument("--attacker", default="attacker", help="Account whose token lifecycle is tested.")
    parser.add_argument("--evidence-dir", default="evidence/retest/jwt-auth", help="Local sanitized evidence directory.")
    parser.add_argument("--non-interactive", action="store_true", help="Require W4_ATTACKER_PASSWORD and W4_TEMPORARY_PASSWORD.")
    return parser.parse_args()


def read_secret(env_name: str, prompt: str, non_interactive: bool) -> str:
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


def add_result(results: list[dict[str, Any]], name: str, expected: str, actual: str, passed: bool) -> None:
    results.append({"name": name, "expected": expected, "actual": actual, "passed": passed})
    marker = "PASS" if passed else "FAIL"
    print(f"[{marker}] {name}: {actual} (expected {expected})")
    if not passed:
        raise RetestFailure(f"{name}: expected {expected}, got {actual}.")


def write_evidence(destination: Path, payload: dict[str, Any]) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / f"w4-retest-jwt-replay-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


def main() -> int:
    args = parse_args()
    api = args.api.rstrip("/")
    started_at = datetime.now(timezone.utc)
    probe_prefix = f"w4jwtreplay-{started_at.strftime('%Y%m%d-%H%M%S')}"
    results: list[dict[str, Any]] = []
    outcome = "FAIL"
    return_code = 1
    original_password = ""
    temporary_password = ""
    replacement_token: str | None = None
    changed = False
    cleanup_note = "not-needed"

    try:
        original_password = read_secret("W4_ATTACKER_PASSWORD", f"Current password for {args.attacker}: ", args.non_interactive)
        temporary_password = read_secret("W4_TEMPORARY_PASSWORD", "Temporary password for this test: ", args.non_interactive)
        if temporary_password == original_password:
            raise RetestFailure("Temporary password must differ from the current password.")

        status, old_token = login(api, args.attacker, original_password, f"{probe_prefix}-old-login")
        add_result(results, "Old-token login", "HTTP 200 with auth_token", f"HTTP {status}", status == 200 and old_token is not None)

        status, _ = request_json(api, "GET", "/me", f"{probe_prefix}-old-before-change", old_token)
        add_result(results, "Old token before password change", "HTTP 200", f"HTTP {status}", status == 200)

        status, _ = request_json(
            api,
            "PUT",
            f"/users/v1/{args.attacker}/password",
            f"{probe_prefix}-password-change",
            old_token,
            {"password": temporary_password},
        )
        add_result(results, "Password change", "HTTP 204", f"HTTP {status}", status == 204)
        changed = True

        status, _ = request_json(api, "GET", "/me", f"{probe_prefix}-old-stale", old_token)
        add_result(results, "Old token replay rejected", "HTTP 401", f"HTTP {status}", status == 401)

        status, replacement_token = login(api, args.attacker, temporary_password, f"{probe_prefix}-new-login")
        add_result(results, "Temporary-password login", "HTTP 200 with auth_token", f"HTTP {status}", status == 200 and replacement_token is not None)

        status, _ = request_json(api, "GET", "/me", f"{probe_prefix}-new-token", replacement_token)
        add_result(results, "New token after password change", "HTTP 200", f"HTTP {status}", status == 200)

        status, _ = request_json(
            api,
            "PUT",
            f"/users/v1/{args.attacker}/password",
            f"{probe_prefix}-password-restore",
            replacement_token,
            {"password": original_password},
        )
        add_result(results, "Restore original password", "HTTP 204", f"HTTP {status}", status == 204)
        changed = False
        cleanup_note = "restored"

        status, final_token = login(api, args.attacker, original_password, f"{probe_prefix}-final-login")
        add_result(results, "Final login with original password", "HTTP 200 with auth_token", f"HTTP {status}", status == 200 and final_token is not None)

        status, _ = request_json(api, "GET", "/me", f"{probe_prefix}-final-token", final_token)
        add_result(results, "Final token after restoration", "HTTP 200", f"HTTP {status}", status == 200)

        outcome = "PASS"
        return_code = 0
        print("\nW4-RETEST-JWT-B: PASS")
        print(f"Probe prefix for Ubuntu logs: {probe_prefix}")
    except RetestFailure as exc:
        print(f"\nW4-RETEST-JWT-B: FAIL - {exc}", file=sys.stderr)
    finally:
        # Best-effort recovery prevents a failed assertion from unnecessarily
        # leaving the shared lab account on the temporary password.
        if changed and replacement_token is None and temporary_password:
            recovery_status, recovery_token = login(api, args.attacker, temporary_password, f"{probe_prefix}-emergency-login")
            if recovery_status == 200:
                replacement_token = recovery_token
        if changed and replacement_token and original_password:
            restore_status, _ = request_json(
                api,
                "PUT",
                f"/users/v1/{args.attacker}/password",
                f"{probe_prefix}-emergency-restore",
                replacement_token,
                {"password": original_password},
            )
            cleanup_note = "emergency-restored" if restore_status == 204 else f"emergency-restore-failed-http-{restore_status}"
        elif changed:
            cleanup_note = "manual-restore-required-with-temporary-password"

        evidence = {
            "task": "W4-RETEST-JWT-B",
            "outcome": outcome,
            "started_at_utc": started_at.isoformat(),
            "api": api,
            "probe_prefix": probe_prefix,
            "cleanup": cleanup_note,
            "expected": {"old_before_change": 200, "old_after_change": 401, "new_token": 200},
            "results": results,
            "note": "Sanitized evidence: no passwords, JWTs, response bodies, or secret values are recorded.",
        }
        output = write_evidence(Path(args.evidence_dir), evidence)
        print(f"Sanitized evidence saved: {output}")
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
