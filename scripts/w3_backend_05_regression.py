#!/usr/bin/env python3
"""Regression test for W3-BACKEND-01 through W3-BACKEND-04.

Run this script from the repository root after the State B containers are up.
It talks only to Kong's public proxy, never directly to VAmPI. Passwords are
read securely from the terminal (or named environment variables) and are never
written to the evidence file. The attacker password is changed temporarily to
prove token revocation, then restored before the script exits successfully.

Example:
    python3 scripts/w3_backend_05_regression.py --api http://192.168.42.130:8000

Optional non-interactive inputs:
    W3_ATTACKER_PASSWORD, W3_VICTIM_PASSWORD, W3_TEMPORARY_PASSWORD
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


FORBIDDEN_PROFILE_FIELDS = {"password", "admin", "secret", "auth_token", "token"}


class RegressionFailure(RuntimeError):
    """Raised when an assertion fails while preserving test diagnostics."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="W3-BACKEND-05 State B regression assertions through Kong."
    )
    parser.add_argument("--api", required=True, help="Kong proxy URL, e.g. http://192.168.42.130:8000")
    parser.add_argument("--attacker", default="attacker", help="Attacker username (default: attacker)")
    parser.add_argument("--victim", default="victim", help="Victim username (default: victim)")
    parser.add_argument("--victim-book", default="VictimDiary", help="Victim-owned book title used for BOLA test")
    parser.add_argument(
        "--evidence-dir",
        default="evidence/state-b/w3-backend-05",
        help="Directory for sanitized pass/fail JSON (default: evidence/state-b/w3-backend-05)",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Fail instead of prompting when a required password environment variable is absent.",
    )
    return parser.parse_args()


def read_secret(env_name: str, prompt: str, non_interactive: bool) -> str:
    value = os.getenv(env_name)
    if value:
        return value
    if non_interactive:
        raise RegressionFailure(f"Missing required environment variable {env_name} in non-interactive mode.")
    value = getpass.getpass(prompt)
    if not value:
        raise RegressionFailure("A required password was empty.")
    return value


def url_with_probe(base_api: str, path: str, probe: str) -> str:
    parsed = urlparse(base_api.rstrip("/") + path)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["probe"] = probe
    return urlunparse(parsed._replace(query=urlencode(query)))


def request_json(
    base_api: str,
    method: str,
    path: str,
    probe: str,
    token: str | None = None,
    payload: dict[str, Any] | None = None,
) -> tuple[int, dict[str, str], Any]:
    headers = {"Accept": "application/json"}
    body = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")

    req = Request(url_with_probe(base_api, path, probe), data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=15) as response:
            raw = response.read().decode("utf-8", errors="replace")
            status = response.status
            response_headers = dict(response.headers.items())
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        status = exc.code
        response_headers = dict(exc.headers.items())
    except URLError as exc:
        raise RegressionFailure(f"Cannot reach Kong at {base_api}: {exc.reason}") from exc

    try:
        parsed_body: Any = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        parsed_body = {"non_json_response": raw[:300]}
    return status, response_headers, parsed_body


def response_message(body: Any) -> str:
    if isinstance(body, dict):
        message = body.get("message")
        if isinstance(message, str):
            return message[:160]
    return ""


def run_assertion(results: list[dict[str, Any]], name: str, status: int, expected: int, detail: str = "") -> None:
    passed = status == expected
    results.append({"name": name, "expected": expected, "actual": status, "passed": passed, "detail": detail})
    marker = "PASS" if passed else "FAIL"
    print(f"[{marker}] {name}: HTTP {status} (expected {expected})")
    if not passed:
        raise RegressionFailure(f"{name}: expected HTTP {expected}, got {status}. {detail}".strip())


def login(
    base_api: str, username: str, password: str, probe: str, results: list[dict[str, Any]], label: str
) -> tuple[str, dict[str, str]]:
    status, headers, body = request_json(
        base_api, "POST", "/users/v1/login", probe, payload={"username": username, "password": password}
    )
    remaining = headers.get("X-RateLimit-Remaining-Minute") or headers.get("RateLimit-Remaining")
    suffix = f" rate_limit_remaining={remaining}" if remaining is not None else ""
    token = body.get("auth_token") if isinstance(body, dict) else None
    passed = status == 200 and isinstance(token, str) and bool(token)
    detail = response_message(body) + suffix
    results.append(
        {
            "name": label,
            "expected": "HTTP 200 with auth_token",
            "actual": status,
            "passed": passed,
            "detail": detail,
        }
    )
    marker = "PASS" if passed else "FAIL"
    print(f"[{marker}] {label}: HTTP {status} (expected 200 with auth_token)")
    if not passed:
        if status == 200:
            raise RegressionFailure(f"{label}: login was rejected: {detail or 'response has no auth_token'}")
        raise RegressionFailure(f"{label}: expected HTTP 200, got {status}. {detail}".strip())
    return token, headers


def ensure_login_budget(headers: dict[str, str]) -> None:
    """Avoid rotating a password when Kong's low login quota cannot finish cleanup."""
    raw = headers.get("X-RateLimit-Remaining-Minute") or headers.get("RateLimit-Remaining")
    if raw is None:
        return
    try:
        remaining = int(raw)
    except ValueError:
        return
    # Two more logins are required after rotation: temporary and restored password.
    if remaining < 2:
        raise RegressionFailure(
            "Login rate-limit budget is too low to safely test password rotation. "
            "Wait for Kong's rate-limit reset, then rerun before any password change."
        )


def write_evidence(destination: Path, payload: dict[str, Any]) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / f"w3-backend-05-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


def main() -> int:
    args = parse_args()
    api = args.api.rstrip("/")
    started_at = datetime.now(timezone.utc)
    run_id = f"w3backend05-{started_at.strftime('%Y%m%d-%H%M%S')}"
    results: list[dict[str, Any]] = []
    cleanup_note = "not-needed"

    try:
        attacker_password = read_secret(
            "W3_ATTACKER_PASSWORD", f"Current password for {args.attacker}: ", args.non_interactive
        )
        victim_password = read_secret(
            "W3_VICTIM_PASSWORD", f"Current password for {args.victim}: ", args.non_interactive
        )
        temporary_password = read_secret(
            "W3_TEMPORARY_PASSWORD", "Temporary password for the rotation test: ", args.non_interactive
        )
        if temporary_password == attacker_password:
            raise RegressionFailure("Temporary password must differ from the current attacker password.")

        attacker_token, _ = login(
            api, args.attacker, attacker_password, f"{run_id}-attacker-login", results, "Attacker login"
        )
        victim_token, victim_login_headers = login(
            api, args.victim, victim_password, f"{run_id}-victim-login", results, "Victim login"
        )

        # The victim's own object remains readable.
        status, _, body = request_json(api, "GET", f"/books/v1/{args.victim_book}", f"{run_id}-victim-own-book", victim_token)
        detail = response_message(body)
        if isinstance(body, dict) and body.get("owner") != args.victim:
            detail = "Owner in response did not match victim."
            status = 599
        run_assertion(results, "Victim reads own book", status, 200, detail)

        # Attacker must not infer a victim-owned book through this endpoint.
        status, _, body = request_json(api, "GET", f"/books/v1/{args.victim_book}", f"{run_id}-attacker-foreign-book", attacker_token)
        run_assertion(results, "Attacker blocked from victim book", status, 404, response_message(body))

        # DB-backed ACL checks, not merely Kong JWT acceptance.
        status, _, body = request_json(api, "GET", "/users/v1", f"{run_id}-attacker-users-list", attacker_token)
        run_assertion(results, "Attacker blocked from user directory", status, 403, response_message(body))
        status, _, body = request_json(api, "GET", f"/users/v1/{args.victim}", f"{run_id}-attacker-victim-profile", attacker_token)
        run_assertion(results, "Attacker blocked from victim profile", status, 403, response_message(body))

        # DTO whitelist: check exact profile fields as well as forbidden substrings.
        status, _, body = request_json(api, "GET", "/me", f"{run_id}-dto", attacker_token)
        run_assertion(results, "Authenticated profile request", status, 200, response_message(body))
        if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
            raise RegressionFailure("DTO assertion: /me response did not contain an object at data.")
        fields = set(body["data"])
        serialized = json.dumps(body, sort_keys=True).lower()
        forbidden = sorted(field for field in FORBIDDEN_PROFILE_FIELDS if field in serialized)
        dto_ok = fields == {"username", "email"} and not forbidden
        results.append({
            "name": "DTO whitelist excludes sensitive fields",
            "expected": "data keys exactly username,email and no forbidden field",
            "actual": sorted(fields),
            "passed": dto_ok,
            "detail": "forbidden=" + ",".join(forbidden) if forbidden else "",
        })
        print(f"[{'PASS' if dto_ok else 'FAIL'}] DTO whitelist excludes sensitive fields")
        if not dto_ok:
            raise RegressionFailure("DTO whitelist assertion failed.")

        # Retired operations must remain unavailable even with a valid JWT.
        status, _, body = request_json(api, "GET", "/users/v1/_debug", f"{run_id}-debug", attacker_token)
        run_assertion(results, "Retired /users/v1/_debug", status, 404, response_message(body))
        status, _, body = request_json(api, "GET", "/createdb", f"{run_id}-createdb", attacker_token)
        run_assertion(results, "Retired /createdb", status, 404, response_message(body))

        # Read remaining quota before making an irreversible test change.
        status, _, body = request_json(api, "GET", "/me", f"{run_id}-pre-rotation", attacker_token)
        run_assertion(results, "Old token works before password change", status, 200, response_message(body))
        ensure_login_budget(victim_login_headers)

        changed = False
        replacement_token: str | None = None
        try:
            status, _, body = request_json(
                api,
                "PUT",
                f"/users/v1/{args.attacker}/password",
                f"{run_id}-password-change",
                attacker_token,
                {"password": temporary_password},
            )
            run_assertion(results, "Password change", status, 204, response_message(body))
            changed = True

            status, _, body = request_json(api, "GET", "/me", f"{run_id}-old-token-stale", attacker_token)
            run_assertion(results, "Old token rejected after password change", status, 401, response_message(body))

            replacement_token, _ = login(
                api, args.attacker, temporary_password, f"{run_id}-new-login", results, "Login with temporary password"
            )
            status, _, body = request_json(api, "GET", "/me", f"{run_id}-new-token", replacement_token)
            run_assertion(results, "New token works", status, 200, response_message(body))

            status, _, body = request_json(
                api,
                "PUT",
                f"/users/v1/{args.attacker}/password",
                f"{run_id}-password-restore",
                replacement_token,
                {"password": attacker_password},
            )
            run_assertion(results, "Restore original attacker password", status, 204, response_message(body))
            changed = False
            cleanup_note = "restored"
        finally:
            # Best effort cleanup if a later assertion failed after the password
            # change. Attempt to obtain a temporary-password token first; this
            # keeps the normal lab account usable even when an assertion fails.
            if changed and replacement_token is None:
                recovery_status, _, recovery_body = request_json(
                    api,
                    "POST",
                    "/users/v1/login",
                    f"{run_id}-emergency-login",
                    payload={"username": args.attacker, "password": temporary_password},
                )
                if recovery_status == 200 and isinstance(recovery_body, dict):
                    candidate = recovery_body.get("auth_token")
                    if isinstance(candidate, str):
                        replacement_token = candidate
            if changed and replacement_token:
                status, _, _ = request_json(
                    api,
                    "PUT",
                    f"/users/v1/{args.attacker}/password",
                    f"{run_id}-emergency-restore",
                    replacement_token,
                    {"password": attacker_password},
                )
                cleanup_note = "emergency-restored" if status == 204 else f"emergency-restore-failed-http-{status}"
            elif changed:
                cleanup_note = "manual-restore-required-with-temporary-password"

        final_token, _ = login(
            api, args.attacker, attacker_password, f"{run_id}-final-login", results, "Final login with original password"
        )
        status, _, body = request_json(api, "GET", "/me", f"{run_id}-final-me", final_token)
        run_assertion(results, "Final token works after restoration", status, 200, response_message(body))

        outcome = "PASS"
        print("\nW3-BACKEND-05: PASS")
        return_code = 0
    except RegressionFailure as exc:
        outcome = "FAIL"
        print(f"\nW3-BACKEND-05: FAIL - {exc}", file=sys.stderr)
        return_code = 1
    finally:
        evidence = {
            "task": "W3-BACKEND-05",
            "outcome": locals().get("outcome", "FAIL"),
            "started_at_utc": started_at.isoformat(),
            "api": api,
            "probe_prefix": run_id,
            "cleanup": cleanup_note,
            "results": results,
            "note": "Sanitized evidence: no passwords, JWTs, response bodies, or secrets are recorded.",
        }
        output = write_evidence(Path(args.evidence_dir), evidence)
        print(f"Sanitized evidence saved: {output}")

    return return_code


if __name__ == "__main__":
    sys.exit(main())
