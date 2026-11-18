#!/usr/bin/env python3
"""Package sanitized W3-BACKEND-05 assertions as W3-WRAP-03 evidence.

Run in the Kali repository after scripts/w3_backend_05_regression.py succeeds.
It copies only an allow-listed summary from that script's already-sanitized
JSON. Passwords, JWTs, request/response bodies, and secrets are rejected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FORBIDDEN_KEY = re.compile(r"password|secret|auth[_-]?token|jwt", re.IGNORECASE)
ALLOWED_RESULT_KEYS = {"name", "expected", "actual", "passed", "detail"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create sanitized Kali evidence manifest for W3-WRAP-03.")
    parser.add_argument(
        "--source-dir",
        default="evidence/state-b/w3-backend-05",
        help="Directory containing sanitized W3-BACKEND-05 JSON output.",
    )
    parser.add_argument(
        "--output-root",
        default="evidence/state-b/w3-wrap-03",
        help="Root directory for the generated W3-WRAP-03 evidence.",
    )
    return parser.parse_args()


def latest_json(source_dir: Path) -> Path:
    candidates = sorted(source_dir.glob("w3-backend-05-*.json"), key=lambda item: item.stat().st_mtime)
    if not candidates:
        raise ValueError(f"No W3-BACKEND-05 evidence JSON found in {source_dir}")
    return candidates[-1]


def validate_and_project(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("task") != "W3-BACKEND-05":
        raise ValueError("Source evidence is not a W3-BACKEND-05 result.")
    if payload.get("outcome") != "PASS":
        raise ValueError("Source regression outcome is not PASS; do not package it as passing evidence.")
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        raise ValueError("Source evidence has no assertion results.")

    safe_results: list[dict[str, Any]] = []
    for item in results:
        if not isinstance(item, dict) or not set(item).issubset(ALLOWED_RESULT_KEYS):
            raise ValueError("Source result has unexpected fields and is not safe to copy.")
        if any(FORBIDDEN_KEY.search(str(key)) for key in item):
            raise ValueError("Source result contains a forbidden key.")
        projected = {key: item[key] for key in ("name", "expected", "actual", "passed", "detail") if key in item}
        if not isinstance(projected.get("passed"), bool):
            raise ValueError("A source assertion lacks a boolean passed value.")
        safe_results.append(projected)

    if not all(item["passed"] for item in safe_results):
        raise ValueError("At least one source assertion failed.")

    return {
        "task": "W3-WRAP-03",
        "source_task": "W3-BACKEND-05",
        "outcome": "PASS",
        "source_started_at_utc": payload.get("started_at_utc"),
        "api": payload.get("api"),
        "probe_prefix": payload.get("probe_prefix"),
        "assertion_count": len(safe_results),
        "request_response_assertions": safe_results,
        "note": (
            "Sanitized manifest: stores endpoint-level status assertions only; no passwords, JWTs, "
            "request/response bodies, database records, or secret values."
        ),
    }


def main() -> int:
    args = parse_args()
    source = latest_json(Path(args.source_dir))
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Source JSON must be an object.")
    projected = validate_and_project(payload)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    output_dir = Path(args.output_root) / f"kali-{stamp}"
    output_dir.mkdir(parents=True, exist_ok=False)
    summary = output_dir / "request-response-assertions.json"
    summary.write_text(json.dumps(projected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    readme = output_dir / "README.txt"
    readme.write_text(
        "W3-WRAP-03 Kali evidence\n"
        f"Source file: {source}\n"
        f"Probe prefix: {projected.get('probe_prefix')}\n"
        "This directory is local evidence and is excluded from Git.\n"
        "Use the probe prefix and the source started_at_utc value when collecting Ubuntu logs.\n"
        "Interpret matching logs as documented in docs/evidence-state-b.md.\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(summary.read_bytes()).hexdigest()
    (output_dir / "SHA256SUMS").write_text(f"{digest}  {summary.name}\n", encoding="utf-8")

    print(f"W3-WRAP-03 Kali evidence saved: {output_dir}")
    print(f"Probe prefix: {projected.get('probe_prefix')}")
    print(f"Source start time: {projected.get('source_started_at_utc')}")
    print(f"Assertions packaged: {projected['assertion_count']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"W3-WRAP-03: FAIL - {exc}", file=sys.stderr)
        raise SystemExit(1)
