#!/usr/bin/env python3
"""Validate and index sanitized Kali re-test evidence for W4.

The generated manifest contains only task names, timestamps, probe prefixes,
and assertion counts. It rejects failed or unexpected evidence; no JWT,
password, response body, or secret is copied into the manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED = {
    "W4-RETEST-BOLA": "bola/w4-retest-bola-*.json",
    "W4-RETEST-JWT-A": "jwt-auth/w4-retest-jwt-forgery-*.json",
    "W4-RETEST-JWT-B": "jwt-auth/w4-retest-jwt-replay-*.json",
    "W4-RETEST-EXPOSURE": "exposure/w4-retest-exposure-*.json",
}
ALLOWED_RESULT_KEYS = {"name", "expected", "actual", "passed"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate and index W4 sanitized re-test evidence.")
    parser.add_argument("--evidence-root", default="evidence/retest", help="Kali local evidence root.")
    return parser.parse_args()


def latest(root: Path, pattern: str) -> Path:
    files = sorted(root.glob(pattern), key=lambda item: item.stat().st_mtime)
    if not files:
        raise ValueError(f"Missing required evidence matching {pattern}")
    return files[-1]


def validate(path: Path, expected_task: str) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("task") != expected_task:
        raise ValueError(f"{path}: unexpected task")
    if payload.get("outcome") != "PASS":
        raise ValueError(f"{path}: outcome is not PASS")
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        raise ValueError(f"{path}: no assertion results")
    for result in results:
        if not isinstance(result, dict) or not set(result).issubset(ALLOWED_RESULT_KEYS):
            raise ValueError(f"{path}: unsafe or unexpected result fields")
        if result.get("passed") is not True:
            raise ValueError(f"{path}: a result did not pass")
    return {
        "task": expected_task,
        "outcome": "PASS",
        "source_file": str(path),
        "started_at_utc": payload.get("started_at_utc"),
        "probe_prefix": payload.get("probe_prefix"),
        "assertion_count": len(results),
    }


def main() -> int:
    args = parse_args()
    root = Path(args.evidence_root)
    entries = [validate(latest(root, pattern), task) for task, pattern in REQUIRED.items()]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    output = root / f"w4-retest-manifest-{stamp}.json"
    manifest = {
        "task": "W4-RETEST-EVIDENCE",
        "outcome": "PASS",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "retests": entries,
        "note": "Sanitized index: filenames, probe prefixes, timestamps, and assertion counts only.",
    }
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    checksum = output.with_suffix(".SHA256SUMS")
    checksum.write_text(f"{digest}  {output.name}\n", encoding="utf-8")
    print("W4-RETEST-EVIDENCE: PASS")
    for entry in entries:
        print(f"PASS: {entry['task']} ({entry['assertion_count']} assertions) probe={entry['probe_prefix']}")
    print(f"Sanitized manifest saved: {output}")
    print(f"Checksum saved: {checksum}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"W4-RETEST-EVIDENCE: FAIL - {exc}", file=sys.stderr)
        raise SystemExit(1)
