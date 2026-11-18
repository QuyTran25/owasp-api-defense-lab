#!/usr/bin/env python3
"""Run State B re-tests as one sanitized assurance session on Kali.

This runner deliberately reuses the reviewed W4 test scripts.  It never
changes Kong, VAmPI source, or runtime configuration.  Passwords are read at
the terminal and only supplied to child processes; they are excluded from the
manifest.  A separate Ubuntu collector is required to prove enforcement layer.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TASKS = (
    ("W4-RETEST-BOLA", "w4_retest_bola.py", "bola"),
    ("W4-RETEST-JWT-A", "w4_retest_jwt_forgery.py", "jwt-auth"),
    ("W4-RETEST-JWT-B", "w4_retest_jwt_replay.py", "jwt-auth"),
    ("W4-RETEST-EXPOSURE", "w4_retest_exposure.py", "exposure"),
)
SAFE_RESULT_KEYS = {"name", "expected", "actual", "passed"}


class AssuranceFailure(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a State B security-assurance session from Kali.")
    parser.add_argument("--api", required=True, help="Kong proxy URL, for example http://192.168.42.130:8000")
    parser.add_argument("--policy", default="security/security-assurance-policy.json")
    parser.add_argument("--output-root", default="evidence/assurance", help="Local sanitized evidence root.")
    parser.add_argument("--cooldown-seconds", type=int, default=65, help="Wait before replay test to avoid the lab login quota.")
    parser.add_argument("--non-interactive", action="store_true", help="Read passwords from W4_* environment variables.")
    return parser.parse_args()


def secret(name: str, prompt: str, non_interactive: bool) -> str:
    value = os.getenv(name)
    if not value and not non_interactive:
        value = getpass.getpass(prompt)
    if not value:
        raise AssuranceFailure(f"Missing required password input {name}.")
    return value


def load_policy(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("controls"), list):
        raise AssuranceFailure("Policy must be a JSON object with controls.")
    return payload


def latest_json(directory: Path, prefix: str) -> Path:
    matches = sorted(directory.glob(f"{prefix}-*.json"), key=lambda item: item.stat().st_mtime)
    if len(matches) != 1:
        raise AssuranceFailure(f"Expected exactly one {prefix} evidence file in {directory}, found {len(matches)}.")
    return matches[0]


def project_evidence(path: Path, expected_task: str) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("task") != expected_task or payload.get("outcome") != "PASS":
        raise AssuranceFailure(f"{expected_task} did not produce PASS evidence.")
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        raise AssuranceFailure(f"{expected_task} has no assertions.")
    safe_results = []
    for result in results:
        if not isinstance(result, dict) or not set(result).issubset(SAFE_RESULT_KEYS):
            raise AssuranceFailure(f"{expected_task} evidence has unsafe result fields.")
        if result.get("passed") is not True:
            raise AssuranceFailure(f"{expected_task} has a failed assertion.")
        safe_results.append({key: result[key] for key in SAFE_RESULT_KEYS if key in result})
    return {
        "task": expected_task,
        "outcome": "PASS",
        "source_file": str(path),
        "started_at_utc": payload.get("started_at_utc"),
        "probe_prefix": payload.get("probe_prefix"),
        "assertions": safe_results,
    }


def run_task(repo: Path, script: str, api: str, evidence_dir: Path, env: dict[str, str]) -> None:
    command = [sys.executable, str(repo / "scripts" / script), "--api", api, "--evidence-dir", str(evidence_dir), "--non-interactive"]
    completed = subprocess.run(command, cwd=repo, env=env, text=True)
    if completed.returncode != 0:
        raise AssuranceFailure(f"{script} returned exit status {completed.returncode}.")


def main() -> int:
    args = parse_args()
    if args.cooldown_seconds < 0:
        raise AssuranceFailure("--cooldown-seconds must not be negative.")
    repo = Path(__file__).resolve().parents[1]
    policy = load_policy((repo / args.policy).resolve() if not Path(args.policy).is_absolute() else Path(args.policy))
    started = datetime.now(timezone.utc)
    run_id = f"w5assurance-{started.strftime('%Y%m%d-%H%M%S')}"
    output = (repo / args.output_root / run_id).resolve()
    raw_root = output / "w4-sanitized"
    output.mkdir(parents=True, exist_ok=False)

    outcome = "FAIL"
    detail = ""
    manifest_tasks: list[dict[str, Any]] = []
    try:
        attacker = secret("W4_ATTACKER_PASSWORD", "Current password for attacker: ", args.non_interactive)
        victim = secret("W4_VICTIM_PASSWORD", "Current password for victim: ", args.non_interactive)
        temporary = secret("W4_TEMPORARY_PASSWORD", "Temporary password for replay test: ", args.non_interactive)
        if temporary == attacker:
            raise AssuranceFailure("Temporary password must differ from the attacker password.")
        child_env = os.environ.copy()
        child_env.update({"W4_ATTACKER_PASSWORD": attacker, "W4_VICTIM_PASSWORD": victim, "W4_TEMPORARY_PASSWORD": temporary})

        prefixes = {
            "W4-RETEST-BOLA": "w4-retest-bola",
            "W4-RETEST-JWT-A": "w4-retest-jwt-forgery",
            "W4-RETEST-JWT-B": "w4-retest-jwt-replay",
            "W4-RETEST-EXPOSURE": "w4-retest-exposure",
        }
        for task, script, subdir in TASKS:
            if task == "W4-RETEST-JWT-B" and args.cooldown_seconds:
                print(f"Waiting {args.cooldown_seconds}s before replay test to avoid the configured login quota ...")
                time.sleep(args.cooldown_seconds)
            evidence_dir = raw_root / subdir
            run_task(repo, script, args.api.rstrip("/"), evidence_dir, child_env)
            manifest_tasks.append(project_evidence(latest_json(evidence_dir, prefixes[task]), task))

        outcome = "PENDING_UBUNTU_EVIDENCE"
        detail = "All Kali assertions passed; collect and verify Ubuntu logs before declaring final PASS."
    except (AssuranceFailure, OSError, ValueError, json.JSONDecodeError) as exc:
        detail = str(exc)
        print(f"W5-ASSURANCE-KALI: FAIL - {detail}", file=sys.stderr)
    finally:
        probes = [entry.get("probe_prefix") for entry in manifest_tasks if isinstance(entry.get("probe_prefix"), str)]
        manifest = {
            "task": "W5-SECURITY-ASSURANCE-KALI",
            "outcome": outcome,
            "started_at_utc": started.isoformat(),
            "api": args.api.rstrip("/"),
            "run_id": run_id,
            "policy": str(args.policy),
            "tests": manifest_tasks,
            "ubuntu_collection": {
                "since": started.isoformat(),
                "probes": probes,
                "command_template": "bash scripts/w5_security_assurance_collect_ubuntu.sh --since '<UTC_START>' --probe '<PROBE>' [--probe '<PROBE>' ...]",
            },
            "note": "Sanitized manifest: passwords, JWTs, response bodies, runtime secrets and Authorization headers are excluded.",
            "detail": detail,
        }
        manifest_path = output / "kali-manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (output / "SHA256SUMS").write_text(
            f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  {manifest_path.name}\n", encoding="utf-8"
        )
        print(f"Kali assurance manifest saved: {manifest_path}")
        print(f"Kali manifest checksum saved: {output / 'SHA256SUMS'}")
        for probe in probes:
            print(f"Ubuntu collector probe: {probe}")
    return 0 if outcome == "PENDING_UBUNTU_EVIDENCE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
