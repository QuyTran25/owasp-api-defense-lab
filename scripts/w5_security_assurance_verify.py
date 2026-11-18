#!/usr/bin/env python3
"""Verify a W5 assurance session from sanitized Kali and Ubuntu evidence.

The verifier never calls the target API and never needs credentials.  It
matches policy controls to already-sanitized W4 assertion data and to the two
runtime logs.  PASS is issued only when HTTP assertion, expected enforcement
layer, runtime invariants and SHA-256 checks all agree.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class VerificationError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify sanitized State B assurance evidence.")
    parser.add_argument("--kali-manifest", required=True, help="kali-manifest.json from W5 runner.")
    parser.add_argument("--ubuntu-evidence", required=True, help="Ubuntu evidence directory from W5 collector.")
    parser.add_argument("--policy", default="security/security-assurance-policy.json")
    parser.add_argument("--output-dir", default="evidence/assurance-reports")
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise VerificationError(f"{path} is not a JSON object.")
    return payload


def check_checksums(folder: Path) -> tuple[bool, str]:
    sums = folder / "SHA256SUMS"
    if not sums.is_file():
        return False, "SHA256SUMS is absent"
    try:
        for line in sums.read_text(encoding="utf-8").splitlines():
            digest, name = line.split(maxsplit=1)
            target = folder / name.strip().lstrip("*")
            if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                return False, f"checksum mismatch: {target.name}"
    except (OSError, ValueError):
        return False, "SHA256SUMS is malformed"
    return True, "all Ubuntu evidence checksums match"


def check_manifest_checksum(manifest: Path) -> tuple[bool, str]:
    sums = manifest.parent / "SHA256SUMS"
    if not sums.is_file():
        return False, "Kali manifest SHA256SUMS is absent"
    for line in sums.read_text(encoding="utf-8").splitlines():
        try:
            digest, name = line.split(maxsplit=1)
        except ValueError:
            continue
        if name.strip().lstrip("*") == manifest.name:
            actual = hashlib.sha256(manifest.read_bytes()).hexdigest()
            return (actual == digest, "Kali manifest checksum matches" if actual == digest else "Kali manifest checksum mismatch")
    return False, "Kali manifest is not listed in SHA256SUMS"


def task_index(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tests = manifest.get("tests")
    if not isinstance(tests, list):
        raise VerificationError("Kali manifest has no tests list.")
    indexed = {item.get("task"): item for item in tests if isinstance(item, dict) and isinstance(item.get("task"), str)}
    if not indexed:
        raise VerificationError("Kali manifest contains no valid test records.")
    return indexed


def assertion_result(test: dict[str, Any], name: str) -> bool | None:
    values = test.get("assertions")
    if not isinstance(values, list):
        return None
    for item in values:
        if isinstance(item, dict) and item.get("name") == name:
            return item.get("passed") is True
    return None


def layer_result(kong_log: str, vampi_log: str, probe: str, expected_layer: str) -> tuple[str, str]:
    kong = probe in kong_log
    vampi = probe in vampi_log
    if not kong:
        return "INCONCLUSIVE", "probe is absent from Kong log"
    if expected_layer == "gateway":
        return ("PASS", "Kong present; VAmPI absent") if not vampi else ("FAIL", "request reached VAmPI, expected gateway block")
    if expected_layer == "backend":
        return ("PASS", "Kong and VAmPI both present") if vampi else ("FAIL", "VAmPI log absent, expected backend enforcement")
    return "INCONCLUSIVE", f"unknown expected layer {expected_layer}"


def render_html(report: dict[str, Any]) -> str:
    rows = []
    for item in report["results"]:
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(item.get(key, '')))}</td>" for key in ("id", "status", "expected_layer", "detail")) + "</tr>")
    return """<!doctype html><html lang=\"vi\"><head><meta charset=\"utf-8\"><title>Security Assurance Report</title>
<style>body{font-family:Arial,sans-serif;margin:2rem;color:#111}table{border-collapse:collapse;width:100%%}th,td{border:1px solid #777;padding:.5rem;text-align:left}th{background:#eee}.PASS{color:#147a25}.FAIL{color:#b00020}.INCONCLUSIVE{color:#9a6700}</style></head><body>
<h1>State B Security Assurance Report</h1>
<p><strong>Outcome:</strong> <span class=\"%s\">%s</span></p><p>Created UTC: %s</p>
<table><thead><tr><th>Control</th><th>Status</th><th>Expected layer</th><th>Evidence evaluation</th></tr></thead><tbody>%s</tbody></table>
<p>This report contains only sanitized assertion metadata and enforcement evidence. It contains no passwords, JWTs, secrets, Authorization headers, or response bodies.</p></body></html>""" % (
        html.escape(report["outcome"]), html.escape(report["outcome"]), html.escape(report["created_at_utc"]), "".join(rows)
    )


def main() -> int:
    args = parse_args()
    kali_path = Path(args.kali_manifest).resolve()
    ubuntu = Path(args.ubuntu_evidence).resolve()
    policy_path = Path(args.policy).resolve()
    manifest, policy = load_json(kali_path), load_json(policy_path)
    if manifest.get("outcome") != "PENDING_UBUNTU_EVIDENCE":
        raise VerificationError("Kali manifest is not a successful pending assurance session.")
    controls = policy.get("controls")
    if not isinstance(controls, list):
        raise VerificationError("Policy has no controls list.")
    tasks = task_index(manifest)
    kong_log = (ubuntu / "kong.log").read_text(encoding="utf-8", errors="replace")
    vampi_log = (ubuntu / "vampi.log").read_text(encoding="utf-8", errors="replace")
    runtime = load_json(ubuntu / "runtime-assertions.json")
    checksum_ok, checksum_detail = check_checksums(ubuntu)
    kali_checksum_ok, kali_checksum_detail = check_manifest_checksum(kali_path)
    results: list[dict[str, str]] = [
        {"id": "KALI-MANIFEST-INTEGRITY", "status": "PASS" if kali_checksum_ok else "FAIL", "expected_layer": "evidence", "detail": kali_checksum_detail},
        {"id": "UBUNTU-EVIDENCE-INTEGRITY", "status": "PASS" if checksum_ok else "FAIL", "expected_layer": "evidence", "detail": checksum_detail},
    ]

    runtime_by_id = {item.get("id"): item for item in runtime.get("results", []) if isinstance(item, dict)}
    for invariant in policy.get("runtime_invariants", []):
        item = runtime_by_id.get(invariant)
        if item is None:
            results.append({"id": str(invariant), "status": "INCONCLUSIVE", "expected_layer": "runtime", "detail": "runtime assertion is absent"})
        else:
            results.append({"id": str(invariant), "status": "PASS" if item.get("passed") is True else "FAIL", "expected_layer": "runtime", "detail": str(item.get("actual", ""))})

    for control in controls:
        if not isinstance(control, dict):
            continue
        control_id = str(control.get("id", "UNKNOWN"))
        test = tasks.get(control.get("task"))
        if test is None:
            results.append({"id": control_id, "status": "INCONCLUSIVE", "expected_layer": str(control.get("expected_layer", "")), "detail": "required Kali test is absent"})
            continue
        assertion = assertion_result(test, str(control.get("assertion", "")))
        if assertion is not True:
            results.append({"id": control_id, "status": "FAIL" if assertion is False else "INCONCLUSIVE", "expected_layer": str(control.get("expected_layer", "")), "detail": "required HTTP assertion did not pass or is absent"})
            continue
        prefix = test.get("probe_prefix")
        if not isinstance(prefix, str):
            results.append({"id": control_id, "status": "INCONCLUSIVE", "expected_layer": str(control.get("expected_layer", "")), "detail": "test has no probe prefix"})
            continue
        status, detail = layer_result(kong_log, vampi_log, f"{prefix}-{control.get('probe_suffix')}", str(control.get("expected_layer")))
        results.append({"id": control_id, "status": status, "expected_layer": str(control.get("expected_layer", "")), "detail": detail})

    statuses = {item["status"] for item in results}
    outcome = "FAIL" if "FAIL" in statuses else "INCONCLUSIVE" if "INCONCLUSIVE" in statuses else "PASS"
    report = {
        "task": "W5-SECURITY-ASSURANCE-VERIFY",
        "outcome": outcome,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "policy": str(policy_path),
        "kali_manifest": str(kali_path),
        "ubuntu_evidence": str(ubuntu),
        "results": results,
        "note": "A non-PASS outcome must not be described as a secure State B result.",
    }
    output = Path(args.output_dir).resolve() / f"security-assurance-report-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    output.mkdir(parents=True, exist_ok=False)
    (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "report.html").write_text(render_html(report), encoding="utf-8")
    digest = hashlib.sha256((output / "report.json").read_bytes()).hexdigest()
    (output / "SHA256SUMS").write_text(f"{digest}  report.json\n", encoding="utf-8")
    print(f"W5-SECURITY-ASSURANCE: {outcome}")
    for item in results:
        print(f"{item['status']}: {item['id']} - {item['detail']}")
    print(f"Report saved: {output}")
    return 0 if outcome == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, VerificationError) as exc:
        print(f"W5-SECURITY-ASSURANCE: FAIL - {exc}", file=sys.stderr)
        raise SystemExit(1)
