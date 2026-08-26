#!/usr/bin/env python3
"""Attestor Juniper Junos vendor adapter (source-backed subset)."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import socket
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from engines.network.junos import parse_config, statement_matches  # noqa: E402
from engines.network.normalize_junos import normalize_junos  # noqa: E402
from tests.validate_rules import format_errors, load_validator  # noqa: E402

ENGINE_VERSION = "0.1.0"
NOW_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def now() -> str:
    return datetime.now(timezone.utc).strftime(NOW_FORMAT)


def load_rules(rules_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    validator = load_validator()
    rules: list[dict[str, Any]] = []
    errors: list[str] = []
    for path in sorted(rules_dir.glob("*.yaml")):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"{path}: {exc}")
            continue
        schema_errors = format_errors(validator, rule)
        if schema_errors:
            errors.append(f"{path}: {'; '.join(schema_errors)}")
            continue
        if "network_device" not in rule.get("profile", []) or rule.get("device", {}).get("vendor") != "Juniper":
            errors.append(f"{path}: not a Juniper network rule")
            continue
        rules.append(rule)
    return rules, errors


def check_rule(rule: dict[str, Any], statements) -> dict[str, Any]:
    checks = []
    for index, check in enumerate(rule.get("checks", [])):
        if check.get("type") != "junos_statement":
            checks.append({"rule_id": rule["id"], "check_index": index, "status": "error", "actual": None, "expected": None, "evidence": "unsupported Junos check type", "error": "only junos_statement is implemented", "timestamp": now()})
            continue
        try:
            matches = statement_matches(statements, check["path_pattern"], check["statement_pattern"])
        except (KeyError, __import__("re").error) as exc:
            checks.append({"rule_id": rule["id"], "check_index": index, "status": "error", "actual": None, "expected": check.get("op"), "evidence": "invalid Junos statement matcher", "error": str(exc), "timestamp": now()})
            continue
        op = check["op"]
        passed = bool(matches) if op in {"present", "matches"} else not matches
        status = "pass" if passed else "fail"
        observation = f"line {matches[0].line}: Junos statement observed" if matches else "no matching Junos statement observed"
        checks.append({"rule_id": rule["id"], "check_index": index, "status": status, "actual": matches[0].text if matches else None, "expected": op, "evidence": f"path {check['path_pattern']!r}, statement {check['statement_pattern']!r}: {observation}", "timestamp": now()})
    statuses = [check["status"] for check in checks]
    status = "error" if not statuses or "error" in statuses else "fail" if "fail" in statuses else "pass"
    return {"rule_id": rule["id"], "title": rule["title"], "level": rule["level"], "profile": rule["profile"], "device": rule["device"], "severity": rule["severity"], "automated": rule["automated"], "status": status, "checks": checks, "evidence_summary": "; ".join(check["evidence"] for check in checks)[:500], "remediation": rule["remediation"], "source": rule["source"], "framework_mappings": rule.get("framework_mappings", [])}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Attestor — offline Juniper Junos configuration audit")
    parser.add_argument("--config", required=True)
    parser.add_argument("--device-id", default=None)
    parser.add_argument("--rules-dir", default=str(REPO_ROOT / "rules" / "juniper_junos"))
    parser.add_argument("--output", "-o", default="results.json")
    args = parser.parse_args(argv)
    path = Path(args.config).expanduser().resolve()
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8-sig")
        statements = parse_config(text)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"ERROR: could not read/parse Junos config: {exc}", file=sys.stderr)
        return 2
    rules, load_errors = load_rules(Path(args.rules_dir).expanduser().resolve())
    if not rules:
        print("ERROR: no valid Junos rules remain", file=sys.stderr)
        return 2
    hostname = normalize_junos(statements)["fields"]["hostname"]["value"]
    device_id = args.device_id or hostname
    if not device_id:
        print("ERROR: no Junos host-name; provide --device-id", file=sys.stderr)
        return 2
    controls = [check_rule(rule, statements) for rule in rules]
    summary = {key: 0 for key in ("pass", "fail", "error", "manual", "not_applicable")}
    for control in controls:
        summary[control["status"]] += 1
    results = {
        "attestor_format_version": "1.0",
        "report_id": str(uuid.uuid4()),
        "target": "juniper_junos",
        "benchmark": "Juniper Junos Security Baseline (vendor documentation)",
        "benchmark_version": "2026-08",
        "device": {"device_id": device_id, "hostname": hostname, "vendor": "Juniper", "platform": "Junos", "model": None, "roles": [], "config_source": "file", "config_sha256": hashlib.sha256(raw).hexdigest()},
        "host": {"hostname": socket.gethostname(), "os_name": platform.system() or "unknown", "os_version": platform.version() or "unknown", "os_id": (platform.system() or "unknown").lower(), "kernel": platform.release() or "unknown", "arch": platform.machine() or "unknown", "environment": "container" if Path("/.dockerenv").exists() else "native", "elevated": bool(getattr(os, "geteuid", lambda: -1)() == 0), "user": getpass.getuser() or "unknown"},
        "run": {"started_at": now(), "finished_at": now(), "complete": not load_errors and len(controls) == len(rules), "total_controls": len(rules), "evaluated": len(controls), "engine": "network-junos", "engine_version": ENGINE_VERSION},
        "summary": summary,
        "controls": controls,
        "security_model": normalize_junos(statements),
    }
    if load_errors:
        for error in load_errors:
            print(f"LOAD ERROR: {error}", file=sys.stderr)
    Path(args.output).write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Run {'COMPLETE' if results['run']['complete'] else 'INCOMPLETE'}: evaluated {len(controls)}/{len(rules)} controls (pass={summary['pass']} fail={summary['fail']} error={summary['error']})", file=sys.stderr)
    return 0 if results["run"]["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
