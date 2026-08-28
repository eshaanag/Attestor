#!/usr/bin/env python3
"""Attestor Fortinet FortiOS vendor-baseline adapter."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import re
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

from engines.network.fortios import FortiOSDocument, matching_paths, parse_config  # noqa: E402
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
        device = rule.get("device", {})
        if "network_device" not in rule.get("profile", []) or device.get("vendor") != "Fortinet":
            errors.append(f"{path}: not a Fortinet network rule")
            continue
        rules.append(rule)
    return rules, errors


def _hostname(text: str, document: FortiOSDocument) -> str | None:
    header = re.search(r"^#\s*Hostname:\s*(.+?)\s*$", text, re.MULTILINE | re.IGNORECASE)
    if header:
        return header.group(1).strip().strip('"')
    for statement in document.statements:
        if statement.path[-1].casefold() == "system global":
            match = re.fullmatch(r"set hostname\s+(.+)", statement.text, re.IGNORECASE)
            if match:
                return match.group(1).strip().strip('"')
    return None


def _platform(text: str) -> tuple[str | None, str | None]:
    version = re.search(r"^#\s*Version:\s*(FortiGate-[^\s]+)\s+v([^,\s]+)", text, re.MULTILINE)
    if version:
        return version.group(1), version.group(2)
    config_version = re.search(r"^#config-version=([^:\s]+)", text, re.MULTILINE)
    return (config_version.group(1), None) if config_version else (None, None)


def _check(rule: dict[str, Any], document: FortiOSDocument) -> dict[str, Any]:
    checks = []
    for index, check in enumerate(rule.get("checks", [])):
        expected = check.get("op")
        base = {
            "rule_id": rule["id"],
            "check_index": index,
            "actual": None,
            "expected": expected,
            "timestamp": now(),
        }
        if check.get("type") != "fortios_statement":
            checks.append({**base, "status": "error", "evidence": "unsupported FortiOS check type", "error": "only fortios_statement is implemented"})
            continue
        try:
            paths = matching_paths(document, check["path_pattern"])
            value_re = re.compile(check["pattern"], re.IGNORECASE)
        except (KeyError, re.error) as exc:
            checks.append({**base, "status": "error", "evidence": "invalid FortiOS matcher", "error": str(exc)})
            continue
        if not paths:
            checks.append({**base, "status": "error", "evidence": "required FortiOS config block was not observed", "error": f"no block matched {check.get('path_pattern')!r}"})
            continue

        target = check["target"]
        if target == "entry":
            matches = [entry for entry in document.entries if entry.path in paths and value_re.fullmatch(entry.name)]
        else:
            matches = [statement for statement in document.statements if statement.path in paths and value_re.fullmatch(statement.text)]

        op = check["op"]
        if op == "all_entries_match":
            if target != "statement":
                checks.append({**base, "status": "error", "evidence": "invalid all-entry target", "error": "all_entries_match requires statement target"})
                continue
            entries = [entry for entry in document.entries if entry.path in paths]
            if not entries:
                checks.append({**base, "status": "error", "evidence": "required FortiOS entries were not observed", "error": "all_entries_match requires at least one entry"})
                continue
            matched_entries = {statement.entry_line for statement in matches}
            missing = [entry for entry in entries if entry.line not in matched_entries]
            passed = not missing
            evidence = (
                f"all {len(entries)} entries have the required statement"
                if passed else f"{len(missing)} of {len(entries)} entries lack the required statement"
            )
            actual = len(entries) - len(missing)
        else:
            passed = bool(matches) if op == "present" else not matches
            evidence = (
                f"{len(matches)} matching {target}(s) observed; first at line {matches[0].line}"
                if matches else f"no matching {target} observed in {len(paths)} required block(s)"
            )
            actual = len(matches)
        checks.append({**base, "status": "pass" if passed else "fail", "actual": actual, "evidence": evidence, "error": None})

    statuses = [check["status"] for check in checks]
    status = "error" if not statuses or "error" in statuses else "fail" if "fail" in statuses else "pass"
    return {
        "rule_id": rule["id"], "rule_namespace": rule.get("id_namespace"),
        "title": rule["title"], "level": rule["level"], "profile": rule["profile"],
        "device": rule["device"], "severity": rule["severity"],
        "automated": rule["automated"], "status": status, "checks": checks,
        "evidence_summary": "; ".join(check["evidence"] for check in checks)[:500],
        "remediation": rule["remediation"], "source": rule["source"],
        "framework_mappings": rule.get("framework_mappings", []),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Attestor - offline Fortinet FortiOS configuration audit")
    parser.add_argument("--config", required=True)
    parser.add_argument("--device-id", default=None)
    parser.add_argument("--rules-dir", default=str(REPO_ROOT / "rules" / "fortinet_fortios"))
    parser.add_argument("--output", "-o", default="results.json")
    args = parser.parse_args(argv)
    path = Path(args.config).expanduser().resolve()
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8-sig")
        document = parse_config(text)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"ERROR: could not read/parse FortiOS config: {exc}", file=sys.stderr)
        return 2
    rules, load_errors = load_rules(Path(args.rules_dir).expanduser().resolve())
    if not rules:
        print("ERROR: no valid FortiOS rules remain", file=sys.stderr)
        return 2
    hostname = _hostname(text, document)
    device_id = args.device_id or hostname
    if not device_id:
        print("ERROR: no FortiOS hostname; provide --device-id", file=sys.stderr)
        return 2
    model, software_version = _platform(text)
    controls = [_check(rule, document) for rule in rules]
    summary = {key: 0 for key in ("pass", "fail", "error", "manual", "not_applicable")}
    for control in controls:
        summary[control["status"]] += 1
    device = {
        "device_id": device_id, "hostname": hostname, "vendor": "Fortinet",
        "platform": "FortiOS", "model": model, "software_version": software_version,
        "serial_number": None, "roles": ["firewall"], "config_source": "file",
        "config_sha256": hashlib.sha256(raw).hexdigest(),
    }
    results = {
        "attestor_format_version": "1.0", "report_id": str(uuid.uuid4()),
        "target": "fortinet_fortios",
        "benchmark": "Fortinet FortiOS Security Baseline (vendor documentation)",
        "benchmark_version": "2026-08", "device": device,
        "host": {"hostname": socket.gethostname(), "os_name": platform.system() or "unknown", "os_version": platform.version() or "unknown", "os_id": (platform.system() or "unknown").lower(), "kernel": platform.release() or "unknown", "arch": platform.machine() or "unknown", "environment": "container" if Path("/.dockerenv").exists() else "native", "elevated": bool(getattr(os, "geteuid", lambda: -1)() == 0), "user": getpass.getuser() or "unknown"},
        "run": {"started_at": now(), "finished_at": now(), "complete": not load_errors and len(controls) == len(rules), "total_controls": len(rules), "evaluated": len(controls), "engine": "network-fortios", "engine_version": ENGINE_VERSION},
        "summary": summary, "controls": controls,
    }
    if load_errors:
        for error in load_errors:
            print(f"LOAD ERROR: {error}", file=sys.stderr)
    Path(args.output).write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Run {'COMPLETE' if results['run']['complete'] else 'INCOMPLETE'}: evaluated {len(controls)}/{len(rules)} controls (pass={summary['pass']} fail={summary['fail']} error={summary['error']})", file=sys.stderr)
    return 0 if results["run"]["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
