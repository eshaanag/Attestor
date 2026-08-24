#!/usr/bin/env python3
"""Attestor Cisco IOS flat-configuration audit engine.

Phase C intentionally supports only whole-file, single-line ``config_grep``
checks. VTY/interface same-block checks are reserved for Phase D. The input is
an existing configuration file; this module does not connect to a device or
simulate an SSH collection flow.
"""
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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tests.validate_rules import format_errors, load_validator  # noqa: E402


ENGINE_NAME = "network"
ENGINE_VERSION = "0.1.0"
ATTESTOR_FORMAT_VERSION = "1.0"
VALID_STATUSES = {"pass", "fail", "error", "manual", "not_applicable"}
WRAPPER_COMMANDS = {"enable", "configure terminal", "end", "write memory"}


class ConfigInputError(RuntimeError):
    """The configuration input could not be read or interpreted safely."""


@dataclass(frozen=True)
class ConfigLine:
    number: int
    raw: str
    normalized: str


@dataclass(frozen=True)
class ConfigDocument:
    path: Path
    raw_bytes: bytes
    sha256: str
    lines: tuple[ConfigLine, ...]

    @property
    def hostname(self) -> str | None:
        for line in self.lines:
            match = re.fullmatch(r"hostname\s+(\S+)", line.normalized, re.IGNORECASE)
            if match:
                return match.group(1)
        return None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_result(
    rule_id: str,
    check_index: int,
    status: str,
    actual: Any,
    expected: Any,
    evidence: str,
    error: str | None = None,
) -> dict[str, Any]:
    assert status in VALID_STATUSES
    assert evidence
    result: dict[str, Any] = {
        "rule_id": rule_id,
        "check_index": check_index,
        "status": status,
        "actual": actual,
        "expected": expected,
        "evidence": evidence,
        "timestamp": _now(),
    }
    if status == "error":
        result["error"] = error or "unspecified error"
    return result


def load_config(path: str | Path) -> ConfigDocument:
    """Read one config exactly once and normalize lines for flat matching.

    SHA-256 covers the original bytes. Only blank lines, IOS ``!`` comments /
    separators, and known paste-script wrapper commands are excluded from the
    logical line view. No configuration command is synthesized.
    """
    resolved = Path(path).expanduser().resolve()
    try:
        raw = resolved.read_bytes()
    except FileNotFoundError as exc:
        raise ConfigInputError(f"config file not found: {resolved}") from exc
    except PermissionError as exc:
        raise ConfigInputError(f"permission denied reading config: {resolved}") from exc
    except IsADirectoryError as exc:
        raise ConfigInputError(f"config path is a directory: {resolved}") from exc
    except OSError as exc:
        raise ConfigInputError(f"could not read config {resolved}: {exc}") from exc

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigInputError(
            f"config is not valid UTF-8/UTF-8-BOM at byte {exc.start}: {resolved}"
        ) from exc

    logical_lines: list[ConfigLine] = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        normalized = raw_line.strip()
        if not normalized or normalized.startswith("!"):
            continue
        if normalized.casefold() in WRAPPER_COMMANDS:
            continue
        logical_lines.append(ConfigLine(number, raw_line, normalized))

    return ConfigDocument(
        path=resolved,
        raw_bytes=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        lines=tuple(logical_lines),
    )


def check_config_grep(
    rule_id: str,
    idx: int,
    check: dict[str, Any],
    config: ConfigDocument,
) -> dict[str, Any]:
    """Evaluate one regex independently against each active config line."""
    pattern = check.get("pattern")
    op = check.get("op", "matches")
    if not isinstance(pattern, str) or not pattern:
        return _check_result(
            rule_id,
            idx,
            "error",
            None,
            pattern,
            "config_grep check missing required non-empty 'pattern'",
            error="malformed rule: 'pattern' is required for network config_grep",
        )
    if op not in {"matches", "present", "absent"}:
        return _check_result(
            rule_id,
            idx,
            "error",
            None,
            pattern,
            f"unsupported network config_grep op: {op!r}",
            error=f"config_grep op {op!r} is not implemented",
        )

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return _check_result(
            rule_id,
            idx,
            "error",
            None,
            pattern,
            f"invalid regex {pattern!r}",
            error=f"regex compile failed: {exc}",
        )

    matches = [line for line in config.lines if regex.search(line.normalized)]
    found = bool(matches)
    first = matches[0] if matches else None
    actual = first.normalized if first else None
    if first:
        observation = f"line {first.number}: {first.raw.strip()}"
    else:
        observation = "(no active-line match)"
    evidence = (
        f"regex {pattern!r} in {config.path} => {observation} "
        f"({len(matches)} match{'es' if len(matches) != 1 else ''})"
    )

    if op in {"matches", "present"}:
        status = "pass" if found else "fail"
    else:
        status = "pass" if not found else "fail"
    return _check_result(rule_id, idx, status, actual, pattern, evidence)


def run_check(
    rule_id: str,
    idx: int,
    check: dict[str, Any],
    config: ConfigDocument,
) -> dict[str, Any]:
    check_type = check.get("type")
    if check_type != "config_grep":
        return _check_result(
            rule_id,
            idx,
            "error",
            None,
            check.get("expected"),
            f"network Phase C has no dispatcher for check_type {check_type!r}",
            error=(
                "only flat config_grep is implemented; config_block and other "
                "types remain outside Phase C"
            ),
        )
    try:
        return check_config_grep(rule_id, idx, check, config)
    except Exception as exc:  # a crashing check must never become a pass
        return _check_result(
            rule_id,
            idx,
            "error",
            None,
            check.get("pattern"),
            "network config_grep raised during execution",
            error=f"{type(exc).__name__}: {exc}",
        )


def roll_up(automated: bool, checks: list[dict[str, Any]]) -> str:
    if not automated:
        return "manual"
    statuses = [check["status"] for check in checks]
    if not statuses or "error" in statuses:
        return "error"
    if "fail" in statuses:
        return "fail"
    if "manual" in statuses:
        return "manual"
    if all(status == "not_applicable" for status in statuses):
        return "not_applicable"
    return "pass"


def _evidence_summary(status: str, automated: bool, checks: list[dict[str, Any]]) -> str:
    if not automated:
        return "manual review required (control marked automated: false)"
    if not checks:
        return "engine error: automated control has no checks"
    if status == "pass":
        return "; ".join(check["evidence"] for check in checks)[:500]
    precedence = {"error": 0, "fail": 1, "manual": 2, "not_applicable": 3, "pass": 4}
    worst = min(checks, key=lambda check: precedence.get(check["status"], 9))
    return f"[{worst['status']}] {worst.get('error') or worst['evidence']}"[:500]


def evaluate_rule(
    rule: dict[str, Any],
    config: ConfigDocument,
    emit: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    automated = rule["automated"]
    check_results: list[dict[str, Any]] = []
    if automated:
        for idx, check in enumerate(rule.get("checks", [])):
            result = run_check(rule["id"], idx, check, config)
            emit(result)
            check_results.append(result)

    status = roll_up(automated, check_results)
    control = {
        "rule_id": rule["id"],
        "title": rule["title"],
        "level": rule["level"],
        "profile": rule["profile"],
        "device": rule["device"],
        "severity": rule["severity"],
        "automated": automated,
        "status": status,
        "checks": check_results,
        "evidence_summary": _evidence_summary(status, automated, check_results),
        "remediation": rule["remediation"],
        "source": rule["source"],
    }
    if "framework_mappings" in rule:
        control["framework_mappings"] = rule["framework_mappings"]
    return control


def load_rules(paths: list[Path]) -> tuple[list[dict[str, Any]], list[str]]:
    validator = load_validator()
    rules: list[dict[str, Any]] = []
    errors: list[str] = []
    for path in paths:
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"{path}: could not load rule: {exc}")
            continue
        schema_errors = format_errors(validator, rule)
        if schema_errors:
            errors.append(f"{path}: " + "; ".join(schema_errors))
            continue
        if "network_device" not in rule["profile"]:
            errors.append(f"{path}: rule is not a network_device rule")
            continue
        rules.append(rule)
    return rules, errors


def gather_host() -> dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "os_name": platform.system() or "unknown",
        "os_version": platform.version() or "unknown",
        "os_id": (platform.system() or "unknown").lower(),
        "kernel": platform.release() or "unknown",
        "arch": platform.machine() or "unknown",
        "environment": "container" if Path("/.dockerenv").exists() else "native",
        "elevated": hasattr(os, "geteuid") and os.geteuid() == 0,
        "user": getpass.getuser() or "unknown",
    }


def build_results(
    rules: list[dict[str, Any]],
    load_errors: list[str],
    config: ConfigDocument,
    device_id: str,
    started_at: str,
    controls: list[dict[str, Any]],
) -> dict[str, Any]:
    names = {rule["benchmark"] for rule in rules}
    versions = {rule["benchmark_version"] for rule in rules}
    benchmark = next(iter(names), "unknown") if len(names) <= 1 else "mixed"
    benchmark_version = next(iter(versions), "unknown") if len(versions) <= 1 else "mixed"
    controls = sorted(
        controls, key=lambda control: tuple(int(part) for part in control["rule_id"].split("."))
    )
    summary = {key: 0 for key in ("pass", "fail", "error", "manual", "not_applicable")}
    for control in controls:
        summary[control["status"]] += 1

    platforms = {rule["device"]["platform"] for rule in rules}
    roles = sorted({role for rule in rules for role in rule["device"].get("roles", [])})
    parsed_hostname = config.hostname
    return {
        "attestor_format_version": ATTESTOR_FORMAT_VERSION,
        "report_id": str(uuid.uuid4()),
        "target": "cisco_ios",
        "benchmark": benchmark,
        "benchmark_version": benchmark_version,
        "device": {
            "device_id": device_id,
            "hostname": parsed_hostname,
            "vendor": "Cisco",
            "platform": next(iter(platforms), "IOS") if len(platforms) <= 1 else "IOS/IOS-XE",
            "model": None,
            "roles": roles,
            "config_source": "file",
            "config_sha256": config.sha256,
        },
        "host": gather_host(),
        "run": {
            "started_at": started_at,
            "finished_at": _now(),
            "complete": not load_errors and len(controls) == len(rules),
            "total_controls": len(rules),
            "evaluated": len(controls),
            "engine": ENGINE_NAME,
            "engine_version": ENGINE_VERSION,
        },
        "summary": summary,
        "controls": controls,
    }


def resolve_rule_paths(args: argparse.Namespace) -> list[Path]:
    if args.rule:
        return [Path(path).expanduser().resolve() for path in args.rule]
    rules_dir = (
        Path(args.rules_dir).expanduser().resolve()
        if args.rules_dir
        else REPO_ROOT / "rules" / "cisco_ios"
    )
    return sorted(rules_dir.glob("*.yaml"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Attestor — offline Cisco IOS flat configuration audit engine (Phase C)."
    )
    parser.add_argument("--config", required=True, help="saved Cisco IOS/IOS-XE config file")
    parser.add_argument("--device-id", default=None, help="stable device ID; defaults to parsed hostname")
    parser.add_argument("--rules-dir", default=None, help="rule directory (default: rules/cisco_ios)")
    parser.add_argument("--rule", action="append", help="explicit rule file; repeatable")
    parser.add_argument("--output", "-o", default="results.json", help="results JSON path")
    parser.add_argument("--format", choices=["json", "ndjson"], default="json")
    args = parser.parse_args(argv)

    started_at = _now()
    rule_paths = resolve_rule_paths(args)
    if not rule_paths:
        print("ERROR: no Cisco IOS rule files selected; production rules are Phase E", file=sys.stderr)
        return 2

    rules, load_errors = load_rules(rule_paths)
    for error in load_errors:
        print(f"LOAD ERROR (excluded): {error}", file=sys.stderr)
    if not rules:
        print("ERROR: no valid network-device rules remain", file=sys.stderr)
        return 2

    try:
        config = load_config(args.config)
    except ConfigInputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    device_id = args.device_id or config.hostname
    if not device_id:
        print("ERROR: no hostname in config; provide --device-id", file=sys.stderr)
        return 2

    def emit(check: dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(check, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    controls = [evaluate_rule(rule, config, emit) for rule in rules]
    results = build_results(rules, load_errors, config, device_id, started_at, controls)
    if args.format == "json":
        output = Path(args.output)
        output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(output, 0o644)

    run = results["run"]
    summary = results["summary"]
    print(
        f"Run {'COMPLETE' if run['complete'] else 'INCOMPLETE'}: "
        f"evaluated {run['evaluated']}/{run['total_controls']} controls "
        f"(pass={summary['pass']} fail={summary['fail']} error={summary['error']})",
        file=sys.stderr,
    )
    return 0 if run["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
