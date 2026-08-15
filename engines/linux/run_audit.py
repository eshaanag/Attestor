#!/usr/bin/env python3
"""Attestor — Linux audit engine (Phase 1 skeleton).

Loads a rule pack, validates every rule against schema/rule_schema.json (reusing
tests/validate_rules.py — no duplicated validation logic), dispatches each check
to its check_type handler, streams one NDJSON line per check to **stdout** as it
completes (docs/interfaces.md §1), and writes the final aggregated
**results.json** (docs/interfaces.md §3) to --output.

Phase 1 scope (this skeleton):
  * IMPLEMENTED check_types: ``sysctl``, ``file_permission``.
  * STUBBED check_types (raise NotImplementedError, surfaced as status=error,
    never a silent no-op / false pass): ``kernel_module``, ``package_installed``,
    ``service_state``, ``config_grep``. (``registry``/``account_policy``/``secpol``/
    ``audit_policy`` are Windows-only and not dispatched here.)

NOTHING here is "verified". Correctness of any control is only established by
running against a real Ubuntu 22.04 VM (Phase 1 exit condition). This file being
runnable on macOS only proves the plumbing, not control accuracy.

Streams:
  * stdout  → live NDJSON, one per-check object per line (for the GUI/CLI).
  * <output file> → final results.json (for report generator + ledger).
  * stderr  → diagnostics, load errors, end-of-run summary.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import socket
import stat as stat_module
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

# Reuse the schema-validation logic — do NOT duplicate it (task requirement).
from tests.validate_rules import load_validator, format_errors  # noqa: E402

import yaml  # noqa: E402  (pyyaml; already a project dependency)

ENGINE_NAME = "linux"
ENGINE_VERSION = "0.1.0"
ATTESTOR_FORMAT_VERSION = "1.0"

VALID_STATUSES = {"pass", "fail", "error", "manual", "not_applicable"}


# ───────────────────────────── helpers ──────────────────────────────

def _now() -> str:
    """UTC ISO-8601, second precision, 'Z' suffix (docs/interfaces.md §0)."""
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
    """Build a per-check result object (docs/interfaces.md §1). Enforces invariants."""
    assert status in VALID_STATUSES, f"illegal status {status!r}"  # never emit an off-contract status
    assert evidence, "evidence must never be empty"
    obj: dict[str, Any] = {
        "rule_id": rule_id,
        "check_index": check_index,
        "status": status,
        "actual": actual,
        "expected": expected,
        "evidence": evidence,
        "timestamp": _now(),
    }
    if status == "error":
        # error MUST carry a reason; other statuses MUST NOT include the field.
        obj["error"] = error or "unspecified error"
    return obj


# ───────────────────────── check dispatchers ─────────────────────────
# Each returns a §1 per-check result dict. A dispatcher may raise; run_check()
# converts any raise into status=error. There is NO default-pass path anywhere.

def check_sysctl(rule_id: str, idx: int, check: dict[str, Any]) -> dict[str, Any]:
    key = check.get("key")
    expected = check.get("expected")
    op = check.get("op", "equals")
    if not key:
        return _check_result(rule_id, idx, "error", None, expected,
                             "sysctl check missing required 'key' param",
                             error="malformed rule: 'key' is required for sysctl")

    cmd = ["sysctl", "-n", str(key)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return _check_result(rule_id, idx, "error", None, expected,
                             f"ran: {' '.join(cmd)}", error="sysctl binary not found")
    except subprocess.TimeoutExpired:
        return _check_result(rule_id, idx, "error", None, expected,
                             f"ran: {' '.join(cmd)}", error="sysctl timed out")

    observed = proc.returncode == 0
    actual = proc.stdout.strip() if observed else None
    raw = (proc.stdout or proc.stderr).strip()
    evidence = f"{' '.join(cmd)} => {raw or '(no output)'}"

    if op in ("equals", "matches", "present") and not observed:
        # Could not read the value → error, never pass/fail.
        return _check_result(rule_id, idx, "error", None, expected, evidence,
                             error=f"sysctl exit {proc.returncode}: {proc.stderr.strip() or 'unreadable'}")

    if op == "equals":
        status = "pass" if actual == str(expected) else "fail"
    elif op == "matches":
        status = "pass" if re.search(str(expected), actual or "") else "fail"
    elif op == "present":
        status = "pass"  # observed==True reached here
    else:
        # 'absent' (and any other) not meaningful/implemented for sysctl yet.
        raise NotImplementedError(f"sysctl op '{op}' not implemented")

    return _check_result(rule_id, idx, status, actual, expected, evidence)


def check_file_permission(rule_id: str, idx: int, check: dict[str, Any]) -> dict[str, Any]:
    path = check.get("path")
    op = check.get("op", "equals")
    expected_mode = check.get("expected")  # e.g. "0600" / "600"
    expected_owner = check.get("owner")
    expected_group = check.get("group")
    if not path:
        return _check_result(rule_id, idx, "error", None, expected_mode,
                             "file_permission check missing required 'path' param",
                             error="malformed rule: 'path' is required for file_permission")

    try:
        st = os.stat(path)  # follows symlinks; controls needing lstat can specify later
    except FileNotFoundError:
        if op == "absent":
            return _check_result(rule_id, idx, "pass", "absent", "absent",
                                 f"stat {path} => not present")
        # For equals/present, a missing file cannot be verified as compliant →
        # error (conservative; never a false pass). Real rule semantics may refine.
        return _check_result(rule_id, idx, "error", None, expected_mode,
                             f"stat {path} => not present",
                             error=f"path not found: {path}")
    except PermissionError as exc:
        return _check_result(rule_id, idx, "error", None, expected_mode,
                             f"stat {path}", error=f"permission denied: {exc}")

    mode = oct(stat_module.S_IMODE(st.st_mode))[2:].zfill(4)  # e.g. "0600"
    owner = _uid_name(st.st_uid)
    group = _gid_name(st.st_gid)
    evidence = f"stat {path} => mode={mode} owner={owner} group={group}"

    if op == "present":
        return _check_result(rule_id, idx, "pass", mode, "present", evidence)
    if op == "absent":
        return _check_result(rule_id, idx, "fail", mode, "absent", evidence)
    if op != "equals":
        raise NotImplementedError(f"file_permission op '{op}' not implemented")

    # op == equals: mode must match (if given); owner/group must match (if given).
    ok = True
    if expected_mode is not None:
        ok = ok and (_norm_mode(mode) == _norm_mode(str(expected_mode)))
    if expected_owner is not None:
        ok = ok and (owner == str(expected_owner))
    if expected_group is not None:
        ok = ok and (group == str(expected_group))
    expected_summary = _expected_summary(expected_mode, expected_owner, expected_group)
    return _check_result(rule_id, idx, "pass" if ok else "fail", mode, expected_summary, evidence)


def _norm_mode(m: str) -> str:
    """Normalize a mode string for comparison: strip 0o/leading zeros → int-compare."""
    m = m.strip().lower()
    if m.startswith("0o"):
        m = m[2:]
    return str(int(m, 8))


def _uid_name(uid: int) -> str:
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        return str(uid)


def _gid_name(gid: int) -> str:
    try:
        import grp
        return grp.getgrgid(gid).gr_name
    except (ImportError, KeyError):
        return str(gid)


def _expected_summary(mode: Any, owner: Any, group: Any) -> str:
    parts = []
    if mode is not None:
        parts.append(f"mode={mode}")
    if owner is not None:
        parts.append(f"owner={owner}")
    if group is not None:
        parts.append(f"group={group}")
    return " ".join(parts) if parts else None


def check_kernel_module(rule_id: str, idx: int, check: dict[str, Any]) -> dict[str, Any]:
    name = check.get("name")
    op = check.get("op", "absent")  # CIS typically wants modules absent/disabled
    if not name:
        return _check_result(rule_id, idx, "error", None, None,
                             "kernel_module check missing required 'name' param",
                             error="malformed rule: 'name' is required for kernel_module")

    evidence_parts = []
    # Check 1: is it currently loaded?
    try:
        proc = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=15)
        loaded = any(line.split()[0] == name for line in proc.stdout.splitlines()[1:] if line.strip())
        evidence_parts.append(f"lsmod | grep {name} => {'loaded' if loaded else 'not loaded'}")
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return _check_result(rule_id, idx, "error", None, op,
                             f"lsmod failed", error=str(exc))

    # Check 2: is it disabled in modprobe config?
    try:
        proc2 = subprocess.run(["modprobe", "-n", "-v", name],
                               capture_output=True, text=True, timeout=15)
        output = proc2.stdout.strip()
        disabled = bool(re.search(r'install\s+/bin/(true|false)', output))
        evidence_parts.append(f"modprobe -n -v {name} => {output or '(empty)'}")
    except FileNotFoundError:
        return _check_result(rule_id, idx, "error", None, op,
                             " ; ".join(evidence_parts), error="modprobe binary not found")
    except subprocess.TimeoutExpired:
        return _check_result(rule_id, idx, "error", None, op,
                             " ; ".join(evidence_parts), error="modprobe timed out")

    evidence = " ; ".join(evidence_parts)
    actual = "loaded" if loaded else ("disabled" if disabled else "available")

    if op == "absent":
        # Module should be not loaded AND disabled in config
        status = "pass" if (not loaded and disabled) else "fail"
    elif op == "present":
        status = "pass" if loaded else "fail"
    else:
        raise NotImplementedError(f"kernel_module op '{op}' not implemented")

    return _check_result(rule_id, idx, status, actual, op, evidence)


def check_package_installed(rule_id: str, idx: int, check: dict[str, Any]) -> dict[str, Any]:
    name = check.get("name")
    op = check.get("op", "present")
    if not name:
        return _check_result(rule_id, idx, "error", None, op,
                             "package_installed check missing required 'name' param",
                             error="malformed rule: 'name' is required for package_installed")

    cmd = ["dpkg-query", "-W", "-f=${Status}", name]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return _check_result(rule_id, idx, "error", None, op,
                             f"ran: {' '.join(cmd)}", error="dpkg-query not found")
    except subprocess.TimeoutExpired:
        return _check_result(rule_id, idx, "error", None, op,
                             f"ran: {' '.join(cmd)}", error="dpkg-query timed out")

    installed = proc.returncode == 0 and "install ok installed" in proc.stdout
    actual = "installed" if installed else "not installed"
    evidence = f"dpkg-query -W {name} => {proc.stdout.strip() or proc.stderr.strip() or '(not found)'}"

    if op == "present":
        status = "pass" if installed else "fail"
    elif op == "absent":
        status = "pass" if not installed else "fail"
    else:
        raise NotImplementedError(f"package_installed op '{op}' not implemented")

    return _check_result(rule_id, idx, status, actual, op, evidence)


def check_service_state(rule_id: str, idx: int, check: dict[str, Any]) -> dict[str, Any]:
    name = check.get("name")
    expected = check.get("expected")  # "enabled", "disabled", "masked"
    op = check.get("op", "equals")
    if not name:
        return _check_result(rule_id, idx, "error", None, expected,
                             "service_state check missing required 'name' param",
                             error="malformed rule: 'name' is required for service_state")

    cmd = ["systemctl", "is-enabled", name]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return _check_result(rule_id, idx, "error", None, expected,
                             f"ran: {' '.join(cmd)}", error="systemctl not found")
    except subprocess.TimeoutExpired:
        return _check_result(rule_id, idx, "error", None, expected,
                             f"ran: {' '.join(cmd)}", error="systemctl timed out")

    actual = proc.stdout.strip()
    evidence = f"systemctl is-enabled {name} => {actual or proc.stderr.strip()}"

    # "not-found" means the service doesn't exist
    if "not-found" in actual or "No such file" in proc.stderr:
        # If we expect disabled/masked, a non-existent service can't run → pass
        if expected in ("disabled", "masked"):
            return _check_result(rule_id, idx, "pass", "not-found", expected, evidence)
        else:
            return _check_result(rule_id, idx, "fail", "not-found", expected, evidence)

    if op == "equals":
        # "masked" satisfies "disabled" (stricter), but "disabled" doesn't satisfy "masked"
        if expected == "disabled":
            status = "pass" if actual in ("disabled", "masked") else "fail"
        else:
            status = "pass" if actual == expected else "fail"
    elif op == "matches":
        status = "pass" if re.search(str(expected), actual) else "fail"
    else:
        raise NotImplementedError(f"service_state op '{op}' not implemented")

    return _check_result(rule_id, idx, status, actual, expected, evidence)


def check_config_grep(rule_id: str, idx: int, check: dict[str, Any]) -> dict[str, Any]:
    path = check.get("path")
    pattern = check.get("pattern")
    op = check.get("op", "matches")  # "matches" = pattern found = pass; "absent" = not found = pass
    ignore_comments = check.get("ignore_comments", True)
    if not path or not pattern:
        return _check_result(rule_id, idx, "error", None, pattern,
                             "config_grep check missing required 'path' or 'pattern' param",
                             error="malformed rule: 'path' and 'pattern' are required for config_grep")

    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return _check_result(rule_id, idx, "error", None, pattern,
                             f"read {path}", error=f"file not found: {path}")
    except PermissionError as exc:
        return _check_result(rule_id, idx, "error", None, pattern,
                             f"read {path}", error=f"permission denied: {exc}")

    # Filter comments if requested
    if ignore_comments:
        lines = [l for l in lines if not l.lstrip().startswith("#")]

    # Search for pattern
    matching_lines = [l for l in lines if re.search(pattern, l)]
    found = len(matching_lines) > 0
    actual = matching_lines[0].strip() if matching_lines else None
    evidence = f"grep '{pattern}' {path} => {actual or '(no match)'} ({len(matching_lines)} matches)"

    if op == "matches":
        status = "pass" if found else "fail"
    elif op == "absent":
        status = "pass" if not found else "fail"
    else:
        raise NotImplementedError(f"config_grep op '{op}' not implemented")

    return _check_result(rule_id, idx, status, actual, pattern, evidence)


def _stub(check_type: str) -> Callable[..., dict[str, Any]]:
    def _raise(rule_id: str, idx: int, check: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError(
            f"check_type '{check_type}' is not implemented yet"
        )
    return _raise


# check_type → dispatcher. All Linux types now implemented.
DISPATCH: dict[str, Callable[..., dict[str, Any]]] = {
    "sysctl": check_sysctl,
    "file_permission": check_file_permission,
    "kernel_module": check_kernel_module,
    "package_installed": check_package_installed,
    "service_state": check_service_state,
    "config_grep": check_config_grep,
}


def run_check(rule_id: str, idx: int, check: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one check; any raise (incl. NotImplementedError) → status=error."""
    ctype = check.get("type")
    fn = DISPATCH.get(ctype)
    if fn is None:
        return _check_result(rule_id, idx, "error", None, check.get("expected"),
                             f"no dispatcher for check_type {ctype!r}",
                             error=f"unknown check_type: {ctype!r}")
    try:
        return fn(rule_id, idx, check)
    except NotImplementedError as exc:
        return _check_result(rule_id, idx, "error", None, check.get("expected"),
                             f"check_type {ctype!r} dispatched but not implemented",
                             error=str(exc))
    except Exception as exc:  # defensive: a crashing check must never become pass
        return _check_result(rule_id, idx, "error", None, check.get("expected"),
                             f"check_type {ctype!r} raised during execution",
                             error=f"{type(exc).__name__}: {exc}")


# ───────────────────────── control roll-up ─────────────────────────

def roll_up(automated: bool, check_results: list[dict[str, Any]]) -> str:
    """Control-level status per docs/interfaces.md §2 precedence ladder."""
    if not automated:
        return "manual"
    statuses = [c["status"] for c in check_results]
    if not statuses:
        return "error"  # defensive: automated control with no checks is a bug
    if any(s == "error" for s in statuses):
        return "error"
    if any(s == "fail" for s in statuses):
        return "fail"
    if any(s == "manual" for s in statuses):
        return "manual"
    if all(s == "not_applicable" for s in statuses):
        return "not_applicable"
    return "pass"


def _evidence_summary(control_status: str, automated: bool,
                      check_results: list[dict[str, Any]]) -> str:
    if not automated:
        return "manual review required (control marked automated: false)"
    if not check_results:
        return "engine error: automated control has no checks"
    if control_status == "pass":
        return "; ".join(c["evidence"] for c in check_results)[:500]
    # For non-pass, surface the first offending check.
    order = {"error": 0, "fail": 1, "manual": 2, "not_applicable": 3, "pass": 4}
    worst = min(check_results, key=lambda c: order.get(c["status"], 9))
    detail = worst.get("error") or worst["evidence"]
    return f"[{worst['status']}] {detail}"[:500]


# ───────────────────────── host metadata ─────────────────────────

def gather_host() -> dict[str, Any]:
    os_release = _parse_os_release()
    return {
        "hostname": socket.gethostname(),
        "os_name": os_release.get("NAME", platform.system() or "unknown"),
        "os_version": os_release.get("VERSION_ID", platform.release() or "unknown"),
        "os_id": os_release.get("ID", (platform.system() or "unknown").lower()),
        "kernel": platform.release() or "unknown",
        "arch": platform.machine() or "unknown",
        "environment": _detect_environment(),
        "elevated": _is_elevated(),
        "user": _current_user(),
    }


def _parse_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    data: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                data[k.strip()] = v.strip().strip('"')
    return data


def _detect_environment() -> str:
    try:
        ver = Path("/proc/version").read_text(errors="replace").lower()
        if "microsoft" in ver:
            return "wsl"
    except OSError:
        pass
    if Path("/.dockerenv").exists():
        return "container"
    return "native"


def _is_elevated() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False


def _current_user() -> str:
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


# ───────────────────────── rule loading ─────────────────────────

def load_rules(rule_paths: list[Path]) -> tuple[list[dict[str, Any]], list[str]]:
    """Return (valid_rules, load_errors). Schema-invalid rules are EXCLUDED and
    reported — never silently accepted (architecture §3 step 1)."""
    validator = load_validator()
    valid: list[dict[str, Any]] = []
    errors: list[str] = []
    for path in rule_paths:
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{path.name}: YAML parse error: {exc}")
            continue
        if doc is None:
            errors.append(f"{path.name}: empty file")
            continue
        schema_errors = format_errors(validator, doc)
        if schema_errors:
            errors.append(f"{path.name}: " + "; ".join(schema_errors))
            continue
        valid.append(doc)
    return valid, errors


def evaluate_rule(rule: dict[str, Any], emit: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    """Run all checks for one rule, emit each per-check NDJSON line, return the §2 roll-up."""
    rule_id = rule["id"]
    automated = rule["automated"]
    check_results: list[dict[str, Any]] = []
    if automated:
        for idx, check in enumerate(rule.get("checks", [])):
            result = run_check(rule_id, idx, check)
            emit(result)
            check_results.append(result)
    # automated: false → no checks run, no NDJSON lines (contract §1/§2).

    status = roll_up(automated, check_results)
    return {
        "rule_id": rule_id,
        "title": rule["title"],
        "level": rule["level"],
        "profile": rule["profile"],
        "severity": rule["severity"],
        "automated": automated,
        "status": status,
        "checks": check_results,
        "evidence_summary": _evidence_summary(status, automated, check_results),
        "remediation": rule["remediation"],
        "source": rule["source"],
    }


# ───────────────────────── main ─────────────────────────

def resolve_rule_paths(args: argparse.Namespace) -> list[Path]:
    if args.rule:
        return [Path(p).resolve() for p in args.rule]
    rules_dir = Path(args.rules_dir).resolve() if args.rules_dir \
        else REPO_ROOT / "rules" / args.target
    return sorted(rules_dir.glob("*.yaml"))


def build_results(rules: list[dict[str, Any]], load_errors: list[str],
                  total_selected: int, target: str,
                  started_at: str, controls: list[dict[str, Any]]) -> dict[str, Any]:
    benchmark, benchmark_version = _benchmark_of(rules)
    # interfaces.md §4: engine SHOULD emit controls sorted by rule_id (dotted-int).
    controls = sorted(controls, key=lambda c: tuple(int(p) for p in c["rule_id"].split(".")))
    summary = {s: 0 for s in ("pass", "fail", "error", "manual", "not_applicable")}
    for c in controls:
        summary[c["status"]] += 1
    complete = (len(load_errors) == 0) and (len(controls) == total_selected)
    return {
        "attestor_format_version": ATTESTOR_FORMAT_VERSION,
        "report_id": str(uuid.uuid4()),
        "target": target,
        "benchmark": benchmark,
        "benchmark_version": benchmark_version,
        "host": gather_host(),
        "run": {
            "started_at": started_at,
            "finished_at": _now(),
            "complete": complete,
            "total_controls": total_selected,
            "evaluated": len(controls),
            "engine": ENGINE_NAME,
            "engine_version": ENGINE_VERSION,
        },
        "summary": summary,
        "controls": controls,
    }


def _benchmark_of(rules: list[dict[str, Any]]) -> tuple[str, str]:
    names = {r["benchmark"] for r in rules}
    versions = {r["benchmark_version"] for r in rules}
    if len(names) > 1 or len(versions) > 1:
        print(f"WARNING: mixed benchmark/version across rules: {names} / {versions}",
              file=sys.stderr)
    return (next(iter(names), "unknown"), next(iter(versions), "unknown"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Attestor — CIS Benchmark audit engine for Linux.",
        epilog=(
            "Filter precedence: --include narrows the rule set first (only listed IDs run), "
            "then --exclude removes from that set. --level filters independently (ANDed with "
            "include/exclude). If --include is not specified, all rules in the target are "
            "candidates (minus any --exclude)."
        ),
    )
    parser.add_argument("--target", default="ubuntu2204_desktop",
                        help="rule-pack target under rules/ (default: ubuntu2204_desktop)")
    parser.add_argument("--rules-dir", default=None,
                        help="override rule directory (default: rules/<target>)")
    parser.add_argument("--rule", action="append",
                        help="explicit rule file(s) to run; repeatable. Overrides --rules-dir/--target.")
    parser.add_argument("--level", type=int, choices=[1, 2], default=None,
                        help="filter rules by CIS level (1 or 2). Default: run all levels present.")
    parser.add_argument("--include", nargs="+", metavar="ID", default=None,
                        help="space-separated list of CIS control IDs to include (only these run)")
    parser.add_argument("--exclude", nargs="+", metavar="ID", default=None,
                        help="space-separated list of CIS control IDs to exclude (these are skipped)")
    parser.add_argument("--format", choices=["json", "html", "ndjson"], default="json",
                        help="output format: json (results.json), html (also generates HTML report), "
                             "ndjson (stream only, no file written). Default: json.")
    parser.add_argument("--output", "-o", default="results.json",
                        help="path to write results.json / HTML report (default: ./results.json)")
    parser.add_argument("--blockchain", action="store_true", default=False,
                        help="anchor the report hash to Ethereum Sepolia testnet after audit completes "
                             "(requires ALCHEMY_URL and PRIVATE_KEY env vars)")
    args = parser.parse_args(argv)

    started_at = _now()
    rule_paths = resolve_rule_paths(args)
    if not rule_paths:
        print(f"0 rule files found for target '{args.target}'. Nothing to audit.", file=sys.stderr)

    rules, load_errors = load_rules(rule_paths)
    for err in load_errors:
        print(f"LOAD ERROR (excluded): {err}", file=sys.stderr)

    # --- Apply filters: --level, --include, --exclude ---
    filtered = rules
    if args.level is not None:
        filtered = [r for r in filtered if r.get("level") == args.level]
    if args.include is not None:
        include_set = set(args.include)
        filtered = [r for r in filtered if r["id"] in include_set]
        # Warn about IDs that don't exist in the pack
        found_ids = {r["id"] for r in filtered}
        missing = include_set - found_ids
        if missing:
            print(f"WARNING: --include IDs not found in rule pack: {sorted(missing)}", file=sys.stderr)
    if args.exclude is not None:
        exclude_set = set(args.exclude)
        filtered = [r for r in filtered if r["id"] not in exclude_set]

    rules = filtered
    total_selected = len(rules)

    controls: list[dict[str, Any]] = []

    ndjson_mode = args.format == "ndjson"

    def emit(check_obj: dict[str, Any]) -> None:
        # Live NDJSON line to stdout, one per check as it completes.
        sys.stdout.write(json.dumps(check_obj, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    for rule in rules:
        controls.append(evaluate_rule(rule, emit))

    results = build_results(rules, load_errors, total_selected, args.target,
                            started_at, controls)

    # --- Output handling ---
    if args.format != "ndjson":
        Path(args.output).write_text(
            json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.format == "html":
        # Invoke report generator
        html_path = str(Path(args.output).with_suffix(".html"))
        try:
            sys.path.insert(0, str(REPO_ROOT))
            from report.generate_report import load_results as _lr, render
            html = render(results)
            Path(html_path).write_text(html, encoding="utf-8")
            print(f"HTML report → {html_path}", file=sys.stderr)
        except Exception as exc:
            print(f"WARNING: HTML generation failed: {exc}", file=sys.stderr)

    r = results["run"]
    s = results["summary"]
    print(
        f"\nRun {'COMPLETE' if r['complete'] else 'INCOMPLETE'}: "
        f"evaluated {r['evaluated']}/{r['total_controls']} controls "
        f"(pass={s['pass']} fail={s['fail']} error={s['error']} "
        f"manual={s['manual']} n/a={s['not_applicable']}); "
        f"{len(load_errors)} load error(s)."
        + (f" results.json → {args.output}" if args.format != "ndjson" else ""),
        file=sys.stderr,
    )

    # --- Blockchain anchoring ---
    if args.blockchain and args.format != "ndjson":
        try:
            import os
            from web3 import Web3
            from eth_account import Account

            rpc_url = os.environ.get("ALCHEMY_URL")
            priv_key = os.environ.get("PRIVATE_KEY")
            if not rpc_url or not priv_key:
                print("WARNING: --blockchain requires ALCHEMY_URL and PRIVATE_KEY env vars", file=sys.stderr)
            else:
                # Step 1: Chain the report locally (link to previous)
                sys.path.insert(0, str(REPO_ROOT))
                from ledger.canonical import content_hash
                from ledger.chain import append, verify

                chain_file = REPO_ROOT / "ledger" / "chain.jsonl"
                host_id = results.get("host", {}).get("hostname", "unknown")

                # Append to local chain (links to previous report for this host)
                chain_rec = append(args.output, host_id, chain_path=chain_file)

                print(f"\n🔗 Hash chain:", file=sys.stderr)
                print(f"  Report hash:   0x{chain_rec['content_hash'][:32]}...", file=sys.stderr)
                print(f"  Previous hash: 0x{chain_rec['prev_hash'][:32]}...", file=sys.stderr)
                print(f"  Host: {host_id} | Chain links: {verify(host_id, chain_path=chain_file)['links']}", file=sys.stderr)

                # Step 2: Anchor on Ethereum Sepolia
                w3 = Web3(Web3.HTTPProvider(rpc_url))
                acct = Account.from_key(priv_key)

                contract_file = REPO_ROOT / "ledger" / "contracts" / "sepolia_address.txt"
                if not contract_file.exists():
                    print("WARNING: No Sepolia contract deployed.", file=sys.stderr)
                else:
                    contract_addr = contract_file.read_text().strip()
                    abi = json.loads((REPO_ROOT / "ledger" / "contracts" / "AttestorAnchor.abi.json").read_text())
                    contract = w3.eth.contract(address=contract_addr, abi=abi)

                    root_bytes = bytes.fromhex(chain_rec["content_hash"])
                    prev_bytes = bytes.fromhex(chain_rec["prev_hash"])
                    tx = contract.functions.anchorReport(root_bytes, prev_bytes).build_transaction({
                        "from": acct.address,
                        "nonce": w3.eth.get_transaction_count(acct.address),
                        "gas": 200_000,
                        "gasPrice": w3.eth.gas_price * 2,
                        "chainId": w3.eth.chain_id,
                    })
                    signed = acct.sign_transaction(tx)
                    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
                    print(f"\n⛓️  Anchoring to Ethereum Sepolia...", file=sys.stderr)
                    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                    if receipt.status == 1:
                        print(f"✓ On-chain! https://sepolia.etherscan.io/tx/{tx_hash.hex()}", file=sys.stderr)
                        print(f"  Anyone can verify this report existed at this moment.", file=sys.stderr)
                    else:
                        print(f"✗ Transaction reverted", file=sys.stderr)
        except ImportError:
            print("WARNING: --blockchain requires web3 package. Run: pip install web3", file=sys.stderr)
        except Exception as exc:
            print(f"WARNING: Blockchain anchoring failed: {exc}", file=sys.stderr)

    return 0 if r["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
