"""Fail-closed engine for published organization-defined flat vendor profiles."""
from __future__ import annotations

import getpass
import hashlib
import platform as host_platform
import socket
import uuid
from datetime import datetime, timezone
from typing import Any

from ai.vendor_training import TRAINING_NORMALIZATION_VERSION, collect_training_patterns


class CustomProfileError(ValueError):
    """Raised when a custom profile or input cannot be evaluated reliably."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def audit_custom_profile(
    config_text: str,
    profile: dict[str, Any],
    *,
    device_id: str,
    config_sha256: str | None = None,
) -> dict[str, Any]:
    """Evaluate exact redacted-line rules from a published custom profile."""
    if not isinstance(config_text, str) or not config_text.strip():
        raise CustomProfileError("configuration text is empty")
    if profile.get("status") != "published":
        raise CustomProfileError("custom vendor profile is not published")
    vendor = str(profile.get("vendor", "")).strip()
    platform = str(profile.get("platform", "")).strip()
    profile_id = str(profile.get("profile_id", "")).strip()
    if not vendor or not platform or not profile_id:
        raise CustomProfileError("custom vendor profile identity is incomplete")
    if profile.get("normalization_version") != TRAINING_NORMALIZATION_VERSION:
        raise CustomProfileError(
            "custom vendor profile normalization version is unsupported; review and republish it"
        )
    rules = [rule for rule in profile.get("rules", []) if rule.get("enabled", True)]
    if not rules:
        raise CustomProfileError("custom vendor profile has no enabled rules")
    source = profile.get("source") or {}
    if not source.get("content_sha256"):
        raise CustomProfileError("custom vendor profile has no attached knowledge source")

    started = _now()
    observed_patterns = {
        item["pattern"]
        for item in collect_training_patterns(config_text, vendor, platform)
        if not item["structural"]
    }
    controls = []
    summary = {key: 0 for key in ("pass", "fail", "error", "manual", "not_applicable")}
    for index, rule in enumerate(rules):
        pattern = str(rule.get("pattern", "")).strip()
        secure_when = rule.get("secure_when")
        if not pattern or secure_when not in {"present", "absent"}:
            raise CustomProfileError(f"malformed custom rule: {rule.get('rule_id', index)}")
        observed = pattern in observed_patterns
        passed = observed if secure_when == "present" else not observed
        status = "pass" if passed else "fail"
        summary[status] += 1
        expectation = "present" if secure_when == "present" else "absent"
        evidence = (
            f"Exact redacted pattern was {'observed' if observed else 'not observed'}; "
            f"organization-defined secure state requires it to be {expectation}."
        )
        mappings = []
        if rule.get("framework") and rule.get("framework_control_id"):
            mappings.append({
                "framework": rule["framework"],
                "control_id": rule["framework_control_id"],
                "relationship": "operator-defined mapping; not Attestor-verified equivalence",
                "source": rule["source_reference"],
            })
        device_rule = {
            "vendor": vendor,
            "platform": platform,
            "roles": ["organization_defined"],
            "config_format": "saved_configuration",
        }
        controls.append({
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "level": 1,
            "profile": ["network_device"],
            "device": device_rule,
            "framework_mappings": mappings,
            "severity": rule["severity"],
            "automated": True,
            "status": status,
            "verification_status": "organization_defined",
            "checks": [{
                "check_index": 0,
                "type": "trained_pattern",
                "status": status,
                "actual": observed,
                "expected": secure_when,
                "evidence": evidence,
                "timestamp": _now(),
            }],
            "evidence_summary": evidence,
            "remediation": rule["remediation"],
            "source": rule["source_reference"],
        })

    finished = _now()
    digest = config_sha256 or hashlib.sha256(config_text.encode("utf-8")).hexdigest()
    host = {
        "hostname": socket.gethostname(),
        "os_name": host_platform.system() or "unknown",
        "os_version": host_platform.release() or "unknown",
        "os_id": host_platform.system().casefold() or "unknown",
        "kernel": host_platform.version() or "unknown",
        "arch": host_platform.machine() or "unknown",
        "environment": "native",
        "elevated": False,
        "user": getpass.getuser(),
    }
    return {
        "attestor_format_version": "1.0",
        "report_id": str(uuid.uuid4()),
        "target": f"custom_profile:{profile_id}",
        "benchmark": f"Organization-defined baseline: {profile['name']}",
        "benchmark_version": "1",
        "verification_status": "organization_defined",
        "normalization_version": TRAINING_NORMALIZATION_VERSION,
        "device": {
            "device_id": device_id,
            "hostname": None,
            "vendor": vendor,
            "platform": platform,
            "model": None,
            "roles": ["organization_defined"],
            "config_source": "file",
            "config_sha256": digest,
        },
        "host": host,
        "run": {
            "started_at": started,
            "finished_at": finished,
            "complete": True,
            "total_controls": len(controls),
            "evaluated": len(controls),
            "engine": "network-custom-profile",
            "engine_version": "0.1.0",
        },
        "summary": summary,
        "controls": controls,
    }
