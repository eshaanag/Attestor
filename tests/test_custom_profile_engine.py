"""Organization-defined custom profile engine tests on genuine Cisco corpus."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ai.vendor_training import TRAINING_NORMALIZATION_VERSION, collect_training_patterns
from engines.network.custom import CustomProfileError, audit_custom_profile


CORPUS = Path("tests/fixtures/network/cisco_ios")
PRESENT = CORPUS / "c4geeks_snmp_syslog_router_ios152.txt"
ABSENT = CORPUS / "c4geeks_base_router_iosv.txt"


def _profile(status: str = "published") -> dict:
    source_text = (CORPUS / "SOURCES.md").read_bytes()
    patterns = collect_training_patterns(PRESENT.read_text(), "Cisco", "IOS 15.2")
    timestamp_pattern = next(
        item["pattern"]
        for item in patterns
        if item["pattern"] == "service timestamps log datetime msec"
    )
    community_pattern = next(
        item["pattern"]
        for item in patterns
        if item["pattern"].startswith("snmp-server community ")
    )
    return {
        "profile_id": "profile-source-backed-test",
        "name": "Source-backed operator test profile",
        "vendor": "Cisco",
        "platform": "IOS 15.2",
        "normalization_version": TRAINING_NORMALIZATION_VERSION,
        "status": status,
        "source": {
            "filename": "SOURCES.md",
            "content_sha256": hashlib.sha256(source_text).hexdigest(),
        },
        "rules": [
            {
                "rule_id": "ORG-LOG-1",
                "title": "Require timestamped log messages",
                "category": "logging",
                "pattern_hash": "a" * 64,
                "pattern": timestamp_pattern,
                "secure_when": "present",
                "severity": "medium",
                "framework": "Organization baseline",
                "framework_control_id": "LOG-1",
                "source_reference": "Phase B Cisco corpus SOURCES.md and linked upstream configuration",
                "remediation": "Configure the source-documented timestamp command and verify the running configuration.",
                "enabled": True,
            },
            {
                "rule_id": "ORG-SNMP-1",
                "title": "Disallow the trained SNMP community pattern",
                "category": "access-control",
                "pattern_hash": "b" * 64,
                "pattern": community_pattern,
                "secure_when": "absent",
                "severity": "high",
                "framework": "Organization baseline",
                "framework_control_id": "SNMP-1",
                "source_reference": "Phase B Cisco corpus SOURCES.md and linked upstream configuration",
                "remediation": "Remove the source-documented community command after validating operational impact.",
                "enabled": True,
            },
        ],
    }


def test_custom_profile_proves_pass_and_fail_states_on_genuine_configs():
    present = audit_custom_profile(PRESENT.read_text(), _profile(), device_id="source-config-present")
    absent = audit_custom_profile(ABSENT.read_text(), _profile(), device_id="source-config-absent")

    assert present["summary"] == {
        "pass": 1, "fail": 1, "error": 0, "manual": 0, "not_applicable": 0
    }
    assert absent["summary"] == {
        "pass": 1, "fail": 1, "error": 0, "manual": 0, "not_applicable": 0
    }
    present_by_rule = {item["rule_id"]: item for item in present["controls"]}
    absent_by_rule = {item["rule_id"]: item for item in absent["controls"]}
    assert present_by_rule["ORG-LOG-1"]["status"] == "pass"
    assert absent_by_rule["ORG-LOG-1"]["status"] == "fail"
    assert present_by_rule["ORG-SNMP-1"]["status"] == "fail"
    assert absent_by_rule["ORG-SNMP-1"]["status"] == "pass"
    assert all(item["verification_status"] == "organization_defined" for item in present["controls"])


def test_custom_profile_rejects_unpublished_empty_or_unsourced_profiles():
    with pytest.raises(CustomProfileError, match="not published"):
        audit_custom_profile(PRESENT.read_text(), _profile("draft"), device_id="device")
    empty = _profile()
    empty["rules"] = []
    with pytest.raises(CustomProfileError, match="no enabled rules"):
        audit_custom_profile(PRESENT.read_text(), empty, device_id="device")
    unsourced = _profile()
    unsourced["source"] = None
    with pytest.raises(CustomProfileError, match="no attached knowledge source"):
        audit_custom_profile(PRESENT.read_text(), unsourced, device_id="device")
    incompatible = _profile()
    incompatible["normalization_version"] = "future-normalizer-v2"
    with pytest.raises(CustomProfileError, match="normalization version is unsupported"):
        audit_custom_profile(PRESENT.read_text(), incompatible, device_id="device")
