"""Vendor-neutral Training Studio helper tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai.vendor_training import (
    classify_patterns,
    collect_training_patterns,
    extract_knowledge_text,
    training_pattern_hash,
)


CISCO_CONFIG = Path("tests/fixtures/network/cisco_ios/c4geeks_snmp_syslog_router_ios152.txt")
CISCO_BASE = Path("tests/fixtures/network/cisco_ios/c4geeks_base_router_iosv.txt")


def test_training_patterns_are_vendor_scoped_and_redacted():
    patterns = collect_training_patterns(CISCO_CONFIG.read_text(), "Cisco", "IOS 15.2")
    serialized = json.dumps(patterns)
    assert "CFG-RO" not in serialized
    assert "10.20.20.50" not in serialized
    assert "noc@example.com" not in serialized
    assert "hostname R1" not in serialized
    timestamps = next(
        item for item in patterns if item["pattern"] == "service timestamps log datetime msec"
    )
    assert timestamps["occurrence_count"] == 1
    assert training_pattern_hash("Cisco", "IOS", timestamps["pattern"]) != training_pattern_hash(
        "Juniper", "Junos", timestamps["pattern"]
    )


def test_dry_run_and_prior_confirmation_require_no_provider_call():
    patterns = collect_training_patterns(CISCO_CONFIG.read_text(), "Cisco", "IOS")
    target = next(
        item for item in patterns if item["pattern"] == "service timestamps log datetime msec"
    )

    def lookup(vendor, platform, digest):
        if digest != target["pattern_hash"]:
            return None
        return {
            "pattern_hash": digest,
            "pattern": target["pattern"],
            "category": "logging",
            "reasoning": "Confirmed by operator",
            "source": "human_confirmed",
            "confirmed": True,
            "note": "vendor guide",
            "structural": False,
            "occurrence_count": 1,
        }

    classified = classify_patterns(patterns, "Cisco", "IOS", lookup)
    result = next(item for item in classified if item["pattern_hash"] == target["pattern_hash"])
    assert result["mode"] == "human-confirmed"
    assert result["category"] == "logging"


def test_real_mode_refuses_missing_key_or_insufficient_cap():
    patterns = collect_training_patterns(CISCO_CONFIG.read_text(), "Cisco", "IOS")
    lookup = lambda *args: None
    with pytest.raises(Exception, match="requires ANTHROPIC_API_KEY"):
        classify_patterns(patterns, "Cisco", "IOS", lookup, real_api=True, max_calls=1)
    with pytest.raises(Exception, match="exceed max_calls=0"):
        classify_patterns(
            patterns, "Cisco", "IOS", lookup, real_api=True, max_calls=0, api_key="not-used"
        )


def test_text_knowledge_extraction_redacts_sensitive_examples():
    extracted = extract_knowledge_text(CISCO_BASE.name, CISCO_BASE.read_bytes())
    assert "Cisc0-Lab!" not in extracted
    assert "Adm1n-Lab!" not in extracted
    assert "192.168.10.1" not in extracted
    assert "<REDACTED>" in extracted
    assert "<IP>" in extracted
