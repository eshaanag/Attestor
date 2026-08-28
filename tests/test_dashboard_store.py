"""Persistent local dashboard-state tests."""
from __future__ import annotations

import pytest

from dashboard.store import DashboardStore


def test_device_record_round_trip_and_update(tmp_path):
    store = DashboardStore(tmp_path / "attestor.db")
    record = {
        "record_id": "record-1",
        "device_id": "edge-01",
        "vendor_key": "cisco_ios",
        "vendor": "Cisco",
        "platform": "IOS-XE",
        "status": "queued",
        "history": [],
    }
    store.upsert_device_record(record)
    record["status"] = "complete"
    record["summary"] = {"pass": 4, "fail": 1, "error": 0}
    store.upsert_device_record(record)

    assert store.get_device_record("record-1") == record
    assert store.load_device_records() == {"record-1": record}

    store.delete_device_record("record-1")
    assert store.get_device_record("record-1") is None


def test_training_patterns_store_only_redacted_values_and_confirm(tmp_path):
    store = DashboardStore(tmp_path / "attestor.db")
    store.create_training_session({
        "session_id": "session-1",
        "vendor": "Example Networks",
        "platform": "ExampleOS",
        "filename": "running.cfg",
        "config_sha256": "a" * 64,
    })
    store.save_training_patterns("session-1", [{
        "pattern_hash": "b" * 64,
        "pattern": "snmp community <REDACTED>",
        "category": "access-control",
        "reasoning": "SNMP access setting",
        "source": "provider",
        "mode": "cache",
        "occurrence_count": 2,
    }])
    store.confirm_training_pattern(
        "session-1", "b" * 64, "authentication", "Confirmed from vendor guide"
    )

    session = store.get_training_session("session-1")
    assert session is not None
    assert session["patterns"] == [{
        "pattern_hash": "b" * 64,
        "pattern": "snmp community <REDACTED>",
        "category": "authentication",
        "reasoning": "SNMP access setting",
        "source": "human_confirmed",
        "mode": "human-confirmed",
        "structural": False,
        "occurrence_count": 2,
        "confirmed": True,
        "note": "Confirmed from vendor guide",
    }]


def test_store_rejects_incomplete_or_invalid_entities(tmp_path):
    store = DashboardStore(tmp_path / "attestor.db")
    with pytest.raises(ValueError, match="missing required fields"):
        store.upsert_device_record({"record_id": "broken"})
    with pytest.raises(ValueError, match="unsupported training status"):
        store.create_training_session({
            "session_id": "s", "vendor": "v", "platform": "p",
            "filename": "f", "config_sha256": "a" * 64, "status": "complete",
        })
    with pytest.raises(ValueError, match="unsupported profile status"):
        store.create_vendor_profile({
            "profile_id": "p", "name": "n", "vendor": "v",
            "platform": "x", "status": "verified",
        })


def test_knowledge_source_and_profile_metadata_are_persisted(tmp_path):
    store = DashboardStore(tmp_path / "attestor.db")
    store.add_knowledge_source({
        "source_id": "source-1",
        "vendor": "Example Networks",
        "platform": "ExampleOS",
        "filename": "cli-reference.txt",
        "media_type": "text/plain",
        "content_sha256": "c" * 64,
        "excerpt": "Example command reference excerpt",
    })
    store.create_vendor_profile({
        "profile_id": "profile-1",
        "name": "Example organization baseline",
        "vendor": "Example Networks",
        "platform": "ExampleOS",
        "source_id": "source-1",
        "status": "draft",
    })

    with store._connection() as connection:
        source_count = connection.execute("SELECT COUNT(*) FROM knowledge_sources").fetchone()[0]
        profile = connection.execute(
            "SELECT name, status, source_id FROM vendor_profiles WHERE profile_id = 'profile-1'"
        ).fetchone()
    assert source_count == 1
    assert tuple(profile) == ("Example organization baseline", "draft", "source-1")


def test_profile_rule_publication_lifecycle_is_transactional(tmp_path):
    store = DashboardStore(tmp_path / "attestor.db")
    store.add_knowledge_source({
        "source_id": "source-1",
        "vendor": "Cisco",
        "platform": "IOS 15.2 reference corpus",
        "filename": "SOURCES.md",
        "media_type": "text/markdown",
        "content_sha256": "c" * 64,
        "excerpt": "C4Geeks Cisco IOS reference corpus source manifest.",
    })
    store.create_vendor_profile({
        "profile_id": "profile-1",
        "name": "C4Geeks IOS organization baseline",
        "vendor": "Cisco",
        "platform": "IOS 15.2 reference corpus",
        "source_id": "source-1",
        "status": "draft",
    })
    with pytest.raises(ValueError, match="at least one enabled rule"):
        store.publish_vendor_profile("profile-1")

    store.add_profile_rule({
        "rule_id": "ORG-CISCO-001",
        "profile_id": "profile-1",
        "title": "Require millisecond log timestamps",
        "category": "logging",
        "pattern_hash": "d" * 64,
        "pattern": "service timestamps log datetime msec",
        "secure_when": "present",
        "severity": "medium",
        "framework": "Organization baseline",
        "framework_control_id": "LOG-1",
        "source_reference": "SOURCES.md; c4geeks_snmp_syslog_router_ios152.txt",
        "remediation": "Apply the source-documented configuration after operator review.",
    })
    store.publish_vendor_profile("profile-1")

    profile = store.get_vendor_profile("profile-1")
    assert profile is not None
    assert profile["status"] == "published"
    assert len(profile["rules"]) == 1
    assert store.list_vendor_profiles()[0]["rule_count"] == 1
    with pytest.raises(ValueError, match="cannot be edited"):
        store.add_profile_rule({
            **profile["rules"][0],
            "rule_id": "ORG-CISCO-002",
            "pattern_hash": "e" * 64,
            "pattern": "service timestamps debug datetime msec",
        })
    with pytest.raises(ValueError, match="only draft profiles"):
        store.publish_vendor_profile("profile-1")


def test_provider_suggestions_and_usage_are_persisted_but_not_confirmed(tmp_path):
    store = DashboardStore(tmp_path / "attestor.db")
    for session_id in ("session-1", "session-2"):
        store.create_training_session({
            "session_id": session_id,
            "vendor": "Cisco",
            "platform": "IOS 15.2 reference corpus",
            "filename": "c4geeks_snmp_syslog_router_ios152.txt",
            "config_sha256": "a" * 64,
        })
        store.save_training_patterns(session_id, [{
            "pattern_hash": "b" * 64,
            "pattern": "service timestamps log datetime msec",
            "category": "unknown",
            "reasoning": "DRY-RUN: no provider call made.",
            "source": "dry_run_placeholder",
            "mode": "dry-run",
        }])

    assert store.find_prior_training_pattern(
        "Cisco", "IOS 15.2 reference corpus", "b" * 64
    ) is None
    store.update_training_classifications("session-1", [{
        "pattern_hash": "b" * 64,
        "category": "logging",
        "reasoning": "Configures timestamp precision for log records.",
        "source": "provider",
        "mode": "real-api",
    }])
    store.record_training_api_run({
        "run_id": "run-1",
        "session_id": "session-1",
        "model": "claude-haiku-4-5-20251001",
        "call_count": 1,
        "input_tokens": 42,
        "output_tokens": 9,
        "cost_usd": 0.000087,
    })

    prior = store.find_prior_training_pattern(
        "Cisco", "IOS 15.2 reference corpus", "b" * 64
    )
    session = store.get_training_session("session-1")
    assert prior is not None
    assert prior["category"] == "logging"
    assert prior["confirmed"] is False
    assert prior["source"] == "provider"
    assert session is not None
    assert session["patterns"][0]["confirmed"] is False
    assert session["api_runs"] == [{
        "run_id": "run-1",
        "model": "claude-haiku-4-5-20251001",
        "call_count": 1,
        "input_tokens": 42,
        "output_tokens": 9,
        "cost_usd": 0.000087,
        "created_at": session["api_runs"][0]["created_at"],
    }]
