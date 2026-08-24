"""F' tests: unmatched corpus inventory and provider-safe training loop."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai.network_discovery import (
    CallBudgetExceeded,
    MappingStore,
    collect_observations,
    classify_candidates,
    inventory_document,
    redact_line,
)


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "network" / "cisco_ios"
RULES = ROOT / "rules" / "cisco_ios"


def test_real_corpus_inventory_has_reproducible_candidate_counts():
    observations, summary = collect_observations(CORPUS, RULES)
    assert summary == {
        "corpus_status": "reference_configs",
        "config_count": 10,
        "active_line_count": 157,
        "deterministic_config_grep_pattern_count": 14,
        "unmatched_occurrence_count": 135,
        "unique_unmatched_pattern_count": 63,
        "structural_unmatched_occurrence_count": 43,
        "structural_unique_pattern_count": 12,
        "candidate_occurrence_count": 92,
        "candidate_unique_pattern_count": 51,
        "normalization_version": "ios-line-v1",
    }
    document = inventory_document(observations, summary)
    assert len(document["patterns"]) == 63
    assert all("<REDACTED>" not in item["pattern_hash"] for item in document["patterns"])


def test_redaction_removes_sensitive_values_before_persistence():
    redacted = redact_line(
        "snmp-server community TESTTOKEN ro 198.51.100.7 contact test@example.invalid"
    )
    assert "TESTTOKEN" not in redacted
    assert "198.51.100.7" not in redacted
    assert "test@example.invalid" not in redacted
    assert redacted == "snmp-server community <REDACTED> ro <IP> contact <EMAIL>"
    assert redact_line("snmp-server host 198.51.100.7 version 2c TESTTOKEN") == (
        "snmp-server host <IP> version 2c <REDACTED>"
    )


def test_dry_run_classification_makes_no_provider_calls_or_cache_files(tmp_path):
    observations, summary = collect_observations(CORPUS, RULES)
    inventory = inventory_document(observations, summary)
    store = MappingStore(tmp_path)
    results = classify_candidates(inventory["patterns"], store, real_api=False)
    assert len(results) == 51
    assert {result["mode"] for result in results} == {"dry-run"}
    assert all(result["source"] == "dry_run_placeholder" for result in results)
    assert not (tmp_path / "classifications.json").exists()
    assert not (tmp_path / "confirmed_mappings.json").exists()


def test_human_confirmation_is_persisted_and_reused_without_provider(tmp_path):
    store = MappingStore(tmp_path)
    digest = store.confirm("service timestamps log datetime msec", "logging", "operator")
    reloaded = MappingStore(tmp_path)
    results = classify_candidates(
        [{
            "pattern_hash": digest,
            "pattern": "service timestamps log datetime msec",
            "structural": False,
            "occurrence_count": 1,
            "occurrences": [],
        }],
        reloaded,
        real_api=False,
    )
    assert results[0]["mode"] == "human-confirmed"
    assert results[0]["category"] == "logging"
    assert json.loads((tmp_path / "confirmed_mappings.json").read_text())[digest]["source"] == "human_confirmed"


def test_real_mode_refuses_to_exceed_call_cap_before_any_request(tmp_path):
    store = MappingStore(tmp_path)
    with pytest.raises(CallBudgetExceeded, match="uncached patterns exceed max_calls=0"):
        classify_candidates(
            [{
                "pattern_hash": "a" * 64,
                "pattern": "service timestamps log datetime msec",
                "structural": False,
                "occurrence_count": 1,
                "occurrences": [],
            }],
            store,
            real_api=True,
            max_calls=0,
            api_key="test-only-not-used",
        )


def test_real_provider_usage_is_recorded_and_costed(monkeypatch):
    from ai import network_discovery as module

    response = {
        "content": [{"text": '{"category":"logging","reasoning":"timestamped log output"}'}],
        "usage": {"input_tokens": 100, "output_tokens": 20},
    }

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(response).encode()

    monkeypatch.setattr(module.urllib.request, "urlopen", lambda *args, **kwargs: FakeResponse())
    result = module._provider_classify("service timestamps log datetime msec", "test", "test-model")
    assert result["usage"] == {"input_tokens": 100, "output_tokens": 20, "cost_usd": 0.0002}


def test_real_provider_accepts_fenced_json(monkeypatch):
    from ai import network_discovery as module

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({
                "content": [{"text": '```json\\n{"category":"logging","reasoning":"logs"}\\n```'}],
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }).encode()

    monkeypatch.setattr(module.urllib.request, "urlopen", lambda *args, **kwargs: FakeResponse())
    assert module._provider_classify("logging buffered 4096", "test", "test-model")["category"] == "logging"
