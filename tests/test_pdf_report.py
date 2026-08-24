"""G' PDF and cached remediation tests."""
from __future__ import annotations

import json

from report.generate_pdf import build_pdf
from report.remediation import RemediationStore, remediation_for_failed_controls


def _results():
    return {
        "report_id": "pdf-test",
        "device": {"device_id": "R1", "hostname": "R1", "vendor": "Cisco", "platform": "IOS", "config_sha256": "a" * 64},
        "host": {"hostname": "runner"},
        "summary": {"pass": 0, "fail": 1, "error": 0, "manual": 0, "not_applicable": 0},
        "controls": [{
            "rule_id": "2.6.1", "title": "Ensure SSH version 2 is configured", "severity": "high",
            "status": "fail", "evidence_summary": "no active-line match", "remediation": "Configure SSHv2.",
            "device": {"vendor": "Cisco", "platform": "IOS"},
        }],
    }


def test_pdf_renders_failed_control_and_dry_run_remediation(tmp_path):
    output = tmp_path / "report.pdf"
    result = build_pdf(_results(), output, state_dir=tmp_path / "state")
    assert output.read_bytes().startswith(b"%PDF")
    assert result["failed_controls"] == 1
    assert result["remediations"][0]["mode"] == "dry-run"
    assert "DRY-RUN" in result["remediations"][0]["text"]
    assert "DRY-RUN" in result["remediations"][0]["reasoning"]


def test_remediation_cache_key_is_vendor_platform_rule_and_real_entries_are_reused(tmp_path):
    store = RemediationStore(tmp_path)
    store.put("Cisco|IOS|2.6.1", {
        "cache_key": "Cisco|IOS|2.6.1", "text": "Configure SSHv2 and verify.",
        "reasoning": "SSHv2 removes the obsolete SSHv1 protocol.",
        "mode": "real-api", "provider": "anthropic", "source": "provider", "ai_generated": True,
    })
    second = remediation_for_failed_controls(_results()["controls"], RemediationStore(tmp_path))
    assert second[0]["cache_key"] == "Cisco|IOS|2.6.1"
    assert second[0]["mode"] == "cache"
    assert second[0]["text"] == "Configure SSHv2 and verify."
    assert second[0]["reasoning"] == "SSHv2 removes the obsolete SSHv1 protocol."


def test_real_remediation_context_excludes_evidence_and_config_values():
    from report.remediation import _redact_remediation_context
    context = _redact_remediation_context(_results()["controls"][0])
    assert "no active-line match" not in context
    assert "2.6.1" in context


def test_real_remediation_persists_reasoning_and_rule_metadata(tmp_path, monkeypatch):
    import report.remediation as module

    body = {
        "content": [{"text": json.dumps({
            "remediation": "configure terminal\nip ssh version 2",
            "reasoning": "SSHv2 disables the obsolete protocol version.",
        })}],
        "usage": {"input_tokens": 10, "output_tokens": 12},
    }

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(body).encode("utf-8")

    monkeypatch.setattr(module.urllib.request, "urlopen", lambda *args, **kwargs: FakeResponse())
    store = RemediationStore(tmp_path)
    result = remediation_for_failed_controls(
        _results()["controls"], store, real_api=True, max_calls=1, api_key="test-key"
    )[0]
    persisted = json.loads((tmp_path / "remediations.json").read_text())["Cisco|IOS|2.6.1"]
    assert result["reasoning"] == "SSHv2 disables the obsolete protocol version."
    assert persisted["rule_id"] == "2.6.1"
    assert persisted["title"] == "Ensure SSH version 2 is configured"
