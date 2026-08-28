"""Training Studio dashboard integration tests."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient
from pypdf import PdfReader

import dashboard.app as dashboard
from dashboard.store import DashboardStore
from ai.vendor_training import collect_training_patterns, dry_run_classification


CISCO_CONFIG = Path("tests/fixtures/network/cisco_ios/c4geeks_snmp_syslog_router_ios152.txt")
CISCO_SOURCES = Path("tests/fixtures/network/cisco_ios/SOURCES.md")
JUNOS_CONFIG = Path("tests/fixtures/network/junos/junos_example.conf")
BASE_CISCO_CONFIG = Path("tests/fixtures/network/cisco_ios/c4geeks_base_router_iosv.txt")


def _client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setattr(dashboard, "STORE", DashboardStore(tmp_path / "attestor.db"))
    monkeypatch.setattr(dashboard, "RESULTS_DIR", tmp_path / "reports")
    dashboard.RESULTS_DIR.mkdir()
    dashboard.DEVICE_RECORDS.clear()
    return TestClient(dashboard.app)


def test_training_page_exposes_human_review_workflow(tmp_path, monkeypatch):
    response = _client(tmp_path, monkeypatch).get("/training")
    assert response.status_code == 200
    assert "Training Studio" in response.text
    assert "Vendor documentation" in response.text
    assert "Analyze in dry-run mode" in response.text


def test_training_upload_redacts_before_persistence_and_provider_use(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/api/training/analyze",
        data={"vendor": "Example Networks", "platform": "ExampleOS"},
        files={
            "config_file": (
                CISCO_CONFIG.name,
                CISCO_CONFIG.read_bytes(),
                "text/plain",
            ),
            "knowledge_file": (
                CISCO_SOURCES.name,
                CISCO_SOURCES.read_bytes(),
                "text/plain",
            ),
        },
    )
    assert response.status_code == 200
    assert "Dry-run analysis complete" in response.text
    assert "CFG-RO" not in response.text
    assert "Auth-Pass-2026" not in response.text
    assert "10.20.20.50" not in response.text

    database_bytes = (tmp_path / "attestor.db").read_bytes()
    assert b"CFG-RO" not in database_bytes
    assert b"Auth-Pass-2026" not in database_bytes
    assert b"10.20.20.50" not in database_bytes
    sessions = dashboard.STORE.list_training_sessions()
    assert len(sessions) == 1
    session = dashboard.STORE.get_training_session(sessions[0]["session_id"])
    assert session is not None
    assert session["source_id"]
    assert any("<REDACTED>" in item["pattern"] for item in session["patterns"])
    assert "AI suggestion budget" in response.text
    assert "Estimated Haiku-tier cost" in response.text
    assert "No raw configuration is available" in response.text


def test_confirmed_mapping_is_reused_in_later_session(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    first = client.post(
        "/api/training/analyze",
        data={"vendor": "Juniper", "platform": "Junos"},
        files={"config_file": (JUNOS_CONFIG.name, JUNOS_CONFIG.read_bytes(), "text/plain")},
    )
    assert first.status_code == 200
    session = dashboard.STORE.get_training_session(
        dashboard.STORE.list_training_sessions()[0]["session_id"]
    )
    assert session is not None
    pattern = next(item for item in session["patterns"] if not item["structural"])
    confirmed = client.post(
        f'/training/{session["session_id"]}/patterns/{pattern["pattern_hash"]}/confirm',
        data={"category": "logging", "note": "Confirmed against the source-derived Junos fixture"},
    )
    assert confirmed.status_code == 200
    assert "Mapping confirmed" in confirmed.text

    second = client.post(
        "/api/training/analyze",
        data={"vendor": "Juniper", "platform": "Junos"},
        files={"config_file": (JUNOS_CONFIG.name, JUNOS_CONFIG.read_bytes(), "text/plain")},
    )
    assert second.status_code == 200
    latest = dashboard.STORE.get_training_session(
        dashboard.STORE.list_training_sessions()[0]["session_id"]
    )
    assert latest is not None
    reused = next(
        item for item in latest["patterns"] if item["pattern_hash"] == pattern["pattern_hash"]
    )
    assert reused["category"] == "logging"
    assert reused["confirmed"] is True
    assert reused["source"] == "human_confirmed"


def test_training_rejects_invalid_input_without_creating_session(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    invalid = client.post(
        "/api/training/analyze",
        data={"vendor": "Example", "platform": "OS"},
        files={"config_file": ("broken.cfg", b"\xff\xfe", "application/octet-stream")},
    )
    assert invalid.status_code == 400
    assert "not valid UTF-8" in invalid.text
    assert dashboard.STORE.list_training_sessions() == []


def test_published_profile_audits_genuine_pass_and_fail_configs(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    analyzed = client.post(
        "/api/training/analyze",
        data={"vendor": "Cisco", "platform": "IOS 15.2 reference corpus"},
        files={
            "config_file": (CISCO_CONFIG.name, CISCO_CONFIG.read_bytes(), "text/plain"),
            "knowledge_file": (CISCO_SOURCES.name, CISCO_SOURCES.read_bytes(), "text/markdown"),
        },
    )
    assert analyzed.status_code == 200
    session_id = dashboard.STORE.list_training_sessions()[0]["session_id"]
    session = dashboard.STORE.get_training_session(session_id)
    assert session is not None
    timestamp = next(
        item
        for item in session["patterns"]
        if item["pattern"] == "service timestamps log datetime msec"
    )

    confirmed = client.post(
        f'/training/{session_id}/patterns/{timestamp["pattern_hash"]}/confirm',
        data={
            "category": "logging",
            "note": "Confirmed against the committed C4Geeks Cisco IOS reference corpus.",
        },
    )
    assert confirmed.status_code == 200
    created = client.post(
        f"/training/{session_id}/profiles",
        data={"name": "C4Geeks IOS organization baseline"},
    )
    assert created.status_code == 200
    profile_id = dashboard.STORE.list_vendor_profiles()[0]["profile_id"]

    added = client.post(
        f"/profiles/{profile_id}/rules",
        data={
            "pattern_hash": timestamp["pattern_hash"],
            "title": "Require millisecond log timestamps",
            "secure_when": "present",
            "severity": "medium",
            "framework": "Organization baseline",
            "framework_control_id": "LOG-1",
            "source_reference": (
                "tests/fixtures/network/cisco_ios/SOURCES.md; "
                "c4geeks_snmp_syslog_router_ios152.txt"
            ),
            "remediation": (
                "Configure the source-documented timestamp command and verify the saved "
                "running configuration before operational use."
            ),
        },
    )
    assert added.status_code == 200
    assert "Organization-defined rule added" in added.text
    published = client.post(f"/profiles/{profile_id}/publish")
    assert published.status_code == 200
    assert "Profile published as organization-defined" in published.text

    console = client.get("/console")
    assert console.status_code == 200
    assert "C4Geeks IOS organization baseline" in console.text
    assert f'custom:{profile_id}' in console.text

    audited = client.post(
        "/api/network/audit",
        data={"vendor": f"custom:{profile_id}", "framework": "all"},
        files=[
            ("files", (CISCO_CONFIG.name, CISCO_CONFIG.read_bytes(), "text/plain")),
            ("files", (BASE_CISCO_CONFIG.name, BASE_CISCO_CONFIG.read_bytes(), "text/plain")),
        ],
    )
    assert audited.status_code == 200
    assert audited.text.count("HTML report") == 2
    assert "organization-defined profile" in audited.text

    json_reports = sorted(dashboard.RESULTS_DIR.glob("*.json"))
    html_reports = sorted(dashboard.RESULTS_DIR.glob("*.html"))
    pdf_reports = sorted(dashboard.RESULTS_DIR.glob("*.pdf"))
    bundle_reports = sorted(dashboard.RESULTS_DIR.glob("*.zip"))
    assert len(json_reports) == len(html_reports) == len(pdf_reports) == 2
    assert len(bundle_reports) == 2
    results = [dashboard.json.loads(path.read_text()) for path in json_reports]
    assert {item["summary"]["pass"] for item in results} == {0, 1}
    assert {item["summary"]["fail"] for item in results} == {0, 1}
    assert all(item["verification_status"] == "organization_defined" for item in results)
    assert all(
        control["verification_status"] == "organization_defined"
        for item in results
        for control in item["controls"]
    )
    assert all("organization-defined" in path.read_text().casefold() for path in html_reports)
    pdf_text = ["\n".join(page.extract_text() or "" for page in PdfReader(path).pages) for path in pdf_reports]
    assert all("organization-defined" in text.casefold() for text in pdf_text)
    for path in bundle_reports:
        with zipfile.ZipFile(path) as bundle:
            manifest = json.loads(bundle.read("manifest.json"))
            canonical = manifest["integrity"]["canonical_report"]
            assert canonical["status"] == "not_applicable"
            assert canonical["value"] is None
            assert manifest["assurance"] == "organization_defined"
            assert manifest["privacy"]["raw_configuration_file_included"] is False

    assert len(dashboard.DEVICE_RECORDS) == 2
    assert all(
        record["vendor_key"] == f"custom:{profile_id}"
        for record in dashboard.DEVICE_RECORDS.values()
    )
    filtered = client.get(f"/console?vendor=custom:{profile_id}&status=complete")
    assert filtered.status_code == 200
    assert CISCO_CONFIG.stem in filtered.text
    assert BASE_CISCO_CONFIG.stem in filtered.text
    dashboard.DEVICE_RECORDS.clear()
    restored = dashboard.STORE.load_device_records()
    assert len(restored) == 2
    assert all(record["vendor_key"] == f"custom:{profile_id}" for record in restored.values())


def test_draft_profile_cannot_generate_custom_audit_reports(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    dashboard.STORE.add_knowledge_source({
        "source_id": "source-cisco",
        "vendor": "Cisco",
        "platform": "IOS reference",
        "filename": CISCO_SOURCES.name,
        "media_type": "text/markdown",
        "content_sha256": "a" * 64,
        "excerpt": "Committed source manifest for the genuine Cisco IOS corpus.",
    })
    dashboard.STORE.create_vendor_profile({
        "profile_id": "draft-cisco",
        "name": "Draft Cisco profile",
        "vendor": "Cisco",
        "platform": "IOS reference",
        "source_id": "source-cisco",
        "status": "draft",
    })
    response = client.post(
        "/api/custom/audit",
        data={"profile_id": "draft-cisco"},
        files={"files": (CISCO_CONFIG.name, CISCO_CONFIG.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    assert "ERROR" in response.text
    assert "published" in response.text
    assert list(dashboard.RESULTS_DIR.iterdir()) == []


def test_ai_suggestion_route_refuses_missing_key_and_insufficient_cap(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    analyzed = client.post(
        "/api/training/analyze",
        data={"vendor": "Cisco", "platform": "IOS 15.2 reference corpus"},
        files={"config_file": (CISCO_CONFIG.name, CISCO_CONFIG.read_bytes(), "text/plain")},
    )
    assert analyzed.status_code == 200
    session_id = dashboard.STORE.list_training_sessions()[0]["session_id"]

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    missing_key = client.post(
        f"/training/{session_id}/classify", data={"max_calls": 200}
    )
    assert missing_key.status_code == 400
    assert "requires ANTHROPIC_API_KEY" in missing_key.text
    assert dashboard.STORE.get_training_session(session_id)["api_runs"] == []

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-only-key")
    called = False

    def must_not_call(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("provider must not be called when the cap is insufficient")

    monkeypatch.setattr("ai.vendor_training.provider_classify", must_not_call)
    insufficient = client.post(
        f"/training/{session_id}/classify", data={"max_calls": 1}
    )
    assert insufficient.status_code == 400
    assert "exceed max_calls=1" in insufficient.text
    assert called is False
    assert dashboard.STORE.get_training_session(session_id)["api_runs"] == []


def test_ai_suggestion_route_sends_only_redacted_genuine_pattern(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    raw = CISCO_CONFIG.read_text()
    timestamp = next(
        item
        for item in collect_training_patterns(
            raw, "Cisco", "IOS 15.2 reference corpus"
        )
        if item["pattern"] == "service timestamps log datetime msec"
    )
    session_id = "genuine-pattern-session"
    dashboard.STORE.create_training_session({
        "session_id": session_id,
        "vendor": "Cisco",
        "platform": "IOS 15.2 reference corpus",
        "filename": CISCO_CONFIG.name,
        "config_sha256": "a" * 64,
    })
    dashboard.STORE.save_training_patterns(
        session_id, [dry_run_classification(timestamp)]
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-only-key")
    observed = []

    def fake_provider(pattern, vendor, platform, api_key, model):
        observed.append(pattern["pattern"])
        assert vendor == "Cisco"
        assert platform == "IOS 15.2 reference corpus"
        assert api_key == "test-only-key"
        return {
            **pattern,
            "category": "logging",
            "reasoning": "Configures timestamp precision for log records.",
            "mode": "real-api",
            "source": "provider",
            "confirmed": False,
            "model": model,
            "usage": {"input_tokens": 42, "output_tokens": 9, "cost_usd": 0.000087},
        }

    monkeypatch.setattr("ai.vendor_training.provider_classify", fake_provider)
    response = client.post(
        f"/training/{session_id}/classify", data={"max_calls": 1}
    )

    assert response.status_code == 200
    assert "1 real call(s)" in response.text
    assert "actual cost $0.000087" in response.text
    assert "Human confirmation is still required" in response.text
    assert observed == ["service timestamps log datetime msec"]
    persisted = dashboard.STORE.get_training_session(session_id)
    assert persisted is not None
    assert persisted["patterns"][0]["category"] == "logging"
    assert persisted["patterns"][0]["source"] == "provider"
    assert persisted["patterns"][0]["confirmed"] is False
    assert persisted["api_runs"][0]["call_count"] == 1
    assert persisted["api_runs"][0]["cost_usd"] == 0.000087


def test_ai_suggestion_interruption_keeps_completed_call_accounting(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    patterns = [
        item
        for item in collect_training_patterns(
            CISCO_CONFIG.read_text(), "Cisco", "IOS 15.2 reference corpus"
        )
        if not item["structural"]
    ][:2]
    session_id = "interrupted-provider-session"
    dashboard.STORE.create_training_session({
        "session_id": session_id,
        "vendor": "Cisco",
        "platform": "IOS 15.2 reference corpus",
        "filename": CISCO_CONFIG.name,
        "config_sha256": "a" * 64,
    })
    dashboard.STORE.save_training_patterns(
        session_id, [dry_run_classification(item) for item in patterns]
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-only-key")
    calls = 0

    def flaky_provider(pattern, vendor, platform, api_key, model):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise dashboard.ProviderError("test interruption")
        return {
            **pattern,
            "category": "logging",
            "reasoning": "First result completed before interruption.",
            "mode": "real-api",
            "source": "provider",
            "confirmed": False,
            "model": model,
            "usage": {"input_tokens": 40, "output_tokens": 8, "cost_usd": 0.00008},
        }

    monkeypatch.setattr("ai.vendor_training.provider_classify", flaky_provider)
    response = client.post(
        f"/training/{session_id}/classify", data={"max_calls": 2}
    )

    assert response.status_code == 400
    assert "stopped after 1 persisted result" in response.text
    persisted = dashboard.STORE.get_training_session(session_id)
    assert persisted is not None
    assert len(persisted["api_runs"]) == 1
    assert persisted["api_runs"][0]["call_count"] == 1
    assert sum(item["source"] == "provider" for item in persisted["patterns"]) == 1
