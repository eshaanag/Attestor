"""Phase H' network ingestion dashboard tests using genuine Phase B configs."""
from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

import dashboard.app as dashboard
from dashboard.store import DashboardStore
from engines.network.device_facts import load_device_facts
from engines.network.netmiko_collector import CollectionError, CollectionResult


CORPUS = Path("tests/fixtures/network/cisco_ios")
DEVICE_FACTS = Path("tests/fixtures/network/device_facts")


def _client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setattr(dashboard, "RESULTS_DIR", tmp_path / "reports")
    dashboard.RESULTS_DIR.mkdir()
    monkeypatch.setattr(dashboard, "STORE", DashboardStore(tmp_path / "attestor.db"))
    dashboard.DEVICE_RECORDS.clear()
    return TestClient(dashboard.app)


def test_dashboard_home_explains_both_audit_tracks():
    response = TestClient(dashboard.app).get("/")
    assert response.status_code == 200
    assert "Turn device state into evidence" in response.text
    assert "Open audit console" in response.text
    assert "Windows 11 Standalone" in response.text
    assert "Cisco IOS / IOS-XE" in response.text
    assert "Juniper Junos" in response.text
    assert "Fortinet FortiOS" in response.text
    assert "Hash-only proof" in response.text


def test_console_exposes_live_collection_without_arbitrary_command_input(tmp_path, monkeypatch):
    response = _client(tmp_path, monkeypatch).get("/console")
    assert response.status_code == 200
    assert "Collect from a live device" in response.text
    assert 'action="/api/network/collect"' in response.text
    assert 'name="password"' in response.text
    assert 'name="secret"' in response.text
    assert 'name="command"' not in response.text


def test_network_single_upload_generates_json_html_and_pdf(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    source = CORPUS / "c4geeks_snmp_syslog_router_ios152.txt"
    response = client.post(
        "/api/network/audit",
        data={"framework": "all"},
        files={"files": (source.name, source.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    assert "pass=5, fail=9, error=0" in response.text
    assert "HTML report" in response.text
    assert "PDF report" in response.text
    reports = list(dashboard.RESULTS_DIR.iterdir())
    assert {path.suffix for path in reports} == {".json", ".html", ".pdf", ".zip"}
    results = json.loads(next(path for path in reports if path.suffix == ".json").read_text())
    assert results["device"]["hostname"] == "R1"
    assert results["summary"] == {"pass": 5, "fail": 9, "error": 0, "manual": 0, "not_applicable": 0}
    assert next(path for path in reports if path.suffix == ".pdf").read_bytes().startswith(b"%PDF")
    bundle_path = next(path for path in reports if path.suffix == ".zip")
    with zipfile.ZipFile(bundle_path) as bundle:
        assert set(bundle.namelist()) == {
            "report.json", "report.html", "report.pdf", "manifest.json"
        }
        manifest = json.loads(bundle.read("manifest.json"))
        assert manifest["bundle_format_version"] == "attestor-evidence-bundle-v1"
        assert manifest["source_filename"] == source.name
        assert manifest["privacy"]["raw_configuration_file_included"] is False
        assert manifest["privacy"]["may_contain_sensitive_report_evidence"] is True
        assert manifest["integrity"]["canonical_report"]["status"] == "available"
        for artifact in manifest["artifacts"]:
            data = bundle.read(artifact["path"])
            assert artifact["size_bytes"] == len(data)
            assert artifact["sha256"] == hashlib.sha256(data).hexdigest()
        assert source.read_bytes() not in [bundle.read(name) for name in bundle.namelist()]
    assert "Evidence bundle" in response.text
    record = next(iter(dashboard.DEVICE_RECORDS.values()))
    download = client.get(record["urls"]["bundle_url"])
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("application/zip")


def test_network_bulk_upload_isolates_valid_files(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    sources = [
        CORPUS / "c4geeks_snmp_syslog_router_ios152.txt",
        CORPUS / "c4geeks_ntp_router_ios152.txt",
    ]
    response = client.post(
        "/api/network/audit",
        data={"framework": "cis"},
        files=[("files", (path.name, path.read_bytes(), "text/plain")) for path in sources],
    )
    assert response.status_code == 200
    assert response.text.count("HTML report") == 2
    json_reports = list(dashboard.RESULTS_DIR.glob("*.json"))
    assert len(json_reports) == 2
    assert all(
        "framework_mappings" not in control
        for path in json_reports
        for control in json.loads(path.read_text())["controls"]
    )


def test_network_invalid_input_returns_error_without_reports(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/api/network/audit",
        data={"framework": "all"},
        files={"files": ("broken.cfg", b"\xff\xfe\xfa", "application/octet-stream")},
    )
    assert response.status_code == 200
    assert "ERROR" in response.text
    assert "not valid UTF-8" in response.text
    assert not list(dashboard.RESULTS_DIR.glob("*"))


def test_network_bundle_failure_fails_scan_and_removes_partial_reports(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    source = CORPUS / "c4geeks_snmp_syslog_router_ios152.txt"

    def fail_bundle(*args, **kwargs):
        raise OSError("bundle write failed")

    monkeypatch.setattr(dashboard, "build_evidence_bundle", fail_bundle)
    response = client.post(
        "/api/network/audit",
        data={"framework": "all"},
        files={"files": (source.name, source.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    assert "ERROR" in response.text
    assert "bundle write failed" in response.text
    assert not list(dashboard.RESULTS_DIR.iterdir())


def test_network_nist_view_is_explicitly_mapped(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    source = CORPUS / "c4geeks_snmp_syslog_router_ios152.txt"
    response = client.post(
        "/api/network/audit",
        data={"framework": "nist"},
        files={"files": (source.name, source.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    assert "NIST is a mapped view" in response.text
    results = json.loads(next(dashboard.RESULTS_DIR.glob("*.json")).read_text())
    assert results["benchmark"].startswith("NIST SP 800-53 mapped view")
    assert results["controls"]
    assert all(control.get("framework_mappings") for control in results["controls"])


def test_junos_upload_uses_verified_engine_and_shared_reports(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    source = Path("tests/fixtures/network/junos/junos_fabric01.conf")
    response = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "juniper_junos"},
        files={"files": (source.name, source.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    assert "juniper_junos" in response.text
    assert "pass=4, fail=0, error=0" in response.text
    results = json.loads(next(dashboard.RESULTS_DIR.glob("*.json")).read_text())
    assert results["device"]["vendor"] == "Juniper"
    assert results["target"] == "juniper_junos"


def test_fortios_upload_uses_verified_engine_and_shared_reports(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    source = Path("tests/fixtures/network/fortios/oxidized_fortigate_91g_7.4.7.txt")
    response = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "fortinet_fortios"},
        files={"files": (source.name, source.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    assert "fortinet_fortios" in response.text
    assert "pass=2, fail=1, error=0" in response.text
    results = json.loads(next(dashboard.RESULTS_DIR.glob("*.json")).read_text())
    assert results["device"]["vendor"] == "Fortinet"
    assert results["target"] == "fortinet_fortios"
    assert next(dashboard.RESULTS_DIR.glob("*.pdf")).read_bytes().startswith(b"%PDF")


def test_fortios_rejects_unimplemented_companion_facts(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    source = Path("tests/fixtures/network/fortios/oxidized_fortigate_91g_7.4.7.txt")
    response = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "fortinet_fortios"},
        files=[
            ("files", (source.name, source.read_bytes(), "text/plain")),
            ("facts_files", ("facts.txt", b"not implemented", "text/plain")),
        ],
    )
    assert response.status_code == 400
    assert "not implemented for the scoped FortiOS adapter" in response.text


def test_live_cisco_collection_reuses_existing_audit_pipeline_without_persisting_credentials(
    tmp_path, monkeypatch
):
    client = _client(tmp_path, monkeypatch)
    config = DEVICE_FACTS / "cisco_router1_running_config_redacted.txt"
    facts = DEVICE_FACTS / "cisco_ios_catalyst4948_show_version.txt"
    config_text = config.read_text(encoding="utf-8")
    facts_text = facts.read_text(encoding="utf-8")
    observed = {}

    def fake_collect(request):
        observed["request"] = request
        return CollectionResult(
            vendor=request.vendor,
            host=request.host,
            port=request.port,
            config_command="show running-config",
            config_text=config_text,
            config_sha256=hashlib.sha256(config_text.encode()).hexdigest(),
            facts_command="show version",
            facts_text=facts_text,
            facts_sha256=hashlib.sha256(facts_text.encode()).hexdigest(),
            collected_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    monkeypatch.setattr(dashboard, "collect_running_config", fake_collect)
    response = client.post(
        "/api/network/collect",
        data={
            "vendor": "cisco_ios",
            "host": "router1.example.test",
            "port": "22",
            "username": "auditor",
            "password": "do-not-persist-password",
            "secret": "do-not-persist-enable",
            "framework": "all",
        },
    )

    assert response.status_code == 200
    assert "HTML report" in response.text
    assert observed["request"].password == "do-not-persist-password"
    results = json.loads(next(dashboard.RESULTS_DIR.glob("*.json")).read_text())
    assert results["device"]["config_source"] == "netmiko-ssh"
    assert results["collection"]["method"] == "netmiko-ssh"
    assert results["collection"]["host"] == "router1.example.test"
    assert results["device"]["model"] == "WS-C4948E"
    serialized = json.dumps(results)
    assert "do-not-persist-password" not in serialized
    assert "do-not-persist-enable" not in serialized
    assert "auditor" not in results["collection"]
    for path in tmp_path.rglob("*"):
        if path.is_file():
            content = path.read_bytes()
            assert b"do-not-persist-password" not in content
            assert b"do-not-persist-enable" not in content


def test_live_collection_failure_is_recorded_without_report_or_secret(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    def fail_collection(_request):
        raise CollectionError("SSH authentication failed")

    monkeypatch.setattr(dashboard, "collect_running_config", fail_collection)
    response = client.post(
        "/api/network/collect",
        data={
            "vendor": "cisco_ios",
            "host": "router1.example.test",
            "port": "22",
            "username": "auditor",
            "password": "failure-password",
            "secret": "failure-enable",
            "framework": "all",
        },
    )

    assert response.status_code == 200
    assert "SSH authentication failed" in response.text
    assert not list(dashboard.RESULTS_DIR.iterdir())
    record = next(iter(dashboard.DEVICE_RECORDS.values()))
    assert record["status"] == "failed"
    assert record["error"] == "SSH authentication failed"
    for path in tmp_path.rglob("*"):
        if path.is_file():
            content = path.read_bytes()
            assert b"failure-password" not in content
            assert b"failure-enable" not in content


def test_dashboard_pairs_cisco_config_and_show_version_into_all_reports(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    config = DEVICE_FACTS / "cisco_router1_running_config_redacted.txt"
    facts = DEVICE_FACTS / "cisco_ios_catalyst4948_show_version.txt"
    response = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "cisco_ios"},
        files=[
            ("files", (config.name, config.read_bytes(), "text/plain")),
            ("facts_files", (facts.name, facts.read_bytes(), "text/plain")),
        ],
    )
    assert response.status_code == 200
    assert "WS-C4948E" in response.text
    results_path = next(dashboard.RESULTS_DIR.glob("*.json"))
    results = json.loads(results_path.read_text(encoding="utf-8"))
    assert results["device"]["model"] == "WS-C4948E"
    assert results["device"]["serial_number"] == "CAT1451S15C"
    assert results["device"]["software_version"] == "12.2(54)SG1"
    html_report = next(dashboard.RESULTS_DIR.glob("*.html")).read_text(encoding="utf-8")
    assert "Device facts source" in html_report
    assert "cisco_show_version_v1" in html_report

    record = next(iter(dashboard.DEVICE_RECORDS.values()))
    assert record["model"] == "WS-C4948E"
    detail = client.get(f'/console/devices/{record["record_id"]}')
    assert detail.status_code == 200
    assert "Model: WS-C4948E" in detail.text
    assert "Serial: CAT1451S15C" in detail.text
    assert "cisco_show_version_v1" in detail.text
    assert "Evidence bundle" in detail.text


def test_dashboard_requires_one_facts_file_per_config(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    configs = [
        DEVICE_FACTS / "cisco_router1_running_config_redacted.txt",
        CORPUS / "c4geeks_base_router_iosv.txt",
    ]
    facts = DEVICE_FACTS / "cisco_ios_catalyst4948_show_version.txt"
    response = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "cisco_ios"},
        files=[
            *(('files', (path.name, path.read_bytes(), 'text/plain')) for path in configs),
            ("facts_files", (facts.name, facts.read_bytes(), "text/plain")),
        ],
    )
    assert response.status_code == 400
    assert "exactly one show version file per configuration" in response.text
    assert not list(dashboard.RESULTS_DIR.iterdir())


def test_dashboard_bulk_device_facts_isolates_hostname_mismatch(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    matching = DEVICE_FACTS / "cisco_router1_running_config_redacted.txt"
    mismatched = CORPUS / "c4geeks_base_router_iosv.txt"
    facts = DEVICE_FACTS / "cisco_ios_catalyst4948_show_version.txt"
    response = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "cisco_ios"},
        files=[
            ("files", (matching.name, matching.read_bytes(), "text/plain")),
            ("files", (mismatched.name, mismatched.read_bytes(), "text/plain")),
            ("facts_files", (facts.name, facts.read_bytes(), "text/plain")),
            ("facts_files", (facts.name, facts.read_bytes(), "text/plain")),
        ],
    )
    assert response.status_code == 200
    assert response.text.count("HTML report") == 1
    assert "does not match" in response.text
    assert len(list(dashboard.RESULTS_DIR.glob("*.json"))) == 1
    statuses = sorted(record["status"] for record in dashboard.DEVICE_RECORDS.values())
    assert statuses == ["complete", "failed"]


def test_dashboard_pairs_junos_facts_and_rejects_facts_for_custom_profiles(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    config = Path("tests/fixtures/network/junos/junos_example.conf")
    facts = DEVICE_FACTS / "juniper_junos_nfx250_show_version.txt"
    response = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "juniper_junos"},
        files=[
            ("files", (config.name, config.read_bytes(), "text/plain")),
            ("facts_files", (facts.name, facts.read_bytes(), "text/plain")),
        ],
    )
    assert response.status_code == 200
    results = json.loads(next(dashboard.RESULTS_DIR.glob("*.json")).read_text())
    assert results["device"]["model"] == "nfx250_att_s1_10_t"
    assert results["device"]["software_version"] is None

    custom = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "custom:not-used"},
        files=[
            ("files", (config.name, config.read_bytes(), "text/plain")),
            ("facts_files", (facts.name, facts.read_bytes(), "text/plain")),
        ],
    )
    assert custom.status_code == 400
    assert "only for built-in Cisco and Junos adapters" in custom.text


def test_console_inventory_and_device_detail_after_bulk_upload(tmp_path, monkeypatch):
    dashboard.DEVICE_RECORDS.clear()
    client = _client(tmp_path, monkeypatch)
    sources = [
        Path("tests/fixtures/network/cisco_ios/c4geeks_snmp_syslog_router_ios152.txt"),
        Path("tests/fixtures/network/junos/junos_fabric01.conf"),
    ]
    response = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "cisco_ios"},
        files=[("files", (sources[0].name, sources[0].read_bytes(), "text/plain"))],
    )
    assert response.status_code == 200
    response = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "juniper_junos"},
        files=[("files", (sources[1].name, sources[1].read_bytes(), "text/plain"))],
    )
    assert response.status_code == 200
    console = client.get("/console")
    assert console.status_code == 200
    assert "Devices tracked" in console.text
    assert "2" in console.text
    assert "Completed" in console.text
    junos = next(record for record in dashboard.DEVICE_RECORDS.values() if record["vendor"] == "Juniper")
    detail = client.get(f"/console/devices/{junos['record_id']}")
    assert detail.status_code == 200
    assert "Findings and evidence" in detail.text
    assert "4" in detail.text
    assert "Not chained (local report only)" in detail.text


def test_console_filters_and_missing_device_are_explicit(tmp_path, monkeypatch):
    dashboard.DEVICE_RECORDS.clear()
    client = _client(tmp_path, monkeypatch)
    source = Path("tests/fixtures/network/junos/junos_example.conf")
    response = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "juniper_junos"},
        files={"files": (source.name, source.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    filtered = client.get("/console?vendor=juniper_junos&status=complete&search=junos_example")
    assert filtered.status_code == 200
    assert "junos_example" in filtered.text
    assert client.get("/console/devices/missing").status_code == 404


def test_console_inventory_survives_memory_reload(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    source = CORPUS / "c4geeks_snmp_syslog_router_ios152.txt"
    response = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "cisco_ios"},
        files={"files": (source.name, source.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    record_id = next(iter(dashboard.DEVICE_RECORDS))

    dashboard.DEVICE_RECORDS.clear()
    restored = dashboard.STORE.load_device_records()
    dashboard.DEVICE_RECORDS.update(restored)

    console = client.get("/console")
    detail = client.get(f"/console/devices/{record_id}")
    assert console.status_code == 200
    assert "c4geeks_snmp_syslog_router_ios152" in console.text
    assert detail.status_code == 200
    assert "Findings and evidence" in detail.text


def test_repeat_scan_updates_one_device_history(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    source = CORPUS / "c4geeks_snmp_syslog_router_ios152.txt"
    for _ in range(2):
        response = client.post(
            "/api/network/audit",
            data={"framework": "all", "vendor": "cisco_ios"},
            files={"files": (source.name, source.read_bytes(), "text/plain")},
        )
        assert response.status_code == 200

    assert len(dashboard.DEVICE_RECORDS) == 1
    record = next(iter(dashboard.DEVICE_RECORDS.values()))
    assert len(record["history"]) == 2
    detail = client.get(f'/console/devices/{record["record_id"]}')
    assert detail.status_code == 200
    assert detail.text.count("pass 5 · fail 9 · error 0") == 2
    assert "Change since previous comparable scan" in detail.text
    assert "Unchanged" in detail.text
    comparison = dashboard._compare_scan_history(record)
    assert comparison["available"] is True
    assert comparison["score_delta"] == 0
    assert comparison["new_failures"] == []
    assert comparison["resolved"] == []
    assert comparison["configuration"]["status"] == "unchanged"


def test_repeat_scan_compares_genuine_control_state_changes(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    before = CORPUS / "c4geeks_base_router_iosv.txt"
    after = CORPUS / "c4geeks_snmp_syslog_router_ios152.txt"

    response = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "cisco_ios"},
        files={"files": ("edge-router.cfg", before.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    first_record = next(iter(dashboard.DEVICE_RECORDS.values()))
    first_artifacts = {
        key: (dashboard.RESULTS_DIR / Path(url).name).read_bytes()
        for key, url in first_record["history"][0]["urls"].items()
    }

    response = client.post(
        "/api/network/audit",
        data={"framework": "all", "vendor": "cisco_ios"},
        files={"files": ("edge-router.cfg", after.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200

    assert len(dashboard.DEVICE_RECORDS) == 1
    record = next(iter(dashboard.DEVICE_RECORDS.values()))
    comparison = dashboard._compare_scan_history(record)
    assert comparison["available"] is True
    assert comparison["configuration"]["status"] == "changed"
    assert comparison["new_failures"]
    assert comparison["resolved"]
    for key, url in record["history"][0]["urls"].items():
        assert (dashboard.RESULTS_DIR / Path(url).name).read_bytes() == first_artifacts[key]

    previous = {item["rule_id"]: item["status"] for item in record["history"][0]["controls"]}
    current = {item["rule_id"]: item["status"] for item in record["history"][1]["controls"]}
    assert {item["rule_id"] for item in comparison["new_failures"]} == {
        rule_id for rule_id, status in current.items()
        if status == "fail" and previous.get(rule_id) != "fail"
    }
    assert {item["rule_id"] for item in comparison["resolved"]} == {
        rule_id for rule_id, status in current.items()
        if status == "pass" and previous.get(rule_id) == "fail"
    }

    detail = client.get(f'/console/devices/{record["record_id"]}')
    assert detail.status_code == 200
    assert "New failures" in detail.text
    assert "Resolved findings" in detail.text
    assert "Configuration" in detail.text
    assert detail.text.count("Bundle") >= 2


def test_comparison_requires_same_framework_view_and_survives_reload(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    source = CORPUS / "c4geeks_snmp_syslog_router_ios152.txt"
    for framework in ("all", "nist"):
        response = client.post(
            "/api/network/audit",
            data={"framework": framework, "vendor": "cisco_ios"},
            files={"files": ("stable-router.cfg", source.read_bytes(), "text/plain")},
        )
        assert response.status_code == 200

    record_id = next(iter(dashboard.DEVICE_RECORDS))
    record = dashboard.DEVICE_RECORDS[record_id]
    assert dashboard._compare_scan_history(record)["available"] is False
    assert all(entry["urls"]["bundle_url"] for entry in record["history"])

    dashboard.DEVICE_RECORDS.clear()
    dashboard.DEVICE_RECORDS.update(dashboard.STORE.load_device_records())
    restored = dashboard.DEVICE_RECORDS[record_id]
    assert len(restored["history"]) == 2
    assert restored["history"][0]["framework_view"] == "all"
    assert restored["history"][1]["framework_view"] == "nist"
    detail = client.get(f"/console/devices/{record_id}")
    assert "same framework view" in detail.text


def test_software_comparison_uses_explicit_genuine_parsed_facts_only():
    older = load_device_facts(
        DEVICE_FACTS / "cisco_ios_catalyst4948_show_version.txt", "cisco_ios"
    )
    newer = load_device_facts(
        DEVICE_FACTS / "cisco_iosxe_catalyst3850_stack_show_version.txt", "cisco_ios"
    )
    comparison = dashboard._metadata_comparison(older, newer, "software_version")
    assert comparison == {
        "status": "changed",
        "previous": "12.2(54)SG1",
        "current": "03.06.05E",
    }
    assert dashboard._metadata_comparison(older, {}, "software_version")["status"] == "not_comparable"
