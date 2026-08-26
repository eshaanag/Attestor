"""Phase H' network ingestion dashboard tests using genuine Phase B configs."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

import dashboard.app as dashboard


CORPUS = Path("tests/fixtures/network/cisco_ios")


def _client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setattr(dashboard, "RESULTS_DIR", tmp_path / "reports")
    dashboard.RESULTS_DIR.mkdir()
    return TestClient(dashboard.app)


def test_dashboard_home_explains_both_audit_tracks():
    response = TestClient(dashboard.app).get("/")
    assert response.status_code == 200
    assert "Turn device state into evidence" in response.text
    assert "Open audit console" in response.text
    assert "Windows 11 Standalone" in response.text
    assert "Cisco IOS / IOS-XE" in response.text
    assert "Juniper Junos" in response.text
    assert "Hash-only proof" in response.text


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
    assert {path.suffix for path in reports} == {".json", ".html", ".pdf"}
    results = json.loads(next(path for path in reports if path.suffix == ".json").read_text())
    assert results["device"]["hostname"] == "R1"
    assert results["summary"] == {"pass": 5, "fail": 9, "error": 0, "manual": 0, "not_applicable": 0}
    assert next(path for path in reports if path.suffix == ".pdf").read_bytes().startswith(b"%PDF")


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
