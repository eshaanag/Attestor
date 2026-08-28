"""Offline report rendering checks, including network framework mappings."""

from report.generate_report import render


def test_network_report_renders_device_and_dual_framework_mapping():
    results = {
        "attestor_format_version": "1.0",
        "report_id": "network-report-test",
        "target": "cisco_ios",
        "benchmark": "CIS Cisco IOS Benchmark v4.1.0",
        "benchmark_version": "v4.1.0",
        "device": {
            "device_id": "R1",
            "hostname": "R1",
            "vendor": "Cisco",
            "platform": "IOS",
            "roles": ["router"],
            "config_source": "file",
            "config_sha256": "a" * 64,
            "model": "WS-C4948E",
            "serial_number": "CAT1451S15C",
            "serial_numbers": ["CAT1451S15C"],
            "software_version": "12.2(54)SG1",
            "facts_source": {
                "command": "show version",
                "sha256": "b" * 64,
                "parser": "cisco_show_version_v1",
            },
        },
        "host": {
            "hostname": "runner",
            "os_name": "Darwin",
            "os_version": "test",
            "kernel": "test",
            "arch": "arm64",
            "environment": "native",
            "elevated": False,
            "user": "tester",
        },
        "run": {
            "started_at": "2026-08-24T00:00:00Z",
            "finished_at": "2026-08-24T00:00:01Z",
            "engine": "network",
            "engine_version": "0.3.0",
            "complete": True,
            "evaluated": 1,
            "total_controls": 1,
        },
        "summary": {"pass": 1, "fail": 0, "error": 0, "manual": 0, "not_applicable": 0},
        "controls": [
            {
                "rule_id": "2.6.1",
                "title": "Ensure SSH version 2 is configured",
                "level": 1,
                "profile": ["network_device"],
                "device": {"vendor": "Cisco", "platform": "IOS"},
                "severity": "high",
                "automated": True,
                "status": "pass",
                "checks": [],
                "evidence_summary": "line 17: ip ssh version 2",
                "remediation": "Configure SSHv2.",
                "source": "CIS Cisco IOS Benchmark v4.1.0, control 2.6.1",
                "framework_mappings": [
                    {
                        "framework": "NIST SP 800-53",
                        "version": "Rev. 5",
                        "control_id": "SC-8",
                        "relationship": "direct",
                        "source": "NIST official catalog",
                    }
                ],
            }
        ],
    }
    html = render(results)
    assert "Audited device" in html
    assert "Cisco / IOS" in html
    assert "WS-C4948E" in html
    assert "CAT1451S15C" in html
    assert "12.2(54)SG1" in html
    assert "cisco_show_version_v1" in html
    assert "NIST SP 800-53" in html
    assert "SC-8" in html
    assert "direct" in html
    assert "NIST official catalog" in html


def test_organization_defined_html_is_explicitly_not_attestor_verified():
    results = {
        "attestor_format_version": "1.0",
        "report_id": "custom-report-test",
        "target": "custom_profile:cisco-reference",
        "benchmark": "Organization-defined baseline: C4Geeks IOS",
        "benchmark_version": "1",
        "verification_status": "organization_defined",
        "device": {
            "device_id": "reference-router",
            "hostname": None,
            "vendor": "Cisco",
            "platform": "IOS reference",
            "roles": ["organization_defined"],
            "config_source": "file",
            "config_sha256": "a" * 64,
        },
        "host": {
            "hostname": "runner", "os_name": "Darwin", "os_version": "test",
            "kernel": "test", "arch": "arm64", "environment": "native",
            "elevated": False, "user": "tester",
        },
        "run": {
            "started_at": "2026-08-28T00:00:00Z",
            "finished_at": "2026-08-28T00:00:01Z",
            "engine": "network-custom-profile", "engine_version": "0.1.0",
            "complete": True, "evaluated": 1, "total_controls": 1,
        },
        "summary": {"pass": 0, "fail": 1, "error": 0, "manual": 0, "not_applicable": 0},
        "controls": [{
            "rule_id": "ORG-CISCO-001", "title": "Require log timestamps", "level": 1,
            "severity": "medium", "status": "fail", "verification_status": "organization_defined",
            "evidence_summary": "Exact redacted pattern was not observed.",
            "remediation": "Apply the source-documented timestamp command.",
            "source": "SOURCES.md; C4Geeks Cisco IOS fixture", "framework_mappings": [],
        }],
    }

    html = render(results)
    assert "Organization-defined profile" in html
    assert "not an\n  Attestor-verified vendor benchmark" in html
    assert "Operator-defined remediation" in html
