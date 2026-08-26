"""Normalization tests use only the genuine Phase B Cisco corpus."""
from __future__ import annotations

from pathlib import Path

from engines.network.normalize import normalize_config
from engines.network.run_audit import load_config
from report.generate_report import render
from report.generate_pdf import build_pdf


CORPUS = Path("tests/fixtures/network/cisco_ios")


def test_normalized_model_is_tri_state_and_secret_safe():
    config = load_config(CORPUS / "c4geeks_snmp_syslog_router_ios152.txt")
    model = normalize_config(config)
    assert model["schema_version"] == "1.0"
    assert model["vendor"] == "Cisco"
    assert model["fields"]["hostname"]["value"] == "R1"
    assert model["fields"]["password_encryption"]["value"] is None
    assert model["fields"]["logging_host_configured"]["value"] is True
    assert model["fields"]["snmpv3_privacy_configured"]["value"] is True
    serialized = repr(model)
    assert "Auth-Pass-2026" not in serialized
    assert "Priv-Pass-2026" not in serialized
    assert "10.20.20.50" not in serialized


def test_normalization_observes_explicit_facts_across_real_corpus():
    expected = {
        "c4geeks_base_router_iosv.txt": (2, True, True),
        "c4geeks_base_switch_iosvl2.txt": (2, True, True),
        "c4geeks_ntp_router_ios152.txt": (None, None, None),
    }
    for name, (ssh_version, password_encryption, banner) in expected.items():
        model = normalize_config(load_config(CORPUS / name))["fields"]
        assert model["ssh_version"]["value"] == ssh_version
        assert model["password_encryption"]["value"] is password_encryption
        assert model["banner_motd_configured"]["value"] is banner


def test_normalized_model_renders_in_html_and_pdf(tmp_path):
    from engines.network.run_audit import build_results, evaluate_rule, load_rules

    config = load_config(CORPUS / "c4geeks_snmp_syslog_router_ios152.txt")
    rules, errors = load_rules(sorted(Path("rules/cisco_ios").glob("*.yaml")))
    controls = [evaluate_rule(rule, config, lambda _check: None) for rule in rules]
    results = build_results(rules, errors, config, "normalization-demo", "2026-08-26T00:00:00Z", controls)
    html = render(results)
    assert "Normalized security model" in html
    assert "logging host configured" in html
    # Existing deterministic control evidence intentionally retains the matched
    # raw line; the new normalized model itself must remain secret-safe.
    assert "10.20.20.50" not in repr(results["security_model"])
    pdf = tmp_path / "normalized.pdf"
    build_pdf(results, pdf, state_dir=tmp_path / "state")
    assert pdf.read_bytes().startswith(b"%PDF")
