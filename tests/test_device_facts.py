from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from engines.network.device_facts import DeviceFactsError, load_device_facts
from ledger.canonical import content_hash


ROOT = Path(__file__).resolve().parents[1]
FACTS = ROOT / "tests" / "fixtures" / "network" / "device_facts"


def _run_engine(engine: str, config: Path, facts: Path, output: Path) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(ROOT / "engines" / "network" / engine),
        "--config",
        str(config),
        "--device-facts",
        str(facts),
        "--output",
        str(output),
    ]
    if engine == "run_audit.py":
        command.extend(["--format", "json"])
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True)


def test_device_facts_corpus_matches_manifest_hashes():
    manifest = json.loads((FACTS / "manifest.json").read_text(encoding="utf-8"))
    entries = list(manifest["files"])
    entries.append({
        "filename": manifest["integration_config"]["filename"],
        "sha256": manifest["integration_config"]["fixture_sha256"],
    })
    for entry in entries:
        actual = hashlib.sha256((FACTS / entry["filename"]).read_bytes()).hexdigest()
        assert actual == entry["sha256"], entry["filename"]


def test_cisco_show_version_parses_classic_and_stack_identity():
    classic = load_device_facts(FACTS / "cisco_ios_catalyst4948_show_version.txt", "cisco_ios")
    assert classic["hostname"] == "router1"
    assert classic["model"] == "WS-C4948E"
    assert classic["serial_number"] == "CAT1451S15C"
    assert classic["serial_numbers"] == ["CAT1451S15C"]
    assert classic["software_version"] == "12.2(54)SG1"
    assert classic["facts_source"]["parser"] == "cisco_show_version_v1"

    stack = load_device_facts(
        FACTS / "cisco_iosxe_catalyst3850_stack_show_version.txt", "cisco_ios"
    )
    assert stack["hostname"] == "city-building-4-sw"
    assert stack["model"] == "WS-C3850-48U"
    assert stack["serial_number"] == "FOC11111111"
    assert stack["serial_numbers"] == [
        "FOC11111111",
        "FCW22222222",
        "FCW33333333",
        "FCW44444444",
    ]
    assert stack["software_version"] == "03.06.05E"


def test_junos_show_version_keeps_unexposed_fields_null():
    mx = load_device_facts(FACTS / "juniper_junos_mx240_show_version.txt", "juniper_junos")
    assert mx["hostname"] == "lab"
    assert mx["model"] == "mx240"
    assert mx["serial_number"] == "qfsn-0123456789"
    assert mx["software_version"] == "13.3R1.4"

    qfx = load_device_facts(FACTS / "juniper_junos_qfx5100_show_version.txt", "juniper_junos")
    assert qfx["serial_number"] is None
    assert qfx["serial_numbers"] == []

    nfx = load_device_facts(FACTS / "juniper_junos_nfx250_show_version.txt", "juniper_junos")
    assert nfx["hostname"] == "MyRouter"
    assert nfx["model"] == "nfx250_att_s1_10_t"
    assert nfx["serial_number"] is None
    assert nfx["software_version"] is None


def test_device_facts_reject_wrong_vendor_invalid_utf8_and_empty(tmp_path):
    with pytest.raises(DeviceFactsError, match="Junos show version marker"):
        load_device_facts(FACTS / "cisco_ios_catalyst4948_show_version.txt", "juniper_junos")
    invalid = tmp_path / "invalid.txt"
    invalid.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(DeviceFactsError, match="not valid UTF-8"):
        load_device_facts(invalid, "cisco_ios")
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    with pytest.raises(DeviceFactsError, match="empty"):
        load_device_facts(empty, "cisco_ios")


def test_cisco_engine_enriches_identity_without_changing_control_summary(tmp_path):
    config = FACTS / "cisco_router1_running_config_redacted.txt"
    facts = FACTS / "cisco_ios_catalyst4948_show_version.txt"
    enriched_path = tmp_path / "enriched.json"
    plain_path = tmp_path / "plain.json"
    enriched = _run_engine("run_audit.py", config, facts, enriched_path)
    assert enriched.returncode == 0, enriched.stderr
    plain = subprocess.run(
        [
            sys.executable,
            str(ROOT / "engines" / "network" / "run_audit.py"),
            "--config",
            str(config),
            "--output",
            str(plain_path),
            "--format",
            "json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert plain.returncode == 0, plain.stderr
    enriched_results = json.loads(enriched_path.read_text(encoding="utf-8"))
    plain_results = json.loads(plain_path.read_text(encoding="utf-8"))
    assert enriched_results["summary"] == plain_results["summary"]
    assert [item["status"] for item in enriched_results["controls"]] == [
        item["status"] for item in plain_results["controls"]
    ]
    device = enriched_results["device"]
    assert device["hostname"] == "router1"
    assert device["model"] == "WS-C4948E"
    assert device["serial_number"] == "CAT1451S15C"
    assert device["software_version"] == "12.2(54)SG1"
    assert device["facts_source"]["sha256"] == hashlib.sha256(facts.read_bytes()).hexdigest()
    assert "serial_number" not in plain_results["device"]


def test_junos_engine_accepts_case_insensitive_hostname_match(tmp_path):
    output = tmp_path / "junos.json"
    process = _run_engine(
        "run_junos_audit.py",
        ROOT / "tests" / "fixtures" / "network" / "junos" / "junos_example.conf",
        FACTS / "juniper_junos_nfx250_show_version.txt",
        output,
    )
    assert process.returncode == 0, process.stderr
    device = json.loads(output.read_text(encoding="utf-8"))["device"]
    assert device["hostname"] == "myrouter"
    assert device["model"] == "nfx250_att_s1_10_t"
    assert device["serial_number"] is None
    assert device["software_version"] is None


def test_engine_rejects_hostname_mismatch_before_writing_results(tmp_path):
    output = tmp_path / "mismatch.json"
    process = _run_engine(
        "run_audit.py",
        ROOT / "tests" / "fixtures" / "network" / "cisco_ios" / "c4geeks_base_router_iosv.txt",
        FACTS / "cisco_ios_catalyst4948_show_version.txt",
        output,
    )
    assert process.returncode == 2
    assert "does not match" in process.stderr
    assert not output.exists()


def test_device_facts_participate_in_existing_canonical_hash(tmp_path):
    output = tmp_path / "network.json"
    process = _run_engine(
        "run_audit.py",
        FACTS / "cisco_router1_running_config_redacted.txt",
        FACTS / "cisco_ios_catalyst4948_show_version.txt",
        output,
    )
    assert process.returncode == 0, process.stderr
    results = json.loads(output.read_text(encoding="utf-8"))
    original = content_hash(results)
    assert content_hash(json.loads(json.dumps(results, sort_keys=True))) == original
    changed = json.loads(json.dumps(results))
    changed["device"]["software_version"] = "different-explicit-version"
    assert content_hash(changed) != original
