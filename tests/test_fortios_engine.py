from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from engines.network.fortios import (
    FortiOSBlock,
    FortiOSDocument,
    FortiOSEntry,
    FortiOSStatement,
    parse_config,
)
from engines.network.run_fortios_audit import _check

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "engines/network/run_fortios_audit.py"
CORPUS = ROOT / "tests/fixtures/network/fortios"


def _run(name: str, tmp_path: Path) -> dict:
    output = tmp_path / f"{name}.json"
    subprocess.run(
        [sys.executable, str(ENGINE), "--config", str(CORPUS / name), "--output", str(output)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(output.read_text(encoding="utf-8"))


def test_fortios_manifest_hashes_match_unmodified_sources():
    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["files"]) == 8
    for item in manifest["files"]:
        content = (CORPUS / item["file"]).read_bytes()
        assert hashlib.sha256(content).hexdigest() == item["source_sha256"]
        assert item["license"] in {"Apache-2.0", "MIT"}
        assert item["revision"] in item["source_url"]


def test_fortios_corpus_matches_manual_pass_fail_error_oracle(tmp_path):
    oracle = json.loads((CORPUS / "manual_expectations.json").read_text(encoding="utf-8"))
    results = {
        item["file"]: _run(item["file"], tmp_path)
        for item in json.loads((CORPUS / "manifest.json").read_text())["files"]
    }
    for rule_id, expected in oracle["rules"].items():
        observed = {"pass": [], "fail": [], "error": []}
        for filename, report in results.items():
            control = next(control for control in report["controls"] if control["rule_id"] == rule_id)
            observed[control["status"]].append(filename)
        for status in observed:
            assert sorted(observed[status]) == sorted(expected[status])
        assert expected["pass"] and expected["fail"]


def test_fortios_reports_identity_without_affecting_control_results(tmp_path):
    report = _run("oxidized_fortigate_91g_7.4.7.txt", tmp_path)
    assert report["target"] == "fortinet_fortios"
    assert report["device"]["vendor"] == "Fortinet"
    assert report["device"]["platform"] == "FortiOS"
    assert report["device"]["hostname"] == "TEST-FW1234"
    assert report["device"]["model"] == "FortiGate-91G"
    assert report["device"]["software_version"] == "7.4.7"
    assert report["summary"] == {"pass": 2, "fail": 1, "error": 0, "manual": 0, "not_applicable": 0}


def test_all_entries_match_tracks_each_entry_instance_not_only_its_name():
    document = FortiOSDocument(
        blocks=(FortiOSBlock(1, ("vdom", "system admin")),),
        entries=(
            FortiOSEntry(2, ("vdom", "system admin"), "admin"),
            FortiOSEntry(8, ("vdom", "system admin"), "admin"),
        ),
        statements=(
            FortiOSStatement(
                3,
                ("vdom", "system admin"),
                "admin",
                2,
                "set trusthost1 10.0.0.0 255.255.255.0",
            ),
        ),
    )
    rule = {
        "id": "1.3",
        "id_namespace": "fortios-baseline",
        "title": "Restrict every administrator account to trusted hosts",
        "level": 1,
        "profile": ["network_device"],
        "device": {"vendor": "Fortinet", "platform": "FortiOS"},
        "severity": "high",
        "automated": True,
        "checks": [{
            "type": "fortios_statement",
            "path_pattern": "(?:.*/)?system admin",
            "target": "statement",
            "pattern": r"set trusthost[1-9]\s+.+",
            "op": "all_entries_match",
        }],
        "remediation": "Restrict every administrator.",
        "source": "Fortinet hardening guidance",
    }

    result = _check(rule, document)

    assert result["status"] == "fail"
    assert result["checks"][0]["actual"] == 1
    assert result["checks"][0]["evidence"] == "1 of 2 entries lack the required statement"


@pytest.mark.parametrize(
    "text",
    [
        "not fortios\n",
        "config system admin\nnext\nend\n",
        "config system admin\n",
        "config system admin\nend\nend\n",
    ],
)
def test_fortios_parser_rejects_missing_or_unbalanced_structure(text):
    with pytest.raises(ValueError):
        parse_config(text)
