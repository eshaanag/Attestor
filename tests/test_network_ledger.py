"""Phase F proof that network reports use the unchanged ledger contracts."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

from ledger.canonical import content_hash
from ledger.chain import append, verify


ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "engines" / "network" / "run_audit.py"
CONFIG = ROOT / "tests" / "fixtures" / "network" / "cisco_ios" / "c4geeks_snmp_syslog_router_ios152.txt"


def _run_network_report(path: Path) -> dict:
    output = path / "network-report.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(ENGINE),
            "--config",
            str(CONFIG),
            "--device-id",
            "cisco-demo-01",
            "--output",
            str(output),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "Run COMPLETE" in completed.stderr
    return json.loads(output.read_text(encoding="utf-8"))


def test_network_report_hash_tracks_device_and_framework_mapping_but_not_serialization(tmp_path):
    results = _run_network_report(tmp_path)
    original_hash = content_hash(results)

    device_changed = copy.deepcopy(results)
    device_changed["device"]["vendor"] = "Cisco Systems"
    assert content_hash(device_changed) != original_hash

    mapping_changed = copy.deepcopy(results)
    mapping = mapping_changed["controls"][0]["framework_mappings"][0]
    mapping["relationship"] = "supports"
    assert content_hash(mapping_changed) != original_hash

    reordered = {key: results[key] for key in reversed(list(results))}
    reparsed = json.loads(json.dumps(reordered, indent=4, ensure_ascii=False))
    assert content_hash(reparsed) == original_hash


def test_network_report_chains_under_stable_device_id(tmp_path):
    report = _run_network_report(tmp_path)
    report_path = tmp_path / "network-report.json"
    chain_path = tmp_path / "chain.jsonl"

    first = append(report_path, "cisco-demo-01", chain_path=chain_path)

    second_report = copy.deepcopy(report)
    second_report["report_id"] = "second-network-report"
    second_path = tmp_path / "second-network-report.json"
    second_path.write_text(json.dumps(second_report, indent=2), encoding="utf-8")
    second = append(second_path, "cisco-demo-01", chain_path=chain_path)

    assert first["prev_hash"] == "0" * 64
    assert second["prev_hash"] == first["content_hash"]
    assert verify("cisco-demo-01", chain_path=chain_path, results_dir=tmp_path)["intact"] is True
