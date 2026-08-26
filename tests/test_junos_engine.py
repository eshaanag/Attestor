from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "engines/network/run_junos_audit.py"
CORPUS = ROOT / "tests/fixtures/network/junos"


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


def test_junos_real_source_excerpts_prove_pass_and_fail_states(tmp_path):
    example = _run("junos_example.conf", tmp_path)
    fabric = _run("junos_fabric01.conf", tmp_path)
    assert example["device"]["vendor"] == "Juniper"
    assert example["summary"]["fail"] >= 2
    assert fabric["summary"]["pass"] == 4
    assert fabric["summary"]["fail"] == 0


def test_junos_minimal_source_excerpt_fails_syslog_and_passes_absence_rules(tmp_path):
    minimal = _run("junos_minimal.conf", tmp_path)
    statuses = {control["rule_id"]: control["status"] for control in minimal["controls"]}
    assert statuses["1.1"] == "pass"
    assert statuses["1.2"] == "pass"
    assert statuses["2.1"] == "fail"
    assert statuses["3.1"] == "pass"
