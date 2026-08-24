"""Phase C: manual oracle versus the flat Cisco config engine."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from engines.network.run_audit import (
    ConfigInputError,
    check_config_grep,
    load_config,
    run_check,
)


CORPUS_DIR = Path(__file__).parent / "fixtures" / "network" / "cisco_ios"


def test_flat_engine_matches_manual_oracle_for_every_fixture():
    oracle = json.loads((CORPUS_DIR / "manual_flat_expectations.json").read_text())
    configs = {
        path.name: load_config(path)
        for path in CORPUS_DIR.glob("*.txt")
    }

    assert len(configs) == 8
    for check_index, expected in enumerate(oracle["checks"]):
        pass_files = set(expected["pass"])
        fail_files = set(expected["fail"])
        assert pass_files
        assert fail_files
        assert pass_files.isdisjoint(fail_files)
        assert pass_files | fail_files == set(configs)

        check = {"pattern": expected["pattern"], "op": expected["op"]}
        for filename, config in configs.items():
            result = check_config_grep(expected["name"], check_index, check, config)
            expected_status = "pass" if filename in pass_files else "fail"
            assert result["status"] == expected_status, filename
            assert result["evidence"]
            if expected_status == "pass":
                assert result["actual"]
                assert f"line {expected['pass'][filename]}:" in result["evidence"]
            else:
                assert result["actual"] is None


def test_flat_engine_ignores_comments_and_known_paste_wrappers():
    config = load_config(CORPUS_DIR / "c4geeks_base_router_iosv.txt")
    assert all(line.normalized not in {"enable", "configure terminal", "end", "write memory"}
               for line in config.lines)

    result = check_config_grep(
        "fixture",
        0,
        {"pattern": "^service password-encryption$", "op": "matches"},
        config,
    )
    assert result["status"] == "pass"
    assert result["actual"] == "service password-encryption"


def test_config_identity_uses_exact_source_bytes_and_parsed_hostname():
    path = CORPUS_DIR / "c4geeks_base_router_iosv.txt"
    config = load_config(path)

    assert config.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert config.hostname == "R1"


def test_flat_engine_fails_closed_for_bad_input_and_bad_regex(tmp_path):
    missing = tmp_path / "missing.cfg"
    with pytest.raises(ConfigInputError, match="not found"):
        load_config(missing)

    config = load_config(CORPUS_DIR / "c4geeks_base_router_iosv.txt")
    result = check_config_grep("fixture", 0, {"pattern": "[", "op": "matches"}, config)
    assert result["status"] == "error"
    assert "regex compile failed" in result["error"]

    unsupported_op = check_config_grep(
        "fixture", 1, {"pattern": "^hostname ", "op": "equals"}, config
    )
    assert unsupported_op["status"] == "error"
    assert "not implemented" in unsupported_op["error"]

    unsupported_type = run_check(
        "fixture", 2, {"type": "config_block", "expected": "ssh-only"}, config
    )
    assert unsupported_type["status"] == "error"
    assert "outside Phase C" in unsupported_type["error"]
