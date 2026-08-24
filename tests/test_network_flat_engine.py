"""Phase C: manual oracle versus the flat Cisco config engine."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from tests.validate_rules import format_errors, load_validator
from engines.network.run_audit import (
    ConfigInputError,
    check_config_grep,
    check_config_block,
    load_config,
    parse_blocks,
    run_check,
)


CORPUS_DIR = Path(__file__).parent / "fixtures" / "network" / "cisco_ios"


def test_flat_engine_matches_manual_oracle_for_every_fixture():
    oracle = json.loads((CORPUS_DIR / "manual_flat_expectations.json").read_text())
    configs = {
        path.name: load_config(path)
        for path in CORPUS_DIR.glob("*.txt")
    }

    assert len(configs) == 10
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
    assert "context_type" in unsupported_type["error"]


def test_block_engine_matches_manual_oracle_with_both_states():
    oracle = json.loads((CORPUS_DIR / "manual_block_expectations.json").read_text())
    configs = {path.name: load_config(path) for path in CORPUS_DIR.glob("*.txt")}

    for check_index, expected in enumerate(oracle["checks"]):
        pass_files = set(expected["pass"])
        fail_files = set(expected["fail"])
        assert pass_files and fail_files
        assert pass_files.isdisjoint(fail_files)
        assert pass_files | fail_files == set(configs)

        check = {
            "type": "config_block",
            "context_type": expected["context_type"],
            "header_pattern": expected["header_pattern"],
            "required_patterns": expected["required_patterns"],
            "forbidden_patterns": expected["forbidden_patterns"],
        }
        for filename, config in configs.items():
            result = check_config_block(expected["name"], check_index, check, config)
            expected_status = "pass" if filename in pass_files else "fail"
            assert result["status"] == expected_status, filename
            assert isinstance(result["actual"], str)
            assert isinstance(result["expected"], str)
            assert result["evidence"]
            for line_number in expected[expected_status][filename]:
                assert f'"header_line": {line_number}' in result["evidence"]


def test_block_parser_keeps_interface_children_in_their_own_stanza():
    config = load_config(CORPUS_DIR / "c4geeks_cdp_lldp_switch_iosvl2.txt")
    blocks = parse_blocks(config, "interface")
    assert [block.header.normalized for block in blocks] == [
        "interface Vlan1",
        "interface GigabitEthernet0/0",
    ]
    assert [line.normalized for line in blocks[0].children] == [
        "ip address 10.10.10.1 255.255.255.0",
        "no shutdown",
    ]
    assert [line.normalized for line in blocks[1].children] == [
        "switchport mode access",
        "switchport access vlan 1",
    ]

    vlan_only = check_config_block(
        "fixture",
        0,
        {
            "context_type": "interface",
            "header_pattern": r"^interface Vlan1$",
            "required_patterns": [r"^switchport mode access$"],
            "forbidden_patterns": [],
        },
        config,
    )
    assert vlan_only["status"] == "fail"
    assert "missing_required" in vlan_only["evidence"]


def test_block_engine_fails_closed_for_missing_or_malformed_context():
    config = load_config(CORPUS_DIR / "c4geeks_base_router_iosv.txt")
    missing = check_config_block(
        "fixture", 0,
        {
            "context_type": "interface",
            "header_pattern": r"^interface Loopback999$",
            "required_patterns": [r"^no shutdown$"],
            "forbidden_patterns": [],
        },
        config,
    )
    assert missing["status"] == "error"
    assert "cannot be inferred" in missing["error"]

    malformed = check_config_block(
        "fixture", 1,
        {
            "context_type": "line_console",
            "header_pattern": r"^line console",
            "required_patterns": [],
            "forbidden_patterns": [],
        },
        config,
    )
    assert malformed["status"] == "error"


def test_vty_block_parsing_passes_present_ssh_block_and_errors_when_absent():
    base = load_config(CORPUS_DIR / "c4geeks_base_router_iosv.txt")
    ssh_only = check_config_block(
        "fixture", 0,
        {
            "context_type": "line_vty",
            "header_pattern": r"^line vty\s+",
            "required_patterns": [r"^transport input ssh$"],
            "forbidden_patterns": [r"^transport input telnet$"],
        },
        base,
    )
    assert ssh_only["status"] == "pass"
    assert '"header": "line vty 0 4"' in ssh_only["evidence"]

    no_vty = load_config(CORPUS_DIR / "c4geeks_dhcp_router_ios152.txt")
    absent = check_config_block(
        "fixture", 1,
        {
            "context_type": "line_vty",
            "header_pattern": r"^line vty\s+",
            "required_patterns": [r"^transport input ssh$"],
            "forbidden_patterns": [],
        },
        no_vty,
    )
    assert absent["status"] == "error"
    assert "cannot be inferred" in absent["error"]


def test_cisco_rule_pack_matches_manual_oracle_with_both_states():
    oracle = json.loads((CORPUS_DIR / "manual_rule_expectations.json").read_text())
    configs = {path.name: load_config(path) for path in CORPUS_DIR.glob("*.txt")}
    rule_files = sorted((CORPUS_DIR.parents[3] / "rules" / "cisco_ios").glob("*.yaml"))
    assert len(rule_files) == len(oracle["rules"]) == 14

    oracle_by_id = {entry["rule_id"]: entry for entry in oracle["rules"]}
    validator = load_validator()
    for path in rule_files:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert not format_errors(validator, rule), path.name
        entry = oracle_by_id[rule["id"]]
        assert entry["pass"] and entry["fail"], rule["id"]
        assert set(entry["pass"]) | set(entry["fail"]) == set(configs)
        assert set(entry["pass"]) & set(entry["fail"]) == set()
        check = rule["checks"][0]
        for filename, config in configs.items():
            result = check_config_grep(rule["id"], 0, check, config)
            expected = "pass" if filename in entry["pass"] else "fail"
            assert result["status"] == expected, (rule["id"], filename)
            if expected == "pass":
                assert f"line {entry['pass'][filename]}:" in result["evidence"]
