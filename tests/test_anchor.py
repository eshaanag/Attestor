"""Regression tests for the deployed Ethereum Sepolia anchor integration."""
from __future__ import annotations

import json
from pathlib import Path

from ledger import anchor


def test_anchor_configuration_matches_deployed_sepolia_contract():
    assert anchor.SEPOLIA_CHAIN_ID == 11155111
    assert anchor.DEPLOYED_ADDRESS_PATH.name == "sepolia_address.txt"
    assert anchor.DEPLOYED_ADDRESS_PATH.read_text().strip() == (
        "0xbd19e20aD6C216A8a793fdE3Bd46B9D291Bf5C41"
    )

    abi = json.loads(anchor.ABI_PATH.read_text())
    functions = {item["name"]: item for item in abi if item.get("type") == "function"}

    anchor_inputs = functions["anchorReport"]["inputs"]
    assert [(item["name"], item["type"]) for item in anchor_inputs] == [
        ("root", "bytes32"),
        ("previousRoot", "bytes32"),
    ]

    verify_outputs = functions["verifyRoot"]["outputs"]
    assert [(item["name"], item["type"]) for item in verify_outputs] == [
        ("found", "bool"),
        ("previousRoot", "bytes32"),
        ("timestamp", "uint256"),
        ("submitter", "address"),
    ]


def test_latest_chain_link_returns_current_and_previous_hash(tmp_path: Path):
    chain_path = tmp_path / "chain.jsonl"
    first = {
        "content_hash": "1" * 64,
        "prev_hash": "0" * 64,
    }
    second = {
        "content_hash": "2" * 64,
        "prev_hash": "1" * 64,
    }
    chain_path.write_text(
        json.dumps(first) + "\n" + json.dumps(second) + "\n",
        encoding="utf-8",
    )

    assert anchor.latest_chain_link(chain_path) == second
