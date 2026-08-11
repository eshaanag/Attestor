#!/usr/bin/env python3
"""Attestor — Testnet anchoring (Phase 9).

Deploys the AttestorAnchor contract to Polygon Amoy testnet and/or anchors
ledger root hashes on-chain for public, independent verification.

Usage:
    # Deploy the contract (one-time):
    python ledger/anchor.py deploy

    # Anchor the current chain root:
    python ledger/anchor.py anchor --chain-file ledger/chain.jsonl

    # Verify a root on-chain:
    python ledger/anchor.py verify --root <hex-hash>

Prerequisites:
    - .env file with AMOY_RPC_URL, AMOY_PRIVATE_KEY, AMOY_WALLET_ADDRESS
    - Wallet funded with test POL from https://faucet.polygon.technology/
    - pip install web3 python-dotenv

Configuration (saved after deploy):
    - ledger/contracts/deployed_address.txt — contract address on Amoy
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

try:
    from web3 import Web3
    from eth_account import Account
except ImportError:
    sys.exit("ERROR: web3 not installed. Run: pip install web3")

try:
    from dotenv import load_dotenv
    import os
    load_dotenv()
except ImportError:
    sys.exit("ERROR: python-dotenv not installed. Run: pip install python-dotenv")

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = REPO_ROOT / "ledger" / "contracts"
ABI_PATH = CONTRACTS_DIR / "AttestorAnchor.abi.json"
BIN_PATH = CONTRACTS_DIR / "AttestorAnchor.bin"
DEPLOYED_ADDRESS_PATH = CONTRACTS_DIR / "deployed_address.txt"
CHAIN_FILE = REPO_ROOT / "ledger" / "chain.jsonl"


def get_web3() -> Web3:
    rpc_url = os.environ.get("AMOY_RPC_URL")
    if not rpc_url:
        sys.exit("ERROR: AMOY_RPC_URL not set in .env")
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        sys.exit(f"ERROR: Cannot connect to {rpc_url}")
    return w3


def get_account():
    private_key = os.environ.get("AMOY_PRIVATE_KEY")
    if not private_key:
        sys.exit("ERROR: AMOY_PRIVATE_KEY not set in .env")
    return Account.from_key(private_key)


def compute_chain_root(chain_path: Path) -> str:
    """Compute a root hash over all entries in the chain file.
    
    Method: SHA-256 of concatenated content_hashes (ordered by appearance).
    This gives a single fingerprint representing the entire chain state.
    """
    if not chain_path.exists():
        sys.exit(f"ERROR: Chain file not found: {chain_path}")
    
    hashes = []
    for line in chain_path.read_text().splitlines():
        if line.strip():
            record = json.loads(line)
            hashes.append(record["content_hash"])
    
    if not hashes:
        sys.exit("ERROR: Chain file is empty")
    
    combined = "".join(hashes).encode("utf-8")
    root = hashlib.sha256(combined).hexdigest()
    return root


def deploy(args):
    """Deploy the AttestorAnchor contract to Amoy."""
    w3 = get_web3()
    account = get_account()
    
    abi = json.loads(ABI_PATH.read_text())
    bytecode = BIN_PATH.read_text().strip()
    
    print(f"Deploying AttestorAnchor to Polygon Amoy (chain {w3.eth.chain_id})...")
    print(f"  From: {account.address}")
    
    balance = w3.eth.get_balance(account.address)
    print(f"  Balance: {Web3.from_wei(balance, 'ether')} POL")
    if balance == 0:
        sys.exit("ERROR: Wallet has 0 POL. Fund it from https://faucet.polygon.technology/")
    
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    
    tx = contract.constructor().build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 1_000_000,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    })
    
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"  Tx sent: {tx_hash.hex()}")
    
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    contract_address = receipt.contractAddress
    print(f"  Contract deployed at: {contract_address}")
    print(f"  Tx hash: {tx_hash.hex()}")
    print(f"  Block: {receipt.blockNumber}")
    print(f"  Gas used: {receipt.gasUsed}")
    print(f"\n  View on Polygonscan: https://amoy.polygonscan.com/address/{contract_address}")
    
    # Save address
    DEPLOYED_ADDRESS_PATH.write_text(contract_address)
    print(f"  Address saved to: {DEPLOYED_ADDRESS_PATH}")


def anchor(args):
    """Anchor the current chain root hash on-chain."""
    w3 = get_web3()
    account = get_account()
    
    if not DEPLOYED_ADDRESS_PATH.exists():
        sys.exit("ERROR: Contract not deployed yet. Run: python ledger/anchor.py deploy")
    
    contract_address = DEPLOYED_ADDRESS_PATH.read_text().strip()
    abi = json.loads(ABI_PATH.read_text())
    contract = w3.eth.contract(address=contract_address, abi=abi)
    
    chain_path = Path(args.chain_file) if args.chain_file else CHAIN_FILE
    root = compute_chain_root(chain_path)
    root_bytes = bytes.fromhex(root)
    
    print(f"Anchoring root hash on-chain...")
    print(f"  Chain file: {chain_path}")
    print(f"  Root hash: 0x{root}")
    print(f"  Contract: {contract_address}")
    
    tx = contract.functions.anchorRoot(root_bytes).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 200_000,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    })
    
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"  Tx sent: {tx_hash.hex()}")
    
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    print(f"  Confirmed in block: {receipt.blockNumber}")
    print(f"  Gas used: {receipt.gasUsed}")
    print(f"\n  Verify on Polygonscan: https://amoy.polygonscan.com/tx/{tx_hash.hex()}")
    print(f"  Anyone can independently confirm this root was anchored at this time.")


def verify(args):
    """Verify if a root hash exists on-chain (publicly, no special access)."""
    w3 = get_web3()
    
    if not DEPLOYED_ADDRESS_PATH.exists():
        sys.exit("ERROR: Contract not deployed yet.")
    
    contract_address = DEPLOYED_ADDRESS_PATH.read_text().strip()
    abi = json.loads(ABI_PATH.read_text())
    contract = w3.eth.contract(address=contract_address, abi=abi)
    
    root_hex = args.root.replace("0x", "")
    root_bytes = bytes.fromhex(root_hex)
    
    print(f"Verifying root on-chain...")
    print(f"  Root: 0x{root_hex}")
    print(f"  Contract: {contract_address}")
    
    found, timestamp, submitter = contract.functions.verifyRoot(root_bytes).call()
    
    if found:
        from datetime import datetime, timezone
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        print(f"\n  ✓ ROOT FOUND ON-CHAIN")
        print(f"  Anchored at: {dt.isoformat()}")
        print(f"  Submitted by: {submitter}")
        print(f"  This proves the chain state existed at that time — independently verifiable.")
    else:
        print(f"\n  ✗ ROOT NOT FOUND ON-CHAIN")
        print(f"  This root has not been anchored.")


def main():
    parser = argparse.ArgumentParser(description="Attestor testnet anchoring (Polygon Amoy)")
    sub = parser.add_subparsers(dest="command")
    
    sub.add_parser("deploy", help="Deploy AttestorAnchor contract to Amoy")
    
    anchor_p = sub.add_parser("anchor", help="Anchor current chain root on-chain")
    anchor_p.add_argument("--chain-file", default=None, help="Path to chain.jsonl")
    
    verify_p = sub.add_parser("verify", help="Verify a root hash exists on-chain")
    verify_p.add_argument("--root", required=True, help="Root hash to verify (hex)")
    
    args = parser.parse_args()
    
    if args.command == "deploy":
        deploy(args)
    elif args.command == "anchor":
        anchor(args)
    elif args.command == "verify":
        verify(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
