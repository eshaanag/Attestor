"""Attestor tamper-evident ledger — append and verify.

Implements the SHA-256 hash chain over report content, per docs/interfaces.md §4.
Each generated report is hash-chained to the previous report for that host, so
findings can be proven un-tampered-with after the fact.

Uses ledger/canonical.py (the single source of truth for canonicalization + hashing)
— does NOT re-implement hashing.

Chain storage: ``ledger/chain.jsonl`` — one JSON object per line, append-only.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ledger.canonical import content_hash

CHAIN_FILE = Path(__file__).parent / "chain.jsonl"
GENESIS_HASH = "0" * 64  # prev_hash for the first entry of any host


def _now() -> str:
    """UTC ISO-8601, second precision, Z suffix (interfaces.md §0)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_chain(chain_path: Path | None = None) -> list[dict[str, Any]]:
    """Load all chain records from the JSONL file."""
    path = chain_path or CHAIN_FILE
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def _get_last_hash_for_host(records: list[dict[str, Any]], host_id: str) -> str:
    """Return the content_hash of the most recent record for this host, or GENESIS."""
    for record in reversed(records):
        if record["host_id"] == host_id:
            return record["content_hash"]
    return GENESIS_HASH


def load_results(path: str | Path) -> dict[str, Any]:
    """Load a results.json, handling Windows BOM if present."""
    raw = Path(path).read_bytes()
    if raw[:3] == b"\xef\xbb\xbf":
        raw = raw[3:]
    return json.loads(raw.decode("utf-8"))


def append(results_json_path: str | Path, host_id: str,
           chain_path: Path | None = None) -> dict[str, Any]:
    """Append a new entry to the chain for the given host.

    Args:
        results_json_path: Path to the results.json to chain.
        host_id: Stable identifier for this host (e.g. hostname).
        chain_path: Override for the chain file (default: ledger/chain.jsonl).

    Returns:
        The appended chain record.
    """
    path = chain_path or CHAIN_FILE
    results = load_results(results_json_path)

    # Compute the content hash via canonical.py (single source of truth).
    c_hash = content_hash(results)

    # Get the previous hash for this host.
    records = _load_chain(path)
    prev = _get_last_hash_for_host(records, host_id)

    # Build the chain record (interfaces.md §4).
    record = {
        "host_id": host_id,
        "report_id": results["report_id"],
        "timestamp": _now(),
        "prev_hash": prev,
        "content_hash": c_hash,
    }

    # Append to the chain file (create if missing).
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")

    return record


def verify(host_id: str, chain_path: Path | None = None,
           results_dir: Path | None = None) -> dict[str, Any]:
    """Verify the chain integrity for a given host.

    Walks the chain for this host and confirms each link: prev_hash[n] must equal
    content_hash[n-1] (or GENESIS for the first). Does NOT re-verify content_hash
    against the original results.json (that requires the files to still exist).

    Args:
        host_id: The host whose chain to verify.
        chain_path: Override for the chain file.
        results_dir: If provided, also re-verify each content_hash against the
                     stored results.json files in this directory (by report_id).

    Returns:
        {"intact": True/False, "links": N, "broken_at": None or link index,
         "reason": description if broken}
    """
    path = chain_path or CHAIN_FILE
    records = _load_chain(path)

    # Filter to this host's records (in order).
    host_records = [r for r in records if r["host_id"] == host_id]

    if not host_records:
        return {"intact": True, "links": 0, "broken_at": None, "reason": None}

    # Walk the chain.
    expected_prev = GENESIS_HASH
    for i, record in enumerate(host_records):
        # Check prev_hash links correctly.
        if record["prev_hash"] != expected_prev:
            return {
                "intact": False,
                "links": len(host_records),
                "broken_at": i,
                "reason": (
                    f"Link {i}: prev_hash mismatch. "
                    f"Expected prev_hash={expected_prev[:16]}..., "
                    f"got {record['prev_hash'][:16]}..."
                ),
            }

        # If results_dir is provided, re-verify content_hash against the file.
        if results_dir:
            results_file = results_dir / f"{record['report_id']}.json"
            if results_file.exists():
                results = load_results(results_file)
                recomputed = content_hash(results)
                if recomputed != record["content_hash"]:
                    return {
                        "intact": False,
                        "links": len(host_records),
                        "broken_at": i,
                        "reason": (
                            f"Link {i}: content_hash mismatch (report tampered). "
                            f"Chain says {record['content_hash'][:16]}..., "
                            f"recomputed {recomputed[:16]}..."
                        ),
                    }

        expected_prev = record["content_hash"]

    return {"intact": True, "links": len(host_records), "broken_at": None, "reason": None}
