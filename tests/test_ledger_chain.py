"""Phase 4 exit condition test: tamper-evident ledger chain.

Tests:
  * 3-report chain builds correctly (prev_hash links)
  * verify() confirms intact chain
  * Tampering with a report's content is detected via content re-check
  * Re-serialization with different key order does NOT falsely break the chain
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ledger.chain import append, verify, load_results, GENESIS_HASH
from ledger.canonical import content_hash


def _make_results(report_id: str, host: str = "test-host", status: str = "pass") -> dict:
    """Create a minimal valid results.json for testing."""
    return {
        "attestor_format_version": "1.0",
        "report_id": report_id,
        "target": "test",
        "benchmark": "Test Benchmark",
        "benchmark_version": "v1.0.0",
        "host": {"hostname": host, "os_name": "Test", "os_version": "1.0",
                 "os_id": "test", "kernel": "1.0", "arch": "x86_64",
                 "environment": "native", "elevated": True, "user": "root"},
        "run": {"started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:01Z",
                "complete": True, "total_controls": 1, "evaluated": 1,
                "engine": "test", "engine_version": "0.1.0"},
        "summary": {"pass": 1 if status == "pass" else 0, "fail": 0 if status == "pass" else 1,
                    "error": 0, "manual": 0, "not_applicable": 0},
        "controls": [{
            "rule_id": "1.1.1", "title": "Test control", "level": 1,
            "profile": ["server"], "severity": "medium", "automated": True,
            "status": status,
            "checks": [{"rule_id": "1.1.1", "check_index": 0, "status": status,
                        "actual": "1", "expected": "1", "evidence": "test",
                        "timestamp": "2026-01-01T00:00:01Z"}],
            "evidence_summary": "test", "remediation": "fix it", "source": "test"
        }],
    }


def _setup_chain(tmp_path: Path):
    """Build a 3-report chain and return (chain_path, reports_dir, records)."""
    chain_path = tmp_path / "chain.jsonl"
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()

    results = []
    for i, rid in enumerate(["report-aaa", "report-bbb", "report-ccc"]):
        r = _make_results(rid, status="pass" if i % 2 == 0 else "fail")
        path = reports_dir / f"{rid}.json"
        path.write_text(json.dumps(r, ensure_ascii=False), encoding="utf-8")
        results.append((path, r))

    records = []
    for path, _ in results:
        rec = append(path, "test-host", chain_path=chain_path)
        records.append(rec)

    return chain_path, reports_dir, records, results


def test_chain_builds_correctly(tmp_path):
    chain_path, _, records, _ = _setup_chain(tmp_path)
    assert records[0]["prev_hash"] == GENESIS_HASH
    assert records[1]["prev_hash"] == records[0]["content_hash"]
    assert records[2]["prev_hash"] == records[1]["content_hash"]
    assert len(chain_path.read_text().splitlines()) == 3


def test_verify_intact(tmp_path):
    chain_path, reports_dir, _, _ = _setup_chain(tmp_path)
    result = verify("test-host", chain_path=chain_path)
    assert result["intact"] is True
    assert result["links"] == 3
    # Also with content re-check
    result2 = verify("test-host", chain_path=chain_path, results_dir=reports_dir)
    assert result2["intact"] is True


def test_tamper_detected(tmp_path):
    chain_path, reports_dir, records, results = _setup_chain(tmp_path)
    # Tamper with report #2 (index 1)
    _, r2 = results[1]
    tampered = copy.deepcopy(r2)
    tampered["controls"][0]["status"] = "pass"  # was "fail"
    r2_path = reports_dir / f"{r2['report_id']}.json"
    r2_path.write_text(json.dumps(tampered, ensure_ascii=False), encoding="utf-8")
    # Verify detects the tamper
    result = verify("test-host", chain_path=chain_path, results_dir=reports_dir)
    assert result["intact"] is False
    assert result["broken_at"] == 1
    assert "content_hash mismatch" in result["reason"]


def test_reserialization_no_false_break(tmp_path):
    """Different key order / whitespace must produce the same content_hash."""
    r = _make_results("report-xyz")
    shuffled = {k: r[k] for k in reversed(list(r.keys()))}
    assert content_hash(r) == content_hash(shuffled)
    # Round-trip through pretty-printed JSON
    pretty = json.dumps(r, indent=4, sort_keys=False)
    reparsed = json.loads(pretty)
    assert content_hash(r) == content_hash(reparsed)


def test_empty_host_verifies_intact(tmp_path):
    chain_path = tmp_path / "chain.jsonl"
    chain_path.write_text("", encoding="utf-8")
    result = verify("nonexistent-host", chain_path=chain_path)
    assert result["intact"] is True
    assert result["links"] == 0
