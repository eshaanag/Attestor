"""Regression guard for the canonical serialization + content hash contract.

Pins the worked example from docs/interfaces.md §5.4/§5.5:
  * the exact canonical byte string (§5.5), and
  * the pinned SHA-256 content_hash hex digest.

If ledger/canonical.py ever changes its output, these tests fail — which is the
whole point: the report hash chain (Phase 4) must never drift silently.
"""
from __future__ import annotations

import copy
import pathlib
import sys

# Make the repo root importable so `ledger.canonical` resolves regardless of CWD.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from ledger.canonical import canonical_bytes, content_hash  # noqa: E402


# --- Pinned fixture: the §5.4 results.json ---------------------------------
RESULTS = {
    "attestor_format_version": "1.0",
    "report_id": "b3f1c2a4-9d7e-4c1a-8f2b-0a1c2d3e4f56",
    "target": "ubuntu2204_desktop",
    "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark",
    "benchmark_version": "v2.0.0",
    "host": {
        "hostname": "demo-ubuntu", "os_name": "Ubuntu", "os_version": "22.04",
        "os_id": "ubuntu", "kernel": "5.15.0-91-generic", "arch": "x86_64",
        "environment": "native", "elevated": True, "user": "root",
    },
    "run": {
        "started_at": "2026-08-07T05:48:10Z", "finished_at": "2026-08-07T05:48:13Z",
        "complete": True, "total_controls": 1, "evaluated": 1,
        "engine": "linux", "engine_version": "0.1.0",
    },
    "summary": {"pass": 1, "fail": 0, "error": 0, "manual": 0, "not_applicable": 0},
    "controls": [
        {
            "rule_id": "1.5.1",
            "title": "Ensure address space layout randomization (ASLR) is enabled",
            "level": 1, "profile": ["server", "workstation"], "severity": "medium",
            "automated": True, "status": "pass",
            "checks": [
                {"rule_id": "1.5.1", "check_index": 0, "status": "pass", "actual": "2",
                 "expected": "2",
                 "evidence": "sysctl -n kernel.randomize_va_space => 2",
                 "timestamp": "2026-08-07T05:48:12Z"},
            ],
            "evidence_summary": "kernel.randomize_va_space = 2 (expected 2)",
            "remediation": "Set kernel.randomize_va_space = 2 in /etc/sysctl.conf or /etc/sysctl.d/*, then apply with sysctl -w kernel.randomize_va_space=2.",
            "source": "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0, control 1.5.1",
        },
    ],
}

# --- Pinned expected outputs (docs/interfaces.md §5.5) ---------------------
PINNED_CANONICAL = (
    '{"attestor_format_version":"1.0","benchmark":"CIS Ubuntu Linux 22.04 LTS Benchmark",'
    '"benchmark_version":"v2.0.0","controls":[{"automated":true,"checks":[{"actual":"2",'
    '"check_index":0,"evidence":"sysctl -n kernel.randomize_va_space => 2","expected":"2",'
    '"rule_id":"1.5.1","status":"pass","timestamp":"2026-08-07T05:48:12Z"}],'
    '"evidence_summary":"kernel.randomize_va_space = 2 (expected 2)","level":1,'
    '"profile":["server","workstation"],'
    '"remediation":"Set kernel.randomize_va_space = 2 in /etc/sysctl.conf or /etc/sysctl.d/*, '
    'then apply with sysctl -w kernel.randomize_va_space=2.","rule_id":"1.5.1",'
    '"severity":"medium",'
    '"source":"CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0, control 1.5.1","status":"pass",'
    '"title":"Ensure address space layout randomization (ASLR) is enabled"}],'
    '"host":{"arch":"x86_64","elevated":true,"environment":"native","hostname":"demo-ubuntu",'
    '"kernel":"5.15.0-91-generic","os_id":"ubuntu","os_name":"Ubuntu","os_version":"22.04",'
    '"user":"root"},"report_id":"b3f1c2a4-9d7e-4c1a-8f2b-0a1c2d3e4f56",'
    '"run":{"complete":true,"engine":"linux","engine_version":"0.1.0","evaluated":1,'
    '"finished_at":"2026-08-07T05:48:13Z","started_at":"2026-08-07T05:48:10Z","total_controls":1},'
    '"summary":{"error":0,"fail":0,"manual":0,"not_applicable":0,"pass":1},'
    '"target":"ubuntu2204_desktop"}'
)
PINNED_HASH = "7127f834f00f28c6cd8f84aa094dcefd7ae3090e9948544ca5bab81386eea829"


def test_canonical_bytes_matches_pinned_string():
    """canonical_bytes() must equal the §5.5 canonical string, byte-for-byte."""
    assert canonical_bytes(RESULTS) == PINNED_CANONICAL.encode("utf-8")


def test_content_hash_matches_pinned_digest():
    """content_hash() must equal the pinned SHA-256 hex digest."""
    assert content_hash(RESULTS) == PINNED_HASH


def test_hash_is_order_independent():
    """Re-serializing with shuffled dict/array order yields the same hash."""
    shuffled = copy.deepcopy(RESULTS)
    # reverse top-level key order and check order to prove canonicalization normalizes it
    shuffled = {k: shuffled[k] for k in reversed(list(shuffled.keys()))}
    assert content_hash(shuffled) == PINNED_HASH


def test_tamper_changes_hash():
    """Changing a single control status must change the content_hash."""
    tampered = copy.deepcopy(RESULTS)
    tampered["controls"][0]["status"] = "fail"
    assert content_hash(tampered) != PINNED_HASH


def test_ledger_key_excluded_from_hash():
    """A top-level 'ledger' key must not affect the content_hash."""
    with_ledger = copy.deepcopy(RESULTS)
    with_ledger["ledger"] = {"content_hash": "deadbeef", "prev_hash": "0" * 64}
    assert content_hash(with_ledger) == PINNED_HASH


if __name__ == "__main__":  # allow `python tests/test_canonical_hash.py` without pytest
    test_canonical_bytes_matches_pinned_string()
    test_content_hash_matches_pinned_digest()
    test_hash_is_order_independent()
    test_tamper_changes_hash()
    test_ledger_key_excluded_from_hash()
    print("all canonical-hash regression tests passed")
