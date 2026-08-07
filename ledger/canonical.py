"""Canonical serialization + content hashing for Attestor reports.

This is the single, authoritative implementation of the canonicalization contract
pinned in ``docs/interfaces.md`` §4. The ledger (Phase 4) and any consumer that
needs a reproducible hash of a ``results.json`` MUST use these functions rather
than calling ``json.dumps`` directly — the hash chain's tamper-evidence depends on
byte-for-byte reproducible output.

Contract summary (see docs/interfaces.md §4 for the full spec):
  * exclude ledger-injected top-level keys (default: ("ledger",)) before hashing
  * sort object keys recursively (json.dumps sort_keys=True)
  * pin array order: controls by rule_id (dotted-int tuple), checks by check_index
  * separators=(",", ":"); ensure_ascii=False; encode UTF-8
  * SHA-256 the resulting bytes

Any change to the output of these functions is a breaking change to the report
hash and is guarded by tests/test_canonical_hash.py.
"""
from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

# Top-level keys excluded from the hashed content (belt-and-braces: results.json
# itself should not contain these; the ledger stores its hash separately).
LEDGER_KEYS: tuple[str, ...] = ("ledger",)


def _rule_id_key(rule_id: str) -> tuple[int, ...]:
    """Sort key for a dotted CIS id, e.g. "1.10" -> (1, 10) so 1.10 > 1.9."""
    return tuple(int(part) for part in rule_id.split("."))


def canonicalize(results: dict[str, Any], exclude_keys: tuple[str, ...] = LEDGER_KEYS) -> dict[str, Any]:
    """Return a deep copy with excluded top-level keys removed and array order pinned.

    Key *sorting* is delegated to ``json.dumps(sort_keys=True)`` in
    :func:`canonical_bytes`. Input is not mutated.
    """
    obj: dict[str, Any] = {k: copy.deepcopy(v) for k, v in results.items() if k not in exclude_keys}
    if "controls" in obj and isinstance(obj["controls"], list):
        controls = sorted(obj["controls"], key=lambda c: _rule_id_key(c["rule_id"]))
        for control in controls:
            checks = control.get("checks")
            if checks:
                control["checks"] = sorted(checks, key=lambda ck: ck["check_index"])
        obj["controls"] = controls
    return obj


def canonical_bytes(results: dict[str, Any], exclude_keys: tuple[str, ...] = LEDGER_KEYS) -> bytes:
    """Serialize ``results`` to the canonical UTF-8 byte form used for hashing."""
    obj = canonicalize(results, exclude_keys)
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def content_hash(results: dict[str, Any], exclude_keys: tuple[str, ...] = LEDGER_KEYS) -> str:
    """Return the SHA-256 hex digest of the canonical byte form of ``results``."""
    return hashlib.sha256(canonical_bytes(results, exclude_keys)).hexdigest()
