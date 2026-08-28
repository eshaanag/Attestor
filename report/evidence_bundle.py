"""Build self-contained, privacy-bounded evidence exports for completed scans."""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ledger.canonical import content_hash


BUNDLE_FORMAT_VERSION = "attestor-evidence-bundle-v1"
_CANONICAL_RULE_ID = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_integrity(results: dict[str, Any]) -> dict[str, Any]:
    rule_ids = [str(control.get("rule_id", "")) for control in results.get("controls", [])]
    if rule_ids and all(_CANONICAL_RULE_ID.fullmatch(rule_id) for rule_id in rule_ids):
        return {
            "status": "available",
            "algorithm": "sha256",
            "value": content_hash(results),
            "contract": "ledger/canonical.py",
        }
    return {
        "status": "not_applicable",
        "algorithm": "sha256",
        "value": None,
        "contract": "ledger/canonical.py",
        "reason": "report contains rule IDs outside the pinned dotted-numeric ledger contract",
    }


def _control_provenance(results: dict[str, Any]) -> list[dict[str, Any]]:
    provenance = []
    for control in results.get("controls", []):
        provenance.append({
            "rule_id": control.get("rule_id"),
            "source": control.get("source"),
            "verification_status": control.get(
                "verification_status", results.get("verification_status", "attestor_verified")
            ),
            "framework_mappings": control.get("framework_mappings", []),
        })
    return provenance


def build_evidence_bundle(
    results: dict[str, Any],
    json_path: Path,
    html_path: Path,
    pdf_path: Path,
    output_path: Path,
    *,
    source_filename: str,
    framework_view: str,
    integrity_status: str,
) -> dict[str, Any]:
    """Write a ZIP containing existing reports and a verification manifest."""
    source_paths = (
        ("report.json", "application/json", Path(json_path)),
        ("report.html", "text/html", Path(html_path)),
        ("report.pdf", "application/pdf", Path(pdf_path)),
    )
    artifacts: list[dict[str, Any]] = []
    artifact_bytes: dict[str, bytes] = {}
    for archive_name, media_type, path in source_paths:
        data = path.read_bytes()
        artifact_bytes[archive_name] = data
        artifacts.append({
            "path": archive_name,
            "media_type": media_type,
            "size_bytes": len(data),
            "sha256": _sha256(data),
        })

    device = results.get("device") or {}
    facts_source = device.get("facts_source") or {}
    manifest = {
        "bundle_format_version": BUNDLE_FORMAT_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "report_id": results.get("report_id"),
        "target": results.get("target"),
        "source_filename": source_filename,
        "framework_view": framework_view,
        "assurance": results.get("verification_status", "attestor_verified"),
        "device": {
            "device_id": device.get("device_id"),
            "hostname": device.get("hostname"),
            "vendor": device.get("vendor"),
            "platform": device.get("platform"),
            "model": device.get("model"),
            "software_version": device.get("software_version"),
            "serial_number": device.get("serial_number"),
            "config_sha256": device.get("config_sha256"),
            "facts_sha256": facts_source.get("sha256"),
        },
        "summary": results.get("summary", {}),
        "integrity": {
            "chain_status": integrity_status,
            "canonical_report": _canonical_integrity(results),
        },
        "artifacts": artifacts,
        "provenance": {
            "benchmark": results.get("benchmark"),
            "benchmark_version": results.get("benchmark_version"),
            "controls": _control_provenance(results),
            "device_facts_source": facts_source or None,
        },
        "privacy": {
            "raw_configuration_file_included": False,
            "report_artifacts_included": True,
            "may_contain_sensitive_report_evidence": True,
            "handling": "treat the bundle as sensitive audit evidence",
            "blockchain_payload": "hash roots only when explicitly anchored; report content stays local",
        },
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    partial_path = output_path.with_name(f"{output_path.name}.part")
    partial_path.unlink(missing_ok=True)
    try:
        with zipfile.ZipFile(partial_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for archive_name, _, _ in source_paths:
                archive.writestr(archive_name, artifact_bytes[archive_name])
            archive.writestr("manifest.json", manifest_bytes)
        partial_path.replace(output_path)
    except Exception:
        partial_path.unlink(missing_ok=True)
        raise
    return manifest
