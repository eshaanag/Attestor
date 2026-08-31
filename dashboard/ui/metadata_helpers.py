"""
metadata_helpers.py - Audit metadata helpers for the Attestor dashboard UI.

Provides small, pure helpers for extracting and formatting audit metadata
for display in dashboard components.
"""

from typing import Any


def get_audit_identifier(audit_data: dict[str, Any]) -> str:
    """Return the audit identifier as a display string.

    Missing identifiers are represented as ``"Unknown audit"``.
    """
    value = audit_data.get("audit_id")
    if value is None or str(value).strip() == "":
        return "Unknown audit"
    return str(value)


def get_platform(audit_data: dict[str, Any]) -> str:
    """Return the platform name from an audit result."""
    value = audit_data.get("platform")
    if value is None or str(value).strip() == "":
        return "Unknown platform"
    return str(value)


def get_benchmark_name(audit_data: dict[str, Any]) -> str:
    """Return the benchmark name from an audit result."""
    value = audit_data.get("benchmark")
    if value is None or str(value).strip() == "":
        return "Unknown benchmark"
    return str(value)


def get_benchmark_version(audit_data: dict[str, Any]) -> str:
    """Return the benchmark version from an audit result."""
    value = audit_data.get("benchmark_version")
    if value is None or str(value).strip() == "":
        return "Unknown version"
    return str(value)


def get_hostname(audit_data: dict[str, Any]) -> str:
    """Return the audited hostname."""
    value = audit_data.get("hostname")
    if value is None or str(value).strip() == "":
        return "Unknown host"
    return str(value)


def get_timestamp(audit_data: dict[str, Any]) -> str:
    """Return the audit timestamp as a display string."""
    value = audit_data.get("timestamp")
    if value is None or str(value).strip() == "":
        return "Unknown time"
    return str(value)


def build_metadata_summary(audit_data: dict[str, Any]) -> dict[str, str]:
    """Build a normalized metadata dictionary for dashboard rendering.

    The returned dictionary contains consistently named display values and
    does not modify the supplied audit data.
    """
    return {
        "audit_id": get_audit_identifier(audit_data),
        "platform": get_platform(audit_data),
        "benchmark": get_benchmark_name(audit_data),
        "benchmark_version": get_benchmark_version(audit_data),
        "hostname": get_hostname(audit_data),
        "timestamp": get_timestamp(audit_data),
    }