"""
result_formatter.py - Dashboard result formatting helpers.

Provides pure helpers for converting raw audit controls into consistent
display-ready dictionaries for the Attestor dashboard UI.
"""

from typing import Any, Iterable


def format_control(control: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized display dictionary for one audit control.

    Missing optional values receive sensible display defaults. The original
    control dictionary is never modified.
    """
    status = str(control.get("status", "Unknown"))
    severity = str(control.get("severity", "Unknown"))

    return {
        "id": str(control.get("id", "Unknown")),
        "title": str(control.get("title", "Untitled control")),
        "status": status,
        "severity": severity,
        "description": str(control.get("description", "")),
        "remediation": str(control.get("remediation", "")).strip(),
        "requires_attention": status in {"Fail", "Error"},
    }


def format_controls(
    controls: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalize a collection of audit controls for dashboard display."""
    return [format_control(control) for control in controls]


def format_status_label(status: str) -> str:
    """Return a human-readable label for a control status."""
    labels = {
        "Pass": "Passed",
        "Fail": "Failed",
        "Error": "Error",
    }
    return labels.get(status, "Unknown")


def format_severity_label(severity: str) -> str:
    """Return a human-readable label for a control severity."""
    labels = {
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
    }
    return labels.get(severity, "Unknown")


def build_result_row(control: dict[str, Any]) -> dict[str, Any]:
    """Build a compact dashboard result-row representation.

    The returned structure contains the fields most commonly required by
    a results table without changing the original control.
    """
    formatted = format_control(control)

    return {
        "id": formatted["id"],
        "title": formatted["title"],
        "status": formatted["status"],
        "status_label": format_status_label(formatted["status"]),
        "severity": formatted["severity"],
        "severity_label": format_severity_label(formatted["severity"]),
        "requires_attention": formatted["requires_attention"],
    }


def build_result_rows(
    controls: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build dashboard result rows for all supplied controls."""
    return [build_result_row(control) for control in controls]