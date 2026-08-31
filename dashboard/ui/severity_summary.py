"""
severity_summary.py - Severity-focused dashboard helpers.

Provides pure helpers for summarising audit findings by severity and
identifying the most important severity level present in an audit.
"""

from typing import Any, Iterable


_SEVERITY_ORDER: tuple[str, ...] = ("High", "Medium", "Low")


def count_by_severity(
    controls: Iterable[dict[str, Any]],
) -> dict[str, int]:
    """Count recognised control severities.

    Returns counts for High, Medium, and Low. Unknown or missing severity
    values are ignored, and the input is not modified.
    """
    counts = {severity: 0 for severity in _SEVERITY_ORDER}

    for control in controls:
        severity = control.get("severity")
        if severity in counts:
            counts[severity] += 1

    return counts


def highest_severity(
    controls: Iterable[dict[str, Any]],
) -> str | None:
    """Return the highest severity present in the supplied controls.

    Returns ``"High"``, ``"Medium"``, or ``"Low"`` depending on the most
    severe recognised value. Returns ``None`` when no recognised severity
    exists.
    """
    present = {
        control.get("severity")
        for control in controls
        if control.get("severity") in _SEVERITY_ORDER
    }

    for severity in _SEVERITY_ORDER:
        if severity in present:
            return severity

    return None


def severity_percentages(
    controls: Iterable[dict[str, Any]],
) -> dict[str, float]:
    """Calculate the percentage distribution of recognised severities.

    Percentages are based on recognised severity values only. When there
    are no recognised severities, all returned percentages are 0.0.
    """
    counts = count_by_severity(controls)
    total = sum(counts.values())

    if total == 0:
        return {severity: 0.0 for severity in _SEVERITY_ORDER}

    return {
        severity: (count / total) * 100.0
        for severity, count in counts.items()
    }


def build_severity_summary(
    controls: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Build a dashboard-ready severity summary.

    Returns counts, percentages, total recognised findings, and the highest
    severity present. The supplied controls are not modified.
    """
    control_list = list(controls)
    counts = count_by_severity(control_list)

    return {
        "counts": counts,
        "percentages": severity_percentages(control_list),
        "total": sum(counts.values()),
        "highest": highest_severity(control_list),
    }