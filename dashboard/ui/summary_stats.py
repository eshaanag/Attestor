"""
summary_stats.py - Summary statistics helpers for the Attestor dashboard UI.

Provides pure functions for calculating status counts, severity counts,
percentages, and a complete dashboard summary from a list of audit controls.
None of the functions mutate their input, and all use only Python
standard-library functionality.
"""

from typing import Any, Iterable

# Recognised values - unknown entries are silently ignored.
_STATUSES: tuple[str, ...] = ("Pass", "Fail", "Error")
_SEVERITIES: tuple[str, ...] = ("High", "Medium", "Low")


def calculate_status_counts(
    controls: Iterable[dict[str, Any]],
) -> dict[str, int]:
    """Count controls by their status value.

    Only the statuses ``"Pass"``, ``"Fail"``, and ``"Error"`` are counted.
    Controls with missing or unknown ``"status"`` keys are silently ignored.
    Every recognised status is present in the returned dictionary even when
    its count is zero.

    Args:
        controls: Iterable of control dictionaries from an audit result.

    Returns:
        A dictionary mapping each recognised status to its count.
    """
    counts: dict[str, int] = {s: 0 for s in _STATUSES}
    for c in controls:
        status = c.get("status")
        if status in counts:
            counts[status] += 1
    return counts


def calculate_severity_counts(
    controls: Iterable[dict[str, Any]],
) -> dict[str, int]:
    """Count controls by their severity value.

    Only ``"High"``, ``"Medium"``, and ``"Low"`` are counted.  Controls with
    missing or unknown ``"severity"`` keys are silently ignored.  Every
    recognised severity is present in the returned dictionary even when its
    count is zero.

    Args:
        controls: Iterable of control dictionaries from an audit result.

    Returns:
        A dictionary mapping each recognised severity to its count.
    """
    counts: dict[str, int] = {s: 0 for s in _SEVERITIES}
    for c in controls:
        severity = c.get("severity")
        if severity in counts:
            counts[severity] += 1
    return counts


def calculate_summary_percentages(
    counts: dict[str, int],
    total: int,
) -> dict[str, float]:
    """Convert a counts dictionary to percentages.

    Divides each count by *total* and multiplies by 100.  Returns 0.0 for
    every key when *total* is zero to avoid division-by-zero.  The input
    dictionary is not mutated.

    Args:
        counts: A dictionary mapping label strings to integer counts.
        total:  The denominator for percentage calculation.

    Returns:
        A dictionary with the same keys as *counts*, each mapped to a
        float percentage in the range [0.0, 100.0].
    """
    if not total:
        return {k: 0.0 for k in counts}
    return {k: (v / total) * 100.0 for k, v in counts.items()}


def build_dashboard_summary(
    controls: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Build a complete dashboard summary from a list of audit controls.

    Calculates all statistics directly from the supplied controls rather
    than relying on a pre-existing summary block.  The input is not mutated.

    Args:
        controls: Iterable of control dictionaries from an audit result.

    Returns:
        A dictionary containing:
        - ``total``           (int)  total number of controls processed
        - ``status_counts``   (dict) per-status counts
        - ``severity_counts`` (dict) per-severity counts
        - ``pass_percentage`` (float)
        - ``fail_percentage`` (float)
        - ``error_percentage`` (float)
    """
    control_list = list(controls)
    total = len(control_list)
    status_counts   = calculate_status_counts(control_list)
    severity_counts = calculate_severity_counts(control_list)
    percentages     = calculate_summary_percentages(status_counts, total)

    return {
        "total":           total,
        "status_counts":   status_counts,
        "severity_counts": severity_counts,
        "pass_percentage":  percentages.get("Pass",  0.0),
        "fail_percentage":  percentages.get("Fail",  0.0),
        "error_percentage": percentages.get("Error", 0.0),
    }
