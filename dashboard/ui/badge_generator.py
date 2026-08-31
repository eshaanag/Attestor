"""
badge_generator.py - Compliance summary helpers for the Attestor dashboard UI.

Provides three pure functions for turning an audit summary dictionary into
human-readable compliance information.  None of the functions mutate their
input, and all use only Python standard-library functionality.
"""

from typing import Any


def compliance_percentage(summary: dict[str, Any]) -> float:
    """Calculate the percentage of controls that passed.

    Args:
        summary: A dictionary containing at least the keys ``total`` and
                 ``passed``, as produced by the Attestor audit engines.

    Returns:
        Percentage of passed controls as a float in the range [0.0, 100.0].
        Returns 0.0 when ``total`` is zero to avoid division-by-zero.
    """
    total = summary.get("total", 0)
    if not total:
        return 0.0
    return (summary.get("passed", 0) / total) * 100.0


def compliance_badge(summary: dict[str, Any]) -> str:
    """Return a concise human-readable compliance summary string.

    Example output: ``"70% compliant (14/20 passed)"``

    Args:
        summary: A dictionary containing ``total`` and ``passed``.

    Returns:
        A formatted badge string suitable for report headers and UI widgets.
    """
    pct = compliance_percentage(summary)
    passed = summary.get("passed", 0)
    total = summary.get("total", 0)
    return "{}% compliant ({}/{} passed)".format(round(pct), passed, total)


def compliance_level(summary: dict[str, Any]) -> str:
    """Classify the compliance result into a named level.

    Thresholds:
        - ``"excellent"``       90% and above
        - ``"good"``            75% to below 90%
        - ``"needs-attention"`` 50% to below 75%
        - ``"critical"``        below 50%, or total == 0

    Args:
        summary: A dictionary containing ``total`` and ``passed``.

    Returns:
        One of ``"excellent"``, ``"good"``, ``"needs-attention"``,
        or ``"critical"``.
    """
    pct = compliance_percentage(summary)
    if pct >= 90.0:
        return "excellent"
    if pct >= 75.0:
        return "good"
    if pct >= 50.0:
        return "needs-attention"
    return "critical"
