"""
filter_controls.py - Control filtering utilities for the Attestor dashboard UI.

Provides three pure functions for filtering lists of audit control
dictionaries by status, severity, or both.  All functions return new
lists and never mutate the input.  Controls missing the requested key
are treated as non-matches rather than raising KeyError.

Only Python standard-library functionality is used.
"""

from typing import Any, Iterable


def filter_by_status(
    controls: Iterable[dict[str, Any]],
    status: str,
) -> list[dict[str, Any]]:
    """Return controls whose "status" field exactly matches *status*.

    Matching is case-sensitive.  Controls missing the "status" key are
    silently excluded (treated as non-matches).

    Args:
        controls: Iterable of control dictionaries (e.g. audit["controls"]).
        status:   Exact status string to match, e.g. "Pass", "Fail", "Error".

    Returns:
        A new list containing only the matching control dictionaries.
    """
    return [c for c in controls if c.get("status") == status]


def filter_by_severity(
    controls: Iterable[dict[str, Any]],
    severity: str,
) -> list[dict[str, Any]]:
    """Return controls whose "severity" field exactly matches *severity*.

    Matching is case-sensitive.  Controls missing the "severity" key are
    silently excluded (treated as non-matches).

    Args:
        controls: Iterable of control dictionaries (e.g. audit["controls"]).
        severity: Exact severity string to match, e.g. "High", "Medium", "Low".

    Returns:
        A new list containing only the matching control dictionaries.
    """
    return [c for c in controls if c.get("severity") == severity]


def filter_controls(
    controls: Iterable[dict[str, Any]],
    status: str | None = None,
    severity: str | None = None,
) -> list[dict[str, Any]]:
    """Filter controls by status, severity, or both.

    Applies the supplied filters in order (status first, then severity).
    If neither filter is given, all controls are returned as a new list.
    Controls missing the relevant key are treated as non-matches.

    Args:
        controls: Iterable of control dictionaries (e.g. audit["controls"]).
        status:   If provided, keep only controls whose "status" matches exactly.
        severity: If provided, keep only controls whose "severity" matches exactly.

    Returns:
        A new list of control dictionaries satisfying all supplied filters.
    """
    result: list[dict[str, Any]] = list(controls)
    if status is not None:
        result = filter_by_status(result, status)
    if severity is not None:
        result = filter_by_severity(result, severity)
    return result
