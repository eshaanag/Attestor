"""
control_groups.py - Control grouping helpers for the Attestor dashboard UI.

Provides pure functions for grouping audit control dictionaries by status
or severity, suitable for rendering grouped result sections in the dashboard.
None of the functions mutate their input, and all use only Python
standard-library functionality.
"""

from typing import Any, Iterable

# Recognised grouping keys.
_STATUSES: tuple[str, ...] = ("Pass", "Fail", "Error")
_SEVERITIES: tuple[str, ...] = ("High", "Medium", "Low")


def group_by_status(
    controls: Iterable[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group controls by their status value.

    Returns a dictionary with keys ``"Pass"``, ``"Fail"``, and ``"Error"``.
    Controls with a missing or unrecognised ``"status"`` value are silently
    excluded.  The original order of controls is preserved within each group.
    The input is not mutated.

    Args:
        controls: Iterable of control dictionaries from an audit result.

    Returns:
        A dictionary mapping each recognised status to a list of controls.
    """
    groups: dict[str, list[dict[str, Any]]] = {s: [] for s in _STATUSES}
    for control in controls:
        status = control.get("status")
        if status in groups:
            groups[status].append(control)
    return groups


def group_by_severity(
    controls: Iterable[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group controls by their severity value.

    Returns a dictionary with keys ``"High"``, ``"Medium"``, and ``"Low"``.
    Controls with a missing or unrecognised ``"severity"`` value are silently
    excluded.  The original order of controls is preserved within each group.
    The input is not mutated.

    Args:
        controls: Iterable of control dictionaries from an audit result.

    Returns:
        A dictionary mapping each recognised severity to a list of controls.
    """
    groups: dict[str, list[dict[str, Any]]] = {s: [] for s in _SEVERITIES}
    for control in controls:
        severity = control.get("severity")
        if severity in groups:
            groups[severity].append(control)
    return groups


def group_failed_controls_by_severity(
    controls: Iterable[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group failed controls by their severity value.

    Considers only controls whose ``"status"`` is ``"Fail"``, then groups
    those controls by severity (``"High"``, ``"Medium"``, ``"Low"``).
    Failed controls with a missing or unrecognised severity are silently
    excluded.  The original order of controls is preserved within each group.
    The input is not mutated.

    Args:
        controls: Iterable of control dictionaries from an audit result.

    Returns:
        A dictionary mapping each recognised severity to a list of failed
        controls with that severity.
    """
    failed = (c for c in controls if c.get("status") == "Fail")
    return group_by_severity(failed)
