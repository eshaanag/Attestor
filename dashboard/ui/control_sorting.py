"""
control_sorting.py - Sorting helpers for the Attestor dashboard UI.

Provides pure functions for sorting lists of audit control dictionaries by
status, severity, title, or control ID.  All functions return new lists and
never mutate the input.  Unknown or missing field values always sort after
all recognised values, regardless of whether ascending or descending order
is requested.

Only Python standard-library functionality is used.
"""

from typing import Any, Iterable

# Logical sort orders (ascending).
_STATUS_ORDER: dict[str, int] = {"Pass": 0, "Fail": 1, "Error": 2}
_STATUS_ORDER_REV: dict[str, int] = {"Error": 0, "Fail": 1, "Pass": 2}

_SEVERITY_ORDER: dict[str, int] = {"High": 0, "Medium": 1, "Low": 2}
_SEVERITY_ORDER_REV: dict[str, int] = {"Low": 0, "Medium": 1, "High": 2}


def sort_by_status(
    controls: Iterable[dict[str, Any]],
    reverse: bool = False,
) -> list[dict[str, Any]]:
    """Return a new list of controls sorted by status.

    Ascending order:  ``Pass`` -> ``Fail`` -> ``Error``.
    Descending order: ``Error`` -> ``Fail`` -> ``Pass``.

    Controls with an unknown or missing ``"status"`` value always sort after
    recognised statuses in both sort directions.  Relative ordering among
    controls with the same status is preserved (stable sort).  The input
    is not mutated.

    Args:
        controls: Iterable of control dictionaries.
        reverse:  If ``True``, sort descending (Error -> Fail -> Pass).

    Returns:
        A new sorted list of control dictionaries.
    """
    order = _STATUS_ORDER_REV if reverse else _STATUS_ORDER
    recognised: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    for c in controls:
        if c.get("status") in order:
            recognised.append(c)
        else:
            unknown.append(c)
    return sorted(recognised, key=lambda c: order[c["status"]]) + unknown


def sort_by_severity(
    controls: Iterable[dict[str, Any]],
    reverse: bool = False,
) -> list[dict[str, Any]]:
    """Return a new list of controls sorted by severity.

    Ascending order:  ``High`` -> ``Medium`` -> ``Low``.
    Descending order: ``Low`` -> ``Medium`` -> ``High``.

    Controls with an unknown or missing ``"severity"`` value always sort
    after recognised severities in both sort directions.  Relative ordering
    among controls with the same severity is preserved (stable sort).  The
    input is not mutated.

    Args:
        controls: Iterable of control dictionaries.
        reverse:  If ``True``, sort descending (Low -> Medium -> High).

    Returns:
        A new sorted list of control dictionaries.
    """
    order = _SEVERITY_ORDER_REV if reverse else _SEVERITY_ORDER
    recognised: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    for c in controls:
        if c.get("severity") in order:
            recognised.append(c)
        else:
            unknown.append(c)
    return sorted(recognised, key=lambda c: order[c["severity"]]) + unknown


def sort_by_title(
    controls: Iterable[dict[str, Any]],
    reverse: bool = False,
) -> list[dict[str, Any]]:
    """Return a new list of controls sorted alphabetically by title.

    Comparison is case-insensitive.  Controls with a missing or null
    ``"title"`` field always sort after all controls with titles, in both
    ascending and descending modes.  The input is not mutated.

    Args:
        controls: Iterable of control dictionaries.
        reverse:  If ``True``, reverse alphabetical order (Z -> A).

    Returns:
        A new sorted list of control dictionaries.
    """
    present: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for c in controls:
        if "title" in c and c["title"] is not None:
            present.append(c)
        else:
            missing.append(c)
    return sorted(present, key=lambda c: str(c["title"]).casefold(), reverse=reverse) + missing


def sort_by_control_id(
    controls: Iterable[dict[str, Any]],
    reverse: bool = False,
) -> list[dict[str, Any]]:
    """Return a new list of controls sorted by their ID field.

    Uses standard string comparison on the ``"id"`` field.  Controls with
    a missing or null ``"id"`` field always sort after all controls with IDs,
    in both ascending and descending modes.  The input is not mutated.

    Args:
        controls: Iterable of control dictionaries.
        reverse:  If ``True``, reverse string comparison order.

    Returns:
        A new sorted list of control dictionaries.
    """
    present: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for c in controls:
        if "id" in c and c["id"] is not None:
            present.append(c)
        else:
            missing.append(c)
    return sorted(present, key=lambda c: str(c["id"]), reverse=reverse) + missing
