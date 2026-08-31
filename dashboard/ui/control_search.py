"""
control_search.py - Search helpers for the Attestor dashboard UI.

Provides pure functions for searching audit controls by title, control ID,
description, and combined text fields.
"""

from typing import Any, Iterable


def search_controls(
    controls: Iterable[dict[str, Any]],
    query: str,
) -> list[dict[str, Any]]:
    """Return controls matching a case-insensitive text query.

    The query is matched against the control ID, title, and description.
    An empty or whitespace-only query returns all controls. The original
    input is not modified and control order is preserved.
    """
    control_list = list(controls)
    normalized_query = query.strip().casefold()

    if not normalized_query:
        return control_list

    results: list[dict[str, Any]] = []

    for control in control_list:
        searchable = " ".join(
            str(control.get(field, ""))
            for field in ("id", "title", "description")
        ).casefold()

        if normalized_query in searchable:
            results.append(control)

    return results


def search_by_title(
    controls: Iterable[dict[str, Any]],
    query: str,
) -> list[dict[str, Any]]:
    """Return controls whose title contains the supplied query.

    Matching is case-insensitive and preserves the original order.
    """
    normalized_query = query.strip().casefold()

    if not normalized_query:
        return list(controls)

    return [
        control
        for control in controls
        if normalized_query in str(control.get("title", "")).casefold()
    ]


def search_by_control_id(
    controls: Iterable[dict[str, Any]],
    query: str,
) -> list[dict[str, Any]]:
    """Return controls whose ID contains the supplied query.

    Matching is case-insensitive and preserves the original order.
    """
    normalized_query = query.strip().casefold()

    if not normalized_query:
        return list(controls)

    return [
        control
        for control in controls
        if normalized_query in str(control.get("id", "")).casefold()
    ]


def search_by_description(
    controls: Iterable[dict[str, Any]],
    query: str,
) -> list[dict[str, Any]]:
    """Return controls whose description contains the supplied query.

    Matching is case-insensitive and preserves the original order.
    """
    normalized_query = query.strip().casefold()

    if not normalized_query:
        return list(controls)

    return [
        control
        for control in controls
        if normalized_query in str(control.get("description", "")).casefold()
    ]


def count_search_results(
    controls: Iterable[dict[str, Any]],
    query: str,
) -> int:
    """Return the number of controls matching a search query."""
    return len(search_controls(controls, query))