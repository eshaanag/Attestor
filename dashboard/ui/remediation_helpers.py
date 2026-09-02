"""
remediation_helpers.py - Remediation helpers for the Attestor dashboard UI.

Provides pure helpers for identifying controls that need remediation and
preparing remediation information for dashboard presentation.
"""

from typing import Any, Iterable"""
filter_controls.py - Control filtering """"""
remediation_helpers.py - Remediation helpers for the Attestor dashboard UI.

Provides pure helpers for identifying controls that need remediation and
preparing remediation information for dashboard presentation.
"""

from typing import Any, Iterable"""
filter_controls.py - Control filtering """
remediation_helpers.py - Remediation helpers for the Attestor dashboard UI.

Provides pure helpers for identifying controls that need remediation and
preparing remediation information for dashboard presentation.
"""

from typing import Any, Iterable"""
filter_controls.py - Control filtering utilities for the Attestor dashboard UI.

Provides three pure functions for filtering lists of audit control
dictionaries by status, severity, or both.  All functions return new
lists and never mutate the input.  """
pagination.py - Pagination helpers for the Attestor dashboard UI.

Provides pure helpers for splitting audit controls into predictable pages
for dashboard result tables.
"""

from typing import Any, Iterable


def total_pages(total_items: int, page_size: int) -> int:
    """Return the number of pages required for a collection.

    Returns zero when there are no items. Raises ValueError when page_size
    is not positive or total_items is negative.
    """
    if total_items < 0:
        raise ValueError("total_items cannot be negative.")
    if page_size <= 0:
        raise ValueError("page_size must be greater than zero.")
    if total_items == 0:
        return 0

    return (total_items + page_size - 1) // page_size


def clamp_page(page: int, page_count: int) -> int:
    """Return a page number constrained to the available page range.

    Pages are one-based. When there are no pages, zero is returned.
    """
    if page_count < 0:
        raise ValueError("page_count cannot be negative.")

    if page_count == 0:
        return 0

    return max(1, min(page, page_count))


def paginate_items(
    items: Iterable[Any],
    page: int,
    page_size: int,
) -> list[Any]:
    """Return the items belonging to a one-based page.

    The input iterable is converted to a list without modifying the
    original collection. Out-of-range pages return an empty list.
    """
    if page_size <= 0:
        raise ValueError("page_size must be greater than zero.")
    if page < 1:
        raise ValueError("page must be at least 1.")

    item_list = list(items)
    start = (page - 1) * page_size
    end = start + page_size

    return item_list[start:end]


def paginate_controls(
    controls: Iterable[dict[str, Any]],
    page: int,
    page_size: int = 25,
) -> list[dict[str, Any]]:
    """Return one page of dashboard controls.

    This is a convenience wrapper around :func:`paginate_items` for audit
    control dictionaries.
    """
    return paginate_items(controls, page, page_size)


def build_pagination_info(
    total_items: int,
    page: int,
    page_size: int,
) -> dict[str, int | bool]:
    """Build dashboard-ready pagination metadata.

    Returns total item count, page size, page count, current page, and
    previous/next availability flags.
    """
    pages = total_pages(total_items, page_size)

    if pages == 0:
        current = 0
    else:
        current = clamp_page(page, pages)

    return {
        "total_items": total_items,
        "page_size": page_size,
        "page_count": pages,
        "current_page": current,
        "has_previous": current > 1,
        "has_next": current < pages,
    }Controls missing the requested key
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


_REMEDIATION_STATUSES: frozenset[str] = frozenset({"Fail", "Error"})


def requires_remediation(control: dict[str, Any]) -> bool:
    """Return whether a control requires remediation attention.

    Failed and errored controls are considered remediation candidates.
    """
    return control.get("status") in _REMEDIATION_STATUSES


def get_remediation_text(control: dict[str, Any]) -> str | None:
    """Return remediation guidance from a control.

    Returns ``None`` when the control has no remediation guidance or when
    the remediation value is empty.
    """
    remediation = control.get("remediation")
    if remediation is None:
        return None

    text = str(remediation).strip()
    return text if text else None


def get_remediation_candidates(
    controls: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return controls that require remediation.

    Only controls with ``Fail`` or ``Error`` status are included.
    The original order is preserved and the input is not modified.
    """
    return [control for control in controls if requires_remediation(control)]


def get_controls_with_guidance(
    controls: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return controls that contain non-empty remediation guidance.

    The original order is preserved and the input is not modified.
    """
    return [
        control
        for control in controls
        if get_remediation_text(control) is not None
    ]


def build_remediation_summary(
    controls: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Build dashboard-ready remediation statistics.

    Returns total remediation candidates, the number with guidance, and
    the number without guidance. The input controls are not modified.
    """
    control_list = list(controls)
    candidates = get_remediation_candidates(control_list)
    with_guidance = get_controls_with_guidance(candidates)

    return {
        "candidate_count": len(candidates),
        "with_guidance": len(with_guidance),
        "without_guidance": len(candidates) - len(with_guidance),
    }utilities for the Attestor dashboard UI.

Provides three pure functions for filtering lists of audit control
dictionaries by status, severity, or both.  All functions return new
lists and never mutate the input.  """
pagination.py - Pagination helpers for the Attestor dashboard UI.

Provides pure helpers for splitting audit controls into predictable pages
for dashboard result tables.
"""

from typing import Any, Iterable


def total_pages(total_items: int, page_size: int) -> int:
    """Return the number of pages required for a collection.

    Returns zero when there are no items. Raises ValueError when page_size
    is not positive or total_items is negative.
    """
    if total_items < 0:
        raise ValueError("total_items cannot be negative.")
    if page_size <= 0:
        raise ValueError("page_size must be greater than zero.")
    if total_items == 0:
        return 0

    return (total_items + page_size - 1) // page_size


def clamp_page(page: int, page_count: int) -> int:
    """Return a page number constrained to the available page range.

    Pages are one-based. When there are no pages, zero is returned.
    """
    if page_count < 0:
        raise ValueError("page_count cannot be negative.")

    if page_count == 0:
        return 0

    return max(1, min(page, page_count))


def paginate_items(
    items: Iterable[Any],
    page: int,
    page_size: int,
) -> list[Any]:
    """Return the items belonging to a one-based page.

    The input iterable is converted to a list without modifying the
    original collection. Out-of-range pages return an empty list.
    """
    if page_size <= 0:
        raise ValueError("page_size must be greater than zero.")
    if page < 1:
        raise ValueError("page must be at least 1.")

    item_list = list(items)
    start = (page - 1) * page_size
    end = start + page_size

    return item_list[start:end]


def paginate_controls(
    controls: Iterable[dict[str, Any]],
    page: int,
    page_size: int = 25,
) -> list[dict[str, Any]]:
    """Return one page of dashboard controls.

    This is a convenience wrapper around :func:`paginate_items` for audit
    control dictionaries.
    """
    return paginate_items(controls, page, page_size)


def build_pagination_info(
    total_items: int,
    page: int,
    page_size: int,
) -> dict[str, int | bool]:
    """Build dashboard-ready pagination metadata.

    Returns total item count, page size, page count, current page, and
    previous/next availability flags.
    """
    pages = total_pages(total_items, page_size)

    if pages == 0:
        current = 0
    else:
        current = clamp_page(page, pages)

    return {
        "total_items": total_items,
        "page_size": page_size,
        "page_count": pages,
        "current_page": current,
        "has_previous": current > 1,
        "has_next": current < pages,
    }Controls missing the requested key
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


_REMEDIATION_STATUSES: frozenset[str] = frozenset({"Fail", "Error"})


def requires_remediation(control: dict[str, Any]) -> bool:
    """Return whether a control requires remediation attention.

    Failed and errored controls are considered remediation candidates.
    """
    return control.get("status") in _REMEDIATION_STATUSES


def get_remediation_text(control: dict[str, Any]) -> str | None:
    """Return remediation guidance from a control.

    Returns ``None`` when the control has no remediation guidance or when
    the remediation value is empty.
    """
    remediation = control.get("remediation")
    if remediation is None:
        return None

    text = str(remediation).strip()
    return text if text else None


def get_remediation_candidates(
    controls: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return controls that require remediation.

    Only controls with ``Fail`` or ``Error`` status are included.
    The original order is preserved and the input is not modified.
    """
    return [control for control in controls if requires_remediation(control)]


def get_controls_with_guidance(
    controls: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return controls that contain non-empty remediation guidance.

    The original order is preserved and the input is not modified.
    """
    return [
        control
        for control in controls
        if get_remediation_text(control) is not None
    ]


def build_remediation_summary(
    controls: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Build dashboard-ready remediation statistics.

    Returns total remediation candidates, the number with guidance, and
    the number without guidance. The input controls are not modified.
    """
    control_list = list(controls)
    candidates = get_remediation_candidates(control_list)
    with_guidance = get_controls_with_guidance(candidates)

    return {
        "candidate_count": len(candidates),
        "with_guidance": len(with_guidance),
        "without_guidance": len(candidates) - len(with_guidance),
    }
remediation_helpers.py - Remediation helpers for the Attestor dashboard UI.

Provides pure helpers for identifying controls that need remediation and
preparing remediation information for dashboard presentation.
"""

from typing import Any, Iterable"""
filter_controls.py - Control filtering utilities for the Attestor dashboard UI.

Provides three pure functions for filtering lists of audit control
dictionaries by status, severity, or both.  All functions return new
lists and never mutate the input.  """
pagination.py - Pagination helpers for the Attestor dashboard UI.

Provides pure helpers for splitting audit controls into predictable pages
for dashboard result tables.
"""

from typing import Any, Iterable


def total_pages(total_items: int, page_size: int) -> int:
    """Return the number of pages required for a collection.

    Returns zero when there are no items. Raises ValueError when page_size
    is not positive or total_items is negative.
    """
    if total_items < 0:
        raise ValueError("total_items cannot be negative.")
    if page_size <= 0:
        raise ValueError("page_size must be greater than zero.")
    if total_items == 0:
        return 0

    return (total_items + page_size - 1) // page_size


def clamp_page(page: int, page_count: int) -> int:
    """Return a page number constrained to the available page range.

    Pages are one-based. When there are no pages, zero is returned.
    """
    if page_count < 0:
        raise ValueError("page_count cannot be negative.")

    if page_count == 0:
        return 0

    return max(1, min(page, page_count))


def paginate_items(
    items: Iterable[Any],
    page: int,
    page_size: int,
) -> list[Any]:
    """Return the items belonging to a one-based page.

    The input iterable is converted to a list without modifying the
    original collection. Out-of-range pages return an empty list.
    """
    if page_size <= 0:
        raise ValueError("page_size must be greater than zero.")
    if page < 1:
        raise ValueError("page must be at least 1.")

    item_list = list(items)
    start = (page - 1) * page_size
    end = start + page_size

    return item_list[start:end]


def paginate_controls(
    controls: Iterable[dict[str, Any]],
    page: int,
    page_size: int = 25,
) -> list[dict[str, Any]]:
    """Return one page of dashboard controls.

    This is a convenience wrapper around :func:`paginate_items` for audit
    control dictionaries.
    """
    return paginate_items(controls, page, page_size)


def build_pagination_info(
    total_items: int,
    page: int,
    page_size: int,
) -> dict[str, int | bool]:
    """Build dashboard-ready pagination metadata.

    Returns total item count, page size, page count, current page, and
    previous/next availability flags.
    """
    pages = total_pages(total_items, page_size)

    if pages == 0:
        current = 0
    else:
        current = clamp_page(page, pages)

    return {
        "total_items": total_items,
        "page_size": page_size,
        "page_count": pages,
        "current_page": current,
        "has_previous": current > 1,
        "has_next": current < pages,
    }Controls missing the requested key
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


_REMEDIATION_STATUSES: frozenset[str] = frozenset({"Fail", "Error"})


def requires_remediation(control: dict[str, Any]) -> bool:
    """Return whether a control requires remediation attention.

    Failed and errored controls are considered remediation candidates.
    """
    return control.get("status") in _REMEDIATION_STATUSES


def get_remediation_text(control: dict[str, Any]) -> str | None:
    """Return remediation guidance from a control.

    Returns ``None`` when the control has no remediation guidance or when
    the remediation value is empty.
    """
    remediation = control.get("remediation")
    if remediation is None:
        return None

    text = str(remediation).strip()
    return text if text else None


def get_remediation_candidates(
    controls: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return controls that require remediation.

    Only controls with ``Fail`` or ``Error`` status are included.
    The original order is preserved and the input is not modified.
    """
    return [control for control in controls if requires_remediation(control)]


def get_controls_with_guidance(
    controls: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return controls that contain non-empty remediation guidance.

    The original order is preserved and the input is not modified.
    """
    return [
        control
        for control in controls
        if get_remediation_text(control) is not None
    ]


def build_remediation_summary(
    controls: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Build dashboard-ready remediation statistics.

    Returns total remediation candidates, the number with guidance, and
    the number without guidance. The input controls are not modified.
    """
    control_list = list(controls)
    candidates = get_remediation_candidates(control_list)
    with_guidance = get_controls_with_guidance(candidates)

    return {
        "candidate_count": len(candidates),
        "with_guidance": len(with_guidance),
        "without_guidance": len(candidates) - len(with_guidance),
    }utilities for the Attestor dashboard UI.

Provides three pure functions for filtering lists of audit control
dictionaries by status, severity, or both.  All functions return new
lists and never mutate the input.  """
pagination.py - Pagination helpers for the Attestor dashboard UI.

Provides pure helpers for splitting audit controls into predictable pages
for dashboard result tables.
"""

from typing import Any, Iterable


def total_pages(total_items: int, page_size: int) -> int:
    """Return the number of pages required for a collection.

    Returns zero when there are no items. Raises ValueError when page_size
    is not positive or total_items is negative.
    """
    if total_items < 0:
        raise ValueError("total_items cannot be negative.")
    if page_size <= 0:
        raise ValueError("page_size must be greater than zero.")
    if total_items == 0:
        return 0

    return (total_items + page_size - 1) // page_size


def clamp_page(page: int, page_count: int) -> int:
    """Return a page number constrained to the available page range.

    Pages are one-based. When there are no pages, zero is returned.
    """
    if page_count < 0:
        raise ValueError("page_count cannot be negative.")

    if page_count == 0:
        return 0

    return max(1, min(page, page_count))


def paginate_items(
    items: Iterable[Any],
    page: int,
    page_size: int,
) -> list[Any]:
    """Return the items belonging to a one-based page.

    The input iterable is converted to a list without modifying the
    original collection. Out-of-range pages return an empty list.
    """
    if page_size <= 0:
        raise ValueError("page_size must be greater than zero.")
    if page < 1:
        raise ValueError("page must be at least 1.")

    item_list = list(items)
    start = (page - 1) * page_size
    end = start + page_size

    return item_list[start:end]


def paginate_controls(
    controls: Iterable[dict[str, Any]],
    page: int,
    page_size: int = 25,
) -> list[dict[str, Any]]:
    """Return one page of dashboard controls.

    This is a convenience wrapper around :func:`paginate_items` for audit
    control dictionaries.
    """
    return paginate_items(controls, page, page_size)


def build_pagination_info(
    total_items: int,
    page: int,
    page_size: int,
) -> dict[str, int | bool]:
    """Build dashboard-ready pagination metadata.

    Returns total item count, page size, page count, current page, and
    previous/next availability flags.
    """
    pages = total_pages(total_items, page_size)

    if pages == 0:
        current = 0
    else:
        current = clamp_page(page, pages)

    return {
        "total_items": total_items,
        "page_size": page_size,
        "page_count": pages,
        "current_page": current,
        "has_previous": current > 1,
        "has_next": current < pages,
    }Controls missing the requested key
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


_REMEDIATION_STATUSES: frozenset[str] = frozenset({"Fail", "Error"})


def requires_remediation(control: dict[str, Any]) -> bool:
    """Return whether a control requires remediation attention.

    Failed and errored controls are considered remediation candidates.
    """
    return control.get("status") in _REMEDIATION_STATUSES


def get_remediation_text(control: dict[str, Any]) -> str | None:
    """Return remediation guidance from a control.

    Returns ``None`` when the control has no remediation guidance or when
    the remediation value is empty.
    """
    remediation = control.get("remediation")
    if remediation is None:
        return None

    text = str(remediation).strip()
    return text if text else None


def get_remediation_candidates(
    controls: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return controls that require remediation.

    Only controls with ``Fail`` or ``Error`` status are included.
    The original order is preserved and the input is not modified.
    """
    return [control for control in controls if requires_remediation(control)]


def get_controls_with_guidance(
    controls: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return controls that contain non-empty remediation guidance.

    The original order is preserved and the input is not modified.
    """
    return [
        control
        for control in controls
        if get_remediation_text(control) is not None
    ]


def build_remediation_summary(
    controls: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Build dashboard-ready remediation statistics.

    Returns total remediation candidates, the number with guidance, and
    the number without guidance. The input controls are not modified.
    """
    control_list = list(controls)
    candidates = get_remediation_candidates(control_list)
    with_guidance = get_controls_with_guidance(candidates)

    return {
        "candidate_count": len(candidates),
        "with_guidance": len(with_guidance),
        "without_guidance": len(candidates) - len(with_guidance),
    }
