"""
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
    }