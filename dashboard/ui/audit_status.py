"""
audit_status.py - Audit result status helpers for the Attestor dashboard UI.

Provides pure helpers for determining the overall state of an audit from
its individual control results.
"""

from typing import Any, Iterable


_STATUS_ORDER: tuple[str, ...] = ("Error", "Fail", "Pass")
_VALID_STATUSES: frozenset[str] = frozenset({"Pass", "Fail", "Error"})


def get_overall_status(
    controls: Iterable[dict[str, Any]],
) -> str:
    """Return the overall status of an audit.

    ``Error`` takes highest priority, followed by ``Fail``, then ``Pass``.
    An empty audit returns ``"No Results"``. Unknown statuses are ignored.
    """
    found = {
        control.get("status")
        for control in controls
        if control.get("status") in _VALID_STATUSES
    }

    for status in _STATUS_ORDER:
        if status in found:
            return status

    return "No Results"


def is_successful_audit(
    controls: Iterable[dict[str, Any]],
) -> bool:
    """Return True when every recognised control has passed.

    An empty audit is not considered successful. Unknown statuses are
    treated as non-passing results.
    """
    control_list = list(controls)

    if not control_list:
        return False

    return all(control.get("status") == "Pass" for control in control_list)


def has_failures(
    controls: Iterable[dict[str, Any]],
) -> bool:
    """Return True when at least one control has failed."""
    return any(control.get("status") == "Fail" for control in controls)


def has_errors(
    controls: Iterable[dict[str, Any]],
) -> bool:
    """Return True when at least one control has an error."""
    return any(control.get("status") == "Error" for control in controls)


def status_message(status: str) -> str:
    """Return a human-readable message for an audit status."""
    messages = {
        "Pass": "All applicable checks passed.",
        "Fail": "One or more checks require remediation.",
        "Error": "One or more checks could not be completed.",
        "No Results": "No audit results are available.",
    }
    return messages.get(status, "Unknown audit status.")