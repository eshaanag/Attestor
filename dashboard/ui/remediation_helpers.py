"""
remediation_helpers.py - Remediation helpers for the Attestor dashboard UI.

Provides pure helpers for identifying controls that need remediation and
preparing remediation information for dashboard presentation.
"""

from typing import Any, Iterable


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