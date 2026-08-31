"""
data_validation.py - Fine-grained validation helpers for the Attestor dashboard UI.

Provides focused validators for individual audit controls and their field
values.  These complement the structural validation in data_loader.py, which
checks the top-level JSON shape, by verifying the content of each control
dictionary.

Only Python standard-library functionality is used.
"""

from typing import Any, Iterable

_REQUIRED_CONTROL_FIELDS: tuple[str, ...] = (
    "id",
    "title",
    "status",
    "severity",
    "description",
)

_VALID_STATUSES: frozenset[str] = frozenset({"Pass", "Fail", "Error"})
_VALID_SEVERITIES: frozenset[str] = frozenset({"High", "Medium", "Low"})


def validate_control(control: dict[str, Any]) -> bool:
    """Validate a single audit control dictionary.

    Checks that all required fields are present.  Does not mutate the input.

    Required fields: ``id``, ``title``, ``status``, ``severity``,
    ``description``.

    Args:
        control: A control dictionary from an audit result.

    Returns:
        ``True`` when all required fields are present.

    Raises:
        ValueError: Listing every missing required field.
    """
    missing = [f for f in _REQUIRED_CONTROL_FIELDS if f not in control]
    if missing:
        ctrl_id = control.get("id", "<unknown>")
        raise ValueError(
            "Control {!r} is missing required field(s): {}.".format(ctrl_id, missing)
        )
    return True


def validate_controls(controls: Iterable[dict[str, Any]]) -> bool:
    """Validate every control in an iterable.

    Iterates through all controls and validates each one with
    :func:`validate_control`.  Does not mutate the input.

    Args:
        controls: Iterable of control dictionaries.

    Returns:
        ``True`` when every control is valid.

    Raises:
        ValueError: Identifying the zero-based index of the first invalid
                    control, along with the original validation message.
    """
    for index, control in enumerate(controls):
        try:
            validate_control(control)
        except ValueError as exc:
            raise ValueError(
                "Validation failed at controls[{}]: {}".format(index, exc)
            ) from exc
    return True


def validate_status(status: Any) -> bool:
    """Validate an audit control status value.

    Args:
        status: The value to validate.

    Returns:
        ``True`` when *status* is one of ``"Pass"``, ``"Fail"``,
        or ``"Error"``.

    Raises:
        ValueError: When *status* is not a recognised value.
    """
    if status not in _VALID_STATUSES:
        raise ValueError(
            "Invalid status {!r}. Expected one of: {}.".format(
                status, sorted(_VALID_STATUSES)
            )
        )
    return True


def validate_severity(severity: Any) -> bool:
    """Validate an audit control severity value.

    Args:
        severity: The value to validate.

    Returns:
        ``True`` when *severity* is one of ``"High"``, ``"Medium"``,
        or ``"Low"``.

    Raises:
        ValueError: When *severity* is not a recognised value.
    """
    if severity not in _VALID_SEVERITIES:
        raise ValueError(
            "Invalid severity {!r}. Expected one of: {}.".format(
                severity, sorted(_VALID_SEVERITIES)
            )
        )
    return True
