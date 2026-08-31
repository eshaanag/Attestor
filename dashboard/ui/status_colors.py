"""
status_colors.py - Presentation mappings for the Attestor dashboard UI.

Provides CSS class names and human-readable labels for audit control
status and severity values.  This module is the single source of truth
for all status/severity presentation data consumed by Jinja2 templates
and other UI utilities.

No web framework dependencies.  Only Python standard-library functionality.
"""

# ---------------------------------------------------------------------------
# CSS class mappings
# ---------------------------------------------------------------------------

#: Maps each audit control status to a CSS class name.
#: Templates should prefer these over hard-coded strings.
STATUS_CLASSES: dict[str, str] = {
    "Pass":  "status-pass",
    "Fail":  "status-fail",
    "Error": "status-error",
}

#: Maps each audit control severity to a CSS class name.
SEVERITY_CLASSES: dict[str, str] = {
    "High":   "severity-high",
    "Medium": "severity-medium",
    "Low":    "severity-low",
}

#: Fallback CSS class returned when a status or severity value is not recognised.
_NEUTRAL_CLASS: str = "status-unknown"

# ---------------------------------------------------------------------------
# Human-readable labels
# ---------------------------------------------------------------------------

#: Display labels for each status value.
STATUS_LABELS: dict[str, str] = {
    "Pass":  "Passed",
    "Fail":  "Failed",
    "Error": "Error - manual review needed",
}

#: Display labels for each severity value.
SEVERITY_LABELS: dict[str, str] = {
    "High":   "High",
    "Medium": "Medium",
    "Low":    "Low",
}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def get_status_class(status: str) -> str:
    """Return the CSS class name for the given audit control status.

    Args:
        status: A status string, e.g. "Pass", "Fail", or "Error".

    Returns:
        The corresponding CSS class from STATUS_CLASSES, or a neutral
        fallback class if the value is not recognised.
    """
    return STATUS_CLASSES.get(status, _NEUTRAL_CLASS)


def get_severity_class(severity: str) -> str:
    """Return the CSS class name for the given audit control severity.

    Args:
        severity: A severity string, e.g. "High", "Medium", or "Low".

    Returns:
        The corresponding CSS class from SEVERITY_CLASSES, or a neutral
        fallback class if the value is not recognised.
    """
    return SEVERITY_CLASSES.get(severity, _NEUTRAL_CLASS)
