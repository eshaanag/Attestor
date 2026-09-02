"""
data_loader.py - Audit data loader for the Attestor dashboard UI.

Provides two public functions:

    load_audit_data(path)      - Read, parse, validate, and return an audit JSON file.
    validate_audit_data(data)  - Validate a parsed audit dictionary; raise ValueError on failure.

Only Python standard-library modules are used."""
data_loader.py - Audit data loader for the Attestor dashboard UI.

Provides two public functions:

    load_audit_data(path)      - Read, parse, validate, and return an audit JSON file.
    validate_audit_data(data)  - Validate a parsed audit dictionary; raise ValueError on failure.

Only Python standard-library modules are used.
"""

import json
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Required field declarations
# ---------------------------------------------------------------------------

_TOP_LEVEL_REQUIRED: tuple[str, ...] = (
    "audit_id",
    "platform",
    "benchmark",
    "benchmark_version",
    "timestamp",
    "hostname",
    "summary",
    "controls",
)

_SUMMARY_REQUIRED: tuple[str, ...] = (
    "total",
    "passed",
    "failed",
    "errors",
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_audit_data(path: "str | Path") -> "dict[str, Any]":
    """Load and validate an Attestor audit result JSON file.

    Reads the file at *path* as UTF-8, parses it as JSON, runs structural
    validation via validate_audit_data(), and returns the resulting dictionary.

    Args:
        path: Filesystem path to the audit JSON file. Accepts a string or
              a pathlib.Path object.

    Returns:
        The parsed and validated audit result as a Python dictionary.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read due to permissions.
        json.JSONDecodeError: If the file content is not valid JSON.
        ValueError: If the parsed data fails structural validation.
    """
    path = Path(path)
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    validate_audit_data(data)
    return data


def validate_audit_data(data: Any) -> bool:
    """Validate the structure of a parsed Attestor audit result.

    Checks that *data* is a dictionary, contains all required top-level
    fields, has a well-formed 'summary' sub-dictionary, and has a
    'controls' list.  Field values are not type-checked beyond these
    structural requirements -- content validation (e.g. status enumerations)
    is left to higher-level callers.

    Required top-level fields:
        audit_id, platform, benchmark, benchmark_version,
        timestamp, hostname, summary, controls

    Required 'summary' sub-fields:
        total, passed, failed, errors

    Args:
        data: The value produced by json.load / json.loads.

    Returns:
        True when the data is valid.

    Raises:
        ValueError: With a descriptive message identifying the first
                    structural problem found.
    """
    # Top-level type check
    if not isinstance(data, dict):
        raise ValueError(
            "Audit data must be a JSON object (dict), got {}.".format(type(data).__name__)
        )

    # Required top-level fields
    missing_top = [f for f in _TOP_LEVEL_REQUIRED if f not in data]
    if missing_top:
        raise ValueError(
            "Audit data is missing required top-level field(s): {}.".format(missing_top)
        )

    # summary must be a dict
    summary = data["summary"]
    if not isinstance(summary, dict):
        raise ValueError(
            "'summary' must be a JSON object (dict), got {}.".format(type(summary).__name__)
        )

    # Required summary sub-fields
    missing_summary = [f for f in _SUMMARY_REQUIRED if f not in summary]
    if missing_summary:
        raise ValueError(
            "'summary' is missing required field(s): {}.".format(missing_summary)
        )

    # controls must be a list
    controls = data["controls"]
    if not isinstance(controls, list):
        raise ValueError(
            "'controls' must be a JSON array (list), got {}.".format(type(controls).__name__)
        )

    return True
"""

import json
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Required field declarations
# ---------------------------------------------------------------------------

_TOP_LEVEL_REQUIRED: tuple[str, ...] = (
    "audit_id",
    "platform",
    "benchmark",
    "benchmark_version",
    "timestamp",
    "hostname",
    "summary",
    "controls",
)

_SUMMARY_REQUIRED: tuple[str, ...] = (
    "total",
    "passed",
    "failed",
    "errors",
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_audit_data(path: "str | Path") -> "dict[str, Any]":
    """Load and validate an Attestor audit result JSON file.

    Reads the file at *path* as UTF-8, parses it as JSON, runs structural
    validation via validate_audit_data(), and returns the resulting dictionary.

    Args:
        path: Filesystem path to the audit JSON file. Accepts a string or
              a pathlib.Path object.

    Returns:
        The parsed and validated audit result as a Python dictionary.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read due to permissions.
        json.JSONDecodeError: If the file content is not valid JSON.
        ValueError: If the parsed data fails structural validation.
    """
    path = Path(path)
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    validate_audit_data(data)
    return data


def validate_audit_data(data: Any) -> bool:
    """Validate the structure of a parsed Attestor audit result.

    Checks that *data* is a dictionary, contains all required top-level
    fields, has a well-formed 'summary' sub-dictionary, and has a
    'controls' list.  Field values are not type-checked beyond these
    structural requirements -- content validation (e.g. status enumerations)
    is left to higher-level callers.

    Required top-level fields:
        audit_id, platform, benchmark, benchmark_version,
        timestamp, hostname, summary, controls

    Required 'summary' sub-fields:
        total, passed, failed, errors

    Args:
        data: The value produced by json.load / json.loads.

    Returns:
        True when the data is valid.

    Raises:
        ValueError: With a descriptive message identifying the first
                    structural problem found.
    """
    # Top-level type check
    if not isinstance(data, dict):
        raise ValueError(
            "Audit data must be a JSON object (dict), got {}.".format(type(data).__name__)
        )

    # Required top-level fields
    missing_top = [f for f in _TOP_LEVEL_REQUIRED if f not in data]
    if missing_top:
        raise ValueError(
            "Audit data is missing required top-level field(s): {}.".format(missing_top)
        )

    # summary must be a dict
    summary = data["summary"]
    if not isinstance(summary, dict):
        raise ValueError(
            "'summary' must be a JSON object (dict), got {}.".format(type(summary).__name__)
        )

    # Required summary sub-fields
    missing_summary = [f for f in _SUMMARY_REQUIRED if f not in summary]
    if missing_summary:
        raise ValueError(
            "'summary' is missing required field(s): {}.".format(missing_summary)
        )

    # controls must be a list
    controls = data["controls"]
    if not isinstance(controls, list):
        raise ValueError(
            "'controls' must be a JSON array (list), got {}.".format(type(controls).__name__)
        )

    return True
