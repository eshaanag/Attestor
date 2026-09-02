"""
mock_stream.py - Development utility for simulating incremental audit output.

Simulates the Attestor dashboard receiving audit control results one by one,
as if they were arriving from the real audit engine's NDJSON live stream.
Uses dashboard/ui/sample_data.json as the mock data source.

Only Python standard-library functionality is used.  This module has no
side-effects on import; callers control iteration explicitly.
"""

import json
from pathlib import Path"""
mock_stream.py - Development utility for simulating incremental audit output.

Simulates the Attestor dashboard receiving audit control results one by one,
as if they were arriving from the real audit engine's NDJSON live stream.
Uses dashboard/ui/sample_data.json as the mock data source.

Only Python standard-library functionality is used.  This module has no
side-effects on import; callers control iteration explicitly.
"""

import json
from pathlib import Path
from typing import Any, Generator


def load_sample_audit(path: "str | Path") -> dict[str, Any]:
    """Read and parse an audit JSON file.

    Args:
        path: Filesystem path to the audit JSON file.  Accepts a string or
              a :class:`pathlib.Path` object.

    Returns:
        The parsed audit result as a Python dictionary.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    with Path(path).open(encoding="utf-8") as fh:
        return json.load(fh)


def iter_control_events(
    audit_data: dict[str, Any],
) -> Generator[dict[str, Any], None, None]:
    """Yield one event dictionary per control in the audit result.

    Each yielded event contains exactly the fields needed by the dashboard
    to display a live result row: ``control_id``, ``title``, ``status``,
    and ``severity``.  The source audit data is never mutated.

    If ``audit_data["controls"]`` is empty, nothing is yielded.

    Args:
        audit_data: A parsed audit result dictionary containing a
                    ``"controls"`` list.

    Yields:
        A dictionary with keys ``control_id``, ``title``, ``status``,
        and ``severity`` for each control.
    """
    for control in audit_data.get("controls", []):
        yield {
            "control_id": control["id"],
            "title":      control["title"],
            "status":     control["status"],
            "severity":   control["severity"],
        }


def iter_ndjson_events(
    audit_data: dict[str, Any],
) -> Generator[str, None, None]:
    """Yield each control event as a JSON string (no trailing newline).

    Produces deterministic output by using the default json.dumps key
    ordering (insertion order, which is deterministic in Python 3.7+).
    Each yielded string is a complete, self-contained JSON object that
    can be written directly to a stream with a newline appended by the
    caller.

    Args:
        audit_data: A parsed audit result dictionary containing a
                    ``"controls"`` list.

    Yields:
        A JSON-encoded string for each control event.
    """
    for event in iter_control_events(audit_data):
        yield json.dumps(event, ensure_ascii=False)


def count_events(audit_data: dict[str, Any]) -> int:
    """Return the number of control events that would be emitted.

    Equivalent to ``len(audit_data.get("controls", []))`` but expressed
    through the public API for consistency.  Does not mutate the input.

    Args:
        audit_data: A parsed audit result dictionary.

    Returns:
        The number of controls in the audit result.
    """
    return len(audit_data.get("controls", []))
from typing import Any, Generator


def load_sample_audit(path: "str | Path") -> dict[str, Any]:
    """Read and parse an audit JSON file.

    Args:
        path: Filesystem path to the audit JSON file.  Accepts a string or
              a :class:`pathlib.Path` object.

    Returns:
        The parsed audit result as a Python dictionary.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    with Path(path).open(encoding="utf-8") as fh:
        return json.load(fh)


def iter_control_events(
    audit_data: dict[str, Any],
) -> Generator[dict[str, Any], None, None]:
    """Yield one event dictionary per control in the audit result.

    Each yielded event contains exactly the fields needed by the dashboard
    to display a live result row: ``control_id``, ``title``, ``status``,
    and ``severity``.  The source audit data is never mutated.

    If ``audit_data["controls"]`` is empty, nothing is yielded.

    Args:
        audit_data: A parsed audit result dictionary containing a
                    ``"controls"`` list.

    Yields:
        A dictionary with keys ``control_id``, ``title``, ``status``,
        and ``severity`` for each control.
    """
    for control in audit_data.get("controls", []):
        yield {
            "control_id": control["id"],
            "title":      control["title"],
            "status":     control["status"],
            "severity":   control["severity"],
        }


def iter_ndjson_events(
    audit_data: dict[str, Any],
) -> Generator[str, None, None]:
    """Yield each control event as a JSON string (no trailing newline).

    Produces deterministic output by using the default json.dumps key
    ordering (insertion order, which is deterministic in Python 3.7+).
    Each yielded string is a complete, self-contained JSON object that
    can be written directly to a stream with a newline appended by the
    caller.

    Args:
        audit_data: A parsed audit result dictionary containing a
                    ``"controls"`` list.

    Yields:
        A JSON-encoded string for each control event.
    """
    for event in iter_control_events(audit_data):
        yield json.dumps(event, ensure_ascii=False)


def count_events(audit_data: dict[str, Any]) -> int:
    """Return the number of control events that would be emitted.

    Equivalent to ``len(audit_data.get("controls", []))`` but expressed
    through the public API for consistency.  Does not mutate the input.

    Args:
        audit_data: A parsed audit result dictionary.

    Returns:
        The number of controls in the audit result.
    """
    return len(audit_data.get("controls", []))
