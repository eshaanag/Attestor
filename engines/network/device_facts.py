#!/usr/bin/env python3
"""Narrow, source-backed parsers for optional network device identity facts."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any


class DeviceFactsError(RuntimeError):
    """The companion command output cannot be associated safely."""


def _read_text(path: str | Path) -> tuple[Path, bytes, str]:
    resolved = Path(path).expanduser().resolve()
    try:
        raw = resolved.read_bytes()
    except FileNotFoundError as exc:
        raise DeviceFactsError(f"device facts file not found: {resolved}") from exc
    except PermissionError as exc:
        raise DeviceFactsError(f"permission denied reading device facts: {resolved}") from exc
    except IsADirectoryError as exc:
        raise DeviceFactsError(f"device facts path is a directory: {resolved}") from exc
    except OSError as exc:
        raise DeviceFactsError(f"could not read device facts {resolved}: {exc}") from exc
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise DeviceFactsError(
            f"device facts are not valid UTF-8/UTF-8-BOM at byte {exc.start}: {resolved}"
        ) from exc
    if not text.strip():
        raise DeviceFactsError(f"device facts file is empty: {resolved}")
    return resolved, raw, text


def _first(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else None


def _unique_matches(pattern: str, text: str) -> list[str]:
    values: list[str] = []
    for value in re.findall(pattern, text, re.IGNORECASE | re.MULTILINE):
        cleaned = value.strip()
        if cleaned and cleaned not in values:
            values.append(cleaned)
    return values


def _source(raw: bytes, parser: str) -> dict[str, str]:
    return {
        "command": "show version",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "parser": parser,
    }


def _parse_cisco(raw: bytes, text: str) -> dict[str, Any]:
    if not re.search(r"^Cisco IOS(?:-XE)? Software,", text, re.IGNORECASE | re.MULTILINE):
        raise DeviceFactsError(
            "device facts do not contain a supported Cisco IOS/IOS-XE show version marker"
        )
    hostname = _first(r"^(\S+)\s+uptime is\b", text)
    software_version = _first(
        r"^Cisco IOS(?:-XE)? Software,.*?\bVersion\s+([^,\s]+)", text
    )
    models = _unique_matches(r"^Model Number\s*:\s*(\S+)\s*$", text)
    if not models:
        model = _first(r"^cisco\s+(\S+)\s+\([^\r\n]+\)\s+processor\b", text)
        models = [model] if model else []
    serials = _unique_matches(r"^System Serial Number\s*:\s*(\S+)\s*$", text)
    if not serials:
        serials = _unique_matches(r"^Processor board ID\s+(\S+)\s*$", text)
    return {
        "hostname": hostname,
        "model": models[0] if models else None,
        "serial_number": serials[0] if serials else None,
        "serial_numbers": serials,
        "software_version": software_version,
        "facts_source": _source(raw, "cisco_show_version_v1"),
    }


def _parse_junos(raw: bytes, text: str) -> dict[str, Any]:
    if not re.search(r"\bJUNOS\b", text, re.IGNORECASE):
        raise DeviceFactsError(
            "device facts do not contain a supported Juniper Junos show version marker"
        )
    hostname = _first(r"^Hostname\s*:\s*(\S+)\s*$", text)
    model = _first(r"^Model\s*:\s*(\S+)\s*$", text)
    software_version = _first(r"^Junos\s*:\s*(\S+)\s*$", text)
    serials = _unique_matches(r"^Serial Number\s*:\s*(\S+)\s*$", text)
    return {
        "hostname": hostname,
        "model": model,
        "serial_number": serials[0] if serials else None,
        "serial_numbers": serials,
        "software_version": software_version,
        "facts_source": _source(raw, "junos_show_version_v1"),
    }


def load_device_facts(path: str | Path, vendor: str) -> dict[str, Any]:
    """Read and parse one supported show-version output without inference."""
    _, raw, text = _read_text(path)
    normalized_vendor = vendor.casefold().replace("-", "_")
    if normalized_vendor in {"cisco", "cisco_ios", "cisco_iosxe"}:
        return _parse_cisco(raw, text)
    if normalized_vendor in {"juniper", "juniper_junos", "junos"}:
        return _parse_junos(raw, text)
    raise DeviceFactsError(f"unsupported device-facts vendor: {vendor}")


def apply_device_facts(
    device: dict[str, Any], facts: dict[str, Any], config_hostname: str | None
) -> dict[str, Any]:
    """Add identity facts after enforcing config/output hostname association."""
    facts_hostname = facts.get("hostname")
    if config_hostname and facts_hostname and config_hostname.casefold() != facts_hostname.casefold():
        raise DeviceFactsError(
            "configuration hostname "
            f"{config_hostname!r} does not match device-facts hostname {facts_hostname!r}"
        )
    enriched = dict(device)
    if not enriched.get("hostname") and facts_hostname:
        enriched["hostname"] = facts_hostname
    for field in (
        "model",
        "serial_number",
        "serial_numbers",
        "software_version",
        "facts_source",
    ):
        enriched[field] = facts.get(field)
    return enriched
