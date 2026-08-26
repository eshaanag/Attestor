"""Vendor-neutral facts extracted from a network configuration.

This module is deliberately conservative.  It does not decide compliance and
it does not infer that an omitted IOS command is secure.  Each fact is either
explicitly observed (``true``/a value), explicitly disabled (``false``), or
``None`` when the saved configuration cannot establish the value.  Evidence is
limited to line numbers and safe descriptions so credential-bearing lines are
never copied into the normalized report.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Any


@dataclass(frozen=True)
class NormalizedLine:
    number: int
    normalized: str


def _lines(config: Any) -> tuple[NormalizedLine, ...]:
    """Accept the engine's ConfigDocument without importing it (no cycle)."""
    return tuple(
        NormalizedLine(int(line.number), str(line.normalized))
        for line in getattr(config, "lines", config)
    )


def _match(lines: Iterable[NormalizedLine], pattern: str) -> NormalizedLine | None:
    regex = re.compile(pattern, re.IGNORECASE)
    return next((line for line in lines if regex.search(line.normalized)), None)


def _explicit_toggle(
    lines: tuple[NormalizedLine, ...],
    positive: str,
    negative: str,
    label: str,
) -> dict[str, Any]:
    positive_line = _match(lines, positive)
    negative_line = _match(lines, negative)
    if positive_line:
        return {"value": True, "evidence": {"line": positive_line.number, "observation": label}}
    if negative_line:
        return {"value": False, "evidence": {"line": negative_line.number, "observation": f"{label} explicitly disabled"}}
    return {"value": None, "evidence": None}


def _pattern_toggle(
    lines: tuple[NormalizedLine, ...],
    positive: str,
    negative: str,
    label: str,
) -> dict[str, Any]:
    return _explicit_toggle(lines, positive, negative, label)


def normalize_config(config: Any) -> dict[str, Any]:
    """Return the additive ``security_model`` for an IOS/IOS-XE config.

    The field names are vendor-neutral.  The current implementation only
    populates facts that can be observed safely from the flat IOS corpus; a
    future Junos/Arista adapter can emit the same names from different syntax.
    """
    lines = _lines(config)
    hostname_line = _match(lines, r"^hostname\s+(\S+)$")
    hostname = hostname_line.normalized.split(None, 1)[1] if hostname_line else None

    ssh = _match(lines, r"^ip\s+ssh\s+version\s+(\d+)\s*$")
    ssh_version = int(ssh.normalized.split()[-1]) if ssh else None
    ssh_evidence = {"line": ssh.number, "observation": "SSH protocol version explicitly configured"} if ssh else None

    fields: dict[str, Any] = {
        "hostname": {"value": hostname, "evidence": {"line": hostname_line.number, "observation": "device hostname"} if hostname_line else None},
        "ssh_version": {"value": ssh_version, "evidence": ssh_evidence},
        "password_encryption": _explicit_toggle(
            lines, r"^service\s+password-encryption\s*$", r"^no\s+service\s+password-encryption\s*$", "password encryption enabled"
        ),
        "banner_motd_configured": _pattern_toggle(
            lines, r"^banner\s+motd\s+.+", r"^no\s+banner\s+motd\s*$", "MOTD banner configured"
        ),
        "logging_buffered_configured": _pattern_toggle(
            lines, r"^logging\s+buffered\s+\S+", r"^no\s+logging\s+buffered\s*$", "buffered logging configured"
        ),
        "logging_host_configured": _pattern_toggle(
            lines, r"^logging\s+host\s+\S+", r"^no\s+logging\s+host\s+\S+", "remote logging host configured"
        ),
        "logging_trap_configured": _pattern_toggle(
            lines, r"^logging\s+trap\s+\S+", r"^no\s+logging\s+trap\s*$", "logging trap level configured"
        ),
        "ntp_authentication_enabled": _pattern_toggle(
            lines, r"^ntp\s+authenticate\s*$", r"^no\s+ntp\s+authenticate\s*$", "NTP authentication enabled"
        ),
        "ntp_authentication_key_configured": _pattern_toggle(
            lines, r"^ntp\s+authentication-key\s+\S+\s+\S+\s+\S+", r"^no\s+ntp\s+authentication-key\s+\S+", "NTP authentication key configured"
        ),
        "ntp_trusted_key_configured": _pattern_toggle(
            lines, r"^ntp\s+trusted-key\s+\S+", r"^no\s+ntp\s+trusted-key\s+\S+", "NTP trusted key configured"
        ),
        "ntp_server_keyed": _pattern_toggle(
            lines, r"^ntp\s+server\s+\S+.*\bkey\s+\S+", r"^no\s+ntp\s+server\s+\S+", "NTP server uses an authentication key"
        ),
        "snmpv3_privacy_configured": _pattern_toggle(
            lines, r"^snmp-server\s+(?:group\s+\S+\s+v3\s+priv|user\s+\S+\s+\S+\s+v3\s+.*\bpriv\b)", r"^no\s+snmp-server\s+(?:group|user)\b", "SNMPv3 privacy configuration observed"
        ),
    }

    return {
        "schema_version": "1.0",
        "vendor": "Cisco",
        "platform": "IOS/IOS-XE",
        "fields": fields,
    }
