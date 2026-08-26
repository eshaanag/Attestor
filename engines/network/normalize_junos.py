"""Vendor-neutral facts extracted from a Junos configuration."""
from __future__ import annotations

from typing import Any

from engines.network.junos import JunosStatement, statement_matches


def _fact(value: Any, match: JunosStatement | None, observation: str) -> dict[str, Any]:
    return {
        "value": value,
        "evidence": (
            {"line": match.line, "observation": observation} if match else None
        ),
    }


def normalize_junos(statements: tuple[JunosStatement, ...]) -> dict[str, Any]:
    hostname = next(
        (
            statement.text.removeprefix("host-name ").removesuffix(";")
            for statement in statements
            if "/".join(statement.path) == "system"
            and statement.text.startswith("host-name ")
        ),
        None,
    )
    hostname_statement = next(
        (
            statement
            for statement in statements
            if "/".join(statement.path) == "system"
            and statement.text.startswith("host-name ")
        ),
        None,
    )
    telnet = statement_matches(statements, r"system/services", r"telnet;")
    ftp = statement_matches(statements, r"system/services", r"ftp;")
    syslog = statement_matches(statements, r"system", r"syslog")
    public = statement_matches(statements, r"snmp", r"community public")
    return {
        "schema_version": "1.0",
        "vendor": "Juniper",
        "platform": "Junos",
        "fields": {
            "hostname": _fact(hostname, hostname_statement, "device hostname"),
            "telnet_enabled": _fact(bool(telnet), telnet[0] if telnet else None, "Telnet service statement observed"),
            "ftp_enabled": _fact(bool(ftp), ftp[0] if ftp else None, "FTP service statement observed"),
            "syslog_configured": _fact(bool(syslog), syslog[0] if syslog else None, "system syslog block observed"),
            "snmp_public_community": _fact(bool(public), public[0] if public else None, "SNMP public community statement observed"),
        },
    }
