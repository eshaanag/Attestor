#!/usr/bin/env python3
"""Fail-closed live SSH collection for built-in network adapters."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


MAX_OUTPUT_BYTES = 2 * 1024 * 1024
HOST_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,251}[A-Za-z0-9])?$")
COMMAND_ERRORS = (
    "% invalid input",
    "% authorization failed",
    "% insufficient privileges",
    "permission denied",
    "command fail",
    "unknown command",
    "syntax error",
)


@dataclass(frozen=True)
class VendorCollectionProfile:
    netmiko_device_type: str
    config_command: str
    facts_command: str | None


PROFILES = {
    "cisco_ios": VendorCollectionProfile(
        "cisco_ios", "show running-config", "show version"
    ),
    "juniper_junos": VendorCollectionProfile(
        "juniper_junos", "show configuration | no-more", "show version | no-more"
    ),
    "fortinet_fortios": VendorCollectionProfile(
        "fortinet", "show full-configuration", None
    ),
}


class CollectionError(RuntimeError):
    """The live device could not provide trustworthy configuration input."""


@dataclass(frozen=True)
class CollectionRequest:
    vendor: str
    host: str
    port: int
    username: str
    password: str = field(repr=False)
    secret: str | None = field(default=None, repr=False)
    connect_timeout: int = 15
    read_timeout: int = 60

    def __post_init__(self) -> None:
        if self.vendor not in PROFILES:
            raise ValueError(f"unsupported live collection vendor: {self.vendor!r}")
        host = self.host.strip()
        if not HOST_PATTERN.fullmatch(host) or "/" in host or "@" in host:
            raise ValueError("host must be an IP address or DNS hostname without a URL or path")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if not self.username.strip() or any(ord(char) < 32 for char in self.username):
            raise ValueError("username is required and cannot contain control characters")
        if not self.password:
            raise ValueError("password is required")
        if not 3 <= self.connect_timeout <= 120:
            raise ValueError("connect_timeout must be between 3 and 120 seconds")
        if not 5 <= self.read_timeout <= 300:
            raise ValueError("read_timeout must be between 5 and 300 seconds")

    def connection_parameters(self) -> dict[str, Any]:
        profile = PROFILES[self.vendor]
        parameters: dict[str, Any] = {
            "device_type": profile.netmiko_device_type,
            "host": self.host.strip(),
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "conn_timeout": self.connect_timeout,
            "auth_timeout": self.connect_timeout,
            "banner_timeout": self.connect_timeout,
            "timeout": self.connect_timeout,
            "fast_cli": False,
        }
        if self.secret:
            parameters["secret"] = self.secret
        return parameters


@dataclass(frozen=True)
class CollectionResult:
    vendor: str
    host: str
    port: int
    config_command: str
    config_text: str
    config_sha256: str
    facts_command: str | None
    facts_text: str | None
    facts_sha256: str | None
    collected_at: str

    def public_metadata(self) -> dict[str, Any]:
        return {
            "method": "netmiko-ssh",
            "vendor": self.vendor,
            "host": self.host,
            "port": self.port,
            "config_command": self.config_command,
            "config_sha256": self.config_sha256,
            "facts_command": self.facts_command,
            "facts_sha256": self.facts_sha256,
            "collected_at": self.collected_at,
        }


def _connect_handler(**parameters: Any):
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise CollectionError(
            "Netmiko is not installed; run: python3 -m pip install -r requirements.txt"
        ) from exc
    return ConnectHandler(**parameters)


def _sanitize_error(exc: Exception, request: CollectionRequest) -> str:
    detail = str(exc).strip().replace(request.password, "[REDACTED]")
    if request.secret:
        detail = detail.replace(request.secret, "[REDACTED]")
    detail = re.sub(r"\s+", " ", detail)[:400]
    name = type(exc).__name__
    lowered = name.casefold()
    if "authentication" in lowered:
        return "SSH authentication failed"
    if "timeout" in lowered:
        return "SSH connection or command timed out"
    return f"SSH collection failed ({name})" + (f": {detail}" if detail else "")


def _validated_output(output: Any, command: str) -> str:
    if not isinstance(output, str):
        raise CollectionError(f"device returned non-text output for {command!r}")
    text = output.replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        raise CollectionError(f"device returned empty output for {command!r}")
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise CollectionError(f"device output for {command!r} exceeds the 2 MiB limit")
    output_lines = [line.strip().casefold() for line in text.splitlines() if line.strip()]
    if any(
        line.startswith(marker)
        for line in output_lines
        for marker in COMMAND_ERRORS
    ):
        raise CollectionError(f"device rejected or could not authorize {command!r}")
    return text


def collect_running_config(
    request: CollectionRequest,
    connector: Callable[..., Any] | None = None,
) -> CollectionResult:
    """Collect configuration and optional facts without evaluating compliance."""
    profile = PROFILES[request.vendor]
    connection = None
    try:
        connection = (connector or _connect_handler)(**request.connection_parameters())
        if request.vendor == "cisco_ios" and request.secret:
            connection.enable()
        config_text = _validated_output(
            connection.send_command(
                profile.config_command,
                read_timeout=request.read_timeout,
                strip_prompt=True,
                strip_command=True,
            ),
            profile.config_command,
        )
        facts_text = None
        if profile.facts_command:
            facts_text = _validated_output(
                connection.send_command(
                    profile.facts_command,
                    read_timeout=request.read_timeout,
                    strip_prompt=True,
                    strip_command=True,
                ),
                profile.facts_command,
            )
    except CollectionError:
        raise
    except Exception as exc:
        raise CollectionError(_sanitize_error(exc, request)) from exc
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                pass

    config_bytes = config_text.encode("utf-8")
    facts_bytes = facts_text.encode("utf-8") if facts_text is not None else None
    return CollectionResult(
        vendor=request.vendor,
        host=request.host.strip(),
        port=request.port,
        config_command=profile.config_command,
        config_text=config_text,
        config_sha256=hashlib.sha256(config_bytes).hexdigest(),
        facts_command=profile.facts_command,
        facts_text=facts_text,
        facts_sha256=hashlib.sha256(facts_bytes).hexdigest() if facts_bytes else None,
        collected_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect a real network-device configuration over SSH using Netmiko"
    )
    parser.add_argument("--vendor", choices=sorted(PROFILES), required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--username", required=True)
    parser.add_argument("--output", required=True, help="owner-only collected config path")
    parser.add_argument("--facts-output", help="owner-only show-version path")
    parser.add_argument("--connect-timeout", type=int, default=15)
    parser.add_argument("--read-timeout", type=int, default=60)
    args = parser.parse_args(argv)

    password = os.environ.get("ATTESTOR_DEVICE_PASSWORD") or getpass.getpass("SSH password: ")
    secret = os.environ.get("ATTESTOR_DEVICE_SECRET")
    try:
        result = collect_running_config(CollectionRequest(
            vendor=args.vendor,
            host=args.host,
            port=args.port,
            username=args.username,
            password=password,
            secret=secret,
            connect_timeout=args.connect_timeout,
            read_timeout=args.read_timeout,
        ))
        _write_private(Path(args.output).expanduser().resolve(), result.config_text)
        if result.facts_text is not None and args.facts_output:
            _write_private(Path(args.facts_output).expanduser().resolve(), result.facts_text)
    except (ValueError, CollectionError, OSError) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 2
    print(json.dumps(result.public_metadata(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
