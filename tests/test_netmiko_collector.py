from __future__ import annotations

import stat

import pytest

from engines.network.netmiko_collector import (
    CollectionError,
    CollectionRequest,
    PROFILES,
    _write_private,
    collect_running_config,
)


class FakeConnection:
    def __init__(self, outputs: dict[str, str]):
        self.outputs = outputs
        self.commands: list[tuple[str, dict]] = []
        self.enabled = False
        self.disconnected = False

    def enable(self):
        self.enabled = True

    def send_command(self, command: str, **kwargs):
        self.commands.append((command, kwargs))
        return self.outputs[command]

    def disconnect(self):
        self.disconnected = True


def _request(**overrides) -> CollectionRequest:
    values = {
        "vendor": "cisco_ios",
        "host": "router.example.test",
        "port": 22,
        "username": "auditor",
        "password": "private-password",
        "secret": "private-enable",
    }
    values.update(overrides)
    return CollectionRequest(**values)


def test_cisco_collection_uses_fixed_commands_enable_and_disconnects():
    connection = FakeConnection({
        "show running-config": "hostname edge-router\n!\nip ssh version 2\n",
        "show version": "Cisco IOS Software, Version 17.12\n",
    })
    captured = {}

    def connector(**parameters):
        captured.update(parameters)
        return connection

    result = collect_running_config(_request(), connector=connector)

    assert captured["device_type"] == "cisco_ios"
    assert captured["password"] == "private-password"
    assert captured["secret"] == "private-enable"
    assert connection.enabled is True
    assert connection.disconnected is True
    assert [command for command, _ in connection.commands] == [
        "show running-config", "show version"
    ]
    assert all(options["strip_prompt"] for _, options in connection.commands)
    assert result.config_text.startswith("hostname edge-router")
    assert result.facts_text.startswith("Cisco IOS Software")
    assert "password" not in result.public_metadata()
    assert "username" not in result.public_metadata()
    assert "secret" not in result.public_metadata()
    assert "private-password" not in repr(_request())
    assert "private-enable" not in repr(_request())


@pytest.mark.parametrize(
    ("vendor", "device_type", "config_command", "facts_command"),
    [
        ("cisco_ios", "cisco_ios", "show running-config", "show version"),
        ("juniper_junos", "juniper_junos", "show configuration | no-more", "show version | no-more"),
        ("fortinet_fortios", "fortinet", "show full-configuration", None),
    ],
)
def test_vendor_profiles_are_fixed(vendor, device_type, config_command, facts_command):
    profile = PROFILES[vendor]
    assert profile.netmiko_device_type == device_type
    assert profile.config_command == config_command
    assert profile.facts_command == facts_command


@pytest.mark.parametrize(
    "overrides",
    [
        {"vendor": "unknown"},
        {"host": "https://router.example.test/path"},
        {"host": "user@router"},
        {"port": 0},
        {"username": ""},
        {"password": ""},
        {"connect_timeout": 2},
        {"read_timeout": 301},
    ],
)
def test_collection_request_rejects_unsafe_or_invalid_values(overrides):
    with pytest.raises(ValueError):
        _request(**overrides)


def test_command_rejection_fails_closed_and_disconnects():
    connection = FakeConnection({
        "show running-config": "% Authorization failed",
        "show version": "unused",
    })
    with pytest.raises(CollectionError, match="could not authorize"):
        collect_running_config(_request(secret=None), connector=lambda **_: connection)
    assert connection.disconnected is True


def test_connection_error_redacts_credentials():
    class NetmikoAuthenticationException(Exception):
        pass

    def connector(**_):
        raise NetmikoAuthenticationException("private-password private-enable")

    with pytest.raises(CollectionError) as caught:
        collect_running_config(_request(), connector=connector)
    assert str(caught.value) == "SSH authentication failed"
    assert "private-password" not in str(caught.value)
    assert "private-enable" not in str(caught.value)


def test_private_capture_writer_uses_owner_only_permissions(tmp_path):
    output = tmp_path / "running-config.txt"
    _write_private(output, "hostname edge-router\n")
    assert output.read_text() == "hostname edge-router\n"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
