import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import defusedxml.ElementTree as ET

from app.core.tool_registry import RegistryError
from app.wrappers.base import ToolArtifact, ToolResult

ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


_NETEXEC_BANNER_META = re.compile(r"\((name|domain|signing|SMBv1):([^)]*)\)")
_NETEXEC_SHARE_SKIP = {"Share", "Disk", "Permissions", "Remark"}


def _netexec_signal(raw_output: str, protocol: str) -> dict:
    """Extract the decision-grade NetExec signal shared by every protocol.

    NetExec prints one banner line plus status lines that all share the column
    layout ``PROTO  host  port  hostname  [status] message``. The planner's
    escalation decisions hinge on two booleans distilled here:

    * ``credential_valid`` -- the supplied credential authenticated (a ``[+]``
      status line is present).
    * ``admin`` -- authentication yielded administrative rights (``(Pwn3d!)``),
      i.e. SMB local admin, WinRM execution, or MSSQL sysadmin.

    Protocol-column matching is case-sensitive on the upper-case prefix NetExec
    always emits, so unrelated log noise never populates host/port.
    """
    clean_output = ANSI_ESCAPE.sub("", raw_output)
    proto_lines = [
        line for line in clean_output.splitlines() if line.lstrip().startswith(protocol)
    ]
    metadata: dict = {"protocol": protocol}
    tokens = proto_lines[0].split() if proto_lines else []
    if len(tokens) >= 4:
        metadata.update({"host": tokens[1], "port": tokens[2], "hostname": tokens[3]})
    for line in proto_lines:
        for key, value in _NETEXEC_BANNER_META.findall(line):
            normalized_key = key.lower()
            if normalized_key not in metadata:
                metadata[normalized_key] = (
                    value == "True" if value in {"True", "False"} else value
                )
    body = "\n".join(proto_lines)
    metadata["credential_valid"] = "[+]" in body
    metadata["admin"] = "(Pwn3d!)" in body
    return metadata


def _netexec_smb_shares(raw_output: str) -> list[dict]:
    """Best-effort parse of ``--shares`` rows into ``{name, permissions}``.

    Share rows follow the four-token ``SMB host port hostname`` prefix with a
    ``ShareName  Permissions  Remark`` remainder. Status lines (``[*]``/``[+]``/
    ``[-]``), the column header, and the ``-----`` separator are skipped. This is
    enrichment, not the primary signal, so it stays conservative rather than
    exhaustive.
    """
    clean_output = ANSI_ESCAPE.sub("", raw_output)
    shares: list[dict] = []
    seen: set[str] = set()
    for line in clean_output.splitlines():
        stripped = line.lstrip()
        if not stripped.startswith("SMB"):
            continue
        tokens = stripped.split()
        if len(tokens) < 5:
            continue
        remainder = tokens[4:]
        name = remainder[0]
        if name.startswith("[") or name in _NETEXEC_SHARE_SKIP or set(name) <= {"-"}:
            continue
        if name in seen:
            continue
        permissions = ""
        if len(remainder) > 1 and ("READ" in remainder[1] or "WRITE" in remainder[1]):
            permissions = remainder[1]
        seen.add(name)
        shares.append({"name": name, "permissions": permissions})
    return shares


def _netexec_smb_metadata(
    raw_output: str, artifact: ToolArtifact | None = None
) -> dict:
    metadata = _netexec_signal(raw_output, "SMB")
    metadata["collection_type"] = "smb_validation"
    shares = _netexec_smb_shares(raw_output)
    if shares:
        metadata["shares"] = shares
        metadata["writable_shares"] = sorted(
            {
                share["name"]
                for share in shares
                if "WRITE" in share.get("permissions", "")
            }
        )
    return metadata


def _netexec_ldap_metadata(
    raw_output: str, artifact: ToolArtifact | None = None
) -> dict:
    metadata = _netexec_signal(raw_output, "LDAP")
    metadata["collection_type"] = "ldap_validation"
    return metadata


def _netexec_winrm_metadata(
    raw_output: str, artifact: ToolArtifact | None = None
) -> dict:
    metadata = _netexec_signal(raw_output, "WINRM")
    metadata["collection_type"] = "winrm_validation"
    return metadata


def _netexec_mssql_metadata(
    raw_output: str, artifact: ToolArtifact | None = None
) -> dict:
    metadata = _netexec_signal(raw_output, "MSSQL")
    metadata["collection_type"] = "mssql_validation"
    return metadata


def _bloodhound_json_metadata(raw_output: str, artifact: ToolArtifact | None) -> dict:
    filename = artifact.filename if artifact else None
    fallback_type = (
        Path(filename).stem.split("_")[-1].lower() if filename else "collection_output"
    )
    metadata: dict = {
        "protocol": "BloodHound",
        "collection_type": fallback_type,
    }
    if filename:
        metadata["artifact_filename"] = filename
    try:
        document = json.loads(raw_output)
    except json.JSONDecodeError:
        metadata["record_count"] = 0
        metadata["parse_error"] = "invalid_json"
        return metadata

    meta = document.get("meta", {}) if isinstance(document, dict) else {}
    if isinstance(meta, dict):
        metadata["collection_type"] = str(meta.get("type") or fallback_type).lower()
        if "version" in meta:
            metadata["format_version"] = meta["version"]
        if "methods" in meta:
            metadata["collection_methods"] = meta["methods"]
        if "count" in meta:
            metadata["reported_record_count"] = meta["count"]
    data = document.get("data") if isinstance(document, dict) else None
    metadata["record_count"] = len(data) if isinstance(data, list) else 0
    return metadata


def _certipy_json_metadata(raw_output: str, artifact: ToolArtifact | None) -> dict:
    metadata: dict = {
        "protocol": "AD CS",
        "collection_type": "certificate_services",
    }
    if artifact:
        metadata["artifact_filename"] = artifact.filename
    try:
        document = json.loads(raw_output)
    except json.JSONDecodeError:
        metadata["parse_error"] = "invalid_json"
        metadata["vulnerability_count"] = 0
        return metadata

    if not isinstance(document, dict):
        metadata["parse_error"] = "json_object_required"
        metadata["vulnerability_count"] = 0
        return metadata

    section_counts: dict[str, int] = {}
    vulnerability_count = 0
    for section_name in (
        "Certificate Authorities",
        "Certificate Templates",
        "Issuance Policies",
    ):
        section = document.get(section_name)
        if not isinstance(section, dict):
            section_counts[section_name] = 0
            continue
        section_counts[section_name] = len(section)
        for entry in section.values():
            if not isinstance(entry, dict):
                continue
            vulnerabilities = entry.get("[!] Vulnerabilities")
            if isinstance(vulnerabilities, dict):
                vulnerability_count += sum(
                    1
                    for key in vulnerabilities
                    if re.fullmatch(r"ESC\d+", str(key), flags=re.IGNORECASE)
                )

    metadata["section_counts"] = section_counts
    metadata["vulnerability_count"] = vulnerability_count
    return metadata


def _json_record_count(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    return 1 if value is not None else 0


def _enum4linux_json_metadata(raw_output: str, artifact: ToolArtifact | None) -> dict:
    metadata: dict[str, Any] = {
        "protocol": "SMB/RPC",
        "collection_type": "smb_rpc_enumeration",
    }
    if artifact:
        metadata["artifact_filename"] = artifact.filename
    try:
        document = json.loads(raw_output)
    except json.JSONDecodeError:
        metadata["parse_error"] = "invalid_json"
        metadata["record_count"] = 0
        return metadata
    if not isinstance(document, dict):
        metadata["parse_error"] = "json_object_required"
        metadata["record_count"] = 0
        return metadata

    section_counts: dict[str, int] = {}
    record_count = 0
    for key, value in document.items():
        if key == "credentials":
            metadata["credentials_present"] = True
            continue
        if key == "errors":
            metadata["error_count"] = _json_record_count(value)
            continue
        count = _json_record_count(value)
        section_counts[str(key)] = count
        record_count += count
    metadata["section_counts"] = section_counts
    metadata["record_count"] = record_count
    return metadata


def _kerbrute_json_safe_token(value: str) -> str:
    return value.strip().rstrip(",;.)]")


KERBRUTE_VALID_USERNAME_PATTERN = re.compile(
    r"\[\+\]\s+VALID USERNAME(?: WITH ERROR)?:\s*(?P<value>[^\s(]+)",
    re.IGNORECASE,
)
KERBRUTE_VALID_LOGIN_PATTERN = re.compile(
    r"\[\+\]\s+VALID LOGIN(?: WITH ERROR)?:\s*(?P<value>[^\s(]+)",
    re.IGNORECASE,
)
KERBRUTE_ASREP_PATTERN = re.compile(r"\$krb5asrep\$[^\s]+", re.IGNORECASE)


def _kerbrute_text_metadata(raw_output: str, artifact: ToolArtifact | None) -> dict:
    clean_output = ANSI_ESCAPE.sub("", raw_output)
    valid_usernames = [
        _kerbrute_json_safe_token(match.group("value"))
        for match in KERBRUTE_VALID_USERNAME_PATTERN.finditer(clean_output)
    ]
    valid_logins = [
        _kerbrute_json_safe_token(match.group("value"))
        for match in KERBRUTE_VALID_LOGIN_PATTERN.finditer(clean_output)
    ]
    tested_match = re.search(
        r"Tested\s+(\d+)\s+(?:usernames|logins)\s+\((\d+)\s+(?:valid|successes)\)",
        clean_output,
        flags=re.IGNORECASE,
    )
    metadata: dict[str, Any] = {
        "protocol": "Kerberos",
        "collection_type": "kerbrute",
        "valid_username_count": len(valid_usernames),
        "valid_login_count": len(valid_logins),
        "lockout_detected": bool(
            re.search(
                r"lock(?:ed)?[- ]?out|account lockout",
                clean_output,
                re.IGNORECASE,
            )
        ),
    }
    if tested_match:
        metadata["tested_count"] = int(tested_match.group(1))
        metadata["reported_success_count"] = int(tested_match.group(2))
    if valid_logins:
        metadata["sensitivity"] = "credential"
        metadata["credential_material_withheld"] = True
    asrep_hashes = KERBRUTE_ASREP_PATTERN.findall(clean_output)
    if asrep_hashes:
        metadata["asrep_hash_count"] = len(asrep_hashes)
        metadata["sensitivity"] = "credential"
        metadata["hash_format"] = "hashcat"
    if artifact:
        metadata["artifact_filename"] = artifact.filename
    return metadata


def _ldapdomaindump_json_metadata(
    raw_output: str, artifact: ToolArtifact | None
) -> dict:
    filename = artifact.filename if artifact else "ldapdomaindump.json"
    stem = Path(filename).stem.lower()
    section = stem.removeprefix("domain_")
    if section.endswith(("_by_group", "_by_os")):
        collection_type = section
    else:
        collection_type = section or "domain_report"
    metadata: dict[str, Any] = {
        "protocol": "LDAP",
        "collection_type": collection_type,
        "artifact_filename": filename,
    }
    try:
        document = json.loads(raw_output)
    except json.JSONDecodeError:
        metadata["parse_error"] = "invalid_json"
        metadata["record_count"] = 0
        return metadata
    if not isinstance(document, (dict, list)):
        metadata["parse_error"] = "json_collection_required"
        metadata["record_count"] = 0
        return metadata
    metadata["record_count"] = _json_record_count(document)
    if isinstance(document, dict):
        metadata["field_count"] = len(document)
    return metadata


RESPONDER_HASH_PATTERNS = (
    (re.compile(r"\$krb5asrep\$[^\s]+", re.IGNORECASE), "kerberos_asrep", 18200),
    (re.compile(r"\$krb5tgs\$[^\s]+", re.IGNORECASE), "kerberos_tgs", 13100),
    (
        re.compile(r"^[^:\r\n]+::[^:\r\n]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[^\s:]+$"),
        "netntlmv2",
        5600,
    ),
    (
        re.compile(
            r"^[^:\r\n]+::[^:\r\n]*:[0-9a-fA-F]{32,48}:[0-9a-fA-F]{32,48}:[0-9a-fA-F]{16}$"
        ),
        "netntlmv1",
        5500,
    ),
)


def _responder_hash_match(line: str) -> tuple[str, str, int] | None:
    candidate = line.strip().rstrip(",;.)]")
    for pattern, hash_format, hashcat_mode in RESPONDER_HASH_PATTERNS:
        match = pattern.search(candidate)
        if match:
            return match.group(0), hash_format, hashcat_mode
    if candidate.startswith("$NETNTLM"):
        return candidate, "netntlm", 5600
    return None


def _responder_hash_metadata(raw_output: str, artifact: ToolArtifact | None) -> dict:
    lines = [line.strip() for line in ANSI_ESCAPE.sub("", raw_output).splitlines()]
    captures = [
        match for line in lines if (match := _responder_hash_match(line)) is not None
    ]
    formats = sorted({match[1] for match in captures})
    modes = sorted({match[2] for match in captures})
    metadata: dict[str, Any] = {
        "protocol": "Responder",
        "collection_type": "credential_listener",
        "capture_count": len(captures),
        "hash_formats": formats,
        "hashcat_modes": modes,
        "sensitivity": "credential" if captures else None,
    }
    if artifact:
        metadata["artifact_filename"] = artifact.filename
    return metadata


def _responder_cleartext_metadata(
    raw_output: str, artifact: ToolArtifact | None
) -> dict:
    metadata: dict[str, Any] = {
        "protocol": "Responder",
        "collection_type": "cleartext_listener_credential",
        "sensitivity": "credential",
        "capture_count": sum(
            1 for line in raw_output.splitlines() if line.strip() and ":" in line
        ),
    }
    if artifact:
        metadata["artifact_filename"] = artifact.filename
    return metadata


def _responder_metadata(raw_output: str, artifact: ToolArtifact | None) -> dict:
    if artifact and "clear-text-" in artifact.filename.casefold():
        return _responder_cleartext_metadata(raw_output, artifact)
    return _responder_hash_metadata(raw_output, artifact)


def _coercer_text_metadata(raw_output: str, artifact: ToolArtifact | None) -> dict:
    clean_output = ANSI_ESCAPE.sub("", raw_output)
    metadata: dict[str, Any] = {
        "protocol": "MSRPC",
        "collection_type": "authentication_coercion",
        "authentication_received": bool(
            re.search(
                r"authentication received|NTLM.*received", clean_output, re.IGNORECASE
            )
        ),
    }
    if artifact:
        metadata["artifact_filename"] = artifact.filename
    return metadata


KERBEROAST_HASH_PATTERN = re.compile(r"\$krb5tgs\$[^\s]+", re.IGNORECASE)
KERBEROAST_MODES = {
    17: 19600,
    18: 19700,
    23: 13100,
}
NTLM_HASH_LINE_PATTERN = re.compile(
    r"^[^:\r\n]+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::(?:.*)?$"
)
DCC_HASH_PATTERN = re.compile(r"\$DCC2?\$", re.IGNORECASE)
LSA_SECRET_PREFIX_PATTERN = re.compile(
    r"^(?:\$MACHINE\.ACC|DPAPI_SYSTEM|NL\$\d+|DefaultPassword|_SC_[^:]+):",
    re.IGNORECASE,
)


def _kerberoast_hashes(raw_output: str) -> list[str]:
    clean_output = ANSI_ESCAPE.sub("", raw_output)
    hashes: list[str] = []
    seen: set[str] = set()
    for value in KERBEROAST_HASH_PATTERN.findall(clean_output):
        value = value.rstrip(",;.)]")
        if value not in seen:
            hashes.append(value)
            seen.add(value)
    return hashes


def _kerberoast_hash_metadata(raw_output: str, artifact: ToolArtifact | None) -> dict:
    hashes = _kerberoast_hashes(raw_output)
    modes: set[int] = set()
    for hash_value in hashes:
        match = re.match(r"\$krb5tgs\$(\d+)\$", hash_value, flags=re.IGNORECASE)
        if match:
            mode = KERBEROAST_MODES.get(int(match.group(1)))
            if mode is not None:
                modes.add(mode)
    metadata: dict = {
        "protocol": "Kerberos",
        "collection_type": "kerberoast",
        "crackable": bool(hashes),
        "hash_format": "hashcat" if hashes else None,
        "hash_count": len(hashes),
    }
    if hashes:
        metadata["sensitivity"] = "credential"
    if len(modes) == 1:
        metadata["hashcat_mode"] = next(iter(modes))
    elif modes:
        metadata["hashcat_modes"] = sorted(modes)
    if artifact:
        metadata["artifact_filename"] = artifact.filename
    return metadata


def _kerberoast_identity(hash_value: str) -> dict[str, str]:
    match = re.match(r"\$krb5tgs\$\d+\$(.+)", hash_value, flags=re.IGNORECASE)
    if match is None:
        return {}
    parts = match.group(1).split("$")
    if len(parts) < 3:
        return {}
    return {
        "principal": parts[0].strip("*"),
        "realm": parts[1],
        "service_principal": parts[2].strip("*"),
    }


def _secretsdump_credential_type(
    line: str, artifact: ToolArtifact | None
) -> str | None:
    candidate = re.sub(r"^(?:\[[^\]]+\]\s*)+", "", line.strip())
    filename = artifact.filename.lower() if artifact else ""
    if filename.endswith(".ntds.kerberos"):
        return "kerberos_key"
    if filename.endswith(".ntds.cleartext"):
        return "cleartext_password"
    if filename.endswith((".sam", ".ntds")):
        return "ntlm_hash"
    if filename.endswith(".cached"):
        return "cached_credential"
    if filename.endswith(".secrets"):
        return "lsa_secret"
    if NTLM_HASH_LINE_PATTERN.fullmatch(candidate):
        return "ntlm_hash"
    if DCC_HASH_PATTERN.search(candidate):
        return "cached_credential"
    if LSA_SECRET_PREFIX_PATTERN.search(candidate):
        return "lsa_secret"
    if ":CLEARTEXT:" in candidate.upper() or "plain_password" in candidate.lower():
        return "cleartext_password"
    if re.search(
        r"(?:kerberos|aes\d+|rc4[_-]?hmac).*:[0-9a-f]{16,}", candidate, re.IGNORECASE
    ):
        return "kerberos_key"
    return None


SECRETSDUMP_HASHCAT_MODES = {
    "ntlm_hash": 1000,
    "cached_credential": 2100,
}


def _secretsdump_crackable_hash(line: str, credential_type: str) -> str | None:
    # Extract the offline-crackable material from a secretsdump credential line
    # so an autonomous crack can be proposed by finding_id alone. Withheld from
    # the planner (not in _finding_context's credential metadata allowlist).
    candidate = re.sub(r"^(?:\[[^\]]+\]\s*)+", "", line.strip())
    if credential_type == "ntlm_hash":
        # user:rid:LM:NT::: -> the NT half is hashcat mode 1000.
        parts = candidate.split(":")
        if len(parts) >= 4 and re.fullmatch(r"[0-9a-fA-F]{32}", parts[3]):
            return parts[3]
        return None
    if credential_type == "cached_credential":
        match = re.search(r"\$DCC2?\$\S+", candidate)
        return match.group(0) if match else None
    return None


def _impacket_kerberoast_metadata(
    raw_output: str, artifact: ToolArtifact | None = None
) -> dict:
    return _kerberoast_hash_metadata(raw_output, artifact)


def _impacket_secretsdump_metadata(
    raw_output: str, artifact: ToolArtifact | None = None
) -> dict:
    clean_output = ANSI_ESCAPE.sub("", raw_output)
    lines = [line.strip() for line in clean_output.splitlines() if line.strip()]
    credential_types = [
        credential_type
        for line in lines
        if (credential_type := _secretsdump_credential_type(line, artifact)) is not None
    ]
    metadata: dict = {
        "protocol": "Windows credentials",
        "collection_type": "secretsdump",
        "credential_count": len(credential_types),
        "credential_types": sorted(set(credential_types)),
    }
    if credential_types:
        metadata["sensitivity"] = "credential"
    if artifact:
        metadata["artifact_filename"] = artifact.filename
    return metadata


def _nmap_int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _nmap_xml_metadata(raw_output: str, artifact: ToolArtifact | None = None) -> dict:
    metadata: dict[str, Any] = {"protocol": "nmap"}
    if artifact:
        metadata["artifact_filename"] = artifact.filename
    try:
        root = ET.fromstring(raw_output)
    except ET.ParseError:
        metadata.update(
            {
                "collection_type": "host_discovery",
                "hosts_total": 0,
                "hosts_up": 0,
                "open_port_count": 0,
                "open_services": [],
                "hosts": [],
                "parse_error": "invalid_xml",
            }
        )
        return metadata

    hosts: list[dict[str, Any]] = []
    services: set[str] = set()
    open_port_count = 0
    for host_element in root.findall("host")[:100]:
        status = host_element.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue
        address = ""
        for addr in host_element.findall("address"):
            if addr.get("addrtype") in {"ipv4", "ipv6"}:
                address = addr.get("addr", "")
                break
        hostname_element = host_element.find("hostnames/hostname")
        hostname = (
            hostname_element.get("name") if hostname_element is not None else None
        )
        open_ports: list[dict[str, Any]] = []
        for port_element in host_element.findall("ports/port")[:50]:
            state = port_element.find("state")
            if state is None or state.get("state") != "open":
                continue
            entry: dict[str, Any] = {
                "port": _nmap_int(port_element.get("portid")),
                "protocol": port_element.get("protocol", "tcp"),
            }
            service = port_element.find("service")
            if service is not None:
                name = service.get("name")
                if name:
                    entry["service"] = name
                    services.add(name)
                for key in ("product", "version"):
                    value = service.get(key)
                    if value:
                        entry[key] = value
            open_ports.append(entry)
        open_port_count += len(open_ports)
        host_record: dict[str, Any] = {"address": address, "open_ports": open_ports}
        if hostname:
            host_record["hostname"] = hostname
        hosts.append(host_record)

    runstats = root.find("runstats/hosts")
    hosts_up = _nmap_int(runstats.get("up")) if runstats is not None else None
    hosts_total = _nmap_int(runstats.get("total")) if runstats is not None else None
    metadata.update(
        {
            "collection_type": "service_scan" if open_port_count else "host_discovery",
            "hosts_total": hosts_total if hosts_total is not None else len(hosts),
            "hosts_up": hosts_up if hosts_up is not None else len(hosts),
            "open_port_count": open_port_count,
            "open_services": sorted(services),
            "hosts": hosts,
        }
    )
    return metadata


HASHCAT_ARTIFACT_PATTERN = re.compile(r"hashcat_(\d+)\.cracked$")


def _hashcat_mode_from_artifact(artifact: ToolArtifact | None) -> int | None:
    if artifact is None:
        return None
    match = HASHCAT_ARTIFACT_PATTERN.search(artifact.filename)
    return int(match.group(1)) if match else None


def _hashcat_metadata(raw_output: str, artifact: ToolArtifact | None = None) -> dict:
    # The crack mode is carried in the artifact filename (hashcat_<mode>.cracked)
    # because this parser has no access to the resolved HashcatOptions.
    cracked_lines = [line for line in raw_output.splitlines() if line.strip()]
    mode = _hashcat_mode_from_artifact(artifact)
    metadata: dict = {
        "protocol": "hashcat",
        "collection_type": "hash_crack",
        "cracked_count": len(cracked_lines),
    }
    if mode is not None:
        metadata["hashcat_mode"] = mode
    if cracked_lines:
        metadata["sensitivity"] = "credential"
    if artifact:
        metadata["artifact_filename"] = artifact.filename
    return metadata


# MANSPIDER logs one line per matched file. Two log-format prefixes are
# possible depending on the harvest source: the per-day logfile
# ("<date> <time> <LEVEL> <message>") and the console fallback ("[+] <message>"
# after the ANSI colour codes are stripped). Both are tolerated.
_MANSPIDER_PREFIX = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} \w+ |\[[*+!\-]{1,3}\] )"
)
# Content-match line body: "<host>\<share>\<name>: matched "<pattern>" <N> times".
# The pattern is the NAME of a curated search term (safe to surface); the matched
# VALUE is never logged because MANSPIDER runs with -q.
_MANSPIDER_MATCH = re.compile(
    r'^(?P<pretty>.+?): matched "(?P<pattern>.*?)" (?P<count>[\d,]+) times\s*$'
)


def _parse_manspider_matches(raw_output: str) -> list[dict]:
    """Group MANSPIDER content-match log lines into one record per file.

    Returns content-free records: host / share / file path plus the NAMES of the
    curated patterns that matched and their hit counts. No matched file content
    is present in the input (the wrapper enforces -q) or in the output.
    """
    grouped: dict[tuple[str, str, str], dict] = {}
    order: list[tuple[str, str, str]] = []
    for line in raw_output.splitlines():
        body = _MANSPIDER_PREFIX.sub("", ANSI_ESCAPE.sub("", line)).strip()
        match = _MANSPIDER_MATCH.match(body)
        if match is None:
            continue
        pretty = match.group("pretty").strip()
        pattern = match.group("pattern")
        count = int(match.group("count").replace(",", ""))
        parts = pretty.split("\\")
        if len(parts) >= 3:
            host, share, file_path = parts[0], parts[1], "\\".join(parts[2:])
        elif len(parts) == 2:
            host, share, file_path = parts[0], parts[1], parts[1]
        else:
            host, share, file_path = "", "", pretty
        key = (host, share, file_path)
        record = grouped.get(key)
        if record is None:
            record = {"host": host, "share": share, "file": file_path, "terms": {}}
            grouped[key] = record
            order.append(key)
        terms = record["terms"]
        terms[pattern] = max(terms.get(pattern, 0), count)
    results: list[dict] = []
    for key in order:
        record = grouped[key]
        results.append(
            {
                "host": record["host"],
                "share": record["share"],
                "file": record["file"],
                "matched_terms": sorted(record["terms"].keys()),
                "match_counts": dict(record["terms"]),
                "total": sum(record["terms"].values()),
            }
        )
    return results


def _manspider_metadata(raw_output: str, artifact: ToolArtifact | None = None) -> dict:
    matches = _parse_manspider_matches(raw_output)
    metadata: dict = {
        "protocol": "smb",
        "collection_type": "share_content_search",
        "matched_file_count": len(matches),
        "match_count": sum(item["total"] for item in matches),
    }
    if matches:
        metadata["sensitivity"] = "sensitive_file"
    return metadata


_NUCLEI_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def _nuclei_severity(info: dict[str, Any]) -> str:
    value = info.get("severity")
    if isinstance(value, str) and value.strip().lower() in _NUCLEI_SEVERITIES:
        return value.strip().lower()
    return "info"


def _nuclei_jsonl_metadata(
    raw_output: str, artifact: ToolArtifact | None = None
) -> dict:
    metadata: dict = {
        "protocol": "vuln-scan",
        "collection_type": "vulnerability_scan",
    }
    if artifact is not None:
        metadata["artifact_filename"] = artifact.filename
    finding_count = 0
    severity_counts: dict[str, int] = {}
    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        finding_count += 1
        info = record.get("info")
        severity = _nuclei_severity(info if isinstance(info, dict) else {})
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    metadata["finding_count"] = finding_count
    metadata["severity_counts"] = severity_counts
    return metadata


# High-signal path markers: a discovered path matching one of these is likely a
# management surface, secret, or source/backup leak, so it is prioritised to
# medium severity ahead of the plain 401/403 -> low / else -> info baseline.
# These drive severity ONLY (a priority hint); ffuf findings are recon and are
# never masked (sensitivity stays None), so over-flagging is harmless.
_FFUF_SENSITIVE_KEYWORDS = (
    "admin",
    "manage",
    "console",
    "actuator",
    "phpmyadmin",
    "wp-admin",
    "swagger",
    "api",
    ".git",
    ".svn",
    ".env",
    ".htpasswd",
    ".htaccess",
    "web.config",
    ".ssh",
    "id_rsa",
    "id_dsa",
    ".key",
    ".pem",
    "backup",
    ".bak",
    ".old",
    ".sql",
    "dump",
    "config",
    "secret",
    "credential",
    "password",
    "token",
    "private",
    "phpinfo",
    "server-status",
    "shell",
)


def _ffuf_severity(word: str, url: str, status: int | None) -> str:
    haystack = f"{word} {url}".lower()
    if any(keyword in haystack for keyword in _FFUF_SENSITIVE_KEYWORDS):
        return "medium"
    if status in (401, 403):
        return "low"
    return "info"


def _ffuf_fuzz_word(entry: dict[str, Any]) -> str:
    # ffuf's -of json writer serialises input via JsonResult.Input
    # (map[string]string), so input.FUZZ is PLAINTEXT -- NOT base64 (that is the
    # internal Result/-of ejson path). Read it verbatim; the always-plaintext
    # url field is the authoritative record of what was discovered.
    inp = entry.get("input")
    if isinstance(inp, dict):
        value = inp.get("FUZZ")
        if isinstance(value, str):
            return value
    return ""


def _ffuf_json_metadata(raw_output: str, artifact: ToolArtifact | None = None) -> dict:
    metadata: dict = {
        "protocol": "web-content",
        "collection_type": "web_content_discovery",
    }
    if artifact is not None:
        metadata["artifact_filename"] = artifact.filename
    finding_count = 0
    status_counts: dict[str, int] = {}
    text = raw_output.strip() if isinstance(raw_output, str) else ""
    if text:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        results = data.get("results") if isinstance(data, dict) else None
        if isinstance(results, list):
            for entry in results:
                if not isinstance(entry, dict):
                    continue
                finding_count += 1
                status = entry.get("status")
                key = str(status) if isinstance(status, int) else "unknown"
                status_counts[key] = status_counts.get(key, 0) + 1
    metadata["finding_count"] = finding_count
    metadata["status_counts"] = status_counts
    return metadata


PARSERS = {
    "netexec_smb_text": _netexec_smb_metadata,
    "netexec_ldap_text": _netexec_ldap_metadata,
    "netexec_winrm_text": _netexec_winrm_metadata,
    "netexec_mssql_text": _netexec_mssql_metadata,
    "bloodhound_json": _bloodhound_json_metadata,
    "certipy_json": _certipy_json_metadata,
    "enum4linux_json": _enum4linux_json_metadata,
    "kerbrute_text": _kerbrute_text_metadata,
    "ldapdomaindump_json": _ldapdomaindump_json_metadata,
    "responder_hashes_text": _responder_hash_metadata,
    "coercer_text": _coercer_text_metadata,
    "impacket_kerberoast_text": _impacket_kerberoast_metadata,
    "impacket_secretsdump_text": _impacket_secretsdump_metadata,
    "impacket_text": _impacket_secretsdump_metadata,
    "nmap_xml": _nmap_xml_metadata,
    "hashcat_cracked": _hashcat_metadata,
    "manspider": _manspider_metadata,
    "nuclei_jsonl": _nuclei_jsonl_metadata,
    "ffuf_json": _ffuf_json_metadata,
}

ESC_PATTERN = re.compile(r"ESC\d+", re.IGNORECASE)
CERTIPY_SECTIONS = {
    "Certificate Authorities": "certificate_authority",
    "Certificate Templates": "certificate_template",
    "Issuance Policies": "issuance_policy",
}


def _certipy_entity_name(entity_type: str, entity: dict[str, Any]) -> str:
    name_keys = {
        "certificate_authority": ("CA Name", "name", "Name"),
        "certificate_template": ("Template Name", "cn", "name", "Name"),
        "issuance_policy": ("Issuance Policy Name", "cn", "name", "Name"),
    }
    for key in name_keys[entity_type]:
        value = entity.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return "unnamed"


def _certipy_json_findings(
    *,
    job_id: int,
    tool_name: str,
    target: str,
    raw_output: str,
    return_code: int,
    artifact: ToolArtifact | None,
) -> list[dict]:
    try:
        document = json.loads(raw_output)
    except json.JSONDecodeError:
        return [
            normalize_tool_output(
                job_id=job_id,
                tool_name=tool_name,
                target=target,
                raw_output=raw_output,
                return_code=return_code,
                output_parser="certipy_json",
                artifact=artifact,
            )
        ]

    if not isinstance(document, dict):
        return [
            normalize_tool_output(
                job_id=job_id,
                tool_name=tool_name,
                target=target,
                raw_output=raw_output,
                return_code=return_code,
                output_parser="certipy_json",
                artifact=artifact,
            )
        ]

    findings: list[dict] = []
    report_metadata = _certipy_json_metadata(raw_output, artifact)
    for section_name, entity_type in CERTIPY_SECTIONS.items():
        section = document.get(section_name)
        if not isinstance(section, dict):
            continue
        for entity in section.values():
            if not isinstance(entity, dict):
                continue
            vulnerabilities = entity.get("[!] Vulnerabilities")
            if not isinstance(vulnerabilities, dict):
                continue
            entity_name = _certipy_entity_name(entity_type, entity)
            for vulnerability_key, description in vulnerabilities.items():
                match = ESC_PATTERN.fullmatch(str(vulnerability_key))
                if match is None:
                    continue
                vulnerability_type = match.group(0).upper()
                description_text = str(description)
                metadata = {
                    **report_metadata,
                    "entity_type": entity_type,
                    "entity_name": entity_name,
                    "section": section_name,
                    "vulnerability_description": description_text,
                    "entity": entity,
                }
                findings.append(
                    {
                        "job_id": job_id,
                        "tool_name": tool_name,
                        "target": target,
                        "title": f"{tool_name} {vulnerability_type} {entity_name} for {target}",
                        "severity": "high" if return_code == 0 else "error",
                        "summary": f"{vulnerability_type} on {entity_type.replace('_', ' ')} {entity_name}: {description_text}",
                        "raw_output": raw_output,
                        "vulnerability_type": vulnerability_type,
                        "sensitivity": None,
                        "metadata_json": {
                            "return_code": return_code,
                            **metadata,
                        },
                        "created_at": datetime.now(UTC),
                    }
                )

    if findings:
        return findings

    metadata = {
        **report_metadata,
        "no_vulnerabilities": True,
    }
    return [
        {
            "job_id": job_id,
            "tool_name": tool_name,
            "target": target,
            "title": f"{tool_name} AD CS report for {target}",
            "severity": "info" if return_code == 0 else "error",
            "summary": "Certipy found no ESC vulnerabilities"
            if return_code == 0
            else "Certipy returned an error",
            "raw_output": raw_output,
            "vulnerability_type": None,
            "sensitivity": None,
            "metadata_json": {
                "return_code": return_code,
                **metadata,
            },
            "created_at": datetime.now(UTC),
        }
    ]


def _nuclei_jsonl_findings(
    *,
    job_id: int,
    tool_name: str,
    target: str,
    raw_output: str,
    return_code: int,
    artifact: ToolArtifact | None,
) -> list[dict]:
    findings: list[dict] = []
    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue

        info = record.get("info")
        info = info if isinstance(info, dict) else {}
        severity = _nuclei_severity(info)

        template_id = str(record.get("template-id") or record.get("template") or "")
        name = str(info.get("name") or template_id or "nuclei finding")
        matched_at = str(
            record.get("matched-at")
            or record.get("matched")
            or record.get("host")
            or target
        )

        classification = info.get("classification")
        classification = classification if isinstance(classification, dict) else {}
        cve_raw = classification.get("cve-id")
        if isinstance(cve_raw, str):
            cve = [cve_raw]
        elif isinstance(cve_raw, list):
            cve = [str(item) for item in cve_raw if item]
        else:
            cve = []
        cvss_score = classification.get("cvss-score")

        tags_raw = info.get("tags")
        if isinstance(tags_raw, str):
            tags = [item.strip() for item in tags_raw.split(",") if item.strip()]
        elif isinstance(tags_raw, list):
            tags = [str(item) for item in tags_raw]
        else:
            tags = []

        title = f"{name} on {matched_at}"[:255]
        summary = f"{severity} severity: {name} matched at {matched_at}"
        if cve:
            summary = f"{summary} [{', '.join(cve)}]"

        findings.append(
            {
                "job_id": job_id,
                "tool_name": tool_name,
                "target": target,
                "title": title,
                "severity": severity,
                "summary": summary,
                "raw_output": stripped,
                "vulnerability_type": "NUCLEI_FINDING",
                "sensitivity": None,
                "metadata_json": {
                    "return_code": return_code,
                    "template_id": template_id,
                    "matched_at": matched_at,
                    "type": record.get("type"),
                    "host": record.get("host"),
                    "ip": record.get("ip"),
                    "tags": tags,
                    "cve": cve,
                    "cvss_score": cvss_score,
                    "severity": severity,
                },
                "created_at": datetime.now(UTC),
            }
        )

    if findings:
        return findings

    fallback_metadata: dict = {
        "return_code": return_code,
        "protocol": "vuln-scan",
        "collection_type": "vulnerability_scan",
        "finding_count": 0,
    }
    if artifact is not None:
        fallback_metadata["artifact_filename"] = artifact.filename
    return [
        {
            "job_id": job_id,
            "tool_name": tool_name,
            "target": target,
            "title": f"{tool_name} vulnerability scan for {target}",
            "severity": "info" if return_code == 0 else "error",
            "summary": "nuclei found no matches"
            if return_code == 0
            else "nuclei returned an error",
            "raw_output": raw_output,
            "vulnerability_type": None,
            "sensitivity": None,
            "metadata_json": fallback_metadata,
            "created_at": datetime.now(UTC),
        }
    ]


def _ffuf_int(value: Any) -> int | None:
    # JSON has no int/bool distinction issue, but bool is an int subclass in
    # Python; exclude it so a stray true/false never lands in a numeric field.
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _ffuf_json_findings(
    *,
    job_id: int,
    tool_name: str,
    target: str,
    raw_output: str,
    return_code: int,
    artifact: ToolArtifact | None,
) -> list[dict]:
    # ffuf's -of json export is a SINGLE JSON object
    # {commandline, config, results:[...], time} -- NOT line-delimited like
    # nuclei's JSONL. Parse it once and emit one WEB_CONTENT finding per
    # discovered path.
    findings: list[dict] = []
    results: list[dict] = []
    parse_error = False
    text = raw_output.strip() if isinstance(raw_output, str) else ""
    if text:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            parse_error = True
            data = None
        if isinstance(data, dict):
            raw_results = data.get("results")
            if isinstance(raw_results, list):
                results = [entry for entry in raw_results if isinstance(entry, dict)]

    for entry in results:
        word = _ffuf_fuzz_word(entry)
        url = str(entry.get("url") or "")
        status = _ffuf_int(entry.get("status"))
        length = _ffuf_int(entry.get("length"))
        words = _ffuf_int(entry.get("words"))
        lines = _ffuf_int(entry.get("lines"))
        position = _ffuf_int(entry.get("position"))
        content_type = str(entry.get("content-type") or "") or None
        redirect = str(entry.get("redirectlocation") or "") or None
        host = str(entry.get("host") or "") or None
        duration_raw = entry.get("duration")
        # ffuf serialises Go time.Duration as an int64 NANOSECOND count.
        duration_ms = (
            round(duration_raw / 1e6, 3)
            if isinstance(duration_raw, (int, float))
            and not isinstance(duration_raw, bool)
            else None
        )

        severity = _ffuf_severity(word, url, status)
        display = url or word or target
        title = (f"{display} [{status}]" if status is not None else display)[:255]
        summary = f"{severity} severity: discovered {display}"
        if status is not None:
            summary = f"{summary} (HTTP {status})"
        if length is not None:
            summary = f"{summary}, {length} bytes"

        findings.append(
            {
                "job_id": job_id,
                "tool_name": tool_name,
                "target": target,
                "title": title,
                "severity": severity,
                "summary": summary,
                "raw_output": json.dumps(entry),
                "vulnerability_type": "WEB_CONTENT",
                "sensitivity": None,
                "metadata_json": {
                    "return_code": return_code,
                    "word": word,
                    "url": url,
                    "status": status,
                    "length": length,
                    "words": words,
                    "lines": lines,
                    "content_type": content_type,
                    "redirect_location": redirect,
                    "host": host,
                    "position": position,
                    "duration_ms": duration_ms,
                    "severity": severity,
                },
                "created_at": datetime.now(UTC),
            }
        )

    if findings:
        return findings

    fallback_metadata: dict = {
        "return_code": return_code,
        "protocol": "web-content",
        "collection_type": "web_content_discovery",
        "finding_count": 0,
    }
    if artifact is not None:
        fallback_metadata["artifact_filename"] = artifact.filename

    # rc != 0 or malformed JSON is a failure; a clean run that simply found no
    # content is a SUCCESS (single info finding), mirroring nuclei's divergence
    # from nmap's "no report => failure" rule.
    is_error = parse_error or return_code != 0
    return [
        {
            "job_id": job_id,
            "tool_name": tool_name,
            "target": target,
            "title": f"{tool_name} web content discovery for {target}",
            "severity": "error" if is_error else "info",
            "summary": (
                "ffuf returned an error" if is_error else "ffuf discovered no content"
            ),
            "raw_output": raw_output,
            "vulnerability_type": None,
            "sensitivity": None,
            "metadata_json": fallback_metadata,
            "created_at": datetime.now(UTC),
        }
    ]


def normalize_tool_output(
    *,
    job_id: int,
    tool_name: str,
    target: str,
    raw_output: str,
    return_code: int,
    output_parser: str,
    artifact: ToolArtifact | None = None,
    vulnerability_type: str | None = None,
    sensitivity: str | None = None,
) -> dict:
    try:
        parser = PARSERS[output_parser]
    except KeyError as exc:
        raise RegistryError(f"Unknown output parser: {output_parser}") from exc
    clean_output = ANSI_ESCAPE.sub("", raw_output).strip()
    parser_metadata = (
        _responder_metadata(raw_output, artifact)
        if output_parser == "responder_hashes_text"
        else parser(raw_output, artifact)
    )
    sensitivity = sensitivity or parser_metadata.get("sensitivity")
    collection_type = parser_metadata.get("collection_type")
    if output_parser == "certipy_json":
        title = f"{tool_name} AD CS report for {target}"
        vulnerability_count = parser_metadata.get("vulnerability_count", 0)
        summary = f"Certipy AD CS report: {vulnerability_count} vulnerabilities"
    elif output_parser == "nuclei_jsonl":
        title = f"{tool_name} vulnerability scan for {target}"
        finding_count = parser_metadata.get("finding_count", 0)
        summary = (
            f"nuclei reported {finding_count} match(es)"
            if finding_count
            else "nuclei found no matches"
        )
    elif output_parser == "impacket_kerberoast_text":
        title = f"{tool_name} Kerberos ticket collection for {target}"
        hash_count = parser_metadata.get("hash_count", 0)
        summary = (
            f"Captured {hash_count} crackable Kerberos service-ticket hash(es)"
            if hash_count
            else "No crackable Kerberos service-ticket hashes were captured"
        )
    elif output_parser == "impacket_secretsdump_text":
        title = f"{tool_name} credential extraction for {target}"
        credential_count = parser_metadata.get("credential_count", 0)
        summary = (
            f"Captured {credential_count} credential record(s)"
            if credential_count
            else "No credential records were parsed from secretsdump output"
        )
    elif output_parser == "hashcat_cracked":
        title = f"{tool_name} offline hash crack for {target}"
        cracked_count = parser_metadata.get("cracked_count", 0)
        summary = (
            f"hashcat recovered {cracked_count} plaintext credential(s)"
            if cracked_count
            else "hashcat run completed without recovering any plaintext"
        )
    elif output_parser == "enum4linux_json":
        title = f"{tool_name} SMB/RPC enumeration for {target}"
        record_count = parser_metadata.get("record_count", 0)
        summary = f"enum4linux-ng report: {record_count} structured record(s)"
    elif output_parser == "kerbrute_text":
        title = f"{tool_name} Kerberos validation for {target}"
        valid_usernames = parser_metadata.get("valid_username_count", 0)
        valid_logins = parser_metadata.get("valid_login_count", 0)
        summary = (
            f"Kerbrute identified {valid_usernames} valid username(s) and "
            f"{valid_logins} successful authentication(s)"
        )
    elif output_parser == "ldapdomaindump_json":
        title = f"{tool_name} {collection_type} collection for {target}"
        record_count = parser_metadata.get("record_count", 0)
        summary = f"LDAPDomainDump {collection_type}: {record_count} record(s)"
    elif output_parser == "responder_hashes_text":
        title = f"{tool_name} credential listener result for {target}"
        capture_count = parser_metadata.get("capture_count", 0)
        summary = (
            f"Responder captured {capture_count} credential hash(es)"
            if capture_count
            else "Responder listener stopped without a parsed credential hash"
        )
    elif output_parser == "coercer_text":
        title = f"{tool_name} authentication coercion for {target}"
        summary = (
            "Coercer reported an authentication response"
            if parser_metadata.get("authentication_received")
            else "Coercer completed without a parsed authentication response"
        )
    elif output_parser == "nmap_xml":
        hosts_up = parser_metadata.get("hosts_up", 0)
        open_port_count = parser_metadata.get("open_port_count", 0)
        title = f"{tool_name} host and service discovery for {target}"
        summary = (
            f"nmap found {hosts_up} host(s) up with {open_port_count} open port(s)"
        )
    elif output_parser == "manspider":
        matched_file_count = parser_metadata.get("matched_file_count", 0)
        title = f"{tool_name} SMB share content search for {target}"
        # Content-free by design: only the count of flagged files, never any
        # matched value, appears in the summary.
        summary = (
            f"MANSPIDER flagged {matched_file_count} file(s) against the curated "
            "secret ruleset; matched content withheld"
            if matched_file_count
            else "MANSPIDER found no files matching the curated secret ruleset"
        )
    elif output_parser in {
        "netexec_smb_text",
        "netexec_ldap_text",
        "netexec_winrm_text",
        "netexec_mssql_text",
    }:
        protocol = parser_metadata.get("protocol", "NetExec")
        host = parser_metadata.get("host") or target
        if parser_metadata.get("admin"):
            access = "administrative access (Pwn3d)"
        elif parser_metadata.get("credential_valid"):
            access = "valid credentials, non-administrative"
        else:
            access = "no validated access"
        title = f"{tool_name} {protocol} credential validation for {target}"
        summary = f"NetExec {protocol} on {host}: {access}"
        if parser_metadata.get("shares"):
            writable = parser_metadata.get("writable_shares") or []
            summary += f"; {len(parser_metadata['shares'])} share(s) enumerated" + (
                f", {len(writable)} writable" if writable else ""
            )
    elif collection_type:
        title = f"{tool_name} {collection_type} collection for {target}"
        if "record_count" in parser_metadata:
            summary = f"BloodHound {collection_type} collection: {parser_metadata['record_count']} records"
        else:
            summary = clean_output[:500] or "Tool returned no output"
    else:
        title = f"{tool_name} result for {target}"
        summary = clean_output[:500] or "Tool returned no output"
    severity = (
        "info" if return_code == 0 and "parse_error" not in parser_metadata else "error"
    )
    return {
        "job_id": job_id,
        "tool_name": tool_name,
        "target": target,
        "title": title,
        "severity": severity,
        "summary": summary,
        "raw_output": raw_output,
        "vulnerability_type": vulnerability_type,
        "sensitivity": sensitivity,
        "metadata_json": {"return_code": return_code, **parser_metadata},
        "created_at": datetime.now(UTC),
    }


def _impacket_kerberoast_findings(
    *,
    job_id: int,
    tool_name: str,
    target: str,
    raw_output: str,
    return_code: int,
    artifact: ToolArtifact | None,
) -> list[dict]:
    hashes = _kerberoast_hashes(raw_output)
    if not hashes:
        return [
            normalize_tool_output(
                job_id=job_id,
                tool_name=tool_name,
                target=target,
                raw_output=raw_output,
                return_code=return_code,
                output_parser="impacket_kerberoast_text",
                artifact=artifact,
            )
        ]

    findings: list[dict] = []
    metadata = _kerberoast_hash_metadata(raw_output, artifact)
    for index, hash_value in enumerate(hashes, start=1):
        hash_match = re.match(r"\$krb5tgs\$(\d+)\$", hash_value, flags=re.IGNORECASE)
        etype = int(hash_match.group(1)) if hash_match else None
        hashcat_mode = KERBEROAST_MODES.get(etype) if etype is not None else None
        finding_metadata = {
            "return_code": return_code,
            **metadata,
            **_kerberoast_identity(hash_value),
            "hash_index": index,
            "encryption_type": etype,
        }
        if hashcat_mode is not None:
            finding_metadata["hashcat_mode"] = hashcat_mode
        findings.append(
            {
                "job_id": job_id,
                "tool_name": tool_name,
                "target": target,
                "title": f"{tool_name} crackable Kerberos hash {index} for {target}",
                "severity": "medium" if return_code == 0 else "error",
                "summary": "Crackable Kerberos service-ticket hash captured in hashcat format",
                "raw_output": hash_value,
                "vulnerability_type": "KERBEROAST",
                "sensitivity": "credential",
                "metadata_json": finding_metadata,
                "created_at": datetime.now(UTC),
            }
        )
    return findings


def _impacket_secretsdump_findings(
    *,
    job_id: int,
    tool_name: str,
    target: str,
    raw_output: str,
    return_code: int,
    artifact: ToolArtifact | None,
) -> list[dict]:
    clean_output = ANSI_ESCAPE.sub("", raw_output)
    lines = [line.strip() for line in clean_output.splitlines() if line.strip()]
    credential_lines = [
        (line, credential_type)
        for line in lines
        if (credential_type := _secretsdump_credential_type(line, artifact)) is not None
    ]
    if not credential_lines:
        return [
            normalize_tool_output(
                job_id=job_id,
                tool_name=tool_name,
                target=target,
                raw_output=raw_output,
                return_code=return_code,
                output_parser="impacket_secretsdump_text",
                artifact=artifact,
            )
        ]

    findings: list[dict] = []
    base_metadata = _impacket_secretsdump_metadata(raw_output, artifact)
    for index, (line, credential_type) in enumerate(credential_lines, start=1):
        finding_metadata = {
            "return_code": return_code,
            **base_metadata,
            "credential_type": credential_type,
            "credential_index": index,
        }
        hashcat_mode = SECRETSDUMP_HASHCAT_MODES.get(credential_type)
        if hashcat_mode is not None:
            crackable_hash = _secretsdump_crackable_hash(line, credential_type)
            if crackable_hash is not None:
                # hashcat_mode is planner-visible (allowlisted) so an autonomous
                # crack can be proposed; crackable_hash itself stays withheld.
                finding_metadata["hashcat_mode"] = hashcat_mode
                finding_metadata["crackable_hash"] = crackable_hash
        findings.append(
            {
                "job_id": job_id,
                "tool_name": tool_name,
                "target": target,
                "title": f"{tool_name} {credential_type.replace('_', ' ')} {index} for {target}",
                "severity": "high" if return_code == 0 else "error",
                "summary": f"Extracted {credential_type.replace('_', ' ')}; explicit reveal handling is required",
                "raw_output": line,
                "vulnerability_type": None,
                "sensitivity": "credential",
                "metadata_json": finding_metadata,
                "created_at": datetime.now(UTC),
            }
        )
    return findings


def _responder_hash_findings(
    *,
    job_id: int,
    tool_name: str,
    target: str,
    raw_output: str,
    return_code: int,
    artifact: ToolArtifact | None,
) -> list[dict]:
    clean_output = ANSI_ESCAPE.sub("", raw_output)
    captures = []
    for line in clean_output.splitlines():
        match = _responder_hash_match(line)
        if match is not None:
            captures.append(match)
    if not captures:
        return [
            normalize_tool_output(
                job_id=job_id,
                tool_name=tool_name,
                target=target,
                raw_output=raw_output,
                return_code=return_code,
                output_parser="responder_hashes_text",
                artifact=artifact,
            )
        ]
    base_metadata = _responder_hash_metadata(raw_output, artifact)
    findings: list[dict] = []
    for index, (hash_value, hash_format, hashcat_mode) in enumerate(captures, start=1):
        findings.append(
            {
                "job_id": job_id,
                "tool_name": tool_name,
                "target": target,
                "title": f"{tool_name} captured {hash_format} credential {index} for {target}",
                "severity": "high" if return_code == 0 else "error",
                "summary": (
                    f"Responder captured {hash_format} material; use hashcat mode "
                    f"{hashcat_mode} or an equivalent offline verifier"
                ),
                "raw_output": hash_value,
                "vulnerability_type": "RESPONDER_CAPTURE",
                "sensitivity": "credential",
                "metadata_json": {
                    "return_code": return_code,
                    **base_metadata,
                    "hash_format": hash_format,
                    "hashcat_mode": hashcat_mode,
                    "capture_index": index,
                },
                "created_at": datetime.now(UTC),
            }
        )
    return findings


def _hashcat_findings(
    *,
    job_id: int,
    tool_name: str,
    target: str,
    raw_output: str,
    return_code: int,
    artifact: ToolArtifact | None,
) -> list[dict]:
    # raw_output here is the outfile contents (one recovered plaintext per line)
    # on the artifact path. An empty outfile means the run completed without a
    # crack (exhausted / runtime cap): emit a single info finding, not an error.
    cracked_lines = [line for line in raw_output.splitlines() if line.strip()]
    if not cracked_lines:
        return [
            normalize_tool_output(
                job_id=job_id,
                tool_name=tool_name,
                target=target,
                raw_output=raw_output,
                return_code=return_code,
                output_parser="hashcat_cracked",
                artifact=artifact,
            )
        ]
    base_metadata = _hashcat_metadata(raw_output, artifact)
    mode = base_metadata.get("hashcat_mode")
    findings: list[dict] = []
    for index, plaintext in enumerate(cracked_lines, start=1):
        finding_metadata = {
            "return_code": return_code,
            **base_metadata,
            "credential_type": "cleartext_password",
            "credential_index": index,
            "cracked": True,
            "source": "hashcat",
        }
        if mode is not None:
            finding_metadata["hashcat_mode"] = mode
        findings.append(
            {
                "job_id": job_id,
                "tool_name": tool_name,
                "target": target,
                # Title/summary carry NO plaintext: _finding_context passes the
                # title through to the planner UNREDACTED. The recovered password
                # lives only in raw_output, which the planner never sees.
                "title": f"{tool_name} recovered credential {index} for {target}",
                "severity": "high" if return_code == 0 else "error",
                "summary": (
                    "hashcat recovered a plaintext credential; "
                    "explicit reveal handling is required"
                ),
                "raw_output": plaintext,
                "vulnerability_type": "CREDENTIAL_CRACKED",
                "sensitivity": "credential",
                "metadata_json": finding_metadata,
                "created_at": datetime.now(UTC),
            }
        )
    return findings


def _manspider_findings(
    *,
    job_id: int,
    tool_name: str,
    target: str,
    raw_output: str,
    return_code: int,
    artifact: ToolArtifact | None = None,
) -> list[dict]:
    matches = _parse_manspider_matches(raw_output)
    if not matches:
        # No file matched the curated ruleset (or the crawl errored before
        # matching): emit a single info/error summary finding, not a sensitive
        # one.
        return [
            normalize_tool_output(
                job_id=job_id,
                tool_name=tool_name,
                target=target,
                raw_output=raw_output,
                return_code=return_code,
                output_parser="manspider",
                artifact=artifact,
            )
        ]
    findings: list[dict] = []
    for item in matches:
        host = item["host"] or target
        share = item["share"]
        file_path = item["file"]
        pointer = f"{share}\\{file_path}" if share else file_path
        matched_terms = item["matched_terms"]
        finding_metadata = {
            "return_code": return_code,
            "protocol": "smb",
            "collection_type": "share_content_match",
            "host": host,
            "share": share,
            "file_path": file_path,
            # Pattern NAMES only (e.g. "password") — safe to surface per policy.
            # The matched VALUE is never captured (-q) or stored anywhere.
            "matched_terms": matched_terms,
            "match_counts": item["match_counts"],
            "sensitivity": "sensitive_file",
        }
        findings.append(
            {
                "job_id": job_id,
                "tool_name": tool_name,
                "target": target,
                # Content-free pointer: no matched value in title, summary, or
                # raw_output. sensitive_file findings are additionally withheld
                # from the planner and masked in the dashboard, but there is no
                # secret value here to leak in the first place.
                "title": f"manspider match: {pointer} on {host}",
                "severity": "medium" if return_code == 0 else "error",
                "summary": (
                    f"MANSPIDER flagged {pointer} on {host} against the curated "
                    "secret ruleset; matched content is withheld — retrieve the "
                    "file manually to verify."
                ),
                "raw_output": (
                    f"manspider match: {pointer} on {host}\n"
                    f"matched terms: {', '.join(matched_terms)}"
                ),
                "vulnerability_type": "SENSITIVE_FILE_EXPOSURE",
                "sensitivity": "sensitive_file",
                "metadata_json": finding_metadata,
                "created_at": datetime.now(UTC),
            }
        )
    return findings


def normalize_tool_result(
    *,
    job_id: int,
    tool_name: str,
    target: str,
    result: ToolResult,
    output_parser: str,
) -> list[dict]:
    if output_parser == "certipy_json":
        if result.artifacts:
            findings: list[dict] = []
            for artifact in sorted(result.artifacts, key=lambda item: item.filename):
                findings.extend(
                    _certipy_json_findings(
                        job_id=job_id,
                        tool_name=tool_name,
                        target=target,
                        raw_output=artifact.content,
                        return_code=result.return_code,
                        artifact=artifact,
                    )
                )
            return findings
        return _certipy_json_findings(
            job_id=job_id,
            tool_name=tool_name,
            target=target,
            raw_output=result.raw_output,
            return_code=result.return_code,
            artifact=None,
        )
    if output_parser in {"impacket_kerberoast_text", "impacket_kerberoast"}:
        if result.artifacts:
            findings: list[dict] = []
            for artifact in sorted(result.artifacts, key=lambda item: item.filename):
                findings.extend(
                    _impacket_kerberoast_findings(
                        job_id=job_id,
                        tool_name=tool_name,
                        target=target,
                        raw_output=artifact.content,
                        return_code=result.return_code,
                        artifact=artifact,
                    )
                )
            credential_findings = [
                finding
                for finding in findings
                if finding["sensitivity"] == "credential"
            ]
            if credential_findings:
                return credential_findings
        return _impacket_kerberoast_findings(
            job_id=job_id,
            tool_name=tool_name,
            target=target,
            raw_output=result.raw_output,
            return_code=result.return_code,
            artifact=None,
        )
    if output_parser in {
        "impacket_secretsdump_text",
        "impacket_secretsdump",
        "impacket_text",
    }:
        if result.artifacts:
            findings = []
            for artifact in sorted(result.artifacts, key=lambda item: item.filename):
                findings.extend(
                    _impacket_secretsdump_findings(
                        job_id=job_id,
                        tool_name=tool_name,
                        target=target,
                        raw_output=artifact.content,
                        return_code=result.return_code,
                        artifact=artifact,
                    )
                )
            credential_findings = [
                finding
                for finding in findings
                if finding["sensitivity"] == "credential"
            ]
            if credential_findings:
                return credential_findings
        return _impacket_secretsdump_findings(
            job_id=job_id,
            tool_name=tool_name,
            target=target,
            raw_output=result.raw_output,
            return_code=result.return_code,
            artifact=None,
        )
    if output_parser == "responder_hashes_text":
        if result.artifacts:
            findings: list[dict] = []
            for artifact in sorted(result.artifacts, key=lambda item: item.filename):
                findings.extend(
                    _responder_hash_findings(
                        job_id=job_id,
                        tool_name=tool_name,
                        target=target,
                        raw_output=artifact.content,
                        return_code=result.return_code,
                        artifact=artifact,
                    )
                )
            credential_findings = [
                finding
                for finding in findings
                if finding["sensitivity"] == "credential"
            ]
            if credential_findings:
                return credential_findings
        return _responder_hash_findings(
            job_id=job_id,
            tool_name=tool_name,
            target=target,
            raw_output=result.raw_output,
            return_code=result.return_code,
            artifact=None,
        )
    if output_parser == "hashcat_cracked":
        # No credential filter here (unlike secretsdump): the wrapper always
        # emits exactly one artifact, and an empty outfile must still yield the
        # info "exhausted" finding rather than being dropped.
        if result.artifacts:
            findings = []
            for artifact in sorted(result.artifacts, key=lambda item: item.filename):
                findings.extend(
                    _hashcat_findings(
                        job_id=job_id,
                        tool_name=tool_name,
                        target=target,
                        raw_output=artifact.content,
                        return_code=result.return_code,
                        artifact=artifact,
                    )
                )
            return findings
        return _hashcat_findings(
            job_id=job_id,
            tool_name=tool_name,
            target=target,
            raw_output=result.raw_output,
            return_code=result.return_code,
            artifact=None,
        )
    if output_parser == "manspider":
        # The wrapper emits no artifacts (pointer-only loot policy); the content
        # match log arrives on result.raw_output. The artifact branch is kept
        # for symmetry in case that ever changes.
        if result.artifacts:
            findings = []
            for artifact in sorted(result.artifacts, key=lambda item: item.filename):
                findings.extend(
                    _manspider_findings(
                        job_id=job_id,
                        tool_name=tool_name,
                        target=target,
                        raw_output=artifact.content,
                        return_code=result.return_code,
                        artifact=artifact,
                    )
                )
            return findings
        return _manspider_findings(
            job_id=job_id,
            tool_name=tool_name,
            target=target,
            raw_output=result.raw_output,
            return_code=result.return_code,
            artifact=None,
        )
    if output_parser == "nuclei_jsonl":
        if result.artifacts:
            findings = []
            for artifact in sorted(result.artifacts, key=lambda item: item.filename):
                findings.extend(
                    _nuclei_jsonl_findings(
                        job_id=job_id,
                        tool_name=tool_name,
                        target=target,
                        raw_output=artifact.content,
                        return_code=result.return_code,
                        artifact=artifact,
                    )
                )
            return findings
        return _nuclei_jsonl_findings(
            job_id=job_id,
            tool_name=tool_name,
            target=target,
            raw_output=result.raw_output,
            return_code=result.return_code,
            artifact=None,
        )
    if output_parser == "ffuf_json":
        if result.artifacts:
            findings = []
            for artifact in sorted(result.artifacts, key=lambda item: item.filename):
                findings.extend(
                    _ffuf_json_findings(
                        job_id=job_id,
                        tool_name=tool_name,
                        target=target,
                        raw_output=artifact.content,
                        return_code=result.return_code,
                        artifact=artifact,
                    )
                )
            return findings
        return _ffuf_json_findings(
            job_id=job_id,
            tool_name=tool_name,
            target=target,
            raw_output=result.raw_output,
            return_code=result.return_code,
            artifact=None,
        )
    if result.artifacts:
        return [
            normalize_tool_output(
                job_id=job_id,
                tool_name=tool_name,
                target=target,
                raw_output=artifact.content,
                return_code=result.return_code,
                output_parser=output_parser,
                artifact=artifact,
            )
            for artifact in sorted(result.artifacts, key=lambda item: item.filename)
        ]
    return [
        normalize_tool_output(
            job_id=job_id,
            tool_name=tool_name,
            target=target,
            raw_output=result.raw_output,
            return_code=result.return_code,
            output_parser=output_parser,
        )
    ]
