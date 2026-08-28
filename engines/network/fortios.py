"""Narrow, fail-closed parser for FortiOS configuration output."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class FortiOSBlock:
    line: int
    path: tuple[str, ...]


@dataclass(frozen=True)
class FortiOSEntry:
    line: int
    path: tuple[str, ...]
    name: str


@dataclass(frozen=True)
class FortiOSStatement:
    line: int
    path: tuple[str, ...]
    entry: str | None
    entry_line: int | None
    text: str


@dataclass(frozen=True)
class FortiOSDocument:
    blocks: tuple[FortiOSBlock, ...]
    entries: tuple[FortiOSEntry, ...]
    statements: tuple[FortiOSStatement, ...]


@dataclass(frozen=True)
class _Frame:
    kind: str
    name: str
    line: int


def _config_path(frames: list[_Frame]) -> tuple[str, ...]:
    return tuple(frame.name for frame in frames if frame.kind == "config")


def _current_entry(frames: list[_Frame]) -> _Frame | None:
    for frame in reversed(frames):
        if frame.kind == "edit":
            return frame
    return None


def _entry_name(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def parse_config(text: str) -> FortiOSDocument:
    """Parse the structural subset needed by the verified FortiGate rules.

    Arbitrary configuration statements are retained as opaque text. Only the
    `config`, `edit`, `next`, and `end` structure is interpreted.
    """
    frames: list[_Frame] = []
    blocks: list[FortiOSBlock] = []
    entries: list[FortiOSEntry] = []
    statements: list[FortiOSStatement] = []
    saw_config = False

    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not frames and re.fullmatch(r".+\s[$#]\s+show(?:\s+full-configuration)?", line, re.IGNORECASE):
            continue
        if line.casefold().startswith("config "):
            name = line[7:].strip()
            if not name:
                raise ValueError(f"empty config header at line {number}")
            path = _config_path(frames) + (name,)
            frames.append(_Frame("config", name, number))
            blocks.append(FortiOSBlock(number, path))
            saw_config = True
            continue
        if line.casefold().startswith("edit "):
            if not frames or frames[-1].kind != "config":
                raise ValueError(f"edit outside config block at line {number}")
            name = _entry_name(line[5:])
            if not name:
                raise ValueError(f"empty edit name at line {number}")
            entries.append(FortiOSEntry(number, _config_path(frames), name))
            frames.append(_Frame("edit", name, number))
            continue
        if line.casefold() == "next":
            if not frames or frames[-1].kind != "edit":
                raise ValueError(f"next outside edit block at line {number}")
            frames.pop()
            continue
        if line.casefold() == "end":
            while frames and frames[-1].kind == "edit":
                frames.pop()
            if not frames or frames[-1].kind != "config":
                raise ValueError(f"end outside config block at line {number}")
            frames.pop()
            continue
        if not frames:
            raise ValueError(f"unsupported top-level FortiOS output at line {number}: {line}")
        entry = _current_entry(frames)
        statements.append(FortiOSStatement(
            number,
            _config_path(frames),
            entry.name if entry else None,
            entry.line if entry else None,
            line,
        ))

    if frames:
        open_frame = frames[-1]
        raise ValueError(f"unclosed FortiOS {open_frame.kind} block {open_frame.name!r}")
    if not saw_config:
        raise ValueError("no FortiOS config blocks found")
    return FortiOSDocument(tuple(blocks), tuple(entries), tuple(statements))


def matching_paths(document: FortiOSDocument, path_pattern: str) -> set[tuple[str, ...]]:
    path_re = re.compile(path_pattern, re.IGNORECASE)
    return {
        block.path
        for block in document.blocks
        if path_re.fullmatch("/".join(block.path))
    }
