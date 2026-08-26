"""Small, fail-closed parser for Junos brace configuration excerpts."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class JunosStatement:
    line: int
    path: tuple[str, ...]
    text: str
    kind: str


def _strip_comments(line: str) -> str:
    line = re.sub(r"/\*.*?\*/", "", line)
    line = re.sub(r"//.*$", "", line)
    line = re.sub(r"##.*$", "", line)
    return line.strip()


def parse_config(text: str) -> tuple[JunosStatement, ...]:
    """Parse common multiline Junos hierarchy without pretending to be a grammar.

    The parser tracks brace-delimited contexts and semicolon-terminated leaf
    statements. It intentionally rejects unbalanced braces so an incomplete
    saved configuration cannot silently produce a compliant result.
    """
    stack: list[str] = []
    statements: list[JunosStatement] = []
    balance = 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = _strip_comments(raw)
        if not line:
            continue
        # The source-derived corpus uses one structural token per line. Keep
        # quoted values intact and avoid interpreting braces inside quotes.
        if line == "}":
            if not stack:
                raise ValueError(f"unmatched closing brace at line {number}")
            stack.pop()
            balance -= 1
            continue
        if line.endswith("{"):
            header = line[:-1].strip()
            if not header:
                raise ValueError(f"empty block header at line {number}")
            statements.append(JunosStatement(number, tuple(stack), header, "block"))
            stack.append(header)
            balance += 1
            continue
        if line.endswith(";"):
            statements.append(JunosStatement(number, tuple(stack), line, "leaf"))
            continue
        raise ValueError(f"unsupported or incomplete Junos syntax at line {number}: {line}")
    if balance != 0 or stack:
        raise ValueError("unbalanced Junos braces")
    return tuple(statements)


def statement_matches(
    statements: Iterable[JunosStatement],
    path_pattern: str,
    statement_pattern: str,
) -> list[JunosStatement]:
    path_re = re.compile(path_pattern, re.IGNORECASE)
    statement_re = re.compile(statement_pattern, re.IGNORECASE)
    return [
        statement
        for statement in statements
        if path_re.fullmatch("/".join(statement.path))
        and statement_re.fullmatch(statement.text)
    ]
