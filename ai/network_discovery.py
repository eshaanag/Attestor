#!/usr/bin/env python3
"""Measure and classify Cisco config syntax not covered by deterministic rules.

F' deliberately keeps discovery separate from compliance. The existing network
engine runs first and remains authoritative. This module only sees active lines
that no production ``config_grep`` rule matched. Any future provider call is
opt-in, redacted, cached, and capped; the default mode never calls a provider.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = REPO_ROOT / "tests" / "fixtures" / "network" / "cisco_ios"
DEFAULT_RULES = REPO_ROOT / "rules" / "cisco_ios"
DEFAULT_STATE = REPO_ROOT / "ai" / "state"
NORMALIZATION_VERSION = "ios-line-v1"
MODEL_DEFAULT = "claude-3-5-haiku-latest"
ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages"
CATEGORIES = ("authentication", "logging", "access-control", "encryption", "unknown")

# These are syntax delimiters or context headers, not useful security-category
# candidates. They remain in the inventory for auditability, but are excluded
# from the estimated provider call set.
STRUCTURAL_PATTERNS = (
    re.compile(r"^exit$", re.IGNORECASE),
    re.compile(r"^(?:interface|line|router|vlan)\s+", re.IGNORECASE),
    re.compile(r"^ip\s+dhcp\s+pool\s+", re.IGNORECASE),
)


@dataclass(frozen=True)
class Observation:
    filename: str
    line_number: int
    redacted_line: str
    pattern: str
    pattern_hash: str
    structural: bool


class CallBudgetExceeded(RuntimeError):
    """Raised before any provider call when the configured cap is insufficient."""


class ProviderError(RuntimeError):
    """Raised when an explicitly requested provider call cannot be completed."""


def _replace_secret(match: re.Match[str]) -> str:
    return f"{match.group(1)}<REDACTED>"


def redact_line(line: str) -> str:
    """Remove credentials and identifying values before persistence/provider use."""
    value = line.strip()
    value = re.sub(
        r"(?i)(\b(?:secret|password|community|passphrase|key)\s+)(\S+)",
        _replace_secret,
        value,
    )
    value = re.sub(
        r"(?i)(\bsnmp-server\s+host\s+\S+\s+version\s+2c\s+)(\S+)",
        r"\1<REDACTED>",
        value,
    )
    value = re.sub(r"(?i)(\b(?:md5|sha|aes)\s+)(\S+)", _replace_secret, value)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>", value)
    value = re.sub(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b", "<MAC>", value)
    value = re.sub(r"\b[0-9A-Fa-f]{16,}\b", "<HEX>", value)
    value = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "<EMAIL>", value)
    value = re.sub(r"(?i)^(hostname)\s+\S+", r"\1 <HOSTNAME>", value)
    value = re.sub(r"\b(?:GigabitEthernet|FastEthernet|TenGigabitEthernet)\d+(?:/\d+)+\b", "<INTERFACE>", value)
    return re.sub(r"\s+", " ", value)


def pattern_hash(pattern: str) -> str:
    return hashlib.sha256(
        f"{NORMALIZATION_VERSION}\0{pattern}".encode("utf-8")
    ).hexdigest()


def is_structural(pattern: str) -> bool:
    return any(regex.search(pattern) for regex in STRUCTURAL_PATTERNS)


def _production_patterns(rules_dir: Path) -> list[tuple[str, re.Pattern[str]]]:
    patterns: list[tuple[str, re.Pattern[str]]] = []
    for path in sorted(rules_dir.glob("*.yaml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        for check in rule.get("checks", []):
            if check.get("type") != "config_grep":
                continue
            raw = check.get("pattern")
            if not isinstance(raw, str) or not raw:
                continue
            patterns.append((rule["id"], re.compile(raw, re.IGNORECASE)))
    return patterns


def collect_observations(
    corpus_dir: Path = DEFAULT_CORPUS,
    rules_dir: Path = DEFAULT_RULES,
) -> tuple[list[Observation], dict[str, Any]]:
    """Collect every active line not matched by a production deterministic rule."""
    # Import lazily so this package does not alter or initialize the engine at import time.
    from engines.network.run_audit import load_config

    deterministic = _production_patterns(rules_dir)
    observations: list[Observation] = []
    config_count = 0
    active_line_count = 0
    for config_path in sorted(corpus_dir.glob("*.txt")):
        config_count += 1
        config = load_config(config_path)
        active_line_count += len(config.lines)
        for line in config.lines:
            if any(regex.search(line.normalized) for _, regex in deterministic):
                continue
            redacted = redact_line(line.normalized)
            observations.append(
                Observation(
                    filename=config_path.name,
                    line_number=line.number,
                    redacted_line=redacted,
                    pattern=redacted,
                    pattern_hash=pattern_hash(redacted),
                    structural=is_structural(redacted),
                )
            )

    summary = {
        "corpus_status": "reference_configs",
        "config_count": config_count,
        "active_line_count": active_line_count,
        "deterministic_config_grep_pattern_count": len(deterministic),
        "unmatched_occurrence_count": len(observations),
        "unique_unmatched_pattern_count": len({item.pattern_hash for item in observations}),
        "structural_unmatched_occurrence_count": sum(item.structural for item in observations),
        "structural_unique_pattern_count": len(
            {item.pattern_hash for item in observations if item.structural}
        ),
        "candidate_occurrence_count": sum(not item.structural for item in observations),
        "candidate_unique_pattern_count": len(
            {item.pattern_hash for item in observations if not item.structural}
        ),
        "normalization_version": NORMALIZATION_VERSION,
    }
    return observations, summary


def inventory_document(observations: Iterable[Observation], summary: dict[str, Any]) -> dict[str, Any]:
    grouped: dict[str, dict[str, Any]] = {}
    for item in observations:
        entry = grouped.setdefault(
            item.pattern_hash,
            {
                "pattern_hash": item.pattern_hash,
                "pattern": item.pattern,
                "structural": item.structural,
                "occurrence_count": 0,
                "occurrences": [],
            },
        )
        entry["occurrence_count"] += 1
        entry["occurrences"].append(
            {"file": item.filename, "line": item.line_number}
        )
    return {
        "schema_version": "f1",
        "review_method": "Derived from byte-preserved Phase B corpus; values redacted before persistence.",
        "summary": summary,
        "patterns": sorted(grouped.values(), key=lambda value: (-value["occurrence_count"], value["pattern"])),
    }


def estimate_cost(
    unique_candidate_patterns: int,
    input_tokens_per_call: int = 180,
    output_tokens_per_call: int = 96,
    input_usd_per_million: float = 0.80,
    output_usd_per_million: float = 4.00,
) -> dict[str, Any]:
    input_tokens = unique_candidate_patterns * input_tokens_per_call
    output_tokens = unique_candidate_patterns * output_tokens_per_call
    input_cost = input_tokens / 1_000_000 * input_usd_per_million
    output_cost = output_tokens / 1_000_000 * output_usd_per_million
    return {
        "unique_candidate_patterns": unique_candidate_patterns,
        "estimated_calls": unique_candidate_patterns,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "assumed_model": MODEL_DEFAULT,
        "pricing_assumption_usd_per_million": {
            "input": input_usd_per_million,
            "output": output_usd_per_million,
        },
        "estimated_usd": round(input_cost + output_cost, 4),
        "note": "Estimate only; verify current provider pricing before enabling real calls.",
    }


class MappingStore:
    """Separate provider cache from human-confirmed training mappings."""

    def __init__(self, state_dir: Path = DEFAULT_STATE):
        self.state_dir = state_dir
        self.cache_path = state_dir / "classifications.json"
        self.training_path = state_dir / "confirmed_mappings.json"
        self.cache = self._load(self.cache_path)
        self.training = self._load(self.training_path)

    @staticmethod
    def _load(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderError(f"could not load mapping state {path}: {exc}") from exc
        if not isinstance(value, dict):
            raise ProviderError(f"mapping state must be a JSON object: {path}")
        return value

    def _save(self, path: Path, value: dict[str, Any]) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def confirm(self, pattern: str, category: str, note: str = "") -> str:
        if category not in CATEGORIES:
            raise ValueError(f"category must be one of {CATEGORIES}")
        digest = pattern_hash(pattern)
        self.training[digest] = {
            "pattern_hash": digest,
            "pattern": pattern,
            "category": category,
            "note": note,
            "source": "human_confirmed",
            "normalization_version": NORMALIZATION_VERSION,
        }
        self._save(self.training_path, self.training)
        return digest


def dry_run_classification(pattern: str) -> dict[str, Any]:
    return {
        "pattern_hash": pattern_hash(pattern),
        "pattern": pattern,
        "category": "unknown",
        "reasoning": "DRY-RUN: no provider call made; human confirmation required.",
        "mode": "dry-run",
        "provider": "none",
        "source": "dry_run_placeholder",
        "normalization_version": NORMALIZATION_VERSION,
    }


def _provider_classify(pattern: str, api_key: str, model: str) -> dict[str, Any]:
    prompt = (
        "Classify this redacted Cisco IOS configuration line into exactly one "
        "category: authentication, logging, access-control, encryption, or unknown. "
        "Return JSON only with keys category and reasoning. This is discovery metadata, "
        "not a compliance result.\n\nLine: " + pattern
    )
    payload = json.dumps(
        {"model": model, "max_tokens": 96, "temperature": 0, "messages": [{"role": "user", "content": prompt}]}
    ).encode("utf-8")
    request = urllib.request.Request(
        ANTHROPIC_ENDPOINT,
        data=payload,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        raise ProviderError(f"Anthropic request failed: {exc}") from exc
    text = body.get("content", [{}])[0].get("text", "")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProviderError("Anthropic response was not JSON") from exc
    category = parsed.get("category")
    if category not in CATEGORIES:
        raise ProviderError(f"Anthropic returned invalid category: {category!r}")
    return {
        "category": category,
        "reasoning": str(parsed.get("reasoning", "")),
        "mode": "real-api",
        "provider": "anthropic",
        "source": "provider",
        "model": model,
        "normalization_version": NORMALIZATION_VERSION,
    }


def classify_candidates(
    patterns: Iterable[dict[str, Any]],
    store: MappingStore,
    *,
    real_api: bool = False,
    max_calls: int = 0,
    api_key: str | None = None,
    model: str = MODEL_DEFAULT,
) -> list[dict[str, Any]]:
    candidates = [item for item in patterns if not item["structural"]]
    uncached = [
        item for item in candidates
        if item["pattern_hash"] not in store.training and item["pattern_hash"] not in store.cache
    ]
    if real_api:
        if not api_key:
            raise ProviderError("real API mode requires ANTHROPIC_API_KEY")
        if len(uncached) > max_calls:
            raise CallBudgetExceeded(
                f"refusing to call provider: {len(uncached)} uncached patterns exceed max_calls={max_calls}"
            )

    results: list[dict[str, Any]] = []
    calls = 0
    for item in candidates:
        digest = item["pattern_hash"]
        if digest in store.training:
            result = dict(store.training[digest])
            result["mode"] = "human-confirmed"
        elif digest in store.cache:
            result = dict(store.cache[digest])
            result["mode"] = "cache"
        elif not real_api:
            result = dry_run_classification(item["pattern"])
        else:
            result = _provider_classify(item["pattern"], api_key or "", model)
            result["pattern_hash"] = digest
            result["pattern"] = item["pattern"]
            store.cache[digest] = result
            calls += 1
        result["occurrence_count"] = item["occurrence_count"]
        result["occurrences"] = item["occurrences"]
        results.append(result)
    if real_api and calls:
        store._save(store.cache_path, store.cache)
    return results


def _load_inventory(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Attestor F' AI-assisted syntax discovery")
    sub = parser.add_subparsers(dest="command", required=True)

    inventory_parser = sub.add_parser("inventory", help="measure unmatched patterns in a corpus")
    inventory_parser.add_argument("--corpus-dir", type=Path, default=DEFAULT_CORPUS)
    inventory_parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES)
    inventory_parser.add_argument("--json-out", type=Path)

    classify_parser = sub.add_parser("classify", help="classify candidates; dry-run is the default")
    classify_parser.add_argument("--inventory", type=Path, required=True)
    classify_parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    classify_parser.add_argument("--real-api", action="store_true", help="explicitly enable provider calls")
    classify_parser.add_argument("--max-calls", type=int, default=0)
    classify_parser.add_argument("--model", default=os.environ.get("ANTHROPIC_MODEL", MODEL_DEFAULT))
    classify_parser.add_argument("--json-out", type=Path)

    confirm_parser = sub.add_parser("confirm", help="persist a human-confirmed category")
    confirm_parser.add_argument("--pattern", required=True)
    confirm_parser.add_argument("--category", required=True, choices=CATEGORIES)
    confirm_parser.add_argument("--note", default="")
    confirm_parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)

    args = parser.parse_args(argv)
    if args.command == "inventory":
        observations, summary = collect_observations(args.corpus_dir, args.rules_dir)
        document = inventory_document(observations, summary)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(summary, indent=2))
        return 0
    if args.command == "classify":
        inventory = _load_inventory(args.inventory)
        store = MappingStore(args.state_dir)
        try:
            results = classify_candidates(
                inventory["patterns"],
                store,
                real_api=args.real_api,
                max_calls=args.max_calls,
                api_key=os.environ.get("ANTHROPIC_API_KEY"),
                model=args.model,
            )
        except (CallBudgetExceeded, ProviderError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        document = {"mode": "real-api" if args.real_api else "dry-run", "results": results}
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"mode": document["mode"], "candidate_results": len(results)}, indent=2))
        return 0
    digest = MappingStore(args.state_dir).confirm(args.pattern, args.category, args.note)
    print(json.dumps({"pattern_hash": digest, "source": "human_confirmed"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
