"""Vendor-neutral training helpers for unfamiliar network syntax.

This module creates discovery metadata, not compliance results. Configuration
values are redacted before hashing, persistence, or optional provider use.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import ssl
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from ai.network_discovery import (
    ANTHROPIC_ENDPOINT,
    CATEGORIES,
    INPUT_USD_PER_MILLION,
    MODEL_DEFAULT,
    OUTPUT_USD_PER_MILLION,
    ProviderError,
    redact_line,
)


TRAINING_NORMALIZATION_VERSION = "vendor-line-v1"
MAX_KNOWLEDGE_CHARS = 20_000
MAX_PDF_PAGES = 50


def training_pattern_hash(vendor: str, platform: str, pattern: str) -> str:
    identity = f"{TRAINING_NORMALIZATION_VERSION}\0{vendor.casefold()}\0{platform.casefold()}\0{pattern}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _is_comment_or_separator(value: str) -> bool:
    return not value or value == "!" or value.startswith(("#", "//", ";"))


def _is_structural(value: str) -> bool:
    lowered = value.casefold()
    return (
        value in {"{", "}", "[", "]"}
        or value.endswith("{")
        or lowered in {"exit", "end", "configure terminal", "commit", "top", "up"}
        or lowered.startswith(("interface ", "line ", "router ", "vlan ", "edit "))
    )


def collect_training_patterns(
    text: str,
    vendor: str,
    platform: str,
    known_patterns: Iterable[re.Pattern[str]] = (),
) -> list[dict[str, Any]]:
    """Return unique redacted patterns from an uploaded configuration."""
    grouped: dict[str, dict[str, Any]] = {}
    counts: Counter[str] = Counter()
    for line_number, raw in enumerate(text.splitlines(), start=1):
        normalized = re.sub(r"\s+", " ", raw.strip())
        if _is_comment_or_separator(normalized):
            continue
        if any(pattern.search(normalized) for pattern in known_patterns):
            continue
        redacted = redact_line(normalized)
        digest = training_pattern_hash(vendor, platform, redacted)
        counts[digest] += 1
        entry = grouped.setdefault(
            digest,
            {
                "pattern_hash": digest,
                "pattern": redacted,
                "structural": _is_structural(redacted),
                "occurrence_count": 0,
                "occurrences": [],
            },
        )
        if len(entry["occurrences"]) < 20:
            entry["occurrences"].append({"line": line_number})
    for digest, entry in grouped.items():
        entry["occurrence_count"] = counts[digest]
    return sorted(
        grouped.values(),
        key=lambda item: (item["structural"], -item["occurrence_count"], item["pattern"]),
    )


def dry_run_classification(pattern: dict[str, Any]) -> dict[str, Any]:
    return {
        **pattern,
        "category": "unknown",
        "reasoning": "DRY-RUN: no provider call made; human confirmation required.",
        "mode": "dry-run",
        "source": "dry_run_placeholder",
        "confirmed": False,
    }


def provider_classify(
    pattern: dict[str, Any], vendor: str, platform: str, api_key: str, model: str = MODEL_DEFAULT
) -> dict[str, Any]:
    prompt = (
        "Classify this already-redacted network configuration pattern into exactly one "
        "category: authentication, logging, access-control, encryption, or unknown. "
        "Return JSON only with keys category and reasoning. Keep reasoning under 15 words. "
        "This is discovery metadata, not a compliance result.\n\n"
        f"Vendor: {vendor}\nPlatform: {platform}\nPattern: {pattern['pattern']}"
    )
    payload = json.dumps({
        "model": model,
        "max_tokens": 160,
        "temperature": 0,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
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
        try:
            import certifi
            context = ssl.create_default_context(cafile=certifi.where())
        except ImportError:
            context = ssl.create_default_context()
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise ProviderError(f"training provider HTTP {exc.code}: {detail}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderError(f"training provider request failed: {exc}") from exc
    response_text = body.get("content", [{}])[0].get("text", "")
    try:
        parsed = json.loads(response_text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", response_text, re.DOTALL)
        if not match:
            raise ProviderError("training provider response was not JSON")
        parsed = json.loads(match.group(0))
    category = parsed.get("category")
    if category not in CATEGORIES:
        raise ProviderError(f"training provider returned invalid category: {category!r}")
    usage = body.get("usage") or {}
    input_tokens = int(usage.get("input_tokens", 0))
    output_tokens = int(usage.get("output_tokens", 0))
    return {
        **pattern,
        "category": category,
        "reasoning": str(parsed.get("reasoning", "")),
        "mode": "real-api",
        "source": "provider",
        "confirmed": False,
        "model": model,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": round(
                input_tokens / 1_000_000 * INPUT_USD_PER_MILLION
                + output_tokens / 1_000_000 * OUTPUT_USD_PER_MILLION,
                8,
            ),
        },
    }


def classify_patterns(
    patterns: list[dict[str, Any]],
    vendor: str,
    platform: str,
    prior_lookup,
    *,
    real_api: bool = False,
    max_calls: int = 0,
    api_key: str | None = None,
    model: str = MODEL_DEFAULT,
) -> list[dict[str, Any]]:
    uncached = [
        item for item in patterns
        if not item["structural"] and prior_lookup(vendor, platform, item["pattern_hash"]) is None
    ]
    if real_api:
        if not api_key:
            raise ProviderError("real training mode requires ANTHROPIC_API_KEY")
        if len(uncached) > max_calls:
            raise ProviderError(
                f"refusing training calls: {len(uncached)} uncached patterns exceed max_calls={max_calls}"
            )
    results = []
    for item in patterns:
        prior = prior_lookup(vendor, platform, item["pattern_hash"])
        if prior:
            result = {**item, **prior, "mode": "human-confirmed" if prior["confirmed"] else "cache"}
        elif item["structural"]:
            result = {
                **item,
                "category": "unknown",
                "reasoning": "Structural context retained; classification not required.",
                "mode": "structural",
                "source": "structure_filter",
                "confirmed": True,
            }
        elif real_api:
            result = provider_classify(item, vendor, platform, api_key or "", model)
        else:
            result = dry_run_classification(item)
        results.append(result)
    return results


def extract_knowledge_text(filename: str, content: bytes) -> str:
    """Extract and redact a bounded vendor-document excerpt."""
    suffix = Path(filename).suffix.casefold()
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(content))
            raw = "\n".join((page.extract_text() or "") for page in reader.pages[:MAX_PDF_PAGES])
        except Exception as exc:
            raise ValueError(f"could not extract PDF text: {exc}") from exc
    else:
        try:
            raw = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("knowledge source is not valid UTF-8 text or PDF") from exc
    redacted_lines = [redact_line(line) for line in raw.splitlines() if line.strip()]
    return "\n".join(redacted_lines)[:MAX_KNOWLEDGE_CHARS]
