"""Cached, opt-in remediation text for G' PDF reports.

Remediation is advisory output. It never changes control status or deterministic
evidence. The cache key is exactly vendor/platform/rule_id so the same fix is
not regenerated for every device.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ai.network_discovery import (
    ANTHROPIC_ENDPOINT,
    INPUT_USD_PER_MILLION,
    MODEL_DEFAULT,
    OUTPUT_USD_PER_MILLION,
    ProviderError,
)

DEFAULT_STATE = Path(__file__).resolve().parents[1] / "ai" / "state"
CATEGORIES = ("authentication", "logging", "access-control", "encryption", "unknown")


def remediation_key(control: dict[str, Any]) -> str:
    device = control.get("device") or {}
    vendor = device.get("vendor", "unknown")
    platform = device.get("platform", "unknown")
    return f"{vendor}|{platform}|{control['rule_id']}"


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ProviderError(f"remediation state must be a JSON object: {path}")
    return value


class RemediationStore:
    def __init__(self, state_dir: Path = DEFAULT_STATE):
        self.state_dir = state_dir
        self.path = state_dir / "remediations.json"
        self.entries = _load(self.path)

    def save(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.entries, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def get(self, key: str) -> dict[str, Any] | None:
        value = self.entries.get(key)
        return dict(value) if isinstance(value, dict) else None

    def put(self, key: str, value: dict[str, Any]) -> None:
        self.entries[key] = value
        self.save()


def dry_run_remediation(control: dict[str, Any]) -> dict[str, Any]:
    return {
        "cache_key": remediation_key(control),
        "text": "DRY-RUN: no provider call made; operator review required for device-specific CLI remediation.",
        "reasoning": "DRY-RUN: no provider reasoning generated.",
        "mode": "dry-run",
        "provider": "none",
        "source": "dry_run_placeholder",
        "ai_generated": True,
    }


def _redact_remediation_context(control: dict[str, Any]) -> str:
    """Send only rule metadata; never send raw evidence/configuration to the provider."""
    device = control.get("device") or {}
    return json.dumps(
        {
            "vendor": device.get("vendor", "unknown"),
            "platform": device.get("platform", "unknown"),
            "rule_id": control.get("rule_id"),
            "title": control.get("title"),
            "severity": control.get("severity"),
            "benchmark_remediation": control.get("remediation"),
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _provider_remediation(control: dict[str, Any], api_key: str, model: str) -> dict[str, Any]:
    context = _redact_remediation_context(control)
    prompt = (
        "Generate a concise Cisco IOS CLI remediation for this failed compliance "
        "control. Return JSON only with string keys remediation and reasoning. "
        "Keep reasoning under 30 words and explain why the commands address the control. Include configuration "
        "mode commands where safe, and a brief verification command. Do not invent "
        "device-specific values or credentials. Mark assumptions. This is advisory "
        "AI-generated text, not a compliance result.\n\nControl: " + context
    )
    payload = json.dumps(
        {"model": model, "max_tokens": 220, "temperature": 0, "messages": [{"role": "user", "content": prompt}]}
    ).encode("utf-8")
    request = urllib.request.Request(
        ANTHROPIC_ENDPOINT,
        data=payload,
        headers={"content-type": "application/json", "x-api-key": api_key, "anthropic-version": "2023-06-01"},
        method="POST",
    )
    try:
        try:
            import certifi
            context_ssl = ssl.create_default_context(cafile=certifi.where())
        except ImportError:
            context_ssl = ssl.create_default_context()
        with urllib.request.urlopen(request, timeout=30, context=context_ssl) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise ProviderError(f"remediation provider HTTP {exc.code}: {detail}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderError(f"remediation provider request failed: {exc}") from exc
    text = body.get("content", [{}])[0].get("text", "")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise ProviderError("remediation provider response was not JSON")
        parsed = json.loads(match.group(0))
    remediation = parsed.get("remediation")
    if not isinstance(remediation, str) or not remediation.strip():
        raise ProviderError("remediation provider returned no remediation text")
    reasoning = parsed.get("reasoning")
    if not isinstance(reasoning, str) or not reasoning.strip():
        raise ProviderError("remediation provider returned no reasoning text")
    usage = body.get("usage") or {}
    input_tokens = int(usage.get("input_tokens", 0))
    output_tokens = int(usage.get("output_tokens", 0))
    return {
        "cache_key": remediation_key(control),
        "text": remediation.strip(),
        "reasoning": reasoning.strip(),
        "mode": "real-api",
        "provider": "anthropic",
        "model": model,
        "source": "provider",
        "ai_generated": True,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": round(input_tokens / 1_000_000 * INPUT_USD_PER_MILLION + output_tokens / 1_000_000 * OUTPUT_USD_PER_MILLION, 8),
        },
    }


def remediation_for_failed_controls(
    controls: list[dict[str, Any]],
    store: RemediationStore,
    *,
    real_api: bool = False,
    max_calls: int = 0,
    api_key: str | None = None,
    model: str = MODEL_DEFAULT,
) -> list[dict[str, Any]]:
    failed = [control for control in controls if control.get("status") == "fail"]
    unique = {remediation_key(control): control for control in failed}
    uncached = [key for key in unique if store.get(key) is None]
    if real_api:
        if not api_key:
            raise ProviderError("real remediation mode requires ANTHROPIC_API_KEY")
        if len(uncached) > max_calls:
            raise RuntimeError(f"refusing remediation calls: {len(uncached)} uncached keys exceed max_calls={max_calls}")
    results = []
    for key, control in unique.items():
        cached = store.get(key)
        if cached:
            value = cached
            value["mode"] = "cache"
        elif real_api:
            value = _provider_remediation(control, api_key or "", model)
        else:
            value = dry_run_remediation(control)
        value["rule_id"] = control["rule_id"]
        value["title"] = control.get("title")
        if real_api and cached is None:
            store.put(key, value)
        results.append(value)
    return results
