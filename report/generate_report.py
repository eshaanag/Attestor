#!/usr/bin/env python3
"""Attestor — HTML report generator (Phase 3).

Consumes a results.json (per docs/interfaces.md §3) and renders a single,
self-contained, offline HTML file via Jinja2. No external resources, no CDN
links, no network calls. Must open correctly with zero internet connectivity.

Usage:
    python report/generate_report.py results.json -o report.html
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from jinja2 import Environment, BaseLoader
except ImportError:
    sys.exit("ERROR: jinja2 not installed. Run: pip install jinja2")


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attestor Compliance Report — {{ (device.hostname if device else host.hostname) }} ({{ run.finished_at }})</title>
<style>
:root {
  --pass: #1a7f37; --fail: #cf222e; --error: #9a6700;
  --manual: #0969da; --na: #656d76;
  --bg: #ffffff; --fg: #1f2328; --border: #d0d7de;
  --header-bg: #f6f8fa; --card-bg: #ffffff;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
       color: var(--fg); background: var(--bg); line-height: 1.5; padding: 2rem; max-width: 1200px; margin: 0 auto; }
h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
h2 { font-size: 1.2rem; margin: 1.5rem 0 0.75rem; border-bottom: 1px solid var(--border); padding-bottom: 0.25rem; }
.header { background: var(--header-bg); border: 1px solid var(--border); border-radius: 6px; padding: 1.25rem; margin-bottom: 1.5rem; }
.header-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem 2rem; margin-top: 0.75rem; }
.header-grid dt { font-weight: 600; font-size: 0.85rem; color: #656d76; }
.header-grid dd { font-size: 0.95rem; }
.incomplete-banner { background: #fff8c5; border: 2px solid #d4a72c; border-radius: 6px;
                     padding: 1rem; margin-bottom: 1.5rem; font-weight: 600; text-align: center; }
.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
.summary-item { padding: 0.75rem 1.25rem; border-radius: 6px; border: 1px solid var(--border);
                text-align: center; min-width: 100px; }
.summary-item .count { font-size: 1.75rem; font-weight: 700; }
.summary-item .label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
.s-pass { border-color: var(--pass); } .s-pass .count { color: var(--pass); }
.s-fail { border-color: var(--fail); } .s-fail .count { color: var(--fail); }
.s-error { border-color: var(--error); } .s-error .count { color: var(--error); }
.s-manual { border-color: var(--manual); } .s-manual .count { color: var(--manual); }
.s-na { border-color: var(--na); } .s-na .count { color: var(--na); }
.control { border: 1px solid var(--border); border-radius: 6px; margin-bottom: 0.75rem;
           padding: 1rem; background: var(--card-bg); }
.control-header { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px;
         font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em; }
.badge-pass { background: #dafbe1; color: var(--pass); }
.badge-fail { background: #ffebe9; color: var(--fail); }
.badge-error { background: #fff8c5; color: var(--error); }
.badge-manual { background: #ddf4ff; color: var(--manual); }
.badge-not_applicable { background: #eaeef2; color: var(--na); }
.badge-severity { font-size: 0.7rem; padding: 0.1rem 0.4rem; border: 1px solid var(--border); }
.control-id { font-weight: 700; font-family: monospace; font-size: 0.9rem; }
.control-title { flex: 1; }
.control-details { margin-top: 0.75rem; font-size: 0.9rem; }
.control-details dt { font-weight: 600; margin-top: 0.5rem; }
.control-details dd { margin-left: 1rem; white-space: pre-wrap; word-break: break-word; }
.evidence-block { background: #f6f8fa; border: 1px solid var(--border); border-radius: 4px;
                  padding: 0.5rem 0.75rem; font-family: monospace; font-size: 0.8rem;
                  overflow-x: auto; margin-top: 0.25rem; }
.model-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.6rem; }
.model-fact { border: 1px solid var(--border); border-radius: 5px; padding: 0.7rem; background: #fbfcfd; }
.model-fact dt { font-weight: 600; font-size: 0.82rem; }
.model-fact dd { margin-top: 0.25rem; font-family: monospace; font-size: 0.82rem; }
.model-evidence { color: #656d76; font-family: inherit; font-size: 0.75rem; }
footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border);
         font-size: 0.8rem; color: #656d76; text-align: center; }
@media (max-width: 600px) { .header-grid { grid-template-columns: 1fr; } .summary { flex-direction: column; } }
/* Print styles */
@media print { body { padding: 0.5rem; } .control { break-inside: avoid; } }
</style>
</head>
<body>
<h1>Attestor Compliance Report</h1>

<div class="header">
  <strong>{{ benchmark }}</strong> {{ benchmark_version }}
  <dl class="header-grid">
    {% if device %}
    <dt>Audited device</dt><dd>{{ device.device_id }}{% if device.hostname %} ({{ device.hostname }}){% endif %}</dd>
    <dt>Vendor / platform</dt><dd>{{ device.vendor }} / {{ device.platform }}</dd>
    <dt>Device roles</dt><dd>{{ (device.roles | join(", ")) if device.roles else "not recorded" }}</dd>
    <dt>Config source</dt><dd>{{ device.config_source }}{% if device.config_sha256 %} (SHA-256 {{ device.config_sha256 }}){% endif %}</dd>
    {% endif %}
    <dt>Host</dt><dd>{{ host.hostname }}</dd>
    <dt>OS</dt><dd>{{ host.os_name }} {{ host.os_version }}</dd>
    <dt>Kernel / Build</dt><dd>{{ host.kernel }}</dd>
    <dt>Architecture</dt><dd>{{ host.arch }}</dd>
    <dt>Environment</dt><dd>{{ host.environment }}</dd>
    <dt>Elevated</dt><dd>{{ "Yes" if host.elevated else "No" }}</dd>
    <dt>User</dt><dd>{{ host.user }}</dd>
    <dt>Engine</dt><dd>{{ run.engine }} v{{ run.engine_version }}</dd>
    <dt>Run started</dt><dd>{{ run.started_at }}</dd>
    <dt>Run finished</dt><dd>{{ run.finished_at }}</dd>
    <dt>Controls evaluated</dt><dd>{{ run.evaluated }} / {{ run.total_controls }}</dd>
  </dl>
</div>

{% if not run.complete %}
<div class="incomplete-banner" role="alert" aria-label="Incomplete run warning">
  ⚠️ INCOMPLETE RUN: Only {{ run.evaluated }} of {{ run.total_controls }} controls were evaluated.
  This report does NOT represent a full audit. Results may be missing.
</div>
{% endif %}

<h2>Summary</h2>
<div class="summary" role="group" aria-label="Compliance summary counts">
  <div class="summary-item s-pass"><div class="count">{{ summary.pass }}</div><div class="label">Pass</div></div>
  <div class="summary-item s-fail"><div class="count">{{ summary.fail }}</div><div class="label">Fail</div></div>
  <div class="summary-item s-error"><div class="count">{{ summary.error }}</div><div class="label">Error</div></div>
  <div class="summary-item s-manual"><div class="count">{{ summary.manual }}</div><div class="label">Manual</div></div>
  <div class="summary-item s-na"><div class="count">{{ summary.not_applicable }}</div><div class="label">N/A</div></div>
</div>

{% if security_model %}
<h2>Normalized security model</h2>
<p style="margin-bottom:0.75rem;color:#656d76">Vendor-neutral facts extracted from explicit configuration evidence. Unknown means the saved configuration could not establish the value; it is never treated as a pass.</p>
<dl class="model-grid">
{% for name, fact in security_model.fields.items() %}
  <div class="model-fact">
    <dt>{{ name | replace("_", " ") }}</dt>
    <dd>{% if fact.value is none %}unknown{% elif fact.value is sameas true %}true{% elif fact.value is sameas false %}false{% else %}{{ fact.value }}{% endif %}</dd>
    {% if fact.evidence %}<dd class="model-evidence">line {{ fact.evidence.line }} — {{ fact.evidence.observation }}</dd>{% endif %}
  </div>
{% endfor %}
</dl>
{% endif %}

<h2>Controls ({{ controls | length }} total — failures &amp; errors first)</h2>
{% for control in controls_sorted %}
<div class="control" id="ctrl-{{ control.rule_id }}">
  <div class="control-header">
    <span class="badge badge-{{ control.status }}">{{ control.status | upper }}</span>
    <span class="control-id">{{ control.rule_id }}</span>
    <span class="control-title">{{ control.title }}</span>
    <span class="badge badge-severity">{{ control.severity }}</span>
    <span class="badge badge-severity">L{{ control.level }}</span>
  </div>
  <dl class="control-details">
    <dt>Evidence</dt>
    <dd><div class="evidence-block">{{ control.evidence_summary }}</div></dd>
    {% if control.status in ["fail", "error"] %}
    <dt>Remediation</dt>
    <dd>{{ control.remediation }}</dd>
    {% endif %}
    <dt>Source</dt>
    <dd>{{ control.source }}</dd>
    {% if control.framework_mappings %}
    <dt>Framework mappings</dt>
    <dd>
      <div class="framework-list">
      {% for mapping in control.framework_mappings %}
        <div><strong>{{ mapping.framework }}</strong>{% if mapping.version %} {{ mapping.version }}{% endif %}: <code>{{ mapping.control_id }}</code>{% if mapping.relationship %} ({{ mapping.relationship }}){% endif %}<br><span class="mapping-source">{{ mapping.source }}</span></div>
      {% endfor %}
      </div>
    </dd>
    {% endif %}
  </dl>
</div>
{% endfor %}

<footer>
  Generated by Attestor v{{ run.engine_version }} | Format version {{ format_version }} |
  Report ID: {{ report_id }} | Target: {{ target }}
</footer>
</body>
</html>"""

STATUS_ORDER = {"error": 0, "fail": 1, "manual": 2, "not_applicable": 3, "pass": 4}


def load_results(path: str) -> dict:
    """Load results.json, handling Windows BOM if present."""
    text = Path(path).read_bytes()
    if text[:3] == b'\xef\xbb\xbf':
        text = text[3:]
    return json.loads(text.decode("utf-8"))


def render(results: dict) -> str:
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(TEMPLATE)

    controls_sorted = sorted(
        results["controls"],
        key=lambda c: (STATUS_ORDER.get(c["status"], 9), c["rule_id"])
    )

    return template.render(
        benchmark=results["benchmark"],
        benchmark_version=results["benchmark_version"],
        device=results.get("device"),
        security_model=results.get("security_model"),
        host=results["host"],
        run=results["run"],
        summary=results["summary"],
        controls=results["controls"],
        controls_sorted=controls_sorted,
        format_version=results["attestor_format_version"],
        report_id=results["report_id"],
        target=results["target"],
    )


def main():
    parser = argparse.ArgumentParser(description="Generate Attestor HTML report from results.json")
    parser.add_argument("results", help="Path to results.json")
    parser.add_argument("-o", "--output", default=None,
                        help="Output HTML path (default: <results-stem>_report.html)")
    args = parser.parse_args()

    results = load_results(args.results)
    html = render(results)

    out_path = args.output or Path(args.results).stem + "_report.html"
    Path(out_path).write_text(html, encoding="utf-8")
    print(f"Report generated: {out_path} ({len(results['controls'])} controls)")


if __name__ == "__main__":
    main()
