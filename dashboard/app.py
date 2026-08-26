#!/usr/bin/env python3
"""Attestor — Local Web GUI (Phase 7).

A minimal FastAPI app providing:
  * A "Run Audit" page with target selector
  * Live-streaming per-check results via SSE (Server-Sent Events)
  * Link to the generated HTML report on completion

Architecture decision: runs on localhost (same machine as the engine).
Live-update via SSE — the engine's NDJSON stream maps 1:1 to SSE events.
No external dependencies beyond fastapi/uvicorn/jinja2 (already in stack).

Usage:
    python dashboard/app.py
    # Then open http://localhost:8000 in a browser
"""
from __future__ import annotations

import asyncio
import copy
import html
import json
import re
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from report.generate_pdf import build_pdf  # noqa: E402
from report.generate_report import render  # noqa: E402

RESULTS_DIR = REPO_ROOT / "reports"
RESULTS_DIR.mkdir(exist_ok=True)

app = FastAPI(title="Attestor Local GUI", version="0.2.0")
MAX_NETWORK_FILES = 20
MAX_NETWORK_CONFIG_BYTES = 2 * 1024 * 1024
FRAMEWORK_VIEWS = {"all", "cis", "nist"}
DEVICE_RECORDS: dict[str, dict] = {}

# ─────────────────────── HTML Template (inline, self-contained) ───────────────

PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attestor — CIS Audit</title>
<style>
:root { --ink: #142230; --muted: #607080; --line: #d8e0e7; --canvas: #f3f6f8; --surface: #fff; --blue: #1769aa; --blue-soft: #e8f2fb; --pass: #18794e; --fail: #b42318; --error: #9a6700; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--canvas); color: var(--ink); min-height: 100vh; }
.shell { max-width: 1180px; margin: 0 auto; padding: 28px 28px 56px; }
.topbar { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding-bottom: 26px; }
.brand { display: flex; align-items: center; gap: 12px; }
.brand-mark { display: grid; place-items: center; width: 38px; height: 38px; border-radius: 10px; background: var(--ink); color: #fff; font-weight: 800; font-size: 17px; }
.brand-name { font-size: 17px; font-weight: 760; letter-spacing: .01em; }
.brand-subtitle { color: var(--muted); font-size: 12px; margin-top: 2px; }
.status-pill { display: inline-flex; align-items: center; gap: 7px; border: 1px solid var(--line); background: var(--surface); color: var(--muted); border-radius: 999px; padding: 7px 11px; font-size: 12px; font-weight: 650; }
.status-dot { width: 7px; height: 7px; background: var(--pass); border-radius: 50%; }
.hero { display: grid; grid-template-columns: minmax(0, 1.45fr) minmax(260px, .75fr); gap: 22px; align-items: stretch; margin-bottom: 24px; }
.hero-copy, .hero-metric, .panel, .result-card { background: var(--surface); border: 1px solid var(--line); border-radius: 12px; }
.hero-copy { padding: 30px; }
.eyebrow { color: var(--blue); font-size: 11px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; margin-bottom: 11px; }
h1 { font-size: clamp(28px, 4vw, 43px); line-height: 1.07; letter-spacing: 0; max-width: 680px; text-wrap: balance; }
.hero-copy p { color: var(--muted); line-height: 1.6; max-width: 660px; margin-top: 14px; text-wrap: pretty; }
.hero-metric { padding: 24px; display: flex; flex-direction: column; justify-content: space-between; background: #e9f2f8; border-color: #c9ddea; }
.metric-label { color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; }
.metric-number { font-size: 44px; line-height: 1; font-weight: 780; margin: 18px 0 8px; font-variant-numeric: tabular-nums; }
.metric-note { color: var(--muted); font-size: 13px; line-height: 1.45; }
.grid { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(0, .9fr); gap: 22px; }
.panel { padding: 22px; }
.panel-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; margin-bottom: 17px; }
h2 { font-size: 17px; line-height: 1.25; text-wrap: balance; }
.panel-kicker { color: var(--muted); font-size: 13px; line-height: 1.45; margin-top: 5px; text-wrap: pretty; }
.field { margin-top: 16px; }
label { display: block; color: var(--ink); font-size: 12px; font-weight: 760; margin-bottom: 7px; }
select, input[type=file] { width: 100%; border: 1px solid var(--line); border-radius: 8px; background: #fbfcfd; color: var(--ink); font: inherit; font-size: 13px; padding: 11px 12px; }
input[type=file] { padding: 9px; }
select:focus, input:focus, button:focus-visible, a:focus-visible { outline: 3px solid rgba(23,105,170,.24); outline-offset: 2px; }
.button { display: inline-flex; align-items: center; justify-content: center; gap: 8px; border: 0; border-radius: 8px; background: var(--ink); color: #fff; font: inherit; font-size: 13px; font-weight: 760; padding: 11px 15px; cursor: pointer; }
.button:hover { background: #263b4c; }
.button:disabled { opacity: .55; cursor: not-allowed; }
.button-secondary { background: var(--blue-soft); color: var(--blue); }
.button-secondary:hover { background: #dbeaf6; }
.form-actions { display: flex; align-items: center; gap: 10px; margin-top: 18px; }
.helper { color: var(--muted); font-size: 12px; line-height: 1.45; margin-top: 12px; }
.coverage { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 17px; }
.tag { border: 1px solid var(--line); border-radius: 999px; color: var(--muted); background: #fbfcfd; font-size: 11px; font-weight: 700; padding: 6px 9px; }
.tag-active { color: var(--blue); background: var(--blue-soft); border-color: #c7deef; }
.status-bar { padding: 12px 14px; background: var(--blue-soft); border: 1px solid #b9d6eb; border-radius: 8px; margin: 22px 0; color: var(--blue); font-size: 13px; font-weight: 700; }
.status-bar.complete { background: #e9f7ef; border-color: #b8dec8; color: var(--pass); }
.summary { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 10px; margin: 16px 0 20px; }
.summary-item { padding: 14px 10px; border: 1px solid var(--line); border-radius: 9px; background: var(--surface); text-align: center; }
.summary-item .count { font-size: 24px; font-weight: 780; font-variant-numeric: tabular-nums; }
.summary-item .label { color: var(--muted); font-size: 10px; letter-spacing: .06em; margin: 3px 0 0; text-transform: uppercase; }
.s-pass .count { color: var(--pass); } .s-fail .count { color: var(--fail); } .s-error .count { color: var(--error); }
#results { max-height: 480px; overflow-y: auto; border: 1px solid var(--line); border-radius: 9px; background: var(--surface); font-size: 12px; }
.result-line { display: grid; grid-template-columns: 72px 72px minmax(0, 1fr); gap: 10px; align-items: center; padding: 11px 12px; border-bottom: 1px solid #edf1f4; }
.result-line:last-child { border-bottom: 0; }
.result-evidence { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.badge { display: inline-flex; width: fit-content; align-items: center; border-radius: 999px; padding: 4px 7px; font-size: 10px; font-weight: 800; letter-spacing: .04em; text-transform: uppercase; }
.badge-pass { background: #e7f6ed; color: var(--pass); }
.badge-fail { background: #fdecea; color: var(--fail); }
.badge-error { background: #fff5d7; color: var(--error); }
.report-link { display: inline-flex; align-items: center; border: 1px solid var(--line); border-radius: 7px; background: var(--surface); color: var(--blue); font-size: 12px; font-weight: 760; margin: 12px 8px 0 0; padding: 8px 10px; text-decoration: none; }
.report-link:hover { background: var(--blue-soft); }
.result-card { padding: 20px; margin-bottom: 14px; }
.result-card p { color: var(--muted); font-size: 13px; line-height: 1.5; margin-top: 7px; }
.hidden { display: none; }
@media (max-width: 820px) { .hero, .grid { grid-template-columns: 1fr; } .summary { grid-template-columns: repeat(3, 1fr); } }
@media (max-width: 520px) { .shell { padding: 20px 16px 40px; } .topbar { align-items: flex-start; } .status-pill { display: none; } .hero-copy { padding: 23px; } .panel { padding: 18px; } .summary { grid-template-columns: repeat(2, 1fr); } .result-line { grid-template-columns: 62px 58px minmax(0, 1fr); } }
@media (prefers-reduced-motion: reduce) { * { scroll-behavior: auto !important; } }
</style>
</head>
<body>
<div class="shell">
<header class="topbar">
  <div class="brand"><div class="brand-mark">A</div><div><div class="brand-name">Attestor</div><div class="brand-subtitle">Network security compliance</div></div></div>
  <div class="status-pill"><span class="status-dot"></span>Local workspace</div>
</header>

<section class="hero">
  <div class="hero-copy"><div class="eyebrow">Audit console</div><h1>See what is secure before it becomes an incident.</h1><p>Upload a saved device configuration, evaluate a verified Cisco IOS or Junos baseline, and leave with evidence your team can inspect offline.</p><div class="coverage"><span class="tag tag-active">Cisco IOS</span><span class="tag">Juniper Junos</span><span class="tag">CIS + NIST mappings</span><span class="tag">Offline reports</span></div></div>
  <div class="hero-metric"><div class="metric-label">Verified controls</div><div class="metric-number">18</div><div class="metric-note">14 Cisco IOS controls plus a source-backed four-control Junos subset. Broader vendor coverage remains roadmap.</div></div>
</section>

<div class="grid">
<section class="panel">
  <div class="panel-header"><div><h2>Audit a network configuration</h2><p class="panel-kicker">Start with a real saved device configuration. Upload one device or a small batch.</p></div><span class="tag tag-active">Primary workflow</span></div>
  <form action="/api/network/audit" method="post" enctype="multipart/form-data">
    <div class="field"><label for="vendor">Vendor</label><select id="vendor" name="vendor"><option value="cisco_ios">Cisco IOS / IOS-XE (14 controls)</option><option value="juniper_junos">Juniper Junos (4-control verified subset)</option></select></div>
    <div class="field"><label for="network-files">Configuration files</label><input id="network-files" name="files" type="file" accept=".txt,.cfg,.conf,text/plain" multiple required></div>
    <div class="field"><label for="framework">Report view</label><select id="framework" name="framework"><option value="all">Source-backed checks with NIST mappings</option><option value="cis">Source-backed controls only</option><option value="nist">NIST SP 800-53 mapped view</option></select></div>
    <div class="form-actions"><button class="button" type="submit">Upload and audit</button></div>
  </form>
  <p class="helper">Files are processed locally in a temporary workspace and discarded after the audit. AI remediation stays in dry-run mode here.</p>
</section>

<section class="panel" id="run-panel">
  <div class="panel-header"><div><h2>Audit a local VM</h2><p class="panel-kicker">Run the established Windows or Ubuntu track where the machine itself is the evidence source.</p></div><span class="tag">Existing workflow</span></div>
  <label for="target">Target</label>
  <select id="target">
    <option value="ubuntu2204_desktop">Ubuntu 22.04 Desktop (Level 1)</option>
    <option value="windows11_standalone">Windows 11 Standalone (Level 1)</option>
  </select>
  <div class="field"><label for="level">Level</label>
  <select id="level">
    <option value="1">Level 1</option>
    <option value="2">Level 2</option>
  </select></div>
  <div class="form-actions"><button class="button button-secondary" id="run-btn" onclick="startAudit()">Run live audit</button></div>
</section>
</div>

<div id="status-bar" class="status-bar hidden"></div>

<div id="summary-section" class="hidden">
  <div class="summary">
    <div class="summary-item s-pass"><div class="count" id="cnt-pass">0</div><div class="label">Pass</div></div>
    <div class="summary-item s-fail"><div class="count" id="cnt-fail">0</div><div class="label">Fail</div></div>
    <div class="summary-item s-error"><div class="count" id="cnt-error">0</div><div class="label">Error</div></div>
  </div>
</div>

<div id="results"></div>
<div id="report-section" class="hidden">
  <a id="report-link" class="report-link" href="#" target="_blank">📄 View Full Report</a>
</div>

<script>
let counts = {pass: 0, fail: 0, error: 0};

function startAudit() {
  const target = document.getElementById('target').value;
  const level = document.getElementById('level').value;
  const btn = document.getElementById('run-btn');
  const results = document.getElementById('results');
  const statusBar = document.getElementById('status-bar');
  const summarySection = document.getElementById('summary-section');
  const reportSection = document.getElementById('report-section');

  btn.disabled = true;
  btn.textContent = '⏳ Running...';
  results.innerHTML = '';
  counts = {pass: 0, fail: 0, error: 0};
  statusBar.className = 'status-bar';
  statusBar.textContent = 'Audit running...';
  statusBar.classList.remove('hidden');
  summarySection.classList.remove('hidden');
  reportSection.classList.add('hidden');
  updateCounts();

  const evtSource = new EventSource('/api/run?target=' + target + '&level=' + level);

  evtSource.addEventListener('check', function(e) {
    const data = JSON.parse(e.data);
    const badge = '<span class="badge badge-' + data.status + '">' + data.status.toUpperCase() + '</span>';
    const line = '<div class="result-line">' + badge +
      '<span>' + data.rule_id + '</span>' +
      '<span class="result-evidence">' + escapeHtml(data.evidence) + '</span></div>';
    results.innerHTML += line;
    results.scrollTop = results.scrollHeight;
    if (data.status === 'pass') counts.pass++;
    else if (data.status === 'fail') counts.fail++;
    else if (data.status === 'error') counts.error++;
    updateCounts();
  });

  evtSource.addEventListener('complete', function(e) {
    const data = JSON.parse(e.data);
    evtSource.close();
    btn.disabled = false;
    btn.textContent = '▶ Run Audit';
    statusBar.textContent = 'Audit complete — ' + data.total + ' controls evaluated';
    statusBar.className = 'status-bar complete';
    if (data.report_url) {
      reportSection.classList.remove('hidden');
      document.getElementById('report-link').href = data.report_url;
    }
  });

  evtSource.addEventListener('error', function(e) {
    evtSource.close();
    btn.disabled = false;
    btn.textContent = '▶ Run Audit';
    statusBar.textContent = 'Connection lost or audit failed';
    statusBar.className = 'status-bar';
  });
}

function updateCounts() {
  document.getElementById('cnt-pass').textContent = counts.pass;
  document.getElementById('cnt-fail').textContent = counts.fail;
  document.getElementById('cnt-error').textContent = counts.error;
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
</script>
</div>
</body>
</html>"""

LANDING_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attestor | Security compliance operations</title>
<style>
:root{--ink:#10212b;--muted:#60727d;--line:#dce5e9;--canvas:#f5f8fa;--surface:#fff;--blue:#1266a8;--blue2:#e8f2fa;--green:#18794e}
*{box-sizing:border-box;margin:0;padding:0}body{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--canvas);color:var(--ink);line-height:1.5}.wrap{max-width:1180px;margin:auto;padding:26px 28px 64px}.nav{display:flex;justify-content:space-between;align-items:center}.brand{display:flex;align-items:center;gap:11px}.mark{width:38px;height:38px;border-radius:10px;background:var(--ink);color:#fff;display:grid;place-items:center;font-weight:800}.brand strong{font-size:17px}.brand small{display:block;color:var(--muted);font-size:11px}.navlinks{display:flex;gap:18px;align-items:center}.navlinks a{color:var(--muted);font-size:13px;text-decoration:none}.navlinks a:hover{color:var(--blue)}.navbtn{background:var(--ink)!important;color:#fff!important;padding:10px 14px;border-radius:8px;font-weight:700}.hero{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(300px,.75fr);gap:48px;align-items:center;padding:86px 0 74px}.eyebrow{color:var(--blue);font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.11em;margin-bottom:16px}.hero h1{font-size:clamp(38px,5vw,65px);line-height:1.02;letter-spacing:-.02em;max-width:680px}.hero p{color:var(--muted);font-size:17px;max-width:610px;margin-top:20px}.actions{display:flex;gap:12px;margin-top:28px;flex-wrap:wrap}.btn{display:inline-flex;align-items:center;justify-content:center;text-decoration:none;border-radius:8px;padding:12px 17px;font-size:13px;font-weight:750}.primary{background:var(--ink);color:#fff}.secondary{background:var(--surface);border:1px solid var(--line);color:var(--ink)}.trust{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:23px}.trust h2{font-size:16px;margin-bottom:15px}.trustrow{display:flex;gap:12px;padding:13px 0;border-top:1px solid #edf1f3}.trustrow:first-of-type{border-top:0}.icon{width:30px;height:30px;display:grid;place-items:center;border-radius:8px;background:var(--blue2);color:var(--blue);font-weight:800;flex:none}.trustrow strong{display:block;font-size:13px}.trustrow span{display:block;color:var(--muted);font-size:12px;margin-top:2px}.band{border-top:1px solid var(--line);padding-top:27px}.bandhead{display:flex;justify-content:space-between;align-items:end;gap:20px;margin-bottom:17px}.band h2{font-size:20px}.band p{color:var(--muted);font-size:13px}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.card{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:18px}.card strong{font-size:14px}.card p{color:var(--muted);font-size:12px;margin-top:6px}.pill{display:inline-block;margin-top:14px;border-radius:999px;padding:5px 8px;background:var(--blue2);color:var(--blue);font-size:10px;font-weight:800;text-transform:uppercase}@media(max-width:800px){.hero{grid-template-columns:1fr;padding:58px 0}.cards{grid-template-columns:1fr}.navlinks a:not(.navbtn){display:none}}
</style></head><body><div class="wrap"><nav class="nav"><div class="brand"><div class="mark">A</div><div><strong>Attestor</strong><small>Security compliance operations</small></div></div><div class="navlinks"><a href="#coverage">Coverage</a><a href="#trust">Trust model</a><a class="navbtn" href="/console">Open console</a></div></nav>
<main><section class="hero"><div><div class="eyebrow">Configuration assurance</div><h1>Turn device state into evidence your organization can trust.</h1><p>Attestor evaluates real Windows, Linux, Cisco IOS, and scoped Juniper Junos configurations against source-backed controls, then gives security teams a reviewable trail from finding to remediation.</p><div class="actions"><a class="btn primary" href="/console">Open audit console</a><a class="btn secondary" href="#coverage">View supported scope</a></div></div><aside class="trust" id="trust"><h2>Built for accountable decisions</h2><div class="trustrow"><div class="icon">✓</div><div><strong>Deterministic first</strong><span>Schema-validated rules remain authoritative; unknown input fails closed.</span></div></div><div class="trustrow"><div class="icon">◎</div><div><strong>Evidence stays local</strong><span>Uploads are processed temporarily. Reports open offline.</span></div></div><div class="trustrow"><div class="icon">↗</div><div><strong>AI stays advisory</strong><span>Redacted discovery and cached remediation never override a result.</span></div></div><div class="trustrow"><div class="icon">#</div><div><strong>Hash-only proof</strong><span>Optional Sepolia anchoring publishes report hashes, never configuration.</span></div></div></aside></section>
<section class="band" id="coverage"><div class="bandhead"><div><h2>Verified coverage</h2><p>Start with the controls that have real corpus or VM evidence behind them.</p></div><a class="btn secondary" href="/console">Start a scan</a></div><div class="cards"><div class="card"><strong>Windows 11 Standalone</strong><p>Native PowerShell checks against the verified Level 1 rule pack.</p><span class="pill">30 controls</span></div><div class="card"><strong>Ubuntu 22.04 Desktop</strong><p>Python checks for kernel, sysctl, services, packages, and permissions.</p><span class="pill">35 controls</span></div><div class="card"><strong>Cisco IOS / IOS-XE</strong><p>Flat and block-aware configuration checks with CIS and NIST mappings.</p><span class="pill">14 controls</span></div><div class="card"><strong>Juniper Junos</strong><p>Source-backed vendor baseline for common service and logging controls.</p><span class="pill">4 controls</span></div><div class="card"><strong>Reports</strong><p>Per-device JSON, standalone HTML, and PDF outputs for review and handoff.</p><span class="pill">Offline-ready</span></div><div class="card"><strong>Roadmap</strong><p>Other vendors, broader Junos coverage, live collection, and fleet storage.</p><span class="pill">Clearly scoped</span></div></div></section></main></div></body></html>"""


# ─────────────────────── Routes ───────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    return LANDING_TEMPLATE


def _format_time(value: str | None) -> str:
    if not value:
        return "Not scanned"
    return value.replace("T", " ").replace("Z", " UTC")


def _console_page(search: str = "", vendor: str = "all", status: str = "all") -> str:
    records = list(DEVICE_RECORDS.values())
    if search:
        needle = search.casefold()
        records = [r for r in records if needle in str(r.get("device_id", "")).casefold() or needle in str(r.get("filename", "")).casefold()]
    if vendor != "all":
        records = [r for r in records if r.get("vendor_key") == vendor]
    if status != "all":
        records = [r for r in records if r.get("status") == status]
    counts = {"total": len(DEVICE_RECORDS), "complete": 0, "fail": 0, "error": 0}
    aggregate = {key: 0 for key in ("pass", "fail", "error", "manual", "not_applicable")}
    for record in DEVICE_RECORDS.values():
        if record.get("status") == "complete":
            counts["complete"] += 1
            for key, value in (record.get("summary") or {}).items():
                aggregate[key] = aggregate.get(key, 0) + value
        elif record.get("status") == "failed":
            counts["fail"] += 1
        elif record.get("status") == "error":
            counts["error"] += 1
    rows = []
    for record in records:
        summary = record.get("summary") or {}
        status_name = record.get("status", "queued")
        badge_class = "good" if status_name == "complete" else "bad" if status_name in {"failed", "error"} else "pending"
        score_total = sum(summary.values())
        score = round(summary.get("pass", 0) * 100 / score_total) if score_total else 0
        rows.append(
            f'<a class="device-row" href="/console/devices/{html.escape(record["record_id"])}">'
            f'<div><strong>{html.escape(str(record.get("device_id", "Unknown device")))}</strong><span>{html.escape(str(record.get("vendor", "Unknown")))} · {html.escape(str(record.get("platform", "")))}</span></div>'
            f'<div class="row-score">{score}%<span>compliance</span></div>'
            f'<div class="row-summary"><span class="mini-pass">{summary.get("pass", 0)} pass</span><span class="mini-fail">{summary.get("fail", 0)} fail</span><span>{summary.get("error", 0)} error</span></div>'
            f'<div><span class="state {badge_class}">{html.escape(status_name)}</span><span class="last-scan">{html.escape(_format_time(record.get("last_scan")))}</span></div></a>'
        )
    device_rows = "".join(rows) or '<div class="empty">No devices match this view. Upload a genuine configuration to begin.</div>'
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Attestor | Audit console</title>
<style>
:root{{--ink:#10212b;--muted:#657782;--line:#dce5e9;--canvas:#f5f8fa;--surface:#fff;--blue:#1266a8;--blue2:#e8f2fa;--green:#18794e;--red:#b42318;--amber:#976c00}}*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--ink);background:var(--canvas)}}.shell{{max-width:1280px;margin:auto;padding:25px 28px 60px}}.topbar{{display:flex;justify-content:space-between;align-items:center;padding-bottom:28px}}.brand{{display:flex;align-items:center;gap:11px}}.mark{{width:38px;height:38px;border-radius:10px;background:var(--ink);color:#fff;display:grid;place-items:center;font-weight:800}}.brand strong{{display:block;font-size:17px}}.brand small{{display:block;color:var(--muted);font-size:11px}}.nav{{display:flex;gap:16px;align-items:center}}.nav a{{color:var(--muted);font-size:13px;text-decoration:none}}.nav .active{{color:var(--ink);font-weight:750}}.button{{border:0;border-radius:8px;background:var(--ink);color:#fff;padding:11px 14px;font:inherit;font-size:12px;font-weight:750;text-decoration:none;cursor:pointer}}.button.alt{{background:var(--surface);border:1px solid var(--line);color:var(--ink)}}.eyebrow{{color:var(--blue);font-size:11px;font-weight:800;letter-spacing:.11em;text-transform:uppercase;margin-bottom:10px}}h1{{font-size:32px;line-height:1.1}}.sub{{color:var(--muted);font-size:13px;margin-top:8px}}.top-actions{{display:flex;gap:9px;margin-top:22px;flex-wrap:wrap}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:25px 0}}.metric{{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px}}.metric strong{{font-size:27px;display:block;font-variant-numeric:tabular-nums}}.metric span{{display:block;color:var(--muted);font-size:11px;margin-top:3px;text-transform:uppercase;letter-spacing:.06em}}.metric.good strong{{color:var(--green)}}.metric.bad strong{{color:var(--red)}}.upload{{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:13px}}.upload h2{{font-size:16px}}.upload p{{color:var(--muted);font-size:12px;margin-top:4px}}.upload-grid{{display:grid;grid-template-columns:180px 220px minmax(240px,1fr) auto;gap:10px;align-items:end;margin-top:14px}}label{{display:block;font-size:11px;font-weight:750;margin-bottom:6px}}.upload input,.upload select,.filters input,.filters select{{width:100%;border:1px solid var(--line);border-radius:7px;padding:10px 11px;font:inherit;font-size:12px;background:#fbfcfd;color:var(--ink)}}.upload input[type=file]{{padding:8px}}.filters{{display:flex;gap:10px;align-items:center;background:var(--surface);border:1px solid var(--line);padding:13px;border-radius:10px;margin-bottom:12px}}.filters input{{flex:1;min-width:180px}}.device-list{{background:var(--surface);border:1px solid var(--line);border-radius:10px;overflow:hidden}}.device-row{{display:grid;grid-template-columns:minmax(220px,1.4fr) 100px minmax(190px,1fr) minmax(150px,.8fr);gap:18px;align-items:center;padding:16px 18px;border-bottom:1px solid #edf1f3;text-decoration:none;color:inherit}}.device-row:last-child{{border-bottom:0}}.device-row:hover{{background:#f8fbfd}}.device-row strong{{font-size:13px;display:block}}.device-row span{{color:var(--muted);font-size:11px;display:block;margin-top:4px}}.row-score{{font-size:20px;font-weight:800}}.row-score span{{font-size:10px;font-weight:500;text-transform:uppercase}}.row-summary{{display:flex;gap:9px;flex-wrap:wrap}}.row-summary span{{display:inline-block!important;margin:0!important}}.mini-pass{{color:var(--green)!important}}.mini-fail{{color:var(--red)!important}}.state{{display:inline-block!important;width:max-content;border-radius:999px;padding:5px 8px;font-size:10px!important;font-weight:800;text-transform:uppercase;margin:0!important}}.state.good{{background:#e7f6ed;color:var(--green)}}.state.bad{{background:#fdecea;color:var(--red)}}.state.pending{{background:#fff5d7;color:var(--amber)}}.last-scan{{font-size:10px!important}}.empty{{padding:34px;text-align:center;color:var(--muted);font-size:13px}}@media(max-width:900px){{.upload-grid{{grid-template-columns:1fr 1fr}}}}@media(max-width:800px){{.metrics{{grid-template-columns:repeat(2,1fr)}}.device-row{{grid-template-columns:1fr 80px;gap:10px}}.row-summary{{grid-column:1/-1}}.device-row>div:last-child{{text-align:right}}}}@media(max-width:520px){{.shell{{padding:20px 16px 45px}}.filters,.upload-grid{{display:flex;align-items:stretch;flex-direction:column}}.filters input{{width:100%}}}}
</style></head><body><div class="shell"><header class="topbar"><div class="brand"><div class="mark">A</div><div><strong>Attestor</strong><small>Security compliance operations</small></div></div><nav class="nav"><a class="active" href="/console">Console</a><a href="/">Overview</a></nav></header><main><div class="eyebrow">Organization workspace</div><h1>Audit operations</h1><p class="sub">Monitor configuration posture across the devices in this local workspace.</p><div class="top-actions"><a class="button" href="/#coverage">Supported scope</a><a class="button alt" href="/console#upload">Add configuration</a></div><section class="metrics"><div class="metric"><strong>{counts["total"]}</strong><span>Devices tracked</span></div><div class="metric good"><strong>{counts["complete"]}</strong><span>Completed scans</span></div><div class="metric bad"><strong>{aggregate["fail"]}</strong><span>Failed controls</span></div><div class="metric"><strong>{aggregate["error"]}</strong><span>Errors requiring review</span></div></section><section class="upload" id="upload"><h2>Add configurations</h2><p>Upload one or more genuine saved configurations. Every file is evaluated independently and discarded after processing.</p><form class="upload-grid" action="/api/network/audit" method="post" enctype="multipart/form-data"><div><label for="vendor">Vendor adapter</label><select id="vendor" name="vendor"><option value="cisco_ios">Cisco IOS / IOS-XE</option><option value="juniper_junos">Juniper Junos</option></select></div><div><label for="framework">Framework view</label><select id="framework" name="framework"><option value="all">Source-backed + NIST mappings</option><option value="cis">Source-backed controls</option><option value="nist">NIST mapped view</option></select></div><div><label for="files">Configuration files</label><input id="files" name="files" type="file" accept=".txt,.cfg,.conf,text/plain" multiple required></div><button class="button" type="submit">Queue scans</button></form></section><form class="filters" method="get" action="/console"><input name="search" value="{html.escape(search)}" placeholder="Search device or file"><select name="vendor"><option value="all">All vendors</option><option value="cisco_ios" {"selected" if vendor == "cisco_ios" else ""}>Cisco IOS / IOS-XE</option><option value="juniper_junos" {"selected" if vendor == "juniper_junos" else ""}>Juniper Junos</option></select><select name="status"><option value="all">All statuses</option><option value="queued" {"selected" if status == "queued" else ""}>Queued</option><option value="running" {"selected" if status == "running" else ""}>Running</option><option value="complete" {"selected" if status == "complete" else ""}>Completed</option><option value="failed" {"selected" if status == "failed" else ""}>Failed</option><option value="error" {"selected" if status == "error" else ""}>Error</option></select><button class="button" type="submit">Filter</button></form><section class="device-list">{device_rows}</section></main></div></body></html>"""


def _device_detail_page(record: dict) -> str:
    summary = record.get("summary") or {}
    total = sum(summary.values())
    score = round(summary.get("pass", 0) * 100 / total) if total else 0
    score_color = "var(--green)" if score >= 80 else "var(--amber)" if score >= 50 else "var(--red)"
    controls = sorted(record.get("controls", []), key=lambda item: (item.get("status") != "fail", item.get("severity") != "high", str(item.get("rule_id", ""))))
    controls_html = "".join(
        f'<div class="control"><div><strong>{html.escape(str(c.get("rule_id", "unknown")))}</strong><span>{html.escape(str(c.get("title", "")))} · {html.escape(str(c.get("severity", "unknown")))} severity</span></div><span class="control-status {c.get("status", "error")}">{html.escape(str(c.get("status", "error")))}</span><p>{html.escape(str(c.get("evidence_summary", "Evidence unavailable")))}</p><details><summary>Remediation and source</summary><p>{html.escape(str(c.get("remediation", "Manual review required")))}</p><p class="source">{html.escape(str(c.get("source", "Source unavailable")))}</p></details></div>'
        for c in controls
    ) or '<div class="empty">No control results available.</div>'
    history = "".join(f'<li><strong>{html.escape(_format_time(item.get("timestamp")))}</strong><span>pass {item.get("pass", 0)} · fail {item.get("fail", 0)} · error {item.get("error", 0)}</span></li>' for item in record.get("history", [])) or "<li>No previous scans</li>"
    urls = record.get("urls", {})
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Attestor | {html.escape(str(record.get('device_id','Device')))}</title><style>
:root{{--ink:#10212b;--muted:#657782;--line:#dce5e9;--canvas:#f5f8fa;--surface:#fff;--blue:#1266a8;--green:#18794e;--red:#b42318;--amber:#976c00}}*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--canvas);color:var(--ink)}}.shell{{max-width:1180px;margin:auto;padding:25px 28px 60px}}.topbar,.head,.identity,.summary,.columns,.control-head{{display:flex;justify-content:space-between;gap:18px}}.topbar{{align-items:center;padding-bottom:28px}}.brand{{display:flex;align-items:center;gap:11px}}.mark{{width:38px;height:38px;border-radius:10px;background:var(--ink);color:#fff;display:grid;place-items:center;font-weight:800}}.brand strong{{display:block;font-size:17px}}.brand small,.muted,.identity span,.history span,.control span,.control p,.source{{color:var(--muted);font-size:12px}}.nav a,.link{{color:var(--blue);font-size:12px;font-weight:750;text-decoration:none}}.eyebrow{{color:var(--blue);font-size:11px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;margin-bottom:9px}}h1{{font-size:32px;line-height:1.1}}.head{{align-items:end;margin-bottom:22px}}.actions{{display:flex;gap:8px;flex-wrap:wrap}}.button{{display:inline-block;background:var(--ink);color:#fff;text-decoration:none;border-radius:8px;padding:10px 12px;font-size:12px;font-weight:750}}.button.alt{{background:var(--surface);border:1px solid var(--line);color:var(--ink)}}.identity,.panel{{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:18px}}.identity{{align-items:center;margin-bottom:14px}}.identity strong{{font-size:16px;display:block}}.identity span{{display:block;margin-top:4px}}.score{{font-size:34px;font-weight:850;color:{score_color};text-align:right}}.score small{{display:block;color:var(--muted);font-size:10px;text-transform:uppercase}}.summary{{margin-bottom:14px}}.sum{{flex:1;border:1px solid var(--line);border-radius:9px;padding:13px;background:var(--surface)}}.sum strong{{font-size:23px;display:block}}.sum span{{font-size:10px;color:var(--muted);text-transform:uppercase}}.pass strong{{color:var(--green)}}.fail strong{{color:var(--red)}}.error strong{{color:var(--amber)}}.columns{{align-items:start}}.main{{flex:1;min-width:0}}.side{{width:280px;display:grid;gap:14px}}.panel h2{{font-size:16px;margin-bottom:13px}}.control{{padding:15px 0;border-top:1px solid #edf1f3}}.control:first-child{{border-top:0;padding-top:0}}.control strong{{font-size:13px;margin-right:7px}}.control-status{{float:right;border-radius:999px;padding:4px 7px!important;text-transform:uppercase;font-size:10px!important;font-weight:800}}.control-status.pass{{background:#e7f6ed;color:var(--green)}}.control-status.fail{{background:#fdecea;color:var(--red)}}.control-status.error{{background:#fff5d7;color:var(--amber)}}.control p{{margin-top:8px;line-height:1.45}}details{{margin-top:9px;color:var(--blue);font-size:12px}}details p{{color:var(--ink);margin-top:6px}}.source{{word-break:break-word}}.history{{list-style:none}}.history li{{padding:10px 0;border-top:1px solid #edf1f3}}.history li:first-child{{border-top:0;padding-top:0}}.history strong,.history span{{display:block}}.hash{{font-family:ui-monospace,monospace;word-break:break-all;background:#f5f8fa;padding:9px;border-radius:7px;font-size:10px;color:var(--muted);margin-top:8px}}.empty{{padding:20px;color:var(--muted);font-size:13px}}@media(max-width:820px){{.columns{{display:block}}.side{{width:auto;margin-top:14px}}.head{{display:block}}.actions{{margin-top:15px}}.identity{{align-items:flex-start;display:block}}.score{{text-align:left;margin-top:13px}}.summary{{display:grid;grid-template-columns:repeat(2,1fr)}}}}
</style></head><body><div class="shell"><header class="topbar"><div class="brand"><div class="mark">A</div><div><strong>Attestor</strong><small>Security compliance operations</small></div></div><a class="nav" href="/console">Back to console</a></header><main><div class="head"><div><div class="eyebrow">Device detail</div><h1>{html.escape(str(record.get("device_id", "Unknown device")))}</h1><p class="muted">{html.escape(str(record.get("filename", "")))}</p></div><div class="actions">{''.join(f'<a class="button alt" href="{html.escape(url)}" target="_blank">{label}</a>' for label,url in (("JSON",urls.get("json_url")),("HTML",urls.get("html_url")),("PDF",urls.get("pdf_url"))) if url)}<a class="button" href="/console#upload">New scan</a></div></div><section class="identity"><div><strong>{html.escape(str(record.get("vendor", "Unknown")))} · {html.escape(str(record.get("platform", "")))}</strong><span>Device ID: {html.escape(str(record.get("device_id", "unknown")))}</span><span>Status: {html.escape(str(record.get("status", "unknown")))} · Last scan: {html.escape(_format_time(record.get("last_scan")))}</span></div><div class="score">{score}%<small>current compliance</small></div></section><section class="summary"><div class="sum pass"><strong>{summary.get("pass", 0)}</strong><span>Pass</span></div><div class="sum fail"><strong>{summary.get("fail", 0)}</strong><span>Fail</span></div><div class="sum error"><strong>{summary.get("error", 0)}</strong><span>Error</span></div><div class="sum"><strong>{total}</strong><span>Controls evaluated</span></div></section><div class="columns"><section class="panel main"><h2>Findings and evidence</h2>{controls_html}</section><aside class="side"><section class="panel"><h2>Scan history</h2><ul class="history">{history}</ul></section><section class="panel"><h2>Integrity</h2><p class="muted">Local hash-chain status: <strong>{html.escape(str(record.get("chain_status", "Not chained")))}</strong></p><div class="hash">{html.escape(str(record.get("config_sha256", "Configuration hash unavailable")))}</div></section></aside></div></main></div></body></html>"""


def _safe_upload_name(filename: str | None) -> str:
    basename = Path(filename or "network-config.txt").name
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", basename).strip("._")
    return sanitized or "network-config.txt"


def _apply_framework_view(results: dict, framework: str) -> dict:
    """Create a presentation-only framework view without changing check results."""
    viewed = copy.deepcopy(results)
    viewed["selected_framework"] = framework
    if framework == "all":
        return viewed
    if framework == "cis":
        for control in viewed.get("controls", []):
            control.pop("framework_mappings", None)
        return viewed

    controls = []
    for control in viewed.get("controls", []):
        mappings = [
            mapping for mapping in control.get("framework_mappings", [])
            if str(mapping.get("framework", "")).casefold().startswith("nist")
        ]
        if mappings:
            control["framework_mappings"] = mappings
            controls.append(control)
    viewed["controls"] = controls
    viewed["benchmark"] = "NIST SP 800-53 mapped view (source-backed checks)"
    viewed["benchmark_version"] = "Rev. 5 mappings"
    viewed["summary"] = {key: 0 for key in ("pass", "fail", "error", "manual", "not_applicable")}
    for control in controls:
        viewed["summary"][control["status"]] += 1
    viewed["run"]["total_controls"] = len(controls)
    viewed["run"]["evaluated"] = len(controls)
    return viewed


async def _audit_network_upload(upload: UploadFile, framework: str, vendor: str, work_dir: Path, record_id: str | None = None) -> dict:
    display_name = _safe_upload_name(upload.filename)
    if record_id and record_id in DEVICE_RECORDS:
        DEVICE_RECORDS[record_id]["status"] = "running"
    content = await upload.read(MAX_NETWORK_CONFIG_BYTES + 1)
    if not content:
        return {"record_id": record_id, "filename": display_name, "status": "error", "error": "uploaded file is empty", "vendor": vendor}
    if len(content) > MAX_NETWORK_CONFIG_BYTES:
        return {
            "record_id": record_id, "filename": display_name,
            "status": "error",
            "error": f"file exceeds {MAX_NETWORK_CONFIG_BYTES // (1024 * 1024)} MiB limit",
            "vendor": vendor,
        }

    item_id = uuid.uuid4().hex[:10]
    input_path = work_dir / f"{item_id}_{display_name}"
    input_path.write_bytes(content)
    results_path = RESULTS_DIR / f"network_{item_id}.json"
    html_path = RESULTS_DIR / f"network_{item_id}.html"
    pdf_path = RESULTS_DIR / f"network_{item_id}.pdf"
    device_id = Path(display_name).stem or f"uploaded-device-{item_id}"
    engine = "run_junos_audit.py" if vendor == "juniper_junos" else "run_audit.py"
    cmd = [
        sys.executable,
        str(REPO_ROOT / "engines" / "network" / engine),
        "--config", str(input_path),
        "--device-id", device_id,
        "--output", str(results_path),
    ]
    if vendor == "cisco_ios":
        cmd.extend(["--format", "json"])
    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0 or not results_path.exists():
        detail = stderr.decode("utf-8", errors="replace").strip()
        return {
            "record_id": record_id, "filename": display_name,
            "status": "error",
            "error": detail[-800:] or f"network engine exited {process.returncode}",
            "vendor": vendor,
        }

    try:
        results = json.loads(results_path.read_text(encoding="utf-8"))
        viewed = _apply_framework_view(results, framework)
        results_path.write_text(json.dumps(viewed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        html_path.write_text(render(viewed), encoding="utf-8")
        build_pdf(viewed, pdf_path, state_dir=work_dir / f"state_{item_id}")
    except Exception as exc:
        for artifact in (results_path, html_path, pdf_path):
            try:
                artifact.unlink(missing_ok=True)
            except OSError:
                pass
        return {
            "record_id": record_id, "filename": display_name,
            "status": "error",
            "error": f"report generation failed: {type(exc).__name__}: {exc}",
            "vendor": vendor,
        }

    return {
        "record_id": record_id,
        "filename": display_name,
        "status": "complete",
        "device": viewed.get("device", {}),
        "summary": viewed.get("summary", {}),
        "controls": viewed.get("controls", []),
        "framework": framework,
        "vendor": vendor,
        "json_url": f"/reports/{results_path.name}",
        "html_url": f"/reports/{html_path.name}",
        "pdf_url": f"/reports/{pdf_path.name}",
        "engine_output_lines": len(stdout.decode("utf-8", errors="replace").splitlines()),
    }


def _network_results_page(items: list[dict], framework: str) -> str:
    blocks = []
    for item in items:
        name = html.escape(item["filename"])
        if item["status"] != "complete":
            blocks.append(
                f'<div class="card"><h2>{name}</h2><p class="badge badge-error">ERROR</p>'
                f'<p style="margin-top:0.75rem;white-space:pre-wrap">{html.escape(item["error"])}</p></div>'
            )
            continue
        summary = item["summary"]
        device = item.get("device") or {}
        blocks.append(
            f'<div class="card"><h2>{name}</h2>'
            f'<p><b>Vendor:</b> {html.escape(str(item.get("vendor", "unknown")))}</p>'
            f'<p><b>Device:</b> {html.escape(str(device.get("device_id", "unknown")))}'
            f' ({html.escape(str(device.get("hostname") or "hostname unavailable"))})</p>'
            f'<p><b>Results:</b> pass={summary.get("pass", 0)}, fail={summary.get("fail", 0)}, '
            f'error={summary.get("error", 0)}, manual={summary.get("manual", 0)}</p>'
            f'<a class="report-link" href="{item["html_url"]}" target="_blank">HTML report</a> '
            f'<a class="report-link" href="{item["pdf_url"]}" target="_blank">PDF report</a> '
            f'<a class="report-link" href="{item["json_url"]}" target="_blank">JSON results</a></div>'
        )
    return PAGE_TEMPLATE.split("<body>", 1)[0] + "<body><div class=\"shell\">" + (
        '<header class="topbar"><div class="brand"><div class="brand-mark">A</div><div><div class="brand-name">Attestor</div><div class="brand-subtitle">Network security compliance</div></div></div><div class="status-pill"><span class="status-dot"></span>Audit complete</div></header>'
        '<section class="hero-copy" style="margin-bottom:22px"><div class="eyebrow">Results workspace</div><h1>Configuration findings, ready to review.</h1>'
        f'<p>Framework view: <b>{html.escape(framework)}</b>. NIST is a mapped view of source-backed deterministic checks.</p></section>'
        + "".join(blocks)
        + '<p><a class="report-link" href="/">Back to audit console</a></p></div></body></html>'
    )


@app.post("/api/network/audit", response_class=HTMLResponse)
async def audit_network_configs(
    files: list[UploadFile] = File(...),
    framework: str = Form("all"),
    vendor: str = Form("cisco_ios"),
):
    if framework not in FRAMEWORK_VIEWS:
        return HTMLResponse("Invalid framework view", status_code=400)
    if not files or len(files) > MAX_NETWORK_FILES:
        return HTMLResponse(
            f"Upload between 1 and {MAX_NETWORK_FILES} configuration files", status_code=400
        )
    if vendor not in {"cisco_ios", "juniper_junos"}:
        return HTMLResponse("Unsupported vendor", status_code=400)
    with tempfile.TemporaryDirectory(prefix="attestor-network-upload-") as temp_name:
        work_dir = Path(temp_name)
        queued = []
        for upload in files:
            record_id = uuid.uuid4().hex[:12]
            display_name = _safe_upload_name(upload.filename)
            DEVICE_RECORDS[record_id] = {
                "record_id": record_id,
                "device_id": Path(display_name).stem,
                "filename": display_name,
                "vendor_key": vendor,
                "vendor": "Juniper" if vendor == "juniper_junos" else "Cisco",
                "platform": "Junos" if vendor == "juniper_junos" else "IOS/IOS-XE",
                "status": "queued",
                "summary": {},
                "controls": [],
                "history": [],
                "last_scan": None,
                "chain_status": "Not chained (local report only)",
            }
            queued.append((upload, record_id))
        items = [await _audit_network_upload(upload, framework, vendor, work_dir, record_id) for upload, record_id in queued]
    _record_network_items(items)
    return HTMLResponse(_network_results_page(items, framework))


def _record_network_items(items: list[dict]) -> None:
    """Promote completed or failed upload results into the local inventory."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for item in items:
        device = item.get("device") or {}
        device_id = str(device.get("device_id") or Path(item.get("filename", "device")).stem)
        queued_record = DEVICE_RECORDS.get(str(item.get("record_id")))
        existing = next((record for record in DEVICE_RECORDS.values() if record is not queued_record and record.get("device_id") == device_id), None)
        record = existing or queued_record or {"record_id": uuid.uuid4().hex[:12], "history": []}
        record.update({
            "device_id": device_id,
            "filename": item.get("filename", "unknown"),
            "vendor_key": item.get("vendor", "unknown"),
            "vendor": device.get("vendor") or record.get("vendor") or item.get("vendor", "unknown"),
            "platform": device.get("platform") or record.get("platform", "unknown"),
            "status": "complete" if item.get("status") == "complete" else "failed",
            "summary": item.get("summary", {}),
            "controls": item.get("controls", []),
            "urls": {key: item[key] for key in ("json_url", "html_url", "pdf_url") if key in item},
            "last_scan": now,
            "config_sha256": device.get("config_sha256"),
            "chain_status": "Not chained (local report only)",
        })
        if item.get("status") != "complete":
            record["error"] = item.get("error", "scan failed")
        summary = item.get("summary", {})
        record.setdefault("history", []).append({"timestamp": now, "pass": summary.get("pass", 0), "fail": summary.get("fail", 0), "error": summary.get("error", 0)})
        if existing and queued_record:
            DEVICE_RECORDS.pop(queued_record["record_id"], None)
        DEVICE_RECORDS[record["record_id"]] = record


@app.get("/console", response_class=HTMLResponse)
async def console(request: Request):
    return HTMLResponse(_console_page(request.query_params.get("search", ""), request.query_params.get("vendor", "all"), request.query_params.get("status", "all")))


@app.get("/console/devices/{record_id}", response_class=HTMLResponse)
async def device_detail(record_id: str):
    record = DEVICE_RECORDS.get(record_id)
    if not record:
        return HTMLResponse("Device record not found", status_code=404)
    return HTMLResponse(_device_detail_page(record))


@app.get("/api/run")
async def run_audit(target: str = "ubuntu2204_desktop", level: int = 1):
    """Run the audit engine and stream results as SSE events."""
    run_id = str(uuid.uuid4())[:8]
    output_path = RESULTS_DIR / f"run_{run_id}.json"
    html_path = RESULTS_DIR / f"run_{run_id}.html"

    # Build engine command based on target
    if "windows" in target:
        # Windows: SSH to the Windows VM and run PowerShell engine
        win_host = "192.168.64.4"
        win_user = "lab"
        win_pass = "lab"
        ps_cmd = (
            f"Set-Location C:\\attestor; "
            f".\\engines\\windows\\run_audit.ps1 "
            f"-RulesDir 'C:\\attestor\\rules\\{target}' "
            f"-Level {level} -Format ndjson -Output 'C:\\attestor\\run_{run_id}.json'"
        )
        cmd = [
            "sshpass", "-p", win_pass,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{win_user}@{win_host}",
            f"powershell -NoProfile -ExecutionPolicy Bypass -Command \"{ps_cmd}\""
        ]
    else:
        # Linux: local subprocess
        cmd = [
            sys.executable, str(REPO_ROOT / "engines" / "linux" / "run_audit.py"),
            "--target", target,
            "--level", str(level),
            "--format", "html",
            "--output", str(output_path),
        ]

    async def event_stream() -> AsyncGenerator[str, None]:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        total = 0
        async for line in process.stdout:
            line = line.decode("utf-8").strip()
            if not line:
                continue
            try:
                check_data = json.loads(line)
                total += 1
                yield f"event: check\ndata: {json.dumps(check_data)}\n\n"
            except json.JSONDecodeError:
                continue

        await process.wait()

        # Completion event
        report_url = f"/reports/run_{run_id}.html" if html_path.exists() else None
        complete_data = {"total": total, "report_url": report_url}
        yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/reports/{filename}")
async def serve_report(filename: str):
    """Serve generated reports without allowing paths outside reports/."""
    file_path = (RESULTS_DIR / Path(filename).name).resolve()
    if file_path.parent != RESULTS_DIR.resolve() or not file_path.exists():
        return HTMLResponse("Report not found", status_code=404)
    media_types = {
        ".html": "text/html",
        ".pdf": "application/pdf",
        ".json": "application/json",
    }
    media_type = media_types.get(file_path.suffix.lower())
    if media_type:
        return FileResponse(file_path, media_type=media_type, filename=file_path.name)
    return HTMLResponse("Report not found", status_code=404)


# ─────────────────────── Entry point ───────────────────────────

if __name__ == "__main__":
    import uvicorn
    print("Attestor GUI starting at http://localhost:8000")
    print("Press Ctrl+C to stop.")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
