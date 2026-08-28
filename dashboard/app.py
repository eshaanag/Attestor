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
import hashlib
import html
import json
import os
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

from report.evidence_bundle import build_evidence_bundle  # noqa: E402
from report.generate_pdf import build_pdf  # noqa: E402
from report.generate_report import render  # noqa: E402
from dashboard.store import DashboardStore  # noqa: E402
from ai.network_discovery import (  # noqa: E402
    CATEGORIES,
    MODEL_DEFAULT,
    ProviderError,
    estimate_cost,
)
from ai.vendor_training import (  # noqa: E402
    classify_patterns,
    collect_training_patterns,
    extract_knowledge_text,
)
from engines.network.custom import CustomProfileError, audit_custom_profile  # noqa: E402

RESULTS_DIR = REPO_ROOT / "reports"
RESULTS_DIR.mkdir(exist_ok=True)
DASHBOARD_DATA_DIR = Path(
    os.environ.get("ATTESTOR_DASHBOARD_DATA_DIR", REPO_ROOT / "dashboard" / "data")
)
STORE = DashboardStore(DASHBOARD_DATA_DIR / "attestor.db")

app = FastAPI(title="Attestor Local GUI", version="0.2.0")
MAX_NETWORK_FILES = 20
MAX_NETWORK_CONFIG_BYTES = 2 * 1024 * 1024
MAX_KNOWLEDGE_SOURCE_BYTES = 5 * 1024 * 1024
FRAMEWORK_VIEWS = {"all", "cis", "nist"}
DEVICE_RECORDS: dict[str, dict] = STORE.load_device_records()

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
body { font-family: "SF Pro Display", "SF Pro Text", "Avenir Next", -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif; background: radial-gradient(circle at 12% 0%, rgba(20, 166, 165, .12), transparent 29%), linear-gradient(145deg, #edf7f8 0%, #f8fbfc 52%, #eaf3f5 100%); color: var(--ink); min-height: 100vh; }
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
body { font-family: "SF Pro Display", "SF Pro Text", "Avenir Next", -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif; }
.panel, .hero-copy, .hero-metric, .result-card { background: rgba(255,255,255,.58); border-color: rgba(255,255,255,.82); box-shadow: 0 17px 42px rgba(38,76,89,.09), inset 0 1px 0 rgba(255,255,255,.95); backdrop-filter: blur(18px) saturate(145%); -webkit-backdrop-filter: blur(18px) saturate(145%); }
@supports not ((backdrop-filter: blur(1px)) or (-webkit-backdrop-filter: blur(1px))) { .panel, .hero-copy, .hero-metric, .result-card { background: #f8fbfc; } }
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
    <div class="field"><label for="network-facts">Optional show version files</label><input id="network-facts" name="facts_files" type="file" accept=".txt,text/plain" multiple></div>
    <div class="field"><label for="framework">Report view</label><select id="framework" name="framework"><option value="all">Source-backed checks with NIST mappings</option><option value="cis">Source-backed controls only</option><option value="nist">NIST SP 800-53 mapped view</option></select></div>
    <div class="form-actions"><button class="button" type="submit">Upload and audit</button></div>
  </form>
  <p class="helper">Files are processed locally in a temporary workspace and discarded after the audit. When supplied, show version files pair with configurations in selection order. AI remediation stays in dry-run mode here.</p>
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
  <a id="report-link" class="report-link" href="#" target="_blank">View full report</a>
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
  btn.textContent = 'Running audit...';
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
    btn.textContent = 'Run live audit';
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
    btn.textContent = 'Run live audit';
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
:root{--ink:#10212b;--ink-soft:#203b49;--muted:#60727d;--line:#d8e4e8;--canvas:#f4f8f9;--surface:#fff;--blue:#0b6b8f;--blue-soft:#e5f3f7;--teal:#16a5a0;--green:#18794e;--amber:#9a6700}
*{box-sizing:border-box;margin:0;padding:0}body{font-family:"SF Pro Display","SF Pro Text","Avenir Next",-apple-system,BlinkMacSystemFont,"Helvetica Neue",sans-serif;background:var(--canvas);color:var(--ink);line-height:1.5}.wrap{max-width:1240px;margin:auto;padding:25px 30px 70px}
/* Liquid-glass material layer: static blur, restrained highlights, local fallback. */
body{background:radial-gradient(circle at 14% 8%,rgba(31,183,187,.19),transparent 28%),radial-gradient(circle at 87% 22%,rgba(41,121,178,.15),transparent 25%),linear-gradient(145deg,#edf7f8 0%,#f8fbfc 48%,#e8f2f5 100%);min-height:100vh;background-attachment:fixed}body:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.23) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.23) 1px,transparent 1px);background-size:46px 46px;mask-image:linear-gradient(to bottom,rgba(0,0,0,.52),transparent 76%)}.wrap{position:relative;z-index:1}.nav{position:relative;padding:10px 12px;border:1px solid rgba(255,255,255,.78);border-radius:14px;background:rgba(255,255,255,.52);box-shadow:0 14px 38px rgba(42,82,94,.09),inset 0 1px 0 rgba(255,255,255,.95);backdrop-filter:blur(18px) saturate(145%);-webkit-backdrop-filter:blur(18px) saturate(145%)}.mark{background:rgba(16,33,43,.9);border:1px solid rgba(255,255,255,.34);box-shadow:0 8px 22px rgba(16,33,43,.2),inset 0 1px 0 rgba(255,255,255,.24)}.navbtn,.primary{background:rgba(16,33,43,.9)!important;border:1px solid rgba(255,255,255,.22);box-shadow:0 12px 24px rgba(16,33,43,.17),inset 0 1px 0 rgba(255,255,255,.23)}.btn{transition:transform .16s ease-out,box-shadow .16s ease-out}.btn:hover{transform:translateY(-1px)}.secondary,.trust,.metric,.card{background:rgba(255,255,255,.55);border-color:rgba(255,255,255,.82);box-shadow:0 17px 42px rgba(42,82,94,.09),inset 0 1px 0 rgba(255,255,255,.95);backdrop-filter:blur(18px) saturate(145%);-webkit-backdrop-filter:blur(18px) saturate(145%)}.topology{border:1px solid rgba(255,255,255,.7);border-radius:26px;background:radial-gradient(circle at 50% 38%,rgba(255,255,255,.76),rgba(255,255,255,.24) 48%,rgba(8,115,143,.08));box-shadow:0 30px 70px rgba(30,88,104,.13),inset 0 1px 0 rgba(255,255,255,.92);backdrop-filter:blur(14px) saturate(135%);-webkit-backdrop-filter:blur(14px) saturate(135%)}.plane{background:rgba(241,252,253,.55);border-color:rgba(255,255,255,.9);box-shadow:0 22px 36px rgba(33,75,88,.15),inset 0 1px 0 #fff}.node{background:rgba(255,255,255,.77);border-color:rgba(255,255,255,.96);box-shadow:8px 11px 0 rgba(13,82,102,.12),0 14px 28px rgba(33,75,88,.15),inset 0 1px 0 #fff;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px)}.n-core{background:rgba(16,33,43,.92);border-color:rgba(255,255,255,.3)}.metric,.card{position:relative;overflow:hidden}.metric:before,.card:before{content:"";position:absolute;inset:0 auto auto 0;width:64%;height:1px;background:linear-gradient(90deg,rgba(255,255,255,.95),transparent)}.trust{margin-bottom:64px}.icon,.pill{background:rgba(222,247,248,.72);border:1px solid rgba(255,255,255,.8)}@supports not ((backdrop-filter:blur(1px)) or (-webkit-backdrop-filter:blur(1px))){.nav,.secondary,.trust,.metric,.card,.topology,.node{background:#f8fbfc}}
/* Base geometry retained explicitly so the glass layer cannot change layout. */
.nav{display:flex;justify-content:space-between;align-items:center}.brand{display:flex;align-items:center;gap:11px}.navlinks{display:flex;gap:22px;align-items:center}.navlinks a{color:var(--muted);font-size:13px;text-decoration:none}.navbtn{color:#fff!important}.hero{display:grid;grid-template-columns:minmax(0,1fr) minmax(450px,.95fr);gap:46px;align-items:center;padding:76px 0 65px}.hero h1{font-size:clamp(40px,5vw,67px);line-height:1.02;max-width:670px;text-wrap:balance}.hero p{color:var(--muted);font-size:17px;max-width:610px;margin-top:21px;text-wrap:pretty}.actions{display:flex;gap:12px;margin-top:29px;flex-wrap:wrap}.btn{display:inline-flex;align-items:center;justify-content:center;text-decoration:none;border-radius:8px;padding:12px 17px;font-size:13px;font-weight:750}.topology{position:relative;min-height:425px;display:grid;place-items:center;perspective:1050px}.scene{position:relative;width:min(100%,520px);height:370px;transform:rotateX(54deg) rotateZ(-24deg);transform-style:preserve-3d}.scene:before{content:"";position:absolute;inset:34px 20px 30px;background:linear-gradient(135deg,#ecf6f8 25%,transparent 25%) 0 0/27px 27px;opacity:.8;border:1px solid #cbdfe5;box-shadow:20px 24px 0 rgba(32,84,99,.08),38px 44px 0 rgba(32,84,99,.05);transform:translateZ(-12px)}.plane{position:absolute;inset:0;transform:translateZ(0)}.link{position:absolute;height:3px;background:var(--teal);transform-origin:left center}.l1{left:20%;top:51%;width:37%;transform:rotate(-23deg)}.l2{left:48%;top:49%;width:34%;transform:rotate(24deg)}.l3{left:46%;top:51%;width:33%;transform:rotate(77deg)}.l4{left:25%;top:52%;width:31%;transform:rotate(65deg)}.node{position:absolute;width:104px;height:72px;padding:10px;border-radius:8px;transform:translateZ(26px);font-size:10px}.node:after{content:"";position:absolute;left:13px;right:13px;bottom:9px;height:4px;background:#e6f3f4;border-radius:3px}.node strong{display:block;font-size:11px}.node span{display:block;color:var(--muted);margin-top:3px}.n-core{left:39%;top:39%;width:118px;height:82px;color:#fff;transform:translateZ(54px)}.n-core span{color:#b8d3da}.n-core:after{background:var(--teal)}.n-edge{left:5%;top:18%}.n-router{right:2%;top:17%}.n-firewall{left:7%;bottom:8%}.n-cloud{right:2%;bottom:8%}.scene-label{position:absolute;right:11px;top:7px;transform:rotateZ(24deg) rotateX(-54deg);font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--blue);font-weight:800}.signal{position:absolute;width:8px;height:8px;border-radius:50%;background:var(--teal);z-index:4}.s1{left:47%;top:47%}.s2{left:73%;top:42%}.trust{padding:22px;border-radius:12px}.trust h2{font-size:16px;margin-bottom:14px}.trustrow{display:flex;gap:12px;padding:12px 0;border-top:1px solid #edf1f3}.trustrow:first-of-type{border-top:0}.icon{width:30px;height:30px;display:grid;place-items:center;border-radius:8px;color:var(--blue);font-weight:800;flex:none}.trustrow strong{display:block;font-size:13px}.trustrow span{display:block;color:var(--muted);font-size:12px;margin-top:2px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:4px 0 65px}.metric{border-radius:10px;padding:17px}.metric strong{display:block;font-size:25px;font-variant-numeric:tabular-nums}.metric span{display:block;color:var(--muted);font-size:11px;margin-top:3px;text-transform:uppercase;letter-spacing:.06em}.metric .accent{color:var(--teal)}.band{border-top:1px solid var(--line);padding-top:28px}.bandhead{display:flex;justify-content:space-between;align-items:end;gap:20px;margin-bottom:18px}.band h2{font-size:21px}.band p{color:var(--muted);font-size:13px}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.card{border-radius:10px;padding:19px;min-height:142px}.card strong{font-size:14px}.card p{color:var(--muted);font-size:12px;margin-top:6px}.pill{display:inline-block;margin-top:14px;border-radius:999px;padding:5px 8px;color:var(--blue);font-size:10px;font-weight:800;text-transform:uppercase}.footer-note{color:var(--muted);font-size:12px;margin-top:23px}@media(max-width:900px){.hero{grid-template-columns:1fr;padding:58px 0 45px}.topology{order:-1;min-height:350px}.metrics{grid-template-columns:repeat(2,1fr);margin-bottom:50px}.cards{grid-template-columns:repeat(2,1fr)}}@media(max-width:620px){.wrap{padding:20px 16px 45px}.navlinks a:not(.navbtn){display:none}.topology{min-height:300px;overflow:hidden}.scene{transform:scale(.78) rotateX(54deg) rotateZ(-24deg)}.cards{grid-template-columns:1fr}.hero h1{font-size:42px}.hero p{font-size:15px}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
</style></head><body><div class="wrap"><nav class="nav"><div class="brand"><div class="mark">A</div><div><strong>Attestor</strong><small>Security compliance operations</small></div></div><div class="navlinks"><a href="#coverage">Coverage</a><a href="#trust">Trust model</a><a class="navbtn" href="/console">Open console</a></div></nav>
<main><section class="hero"><div><div class="eyebrow">Configuration assurance / 2026</div><h1>Turn device state into evidence your organization can defend.</h1><p>Upload a saved configuration, evaluate source-backed controls, and give your team a precise path from finding to remediation—without sending device evidence to a remote dashboard.</p><div class="actions"><a class="btn primary" href="/console">Open audit console</a><a class="btn secondary" href="#coverage">Explore coverage</a></div></div><div class="topology" aria-label="Illustration of a monitored enterprise network"><div class="scene"><div class="plane"></div><div class="scene-label">posture graph / local workspace</div><div class="link l1"></div><div class="link l2"></div><div class="link l3"></div><div class="link l4"></div><div class="signal s1"></div><div class="signal s2"></div><div class="node n-core"><strong>Attestor</strong><span>policy engine</span></div><div class="node n-edge"><strong>Branch edge</strong><span>Cisco IOS</span></div><div class="node n-router"><strong>Core router</strong><span>Junos</span></div><div class="node n-firewall"><strong>Firewall</strong><span>configuration</span></div><div class="node n-cloud"><strong>Reports</strong><span>offline evidence</span></div></div></div></section>
<section class="metrics" aria-label="Verified product scope"><div class="metric"><strong>83</strong><span>Verified controls</span></div><div class="metric"><strong>4</strong><span>Supported targets</span></div><div class="metric"><strong class="accent">100%</strong><span>Offline report ready</span></div><div class="metric"><strong>0</strong><span>Config bytes on-chain</span></div></section>
<aside class="trust" id="trust"><h2>Built for accountable decisions</h2><div class="trustrow"><div class="icon">01</div><div><strong>Deterministic first</strong><span>Schema-validated rules remain authoritative; unknown input fails closed.</span></div></div><div class="trustrow"><div class="icon">02</div><div><strong>Evidence stays local</strong><span>Uploads are processed temporarily. Reports open offline.</span></div></div><div class="trustrow"><div class="icon">03</div><div><strong>AI stays advisory</strong><span>Redacted discovery and cached remediation never override a result.</span></div></div><div class="trustrow"><div class="icon">04</div><div><strong>Hash-only proof</strong><span>Optional Sepolia anchoring publishes report hashes, never configuration.</span></div></div></aside>
<section class="band" id="coverage"><div class="bandhead"><div><h2>Verified coverage</h2><p>Start with controls that have real corpus or VM evidence behind them.</p></div><a class="btn secondary" href="/console">Start a scan</a></div><div class="cards"><div class="card"><strong>Windows 11 Standalone</strong><p>Native PowerShell checks against the verified Level 1 rule pack.</p><span class="pill">30 controls</span></div><div class="card"><strong>Ubuntu 22.04 Desktop</strong><p>Python checks for kernel, sysctl, services, packages, and permissions.</p><span class="pill">35 controls</span></div><div class="card"><strong>Cisco IOS / IOS-XE</strong><p>Flat and block-aware configuration checks with CIS and NIST mappings.</p><span class="pill">14 controls</span></div><div class="card"><strong>Juniper Junos</strong><p>Source-backed vendor baseline for common service and logging controls.</p><span class="pill">4 controls</span></div><div class="card"><strong>Reports</strong><p>Per-device JSON, standalone HTML, and PDF outputs for review and handoff.</p><span class="pill">Offline-ready</span></div><div class="card"><strong>Roadmap</strong><p>Other vendors, broader Junos coverage, live collection, and fleet storage.</p><span class="pill">Clearly scoped</span></div></div><p class="footer-note">Current workspace: local and single-operator. Uploads are discarded after processing; persistent organizations and live collection are roadmap items.</p></section></main></div></body></html>"""

APPLE_GLASS_STYLE = """<style>
html,body,button,input,select{font-family:"SF Pro Text","Avenir Next",-apple-system,BlinkMacSystemFont,"Helvetica Neue",sans-serif!important}
html{background:#087dd7}body{position:relative;min-height:100vh;color:#12202d!important;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;background:radial-gradient(ellipse at 16% 22%,rgba(104,226,255,.94) 0%,rgba(19,154,241,.78) 18%,transparent 42%),radial-gradient(ellipse at 78% 12%,rgba(172,235,255,.74) 0%,rgba(39,132,239,.6) 25%,transparent 48%),radial-gradient(ellipse at 74% 88%,rgba(3,50,190,.92) 0%,rgba(6,98,225,.78) 34%,transparent 62%),linear-gradient(135deg,#83d8fa 0%,#1992ef 35%,#0759cf 68%,#062f9c 100%)!important;background-attachment:fixed!important}body:before{content:"";position:fixed;inset:-18%;z-index:0;pointer-events:none;background:radial-gradient(ellipse at 18% 64%,transparent 0 27%,rgba(195,244,255,.68) 28% 31%,rgba(27,152,238,.42) 32% 40%,transparent 41%),radial-gradient(ellipse at 75% 36%,transparent 0 25%,rgba(174,239,255,.5) 26% 30%,rgba(7,91,213,.42) 31% 41%,transparent 42%);transform:rotate(-9deg);opacity:.88}body:after{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;background:linear-gradient(115deg,rgba(255,255,255,.16),transparent 28%,rgba(255,255,255,.07) 46%,transparent 65%)}.wrap,.shell{position:relative!important;z-index:1!important}
.nav,.topbar,.hero-copy,.hero-metric,.trust,.metric,.card,.panel,.upload,.device-list,.identity,.sum,.result-card{position:relative;background:linear-gradient(135deg,rgba(244,253,255,.66),rgba(211,242,252,.38))!important;border:1px solid rgba(255,255,255,.76)!important;box-shadow:0 28px 70px rgba(0,30,92,.22),inset 0 1px 1px rgba(255,255,255,.98),inset 0 -1px 1px rgba(29,111,166,.12)!important;backdrop-filter:blur(28px) saturate(165%)!important;-webkit-backdrop-filter:blur(28px) saturate(165%)!important}.nav:after,.topbar:after,.hero-copy:after,.trust:after,.panel:after,.upload:after,.identity:after{content:"";position:absolute;inset:1px;border-radius:inherit;pointer-events:none;border-top:1px solid rgba(255,255,255,.86);mask-image:linear-gradient(90deg,#000,transparent 72%)}
.nav,.topbar{min-height:62px;padding-left:88px!important;border-radius:22px!important;background:linear-gradient(135deg,rgba(237,252,255,.68),rgba(199,235,249,.42))!important}.nav:before,.topbar:before{content:"";position:absolute;left:23px;top:25px;width:12px;height:12px;border-radius:50%;background:#ff5f57;box-shadow:20px 0 #febc2e,40px 0 #28c840;z-index:3}.hero-copy,.hero-metric,.trust,.panel,.upload,.device-list,.identity,.result-card{border-radius:22px!important}.metric,.sum,.card{border-radius:18px!important}.topology{border-radius:32px!important;background:linear-gradient(145deg,rgba(226,249,255,.52),rgba(108,190,245,.26))!important;border:1px solid rgba(255,255,255,.7)!important;box-shadow:0 38px 90px rgba(0,35,110,.28),inset 0 1px 1px rgba(255,255,255,.94)!important;backdrop-filter:blur(30px) saturate(170%)!important;-webkit-backdrop-filter:blur(30px) saturate(170%)!important}.plane,.node{background:linear-gradient(145deg,rgba(248,254,255,.82),rgba(170,224,249,.54))!important;border-color:rgba(255,255,255,.86)!important;box-shadow:0 18px 40px rgba(0,50,130,.24),inset 0 1px 1px rgba(255,255,255,.98)!important}.n-core{background:linear-gradient(145deg,rgba(20,83,204,.96),rgba(17,49,158,.94))!important}.link,.signal{background:#eaffff!important;box-shadow:0 0 0 1px rgba(255,255,255,.7),0 0 15px rgba(119,237,255,.9)!important}
.button,.btn,.navbtn{border-radius:999px!important;border:1px solid rgba(255,255,255,.68)!important;background:linear-gradient(180deg,rgba(25,121,234,.95),rgba(5,77,201,.98))!important;color:#fff!important;text-shadow:0 1px 2px rgba(0,28,96,.45);box-shadow:0 9px 22px rgba(0,54,161,.28),inset 0 1px 1px rgba(255,255,255,.48)!important}.button.alt,.secondary,.button-secondary{background:linear-gradient(180deg,rgba(250,254,255,.72),rgba(203,235,248,.55))!important;color:#12344c!important;text-shadow:none;border-color:rgba(255,255,255,.86)!important}.mark,.brand-mark{border-radius:14px!important;background:linear-gradient(145deg,#188df5,#0735b7)!important;border:1px solid rgba(255,255,255,.58)!important;box-shadow:0 12px 28px rgba(0,49,161,.3),inset 0 1px 1px rgba(255,255,255,.52)!important}
input,select{background:linear-gradient(180deg,rgba(251,255,255,.8),rgba(219,242,250,.62))!important;border:1px solid rgba(255,255,255,.88)!important;border-radius:13px!important;color:#132b3d!important;box-shadow:inset 0 1px 1px rgba(255,255,255,.98),0 7px 18px rgba(0,55,124,.1)!important}input::placeholder{color:#506c7d!important;opacity:1}select option{color:#132b3d;background:#effaff}
h1,h2,h3,.brand-name,.brand strong{font-family:"SF Pro Display","Avenir Next",-apple-system,BlinkMacSystemFont,"Helvetica Neue",sans-serif!important}body,button,input,select,p,span,label,a{font-family:"SF Pro Text","Avenir Next",-apple-system,BlinkMacSystemFont,"Helvetica Neue",sans-serif!important}h1{font-weight:720!important}h2,h3{font-weight:680!important}h1,h2{letter-spacing:-.035em!important;text-wrap:balance}h3{letter-spacing:-.018em!important}h1,h2,h3,strong,.brand-name,.brand strong,.device-row strong,.control strong{color:#102a3c!important}p,.sub,.hero-copy p,.panel-kicker,.metric-note,.helper,.muted,.device-row span,.metric small,.card p,.trustrow span,.brand-subtitle,.brand small,.result-evidence,.source,.history span{color:#405b6b!important}label,.field label{color:#18384c!important}a,.nav a,.link,.report-link,details,details summary,.empty a{color:#075fae!important}.eyebrow{color:#0a659d!important}.tag,.pill,.scope-chip{color:#075fae!important;background:rgba(224,249,255,.58)!important;border-color:rgba(255,255,255,.72)!important}.metric strong,.score,.count,.row-score{font-variant-numeric:tabular-nums}.status-pill{color:#38576a!important;background:rgba(231,250,255,.54)!important}.status-bar{color:#075fae!important}.status-bar.complete{color:#0d7043!important}.badge-pass,.control-status.pass,.state.good{color:#0d7043!important}.badge-fail,.control-status.fail,.state.bad{color:#a32621!important}.badge-error,.control-status.error,.state.pending{color:#805400!important}.network-card,.network-card strong,.n-core,.n-core strong{color:#fff!important}.network-card span,.n-core span{color:#d6f4ff!important}.device-row:hover{background:rgba(225,249,255,.5)!important}.list-head{background:rgba(219,244,252,.42)!important}
body:has(.topology) .hero>div:first-child h1,body:has(.topology) .hero>div:first-child p,.workspace-head h1,.workspace-head .sub,.head h1,.head>.muted,.inventory-head h2,.inventory-head p{color:#fff!important;text-shadow:0 2px 18px rgba(0,30,100,.34)}body:has(.topology) .hero>div:first-child .eyebrow,.workspace-head .eyebrow,.head .eyebrow{color:#d9f8ff!important;text-shadow:0 1px 10px rgba(0,38,114,.35)}.inventory-head h2{font-weight:700!important}.inventory-head p,.workspace-head .sub,.head>.muted{color:rgba(235,249,255,.88)!important}.topbar .brand strong,.nav .brand strong,.topbar .brand-name,.nav .brand-name{color:#102a3c!important}.topbar .brand small,.nav .brand small,.topbar .brand-subtitle,.nav .brand-subtitle{color:#536c7a!important}.hash{font-family:"SFMono-Regular",Menlo,Monaco,Consolas,monospace!important}.pass strong,.s-pass .count{color:#087a48!important}.fail strong,.s-fail .count{color:#b12b26!important}.error strong,.s-error .count{color:#8a5a00!important}
/* Containment fixes: glass chrome must never enlarge links or escape its panel. */
body{overflow-x:hidden}.wrap,.shell{width:min(100%,1340px);max-width:100%;overflow:visible}main,section,aside,form,div{min-width:0}.wrap>.nav{display:flex!important}.topbar .nav,a.nav{min-height:0!important;width:auto!important;padding:0!important;margin:0!important;background:transparent!important;border:0!important;border-radius:0!important;box-shadow:none!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important}.topbar .nav:before,.topbar .nav:after,a.nav:before,a.nav:after{display:none!important}.topbar .nav{gap:18px!important;flex-wrap:wrap!important}.topbar a.nav{display:inline-flex!important;align-items:center!important}.topology{overflow:hidden!important;isolation:isolate}.scene{max-width:100%!important}.navlinks,.top-actions,.actions,.filters,.form-actions,.row-summary{flex-wrap:wrap!important}.navlinks a,.top-actions a,.actions a,.button,.btn,.navbtn{max-width:100%}.upload-grid>* ,.filters>* ,.vm-controls>*{min-width:0!important}.upload-grid input,.upload-grid select,.filters input,.filters select,input[type=file]{max-width:100%!important;min-width:0!important}.scope-chip{white-space:normal!important;text-align:center}.device-row>*{min-width:0}.device-row strong,.device-row span,.result-evidence,.source{overflow-wrap:anywhere}.hash{overflow-wrap:anywhere;word-break:break-all}.control-status{max-width:100%}.result-card{overflow:hidden}.report-link{max-width:100%;white-space:normal}.brand{min-width:0}.brand>div:last-child{min-width:0}.brand strong,.brand-name{overflow-wrap:anywhere}
@media(max-width:960px){.list-head{display:none!important}.device-row{grid-template-columns:minmax(0,1fr) 90px!important}.row-summary{grid-column:1/-1}.device-row>div:last-child{text-align:right}.inventory-head{display:block!important}.filters{margin-top:14px!important}.filters input{flex:1 1 220px!important}.filters select{flex:1 1 160px!important}}
@media(max-width:700px){.wrap,.shell{padding-left:14px!important;padding-right:14px!important}.workspace-head,.head,.upload-header,.bandhead{display:block!important}.workspace-head .top-actions,.head .actions,.upload-header .scope-chip,.bandhead .btn{margin-top:14px!important}.metrics,.summary{grid-template-columns:repeat(2,minmax(0,1fr))!important}.hero{grid-template-columns:minmax(0,1fr)!important}.topology{min-height:290px!important}.scene{transform:scale(.72) rotateX(54deg) rotateZ(-24deg)!important}.device-row{grid-template-columns:minmax(0,1fr)!important}.device-row>div:last-child{text-align:left}.row-score,.row-summary{grid-column:1/-1}.filters,.upload-grid,.vm-controls{display:flex!important;flex-direction:column!important;align-items:stretch!important}.filters>* ,.upload-grid>* ,.vm-controls>*{width:100%!important}.topbar{gap:12px!important}.topbar .brand{flex:1 1 180px}.topbar .nav{justify-content:flex-end!important}}
@media(max-width:430px){.metrics,.summary{grid-template-columns:minmax(0,1fr)!important}.navlinks a:not(.navbtn){display:none!important}.hero h1{font-size:38px!important}.topology{min-height:250px!important}.scene{transform:scale(.61) rotateX(54deg) rotateZ(-24deg)!important}.button,.btn,.navbtn{width:100%!important}.top-actions,.actions,.form-actions{display:grid!important;grid-template-columns:minmax(0,1fr)!important;width:100%}.topbar{display:block!important}.topbar .nav{justify-content:flex-start!important;margin-top:12px!important}}
@media(max-width:700px){.nav,.topbar{padding-left:18px!important}.nav:before,.topbar:before{display:none}.hero-copy,.hero-metric,.trust,.panel,.upload,.device-list,.identity,.result-card{border-radius:18px!important}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
@supports not ((backdrop-filter:blur(1px)) or (-webkit-backdrop-filter:blur(1px))){.nav,.topbar,.hero-copy,.hero-metric,.trust,.metric,.card,.panel,.upload,.device-list,.identity,.sum,.result-card{background:#dff4fb!important}}
</style>"""


ENTERPRISE_UI_STYLE = """<style>
:root {
  --ui-ink: #0b1726;
  --ui-ink-soft: #26384b;
  --ui-muted: #5b6b7c;
  --ui-line: rgba(82, 105, 129, .2);
  --ui-line-strong: rgba(60, 84, 110, .32);
  --ui-canvas: #edf2f6;
  --ui-surface: rgba(255, 255, 255, .82);
  --ui-surface-solid: #ffffff;
  --ui-surface-subtle: rgba(246, 249, 252, .88);
  --ui-navy: #10283f;
  --ui-navy-hover: #173b59;
  --ui-blue: #1668b2;
  --ui-blue-soft: #e8f2fb;
  --ui-cyan: #168c9e;
  --ui-green: #157347;
  --ui-red: #b42318;
  --ui-amber: #8a6100;
  --ui-shadow-sm: 0 8px 24px rgba(25, 43, 62, .07);
  --ui-shadow-md: 0 18px 54px rgba(25, 43, 62, .11);
  --ui-focus: 0 0 0 3px rgba(22, 104, 178, .2);
}

html { color-scheme: light; background: var(--ui-canvas); }
html, body, button, input, select, textarea {
  font-family: "Avenir Next", Avenir, "Segoe UI", -apple-system,
    BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif !important;
}
* { letter-spacing: 0 !important; }
body {
  min-height: 100vh;
  overflow-x: hidden;
  color: var(--ui-ink) !important;
  background:
    linear-gradient(rgba(255, 255, 255, .72), rgba(255, 255, 255, .72)),
    linear-gradient(90deg, rgba(79, 107, 133, .055) 1px, transparent 1px),
    linear-gradient(rgba(79, 107, 133, .055) 1px, transparent 1px),
    var(--ui-canvas) !important;
  background-size: auto, 48px 48px, 48px 48px, auto !important;
  background-attachment: fixed !important;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}
body::before, body::after { display: none !important; }
a { color: var(--ui-blue); }
p, .sub, .muted, .helper, .panel-kicker, .metric-note, .field-help,
.device-row span, .profile span, .pattern span, .pattern p, .rule span,
.rule p, .card p, .trustrow span, .history span, .source,
.brand small, .brand-subtitle {
  color: var(--ui-muted) !important;
}
h1, h2, h3, strong, .brand-name, .brand strong, .device-row strong,
.control strong, .metric strong, .score, .row-score {
  color: var(--ui-ink) !important;
}
h1, h2, h3 {
  text-wrap: balance;
  line-height: 1.15;
}
h1 { font-weight: 700 !important; }
h2, h3 { font-weight: 650 !important; }

.wrap, .shell {
  width: min(100%, 1360px) !important;
  max-width: 100% !important;
  margin-inline: auto !important;
  padding: 24px 30px 64px !important;
  position: relative !important;
  z-index: 1 !important;
}
main, section, aside, form, div { min-width: 0; }

.nav, .topbar {
  min-height: 64px;
  display: flex !important;
  align-items: center !important;
  justify-content: space-between !important;
  gap: 20px !important;
  padding: 10px 12px !important;
  margin-bottom: 28px !important;
  border: 1px solid rgba(255, 255, 255, .9) !important;
  border-radius: 12px !important;
  background: rgba(255, 255, 255, .78) !important;
  box-shadow: var(--ui-shadow-sm), inset 0 1px 0 #fff !important;
  backdrop-filter: blur(18px) saturate(130%) !important;
  -webkit-backdrop-filter: blur(18px) saturate(130%) !important;
}
.nav::before, .nav::after, .topbar::before, .topbar::after {
  display: none !important;
}
.brand { display: flex !important; align-items: center !important; gap: 11px !important; }
.mark, .brand-mark {
  width: 40px !important;
  height: 40px !important;
  display: grid !important;
  place-items: center !important;
  flex: 0 0 40px;
  border: 1px solid rgba(255, 255, 255, .16) !important;
  border-radius: 9px !important;
  color: #fff !important;
  background: var(--ui-navy) !important;
  box-shadow: 0 8px 20px rgba(16, 40, 63, .2) !important;
}
.brand strong, .brand-name { display: block; font-size: 16px !important; font-weight: 700 !important; }
.brand small, .brand-subtitle { display: block; margin-top: 1px; font-size: 11px !important; }
.navlinks, .topbar .nav, .navlinks, .top-actions, .actions, .filters,
.form-actions, .row-summary {
  display: flex !important;
  align-items: center !important;
  gap: 10px !important;
  flex-wrap: wrap !important;
}
.topbar .nav, a.nav {
  width: auto !important;
  min-height: 0 !important;
  margin: 0 !important;
  padding: 0 !important;
  border: 0 !important;
  border-radius: 0 !important;
  background: transparent !important;
  box-shadow: none !important;
  backdrop-filter: none !important;
  -webkit-backdrop-filter: none !important;
}
.nav a, .topbar .nav a, .navlinks a {
  min-height: 40px;
  display: inline-flex !important;
  align-items: center !important;
  padding: 0 10px !important;
  border-radius: 7px;
  color: var(--ui-muted) !important;
  font-size: 12px !important;
  font-weight: 650 !important;
  text-decoration: none !important;
  transition: background-color .18s ease, color .18s ease;
}
.nav a:hover, .topbar .nav a:hover, .navlinks a:hover,
.nav a.active, .topbar .nav a.active {
  color: var(--ui-ink) !important;
  background: rgba(16, 40, 63, .065) !important;
}
.navbtn { color: #fff !important; background: var(--ui-navy) !important; }

.button, .btn, .navbtn, .report-link {
  min-height: 44px;
  max-width: 100%;
  display: inline-flex !important;
  align-items: center !important;
  justify-content: center !important;
  gap: 8px !important;
  padding: 10px 15px !important;
  border: 1px solid var(--ui-navy) !important;
  border-radius: 8px !important;
  color: #fff !important;
  background: var(--ui-navy) !important;
  box-shadow: 0 7px 18px rgba(16, 40, 63, .16) !important;
  text-shadow: none !important;
  text-decoration: none !important;
  font-size: 12px !important;
  font-weight: 700 !important;
  cursor: pointer;
  transition: background-color .18s ease, border-color .18s ease,
    box-shadow .18s ease, transform .18s ease;
}
.button:hover, .btn:hover, .navbtn:hover, .report-link:hover {
  color: #fff !important;
  background: var(--ui-navy-hover) !important;
  border-color: var(--ui-navy-hover) !important;
  box-shadow: 0 10px 22px rgba(16, 40, 63, .2) !important;
  transform: translateY(-1px);
}
.button.alt, .button-secondary, .secondary {
  color: var(--ui-navy) !important;
  background: rgba(255, 255, 255, .82) !important;
  border-color: var(--ui-line-strong) !important;
  box-shadow: 0 5px 15px rgba(25, 43, 62, .07) !important;
}
.button.alt:hover, .button-secondary:hover, .secondary:hover {
  color: var(--ui-navy) !important;
  background: #fff !important;
  border-color: rgba(16, 40, 63, .42) !important;
}
.button:disabled { opacity: .58; cursor: not-allowed; transform: none; }

input, select, textarea {
  width: 100%;
  min-width: 0;
  min-height: 44px;
  padding: 10px 12px !important;
  border: 1px solid var(--ui-line-strong) !important;
  border-radius: 8px !important;
  color: var(--ui-ink) !important;
  background: rgba(255, 255, 255, .9) !important;
  box-shadow: inset 0 1px 2px rgba(25, 43, 62, .035) !important;
  font-size: 13px !important;
}
input[type=file] { padding: 8px !important; max-width: 100%; }
textarea { min-height: 112px; resize: vertical; }
input::placeholder, textarea::placeholder { color: #718092 !important; opacity: 1; }
button:focus-visible, a:focus-visible, input:focus-visible, select:focus-visible,
textarea:focus-visible, summary:focus-visible {
  outline: 2px solid var(--ui-blue) !important;
  outline-offset: 2px !important;
  box-shadow: var(--ui-focus) !important;
}
label { color: var(--ui-ink-soft) !important; font-size: 12px !important; font-weight: 700 !important; }

.panel, .upload, .device-list, .identity, .sum, .result-card, .trust,
.metric, .card, .hero-copy, .hero-metric, .pattern {
  border: 1px solid rgba(255, 255, 255, .92) !important;
  background: var(--ui-surface) !important;
  box-shadow: var(--ui-shadow-sm), inset 0 1px 0 #fff !important;
  backdrop-filter: blur(16px) saturate(120%) !important;
  -webkit-backdrop-filter: blur(16px) saturate(120%) !important;
}
.panel, .upload, .device-list, .identity, .result-card, .hero-copy,
.hero-metric, .trust, .pattern { border-radius: 12px !important; }
.metric, .sum, .card { border-radius: 10px !important; }
.panel, .upload, .identity, .result-card { padding: 22px !important; }
.panel::after, .upload::after, .identity::after, .hero-copy::after,
.topbar::after, .nav::after { display: none !important; }

.eyebrow {
  color: var(--ui-blue) !important;
  font-size: 10px !important;
  font-weight: 800 !important;
  letter-spacing: .1em !important;
  text-transform: uppercase;
}
.tag, .pill, .scope-chip, .status-pill {
  border: 1px solid rgba(22, 104, 178, .18) !important;
  border-radius: 999px !important;
  color: #175c92 !important;
  background: rgba(232, 242, 251, .86) !important;
  box-shadow: none !important;
}
.state, .badge, .control-status {
  border: 1px solid transparent;
  font-weight: 800 !important;
}
.state.good, .badge-pass, .control-status.pass {
  color: var(--ui-green) !important;
  background: #e8f5ee !important;
  border-color: #c8e5d4 !important;
}
.state.bad, .badge-fail, .control-status.fail {
  color: var(--ui-red) !important;
  background: #fdeeed !important;
  border-color: #f2cfcb !important;
}
.state.pending, .badge-error, .control-status.error {
  color: var(--ui-amber) !important;
  background: #fff5db !important;
  border-color: #eadcae !important;
}

/* Landing page */
body:has(.topology) { background: #f2f5f8 !important; }
body:has(.topology) .wrap { max-width: 1280px !important; }
body:has(.topology) .nav { position: sticky; top: 16px; z-index: 20; }
body:has(.topology) .hero {
  min-height: min(720px, calc(100vh - 112px));
  display: grid !important;
  grid-template-columns: minmax(0, 1.02fr) minmax(460px, .98fr) !important;
  align-items: center !important;
  gap: 54px !important;
  padding: 62px 0 54px !important;
}
body:has(.topology) .hero h1 {
  max-width: 700px;
  color: var(--ui-ink) !important;
  font-size: clamp(42px, 5.2vw, 70px) !important;
  line-height: 1.01 !important;
}
body:has(.topology) .hero p {
  max-width: 640px;
  color: var(--ui-muted) !important;
  font-size: 17px !important;
  line-height: 1.68 !important;
}
.topology {
  min-height: 450px !important;
  overflow: hidden !important;
  isolation: isolate;
  border: 0 !important;
  border-radius: 0 !important;
  background: transparent !important;
  box-shadow: none !important;
  backdrop-filter: none !important;
  -webkit-backdrop-filter: none !important;
}
.topology::before {
  content: "";
  position: absolute;
  inset: 9% 4% 7%;
  z-index: -1;
  border: 1px solid rgba(255, 255, 255, .95);
  border-radius: 28px;
  background: linear-gradient(145deg, rgba(255,255,255,.78), rgba(222,233,242,.55));
  box-shadow: var(--ui-shadow-md), inset 0 1px 0 #fff;
}
.scene { max-width: 100% !important; animation: ui-float 7s ease-in-out infinite; }
.plane, .node {
  border-color: rgba(255, 255, 255, .95) !important;
  background: rgba(255, 255, 255, .88) !important;
  box-shadow: 10px 14px 0 rgba(16, 40, 63, .07), 0 18px 34px rgba(25, 43, 62, .13) !important;
}
.n-core {
  color: #fff !important;
  background: var(--ui-navy) !important;
}
.n-core strong { color: #fff !important; }
.n-core span { color: #c5d4e2 !important; }
.link, .signal { background: var(--ui-cyan) !important; box-shadow: none !important; }
.trustrow .icon {
  width: 34px !important;
  height: 34px !important;
  border: 1px solid rgba(22, 104, 178, .15) !important;
  border-radius: 8px !important;
  color: var(--ui-blue) !important;
  background: var(--ui-blue-soft) !important;
}
.metrics { gap: 12px !important; }
.metric { min-height: 108px; }
.cards { gap: 14px !important; }
.card { min-height: 154px !important; }
.card:hover { border-color: rgba(22, 104, 178, .26) !important; box-shadow: var(--ui-shadow-md) !important; }

/* Console and operational pages */
.workspace-head, .head, .inventory-head, .upload-header, .bandhead {
  color: var(--ui-ink) !important;
}
.workspace-head h1, .head h1, .inventory-head h2, .workspace-head .sub,
.head > .muted, .inventory-head p {
  color: inherit !important;
  text-shadow: none !important;
}
.overview { gap: 14px !important; }
.upload-grid {
  grid-template-columns: 180px 210px minmax(210px, 1fr) minmax(210px, 1fr) auto !important;
}
.network-card {
  overflow: hidden;
  border: 1px solid rgba(255, 255, 255, .12) !important;
  border-radius: 10px !important;
  color: #fff !important;
  background: linear-gradient(145deg, #10283f, #173b59) !important;
  box-shadow: 0 16px 36px rgba(16, 40, 63, .18) !important;
}
.network-card strong { color: #fff !important; }
.network-card span { color: #c6d7e5 !important; }
.network-nodes i { background: #6dd1d8 !important; }
.device-list { overflow: hidden; }
.inventory-head {
  display: grid !important;
  grid-template-columns: minmax(260px, .8fr) minmax(560px, 1.2fr) !important;
  align-items: end !important;
  gap: 24px !important;
}
.filters {
  display: grid !important;
  grid-template-columns: minmax(190px, 1.3fr) minmax(130px, .8fr)
    minmax(130px, .8fr) auto !important;
  align-items: end !important;
}
.filters > * { min-width: 0 !important; width: 100% !important; }
.filters .button { width: auto !important; }
.list-head { color: var(--ui-muted) !important; background: #f4f7fa !important; }
.device-row {
  min-height: 74px;
  transition: background-color .18s ease, box-shadow .18s ease !important;
}
.device-row:hover {
  transform: none !important;
  background: #f5f9fc !important;
  box-shadow: inset 3px 0 0 var(--ui-blue);
}
.device-icon, .empty-icon {
  border: 1px solid rgba(22, 104, 178, .16) !important;
  border-radius: 8px !important;
  color: var(--ui-blue) !important;
  background: var(--ui-blue-soft) !important;
}
.row-score, .metric strong, .score, .count { font-variant-numeric: tabular-nums; }
.mini-pass { color: var(--ui-green) !important; }
.mini-fail { color: var(--ui-red) !important; }
.hash, code {
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace !important;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.control, .rule, .pattern, .training-row, .profile, .history > div {
  transition: background-color .18s ease, border-color .18s ease;
}
.control:hover, .rule:hover, .pattern:hover, .training-row:hover,
.profile:hover { background-color: rgba(244, 248, 251, .8) !important; }
.training-row, .profile { min-height: 68px; }
.notice {
  border: 1px solid rgba(22, 104, 178, .18) !important;
  border-radius: 8px !important;
  color: var(--ui-ink-soft) !important;
  background: var(--ui-blue-soft) !important;
}
.status-bar { color: #175c92 !important; background: var(--ui-blue-soft) !important; }
.status-bar.complete { color: var(--ui-green) !important; background: #e8f5ee !important; }
.result-card { overflow: hidden; }
.report-link { margin-top: 12px !important; }
.result-evidence, .source, .device-row strong, .device-row span {
  overflow-wrap: anywhere;
}

@keyframes ui-float {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-7px); }
}

@media (max-width: 1024px) {
  body:has(.topology) .hero {
    grid-template-columns: minmax(0, 1fr) minmax(390px, .85fr) !important;
    gap: 28px !important;
  }
  .list-head { display: none !important; }
  .device-row { grid-template-columns: minmax(0, 1fr) 96px !important; }
  .row-summary { grid-column: 1 / -1; }
  .inventory-head { display: block !important; }
  .filters {
    grid-template-columns: minmax(180px, 1.2fr) minmax(130px, .8fr)
      minmax(130px, .8fr) auto !important;
    margin-top: 14px;
  }
}

@media (max-width: 820px) {
  .wrap, .shell { padding: 18px 18px 48px !important; }
  .nav, .topbar { align-items: flex-start !important; }
  .topbar .nav, .navlinks { justify-content: flex-end; }
  body:has(.topology) .hero {
    min-height: auto;
    grid-template-columns: minmax(0, 1fr) !important;
    padding: 38px 0 44px !important;
  }
  .topology { order: -1; min-height: 340px !important; }
  .scene { transform: scale(.83) rotateX(54deg) rotateZ(-24deg) !important; }
  .metrics, .summary { grid-template-columns: repeat(2, minmax(0, 1fr)) !important; }
  .cards { grid-template-columns: repeat(2, minmax(0, 1fr)) !important; }
  .workspace-head, .head, .upload-header, .bandhead { display: block !important; }
  .workspace-head .top-actions, .head .actions, .upload-header .scope-chip,
  .bandhead .btn { margin-top: 14px !important; }
  .filters, .upload-grid, .vm-controls { align-items: stretch !important; }
  .upload-grid { grid-template-columns: repeat(2, minmax(0, 1fr)) !important; }
}

@media (max-width: 620px) {
  .wrap, .shell { padding: 14px 12px 40px !important; }
  .nav, .topbar { display: block !important; }
  .navlinks, .topbar .nav { justify-content: flex-start !important; margin-top: 10px !important; }
  .navlinks a:not(.navbtn) { display: none !important; }
  .topbar .nav a { min-height: 38px; padding-inline: 8px !important; }
  body:has(.topology) .hero h1 { font-size: 40px !important; }
  body:has(.topology) .hero p { font-size: 16px !important; }
  .topology { min-height: 285px !important; }
  .scene { transform: scale(.68) rotateX(54deg) rotateZ(-24deg) !important; }
  .cards, .metrics, .summary { grid-template-columns: minmax(0, 1fr) !important; }
  .button, .btn, .navbtn { width: 100%; }
  .top-actions, .actions, .form-actions { width: 100%; display: grid !important; }
  .filters, .upload-grid, .vm-controls, .confirm-form, .two {
    display: flex !important;
    flex-direction: column !important;
    align-items: stretch !important;
  }
  .filters > *, .upload-grid > *, .vm-controls > *, .confirm-form > *, .two > * {
    width: 100% !important;
    flex: 0 0 auto !important;
  }
  .filters .button { width: 100% !important; }
  .device-row { grid-template-columns: minmax(0, 1fr) !important; }
  .device-row > div:last-child { text-align: left !important; }
  .row-score, .row-summary { grid-column: 1 / -1; }
  .training-row, .profile, .pattern-head { display: block !important; }
  .training-row > div:last-child, .profile > div:last-child {
    margin-top: 9px;
    text-align: left !important;
  }
  .training-row .state, .profile .state { margin-left: 0 !important; }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: .01ms !important;
    animation-iteration-count: 1 !important;
    scroll-behavior: auto !important;
    transition-duration: .01ms !important;
  }
}

@supports not ((backdrop-filter: blur(1px)) or (-webkit-backdrop-filter: blur(1px))) {
  .nav, .topbar, .panel, .upload, .device-list, .identity, .sum,
  .result-card, .trust, .metric, .card, .hero-copy, .hero-metric, .pattern {
    background: var(--ui-surface-solid) !important;
  }
}
</style>"""


def _apple_glass(page: str) -> str:
    """Apply the shared presentation layer without changing page behavior."""
    return page.replace("</head>", ENTERPRISE_UI_STYLE + "</head>", 1)


# ─────────────────────── Routes ───────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    return _apple_glass(LANDING_TEMPLATE)


@app.get("/local-audit", response_class=HTMLResponse)
async def local_audit():
    """Expose the established Windows/Linux VM workflow without changing it."""
    return _apple_glass(PAGE_TEMPLATE)


def _format_time(value: str | None) -> str:
    if not value:
        return "Not scanned"
    return value.replace("T", " ").replace("Z", " UTC")


def _training_page(message: str = "") -> str:
    sessions = STORE.list_training_sessions()
    session_rows = "".join(
        f'<a class="training-row" href="/training/{html.escape(item["session_id"])}">'
        f'<div><strong>{html.escape(item["vendor"])} · {html.escape(item["platform"])}</strong>'
        f'<span>{html.escape(item["filename"])} · {_format_time(item["created_at"])}</span></div>'
        f'<div><span class="state {"good" if item["status"] == "confirmed" else "pending"}">'
        f'{html.escape(item["status"])}</span><span>{item["confirmed_count"]}/{item["pattern_count"]} confirmed</span></div></a>'
        for item in sessions
    ) or '<div class="empty"><strong>No training sessions yet</strong><span>Analyze an unfamiliar genuine configuration to start.</span></div>'
    notice = f'<div class="notice">{html.escape(message)}</div>' if message else ""
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Attestor | Training Studio</title><style>
:root{{--ink:#102a3c;--muted:#526d7d;--green:#0d7043;--amber:#805400}}*{{box-sizing:border-box}}body{{margin:0}}.shell{{max-width:1180px;margin:auto;padding:25px 28px 60px}}.topbar,.head,.training-grid,.training-row{{display:flex;justify-content:space-between;gap:18px}}.topbar{{align-items:center;margin-bottom:28px;padding:10px 12px}}.brand{{display:flex;align-items:center;gap:11px}}.mark{{width:38px;height:38px;display:grid;place-items:center;color:white;font-weight:800}}.brand strong,.brand small{{display:block}}.brand small,.sub,.field-help,.training-row span,.empty span{{color:var(--muted);font-size:12px}}.nav{{display:flex;gap:16px;align-items:center}}.nav a{{text-decoration:none;font-size:12px;font-weight:750}}.head{{align-items:end;margin-bottom:20px}}.eyebrow{{font-size:11px;font-weight:800;text-transform:uppercase;margin-bottom:8px}}h1{{margin:0;font-size:36px}}.sub{{margin:8px 0 0}}.training-grid{{align-items:start}}.panel{{padding:22px;flex:1}}.panel h2{{margin:0;font-size:18px}}.panel p{{line-height:1.5}}label{{display:block;font-size:12px;font-weight:750;margin:15px 0 6px}}input,select{{width:100%;padding:11px 12px}}input[type=file]{{padding:9px}}.button{{display:inline-flex;align-items:center;justify-content:center;margin-top:18px;padding:11px 15px;text-decoration:none;cursor:pointer}}.field-help{{display:block;margin-top:7px}}.notice{{padding:12px 14px;margin-bottom:16px;border:1px solid rgba(255,255,255,.75);border-radius:14px;background:rgba(255,255,255,.55);color:var(--ink)}}.training-list{{display:grid;gap:9px;margin-top:15px}}.training-row{{align-items:center;text-decoration:none;padding:13px;border-bottom:1px solid rgba(255,255,255,.48)}}.training-row strong,.training-row span{{display:block}}.training-row>div:last-child{{text-align:right}}.state{{display:inline-block!important;width:max-content;padding:4px 7px;border-radius:999px;text-transform:uppercase;font-size:9px!important;font-weight:800;margin-left:auto}}.state.good{{background:#e7f6ed;color:var(--green)}}.state.pending{{background:#fff5d7;color:var(--amber)}}.empty{{padding:24px;text-align:center}}.empty strong,.empty span{{display:block}}@media(max-width:760px){{.training-grid,.head{{display:block}}.training-grid .panel+.panel{{margin-top:14px}}.topbar{{display:block}}.nav{{margin-top:12px;flex-wrap:wrap}}}}
</style></head><body><div class="shell"><header class="topbar"><div class="brand"><div class="mark">A</div><div><strong>Attestor</strong><small>AI-assisted vendor onboarding</small></div></div><nav class="nav"><a href="/console">Console</a><a href="/training">Training Studio</a><a href="/">Overview</a></nav></header><main><section class="head"><div><div class="eyebrow">Human-in-the-loop adaptation</div><h1>Training Studio</h1><p class="sub">Teach Attestor unfamiliar syntax without converting an AI guess into a compliance result.</p></div></section>{notice}<div class="training-grid"><section class="panel"><h2>Analyze unfamiliar syntax</h2><p class="sub">The configuration is processed temporarily. Only its SHA-256 and redacted normalized patterns are persisted.</p><form action="/api/training/analyze" method="post" enctype="multipart/form-data"><label for="training-vendor">Vendor</label><input id="training-vendor" name="vendor" placeholder="Example Networks" required maxlength="100"><label for="training-platform">Platform / OS</label><input id="training-platform" name="platform" placeholder="ExampleOS 1.x" required maxlength="100"><label for="training-config">Configuration file</label><input id="training-config" name="config_file" type="file" accept=".txt,.cfg,.conf,text/plain" required><span class="field-help">Maximum 2 MiB. UTF-8 text only.</span><label for="knowledge-file">Vendor documentation (optional)</label><input id="knowledge-file" name="knowledge_file" type="file" accept=".txt,.md,.rst,.pdf,text/plain,application/pdf"><span class="field-help">Text or PDF, maximum 5 MiB. A redacted excerpt and source hash are retained.</span><button class="button" type="submit">Analyze in dry-run mode</button></form></section><section class="panel"><h2>Review queue</h2><p class="sub">Confirmed mappings are reused for the same vendor and platform without another provider call.</p><div class="training-list">{session_rows}</div></section></div></main></div></body></html>"""


def _training_session_page(session: dict, message: str = "") -> str:
    pattern_rows = []
    for item in session.get("patterns", []):
        category_options = "".join(
            f'<option value="{category}" {"selected" if category == item["category"] else ""}>{category}</option>'
            for category in CATEGORIES
        )
        state = "Confirmed" if item["confirmed"] else "Review required"
        form = "" if item["structural"] else f'''<form class="confirm-form" action="/training/{html.escape(session["session_id"])}/patterns/{html.escape(item["pattern_hash"])}/confirm" method="post"><select name="category" aria-label="Security category">{category_options}</select><input name="note" value="{html.escape(item.get("note", ""))}" placeholder="Evidence or correction note" maxlength="500"><button class="button" type="submit">Confirm mapping</button></form>'''
        pattern_rows.append(
            f'<article class="pattern"><div class="pattern-head"><div><strong>{html.escape(item["pattern"])}</strong>'
            f'<span>{item["occurrence_count"]} occurrence(s) · {html.escape(item["source"])} · {html.escape(item["mode"])}</span></div>'
            f'<span class="state {"good" if item["confirmed"] else "pending"}">{state}</span></div>'
            f'<p>{html.escape(item["reasoning"])}</p>{form}</article>'
        )
    notice = f'<div class="notice">{html.escape(message)}</div>' if message else ""
    source_note = "Vendor document attached" if session.get("source_id") else "No vendor document attached"
    ai_candidates = [
        item for item in session.get("patterns", [])
        if not item["structural"]
        and not item["confirmed"]
        and item.get("source") not in {"provider", "human_confirmed"}
    ]
    estimate = estimate_cost(len(ai_candidates))
    api_runs = session.get("api_runs", [])
    total_calls = sum(int(item.get("call_count", 0)) for item in api_runs)
    total_cost = sum(float(item.get("cost_usd", 0.0)) for item in api_runs)
    api_panel = ""
    if ai_candidates:
        key_state = "API key configured" if os.environ.get("ANTHROPIC_API_KEY") else "API key not configured"
        api_panel = f'''<section class="pattern"><h2>AI suggestion budget</h2><p>{len(ai_candidates)} redacted, unconfirmed pattern(s) are eligible. Estimated Haiku-tier cost: <strong>${estimate["estimated_usd"]:.4f}</strong> ({estimate["input_tokens"]} input + {estimate["output_tokens"]} output tokens). {key_state}.</p><p>No raw configuration is available to this action. Suggestions remain unconfirmed until a human accepts or corrects them.</p><form class="confirm-form" action="/training/{html.escape(session["session_id"])}/classify" method="post"><input name="max_calls" type="number" min="1" max="200" value="{len(ai_candidates)}" required aria-label="Maximum provider calls"><button class="button" type="submit">Run budget-capped AI suggestions</button></form></section>'''
    elif api_runs:
        api_panel = f'''<section class="pattern"><h2>AI suggestion accounting</h2><p>No uncached patterns remain. Recorded real calls: <strong>{total_calls}</strong>; recorded cost: <strong>${total_cost:.6f}</strong>. Human confirmation is still required.</p></section>'''
    profile_form = ""
    if session.get("source_id"):
        profile_form = f'''<section class="pattern"><h2>Create a reusable vendor profile</h2><p>Creates an organization-defined draft. It cannot be audited until at least one confirmed, source-referenced rule is added and the profile is explicitly published.</p><form class="confirm-form" action="/training/{html.escape(session["session_id"])}/profiles" method="post"><input name="name" placeholder="Organization baseline name" required maxlength="120"><button class="button" type="submit">Create draft profile</button></form></section>'''
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Attestor | Training review</title><style>
:root{{--ink:#102a3c;--muted:#526d7d;--green:#0d7043;--amber:#805400}}*{{box-sizing:border-box}}body{{margin:0}}.shell{{max-width:1120px;margin:auto;padding:25px 28px 60px}}.topbar,.pattern-head,.confirm-form{{display:flex;justify-content:space-between;gap:14px}}.topbar{{align-items:center;margin-bottom:26px;padding:10px 12px}}.brand{{display:flex;align-items:center;gap:11px}}.mark{{width:38px;height:38px;display:grid;place-items:center;color:white;font-weight:800}}.brand strong,.brand small,.pattern strong,.pattern span{{display:block}}.brand small,.muted,.pattern span,.pattern p{{color:var(--muted);font-size:12px}}.nav{{display:flex;gap:16px}}.nav a{{text-decoration:none;font-size:12px;font-weight:750}}h1{{margin:6px 0;font-size:34px}}.eyebrow{{font-size:11px;font-weight:800;text-transform:uppercase}}.summary-strip{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:20px 0}}.metric{{padding:14px}}.metric strong,.metric span{{display:block}}.metric strong{{font-size:20px}}.metric span{{color:var(--muted);font-size:10px;text-transform:uppercase}}.notice{{padding:12px 14px;margin:15px 0;border-radius:14px;background:rgba(255,255,255,.55)}}.pattern-list{{display:grid;gap:12px}}.pattern{{padding:18px;border-radius:20px;background:rgba(238,251,255,.58);border:1px solid rgba(255,255,255,.76);box-shadow:0 20px 48px rgba(0,38,105,.14);backdrop-filter:blur(24px) saturate(160%)}}.pattern strong{{overflow-wrap:anywhere}}.pattern p{{margin:9px 0 0}}.state{{display:inline-block!important;width:max-content;height:max-content;padding:5px 8px;border-radius:999px;text-transform:uppercase;font-size:9px!important;font-weight:800}}.state.good{{background:#e7f6ed;color:var(--green)}}.state.pending{{background:#fff5d7;color:var(--amber)}}.confirm-form{{margin-top:13px;align-items:center}}.confirm-form select{{flex:0 0 180px}}.confirm-form input{{flex:1}}input,select{{min-width:0;padding:10px 11px}}.button{{padding:10px 13px;cursor:pointer}}@media(max-width:720px){{.topbar,.pattern-head,.confirm-form{{display:block}}.nav{{margin-top:12px;flex-wrap:wrap}}.summary-strip{{grid-template-columns:1fr}}.confirm-form>*{{width:100%;margin-top:8px}}}}
</style></head><body><div class="shell"><header class="topbar"><div class="brand"><div class="mark">A</div><div><strong>Attestor</strong><small>Training review</small></div></div><nav class="nav"><a href="/training">All sessions</a><a href="/profiles">Vendor profiles</a><a href="/console">Console</a></nav></header><main><div class="eyebrow">Unfamiliar syntax review</div><h1>{html.escape(session["vendor"])} · {html.escape(session["platform"])}</h1><p class="muted">{html.escape(session["filename"])} · {source_note} · status {html.escape(session["status"])}</p>{notice}<section class="summary-strip"><div class="metric"><strong>{len(session.get("patterns", []))}</strong><span>Unique redacted patterns</span></div><div class="metric"><strong>{sum(1 for item in session.get("patterns", []) if item["confirmed"])}</strong><span>Confirmed or structural</span></div><div class="metric"><strong>0</strong><span>Compliance results changed</span></div></section><section class="pattern-list">{api_panel}{profile_form}{''.join(pattern_rows)}</section></main></div></body></html>"""


def _profiles_page(message: str = "") -> str:
    profiles = STORE.list_vendor_profiles()
    rows = "".join(
        f'<a class="profile" href="/profiles/{html.escape(item["profile_id"])}"><div><strong>{html.escape(item["name"])}</strong><span>{html.escape(item["vendor"])} · {html.escape(item["platform"])}</span></div><div><span class="state {"good" if item["status"] == "published" else "pending"}">{html.escape(item["status"])}</span><span>{item["rule_count"]} rule(s)</span></div></a>'
        for item in profiles
    ) or '<div class="empty"><strong>No vendor profiles</strong><span>Create one from a training session with an attached source document.</span></div>'
    notice = f'<div class="notice">{html.escape(message)}</div>' if message else ""
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Attestor | Vendor profiles</title><style>
:root{{--muted:#526d7d;--green:#0d7043;--amber:#805400}}*{{box-sizing:border-box}}body{{margin:0}}.shell{{max-width:1020px;margin:auto;padding:25px 28px 60px}}.topbar,.profile{{display:flex;justify-content:space-between;gap:16px}}.topbar{{align-items:center;padding:10px 12px;margin-bottom:28px}}.brand{{display:flex;gap:11px;align-items:center}}.mark{{width:38px;height:38px;display:grid;place-items:center;color:white;font-weight:800}}.brand strong,.brand small,.profile strong,.profile span{{display:block}}.brand small,.sub,.profile span,.empty span{{font-size:12px;color:var(--muted)}}.nav{{display:flex;gap:16px}}.nav a{{text-decoration:none;font-size:12px;font-weight:750}}h1{{font-size:36px;margin:5px 0}}.eyebrow{{font-size:11px;font-weight:800;text-transform:uppercase}}.panel{{padding:20px;margin-top:20px}}.profile{{align-items:center;padding:16px;text-decoration:none;border-bottom:1px solid rgba(255,255,255,.45)}}.profile>div:last-child{{text-align:right}}.state{{display:inline-block!important;width:max-content;margin-left:auto;padding:5px 8px;border-radius:999px;text-transform:uppercase;font-size:9px!important;font-weight:800}}.state.good{{background:#e7f6ed;color:var(--green)}}.state.pending{{background:#fff5d7;color:var(--amber)}}.notice{{padding:12px 14px;border-radius:14px;background:rgba(255,255,255,.55)}}.empty{{padding:30px;text-align:center}}.empty strong,.empty span{{display:block}}@media(max-width:620px){{.topbar,.profile{{display:block}}.nav{{margin-top:12px;flex-wrap:wrap}}.profile>div:last-child{{text-align:left;margin-top:8px}}.state{{margin-left:0}}}}
</style></head><body><div class="shell"><header class="topbar"><div class="brand"><div class="mark">A</div><div><strong>Attestor</strong><small>Organization-defined adapters</small></div></div><nav class="nav"><a href="/training">Training Studio</a><a href="/console">Console</a></nav></header><main><div class="eyebrow">Low-code vendor onboarding</div><h1>Vendor profiles</h1><p class="sub">Published profiles can audit exact redacted line patterns. They remain organization-defined, not Attestor-verified vendor benchmarks.</p>{notice}<section class="panel">{rows}</section></main></div></body></html>"""


def _profile_page(profile: dict, message: str = "") -> str:
    confirmed = STORE.list_confirmed_patterns(profile["vendor"], profile["platform"])
    used_hashes = {rule["pattern_hash"] for rule in profile.get("rules", [])}
    options = "".join(
        f'<option value="{html.escape(item["pattern_hash"])}">{html.escape(item["pattern"])} · {html.escape(item["category"])}</option>'
        for item in confirmed if item["pattern_hash"] not in used_hashes
    )
    rule_rows = "".join(
        f'<article class="rule"><div><strong>{html.escape(rule["title"])}</strong><span>{html.escape(rule["category"])} · secure when {html.escape(rule["secure_when"])} · {html.escape(rule["severity"])} severity</span></div><code>{html.escape(rule["pattern"])}</code><p>{html.escape(rule["source_reference"])}</p></article>'
        for rule in profile.get("rules", [])
    ) or '<div class="empty">No rules yet. Add a confirmed pattern below.</div>'
    notice = f'<div class="notice">{html.escape(message)}</div>' if message else ""
    editable = profile["status"] == "draft"
    rule_form = ""
    publish_form = ""
    if editable and options:
        rule_form = f'''<section class="panel"><h2>Add a confirmed pattern rule</h2><form action="/profiles/{html.escape(profile["profile_id"])}/rules" method="post"><label>Confirmed pattern</label><select name="pattern_hash" required>{options}</select><label>Control title</label><input name="title" required maxlength="160"><div class="two"><div><label>Secure when</label><select name="secure_when"><option value="present">Pattern is present</option><option value="absent">Pattern is absent</option></select></div><div><label>Severity</label><select name="severity"><option>low</option><option selected>medium</option><option>high</option></select></div></div><div class="two"><div><label>Framework</label><select name="framework"><option value="Organization baseline">Organization baseline</option><option value="CIS Benchmark">CIS Benchmark (operator mapping)</option><option value="NIST SP 800-53">NIST SP 800-53 (operator mapping)</option><option value="DISA STIG">DISA STIG (operator mapping)</option><option value="ISO/IEC 27001">ISO/IEC 27001 (operator mapping)</option></select></div><div><label>Control ID</label><input name="framework_control_id" placeholder="e.g. internal LOG-1" maxlength="80"></div></div><label>Exact source reference</label><input name="source_reference" required maxlength="500" placeholder="Document title, version, section/page"><label>Remediation</label><textarea name="remediation" required maxlength="2000"></textarea><button class="button" type="submit">Add organization-defined rule</button></form></section>'''
    if editable and profile.get("rules"):
        publish_form = f'''<form action="/profiles/{html.escape(profile["profile_id"])}/publish" method="post"><button class="button" type="submit">Publish profile for auditing</button></form>'''
    audit_form = ""
    if profile["status"] == "published":
        audit_form = f'''<section class="panel"><h2>Audit with this profile</h2><p>Each uploaded configuration is processed independently and receives JSON, HTML, and PDF output.</p><form action="/api/custom/audit" method="post" enctype="multipart/form-data"><input type="hidden" name="profile_id" value="{html.escape(profile["profile_id"])}"><label>Configuration files</label><input type="file" name="files" accept=".txt,.cfg,.conf,text/plain" multiple required><button class="button" type="submit">Run organization-defined audit</button></form></section>'''
    source = profile.get("source") or {}
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Attestor | {html.escape(profile["name"])}</title><style>
:root{{--muted:#526d7d;--green:#0d7043;--amber:#805400}}*{{box-sizing:border-box}}body{{margin:0}}.shell{{max-width:1080px;margin:auto;padding:25px 28px 60px}}.topbar,.head,.two{{display:flex;justify-content:space-between;gap:16px}}.topbar{{align-items:center;padding:10px 12px;margin-bottom:26px}}.brand{{display:flex;gap:11px;align-items:center}}.mark{{width:38px;height:38px;display:grid;place-items:center;color:white;font-weight:800}}.brand strong,.brand small{{display:block}}.brand small,.muted,.rule span,.rule p,.panel p{{font-size:12px;color:var(--muted)}}.nav{{display:flex;gap:16px}}.nav a{{text-decoration:none;font-size:12px;font-weight:750}}.head{{align-items:end}}h1{{font-size:34px;margin:5px 0}}.eyebrow{{font-size:11px;text-transform:uppercase;font-weight:800}}.state{{display:inline-block;padding:6px 9px;border-radius:999px;text-transform:uppercase;font-size:9px;font-weight:800}}.state.good{{background:#e7f6ed;color:var(--green)}}.state.pending{{background:#fff5d7;color:var(--amber)}}.panel{{padding:20px;margin-top:15px}}.panel h2{{margin-top:0}}.rule{{padding:15px 0;border-bottom:1px solid rgba(255,255,255,.48)}}.rule strong,.rule span,.rule code{{display:block}}.rule code{{margin:9px 0;overflow-wrap:anywhere}}label{{display:block;font-size:12px;font-weight:750;margin:13px 0 6px}}input,select,textarea{{width:100%;padding:10px 11px}}textarea{{min-height:100px;resize:vertical}}.two>div{{flex:1}}.button{{display:inline-flex;margin-top:16px;padding:11px 14px;cursor:pointer}}.notice{{padding:12px 14px;margin:14px 0;border-radius:14px;background:rgba(255,255,255,.55)}}.empty{{padding:18px;color:var(--muted)}}@media(max-width:700px){{.topbar,.head,.two{{display:block}}.nav{{margin-top:12px;flex-wrap:wrap}}.head .state{{margin-top:10px}}}}
</style></head><body><div class="shell"><header class="topbar"><div class="brand"><div class="mark">A</div><div><strong>Attestor</strong><small>Custom vendor profile</small></div></div><nav class="nav"><a href="/profiles">All profiles</a><a href="/training">Training Studio</a><a href="/console">Console</a></nav></header><main><section class="head"><div><div class="eyebrow">Organization-defined flat-pattern adapter</div><h1>{html.escape(profile["name"])}</h1><p class="muted">{html.escape(profile["vendor"])} · {html.escape(profile["platform"])} · source {html.escape(source.get("filename", "unavailable"))}</p></div><span class="state {"good" if profile["status"] == "published" else "pending"}">{html.escape(profile["status"])}</span></section>{notice}<section class="panel"><h2>Rules</h2>{rule_rows}{publish_form}</section>{rule_form}{audit_form}</main></div></body></html>"""


def _console_page(search: str = "", vendor: str = "all", status: str = "all") -> str:
    published_profiles = [
        profile for profile in STORE.list_vendor_profiles()
        if profile["status"] == "published"
    ]
    custom_upload_options = "".join(
        f'<option value="custom:{html.escape(profile["profile_id"])}">'
        f'{html.escape(profile["name"])} ({html.escape(profile["vendor"])} · '
        f'{html.escape(profile["platform"])}) — organization-defined</option>'
        for profile in published_profiles
    )
    custom_filter_options = "".join(
        f'<option value="custom:{html.escape(profile["profile_id"])}" '
        f'{"selected" if vendor == f"custom:{profile["profile_id"]}" else ""}>'
        f'{html.escape(profile["name"])}</option>'
        for profile in published_profiles
    )
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
        vendor_initial = (
            "J" if record.get("vendor_key") == "juniper_junos"
            else "O" if str(record.get("vendor_key", "")).startswith("custom:")
            else "C"
        )
        rows.append(
            f'<a class="device-row" href="/console/devices/{html.escape(record["record_id"])}">'
            f'<div class="device-identity"><span class="device-icon">{vendor_initial}</span><div><strong>{html.escape(str(record.get("device_id", "Unknown device")))}</strong><span>{html.escape(str(record.get("vendor", "Unknown")))} · {html.escape(str(record.get("platform", "")))}</span></div></div>'
            f'<div class="row-score">{score}%<span>compliance</span></div>'
            f'<div class="row-summary"><span class="mini-pass">{summary.get("pass", 0)} pass</span><span class="mini-fail">{summary.get("fail", 0)} fail</span><span>{summary.get("error", 0)} error</span></div>'
            f'<div><span class="state {badge_class}">{html.escape(status_name)}</span><span class="last-scan">{html.escape(_format_time(record.get("last_scan")))}</span></div></a>'
        )
    device_rows = "".join(rows) or '<div class="empty"><div class="empty-icon">+</div><strong>No devices in this view</strong><span>Upload a genuine configuration to create the first auditable device record.</span><a href="#upload">Add configuration</a></div>'
    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Attestor | Audit console</title><style>
:root{{--ink:#10212b;--muted:#657782;--line:#d8e4e8;--canvas:#f4f9fa;--surface:#fff;--blue:#0b6b8f;--teal:#16a5a0;--green:#18794e;--red:#b42318;--amber:#976c00}}*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--ink);background:radial-gradient(circle at 15% 0%,rgba(22,165,160,.14),transparent 31%),linear-gradient(145deg,#edf7f8,#f8fbfc 51%,#eaf3f5);background-attachment:fixed}}body:before{{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.22) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.22) 1px,transparent 1px);background-size:46px 46px;mask-image:linear-gradient(to bottom,rgba(0,0,0,.45),transparent 70%)}}.shell{{max-width:1340px;margin:auto;padding:24px 30px 64px;position:relative;z-index:1}}.topbar,.metric,.upload,.device-list{{border:1px solid rgba(255,255,255,.84);box-shadow:0 16px 40px rgba(38,76,89,.08),inset 0 1px 0 rgba(255,255,255,.95);backdrop-filter:blur(18px) saturate(145%);-webkit-backdrop-filter:blur(18px) saturate(145%)}}.topbar{{display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border-radius:14px;margin-bottom:25px;background:rgba(255,255,255,.5)}}.brand{{display:flex;align-items:center;gap:11px}}.mark{{display:grid;place-items:center;width:39px;height:39px;border-radius:10px;background:rgba(16,33,43,.92);color:#fff;font-weight:800;box-shadow:0 8px 22px rgba(16,33,43,.2),inset 0 1px 0 rgba(255,255,255,.24)}}.brand strong{{display:block;font-size:17px}}.brand small,.sub,.device-row span,.metric small{{color:var(--muted);font-size:11px}}.nav{{display:flex;gap:19px;align-items:center}}.nav a{{color:var(--muted);font-size:13px;text-decoration:none}}.nav .active{{color:var(--ink);font-weight:750}}.workspace-head{{display:flex;align-items:end;justify-content:space-between;gap:24px;margin-bottom:22px}}.eyebrow{{color:var(--blue);font-size:11px;font-weight:800;letter-spacing:.11em;text-transform:uppercase;margin-bottom:9px}}h1{{font-size:34px;line-height:1.1}}.sub{{display:block;font-size:13px;margin-top:8px}}.top-actions,.filters{{display:flex;gap:9px;flex-wrap:wrap}}.button{{border:1px solid rgba(255,255,255,.25);border-radius:8px;background:rgba(16,33,43,.92);color:#fff;padding:11px 14px;font:inherit;font-size:12px;font-weight:750;text-decoration:none;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;box-shadow:0 10px 22px rgba(16,33,43,.15),inset 0 1px 0 rgba(255,255,255,.2)}}.button.alt{{background:rgba(255,255,255,.58);border-color:rgba(255,255,255,.9);color:var(--ink)}}.overview{{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(300px,.7fr);gap:14px;margin-bottom:14px}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:11px}}.metric{{position:relative;overflow:hidden;background:rgba(255,255,255,.58);border-radius:10px;padding:17px;min-height:105px}}.metric strong{{font-size:28px;display:block;font-variant-numeric:tabular-nums}}.metric span{{display:block;color:var(--muted);font-size:10px;margin-top:4px;text-transform:uppercase;letter-spacing:.06em}}.metric small{{display:block;margin-top:11px}}.metric.good strong{{color:var(--green)}}.metric.bad strong{{color:var(--red)}}.network-card{{position:relative;overflow:hidden;background:rgba(16,33,43,.92);color:#fff;border-radius:10px;padding:17px;min-height:105px;box-shadow:0 16px 36px rgba(16,33,43,.2),inset 0 1px 0 rgba(255,255,255,.22)}}.network-card strong{{display:block;font-size:14px}}.network-card span{{display:block;color:#b9d1d8;font-size:11px;margin-top:5px;max-width:190px}}.network-nodes{{position:absolute;right:21px;bottom:18px;display:flex;gap:18px;align-items:center}}.network-nodes i{{display:block;width:9px;height:9px;background:var(--teal);border-radius:50%;box-shadow:0 0 0 5px rgba(22,165,160,.16)}}.network-nodes i:nth-child(2){{width:15px;height:15px;background:#fff;box-shadow:0 0 0 6px rgba(255,255,255,.12)}}.upload{{background:rgba(255,255,255,.58);border-radius:10px;padding:20px;margin-bottom:14px}}.upload-header,.inventory-head{{display:flex;justify-content:space-between;align-items:start;gap:20px}}.upload h2,.inventory-head h2{{font-size:17px}}.upload p,.inventory-head p{{color:var(--muted);font-size:12px;margin-top:5px}}.scope-chip{{background:rgba(222,247,248,.72);border:1px solid rgba(255,255,255,.82);color:var(--blue);border-radius:999px;padding:6px 9px;font-size:10px;font-weight:800;white-space:nowrap}}.upload-grid{{display:grid;grid-template-columns:190px 230px minmax(250px,1fr) auto;gap:10px;align-items:end;margin-top:16px}}label{{display:block;font-size:11px;font-weight:750;margin-bottom:6px}}.upload input,.upload select,.filters input,.filters select{{width:100%;border:1px solid rgba(255,255,255,.92);border-radius:7px;padding:10px 11px;font:inherit;font-size:12px;background:rgba(255,255,255,.68);color:var(--ink);box-shadow:inset 0 1px 0 rgba(255,255,255,.9)}}.upload input[type=file]{{padding:8px}}.upload-note{{display:flex;gap:14px;flex-wrap:wrap;color:var(--muted);font-size:10px;margin-top:12px}}.upload-note span:before{{content:"✓";color:var(--green);font-weight:800;margin-right:5px}}.inventory-head{{align-items:end;margin:24px 0 11px}}.filters{{align-items:center}}.filters input{{min-width:210px}}.device-list{{background:rgba(255,255,255,.58);border-radius:10px;overflow:hidden}}.list-head,.device-row{{display:grid;grid-template-columns:minmax(250px,1.45fr) 110px minmax(200px,1fr) minmax(145px,.7fr);gap:18px;align-items:center}}.list-head{{padding:11px 18px;background:rgba(248,252,253,.55);border-bottom:1px solid var(--line);color:var(--muted);font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.07em}}.device-row{{padding:16px 18px;border-bottom:1px solid rgba(223,235,238,.8);text-decoration:none;color:inherit;transition:transform .16s ease-out,background .16s ease-out}}.device-row:last-child{{border-bottom:0}}.device-row:hover{{background:rgba(255,255,255,.5);transform:translateX(2px)}}.device-identity{{display:flex;align-items:center;gap:11px}}.device-icon{{display:grid!important;place-items:center;width:36px;height:36px;border-radius:9px;background:rgba(222,247,248,.72);border:1px solid rgba(255,255,255,.82);color:var(--blue)!important;font-size:12px!important;font-weight:850;margin:0!important}}.device-row strong{{font-size:13px;display:block}}.row-score{{font-size:20px;font-weight:800;font-variant-numeric:tabular-nums}}.row-score span{{font-size:9px;font-weight:600;text-transform:uppercase}}.row-summary{{display:flex;gap:9px;flex-wrap:wrap}}.row-summary span{{display:inline-block!important;margin:0!important}}.mini-pass{{color:var(--green)!important}}.mini-fail{{color:var(--red)!important}}.state{{display:inline-block!important;width:max-content;border-radius:999px;padding:5px 8px;font-size:9px!important;font-weight:800;text-transform:uppercase;margin:0!important}}.state.good{{background:#e7f6ed;color:var(--green)}}.state.bad{{background:#fdecea;color:var(--red)}}.state.pending{{background:#fff5d7;color:var(--amber)}}.last-scan{{font-size:10px!important}}.empty{{padding:46px;text-align:center;color:var(--muted);font-size:12px}}.empty-icon{{display:grid;place-items:center;width:38px;height:38px;border-radius:10px;background:rgba(222,247,248,.72);color:var(--blue);font-size:21px;margin:0 auto 11px}}.empty strong,.empty span{{display:block}}.empty strong{{color:var(--ink);font-size:14px}}.empty span{{margin-top:5px}}.empty a{{display:inline-block;color:var(--blue);font-weight:750;text-decoration:none;margin-top:12px}}@media(max-width:1000px){{.overview{{grid-template-columns:1fr}}.upload-grid{{grid-template-columns:1fr 1fr}}}}@media(max-width:820px){{.metrics{{grid-template-columns:repeat(2,1fr)}}.inventory-head{{display:block}}.filters{{margin-top:12px}}.list-head{{display:none}}.device-row{{grid-template-columns:1fr 80px;gap:10px}}.row-summary{{grid-column:1/-1}}.device-row>div:last-child{{text-align:right}}}}@media(max-width:560px){{.shell{{padding:20px 16px 45px}}.workspace-head{{display:block}}.top-actions{{margin-top:16px}}.filters,.upload-grid{{display:flex;align-items:stretch;flex-direction:column}}.filters input{{width:100%;min-width:0}}.upload-header{{display:block}}.scope-chip{{display:inline-block;margin-top:10px}}}}@media(prefers-reduced-motion:reduce){{.device-row{{transition:none}}}}
</style></head><body><div class="shell"><header class="topbar"><div class="brand"><div class="mark">A</div><div><strong>Attestor</strong><small>Security compliance operations</small></div></div><nav class="nav"><a class="active" href="/console">Console</a><a href="/training">Training Studio</a><a href="/profiles">Vendor profiles</a><a href="/">Overview</a></nav></header><main><section class="workspace-head"><div><div class="eyebrow">Organization workspace / local</div><h1>Security posture operations</h1><p class="sub">Evaluate saved network state, isolate device-level findings, and produce evidence-ready reports.</p></div><div class="top-actions"><a class="button alt" href="/profiles">Manage profiles</a><a class="button" href="/console#upload">Add configuration</a></div></section><section class="overview"><div class="metrics"><div class="metric"><strong>{counts["total"]}</strong><span>Devices tracked</span><small>Persistent local inventory</small></div><div class="metric good"><strong>{counts["complete"]}</strong><span>Completed scans</span><small>Evidence available</small></div><div class="metric bad"><strong>{aggregate["fail"]}</strong><span>Failed controls</span><small>Require remediation</small></div><div class="metric"><strong>{aggregate["error"]}</strong><span>Errors requiring review</span><small>Fail-closed results</small></div></div><aside class="network-card"><strong>Adapter surface</strong><span>Cisco IOS / IOS-XE and scoped Juniper Junos are built-in. Published low-code profiles remain organization-defined.</span><div class="network-nodes" aria-hidden="true"><i></i><i></i><i></i></div></aside></section><section class="upload" id="upload"><div class="upload-header"><div><h2>Add network configurations</h2><p>Upload genuine saved configurations. Each file becomes an independent scan and report set.</p></div><span class="scope-chip">Up to 20 files · 2 MiB each</span></div><form class="upload-grid" action="/api/network/audit" method="post" enctype="multipart/form-data"><div><label for="vendor">Vendor adapter / profile</label><select id="vendor" name="vendor"><optgroup label="Attestor built-in adapters"><option value="cisco_ios">Cisco IOS / IOS-XE</option><option value="juniper_junos">Juniper Junos</option></optgroup>{f'<optgroup label="Organization-defined profiles">{custom_upload_options}</optgroup>' if custom_upload_options else ''}</select></div><div><label for="framework">Framework view</label><select id="framework" name="framework"><option value="all">Source-backed + mapped controls</option><option value="cis">Source-backed controls</option><option value="nist">NIST mapped view</option></select></div><div><label for="files">Configuration files</label><input id="files" name="files" type="file" accept=".txt,.cfg,.conf,text/plain" multiple required></div><button class="button" type="submit">Queue scans</button></form><div class="upload-note"><span>Processed locally</span><span>Temporary upload workspace</span><span>JSON, HTML and PDF per device</span><span>Custom profiles are operator-defined</span></div></section><section class="inventory-head"><div><h2>Device inventory</h2><p>Open a device to review evidence, severity, remediation, report exports, and integrity state.</p></div><form class="filters" method="get" action="/console"><input name="search" value="{html.escape(search)}" placeholder="Search device or file" aria-label="Search device or file"><select name="vendor" aria-label="Filter by vendor"><option value="all">All adapters</option><option value="cisco_ios" {"selected" if vendor == "cisco_ios" else ""}>Cisco IOS / IOS-XE</option><option value="juniper_junos" {"selected" if vendor == "juniper_junos" else ""}>Juniper Junos</option>{custom_filter_options}</select><select name="status" aria-label="Filter by status"><option value="all">All statuses</option><option value="queued" {"selected" if status == "queued" else ""}>Queued</option><option value="running" {"selected" if status == "running" else ""}>Running</option><option value="complete" {"selected" if status == "complete" else ""}>Completed</option><option value="failed" {"selected" if status == "failed" else ""}>Failed</option><option value="error" {"selected" if status == "error" else ""}>Error</option></select><button class="button alt" type="submit">Filter</button></form></section><section class="device-list"><div class="list-head"><span>Device / platform</span><span>Posture</span><span>Control summary</span><span>Scan state</span></div>{device_rows}</section></main></div></body></html>"""
    return page.replace(
        '<div><label for="files">Configuration files</label><input id="files" name="files" type="file" accept=".txt,.cfg,.conf,text/plain" multiple required></div>',
        '<div><label for="files">Configuration files</label><input id="files" name="files" type="file" accept=".txt,.cfg,.conf,text/plain" multiple required></div>'
        '<div><label for="facts-files">Optional show version files</label><input id="facts-files" name="facts_files" type="file" accept=".txt,text/plain" multiple></div>',
    ).replace(
        '<span>Temporary upload workspace</span>',
        '<span>Temporary upload workspace</span><span>Show version pairs by file order</span>',
    )


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
:root{{--ink:#10212b;--muted:#657782;--line:#dce5e9;--canvas:#f5f8fa;--surface:#fff;--blue:#1266a8;--green:#18794e;--red:#b42318;--amber:#976c00}}*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at 14% 0%,rgba(22,165,160,.13),transparent 31%),linear-gradient(145deg,#edf7f8,#f8fbfc 51%,#eaf3f5);background-attachment:fixed;color:var(--ink)}}body:before{{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.22) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.22) 1px,transparent 1px);background-size:46px 46px;mask-image:linear-gradient(to bottom,rgba(0,0,0,.45),transparent 70%)}}.shell{{max-width:1180px;margin:auto;padding:25px 28px 60px;position:relative;z-index:1}}.topbar,.head,.identity,.summary,.columns{{display:flex;justify-content:space-between;gap:18px}}.topbar,.identity,.panel,.sum{{background:rgba(255,255,255,.58);border:1px solid rgba(255,255,255,.84);box-shadow:0 16px 40px rgba(38,76,89,.08),inset 0 1px 0 rgba(255,255,255,.95);backdrop-filter:blur(18px) saturate(145%);-webkit-backdrop-filter:blur(18px) saturate(145%)}}.topbar{{align-items:center;padding:10px 12px;border-radius:14px;margin-bottom:24px}}.brand{{display:flex;align-items:center;gap:11px}}.mark{{width:38px;height:38px;border-radius:10px;background:rgba(16,33,43,.92);color:#fff;display:grid;place-items:center;font-weight:800;box-shadow:0 8px 22px rgba(16,33,43,.2),inset 0 1px 0 rgba(255,255,255,.24)}}.brand strong{{display:block;font-size:17px}}.brand small,.muted,.identity span,.history span,.control span,.control p,.source{{color:var(--muted);font-size:12px}}.nav,.link{{color:var(--blue);font-size:12px;font-weight:750;text-decoration:none}}.eyebrow{{color:var(--blue);font-size:11px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;margin-bottom:9px}}h1{{font-size:32px;line-height:1.1}}.head{{align-items:end;margin-bottom:22px}}.actions{{display:flex;gap:8px;flex-wrap:wrap}}.button{{display:inline-block;background:rgba(16,33,43,.92);color:#fff;text-decoration:none;border-radius:8px;padding:10px 12px;font-size:12px;font-weight:750;box-shadow:0 10px 22px rgba(16,33,43,.15),inset 0 1px 0 rgba(255,255,255,.2)}}.button.alt{{background:rgba(255,255,255,.58);border:1px solid rgba(255,255,255,.9);color:var(--ink)}}.identity,.panel{{border-radius:10px;padding:18px}}.identity{{align-items:center;margin-bottom:14px}}.identity strong{{font-size:16px;display:block}}.identity span{{display:block;margin-top:4px}}.score{{font-size:34px;font-weight:850;color:{score_color};text-align:right}}.score small{{display:block;color:var(--muted);font-size:10px;text-transform:uppercase}}.summary{{margin-bottom:14px}}.sum{{flex:1;border-radius:9px;padding:13px}}.sum strong{{font-size:23px;display:block}}.sum span{{font-size:10px;color:var(--muted);text-transform:uppercase}}.pass strong{{color:var(--green)}}.fail strong{{color:var(--red)}}.error strong{{color:var(--amber)}}.columns{{align-items:start}}.main{{flex:1;min-width:0}}.side{{width:280px;display:grid;gap:14px}}.panel h2{{font-size:16px;margin-bottom:13px}}.control{{padding:15px 0;border-top:1px solid rgba(222,234,237,.82)}}.control:first-child{{border-top:0;padding-top:0}}.control strong{{font-size:13px;margin-right:7px}}.control-status{{float:right;border-radius:999px;padding:4px 7px!important;text-transform:uppercase;font-size:10px!important;font-weight:800;box-shadow:inset 0 1px 0 rgba(255,255,255,.65)}}.control-status.pass{{background:#e7f6ed;color:var(--green)}}.control-status.fail{{background:#fdecea;color:var(--red)}}.control-status.error{{background:#fff5d7;color:var(--amber)}}.control p{{margin-top:8px;line-height:1.45}}details{{margin-top:9px;color:var(--blue);font-size:12px}}details p{{color:var(--ink);margin-top:6px}}.source{{word-break:break-word}}.history{{list-style:none}}.history li{{padding:10px 0;border-top:1px solid rgba(222,234,237,.82)}}.history li:first-child{{border-top:0;padding-top:0}}.history strong,.history span{{display:block}}.hash{{font-family:ui-monospace,monospace;word-break:break-all;background:rgba(241,248,249,.62);border:1px solid rgba(255,255,255,.75);padding:9px;border-radius:7px;font-size:10px;color:var(--muted);margin-top:8px}}.empty{{padding:20px;color:var(--muted);font-size:13px}}@media(max-width:820px){{.columns{{display:block}}.side{{width:auto;margin-top:14px}}.head{{display:block}}.actions{{margin-top:15px}}.identity{{align-items:flex-start;display:block}}.score{{text-align:left;margin-top:13px}}.summary{{display:grid;grid-template-columns:repeat(2,1fr)}}}}
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


async def _audit_network_upload(
    upload: UploadFile,
    facts_upload: UploadFile | None,
    framework: str,
    vendor: str,
    work_dir: Path,
    record_id: str | None = None,
) -> dict:
    display_name = _safe_upload_name(upload.filename)
    if record_id and record_id in DEVICE_RECORDS:
        DEVICE_RECORDS[record_id]["status"] = "running"
        STORE.upsert_device_record(DEVICE_RECORDS[record_id])
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
    facts_path = None
    if facts_upload is not None:
        facts_name = _safe_upload_name(facts_upload.filename or "show-version.txt")
        facts_content = await facts_upload.read(MAX_NETWORK_CONFIG_BYTES + 1)
        if not facts_content:
            return {
                "record_id": record_id,
                "filename": display_name,
                "status": "error",
                "error": f"paired device facts file {facts_name!r} is empty",
                "vendor": vendor,
            }
        if len(facts_content) > MAX_NETWORK_CONFIG_BYTES:
            return {
                "record_id": record_id,
                "filename": display_name,
                "status": "error",
                "error": f"paired device facts file {facts_name!r} exceeds the 2 MiB limit",
                "vendor": vendor,
            }
        facts_path = work_dir / f"{item_id}_facts_{facts_name}"
        facts_path.write_bytes(facts_content)
    results_path = RESULTS_DIR / f"network_{item_id}.json"
    html_path = RESULTS_DIR / f"network_{item_id}.html"
    pdf_path = RESULTS_DIR / f"network_{item_id}.pdf"
    bundle_path = RESULTS_DIR / f"network_{item_id}.zip"
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
    if facts_path is not None:
        cmd.extend(["--device-facts", str(facts_path)])
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
        build_evidence_bundle(
            viewed,
            results_path,
            html_path,
            pdf_path,
            bundle_path,
            source_filename=display_name,
            framework_view=framework,
            integrity_status="Not chained (local report only)",
        )
    except Exception as exc:
        for artifact in (results_path, html_path, pdf_path, bundle_path):
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
        "bundle_url": f"/reports/{bundle_path.name}",
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
        hardware = " · ".join(
            value for value in (
                str(device.get("model") or "").strip(),
                str(device.get("software_version") or "").strip(),
                str(device.get("serial_number") or "").strip(),
            ) if value
        ) or "not supplied"
        blocks.append(
            f'<div class="card"><h2>{name}</h2>'
            f'<p><b>Vendor:</b> {html.escape(str(item.get("vendor", "unknown")))}</p>'
            f'<p><b>Device:</b> {html.escape(str(device.get("device_id", "unknown")))}'
            f' ({html.escape(str(device.get("hostname") or "hostname unavailable"))})</p>'
            f'<p><b>Hardware facts:</b> {html.escape(hardware)}</p>'
            f'<p><b>Results:</b> pass={summary.get("pass", 0)}, fail={summary.get("fail", 0)}, '
            f'error={summary.get("error", 0)}, manual={summary.get("manual", 0)}</p>'
            f'<a class="report-link" href="{item["html_url"]}" target="_blank">HTML report</a> '
            f'<a class="report-link" href="{item["pdf_url"]}" target="_blank">PDF report</a> '
            f'<a class="report-link" href="{item["json_url"]}" target="_blank">JSON results</a> '
            f'<a class="report-link" href="{item["bundle_url"]}">Evidence bundle</a></div>'
        )
    return PAGE_TEMPLATE.split("<body>", 1)[0] + "<body><div class=\"shell\">" + (
        '<header class="topbar"><div class="brand"><div class="brand-mark">A</div><div><div class="brand-name">Attestor</div><div class="brand-subtitle">Network security compliance</div></div></div><div class="status-pill"><span class="status-dot"></span>Audit complete</div></header>'
        '<section class="hero-copy" style="margin-bottom:22px"><div class="eyebrow">Results workspace</div><h1>Configuration findings, ready to review.</h1>'
        f'<p>Framework view: <b>{html.escape(framework)}</b>. NIST is a mapped view of source-backed deterministic checks.</p></section>'
        + "".join(blocks)
        + '<p><a class="report-link" href="/console">Back to audit console</a></p></div></body></html>'
    )


@app.post("/api/network/audit", response_class=HTMLResponse)
async def audit_network_configs(
    files: list[UploadFile] = File(...),
    facts_files: list[UploadFile] | None = File(None),
    framework: str = Form("all"),
    vendor: str = Form("cisco_ios"),
):
    if framework not in FRAMEWORK_VIEWS:
        return HTMLResponse("Invalid framework view", status_code=400)
    if not files or len(files) > MAX_NETWORK_FILES:
        return HTMLResponse(
            f"Upload between 1 and {MAX_NETWORK_FILES} configuration files", status_code=400
        )
    paired_facts = [item for item in (facts_files or []) if item.filename]
    if paired_facts and len(paired_facts) != len(files):
        return HTMLResponse(
            "When device facts are supplied, provide exactly one show version file per configuration in the same order",
            status_code=400,
        )
    if vendor.startswith("custom:"):
        if paired_facts:
            return HTMLResponse(
                "Device facts are supported only for built-in Cisco and Junos adapters",
                status_code=400,
            )
        return await audit_custom_vendor_profile(
            profile_id=vendor.removeprefix("custom:"), files=files
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
            STORE.upsert_device_record(DEVICE_RECORDS[record_id])
            queued.append((upload, record_id))
        items = [
            await _audit_network_upload(
                upload,
                paired_facts[index] if paired_facts else None,
                framework,
                vendor,
                work_dir,
                record_id,
            )
            for index, (upload, record_id) in enumerate(queued)
        ]
    _record_network_items(items)
    return HTMLResponse(_apple_glass(_network_results_page(items, framework)))


def _record_network_items(items: list[dict]) -> None:
    """Promote completed or failed upload results into the local inventory."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for item in items:
        device = item.get("device") or {}
        device_id = str(device.get("device_id") or Path(item.get("filename", "device")).stem)
        vendor_key = item.get("vendor_key", item.get("vendor", "unknown"))
        queued_record = DEVICE_RECORDS.get(str(item.get("record_id")))
        existing = next(
            (
                record for record in DEVICE_RECORDS.values()
                if record is not queued_record
                and record.get("device_id") == device_id
                and record.get("vendor_key") == vendor_key
            ),
            None,
        )
        record = existing or queued_record or {"record_id": uuid.uuid4().hex[:12], "history": []}
        record.update({
            "device_id": device_id,
            "filename": item.get("filename", "unknown"),
            "vendor_key": vendor_key,
            "vendor": device.get("vendor") or record.get("vendor") or item.get("vendor", "unknown"),
            "platform": device.get("platform") or record.get("platform", "unknown"),
            "status": "complete" if item.get("status") == "complete" else "failed",
            "summary": item.get("summary", {}),
            "controls": item.get("controls", []),
            "urls": {
                key: item[key]
                for key in ("json_url", "html_url", "pdf_url", "bundle_url")
                if key in item
            },
            "last_scan": now,
            "config_sha256": device.get("config_sha256"),
            "model": device.get("model"),
            "serial_number": device.get("serial_number"),
            "serial_numbers": device.get("serial_numbers", []),
            "software_version": device.get("software_version"),
            "facts_source": device.get("facts_source"),
            "chain_status": "Not chained (local report only)",
        })
        if item.get("status") != "complete":
            record["error"] = item.get("error", "scan failed")
        summary = item.get("summary", {})
        record.setdefault("history", []).append({"timestamp": now, "pass": summary.get("pass", 0), "fail": summary.get("fail", 0), "error": summary.get("error", 0)})
        if existing and queued_record:
            DEVICE_RECORDS.pop(queued_record["record_id"], None)
            STORE.delete_device_record(queued_record["record_id"])
        DEVICE_RECORDS[record["record_id"]] = record
        STORE.upsert_device_record(record)


def _device_detail_with_facts(page: str, record: dict) -> str:
    """Project parsed identity facts into the existing detail page."""
    source = record.get("facts_source") or {}
    serials = record.get("serial_numbers") or []
    observed = f" ({len(serials)} observed)" if len(serials) > 1 else ""
    facts = (
        f'<span>Model: {html.escape(str(record.get("model") or "not exposed"))}</span>'
        f'<span>Software: {html.escape(str(record.get("software_version") or "not exposed"))}</span>'
        f'<span>Serial: {html.escape(str(record.get("serial_number") or "not exposed"))}'
        f'{html.escape(observed)}</span>'
    )
    page = page.replace("<span>Status:", facts + "<span>Status:", 1)
    bundle_url = (record.get("urls") or {}).get("bundle_url")
    if bundle_url:
        new_scan = '<a class="button" href="/console#upload">New scan</a>'
        bundle_link = (
            f'<a class="button alt" href="{html.escape(str(bundle_url))}">'
            "Evidence bundle</a>"
        )
        page = page.replace(new_scan, bundle_link + new_scan, 1)
    if source:
        source_block = (
            '<p class="muted" style="margin-top:12px">Device facts: '
            f'{html.escape(str(source.get("command", "unknown command")))} · '
            f'{html.escape(str(source.get("parser", "unknown parser")))}</p>'
            f'<div class="hash">{html.escape(str(source.get("sha256", "facts hash unavailable")))}</div>'
        )
        marker = "</section></aside>"
        page = page.replace(marker, source_block + marker, 1)
    return page


@app.get("/console", response_class=HTMLResponse)
async def console(request: Request):
    page = _console_page(
        request.query_params.get("search", ""),
        request.query_params.get("vendor", "all"),
        request.query_params.get("status", "all"),
    )
    return HTMLResponse(_apple_glass(page))


@app.get("/training", response_class=HTMLResponse)
async def training_studio():
    return HTMLResponse(_apple_glass(_training_page()))


@app.post("/api/training/analyze", response_class=HTMLResponse)
async def analyze_training_config(
    vendor: str = Form(...),
    platform: str = Form(...),
    config_file: UploadFile = File(...),
    knowledge_file: UploadFile | None = File(None),
):
    vendor = vendor.strip()[:100]
    platform = platform.strip()[:100]
    if not vendor or not platform:
        return HTMLResponse(
            _apple_glass(_training_page("Vendor and platform are required.")),
            status_code=400,
        )
    content = await config_file.read(MAX_NETWORK_CONFIG_BYTES + 1)
    if not content or len(content) > MAX_NETWORK_CONFIG_BYTES:
        return HTMLResponse(
            _apple_glass(_training_page("Configuration is empty or exceeds the 2 MiB limit.")),
            status_code=400,
        )
    try:
        config_text = content.decode("utf-8")
    except UnicodeDecodeError:
        return HTMLResponse(
            _apple_glass(_training_page("Configuration is not valid UTF-8 text.")),
            status_code=400,
        )

    source_id = None
    if knowledge_file and knowledge_file.filename:
        knowledge = await knowledge_file.read(MAX_KNOWLEDGE_SOURCE_BYTES + 1)
        if not knowledge or len(knowledge) > MAX_KNOWLEDGE_SOURCE_BYTES:
            return HTMLResponse(
                _apple_glass(_training_page("Knowledge source is empty or exceeds 5 MiB.")),
                status_code=400,
            )
        try:
            excerpt = extract_knowledge_text(knowledge_file.filename, knowledge)
        except ValueError as exc:
            return HTMLResponse(_apple_glass(_training_page(str(exc))), status_code=400)
        if not excerpt:
            return HTMLResponse(
                _apple_glass(_training_page("Knowledge source contains no extractable text.")),
                status_code=400,
            )
        source_id = uuid.uuid4().hex[:12]
        STORE.add_knowledge_source({
            "source_id": source_id,
            "vendor": vendor,
            "platform": platform,
            "filename": _safe_upload_name(knowledge_file.filename),
            "media_type": knowledge_file.content_type or "application/octet-stream",
            "content_sha256": hashlib.sha256(knowledge).hexdigest(),
            "excerpt": excerpt,
        })

    known_patterns = []
    if vendor.casefold() == "cisco" and "ios" in platform.casefold():
        from ai.network_discovery import _production_patterns

        known_patterns = [
            pattern
            for _, pattern in _production_patterns(REPO_ROOT / "rules" / "cisco_ios")
        ]
    patterns = collect_training_patterns(config_text, vendor, platform, known_patterns)
    if not patterns:
        return HTMLResponse(
            _apple_glass(_training_page("No unfamiliar active patterns were found.")),
            status_code=400,
        )
    classified = classify_patterns(
        patterns,
        vendor,
        platform,
        STORE.find_prior_training_pattern,
        real_api=False,
    )
    session_id = uuid.uuid4().hex[:12]
    STORE.create_training_session({
        "session_id": session_id,
        "vendor": vendor,
        "platform": platform,
        "filename": _safe_upload_name(config_file.filename),
        "config_sha256": hashlib.sha256(content).hexdigest(),
        "source_id": source_id,
        "status": "review",
    })
    STORE.save_training_patterns(session_id, classified)
    session = STORE.get_training_session(session_id)
    return HTMLResponse(
        _apple_glass(
            _training_session_page(
                session or {}, "Dry-run analysis complete. No provider call was made."
            )
        )
    )


@app.get("/training/{session_id}", response_class=HTMLResponse)
async def training_session(session_id: str):
    session = STORE.get_training_session(session_id)
    if not session:
        return HTMLResponse("Training session not found", status_code=404)
    return HTMLResponse(_apple_glass(_training_session_page(session)))


@app.post(
    "/training/{session_id}/patterns/{pattern_hash}/confirm",
    response_class=HTMLResponse,
)
async def confirm_training_pattern(
    session_id: str,
    pattern_hash: str,
    category: str = Form(...),
    note: str = Form(""),
):
    if category not in CATEGORIES:
        return HTMLResponse("Invalid training category", status_code=400)
    try:
        STORE.confirm_training_pattern(
            session_id, pattern_hash, category, note.strip()[:500]
        )
    except KeyError:
        return HTMLResponse("Training pattern not found", status_code=404)
    session = STORE.get_training_session(session_id)
    return HTMLResponse(
        _apple_glass(
            _training_session_page(
                session or {}, "Mapping confirmed and saved for future configurations."
            )
        )
    )


@app.post("/training/{session_id}/classify", response_class=HTMLResponse)
async def classify_training_session(session_id: str, max_calls: int = Form(...)):
    session = STORE.get_training_session(session_id)
    if not session:
        return HTMLResponse("Training session not found", status_code=404)
    if max_calls < 1 or max_calls > 200:
        return HTMLResponse(
            _apple_glass(_training_session_page(session, "max_calls must be between 1 and 200.")),
            status_code=400,
        )
    candidates = [
        item for item in session.get("patterns", [])
        if not item["structural"]
        and not item["confirmed"]
        and item.get("source") not in {"provider", "human_confirmed"}
    ]
    if not candidates:
        return HTMLResponse(
            _apple_glass(_training_session_page(session, "No uncached patterns require provider classification."))
        )
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return HTMLResponse(
            _apple_glass(
                _training_session_page(session, "real training mode requires ANTHROPIC_API_KEY")
            ),
            status_code=400,
        )
    if len(candidates) > max_calls:
        return HTMLResponse(
            _apple_glass(
                _training_session_page(
                    session,
                    f"refusing training calls: {len(candidates)} uncached patterns exceed "
                    f"max_calls={max_calls}",
                )
            ),
            status_code=400,
        )
    classified = []
    input_tokens = 0
    output_tokens = 0
    actual_cost = 0.0
    try:
        for candidate in candidates:
            item = classify_patterns(
                [candidate],
                session["vendor"],
                session["platform"],
                STORE.find_prior_training_pattern,
                real_api=True,
                max_calls=1,
                api_key=api_key,
                model=MODEL_DEFAULT,
            )[0]
            classified.append(item)
            if item.get("confirmed"):
                STORE.confirm_training_pattern(
                    session_id,
                    item["pattern_hash"],
                    item["category"],
                    str(item.get("note", "Reused prior human confirmation"))[:500],
                )
                continue
            STORE.update_training_classifications(session_id, [item])
            usage = item.get("usage") or {}
            call_input = int(usage.get("input_tokens", 0))
            call_output = int(usage.get("output_tokens", 0))
            call_cost = float(usage.get("cost_usd", 0.0))
            input_tokens += call_input
            output_tokens += call_output
            actual_cost += call_cost
            STORE.record_training_api_run({
                "run_id": uuid.uuid4().hex[:12],
                "session_id": session_id,
                "model": MODEL_DEFAULT,
                "call_count": 1,
                "input_tokens": call_input,
                "output_tokens": call_output,
                "cost_usd": call_cost,
            })
    except (ProviderError, RuntimeError, KeyError, ValueError) as exc:
        current = STORE.get_training_session(session_id) or session
        return HTMLResponse(
            _apple_glass(
                _training_session_page(
                    current,
                    f"Provider batch stopped after {len(classified)} persisted result(s): {exc}",
                )
            ),
            status_code=400,
        )
    real_results = [item for item in classified if item.get("mode") == "real-api"]
    current = STORE.get_training_session(session_id) or session
    return HTMLResponse(
        _apple_glass(
            _training_session_page(
                current,
                f"AI suggestions loaded: {len(real_results)} real call(s), "
                f"{len(classified) - len(real_results)} cache reuse(s), {input_tokens} input + "
                f"{output_tokens} output tokens, actual cost ${actual_cost:.6f}. "
                "Human confirmation is still required.",
            )
        )
    )


@app.post("/training/{session_id}/profiles", response_class=HTMLResponse)
async def create_profile_from_training(session_id: str, name: str = Form(...)):
    session = STORE.get_training_session(session_id)
    if not session:
        return HTMLResponse("Training session not found", status_code=404)
    if not session.get("source_id"):
        return HTMLResponse(
            _apple_glass(
                _training_session_page(
                    session, "Attach a vendor knowledge source before creating a profile."
                )
            ),
            status_code=400,
        )
    profile_id = uuid.uuid4().hex[:12]
    STORE.create_vendor_profile({
        "profile_id": profile_id,
        "name": name.strip()[:120],
        "vendor": session["vendor"],
        "platform": session["platform"],
        "source_id": session["source_id"],
        "status": "draft",
    })
    profile = STORE.get_vendor_profile(profile_id)
    return HTMLResponse(
        _apple_glass(
            _profile_page(
                profile or {},
                "Draft created. Add only confirmed patterns with exact source references.",
            )
        )
    )


@app.get("/profiles", response_class=HTMLResponse)
async def vendor_profiles():
    return HTMLResponse(_apple_glass(_profiles_page()))


@app.get("/profiles/{profile_id}", response_class=HTMLResponse)
async def vendor_profile(profile_id: str):
    profile = STORE.get_vendor_profile(profile_id)
    if not profile:
        return HTMLResponse("Vendor profile not found", status_code=404)
    return HTMLResponse(_apple_glass(_profile_page(profile)))


@app.post("/profiles/{profile_id}/rules", response_class=HTMLResponse)
async def add_vendor_profile_rule(
    profile_id: str,
    pattern_hash: str = Form(...),
    title: str = Form(...),
    secure_when: str = Form(...),
    severity: str = Form(...),
    framework: str = Form("Organization baseline"),
    framework_control_id: str = Form(""),
    source_reference: str = Form(...),
    remediation: str = Form(...),
):
    profile = STORE.get_vendor_profile(profile_id)
    if not profile:
        return HTMLResponse("Vendor profile not found", status_code=404)
    candidates = {
        item["pattern_hash"]: item
        for item in STORE.list_confirmed_patterns(profile["vendor"], profile["platform"])
    }
    pattern = candidates.get(pattern_hash)
    if not pattern:
        return HTMLResponse("Confirmed training pattern not found", status_code=400)
    try:
        STORE.add_profile_rule({
            "rule_id": f"ORG-{profile_id[:6].upper()}-{len(profile.get('rules', [])) + 1:03d}",
            "profile_id": profile_id,
            "title": title.strip()[:160],
            "category": pattern["category"],
            "pattern_hash": pattern_hash,
            "pattern": pattern["pattern"],
            "secure_when": secure_when,
            "severity": severity,
            "framework": framework.strip()[:100],
            "framework_control_id": framework_control_id.strip()[:80],
            "source_reference": source_reference.strip()[:500],
            "remediation": remediation.strip()[:2000],
        })
    except (KeyError, ValueError) as exc:
        return HTMLResponse(_apple_glass(_profile_page(profile, str(exc))), status_code=400)
    return HTMLResponse(
        _apple_glass(
            _profile_page(
                STORE.get_vendor_profile(profile_id) or {},
                "Organization-defined rule added. It is not active until publication.",
            )
        )
    )


@app.post("/profiles/{profile_id}/publish", response_class=HTMLResponse)
async def publish_vendor_profile(profile_id: str):
    profile = STORE.get_vendor_profile(profile_id)
    if not profile:
        return HTMLResponse("Vendor profile not found", status_code=404)
    try:
        STORE.publish_vendor_profile(profile_id)
    except (KeyError, ValueError) as exc:
        return HTMLResponse(_apple_glass(_profile_page(profile, str(exc))), status_code=400)
    return HTMLResponse(
        _apple_glass(
            _profile_page(
                STORE.get_vendor_profile(profile_id) or {},
                "Profile published as organization-defined and is ready for audit.",
            )
        )
    )


@app.post("/api/custom/audit", response_class=HTMLResponse)
async def audit_custom_vendor_profile(
    profile_id: str = Form(...),
    files: list[UploadFile] = File(...),
):
    profile = STORE.get_vendor_profile(profile_id)
    if not profile:
        return HTMLResponse("Vendor profile not found", status_code=404)
    if not files or len(files) > MAX_NETWORK_FILES:
        return HTMLResponse(
            f"Upload between 1 and {MAX_NETWORK_FILES} configuration files", status_code=400
        )
    items = []
    for upload in files:
        record_id = uuid.uuid4().hex[:12]
        display_name = _safe_upload_name(upload.filename)
        DEVICE_RECORDS[record_id] = {
            "record_id": record_id,
            "device_id": Path(display_name).stem,
            "filename": display_name,
            "vendor_key": f"custom:{profile_id}",
            "vendor": profile["vendor"],
            "platform": profile["platform"],
            "status": "queued",
            "summary": {},
            "controls": [],
            "history": [],
            "last_scan": None,
            "chain_status": "Not chained (local report only)",
        }
        STORE.upsert_device_record(DEVICE_RECORDS[record_id])
        DEVICE_RECORDS[record_id]["status"] = "running"
        STORE.upsert_device_record(DEVICE_RECORDS[record_id])
        content = await upload.read(MAX_NETWORK_CONFIG_BYTES + 1)
        if not content or len(content) > MAX_NETWORK_CONFIG_BYTES:
            items.append({
                "record_id": record_id,
                "filename": display_name,
                "status": "error",
                "error": "configuration is empty or exceeds the 2 MiB limit",
                "vendor": profile["vendor"],
                "vendor_key": f"custom:{profile_id}",
            })
            continue
        try:
            config_text = content.decode("utf-8")
        except UnicodeDecodeError:
            items.append({
                "record_id": record_id,
                "filename": display_name,
                "status": "error",
                "error": "configuration is not valid UTF-8 text",
                "vendor": profile["vendor"],
                "vendor_key": f"custom:{profile_id}",
            })
            continue
        artifacts: tuple[Path, ...] = ()
        try:
            results = audit_custom_profile(
                config_text,
                profile,
                device_id=Path(display_name).stem,
                config_sha256=hashlib.sha256(content).hexdigest(),
            )
            item_id = uuid.uuid4().hex[:10]
            results_path = RESULTS_DIR / f"custom_{item_id}.json"
            html_path = RESULTS_DIR / f"custom_{item_id}.html"
            pdf_path = RESULTS_DIR / f"custom_{item_id}.pdf"
            bundle_path = RESULTS_DIR / f"custom_{item_id}.zip"
            artifacts = (results_path, html_path, pdf_path, bundle_path)
            results_path.write_text(
                json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            html_path.write_text(render(results), encoding="utf-8")
            build_pdf(results, pdf_path, state_dir=DASHBOARD_DATA_DIR / "ai_state")
            build_evidence_bundle(
                results,
                results_path,
                html_path,
                pdf_path,
                bundle_path,
                source_filename=display_name,
                framework_view="organization-defined",
                integrity_status="Not chained (local report only)",
            )
        except (CustomProfileError, OSError, ValueError) as exc:
            for artifact in artifacts:
                artifact.unlink(missing_ok=True)
            items.append({
                "record_id": record_id,
                "filename": display_name,
                "status": "error",
                "error": str(exc),
                "vendor": profile["vendor"],
                "vendor_key": f"custom:{profile_id}",
            })
            continue
        items.append({
            "record_id": record_id,
            "filename": display_name,
            "status": "complete",
            "device": results["device"],
            "summary": results["summary"],
            "controls": results["controls"],
            "framework": "organization-defined",
            "vendor": profile["vendor"],
            "vendor_key": f"custom:{profile_id}",
            "json_url": f"/reports/{results_path.name}",
            "html_url": f"/reports/{html_path.name}",
            "pdf_url": f"/reports/{pdf_path.name}",
            "bundle_url": f"/reports/{bundle_path.name}",
        })
    _record_network_items(items)
    return HTMLResponse(
        _apple_glass(_network_results_page(items, "organization-defined profile"))
    )


@app.get("/console/devices/{record_id}", response_class=HTMLResponse)
async def device_detail(record_id: str):
    record = DEVICE_RECORDS.get(record_id) or STORE.get_device_record(record_id)
    if not record:
        return HTMLResponse("Device record not found", status_code=404)
    DEVICE_RECORDS[record_id] = record
    return HTMLResponse(_apple_glass(_device_detail_with_facts(_device_detail_page(record), record)))


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
        ".zip": "application/zip",
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
