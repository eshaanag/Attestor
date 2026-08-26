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


# ─────────────────────── Routes ───────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    return PAGE_TEMPLATE


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


async def _audit_network_upload(upload: UploadFile, framework: str, vendor: str, work_dir: Path) -> dict:
    display_name = _safe_upload_name(upload.filename)
    content = await upload.read(MAX_NETWORK_CONFIG_BYTES + 1)
    if not content:
        return {"filename": display_name, "status": "error", "error": "uploaded file is empty"}
    if len(content) > MAX_NETWORK_CONFIG_BYTES:
        return {
            "filename": display_name,
            "status": "error",
            "error": f"file exceeds {MAX_NETWORK_CONFIG_BYTES // (1024 * 1024)} MiB limit",
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
            "filename": display_name,
            "status": "error",
            "error": detail[-800:] or f"network engine exited {process.returncode}",
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
            "filename": display_name,
            "status": "error",
            "error": f"report generation failed: {type(exc).__name__}: {exc}",
        }

    return {
        "filename": display_name,
        "status": "complete",
        "device": viewed.get("device", {}),
        "summary": viewed.get("summary", {}),
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
        items = [await _audit_network_upload(upload, framework, vendor, work_dir) for upload in files]
    return HTMLResponse(_network_results_page(items, framework))


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
