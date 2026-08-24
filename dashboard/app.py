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

app = FastAPI(title="Attestor Local GUI", version="0.1.0")
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
:root { --pass: #1a7f37; --fail: #cf222e; --error: #9a6700; --bg: #f6f8fa; --fg: #1f2328; --border: #d0d7de; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--fg); padding: 2rem; max-width: 900px; margin: 0 auto; }
h1 { font-size: 1.6rem; margin-bottom: 1rem; }
.card { background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
label { font-weight: 600; display: block; margin-bottom: 0.3rem; }
select, input { padding: 0.5rem; border: 1px solid var(--border); border-radius: 4px; font-size: 0.95rem; width: 100%; margin-bottom: 1rem; }
button { background: #0969da; color: #fff; border: none; padding: 0.75rem 1.5rem; border-radius: 6px; font-size: 1rem; cursor: pointer; font-weight: 600; }
button:hover { background: #0550ae; }
button:disabled { background: #8c959f; cursor: not-allowed; }
.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
.summary-item { padding: 0.5rem 1rem; border-radius: 6px; border: 1px solid var(--border); text-align: center; min-width: 80px; }
.summary-item .count { font-size: 1.5rem; font-weight: 700; }
.summary-item .label { font-size: 0.75rem; text-transform: uppercase; }
.s-pass .count { color: var(--pass); } .s-fail .count { color: var(--fail); } .s-error .count { color: var(--error); }
#results { max-height: 500px; overflow-y: auto; font-family: monospace; font-size: 0.85rem; }
.result-line { padding: 0.4rem 0.6rem; border-bottom: 1px solid #eee; display: flex; gap: 0.75rem; align-items: center; }
.badge { display: inline-block; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }
.badge-pass { background: #dafbe1; color: var(--pass); }
.badge-fail { background: #ffebe9; color: var(--fail); }
.badge-error { background: #fff8c5; color: var(--error); }
.status-bar { padding: 0.75rem; background: #ddf4ff; border: 1px solid #54aeff; border-radius: 6px; margin-bottom: 1rem; font-weight: 500; }
.status-bar.complete { background: #dafbe1; border-color: var(--pass); }
.report-link { display: inline-block; margin-top: 1rem; padding: 0.5rem 1rem; background: var(--pass); color: #fff; border-radius: 4px; text-decoration: none; font-weight: 600; }
.hidden { display: none; }
</style>
</head>
<body>
<h1>🛡️ Attestor CIS Benchmark Audit</h1>

<div class="card">
  <h2 style="margin-bottom:0.75rem">Cisco IOS configuration ingestion</h2>
  <p style="margin-bottom:1rem">Upload one or more genuine saved configurations. Cisco IOS is the only built network vendor; other vendors remain roadmap.</p>
  <form action="/api/network/audit" method="post" enctype="multipart/form-data">
    <label for="network-files">Configuration files</label>
    <input id="network-files" name="files" type="file" accept=".txt,.cfg,.conf,text/plain" multiple required>
    <label for="framework">Report framework view</label>
    <select id="framework" name="framework">
      <option value="all">CIS with NIST SP 800-53 mappings</option>
      <option value="cis">CIS Cisco IOS only</option>
      <option value="nist">NIST SP 800-53 mapped view</option>
    </select>
    <button type="submit">Upload and audit</button>
  </form>
  <p style="font-size:0.82rem;color:#656d76;margin-top:0.75rem">Uploads are processed locally and discarded after auditing. PDF AI remediation is dry-run by default; no provider call is made.</p>
</div>

<div class="card" id="run-panel">
  <h2 style="margin-bottom:0.75rem">Local operating-system audit</h2>
  <label for="target">Target</label>
  <select id="target">
    <option value="ubuntu2204_desktop">Ubuntu 22.04 Desktop (Level 1)</option>
    <option value="windows11_standalone">Windows 11 Standalone (Level 1)</option>
  </select>
  <label for="level">Level</label>
  <select id="level">
    <option value="1">Level 1</option>
    <option value="2">Level 2</option>
  </select>
  <button id="run-btn" onclick="startAudit()">▶ Run Audit</button>
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
      '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + escapeHtml(data.evidence) + '</span></div>';
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
    viewed["benchmark"] = "NIST SP 800-53 mapped view (CIS-backed checks)"
    viewed["benchmark_version"] = "Rev. 5 mappings"
    viewed["summary"] = {key: 0 for key in ("pass", "fail", "error", "manual", "not_applicable")}
    for control in controls:
        viewed["summary"][control["status"]] += 1
    viewed["run"]["total_controls"] = len(controls)
    viewed["run"]["evaluated"] = len(controls)
    return viewed


async def _audit_network_upload(upload: UploadFile, framework: str, work_dir: Path) -> dict:
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
    cmd = [
        sys.executable,
        str(REPO_ROOT / "engines" / "network" / "run_audit.py"),
        "--config", str(input_path),
        "--device-id", device_id,
        "--output", str(results_path),
        "--format", "json",
    ]
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
            f'<p><b>Device:</b> {html.escape(str(device.get("device_id", "unknown")))}'
            f' ({html.escape(str(device.get("hostname") or "hostname unavailable"))})</p>'
            f'<p><b>Results:</b> pass={summary.get("pass", 0)}, fail={summary.get("fail", 0)}, '
            f'error={summary.get("error", 0)}, manual={summary.get("manual", 0)}</p>'
            f'<a class="report-link" href="{item["html_url"]}" target="_blank">HTML report</a> '
            f'<a class="report-link" href="{item["pdf_url"]}" target="_blank">PDF report</a> '
            f'<a class="report-link" href="{item["json_url"]}" target="_blank">JSON results</a></div>'
        )
    return PAGE_TEMPLATE.split("<body>", 1)[0] + "<body>" + (
        '<h1>Attestor network ingestion results</h1>'
        f'<p style="margin-bottom:1rem">Framework view: <b>{html.escape(framework)}</b>. '
        'NIST is a mapped view of the CIS-backed deterministic checks.</p>'
        + "".join(blocks)
        + '<p><a href="/">← Audit more configurations</a></p></body></html>'
    )


@app.post("/api/network/audit", response_class=HTMLResponse)
async def audit_network_configs(
    files: list[UploadFile] = File(...),
    framework: str = Form("all"),
):
    if framework not in FRAMEWORK_VIEWS:
        return HTMLResponse("Invalid framework view", status_code=400)
    if not files or len(files) > MAX_NETWORK_FILES:
        return HTMLResponse(
            f"Upload between 1 and {MAX_NETWORK_FILES} configuration files", status_code=400
        )
    with tempfile.TemporaryDirectory(prefix="attestor-network-upload-") as temp_name:
        work_dir = Path(temp_name)
        items = [await _audit_network_upload(upload, framework, work_dir) for upload in files]
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
