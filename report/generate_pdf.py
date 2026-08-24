#!/usr/bin/env python3
"""Offline PDF compliance report for G' (additive to the HTML renderer)."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
except ImportError:
    sys.exit("ERROR: reportlab not installed. Run: python3 -m pip install reportlab==4.2.5")

from report.remediation import RemediationStore, remediation_for_failed_controls


def load_results(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def build_pdf(
    results: dict[str, Any],
    output: str | Path,
    *,
    state_dir: Path | None = None,
    real_api: bool = False,
    max_calls: int = 0,
    api_key: str | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    controls = results.get("controls", [])
    remediation = remediation_for_failed_controls(
        controls,
        RemediationStore(state_dir) if state_dir else RemediationStore(),
        real_api=real_api,
        max_calls=max_calls,
        api_key=api_key,
        model=model or "claude-haiku-4-5-20251001",
    )
    remediation_by_rule = {item["rule_id"]: item for item in remediation}
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CenterTitle", parent=styles["Title"], alignment=TA_CENTER, spaceAfter=12))
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="Failed", parent=styles["BodyText"], textColor=colors.HexColor("#b42318")))
    doc = SimpleDocTemplate(str(output), pagesize=letter, rightMargin=.55*inch, leftMargin=.55*inch, topMargin=.5*inch, bottomMargin=.5*inch)
    story = [Paragraph("Attestor Network Compliance Report", styles["CenterTitle"])]
    device = results.get("device") or {}
    host = results.get("host") or {}
    device_id = escape(str(device.get("device_id", "not recorded")))
    hostname = escape(str(device.get("hostname") or "hostname unavailable"))
    serial = escape(str(device.get("serial") or device.get("serial_number") or "not exposed by config"))
    story += [Paragraph(f"<b>Device:</b> {device_id} ({hostname})", styles["BodyText"]),
              Paragraph(f"<b>Serial:</b> {serial}", styles["BodyText"]),
              Paragraph(f"<b>Vendor / platform:</b> {escape(str(device.get('vendor', 'unknown')))} / {escape(str(device.get('platform', 'unknown')))}", styles["BodyText"]),
              Paragraph(f"<b>Config SHA-256:</b> {escape(str(device.get('config_sha256', 'not recorded')))}", styles["Small"]),
              Paragraph(f"<b>Runner:</b> {escape(str(host.get('hostname', 'unknown')))} | <b>Report ID:</b> {escape(str(results.get('report_id', 'unknown')))}", styles["Small"]), Spacer(1, 10)]
    summary = results.get("summary", {})
    story.append(Table([["PASS", "FAIL", "ERROR", "MANUAL", "N/A"], [summary.get("pass", 0), summary.get("fail", 0), summary.get("error", 0), summary.get("manual", 0), summary.get("not_applicable", 0)]], style=TableStyle([("GRID", (0,0), (-1,-1), .5, colors.grey), ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#eef2f6")), ("ALIGN", (0,0), (-1,-1), "CENTER")]), colWidths=[1.25*inch]*5))
    story.append(Spacer(1, 12))
    for control in sorted(controls, key=lambda c: (0 if c.get("status") in {"fail", "error"} else 1, c.get("rule_id", ""))):
        status = control.get("status", "unknown").upper()
        color = "#b42318" if status == "FAIL" else "#1a7f37" if status == "PASS" else "#9a6700"
        story.append(Paragraph(f"<font color='{color}'><b>{status}</b></font>  <b>{escape(str(control.get('rule_id')))}</b> — {escape(str(control.get('title', '')))}  [severity: {escape(str(control.get('severity', 'unknown')))}]", styles["BodyText"]))
        story.append(Paragraph(f"<b>Evidence:</b> {escape(str(control.get('evidence_summary', '')))}", styles["Small"]))
        if control.get("status") == "fail":
            item = remediation_by_rule.get(control["rule_id"], {})
            story.append(Paragraph(f"<b>AI-generated remediation ({escape(str(item.get('mode', 'unknown')))}):</b> {escape(str(item.get('text', 'unavailable')))}", styles["Small"]))
        mappings = control.get("framework_mappings") or []
        if mappings:
            mapping_text = "; ".join(
                f"{mapping.get('framework')} {mapping.get('control_id')}"
                for mapping in mappings
            )
            story.append(Paragraph(f"<b>Framework mappings:</b> {escape(mapping_text)}", styles["Small"]))
        story.append(Spacer(1, 8))
    doc.build(story)
    return {"output": str(output), "failed_controls": len(remediation), "remediations": remediation}


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an offline Attestor PDF report")
    parser.add_argument("results")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--real-api", action="store_true")
    parser.add_argument("--max-calls", type=int, default=0)
    parser.add_argument("--model", default=None)
    args = parser.parse_args()
    result = build_pdf(load_results(args.results), args.output, state_dir=args.state_dir, real_api=args.real_api, max_calls=args.max_calls, api_key=os.environ.get("ANTHROPIC_API_KEY"), model=args.model)
    print(json.dumps({"output": result["output"], "failed_controls": result["failed_controls"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
