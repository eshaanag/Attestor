# dashboard/ui — UI Support Layer

This folder contains shared configuration, fixtures, and utility modules for
the **Attestor** local web dashboard (Phase 7 of the project roadmap).

It is **not** the FastAPI application itself — that lives one level up in
`dashboard/`. This folder holds the supporting pieces that the dashboard
imports or that developers use in isolation while building and testing the UI.

---

## Relationship to the Main Dashboard

```
dashboard/
├── app.py              # FastAPI entry point  (parent scope)
├── templates/          # Jinja2 HTML templates (parent scope)
└── ui/                 # ← you are here: shared UI support layer
    ├── config.py
    ├── sample_data.json
    └── readme.md
```

The dashboard imports constants from `config.py` and uses `sample_data.json`
as a fixture when the real audit engine is not running (development mode,
demos, CI).

---

## Files

### `config.py`

Shared constants imported by the dashboard and any utility scripts in this
folder. Defines:

| Constant | Value | Purpose |
|---|---|---|
| `APP_NAME` | `"ATTESTOR"` | Application title used in report headers |
| `APP_VERSION` | `"1.0.0"` | Version string |
| `SUPPORTED_PLATFORMS` | `["Windows", "Linux"]` | Platforms the audit engine targets |
| `RESULT_STATUSES` | `["Pass", "Fail", "Error"]` | Enumeration of possible check outcomes |
| `DEFAULT_REPORT_TITLE` | `"ATTESTOR Security Audit Report"` | Default heading for generated reports |
| `DEFAULT_DATA_FILE` | `"sample_data.json"` | Default fixture path |
| `DEFAULT_REPORT_FILE` | `"sample_report.json"` | Default output path for generated reports |
| `DEFAULT_UI_CONFIG` | `"ui_config.yaml"` | Path for future dashboard display settings |

### `sample_data.json`

A realistic mock audit result in the exact JSON shape produced by the
Attestor audit engines. Use this file whenever you need to build or test
UI components without running a live audit.

### `readme.md`

This file.

---

## Audit Result Structure

`sample_data.json` (and real engine output) follows this top-level shape:

```json
{
  "audit_id":           "ATT-2026-001",
  "platform":           "Windows",
  "benchmark":          "CIS Microsoft Windows Benchmark",
  "benchmark_version":  "1.0",
  "timestamp":          "2026-08-30T10:30:00",
  "hostname":           "WIN-AUDIT-01",
  "summary": {
    "total":   20,
    "passed":  14,
    "failed":   5,
    "errors":   1
  },
  "controls": [ ... ]
}
```

Each object in `controls` has:

| Field | Type | Always present | Notes |
|---|---|---|---|
| `id` | string | ✅ | CIS control ID, e.g. `"2.1.1"` |
| `title` | string | ✅ | Short human-readable name |
| `status` | string | ✅ | See **Status values** below |
| `severity` | string | ✅ | See **Severity values** below |
| `description` | string | ✅ | What the check tests |
| `remediation` | string | ❌ | Only present when `status` is `Fail` or `Error` |

### Status Values

| Value | Meaning |
|---|---|
| `Pass` | The system meets the CIS requirement. |
| `Fail` | The system does **not** meet the requirement. A `remediation` field is included. |
| `Error` | The check could not complete (e.g., permission denied, missing service). Treat as **manual review needed** — never assume pass. |

### Severity Values

| Value | Meaning |
|---|---|
| `High` | Significant security risk if the control fails. |
| `Medium` | Moderate risk; should be addressed. |
| `Low` | Minor hardening item. |

The current sample data includes 20 controls covering all three statuses and
all three severity levels, making it suitable for exercising every display
path in the UI.

---

## Using `sample_data.json` During Development

**Load it in Python:**

```python
import json
from pathlib import Path

with open(Path(__file__).parent / "sample_data.json") as f:
    audit = json.load(f)

summary  = audit["summary"]
controls = audit["controls"]
```

**Filter by status:**

```python
failures = [c for c in controls if c["status"] == "Fail"]
```

**Filter by severity:**

```python
high_priority = [c for c in controls if c["severity"] == "High"]
```

**Compute compliance score:**

```python
score = round(100 * summary["passed"] / summary["total"])
# → 70
```

The `RESULT_STATUSES` and `SUPPORTED_PLATFORMS` lists in `config.py` can be
used to drive dropdowns and filter controls in templates without hardcoding
strings.

---

## Roadmap — Planned UI Utilities

These modules are planned for this folder. Each will be committed
independently once built and reviewed:

| Module | Purpose |
|---|---|
| `data_loader.py` | Load and validate any audit JSON file; raise clear errors on malformed input |
| `filter_controls.py` | Pure functions for filtering controls by status and severity |
| `status_colors.py` | Map status/severity values to CSS class names and hex colours (single source of truth for templates) |
| `badge_generator.py` | Produce a human-readable compliance score string from a summary block |
| `mock_stream.py` | Yield controls from `sample_data.json` as NDJSON to simulate the engine's live stream during UI development |
| `ui_config.yaml` | Dashboard display settings: page title, colour theme, auto-refresh interval |
| `summary_renderer.py` | Print a formatted summary table to stdout for CLI-level smoke testing |

---

## Contribution Notes

- **Do not add CIS controls here.** Control logic belongs in `rules/` and
  `engines/`. This folder is UI-layer only.
- **Keep `config.py` as the single source of truth** for status and platform
  enumerations. Do not duplicate these strings in templates or utility scripts.
- **`sample_data.json` is a fixture, not a report.** Do not commit
  machine-generated audit reports here; they belong in `reports/` and are
  gitignored. This file is checked in intentionally as a stable test fixture.
- Any new utility added here should be independently importable and should not
  depend on the FastAPI app being running.
