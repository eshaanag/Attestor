# Dashboard

Server-rendered web UI built on **FastAPI + Jinja2 + htmx** (no React / no SPA
build step).

- **Round-1 (in scope) — local web GUI (Phase 7):** a "Run audit" button that
  invokes the engine on the local host, streams live per-check results from the
  engine's NDJSON output, and links to the generated offline HTML report.
- **Stretch (Phase 8) — fleet dashboard:** the same stack grows into a multi-host
  view over the `backend/` collector API. Only started after Phases 0–7 are
  complete and the backend API contract is defined.

## PS26155 network ingestion (Phase H')

The same local FastAPI page accepts one or more saved Cisco IOS/IOS-XE or
Juniper Junos config files and returns JSON, standalone HTML, and PDF reports
for each file. Uploads are processed in an isolated temporary directory and
are not retained.

The console has two explicit workflows: the primary network configuration audit
and the established local Windows/Linux VM audit. The network surface exposes
the verified Cisco IOS scope and the four-control Junos subset, framework view,
bulk upload, and offline report links. Other vendors remain roadmap.

The framework selector offers CIS, NIST SP 800-53 mapped, or combined display.
It changes presentation only: deterministic source-backed checks are
authoritative. Cisco IOS has fourteen CIS-backed controls; Juniper Junos has a
verified four-control vendor-documentation baseline subset. NIST is a mapped
presentation of those checks, not a separate native NIST rule pack. Other
vendors and broader Junos coverage remain roadmap.

PDF remediation remains dry-run by default from the dashboard, clearly labelled,
and makes no provider call. The F' human-confirmation training loop remains a
CLI workflow in this round.
