# Dashboard

Server-rendered web UI built on **FastAPI + Jinja2 + htmx** (no React / no SPA
build step).

- **Round-1 (in scope) — local web GUI (Phase 7):** a "Run audit" button that
  invokes the engine on the local host, streams live per-check results from the
  engine's NDJSON output, and links to the generated offline HTML report.
- **Stretch (Phase 8) — fleet dashboard:** the same stack grows into a multi-host
  view over the `backend/` collector API. Only started after Phases 0–7 are
  complete and the backend API contract is defined.
