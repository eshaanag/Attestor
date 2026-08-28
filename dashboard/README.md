# Dashboard

Server-rendered web UI built on **FastAPI + Jinja2 + htmx** (no React / no SPA
build step).

- **Round-1 (in scope) — local web GUI (Phase 7):** a "Run audit" button that
  invokes the engine on the local host, streams live per-check results from the
  engine's NDJSON output, and links to the generated offline HTML report.
- **Stretch (Phase 8) — fleet dashboard:** the same stack grows into a multi-host
  view over the `backend/` collector API. Only started after Phases 0–7 are
  complete and the backend API contract is defined.

## PS26155 organizational ingestion

The same local FastAPI page accepts one or more saved Cisco IOS/IOS-XE or
Juniper Junos config files and returns JSON, standalone HTML, PDF, and an
evidence-bundle ZIP for each successful file. The ZIP contains the three report
formats plus a hash/provenance manifest; it never contains the raw uploaded
configuration file. Because report evidence may contain matched command text,
the ZIP must be handled as sensitive audit material. Uploads are processed in an
isolated temporary directory and are not retained.

Built-in Cisco and Junos uploads may include one optional `show version` file
per configuration, paired by multipart order. The parser records only explicit
hostname/model/serial/software labels and the command-output SHA-256. A count
mismatch, wrong-vendor file, malformed text, or hostname mismatch fails only
the paired item. Custom profiles reject device-facts files because they do not
have a verified hardware parser.

The console preserves the established Windows/Linux local audit and adds a
persistent network workspace. Built-in adapters cover the verified Cisco IOS
scope and the four-control Junos subset. Published organization-defined profiles
appear in the same upload selector and inventory, but are visually and
semantically separated from Attestor-verified adapters.

The framework selector offers CIS, NIST SP 800-53 mapped, or combined display.
It changes presentation only: deterministic source-backed checks are
authoritative. Cisco IOS has fourteen CIS-backed controls; Juniper Junos has a
verified four-control vendor-documentation baseline subset. NIST is a mapped
presentation of those checks, not a separate native NIST rule pack. Other
vendors and broader Junos coverage remain roadmap.

PDF remediation remains dry-run by default for built-in adapters and makes no
provider call. Organization-defined reports bypass AI remediation and show the
operator-authored, source-referenced remediation instead.

## Training Studio

`/training` accepts an unfamiliar genuine configuration plus optional text/PDF
vendor documentation. Raw configuration is discarded after analysis. SQLite
stores the configuration SHA-256, a bounded redacted document excerpt, and
versioned redacted command patterns.

Upload analysis is always dry-run. The review page shows the uncached pattern
count and estimated Haiku-tier cost before an explicit AI action. That action
requires `ANTHROPIC_API_KEY` and a positive `max_calls` cap, refuses an
insufficient cap before provider access, and records actual token/cost totals.
Suggestions remain unconfirmed until a human accepts or corrects them.

Confirmed patterns can become source-referenced rules in a draft vendor profile.
Publication requires an attached knowledge source and at least one enabled rule.
The custom engine performs exact redacted full-line matching and fails closed;
hierarchical or ambiguous syntax must stay out of this flat-profile path.

## Organizational console

Open `http://localhost:8000` for the product overview, then choose **Open audit
console**. The console is a local organization workspace for the current
session: upload one or more genuine configurations, filter the inventory by
vendor/status/search, and open any device for its compliance score, severity-
sorted findings, evidence, remediation, scan history, JSON/HTML/PDF links, and
the per-scan evidence bundle. Repeated successful scans under the same stable
device ID and framework view show score movement, new failures, fail-to-pass
resolutions, configuration changes, coverage changes, and historical downloads.
Failed attempts and different framework views are never interpreted as posture
movement.

Inventory, training, knowledge-source metadata, profiles, and history persist in
local SQLite under `dashboard/data/` (gitignored). Raw configurations and
credentials are not stored. A failed file is recorded independently and cannot
imply success for another bulk item. Authentication, role-based access,
background workers, and a remote multi-user fleet service remain production
hardening work.

Software-version comparison requires explicit parsed facts on both scans. The
comparison code is covered with genuine vendor outputs, but the retained corpus
does not contain two captures from the same physical device across an upgrade;
that specific live observation is not claimed.
