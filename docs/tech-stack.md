# Attestor — Tech Stack Decisions

For each layer: **what we use and why**, **the realistic alternative and why
not**, and **what would force us to revisit**. Where a common choice is wrong
for a hackathon timeline + live judge demo, this doc says so and proposes the
better option instead of rubber-stamping it.

---

## 1. Windows engine

**Use: PowerShell 5.1+ (Windows PowerShell, built in).**
- *Why:* ships on every Windows 11 install — zero install for the demo. Native,
  first-class access to the exact surfaces CIS Windows controls target:
  registry (`Get-ItemProperty`), local security policy (`secedit /export`),
  audit policy (`auditpol /get`), services (`Get-Service`), account policy
  (`net accounts` / `secedit`). This is precisely the language the PS text
  recommends for Windows.
- *Alternative: Python on Windows.* Rejected — requires installing Python on the
  target, and reaching secpol/auditpol from Python means shelling out to the
  same native tools anyway, so we'd add a dependency to gain nothing.
- *Revisit if:* we ever need the engine and the ledger to be one process on
  Windows. We won't — ledger consumes `results.json` out-of-band (see
  architecture §4c).

## 2. Linux engine

**Use: Python 3 (standard library first).**
- *Why:* Python 3 ships on Ubuntu 22.04. Real data structures and real testing
  (`pytest`) for the dispatcher, versus brittle string-parsing in shell. The PS
  text explicitly allows bash **or** python for Linux; python wins on
  testability and on sharing the results schema with report/ledger.
- *Alternative: bash.* Rejected as the primary engine — parsing `sysctl`,
  `stat`, `systemctl`, `dpkg` output in bash is fragile and hard to unit-test;
  a subtle parse bug is exactly the "silent false pass" AGENTS.md §0 forbids. We
  still *call* these binaries, but the logic and comparisons live in Python.
- *Revisit if:* a target environment genuinely lacks Python 3 (none of our MVP
  targets do).

## 3. Rule format

**Use: YAML, validated by JSON Schema (draft-07) — `schema/rule_schema.json`.**
- *Why:* human-readable and diff-friendly (non-developer can author/audit a
  control), while the JSON Schema gives a hard, fail-closed contract. This *is*
  the wedge against OpenSCAP's XML sprawl and against hackathon tools' hardcoded
  `if` blocks.
- *Alternative: XCCDF/OVAL XML* (rejected — the very complexity we're
  differentiating from) *or JSON/TOML rules* (rejected — JSON is noisy to hand-
  author; TOML is awkward for the nested `checks[]` list).
- *Revisit if:* rule authors need macros/templating across many near-identical
  controls — then add a small build step that expands templates *into* the same
  validated YAML, without changing the schema.

## 4. Report generation

**Use: Jinja2 → a single self-contained, offline HTML file (inline CSS + minimal
vanilla JS).**
- *Why:* opens on any machine with no network and no server — critical for a
  demo on conference wifi. Jinja2 is battle-tested and already in the Python
  stack. Inline everything so the file is portable and archivable alongside its
  ledger hash.
- *Alternative: PDF* (rejected for MVP — adds a heavy renderer like
  wkhtmltopdf/weasyprint; HTML "Print to PDF" covers the need) *or a React SPA
  report* (rejected — overkill for a static findings document).
- *Revisit if:* auditors demand signed PDF deliverables — add a PDF export from
  the same HTML later.

## 5. Ledger (tamper-evidence)

**Use: Python `hashlib` SHA-256 over a canonical `results.json`, appended to a
per-host `chain.jsonl`.**
- *Why:* SHA-256 is standard, stdlib, and easy to explain to a judge in one
  sentence. A newline-delimited chain file (`{prev_hash, this_hash, ts,
  host_id}` per line) is trivial to append and to verify end-to-end. Canonical
  serialization (architecture §4b) makes hashes reproducible.
- *Alternative: SQLite ledger.* Deferred — a flat JSONL chain is simpler to
  demo and to hand-verify; SQLite adds value only at fleet scale.
- *Revisit if:* a host accumulates thousands of reports (indexed lookups) — move
  the chain into SQLite while keeping the same hashing contract.

## 6. Fleet backend *(Phase 8, stretch)*

**Use: FastAPI + SQLite (upgrade path to Postgres).**
- *Why:* FastAPI gives typed request/response models and auto OpenAPI docs
  (good demo artifact) with minimal code, same language as everything else.
  SQLite = zero-ops for a demo fleet.
- *Alternative: Flask* (less built-in validation) *or Django* (too heavy for a
  collector API).
- *Revisit if:* fleet grows past a few dozen hosts or needs concurrent writers →
  swap SQLite for Postgres (managed free tier). **Note:** free-tier Postgres
  (Railway/Fly/Supabase) will cap out under a genuinely "large/diverse
  environment" — we present fleet mode as a *demonstrated architecture*, and are
  honest that production scale needs a paid DB tier.

## 7. Fleet dashboard *(Phase 8, stretch)*

**Use: server-rendered FastAPI + Jinja2 + htmx (decision locked).**
- *Why:* the fleet view is essentially tables and status badges with filter,
  drill-down, and live refresh — htmx over the existing FastAPI + Jinja2 stack
  delivers all of that with one language, one server, far less code, and reuse
  of the report templates. It is also the same stack as the round-1 local GUI
  (§8), so the two share code instead of diverging.
- *Alternative: a React + Vite SPA* (the scaffold's original choice). Rejected
  for a hackathon timeline + judge demo: a second build toolchain, a second
  dependency tree, and CORS/auth plumbing, all to render status tables. The
  time cost buys nothing the demo needs.
- *Revisit if:* we ever need rich client-side interactivity (complex charts, an
  offline SPA). Not expected for MVP-plus-fleet.

## 8. GUI for the standalone tool *(round-1 scope — Phase 7)*

The PS explicitly asks for a **GUI-based** solution, so this is in round-1 scope
as its own phase (Phase 7), between CLI polish and the fleet stretch work — not
deferred to the fleet dashboard.
- *What:* a **minimal local web GUI** on the FastAPI + Jinja2 + htmx stack, run
  locally with a "Run audit" button that invokes the engine, streams the NDJSON
  results (architecture §4a) into a live-updating page, and links the generated
  report. It doubles as the foundation for the Phase 8 fleet dashboard, so it is
  not throwaway work.
- *Exit condition:* from a browser on the local host, clicking "Run audit" runs
  the real engine, shows live pass/fail/error results as checks complete, and
  links to a generated report that opens offline.

For PS26155 Phase H', FastAPI's multipart support (`python-multipart`) is used
for bounded single/bulk Cisco config uploads. Files remain temporary; the
existing network engine still consumes a normal filesystem path. Report output
is JSON + standalone HTML + ReportLab PDF, with provider calls disabled by
default.

## 9. Deployment

- **Standalone (MVP):** `git clone` + `pip install -r requirements.txt`; run the
  engine for your OS. No server required. This is the primary demo path.
- **Fleet [Phase 2]:** backend on a small VM or free-tier PaaS (Railway/Fly);
  hosts POST signed `results.json`.
- **Testnet anchoring [Phase 9]:** Ethereum Sepolia + a minimal Solidity contract,
  called via `web3.py`. Private key / RPC URL live only in `.env` (gitignored,
  AGENTS.md §6) — never committed.
- *Revisit if:* institutional deployment needs packaging (a signed installer or
  container) — add later; out of MVP scope.

---

## Dependency budget (keep it small for a clean demo)

- Python: `pyyaml`, `jsonschema`, `jinja2` for MVP. `fastapi`/`uvicorn`,
  `web3` only when the corresponding stretch phase starts.
- PowerShell: no external modules for MVP — native cmdlets only.
- Pin exact versions in `requirements.txt` before first dependency commit.
