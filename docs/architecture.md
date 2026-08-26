# Attestor — Architecture

Status: design doc for the MVP (Windows 11 Standalone + Ubuntu 22.04 Desktop,
plus scoped PS26155 Cisco IOS and Juniper Junos adapters). Written to be improved, not rubber-stamped — where the obvious
design isn't the best one, the better option and the reasoning are called out
inline and in **Open Risks**.

---

## 1. System diagram

```
                         rules/<target>/*.yaml   (rule packs, data)
                                   │
                                   ▼
                      schema/rule_schema.json  ──► validate (fail-closed)
                                   │
                                   ▼
        ┌─────────────────────────────────────────────────┐
        │               ENGINE (per target)                  │
        │   engines/linux/run_audit.py  (Python 3)           │
        │   engines/windows/run_audit.ps1 (PowerShell)       │
        │   engines/network/run_audit.py (Cisco IOS)         │
        │   engines/network/run_junos_audit.py (Junos)       │
        │                                                    │
        │   loads rules ─► DISPATCHER ─► one check fn per     │
        │                   check_type   (kernel_module,      │
        │                                 sysctl, registry…)  │
        └─────────────────────────────────────────────────┘
                                   │
             per-check result  (streamed as NDJSON, see §4)
                    │                                  │
                    ▼                                  ▼
   dashboard/ LOCAL WEB GUI (round-1)          results.json  (canonical aggregated report)
   FastAPI+Jinja2+htmx: "Run audit"                  │                       │
   button, live results, report link                 ▼                       ▼
                    ▲                       ledger/ (SHA-256 chain)   report/ (Jinja2 → HTML)
                    │                                 │                       │
                    └──── links to ──────────────────┼───────────────────────┘
                                                      ▼
                                    chain.jsonl (per host) + standalone offline HTML report
                                                      │
        ┌─────────────────────────────────── [STRETCH] ───────────────────────────────────┐
        │  backend/ (FastAPI collector) ◄── hosts POST signed results.json  [PHASE 8]       │
        │            │                                                                      │
        │            ▼                                                                      │
        │  dashboard/ (fleet view, same htmx stack)   [PHASE 9] report links → Sepolia     │
        └────────────────────────────────────────────────────────────────────────────────┘
```

Multiple target adapters, one downstream. All engines emit the **same**
`results.json` schema, so the ledger and report generator are target-agnostic
and written once.
The **local web GUI (`dashboard/`, round-1 scope)** consumes the engine's live
NDJSON stream for progress and links the generated report; the *same* htmx stack
grows into the fleet dashboard (stretch).

---

## 2. Folder responsibilities

| Folder | Responsibility | Owner language |
|--------|----------------|----------------|
| `rules/<target>/` | Rule packs — one YAML file per control. Pure data. Targets include OS packs, `cisco_ios`, and the scoped `juniper_junos` baseline. | YAML |
| `schema/` | `rule_schema.json` — the single contract every rule file must satisfy. Fail-closed: a malformed rule never reaches an engine. | JSON Schema |
| `engines/linux/` | `run_audit.py` — loads + validates rules for a Linux target, dispatches each `check_type`, emits results. | Python 3 |
| `engines/windows/` | `run_audit.ps1` — same role on Windows; native registry / `secedit` / `auditpol` access. | PowerShell |
| `engines/network/` | Cisco IOS flat/block adapter and scoped Junos brace-aware adapter; file input only, no simulated SSH. | Python 3 |
| `report/` | Consumes `results.json`, renders a **self-contained, offline** HTML report (inline CSS/JS, no network). | Python (Jinja2) |
| `ai/` | Measures deterministic-rule misses, redacts sensitive values, and stores cached/provider or human-confirmed discovery metadata. It never determines compliance status. | Python |
| `ledger/` | SHA-256 hash-chain over canonical `results.json` per host; append + verify; break detection. | Python |
| `backend/` | *[Stretch]* FastAPI fleet collector — receives host submissions, stores, exposes API. | Python (FastAPI) |
| `dashboard/` | **Round-1 (in scope):** minimal local web GUI — FastAPI + Jinja2 + htmx; a "Run audit" button that invokes the engine, streams live per-check results from the engine's NDJSON output, and links the generated report. **Stretch:** same stack grows into the multi-host fleet dashboard over `backend/`. | Python (FastAPI) + Jinja2 + htmx |
| `tests/` | Rule-schema validator (`validate_rules.py`), fixtures, engine unit tests. | Python |
| `reference/` | Cloned comparison repos — **read-only, gitignored, never shipped.** Read for check *logic*, never copy-pasted (license discipline, AGENTS.md §7). | — |

---

## 3. Data flow — what format crosses each boundary

1. **rule YAML → validated rule object.** `rules/**/*.yaml` is parsed and
   validated against `schema/rule_schema.json`. Invalid → hard stop, the rule is
   excluded and reported as a load error (never silently skipped into a pass).
2. **validated rule → check dispatch.** The engine reads `rule.checks[]` and
   routes each item to the dispatcher function for its `check_type`.
3. **check → per-check result.** Each check returns a small object:
   `{rule_id, check_index, status, actual, expected, evidence, error?}` where
   `status ∈ {pass, fail, error, not_applicable, manual}`.
4. **per-check results → aggregated report.** The engine rolls per-check results
   up to a per-control status (all checks must pass → control passes; any error
   → control = error; `automated:false` → `manual`), plus host metadata and
   counts, into **`results.json`**.
5. **results.json → hashed + chained.** The ledger canonicalizes `results.json`
   (see §4), computes SHA-256, and appends `{prev_hash, this_hash, timestamp,
   host_id}` to that host's chain.
6. **results.json → rendered HTML.** The report generator renders the same
   `results.json` into an offline HTML file, showing per-control
   pass/fail/error/manual/NA, remediation, CIS ID, level, and the ledger hash.
7. **Unmatched syntax → discovery metadata.** After deterministic checks, F'
   inventories active lines that matched no production rule. Structural context
   lines are excluded from provider candidates. Any future AI classification is
   redacted, cached, capped, dry-run by default, and never overrides a rule.
   The first approved real batch used an available Haiku-tier model only after
   explicit approval; provider usage is checkpointed after each response.

**Control-status roll-up rules (the accuracy-critical part):**
- All checks `pass` → control **PASS**
- Any check `fail` (and none `error`) → control **FAIL**
- Any check `error` → control **ERROR** (never coerced to pass or fail)
- `automated: false` → control **MANUAL** (checks empty; needs human review)
- Rule not applicable to this host/profile → **NOT_APPLICABLE**

---

## 4. Design decisions & improvements over the naive plan

The scaffold implies "engine → results.json → report". Two refinements make it
meaningfully better; both are cheap now and expensive to retrofit later.

### 4a. NDJSON stream + canonical results.json (not just one JSON blob)
The naive plan writes a single `results.json` at the end. Problem: the **round-1
local web GUI** (Phase 7 — the PS explicitly wants a GUI) needs results *as each
check finishes*, not after a 200-control run completes.

**Decision:** the engine emits each per-check result as one line of **NDJSON**
(newline-delimited JSON) to stdout *while running*, and writes the final
aggregated **`results.json`** at the end. The GUI/CLI streams the NDJSON for
live progress; the ledger and report consume the final canonical file. One
engine, both consumers, so the Phase 7 GUI needs no engine rework.

### 4b. Canonical serialization before hashing
A hash chain is only tamper-evident if the *input bytes are reproducible*. If we
hash whatever `json.dumps` happens to emit, key ordering or whitespace changes
silently break the chain and produce false "tampering" alarms.

**Decision:** the ledger hashes a **canonical form** of `results.json` — sorted
keys, UTF-8, `separators=(',', ':')`, timestamps in a fixed format, and the
ledger's own hash field excluded from the hashed content. Documented in
`ledger/` and pinned in `docs/interfaces.md` so both engines agree.

### 4c. Ledger & report are OS-agnostic Python, engines are native
The report generator and ledger are **Python** and consume `results.json`, so
they are written once and run anywhere. Consequence: a Windows host needs Python
present to render/chain locally. Alternative considered — reimplement ledger in
PowerShell — rejected: it doubles the most security-sensitive code (hashing) in
two languages, doubling the chance of a subtle mismatch. Python-on-Windows is a
one-time install; a divergent second hasher is a permanent liability.

### 4d. Interface contract is written before the consumers
Per AGENTS.md Rule C7, the exact `results.json` shape lives in
`docs/interfaces.md` and is agreed before the report generator or ledger is
built. Both engines build *to* that contract.

### 4e. Public-chain privacy boundary

The optional Sepolia anchor publishes only SHA-256 root material (the current
report hash and its predecessor). Report contents, configuration text, device
metadata, and AI classifications remain off-chain in local report/ledger files.
The transaction is a tamper-evidence proof, not a public copy of the audited
configuration.

---

## 5. Open Risks (not happy paths)

These are the ways this architecture breaks under real use. Each has a
mitigation stance; unmitigated ones are flagged.

1. **Insufficient privilege → silent false PASS (highest risk).** Many checks
   need root/Administrator (`secedit`, `auditpol`, reading `/etc/shadow`). If run
   unprivileged, a naive check reads "nothing there" and could report PASS.
   *Mitigation:* engine detects privilege at startup; any check requiring
   elevation that can't get it returns **error**, never pass. A check must prove
   it observed the real state, or it errors.

2. **A check throws instead of pass/failing.** Exceptions (missing binary,
   unexpected output format, permission denied mid-run) must map to **error**
   with the reason captured in `evidence`. *Risk:* an over-broad `try/except`
   that swallows an exception and defaults to pass. *Mitigation:* dispatcher
   contract — a check returns a status object or raises; a raise becomes
   `error`, and there is **no default-pass path** anywhere.

3. **Two rules conflict.** Two controls asserting contradictory expected states
   for the same setting, or duplicate CIS IDs in a pack. *Mitigation:* schema +
   validator enforce unique `id` per pack; a lint step flags duplicate
   `(check_type, target-key)` pairs. Semantic contradictions the schema *cannot*
   catch — flagged as a manual review item during rule authoring.

4. **Rule pack vs benchmark version drift.** Running old rules against a newer
   benchmark, or vice versa. *Mitigation:* every rule carries `benchmark` +
   `benchmark_version`; the report header states which benchmark version was
   evaluated so a stale pack is visible, not hidden.

5. **Ledger canonicalization fragility.** (See §4b.) If canonical form isn't
   pinned, benign re-serialization reads as tampering — crying wolf destroys
   trust in the mechanism. *Mitigation:* canonical form is specified and unit-
   tested with a "re-serialize → same hash" test before Phase 4 ships.

6. **Host offline mid-fleet-scan [Phase 2].** *Mitigation by design:* the local
   audit, local report, and local per-host chain are fully standalone and do not
   need the backend. An offline host keeps auditing and chaining locally; on
   reconnect it submits queued reports. The backend must handle partial/missing
   submissions and show **last-seen / stale** indicators rather than implying a
   silent host is compliant.

7. **NDJSON stream truncated / engine crashes mid-run.** A partial run must never
   render as a complete report. *Mitigation:* `results.json` is written only on
   clean completion and includes a `total_controls` vs `evaluated` count; the
   report flags an incomplete run loudly.

8. **WSL vs native.** A Linux engine run under WSL inspects the WSL guest, not
   Windows — a real footgun for a judge testing on a laptop. *Mitigation:* engine
   records and displays the exact OS/kernel/host it evaluated, so what was
   audited is never ambiguous.

---

## 6. Scope boundaries

**In round-1 scope:** the two OS MVP targets, the engines, ledger, report, and the
**local web GUI** (Phase 7 — `dashboard/` run locally). The PS26155 network
track adds file-based Cisco IOS and scoped Junos adapters to the same GUI. GUI
exit condition: from
a browser on the local host, clicking "Run audit" runs the real engine, shows
live pass/fail/error results as checks complete, and links to a generated report
that opens offline.

For the additive PS26155 track, the same local dashboard provides a bounded
multipart ingestion adapter for saved Cisco IOS/IOS-XE or Juniper Junos
configurations. It writes each upload only to a temporary directory, invokes the
selected file-based adapter, and returns JSON plus offline HTML/PDF. Cisco has
14 CIS-backed controls; Junos has four source-backed vendor-baseline controls.
Framework selection is a report view over deterministic results; NIST is a
mapped view, not a native second rule engine. No sandbox/SSH connector is
simulated.

The AI layer is advisory discovery only. It classifies genuinely unmatched,
redacted syntax and generates cached remediation text for failed controls; it
cannot change a deterministic pass/fail result. Dry-run is the dashboard
default. The optional Sepolia anchor publishes only report hashes, never
configuration content or report metadata.

**Explicitly out of current scope:** RHEL 8/9, Windows 11 Enterprise, Ubuntu
20.04 / Server, all Level 2 controls, broader Junos controls, and all other
network vendors. The fleet backend/dashboard remains stretch work. Sepolia
anchoring is already proven for a Cisco network report and remains an optional
hash-only differentiator, not the compliance engine's authority.
