# Attestor

**Deterministic network compliance auditing with privacy-safe AI-assisted vendor
onboarding, offline reports, and optional tamper evidence.**

---

## Problem Statement

**SIH260382 — NTRO (National Technical Research Organisation)**
**Theme: Blockchain & Cybersecurity**

> Design and develop a tool to automatically assess the security configurations of desktops/laptops against the CIS Benchmark. The tool should scan the system, identify deviations from the benchmark, and generate a compliance report highlighting areas of non-compliance with actionable recommendations for remediation.

The current PS26155 track extends the proven OS foundation into an AI-assisted
network configuration auditor. See the concise
[`PS26155 architecture brief`](docs/ps26155-architecture.md) for the exact
delivered scope, privacy boundary, and roadmap.

---

## Why This Approach

- **Deterministic checks remain authoritative.** AI suggestions discover and
  categorize unfamiliar syntax; they never override pass/fail results.
- **Human-in-the-loop vendor onboarding.** An administrator can attach genuine
  vendor documentation, confirm redacted command patterns, publish an
  organization-defined profile, and reuse it without backend redeployment.
- **Evidence stays local.** Raw uploads are temporary. Reports render offline;
  AI receives only redacted patterns and only after an explicit capped action.
- **Tamper evidence is a bonus, not the compliance engine.** The optional ledger
  anchors only a SHA-256 hash, never configuration or report content.

---

## Prerequisites

- **Python 3.10+** — required on **both** Windows and Linux hosts. The Linux
  audit engine is Python; on Windows the audit engine is native **PowerShell**,
  but **report generation and the tamper-evident ledger are shared Python** and
  run on both platforms, so Python is required everywhere Attestor produces or
  chains a report.
- **PowerShell 5.1+** — required on Windows hosts for the audit engine (ships
  with Windows 11; no extra install).
- Python packages are pinned in `requirements.txt` and include FastAPI,
  ReportLab, Jinja2, schema validation, and the optional Sepolia client. No
  external PowerShell modules are needed.

---

## Folder Structure

```
attestor/
├── README.md
├── AGENTS.md
├── LICENSE
├── .gitignore
├── CONTRIBUTING.md
├── docs/
│   ├── architecture.md
│   ├── rule-schema.md
│   └── interfaces.md
├── engines/
│   ├── windows/
│   ├── linux/
│   └── network/
├── ai/
├── rules/
│   ├── windows11_standalone/
│   ├── windows11_enterprise/
│   ├── ubuntu2204_desktop/
│   ├── ubuntu2004_desktop/
│   └── rhel8/
├── schema/
├── report/
├── ledger/
├── backend/
├── dashboard/
├── tests/
└── reference/
```

---

## Status

| Target | Engine | Controls verified | Status |
|--------|--------|-------------------|--------|
| Ubuntu 22.04 Desktop (Level 1) | `engines/linux/run_audit.py` | 35 (sysctl + file_permission + kernel_module + config_grep + service_state + package_installed) | Verified on real VM |
| Windows 11 Standalone (Level 1) | `engines/windows/run_audit.ps1` | 30 (registry + secpol + account_policy + audit_policy + service_state) | Verified on real VM |

**Phase 0** through **Phase 7** and **Phase 9** are complete for the OS track.
For PS26155, Cisco IOS, scoped Junos, persistent single/bulk ingestion,
budget-capped AI-assisted training, organization-defined vendor profiles, and
JSON/HTML/PDF reporting are implemented and covered by the current automated
suite. Live SSH collection remains optional and unverified because no reachable
real device is part of the repository test environment.

**Current blockchain integration:** Ethereum Sepolia contract
[`0xbd19e20aD6C216A8a793fdE3Bd46B9D291Bf5C41`](https://sepolia.etherscan.io/address/0xbd19e20aD6C216A8a793fdE3Bd46B9D291Bf5C41), using
`anchorReport(currentHash, previousHash)`. The earlier Polygon Amoy deployment is
legacy and is not the contract used by the current integration.

See [`reports/sample-report.html`](reports/sample-report.html) for an example rendered report (opens offline, no network required).

### PS26155 network-device track

| Phase | Scope | Status | Evidence |
|---|---|---|---|
| A | Additive schema + interface contracts | Complete | Existing OS rules validate unchanged; current gate is 218 real rules plus 7 schema fixtures; canonical/ledger/anchor tests pass |
| B | Genuine Cisco IOS config corpus | Complete | 10 MIT-licensed source-backed IOS reference configs; immutable source commits, retrieval date, platform, and SHA-256 in `tests/fixtures/network/cisco_ios/manifest.json`; integrity test passes |
| C | Cisco IOS flat-check parser primitive | Complete | `engines/network/run_audit.py`; five manual-oracle checks span all 10 corpus files and each has pass + fail evidence; focused tests pass |
| D | Cisco IOS block-aware VTY/interface parser primitive | Complete | `engines/network/run_audit.py`; interface oracle has pass/fail coverage across all 10 source-backed configs; 21-test suite and rule validator pass |
| E | Cisco IOS rule pack + dual-framework report | Complete (scoped) | 14 source-backed CIS rules under `rules/cisco_ios/`, each with NIST SP 800-53 mapping; 10-config per-rule oracle has pass/fail evidence; 23 tests pass; report renders device identity and mappings offline |
| F | Network-report ledger + real Sepolia transaction | Complete (Cisco IOS scope) | Stable device chain verified; root `6d9319f05742791af8798a288e72e530a0d563a3037f7a5ddecb3d68d843239a` anchored in tx `4b9515e22e18523f08685a1013f8dbf064f9b62f97136cbc0b39132cd174d750`; `verifyRoot` returned found=true |
| F' | AI-assisted syntax discovery/training loop | Complete (deterministic compliance unchanged) | Training Studio persists only redacted patterns, displays pre-call cost, enforces a hard cap, records actual usage, and requires human confirmation; approved reference batch: 51 redacted candidates, `$0.019748` |
| G' | Offline PDF report + cached AI remediation | Complete (AI advisory scope) | ReportLab PDF renders the genuine Cisco report offline; 9 failed controls received clearly labelled Haiku-generated advisory remediation and reasoning; initial batch + one targeted retry used `$0.008774`; retry reproduced the known invalid `SHA-500` phrase, proving why human review remains required |
| H' | Organizational ingestion dashboard | Complete (scoped) | Persistent inventory, single/bulk upload, scan states, device history/detail, CIS/NIST-mapped views, JSON/HTML/PDF links, Training Studio, and published organization-defined profiles |
| J' | Low-code vendor profile path | Complete (organization-defined assurance) | Genuine config + vendor source upload, redacted pattern confirmation, publication gate, exact fail-closed pattern audit, pass/fail corpus proof, and explicit not-Attestor-verified labels in JSON/HTML/PDF |
| K' | Source-backed device identity facts | Complete (optional companion input) | Genuine Cisco/Junos `show version` corpus with provenance and SHA-256; optional CLI/dashboard pairing adds explicit model, serial, and software fields without changing compliance results; 89 tests pass |
| G | Optional additional vendor | Complete (scoped) | Juniper Junos four-control source-backed subset implemented; broader Junos and other vendors remain roadmap |
| H | Honest pitch/documentation pass | Complete | README, architecture brief, detailed architecture, runbook, demo script, vendor matrix, and scorecard state the verified Cisco/Junos scope and roadmap honestly |

The verified Phase C/D/E network track is limited to source-backed Cisco IOS
lab/reference configurations, not production backups or live sandbox captures.
Phase E includes 14 Cisco IOS rules whose corpus oracle contains both pass and
fail states. VTY/unused-interface checks are not claimed as verified. The
built-in network scope is Cisco IOS (14 source-backed CIS controls) and Juniper
Junos (four source-backed vendor-baseline controls). Other vendors can be
onboarded through an organization-defined exact-pattern profile, but those
profiles are not presented as Attestor-verified benchmark coverage. Native DISA
STIG and ISO/IEC 27001 packs, broader Junos coverage, and live SSH collection
remain roadmap. AI classification is discovery metadata only: deterministic
compliance results remain authoritative, credentials are redacted before
provider use, and dry-run remains the default.

### CLI Usage

```bash
# Linux — run all Level 1 controls and generate HTML report
python3 engines/linux/run_audit.py --level 1 --format html --output results.json

# Linux — run only specific controls
python3 engines/linux/run_audit.py --include 1.5.1 3.3.1.1 5.1.20

# Linux — exclude specific controls
python3 engines/linux/run_audit.py --exclude 2.1.11

# Windows (PowerShell) — run all Level 1 controls
.\engines\windows\run_audit.ps1 -Level 1 -Format html -Output results.json

# Windows — include/exclude
.\engines\windows\run_audit.ps1 -Include "2.3.1.1","2.3.17.1" -Format json
```

**Filter precedence:** `--include` narrows the rule set first (only listed IDs run), then `--exclude` removes from that set. `--level` filters independently (ANDed).

### Local Web GUI

```bash
python3 -m pip install -r requirements.txt
python3 -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8000
# Open http://127.0.0.1:8000
```

Use **Open audit console** to upload one or more saved Cisco IOS/IOS-XE or
Juniper Junos configurations. Choose a source-backed, NIST-mapped, or combined
report view, then download JSON, offline HTML, or PDF per device. Use **Training
Studio** to analyze unfamiliar genuine syntax, attach vendor documentation,
review budget-capped AI suggestions, confirm/correct categories, and publish an
organization-defined profile. Published profiles appear in the same upload and
inventory workflow. Raw configuration uploads are processed locally and
discarded; SQLite stores hashes, redacted patterns, report projections, and
history only.

The NIST option is a mapped view of source-backed checks, not a separate
NIST-native rule pack. Operator-created DISA/ISO mappings are explicitly labeled
operator-defined and are not claimed as verified framework equivalence.

Current verification gate: `76 passed`; `218` real rule YAMLs validate with no
failures; the pinned canonical hash and ledger tests pass unchanged.

Requires the dependencies pinned in `requirements.txt`.

---

## License

[MIT](LICENSE)
