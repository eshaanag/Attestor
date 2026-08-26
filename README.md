# Attestor

**Source-backed compliance auditing for Windows, Linux, Cisco IOS, and a scoped
Juniper Junos baseline, with offline reports and optional tamper evidence.**

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

- **Rule-as-data (YAML) over XML-heavy OpenSCAP** — controls are human-readable, easy to author, and trivially validatable against a JSON schema. No XCCDF/OVAL XML sprawl.
- **Free and open-source vs paywalled CIS-CAT Pro** — anyone can run this without a CIS SecureSuite license; the rule packs are community-auditable.
- **Tamper-evident ledger vs static hackathon-tier tools** — SHA-256 hash chain over report content ensures compliance reports can't be silently altered after generation.

---

## Prerequisites

- **Python 3.10+** — required on **both** Windows and Linux hosts. The Linux
  audit engine is Python; on Windows the audit engine is native **PowerShell**,
  but **report generation and the tamper-evident ledger are shared Python** and
  run on both platforms, so Python is required everywhere Attestor produces or
  chains a report.
- **PowerShell 5.1+** — required on Windows hosts for the audit engine (ships
  with Windows 11; no extra install).
- Python packages (MVP): `pyyaml`, `jsonschema`, `jinja2` (see
  `requirements.txt`). No external PowerShell modules are needed for the MVP.

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
│   └── linux/
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
For PS26155, Cisco IOS, scoped Junos, AI discovery, PDF reporting, and the
local ingestion dashboard are complete. The fleet backend/dashboard remains
stretch work.

**Current blockchain integration:** Ethereum Sepolia contract
[`0xbd19e20aD6C216A8a793fdE3Bd46B9D291Bf5C41`](https://sepolia.etherscan.io/address/0xbd19e20aD6C216A8a793fdE3Bd46B9D291Bf5C41), using
`anchorReport(currentHash, previousHash)`. The earlier Polygon Amoy deployment is
legacy and is not the contract used by the current integration.

See [`reports/sample-report.html`](reports/sample-report.html) for an example rendered report (opens offline, no network required).

### PS26155 network-device track

| Phase | Scope | Status | Evidence |
|---|---|---|---|
| A | Additive schema + interface contracts | Complete | 200 legacy rules validate unchanged; 6 schema fixtures behave as expected; canonical/ledger/anchor tests pass |
| B | Genuine Cisco IOS config corpus | Complete | 10 MIT-licensed source-backed IOS reference configs; immutable source commits, retrieval date, platform, and SHA-256 in `tests/fixtures/network/cisco_ios/manifest.json`; integrity test passes |
| C | Cisco IOS flat-check parser primitive | Complete | `engines/network/run_audit.py`; five manual-oracle checks span all 10 corpus files and each has pass + fail evidence; focused tests pass |
| D | Cisco IOS block-aware VTY/interface parser primitive | Complete | `engines/network/run_audit.py`; interface oracle has pass/fail coverage across all 10 source-backed configs; 21-test suite and rule validator pass |
| E | Cisco IOS rule pack + dual-framework report | Complete (scoped) | 14 source-backed CIS rules under `rules/cisco_ios/`, each with NIST SP 800-53 mapping; 10-config per-rule oracle has pass/fail evidence; 23 tests pass; report renders device identity and mappings offline |
| F | Network-report ledger + real Sepolia transaction | Complete (Cisco IOS scope) | Stable device chain verified; root `6d9319f05742791af8798a288e72e530a0d563a3037f7a5ddecb3d68d843239a` anchored in tx `4b9515e22e18523f08685a1013f8dbf064f9b62f97136cbc0b39132cd174d750`; `verifyRoot` returned found=true |
| F' | AI-assisted syntax discovery/training loop | Complete (real batch; deterministic compliance unchanged) | 51 redacted candidates classified with available Haiku model; 32 tests pass; provider-reported usage 3,408 input + 3,268 output tokens, measured cost `$0.019748`; no pre-redaction cache |
| G' | Offline PDF report + cached AI remediation | Complete (AI advisory scope) | ReportLab PDF renders the genuine Cisco report offline; 9 failed controls received clearly labelled Haiku-generated advisory remediation and reasoning; initial batch + one targeted retry used `$0.008774`; retry reproduced the known invalid `SHA-500` phrase, proving why human review remains required |
| H' | Minimal network ingestion dashboard | Complete (Cisco IOS scope) | FastAPI console now separates network ingestion from the established VM workflow; single/bulk genuine config uploads, CIS/NIST-mapped/combined views, JSON/HTML/PDF links; 5 dashboard tests and full 41-test suite pass |
| G | Optional additional vendor | Complete (scoped) | Juniper Junos four-control source-backed subset implemented; broader Junos and other vendors remain roadmap |
| H | Honest pitch/documentation pass | Complete | README, architecture brief, detailed architecture, runbook, demo script, vendor matrix, and scorecard state the verified Cisco/Junos scope and roadmap honestly |

The verified Phase C/D/E network track is limited to source-backed Cisco IOS
lab/reference configurations, not production backups or live sandbox captures.
Phase E includes 14 Cisco IOS rules whose corpus oracle contains both pass and
fail states. VTY/unused-interface checks are not claimed as verified. The
implemented network scope is Cisco IOS (14 source-backed CIS controls) and
Juniper Junos (four source-backed vendor-baseline controls). Broader Junos and
other vendors are roadmap only. F' AI
classification is discovery metadata only: deterministic compliance results
remain authoritative, credentials are redacted before provider use, and dry-run
remains the default. The first real batch ran only after explicit approval.

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
# Start the GUI server (runs on the machine being audited)
python3 dashboard/app.py
# Open http://localhost:8000 in a browser
# Select target + level, click "Run Audit"
# Watch live pass/fail results stream in, then click the report link
```

The same page also accepts one or more saved Cisco IOS/IOS-XE or Juniper Junos
configs. Choose a source-backed, NIST-mapped, or combined report view, upload
the files, then download JSON, offline HTML, or PDF per device. The NIST choice is a mapped view of the
source-backed checks, not a separate NIST-native rule pack. Uploaded configs are
processed locally and discarded.

Requires the dependencies pinned in `requirements.txt`.

---

## License

[MIT](LICENSE)
