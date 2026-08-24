# Attestor

**CIS Benchmark audit tool for Windows 11 and Linux with a tamper-evident report ledger.**

---

## Problem Statement

**SIH260382 — NTRO (National Technical Research Organisation)**
**Theme: Blockchain & Cybersecurity**

> Design and develop a tool to automatically assess the security configurations of desktops/laptops against the CIS Benchmark. The tool should scan the system, identify deviations from the benchmark, and generate a compliance report highlighting areas of non-compliance with actionable recommendations for remediation.

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
| Ubuntu 22.04 Desktop (Level 1+2) | `engines/linux/run_audit.py` | 50 (sysctl + file_permission + kernel_module + config_grep + service_state + package_installed) | ✅ In progress — engine + 50 controls pass/fail verified on real VM |
| Windows 11 Standalone (Level 1+2) | `engines/windows/run_audit.ps1` | 50 (registry + secpol + account_policy + audit_policy + service_state) | ✅ In progress — engine + 50 controls pass/fail verified on real VM |

**Phase 0** (schema + validator), **Phase 1** (Linux engine), **Phase 2** (Windows engine), **Phase 3** (report generation), **Phase 4** (tamper-evident ledger), **Phase 5** (rule pack expansion), **Phase 6** (CLI polish), **Phase 7** (local web GUI), and **Phase 9** (testnet anchoring) complete.
Stretch goal remaining: Phase 8 (fleet backend/dashboard).

**Current blockchain integration:** Ethereum Sepolia contract
[`0xbd19e20aD6C216A8a793fdE3Bd46B9D291Bf5C41`](https://sepolia.etherscan.io/address/0xbd19e20aD6C216A8a793fdE3Bd46B9D291Bf5C41), using
`anchorReport(currentHash, previousHash)`. The earlier Polygon Amoy deployment is
legacy and is not the contract used by the current integration.

See [`reports/sample-report.html`](reports/sample-report.html) for an example rendered report (opens offline, no network required).

### PS26155 network-device track

| Phase | Scope | Status | Evidence |
|---|---|---|---|
| A | Additive schema + interface contracts | Complete | 200 legacy rules validate unchanged; 6 schema fixtures behave as expected; canonical/ledger/anchor tests pass |
| B | Genuine Cisco IOS config corpus | Complete | 8 MIT-licensed source-backed IOS reference configs; immutable source commits, retrieval date, platform, and SHA-256 in `tests/fixtures/network/cisco_ios/manifest.json`; integrity test passes |
| C | Cisco IOS flat-check parser primitive | Complete | `engines/network/run_audit.py`; five manual-oracle checks span all 8 corpus files and each has pass + fail evidence; focused tests pass |
| D | Cisco IOS block-aware VTY/interface parser primitive | Complete | `engines/network/run_audit.py`; interface oracle has pass/fail coverage across all 8 source-backed configs; 21-test suite and rule validator pass |
| E-H | Sourced Cisco rules/report, ledger proof, optional vendor, pitch | Not started | Phase D adds no CIS control or vendor-compliance claim; VTY failure/ACL coverage and unused-interface shutdown remain corpus-incomplete |

The verified Phase C/D parser primitives are limited to source-backed Cisco IOS
lab/reference configurations, not production backups or live sandbox captures.
Phase D adds no production compliance rule and therefore no claim of completed
vendor-compliance coverage. Cisco IOS is the only built network target; other
vendors are roadmap only.

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

Requires: `pip install fastapi uvicorn` (in addition to base requirements).

---

## License

[MIT](LICENSE)
