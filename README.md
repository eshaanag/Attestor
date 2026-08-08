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
| Ubuntu 22.04 Desktop (Level 1) | `engines/linux/run_audit.py` | 35 (sysctl + file_permission + kernel_module + config_grep + service_state + package_installed) | ✅ In progress — engine + 35 controls pass/fail verified on real VM |
| Windows 11 Standalone (Level 1) | `engines/windows/run_audit.ps1` | 30 (registry + secpol + account_policy + audit_policy + service_state) | ✅ In progress — engine + 30 controls pass/fail verified on real VM |

**Phase 0** (schema + validator), **Phase 1** (Linux engine), **Phase 2** (Windows engine), **Phase 3** (report generation), **Phase 4** (tamper-evident ledger), and **Phase 5** (rule pack expansion to 30-40 controls per target) complete.
Next: Phase 6 (CLI polish), then Phase 7 (local web GUI).

See [`reports/sample-report.html`](reports/sample-report.html) for an example rendered report (opens offline, no network required).

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

---

## License

[MIT](LICENSE)
