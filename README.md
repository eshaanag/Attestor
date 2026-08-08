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
| Ubuntu 22.04 Desktop (Level 1) | `engines/linux/run_audit.py` | 10 (sysctl + file_permission) | ✅ In progress — engine + 10 controls pass/fail verified on real VM |
| Windows 11 Standalone (Level 1) | `engines/windows/run_audit.ps1` | 10 (registry only) | ✅ In progress — engine + 10 controls pass/fail verified on real VM (secpol/audit_policy untested) |

**Phase 0** (schema + validator), **Phase 1** (Linux engine), **Phase 2** (Windows engine), and **Phase 3** (report generation) complete.
Next: Phase 4 (tamper-evident ledger), then Phase 5 (rule pack expansion).

See [`reports/sample-report.html`](reports/sample-report.html) for an example rendered report (opens offline, no network required).

---

## License

[MIT](LICENSE)
