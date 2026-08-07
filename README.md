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

Early development — structure only, no functional code yet.

---

## License

[MIT](LICENSE)
