# Attestor - SIH Alignment Scorecard

Nothing is marked done here without repository evidence.

## PS26155 requirements

| Requirement | Delivered scope | Status and evidence |
|---|---|---|
| Unified single/bulk ingestion | Local FastAPI console, bounded UTF-8 uploads, per-file isolation, queued/running/completed/failed records | done: `dashboard/app.py`; genuine Cisco/Junos dashboard tests |
| Multi-vendor compliance | Built-in Cisco IOS/IOS-XE (14 CIS-backed controls) and scoped Junos (4 vendor-baseline controls) | done (scoped): both corpora have pass/fail oracles; other vendors are not claimed built-in |
| Vendor-neutral normalization | Shared result contract plus additive security model; unknown values never become passes | done (scoped): `docs/interfaces.md`, normalization tests |
| AI/NLP for unfamiliar syntax | Redacted pattern discovery, dry-run default, pre-call estimate, explicit cap, cache reuse, actual usage accounting | done: Training Studio and classifier tests; AI remains discovery metadata |
| Interactive training loop | Human confirm/correct, persistent vendor/platform mapping, genuine source upload | done: SQLite-backed `/training` workflow |
| No backend redeployment for every syntax change | Draft/publish organization-defined profiles with exact redacted-line rules | done (bounded): flat syntax only; hierarchical ambiguity stays unsupported/manual |
| Multi-framework engine | Cisco CIS controls with NIST SP 800-53 mappings; operator-defined sourced mapping fields for custom profiles | done (scoped): NIST is a mapped view; native DISA/ISO packs remain roadmap |
| Per-device report | JSON, standalone HTML, ReportLab PDF; identity when observable, severity, evidence, remediation | done: report and dashboard tests |
| Device-specific remediation | Cached, clearly labeled AI advisory for built-in failed controls; operator-authored remediation for custom profiles | done (advisory): known invalid AI phrase retained to prove human review boundary |
| Persistent organization view | Local SQLite device inventory, scan history, filters, details, profile/training state | done: persistence/reload/history tests |
| Live collection via Netmiko/NAPALM | Same file input can consume a real exported running config; connector not verified without a reachable device | not claimed; optional next input adapter |
| Vendor-agnostic scalability | Shared adapter/result/report contracts plus low-code onboarding | done as prototype architecture, not universal grammar coverage |

## Trust and privacy

| Concern | Implementation | Evidence |
|---|---|---|
| False pass | Fail-closed checks; unreadable/ambiguous input errors; draft/unsourced profiles refused | engine and dashboard negative tests |
| Fabricated evidence | Genuine source-tracked Cisco and Junos fixtures; no synthetic demo configs | corpus manifests and hashes |
| AI leakage | Redaction before persistence/provider use; provider action receives only redacted SQLite patterns | vendor-training and dashboard tests |
| AI spend | Dry-run default, cost estimate, hard cap, cache, persisted token/cost totals | Training Studio tests |
| Custom-profile overclaim | `organization_defined` status in result/control plus explicit HTML/PDF notices | report tests |
| Public-chain privacy | Only SHA-256 roots are anchored; no config, identity, findings, or remediation | architecture docs and Sepolia contract path |

## Bonus foundation retained from SIH260382

- Ubuntu 22.04 Desktop: 35 VM-verified CIS controls.
- Windows 11 Standalone: 30 VM-verified CIS controls.
- Shared offline report and immutable canonical hash contract.
- Real Sepolia transaction for a Cisco network report:
  `4b9515e22e18523f08685a1013f8dbf064f9b62f97136cbc0b39132cd174d750`.

## Current exit evidence

- `python3 -m pytest -q`: 76 passed.
- `python3 tests/validate_rules.py`: 218 real rules, 0 failures; all seven
  fixtures behaved as expected.
- Canonical/ledger regression subset: 12 passed unchanged.
- `git diff --check`: clean at the verification point.

## Honest roadmap

1. Verify a Netmiko collector against a reachable real Cisco device.
2. Add native source-backed DISA STIG and ISO/IEC 27001 rule packs.
3. Promote additional vendors only after corpus, source, parser, and pass/fail
   evidence gates.
4. Add authentication, RBAC, background jobs, encrypted secret handling, and a
   remote multi-user database for production fleet deployment.
