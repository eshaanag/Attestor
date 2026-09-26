# Attestor - SIH Alignment Scorecard

Nothing is marked done here without repository evidence.

## PS26155 requirements

| Requirement | Delivered scope | Status and evidence |
|---|---|---|
| Unified single/bulk ingestion | Local FastAPI console, bounded UTF-8 uploads, per-file isolation, queued/running/completed/failed records | done: `dashboard/app.py`; genuine Cisco/Junos/FortiOS dashboard tests |
| Multi-vendor compliance | Built-in Cisco IOS/IOS-XE (14 CIS-backed), scoped Junos (4 vendor-baseline), and scoped FortiOS (3 vendor-baseline) | done (scoped): all three corpora have pass/fail oracles; broader coverage is not claimed |
| Vendor-neutral normalization | Shared result contract plus additive security model; unknown values never become passes | done (scoped): `docs/interfaces.md`, normalization tests |
| AI/NLP for unfamiliar syntax | Redacted pattern discovery, dry-run default, pre-call estimate, explicit cap, cache reuse, actual usage accounting | done: Training Studio and classifier tests; AI remains discovery metadata |
| Interactive training loop | Human confirm/correct, persistent vendor/platform mapping, genuine source upload | done: SQLite-backed `/training` workflow |
| No backend redeployment for every syntax change | Draft/publish organization-defined profiles with exact redacted-line rules | done (bounded): flat syntax only; hierarchical ambiguity stays unsupported/manual |
| Multi-framework engine | Cisco CIS controls with NIST SP 800-53 mappings; operator-defined sourced mapping fields for custom profiles | done (scoped): NIST is a mapped view; official Cisco IOS DISA packages were inspected but native DISA/ISO packs remain gated on complete corpus evidence |
| Per-device report | JSON, standalone HTML, ReportLab PDF, and evidence-bundle ZIP; identity when observable, severity, evidence, remediation, hashes, provenance | done: report and dashboard tests; raw configuration excluded from bundles |
| Device-specific remediation | Cached, clearly labeled AI advisory for built-in failed controls; operator-authored remediation for custom profiles | done (advisory): known invalid AI phrase retained to prove human review boundary |
| Persistent organization view | Local SQLite inventory, immutable scan projections, conservative same-framework comparison, filters, details, profile/training state | done: genuine repeated-scan, artifact-preservation, persistence/reload, and framework-mismatch tests |
| Live collection via Netmiko/NAPALM | Netmiko connector for Cisco/Junos/FortiOS uses fixed commands, temporary bounded output, credential non-persistence, and the existing engines | implemented; automated safety/handoff tests pass, real-device verification pending |
| Vendor-agnostic scalability | Shared adapter/result/report contracts plus low-code onboarding | done as prototype architecture, not universal grammar coverage |

## Trust and privacy

| Concern | Implementation | Evidence |
|---|---|---|
| False pass | Fail-closed checks; unreadable/ambiguous input errors; draft/unsourced profiles refused | engine and dashboard negative tests |
| Fabricated evidence | Genuine source-tracked Cisco, Junos, and FortiOS fixtures; no synthetic demo configs | corpus manifests and hashes |
| AI leakage | Redaction before persistence/provider use; provider action receives only redacted SQLite patterns | vendor-training and dashboard tests |
| AI spend | Dry-run default, cost estimate, hard cap, cache, persisted token/cost totals | Training Studio tests |
| Custom-profile overclaim | `organization_defined` status in result/control plus explicit HTML/PDF notices | report tests |
| Public-chain privacy | Only SHA-256 roots are anchored; no config, identity, findings, or remediation | architecture docs and Sepolia contract path |
| Evidence export privacy | Bundle excludes the raw configuration file and labels the included reports as potentially sensitive command evidence | dashboard bundle integration tests |

## Bonus foundation retained from SIH260382

- Ubuntu 22.04 Desktop: 35 VM-verified CIS controls.
- Windows 11 Standalone: 30 VM-verified CIS controls.
- Shared offline report and immutable canonical hash contract.
- Real Sepolia transaction for a Cisco network report:
  `4b9515e22e18523f08685a1013f8dbf064f9b62f97136cbc0b39132cd174d750`.

## Current exit evidence

- `python3 -m pytest -q`: 122 passed.
- `python3 tests/validate_rules.py`: 221 real rules, 0 failures; all seven
  fixtures behaved as expected.
- Canonical/ledger regression subset: 12 passed unchanged.
- `git diff --check`: clean at the verification point.

## Honest roadmap

1. Complete the implemented Netmiko connector's evidence gate against a reachable real Cisco device.
2. Add native DISA STIG controls only after the official-XCCDF and both-state
   corpus gate in `docs/disa-stig-evidence.md`; apply the same source discipline
   to ISO/IEC 27001.
3. Promote additional vendors only after corpus, source, parser, and pass/fail
   evidence gates.
4. Add authentication, RBAC, background jobs, encrypted secret handling, and a
   remote multi-user database for production fleet deployment.
