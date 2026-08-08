# Attestor — SIH Alignment Scorecard

A **living** scorecard mapping what we build to what wins SIH. Updated honestly
at the end of every phase per AGENTS.md Rule C5 — **never mark something `done`
that isn't verified working.** `done` requires cited evidence (a committed
file, a passing test, a verified control).

Status legend: `planned` · `in progress` · `done` · `blocked`
Evidence = file path and/or commit that proves the claim.

---

## A. PS requirements → how Attestor addresses them

| PS requirement | How Attestor addresses it | Status | Evidence |
|---|---|---|---|
| Audit Windows 11 (Standalone) vs CIS | PowerShell engine (`registry`, `secpol`, `account_policy`, `audit_policy`, `service_state`) + `windows11_standalone` rule pack | in progress (11 L1 verified: 10 registry + 1 secpol; account_policy/audit_policy/service_state dispatchers coded but untested) | `engines/windows/run_audit.ps1` (59eac7a); 11 rule commits (148d1c9–8aa0844) |
| Audit Windows 11 (Enterprise) vs CIS | Same engine; add `windows11_enterprise` rule pack (additive) | planned (Phase 2+) | deferral noted in `PROJECT_CONTEXT.md` |
| Audit Ubuntu 22.04 Desktop vs CIS | Python engine (`kernel_module`, `sysctl`, `file_permission`, `package_installed`, `config_grep`, `service_state`) + `ubuntu2204_desktop` pack | in progress (10/10 L1 verified, Phase 5 targets 30-40) | `engines/linux/run_audit.py` (d0623b2); 10 rule commits (4799f67–cc702bc) |
| Audit RHEL 8/9, Ubuntu 20.04 / Server | Additive rule packs on the same engine/schema | planned (Phase 2+) | deferral rationale in `PROJECT_CONTEXT.md` |
| GUI-based solution | Standalone offline HTML report + **local web GUI (Phase 7, round-1)**: FastAPI + Jinja2 + htmx, "Run audit" button with live NDJSON results | planned (Phase 7) | `docs/tech-stack.md` §8; AGENTS.md Phase 7 |
| Generates findings reports | Jinja2 → self-contained offline HTML; per-control pass/fail/error/manual/NA + remediation + CIS ID + level; failures sorted first; incomplete-run flagged; accessibility handled | done | `report/generate_report.py` (da70d39); `reports/sample-report.html` (bbd51cd) |
| Customizable per org needs | Rule-as-data YAML packs; `--include`/`--exclude`/`--level` filtering (Phase 6) | planned | `schema/rule_schema.json`; AGENTS.md Phase 6 |
| Scales to large/diverse environments | Fleet backend + dashboard (Phase 2 stretch); honest about free-tier DB limits | planned (stretch) | `docs/tech-stack.md` §6 |
| Reliable & accurate deviation detection | Fail-closed schema validation; no default-pass path; privilege detection; error≠pass; all 10 check_types proven on real hardware; 65 controls (35 Linux + 30 Windows) with zero errors across full-pack runs | done | 65 rules VM-verified (Phase 5 commits bddaf90–a76967a); full-pack runs: Linux 35/35 error=0, Windows 30/30 error=0 |
| Easy to update as benchmarks evolve | Purely additive rule packs; `benchmark_version` per rule; schema-gated authoring | in progress | `schema/rule_schema.json` (d59cfac), `docs/rule-schema.md` (7af47ab) |
| Preferred languages (PowerShell / Python) | PowerShell (Windows), Python (Linux) — exactly as PS recommends | planned | `docs/tech-stack.md` §1–2 |

## B. Blockchain theme (theme is "Blockchain & Cybersecurity")

| Item | How Attestor addresses it | Status | Evidence |
|---|---|---|---|
| Real, explainable blockchain mechanism | SHA-256 hash-chained report ledger, per host, with break detection | done | `ledger/chain.py` (062fe39); `tests/test_ledger_chain.py` (8299c2b); 3-report chain proven intact, tamper at link 1 correctly detected |
| Publicly verifiable, not just internal | Anchor chain root hash to Polygon Amoy testnet | planned (Phase 9 stretch) | `PROJECT_CONTEXT.md` (Level 2) |
| Tamper-evidence is honest | Canonical serialization so hashes are reproducible (no false "tamper" alarms); distinct failure modes (report-tampered vs chain-corrupted) | done | `ledger/canonical.py` (a7bd5a1); `tests/test_canonical_hash.py` + `test_reserialization_no_false_break` (8299c2b) |

## C. Judging lenses → how we score

| Judging lens | How Attestor addresses it | Status | Evidence |
|---|---|---|---|
| Novelty | Schema-validated rule-as-data + tamper-evident ledger, free/self-hostable — none of the incumbents combine these | in progress | `PROJECT_CONTEXT.md` (wedge) |
| Technical complexity / depth | Two native engines → shared results contract → hash chain → (stretch) on-chain anchoring | planned | `docs/architecture.md` |
| Clarity of presentation | Offline HTML report designed for an auditor to trust line-by-line; report shows benchmark version + ledger hash | planned | `docs/architecture.md` §3 |
| Feasibility & practicability | **MVP deliberately narrowed** to 2 targets, L1, all verified — proves correctness before breadth | in progress | `PROJECT_CONTEXT.md` (MVP scope rationale) |
| Sustainability | Rule packs are **purely additive** data; new benchmarks = new YAML, no engine rewrite; MIT-licensed, community-auditable | in progress | `schema/rule_schema.json`, `LICENSE` |
| Scale of impact | Free alternative to paywalled CIS-CAT Pro; one tool across Windows + Linux; fleet mode for orgs | planned | `docs/tech-stack.md` §6 |
| UX | One consistent report across both OSes; conservative status language (error/manual, never false pass) | planned | AGENTS.md §5; `docs/architecture.md` §3 |
| Potential for future work | Additive targets, Level 2, fleet, on-chain anchoring — all designed-for, not bolted-on | planned | `docs/architecture.md` §6 |

## D. Cross-cutting / easily-missed rows

| Concern | How Attestor addresses it | Status | Evidence |
|---|---|---|---|
| Trust / no false PASS | No default-pass path; privilege-insufficient → error; `automated:false` → manual | in progress | `docs/architecture.md` Open Risks #1–2 |
| Provenance of every control | `source` field required + min-length; controls traceable to benchmark/VM verification | in progress | `schema/rule_schema.json`, AGENTS.md §0 |
| Reproducible tamper-evidence | Canonical JSON hashing, unit-tested before Phase 4 ships | planned | `docs/architecture.md` §4b |
| Offline / demo resilience | Report opens with no network; standalone needs no server | planned | `docs/tech-stack.md` §4, §9 |
| Repo hygiene / professionalism | `.gitignore` excludes secrets/reference/local memory; disciplined commit messages | in progress | `.gitignore`, AGENTS.md §6 |
| License discipline | Reference repos read for logic only, never copied; project MIT | in progress | `LICENSE`, AGENTS.md §7 |
| Incomplete-run safety | `results.json` written only on clean completion; report flags partial runs | planned | `docs/architecture.md` Open Risk #7 |

---

## Update protocol

At each phase transition (Rule C5): re-verify, run the validator, then update the
Status/Evidence columns above with the **commit hash or file** that proves each
change. Downgrade any row that regresses. Nothing reaches `done` without cited,
verified evidence.
