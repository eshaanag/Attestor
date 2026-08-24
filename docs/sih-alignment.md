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
| GUI-based solution | Local web GUI (Phase 7, round-1): FastAPI + SSE + htmx; "Run audit" button with live per-check results streaming, report link on completion. Runs on the audited machine, opens in any browser. | done | `dashboard/app.py` (7e3d649); proven on real Ubuntu VM: 35 checks streamed live (pass=10, fail=25, error=0), report accessible (37KB) |
| Generates findings reports | Jinja2 → self-contained offline HTML; per-control pass/fail/error/manual/NA + remediation + CIS ID + level; failures sorted first; incomplete-run flagged; accessibility handled | done | `report/generate_report.py` (da70d39); `reports/sample-report.html` (bbd51cd) |
| Customizable per org needs | Rule-as-data YAML packs; `--include`/`--exclude` ID filtering + `--level` filtering; `--format` (json/html/ndjson) output modes. Filter precedence: include narrows → exclude removes → level ANDs. Matches cis-benchmarks-audit CLI convention. | done | `engines/linux/run_audit.py` + `engines/windows/run_audit.ps1` (43f429e) |
| Scales to large/diverse environments | Fleet backend + dashboard (Phase 2 stretch); honest about free-tier DB limits | planned (stretch) | `docs/tech-stack.md` §6 |
| Reliable & accurate deviation detection | Fail-closed schema validation; no default-pass path; privilege detection; error≠pass; all 10 check_types proven on real hardware; 65 controls (35 Linux + 30 Windows) with zero errors across full-pack runs | done | 65 rules VM-verified (Phase 5 commits bddaf90–a76967a); full-pack runs: Linux 35/35 error=0, Windows 30/30 error=0 |
| Easy to update as benchmarks evolve | Purely additive rule packs; `benchmark_version` per rule; schema-gated authoring | in progress | `schema/rule_schema.json` (d59cfac), `docs/rule-schema.md` (7af47ab) |
| Preferred languages (PowerShell / Python) | PowerShell (Windows), Python (Linux) — exactly as PS recommends | planned | `docs/tech-stack.md` §1–2 |

## B. Blockchain theme (theme is "Blockchain & Cybersecurity")

| Item | How Attestor addresses it | Status | Evidence |
|---|---|---|---|
| Real, explainable blockchain mechanism | SHA-256 hash-chained report ledger, per host, with break detection | done | `ledger/chain.py` (062fe39); `tests/test_ledger_chain.py` (8299c2b); 3-report chain proven intact, tamper at link 1 correctly detected |
| Publicly verifiable, not just internal | Anchor each report hash and previous hash to Ethereum Sepolia | done for existing OS track | Current contract `0xbd19e20aD6C216A8a793fdE3Bd46B9D291Bf5C41`; current ABI exposes `anchorReport(root, previousRoot)` |
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

## E. PS26155 network-device track

| Phase | Deliverable | Status | Evidence |
|---|---|---|---|
| A | Backward-compatible network rule/results contracts | done | `schema/rule_schema.json`; 200 legacy rules pass validation; 6 fixtures resolve as expected; pytest passes |
| B | 5-8 genuine Cisco IOS/IOS-XE configs with provenance | done | 10 MIT-licensed, source-backed IOS lab/reference configs; immutable commit URLs, retrieval date, platform, and SHA-256 are pinned in `tests/fixtures/network/cisco_ios/manifest.json` and tested |
| C | Cisco flat-check engine | done | `engines/network/run_audit.py`; manual oracle records exact raw-text lines and complementary absences for five checks across all ten source-backed configs; `tests/test_network_flat_engine.py` and full pytest pass |
| D | Block-aware VTY/interface checks | done (scoped) | `engines/network/run_audit.py`; `tests/test_network_flat_engine.py`; two interface relationships manually verified with both pass/fail states across all ten source-backed configs; VTY failure/ACL and unused-interface coverage explicitly incomplete |
| E | 10-15 sourced Cisco rules + dual-framework report | done (scoped) | 14 rules in `rules/cisco_ios/`; public CIS control sources and NIST mappings recorded per rule; `manual_rule_expectations.json` proves pass/fail states for every rule; `report/generate_report.py` renders device metadata and mappings offline; 23 pytest tests pass |
| F | Network-report ledger + real Sepolia transaction | done (Cisco IOS scope) | `tests/test_network_ledger.py`; unchanged canonical/chain contracts proved against a real network report; Sepolia tx `4b9515e22e18523f08685a1013f8dbf064f9b62f97136cbc0b39132cd174d750`, root `6d9319f05742791af8798a288e72e530a0d563a3037f7a5ddecb3d68d843239a`, `verifyRoot=true` |
| F' | AI-assisted syntax discovery/training loop | done | `ai/network_discovery.py`; 51 redacted candidates classified with `claude-haiku-4-5-20251001`; provider usage 3,408 input + 3,268 output tokens, measured `$0.019748`; 32-test suite passes; deterministic engine remains authoritative |
| G | Optional additional vendor | deferred by default | Roadmap only |
| H | Honest pitch/documentation pass | not started | Must reflect actual delivered coverage |

---

## Update protocol

At each phase transition (Rule C5): re-verify, run the validator, then update the
Status/Evidence columns above with the **commit hash or file** that proves each
change. Downgrade any row that regresses. Nothing reaches `done` without cited,
verified evidence.
