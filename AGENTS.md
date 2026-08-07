# AGENTS.md — Attestor

### Problem Statement 
SIH260382
Development of Audit script for Windows 11 and Linux OS as per CIS (Centre for Internet Security) bench mark
National Technical Research Organisation (NTRO)
Blockchain & Cybersecurity
Software
Background: Organisations across various industries face significant challenges in maintaining robust cyber security posture. Compliance with industry standard bench marks and guidelines, such as those provided by Center for Internet Security (CIS), is crucial for ensuring the security and integrity of their IT Infrastructure. However, manually auditing and ensuring adherence to these benchmarks and guidelines can be time- consuming, error prone, and resource intensive. Current practises often involve manual checks. To address these challenges, there is a critical need to develop automated auditing scripts tailored to CIS benchmarks. Detailed description: This software solution aimed to list out the control guidelines as per CIS benchmark for the following operating systems: - Windows (Reference www.cisecurity.org/benchmark/Microsoft_winodws_desktop) i. Windows 11 (Enterprise version) ii. Windows 11 (Standalone version) Linux (Reference:www.cisecurity.org/benchmark/red_hat_linux, www.cisecurity.org/benchmark/ubuntu_linux) i. Redhat Enterprise (8 and 9) ii. Ubuntu desktop (20.04 LTS, 22.04 LTS) iii. Ubuntu server (12.04LTS and 14.04 LTS) Preferable scripting language (PowerShell for Windows, bash/python for Linux). Expected solution: i. A user-friendly GUI based solution with capability to generate a report of findings. ii. Should be customizable as per organizational needs and scale to audit large and diverse IT environments effectively. iii. Scripts should be reliable and accurate in identifying the deviations from iv. best practices outlined in CIS benchmarks. v. Should facilitate easy update and maintenance to accommodate changes in benchmarks over time.

### Read this fully before writing a single line of code. Re-read it if you feel lost.

Attestor is a CIS Benchmark audit tool for Windows 11 and Linux (SIH260382,
NTRO, Blockchain & Cybersecurity theme). It checks real systems against real
CIS controls and produces a tamper-evident, cryptographically chained
compliance report. This is not a toy. If a control is wrong — a false pass
or a false fail — the tool is worthless and the pitch collapses the moment a
judge tests it live. Build accordingly.

════════════════════════════════════════════════════════
SECTION 0 — THE ONE RULE THAT MATTERS MOST
════════════════════════════════════════════════════════

**Never fabricate a CIS control.** Not an ID, not a registry path, not a
sysctl key, not a default value, not a remediation step. If you are not
certain a control is accurate, mark it in PROGRESS.md under
"NEEDS VERIFICATION" and move on — do not guess and ship it as done. A
plausible-looking but wrong control is worse than no control, because it
erodes trust in every other control the moment one is caught.

Every rule YAML you write must be traceable to one of:
  - The official CIS benchmark PDF/doc for that OS+version
  - A reference repo's equivalent control (ansible-lockdown, ComplianceAsCode)
    — read for the *check logic*, never copy-pasted as code
  - Manual verification on a real VM (`secedit /export`, `sysctl -a`,
    `auditpol /get`, `stat`, etc.)

If none of these back a control, it does not go in a rule pack.

════════════════════════════════════════════════════════
SECTION 1 — PROJECT STRUCTURE (already scaffolded — do not restructure)
════════════════════════════════════════════════════════

```
attestor/
├── engines/windows/     PowerShell audit engine
├── engines/linux/       Python audit engine
├── rules/<target>/      YAML rule packs, one file per control
├── schema/              rule_schema.json — validates every rule file
├── report/              Jinja2 HTML report generator
├── ledger/              SHA-256 hash chain (tamper-evident reports)
├── backend/             [phase 2] FastAPI fleet collector
├── dashboard/           [phase 2] React fleet dashboard
├── docs/                architecture.md, rule-schema.md
├── tests/               rule validation + engine unit tests
└── reference/           cloned comparison repos — gitignored, never committed
```

Do not add new top-level folders without updating this file and asking first.

════════════════════════════════════════════════════════
SECTION 2 — PHASE STRUCTURE
════════════════════════════════════════════════════════

Work through phases in order. Never start a phase whose dependencies aren't
done. Each phase has an exit condition — do not move on until it's met.

**PHASE 0 — FOUNDATION**
  Rule schema locked (`schema/rule_schema.json`) + validator script that
  rejects malformed rule YAML.
  Exit: `python tests/validate_rules.py` runs clean against an empty
  rules/ dir and correctly rejects 3 intentionally-broken sample YAMLs.

**PHASE 1 — LINUX ENGINE (Ubuntu 22.04 Desktop, Level 1)**
  `engines/linux/run_audit.py` + dispatcher for check_types:
  kernel_module, sysctl, file_permission, service_state, package_installed,
  config_grep.
  Start with 10 controls, manually verified on a real Ubuntu 22.04 VM
  before writing the 11th.
  Exit: `python run_audit.py` produces correct pass/fail against a known
  VM state you've manually checked by hand.

**PHASE 2 — WINDOWS ENGINE (Windows 11 Standalone, Level 1)**
  `engines/windows/run_audit.ps1` + dispatcher for check_types: registry,
  secpol, audit_policy, service_state, account_policy.
  Same rule: 10 controls, manually verified, before expanding.
  Exit: script produces correct pass/fail against a known Windows 11 VM
  state you've manually checked by hand.

**PHASE 3 — REPORT GENERATION**
  Jinja2 → standalone HTML. Shows pass/fail/error/not-applicable per
  control, remediation text, CIS control ID, level.
  Exit: report renders correctly from both engines' JSON output, opens
  offline with no network dependency.

**PHASE 4 — TAMPER-EVIDENT LEDGER**
  `ledger/` — SHA-256 hash chain over report content, chained to previous
  report hash for that host. Verification function that detects broken
  chains.
  Exit: chain-of-3 test reports verifies as intact; deliberately editing
  report #2 after the fact is detected by the verifier.

**PHASE 5 — RULE PACK EXPANSION**
  Grow both rule packs to 30-40 Level 1 controls each. Every single one
  manually verified before commit — no exceptions, no batch-adding
  unverified controls "to save time."
  Exit: full run against both target VMs, spot-checked control by control.

**PHASE 6 — CLI POLISH**
  `--level`, `--include`, `--exclude`, `--format` (json/html/csv) on both
  engines, consistent flag behavior across PowerShell and Python.
  Exit: same flags produce equivalent filtered output on both engines.

**PHASE 7 — [STRETCH] FLEET BACKEND + DASHBOARD**
  Only start this if Phases 0-6 are fully done and verified. Do not start
  early "to save time" — an unfinished fleet mode demoing worse than a
  rock-solid standalone tool.

**PHASE 8 — [STRETCH] TESTNET ANCHORING**
  Periodic ledger root hash → Polygon Amoy testnet contract. Only after
  Phase 4's local chain is fully working and tested.

**PHASE 9 — SHIP**
  Full re-run of every control against clean VMs, demo script locked,
  fallback video recorded, README finalized.

════════════════════════════════════════════════════════
SECTION 3 — CONTEXT PRESERVATION (you will lose context — plan for it)
════════════════════════════════════════════════════════

**RULE C1 — CHECKPOINT.md**
At the start of every phase, create/update `/CHECKPOINT.md` (gitignored,
local only) containing: current phase, completed phases, completed
controls (with verification status), current task, architecture decisions
made and why, known issues, exact next step.

**RULE C2 — RE-READ BEFORE YOU WRITE**
Before writing any new rule or engine code: read CHECKPOINT.md fully, read
the last 3 PROGRESS.md entries, read the existing dispatcher code for that
check_type if one exists. Never assume you remember the schema from
earlier in the session — re-read `schema/rule_schema.json` itself.

**RULE C3 — NEVER BREAK AN EXISTING VERIFIED CONTROL**
Before adding a new control or refactoring the dispatcher, re-run the
engine against previously-verified controls. If a change breaks a
control's correctness, stop and fix it before adding anything new.

**RULE C4 — SMALL COMMITS**
One control (or one dispatcher function) per commit where practical. Never
batch more than ~5 unverified controls into one commit — verification
happens per-control, and commits should reflect that granularity.

**RULE C5 — PHASE TRANSITION PROTOCOL**
  1. Re-verify every control added this phase against a real VM
  2. Run the rule validator against the full rules/ directory
  3. Update CHECKPOINT.md with phase summary
  4. Update README.md — mark completed phases/controls
  5. Update PROGRESS.md with phase completion entry
  6. Commit: `chore(phase-X): complete Phase X — N controls verified`
  7. Push
  8. Re-read CHECKPOINT.md fresh before starting next phase

**RULE C6 — IF YOU FEEL LOST**
Stop. Read CHECKPOINT.md. Read last 5 PROGRESS.md entries. List every file
in the relevant `rules/<target>/` and `engines/<os>/` folder. Re-read this
file's Section 2 for the current phase's exit condition. Write a plan in
PROGRESS.md before writing a single line.

**RULE C7 — INTERFACE CONTRACTS FIRST**
Before building two features that talk to each other (e.g. engine output
→ report generator, engine output → ledger), define the JSON shape both
sides agree on first, in `docs/interfaces.md`. Build to that contract.

**RULE C8 — DEPENDENCY ORDER**
Follow phase order strictly. Do not start the ledger before the report
generator produces stable output. Do not start the dashboard before the
backend API contract is defined.

**RULE C9 — PROGRESS.md SUMMARY EVERY ~2 HOURS OR 3 CONTROLS**
What was built, what's verified vs pending verification, what's broken,
biggest decision made, what's next.

**RULE C10 — NEVER REFACTOR AND ADD CONTROLS IN THE SAME COMMIT**
Note refactor needs in PROGRESS.md under "REFACTOR NEEDED," finish and
commit the current control/feature, then refactor separately:
`refactor(engine): description`.

════════════════════════════════════════════════════════
SECTION 4 — BRAINSTORM PROTOCOL (apply before each new check_type)
════════════════════════════════════════════════════════

Before implementing a new check_type (not a new control using an existing
type — a genuinely new dispatcher function), write in PROGRESS.md:

  BRAINSTORM: [check_type name]
  What CIS controls need this: (list the control IDs)
  How to verify it accurately: (exact command/API, tested manually first)
  Failure modes: (permission denied, missing binary, WSL vs native, etc.)
  How errors surface: (must be "error," never silently "pass")
  What would make this wrong in a subtle way a judge could catch live:

Only after this is written, implement the function.

════════════════════════════════════════════════════════
SECTION 5 — WHO THIS IS FOR (keep this in mind for report/UI decisions)
════════════════════════════════════════════════════════

The person reading Attestor's output is a sysadmin or security auditor who
needs to trust every single line without re-checking it by hand. They will
use this to justify a compliance decision, possibly to their own
management or an external auditor. A wrong "PASS" here is not a UX
inconvenience — it's a false statement about a system's security posture.
Design every report and status indicator around that weight: be
conservative, mark uncertainty as "error/manual review needed" rather than
guessing, and never let a check silently fail into a false pass.

════════════════════════════════════════════════════════
SECTION 6 — REPO HYGIENE (public repo — judges and recruiters will see this)
════════════════════════════════════════════════════════

**NEVER COMMIT:**
```
CHECKPOINT.md          — local memory file, gitignored
PROGRESS.md            — private build diary, gitignored
AGENTS.md exceptions   — this file itself CAN be public (no secrets in it)
.env, .env.local        — any credentials, testnet private keys, RPC URLs
*.log
reference/               — cloned comparison repos, never ours to publish
reports/*.html           — generated demo reports, keep sample only, not bulk
node_modules/, __pycache__/, venv/
```

**.gitignore must include** (add immediately, verify before first commit):
```
CHECKPOINT.md
PROGRESS.md
.env
.env.local
.env*.local
*.log
__pycache__/
*.pyc
venv/
node_modules/
reference/
reports/*.html
!reports/sample-report.html
.DS_Store
.vscode/
```

**Before every commit:**
```
[ ] git status — review every staged file individually
[ ] No .env, no CHECKPOINT.md, no PROGRESS.md staged
[ ] No private keys / RPC URLs / API tokens anywhere in staged diff
[ ] Rule validator passes on any changed rule YAML
[ ] No unverified controls committed as if verified
```

**Commit message standard** (this history is public, make it read like
disciplined engineering):
```
✅ feat(linux): add sysctl check_type + 3 verified network hardening controls
✅ feat(ledger): implement SHA-256 hash chain with break detection
✅ fix(windows): correct secpol parse for password history control
✅ docs(rules): add verification notes for 1.1.1.x kernel module controls
✅ chore(schema): tighten rule_schema.json required fields

❌ fix stuff / wip / testing / update
```

════════════════════════════════════════════════════════
SECTION 7 — LICENSE DISCIPLINE
════════════════════════════════════════════════════════

Reference repos in `reference/` (ansible-lockdown = MIT, ComplianceAsCode =
mostly BSD-derived) may be read for control logic and schema shape. Never
copy-paste their code verbatim into this repo. Every function you write
must be an original implementation based on understanding the check's
*behavior*, not a translation of their source text. If you're unsure
whether something counts as "too close," rewrite it from a plain-English
description of what the check does, not from the reference code open in
front of you.

════════════════════════════════════════════════════════
SECTION 8 — MINDSET
════════════════════════════════════════════════════════

Before building any control or feature, ask:
  "Have I verified this against a real system, or am I pattern-matching
   from a benchmark PDF I skimmed?"
  "If a judge ran this live against their own laptop right now, would it
   be correct?"
  "Am I marking uncertainty honestly, or quietly assuming the happy path?"

A tool with 30 controls that are all correct beats a tool with 150
controls where 20 are silently wrong. Never trade accuracy for control
count. The rule pack is not a checklist to fill — it's a set of claims
about system security that someone else will rely on.