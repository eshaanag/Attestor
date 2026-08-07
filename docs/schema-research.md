# Schema Research — Decision Document

Scope of this doc: decide the rule-YAML **field list** and **check_types** for the
MVP (Windows 11 Standalone + Ubuntu 22.04 Desktop, Level 1 only). Not a full audit
of the reference repos. Every claim below is from files actually read in
`reference/`; anything I didn't open is marked low priority.

> Note: the per-repo question list in the task prompt was truncated ("rest of the
> per-repo questions ... unchanged"), so I answered the schema-relevant questions:
> how each repo models a control, what metadata it carries, what check primitives it
> uses, and how it traces to a CIS ID. That is what we need to design the schema.

---

## Per-repo findings

### 1. ComplianceAsCode/content (BSD-ish) — the metadata gold standard
Read: 2 `rule.yml` files (`file_permissions_grub2_cfg`, `secure_boot_enabled`) out of ~2100.
- One rule = one directory; the **check logic is separated from the metadata**. Metadata
  fields: `title`, `description`, `rationale`, `severity` (low/medium/high),
  `identifiers` (CCE), `references` (big dict: `cis@<product>`, `nist`, `hipaa`, ...),
  `ocil_clause` + `ocil` (human/manual check text), `platform`, and a `template:` block
  (`name:` + `vars:`) that is the machine-checkable part.
- Templates ARE our check_types. `file_permissions` template = `{filepath, filemode}`.
  This confirms the "rule-as-data, check-type + params" model is the right shape.
- CIS ID lives in `references.cis@<product>`, not the filename — filename is a semantic slug.
- **Takeaway:** copy the metadata *shape* (title/description/rationale/severity + a
  check block with type+params + a separate manual-check text). Do NOT copy the giant
  `references` compliance-framework dict — that's over-scope for MVP.

### 2. UBUNTU22-CIS-Audit (goss-based) — the closest analog to what we're building
Read: `goss.yml` + 3 section files (1.1.1.1 kernel module, 1.5.1 sysctl, 1.6.1 motd).
- Pure **check-as-data**. goss resource types map almost 1:1 to our planned check_types:
  `file` (path/exists/contents-regex/mode), `kernel-param` (live sysctl value),
  `command` (exec + `exit-status` + `stdout` regex), plus package/service elsewhere.
- Each check has a `title` of form `"<CIS_ID> | <desc> | <method>"` and a `meta:` block:
  `server: 1`, `workstation: 1` (**level is per-profile**), `CIS_ID`, `NIST800-53R5`, `CCI`.
- Key insight: **one CIS control often needs multiple checks** (1.5.1 = live sysctl value
  AND persisted config in sysctl.conf). Our schema must allow a control to hold >1 check,
  or we split into sub-controls. Recommendation below handles this.
- `config_grep` is validated as necessary: motd/pam/sysctl checks are all regex-over-file.

### 3. ansible-lockdown UBUNTU22-CIS & Windows-11-CIS (MIT) — remediation, not audit
Read: Win `section_1/cis_1.1.x` (password policy), `section_2/cis_2.3.1.x`, dir listing of `section_18.9`.
- These are **remediation** playbooks (PATCH tasks), so less useful for check *logic*, but
  they confirm the Windows check primitives cleanly by which Ansible module is used:
  - `win_regedit` (path / name / data / type=dword) → **registry** check_type. Dominant
    (sections 2.3, 18 are almost entirely registry).
  - `win_security_policy` (section: `System Access`, key, value) → **secpol / account_policy**
    (password history, max age, guest account, blank-password limit).
  - Level carried in tags (`level1-corporate-enterprise-environment`) + `rule_<id>` tag.
- **Takeaway:** for Windows MVP, `registry` + `account_policy`/`secpol` cover the large
  majority of L1 Standalone controls. Audit-policy (section 17) and services (section 5)
  fill the rest.

### 4. cis-benchmarks-audit (CC BY-NC-SA — non-commercial, code NOT reusable) — CLI/output model
Read: README only.
- Single zero-dependency Python script. **Its CLI is a good spec to mirror**:
  `--level {1,2}`, `--include`, `--exclude`, `--system-type {server,workstation}`,
  `--outformat {csv,json,text,...}`.
- Result states worth adopting: **Pass / Fail / Skipped / Error** (+ per-check duration).
  This matches our Section-5 "never silently pass" mandate — Error and Skipped are distinct.
- License is non-commercial: read for concepts only, no code/text reuse.

### 5. lynis (GPLv3) — low priority
Not deep-read. Known: general hardening scanner, **not strictly CIS-control-ID traceable**.
It's the "what we are NOT" reference (Section: we are strictly CIS-ID-mapped). No schema value.

### 6. CIS-Sentinel (MIT) — direct SIH competitor, same problem statement
Read: README only.
- Same PS (Win11 Enterprise+Standalone, RHEL+Ubuntu), PowerShell/Bash/Python, `config.yml`
  customization, HTML reports, optional CIS-CAT Pro. README is AI-generated marketing with
  no evidence of a validated rule-as-data schema or any tamper-evidence.
- **Differentiators confirmed for judges:** (a) schema-validated rule-as-data with a JSON
  Schema gate, (b) SHA-256 hash-chained tamper-evident ledger, (c) explicit Error/manual
  states instead of pattern-matched pass. Low priority to dig further.

### 7. RHEL8-CIS-Audit — same goss structure as #2, out of MVP scope. Skipped.

---

## RECOMMENDATION

### A. check_types for the MVP
Matches the AGENTS.md Phase 1/2 lists and is confirmed by the evidence above. Keep it to
these — do not add compliance-framework mapping or Level 2 primitives yet.

**Ubuntu 22.04 L1**
- `kernel_module` — module not loadable/blacklisted (1.1.1.x)
- `sysctl` — live runtime value (`kernel.randomize_va_space`, net.* hardening)
- `file_permission` — owner / group / mode (grub.cfg, /etc/passwd, ...)
- `service_state` — enabled / disabled / masked
- `package_installed` — present / absent
- `config_grep` — regex match/absence in a config file (sshd_config, sysctl.d, motd, pam) — the flexible fallback

**Windows 11 Standalone L1**
- `registry` — key path / value name / expected data / type (covers most of §2.3, §18)
- `account_policy` — password + lockout policy (secedit `System Access`) (§1.1, §1.2)
- `secpol` — security options / user-rights (secedit) (§2.3.x beyond accounts)
- `audit_policy` — `auditpol` subcategory settings (§17)
- `service_state` — service start type (§5)

`service_state` is shared across both engines (same semantics, different backend).

### B. Rule YAML field list (build the JSON Schema to exactly this next)
```yaml
id:            ubuntu2204-1.5.1        # our stable unique id (target-cisid); required
cis_id:        "1.5.1"                  # dotted CIS control number; required
title:         "Ensure ASLR is enabled" # required
description:   "..."                     # what/why, from benchmark; required
rationale:     "..."                     # security reasoning; required
severity:      medium                    # low|medium|high; optional, default medium
level:         1                         # 1|2; required
automated:     true                      # false => report as "manual review", never auto-pass; required
checks:                                  # LIST (a control may need >1 check; ALL must pass); required
  - type: sysctl                         # one of the check_types above; required
    key: kernel.randomize_va_space       # type-specific params...
    expected: "2"
    op: equals                           # equals|matches|absent|present (per type); required
remediation:   "..."                     # fix text for the report; required
references:                              # traceability (Section 0 mandate); required
  benchmark: "CIS Ubuntu Linux 22.04 LTS Benchmark"
  version:   "v2.0.0"
  section:   "1.5.1"
source:        "verified: manual on 22.04 VM, sysctl -a"  # verification provenance; required
```
Design decisions:
- **`checks` is a list, not a single check.** Evidence #2 (1.5.1 live-value + persisted-config)
  proves one control needs multiple assertions. Control passes only if all checks pass;
  any check error → control = Error (never silent pass).
- **`automated` flag** (from CAC's OCIL/scored-vs-manual split, #1/#4). Cheap, and directly
  serves the "mark uncertainty honestly" mandate — manual controls render as MANUAL, not PASS.
- **`source` field** enforces Section 0: no control ships without a traceable origin.
- **`references` kept minimal** (benchmark/version/section only). We deliberately drop CAC's
  nist/hipaa/cce cross-mapping dict — real over-scope with no MVP payoff.
- Result states for the engine (from #4): `pass | fail | error | manual | not_applicable`.

### C. ComplianceAsCode metadata worth borrowing (clear low-effort wins only)
- **`severity` (low/medium/high)** — one enum field, enables report prioritization. Adopt.
- **`automated` (scored/manual)** — one bool, prevents false-pass on manual controls. Adopt.
- **Everything else declined for MVP:** the `references`/`identifiers` framework-mapping dict,
  `platform` applicability gating, and Jinja-templated variables are all real over-scope now.

**Next step:** write `schema/rule_schema.json` to field list (B), plus the validator that
rejects malformed YAML (Phase 0 exit condition). No schema/code written yet, per task.
