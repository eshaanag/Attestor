# Interfaces — Pinned Contracts

The JSON contracts every component builds against: **engine → live NDJSON stream
(GUI)**, **engine → `results.json` → report generator**, and **`results.json` →
ledger**. Defined here *before* implementation (AGENTS.md Rule C7) so the engine,
report generator, and ledger cannot drift apart.

**Authoritative constraints inherited from other docs (do not contradict):**
- `status` values are exactly the five in `docs/architecture.md` §3:
  `pass | fail | error | manual | not_applicable`. **No other value is ever
  permitted** at check level or control level.
- Control-level roll-up follows `docs/architecture.md` §3 (elaborated to a strict
  precedence ladder in §2 below).
- Rule fields (`id`, `title`, `level`, `profile`, `severity`, `automated`,
  `remediation`, `source`, optional `device`, optional `framework_mappings`, …) are defined by `schema/rule_schema.json` /
  `docs/rule-schema.md`. This doc carries them through unchanged.
- `check_type` values are schema-enumerated. Phase A adds the `config_block`
  contract for the future network engine; it adds **no** new status values.

Contract version: `attestor_format_version = "1.0"`. Any breaking change to a
shape below bumps this string.

---

## 0. Global type & formatting rules (apply everywhere)

These exist so the canonical hash in §4 is reproducible.

- **Timestamps:** ISO-8601 **UTC**, second precision, `Z` suffix, no fractional
  seconds, no numeric offset. Exact format: `YYYY-MM-DDThh:mm:ssZ`
  (e.g. `2026-08-07T05:48:12Z`).
- **No floating-point values anywhere in `results.json`.** Numeric fields are
  integers (counts, `check_index`, `level`). Any numeric *expected/actual* value
  is carried as a **string** (e.g. `"2"`, `"0600"`) to avoid float/format
  nondeterminism in serialization.
- **Strings are UTF-8.** Evidence may contain non-ASCII; it is preserved, not
  escaped away (`ensure_ascii=False`).
- **Array order is significant and pinned** (see §4): `controls` sorted by
  `rule_id`, `checks` sorted by `check_index`.

---

## 1. Per-check result object (one NDJSON line per check)

The engine prints exactly one line of NDJSON to stdout **as each check
completes** (architecture §4a). The line **is** this object — no wrapper, no
`record_type`. The GUI consumes the stream live; the same objects are also nested
into the control roll-up (§2) in the final file.

```jsonc
{
  "rule_id":     "1.5.1",       // string. The owning rule's CIS id (== rule.id).
  "check_index": 0,             // integer ≥ 0. 0-based index into rule.checks[].
  "status":      "pass",        // string enum: pass|fail|error|manual|not_applicable. REQUIRED.
  "actual":      "2",           // observed value: string | integer | boolean | null.
                                //   null when the value could not be observed (error/manual/NA).
  "expected":    "2",           // required value from the rule check: string | integer | boolean | null.
  "evidence":    "sysctl kernel.randomize_va_space => kernel.randomize_va_space = 2",
                                // string. ALWAYS present, even on pass. The command run +
                                //   the relevant raw output (truncate long output to a sane cap).
                                //   This is what lets an auditor trust the line without re-checking.
  "error":       "sysctl exited 255: permission denied",
                                // string. OPTIONAL. Present IFF status == "error". Omitted otherwise.
  "timestamp":   "2026-08-07T05:48:12Z"  // string. When this check finished (see §0 format).
}
```

**Field types (strict):**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `rule_id` | string | yes | Matches `^[0-9]+(\.[0-9]+)*$` (same as rule `id`). |
| `check_index` | integer | yes | 0-based position in `rule.checks[]`. |
| `status` | string enum | yes | `pass \| fail \| error \| manual \| not_applicable`. |
| `actual` | string \| integer \| boolean \| null | yes | `null` when not observable. |
| `expected` | string \| integer \| boolean \| null | yes | Mirrors the rule check's expected value. |
| `evidence` | string | yes | Command(s) run + relevant raw output. Never empty. |
| `error` | string | only if `status=="error"` | Machine/human reason; absent otherwise. |
| `timestamp` | string | yes | §0 timestamp format. |

**Check-status semantics (what each value means, so the engine is consistent):**
- `pass` — value was observed and matches `expected`.
- `fail` — value was observed and does **not** match `expected`.
- `error` — could **not** be evaluated reliably (missing binary, permission
  denied, insufficient privilege, unparseable output). **Never** coerced to
  pass/fail. `error` field MUST be set.
- `not_applicable` — the check's precondition does not hold on this host, making
  it moot (e.g. a check keyed to a package/feature that isn't installed). Distinct
  from `fail`.
- `manual` — this specific check needs human verification (rare at check level;
  control-level manual normally comes from `automated:false`, which emits no
  check lines at all).

---

## 2. Control-level roll-up object (one per rule)

Produced after all of a rule's checks have run. Carries rule metadata through
unchanged and adds the rolled-up `status`, nested check results, and a summary.

```jsonc
{
  "rule_id":     "1.5.1",       // string == rule.id
  "title":       "Ensure address space layout randomization (ASLR) is enabled",
  "level":       1,             // integer 1|2 (from rule)
  "profile":     ["server","workstation"],  // array<string> (from rule)
  "device":      {                 // optional; present for network-device rules
    "vendor": "Cisco", "platform": "IOS", "roles": ["router"],
    "config_format": "running-config"
  },
  "framework_mappings": [          // optional secondary mappings; source required
    {"framework": "NIST SP 800-53", "version": "Rev. 5", "control_id": "IA-5",
     "relationship": "supports", "source": "traceable mapping source"}
  ],
  "severity":    "medium",      // string low|medium|high (from rule)
  "automated":   true,          // boolean (from rule)
  "status":      "pass",        // ROLLED UP, enum: pass|fail|error|manual|not_applicable
  "checks":      [ /* array of §1 per-check objects; [] iff automated==false */ ],
  "evidence_summary": "kernel.randomize_va_space = 2 (expected 2)",
                                // string, human-readable one-liner derived from checks
                                //   (for fail/error, summarize the offending check).
  "remediation": "Set kernel.randomize_va_space = 2 ...",  // string (from rule)
  "source":      "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0, control 1.5.1"  // string (from rule)
}
```

**Roll-up precedence ladder (deterministic — evaluate top to bottom, first match wins):**
This is architecture §3 made fully explicit, including check-level `manual` /
`not_applicable` which §3 did not spell out. It does not contradict §3.

1. `automated == false`  → **`manual`**   (and `checks == []`)
2. any check `status == error`  → **`error`**
3. any check `status == fail`   → **`fail`**
4. any check `status == manual` → **`manual`**
5. all checks `status == not_applicable` → **`not_applicable`**
6. otherwise (all `pass`, or `pass` mixed with `not_applicable`, ≥1 `pass`) → **`pass`**

Defensive rule: an `automated==true` control that somehow has zero checks is a
rule-load/engine bug → emit control `status == error` with an `evidence_summary`
saying so. (The schema's `if/then` should prevent this, but the engine must not
silently pass it.)

---

## 3. Final `results.json` (top-level)

Written **once, only on clean completion**. If the run aborts, `run.complete`
is `false` and `run.evaluated < run.total_controls` so the report can flag an
incomplete run loudly (Open Risk #7). `results.json` does **not** embed its own
hash — the ledger stores that separately (§4).

```jsonc
{
  "attestor_format_version": "1.0",     // string; bump on breaking contract change
  "report_id": "b3f1c2a4-9d7e-4c1a-8f2b-0a1c2d3e4f56",  // string UUIDv4, unique per run
  "target": "ubuntu2204_desktop",       // string; rule-pack target evaluated
  "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark",   // string (from rules)
  "benchmark_version": "v2.0.0",        // string (from rules)
  "device": {                             // absent for legacy OS target reports
    "device_id": "edge-01", "hostname": "edge-01",
    "vendor": "Cisco", "platform": "IOS", "model": null,
    "roles": ["router"], "config_source": "file",
    "config_sha256": "64 lowercase hexadecimal characters"
  },

  "host": {
    "hostname":    "demo-ubuntu",       // string
    "os_name":     "Ubuntu",            // string  (Windows: "Windows 11")
    "os_version":  "22.04",             // string  (Windows: display/build version)
    "os_id":       "ubuntu",            // string  (/etc/os-release ID; Windows: "windows")
    "kernel":      "5.15.0-91-generic", // string  (Windows: OS build, e.g. "10.0.22631")
    "arch":        "x86_64",            // string
    "environment": "native",            // string: "native" | "wsl" | "container"  (Open Risk #8)
    "elevated":    true,                // boolean: was the run root/Administrator?
    "user":        "root"               // string: the account that ran the audit
  },

  "run": {
    "started_at":     "2026-08-07T05:48:10Z",  // string §0 format
    "finished_at":    "2026-08-07T05:48:13Z",  // string §0 format
    "complete":       true,             // boolean: false if aborted/partial
    "total_controls": 1,                // integer: rules selected for this run (after level/profile/include/exclude)
    "evaluated":      1,                // integer: controls actually evaluated. evaluated<total ⇒ complete=false
    "engine":         "linux",          // string: "linux" | "windows"
    "engine_version": "0.1.0"           // string
  },

  "summary": {                          // integer counts across controls; must sum to len(controls)
    "pass": 1, "fail": 0, "error": 0, "manual": 0, "not_applicable": 0
  },

  "controls": [ /* array of §2 control roll-up objects */ ]
}
```

## 3a. Network ingestion dashboard contract (Phase H')

`POST /api/network/audit` accepts multipart form data:

- `files`: one or more saved Cisco IOS/IOS-XE or Juniper Junos configuration
  text files.
- `vendor`: `cisco_ios`, `juniper_junos`, or `custom:<profile_id>`. Built-in
  values select a source-backed adapter. A custom value selects a published
  organization-defined exact-pattern profile.
- `framework`: `all`, `cis`, or `nist`. This controls report presentation only;
  deterministic vendor rules and their results are unchanged. The `nist`
  option is explicitly a NIST SP 800-53 *mapped view* of source-backed checks, not
  a separate NIST-native rule pack.

Each file is copied to an isolated temporary directory and passed to the
selected built-in adapter (`run_audit.py` for Cisco or `run_junos_audit.py` for
Junos) or the published custom-profile engine. A successful
item returns links to its JSON, offline HTML, and PDF report. A failed item
returns an explicit error and no report links. Bulk items are processed
independently; one invalid file must not create or imply a successful result for
another. Uploaded configuration files are not retained by the dashboard after
processing.

Custom-profile results add top-level and per-control
`verification_status: "organization_defined"`. Framework mappings and
remediation in those reports are operator-defined and must not be presented as
Attestor-verified vendor or framework equivalence.

### 3b. Additive normalized security model

Network results may include a top-level `security_model` object. This is an
evidence/discovery view, not a second compliance result and not a replacement
for the deterministic `controls` array. The current Cisco adapter emits:

```jsonc
{
  "schema_version": "1.0",
  "vendor": "Cisco",
  "platform": "IOS/IOS-XE",
  "fields": {
    "ssh_version": {
      "value": 2,
      "evidence": {"line": 17, "observation": "SSH protocol version explicitly configured"}
    },
    "logging_host_configured": {"value": true, "evidence": {"line": 24, "observation": "remote logging host configured"}},
    "password_encryption": {"value": null, "evidence": null}
  }
}
```

`value` is a typed fact, `false` only means an explicit disabling command was
observed, and `null` means unknown from the supplied configuration. Evidence is
limited to safe line numbers/descriptions; raw configuration text and secrets
are never copied into this model. A future vendor adapter must emit the same
field names only when its own syntax provides equivalent evidence.

### 3c. Local product-state contract

The organizational dashboard persists local product state in SQLite. The
database is an implementation detail under `dashboard/data/` and is never part
of a report hash or committed repository evidence.

Persisted entity boundaries are:

- `device_records`: the latest inventory projection and scan history for a
  device. The stored JSON is the same dashboard record shape already used by
  `/console`; it does not retain uploaded configuration text.
- `training_sessions`: metadata and SHA-256 for an unfamiliar configuration
  submitted to the training workflow. Raw configuration text is temporary and
  is not stored in SQLite.
- `training_patterns`: redacted, normalized patterns plus provider or
  human-confirmed classification metadata. Unredacted lines are forbidden.
- `training_api_runs`: per-session provider accounting: model, number of real
  calls, input/output token counts, and calculated USD cost. It contains no
  configuration or command text.
- `knowledge_sources`: vendor/platform document metadata, content hash, and a
  bounded extracted excerpt. A source is evidence for operator review, not an
  automatically trusted compliance benchmark.
- `vendor_profiles` and `profile_rules`: operator-defined low-code audit
  profiles. These remain `draft` until explicitly published and are always
  labelled organization-defined unless they later pass the built-in vendor
  evidence gates.

SQLite writes are transactional. Invalid JSON, unsupported enum values, and
missing required identifiers fail with an explicit exception; no write may
silently create a successful scan or verified rule claim.

`POST /training/{session_id}/classify` is the only dashboard action allowed to
request provider classifications. It operates on already-redacted patterns
loaded from SQLite, never on the raw upload. The operator must submit a positive
`max_calls` cap after the review page displays the uncached pattern count and
estimated Haiku-tier cost. The request fails before any provider call when the
API key is absent or the cap is insufficient. Provider suggestions remain
unconfirmed discovery metadata and never alter a compliance result.

**Field types (strict):**

| Path | Type | Notes |
|------|------|-------|
| `attestor_format_version` | string | Contract version. |
| `report_id` | string | UUIDv4. |
| `target` | string | Rule-pack folder name. |
| `benchmark` / `benchmark_version` | string | From the rules evaluated. |
| `device` | object, optional | Audited network device identity and input provenance; absent for legacy OS reports. |
| `host.hostname/os_name/os_version/os_id/kernel/arch/user` | string | See mapping for Windows in comments. |
| `host.environment` | string enum | `native \| wsl \| container`. |
| `host.elevated` | boolean | Privilege at run time. |
| `run.started_at/finished_at` | string | §0 timestamps. |
| `run.complete` | boolean | Incomplete-run flag. |
| `run.total_controls/evaluated` | integer | Risk #7 completeness check. |
| `run.engine/engine_version` | string | |
| `summary.{pass,fail,error,manual,not_applicable}` | integer | Sum == `len(controls)`. |
| `controls` | array\<control roll-up\> | §2 objects. |

### 3.1 Additive network-report contract

The network engine must preserve every required v1.0 field above. Optional
network fields are additive, so `attestor_format_version` remains `"1.0"`.

- `host` identifies the workstation/server that executed Attestor. It is not
  the network device being assessed.
- top-level `device` identifies the audited device and is required for a network
  target. `device.device_id` is the stable identifier used as the ledger
  `host_id`; a parsed IOS hostname is the default, otherwise the CLI must require
  an explicit device ID.
- `device.config_sha256` is SHA-256 over the exact input configuration bytes.
  This proves which saved configuration was assessed without embedding the
  configuration itself in the report.
- control-level `device` describes rule applicability (vendor/platform/roles),
  while top-level `device` describes the concrete audited device.
- `framework_mappings` remains attached to each control. The dotted numeric CIS
  ID remains `rule_id`; secondary IDs such as `IA-5` never replace it.

The Phase A `config_block` check contract reserves these fields:

```jsonc
{
  "type": "config_block",
  "context_type": "line_vty",        // initially line_vty or interface
  "header_pattern": "^line vty ",    // selects candidate block headers
  "required_patterns": ["^transport input ssh$"],
  "forbidden_patterns": ["^transport input telnet"]
}
```

Phase D evaluates these patterns against normalized, indented child commands
inside each selected `line vty` or `interface` block. Zero matching blocks is
an `error`, a present block missing a required pattern is `fail`, and a block
containing a forbidden pattern is `fail`. Full semantics and corpus evidence
are recorded in `PROGRESS.md`; this contract does not itself establish a CIS
control. Phase E network controls preserve optional `framework_mappings` in
the v1.0 control object; the offline report displays each mapping's framework,
control ID, relationship, and source without changing the canonical hash
contract.

---

## 4. Canonicalization for hashing (testable spec)

The ledger (Phase 4) hashes a **canonical form** of `results.json` so identical
content always yields an identical SHA-256, and any edit changes it
(architecture §4b, Open Risk #5).

**Rules:**
1. Parse `results.json` to a Python object (hash the *data*, not raw text).
2. **Exclude** any ledger-injected key at the top level so hashing is stable even
   if we later embed the hash for display. Default exclude set: `("ledger",)`
   (i.e. a top-level `ledger` object, if present, is dropped before hashing).
   `results.json` itself SHOULD NOT contain it; the exclusion is belt-and-braces.
3. **Sort object keys** recursively (`sort_keys=True`).
4. **Pin array order** before serializing: `controls` sorted by `rule_id`
   (compare as dotted-integer tuples, e.g. `1.5.1` → `(1,5,1)`, so `1.10` > `1.9`);
   `checks` sorted by `check_index` ascending. The engine SHOULD already emit them
   in this order; canonicalization enforces it regardless.
5. **Serialize** with `separators=(",", ":")` (no insignificant whitespace),
   `ensure_ascii=False`, then encode **UTF-8**.
6. SHA-256 the resulting bytes; hex digest is the report's `content_hash`.

**Reference implementation (ledger builds to this exactly):**

```python
import json, hashlib
from typing import Any

LEDGER_KEYS = ("ledger",)  # top-level keys excluded from the hashed content

def _rule_id_key(rule_id: str) -> tuple[int, ...]:
    return tuple(int(p) for p in rule_id.split("."))

def canonicalize(results: dict[str, Any], exclude_keys: tuple = LEDGER_KEYS) -> dict[str, Any]:
    """Return a copy with excluded top-level keys removed and pinned array order.
    (Key *sorting* is delegated to json.dumps(sort_keys=True) in canonical_bytes.)"""
    obj = {k: v for k, v in results.items() if k not in exclude_keys}
    if "controls" in obj:
        controls = sorted(obj["controls"], key=lambda c: _rule_id_key(c["rule_id"]))
        for c in controls:
            if c.get("checks"):
                c["checks"] = sorted(c["checks"], key=lambda ck: ck["check_index"])
        obj["controls"] = controls
    return obj

def canonical_bytes(results: dict[str, Any], exclude_keys: tuple = LEDGER_KEYS) -> bytes:
    obj = canonicalize(results, exclude_keys)
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")

def content_hash(results: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(results)).hexdigest()
```

**Required unit test (Phase 4 gate, Risk #5):** load `results.json`, dump it back
out with arbitrary key order / whitespace, reload, and assert
`content_hash(a) == content_hash(b)`. Also assert that changing any single control
`status` changes the hash.

**Ledger chain record (`ledger/chain.jsonl`, one JSON object per line) — for
reference; full ledger contract is finalized in Phase 4:**

```jsonc
{
  "host_id":    "demo-ubuntu",                 // stable per-host identifier
  "report_id":  "b3f1c2a4-...",                // == results.json report_id
  "timestamp":  "2026-08-07T05:48:13Z",        // §0 format
  "prev_hash":  "0000...0000",                 // previous report's content_hash for this host ("0"*64 for the first)
  "content_hash": "e3b0c442..."                // content_hash(results.json)
}
```

---

## 5. Worked example — control `1.5.1` (Linux `sysctl` ASLR)

> **Provenance note (AGENTS.md §0):** control number `1.5.1` and
> `benchmark_version` here are illustrative for the contract. The rule-pack
> author MUST confirm the exact ID/section against the specific CIS Ubuntu 22.04
> benchmark version before this rule ships — CIS renumbers between versions.

### 5.1 The rule YAML (`rules/ubuntu2204_desktop/1.5.1_aslr.yaml`)
```yaml
id: "1.5.1"
title: "Ensure address space layout randomization (ASLR) is enabled"
benchmark: "CIS Ubuntu Linux 22.04 LTS Benchmark"
benchmark_version: "v2.0.0"
level: 1
profile: [server, workstation]
automated: true
severity: medium
checks:
  - type: sysctl
    key: kernel.randomize_va_space
    expected: "2"
    op: equals
remediation: >
  Set kernel.randomize_va_space = 2 in /etc/sysctl.conf or a file under
  /etc/sysctl.d/, then apply with: sysctl -w kernel.randomize_va_space=2
source: "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0, control 1.5.1"
```

### 5.2 NDJSON line emitted while running
Pass:
```json
{"rule_id":"1.5.1","check_index":0,"status":"pass","actual":"2","expected":"2","evidence":"sysctl -n kernel.randomize_va_space => 2","timestamp":"2026-08-07T05:48:12Z"}
```
Fail (value is 0):
```json
{"rule_id":"1.5.1","check_index":0,"status":"fail","actual":"0","expected":"2","evidence":"sysctl -n kernel.randomize_va_space => 0","timestamp":"2026-08-07T05:48:12Z"}
```
Error (no privilege / binary missing — note `actual:null` and `error` set):
```json
{"rule_id":"1.5.1","check_index":0,"status":"error","actual":null,"expected":"2","evidence":"ran: sysctl -n kernel.randomize_va_space","error":"sysctl exited 255: permission denied","timestamp":"2026-08-07T05:48:12Z"}
```

### 5.3 Its entry in the final `results.json` (pass case)
```json
{
  "rule_id": "1.5.1",
  "title": "Ensure address space layout randomization (ASLR) is enabled",
  "level": 1,
  "profile": ["server", "workstation"],
  "severity": "medium",
  "automated": true,
  "status": "pass",
  "checks": [
    {"rule_id":"1.5.1","check_index":0,"status":"pass","actual":"2","expected":"2","evidence":"sysctl -n kernel.randomize_va_space => 2","timestamp":"2026-08-07T05:48:12Z"}
  ],
  "evidence_summary": "kernel.randomize_va_space = 2 (expected 2)",
  "remediation": "Set kernel.randomize_va_space = 2 in /etc/sysctl.conf or /etc/sysctl.d/*, then apply with sysctl -w kernel.randomize_va_space=2.",
  "source": "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0, control 1.5.1"
}
```

### 5.4 The full `results.json` (single-control run)
```json
{
  "attestor_format_version": "1.0",
  "report_id": "b3f1c2a4-9d7e-4c1a-8f2b-0a1c2d3e4f56",
  "target": "ubuntu2204_desktop",
  "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark",
  "benchmark_version": "v2.0.0",
  "host": {
    "hostname": "demo-ubuntu", "os_name": "Ubuntu", "os_version": "22.04",
    "os_id": "ubuntu", "kernel": "5.15.0-91-generic", "arch": "x86_64",
    "environment": "native", "elevated": true, "user": "root"
  },
  "run": {
    "started_at": "2026-08-07T05:48:10Z", "finished_at": "2026-08-07T05:48:13Z",
    "complete": true, "total_controls": 1, "evaluated": 1,
    "engine": "linux", "engine_version": "0.1.0"
  },
  "summary": {"pass": 1, "fail": 0, "error": 0, "manual": 0, "not_applicable": 0},
  "controls": [
    {
      "rule_id": "1.5.1",
      "title": "Ensure address space layout randomization (ASLR) is enabled",
      "level": 1, "profile": ["server", "workstation"], "severity": "medium",
      "automated": true, "status": "pass",
      "checks": [
        {"rule_id":"1.5.1","check_index":0,"status":"pass","actual":"2","expected":"2","evidence":"sysctl -n kernel.randomize_va_space => 2","timestamp":"2026-08-07T05:48:12Z"}
      ],
      "evidence_summary": "kernel.randomize_va_space = 2 (expected 2)",
      "remediation": "Set kernel.randomize_va_space = 2 in /etc/sysctl.conf or /etc/sysctl.d/*, then apply with sysctl -w kernel.randomize_va_space=2.",
      "source": "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0, control 1.5.1"
    }
  ]
}
```

### 5.5 Canonical serialization of 5.4 (exact bytes fed to SHA-256)
Single line, all object keys sorted recursively, `controls`/`checks` order pinned,
`separators=(",",":")`, UTF-8:
```
{"attestor_format_version":"1.0","benchmark":"CIS Ubuntu Linux 22.04 LTS Benchmark","benchmark_version":"v2.0.0","controls":[{"automated":true,"checks":[{"actual":"2","check_index":0,"evidence":"sysctl -n kernel.randomize_va_space => 2","expected":"2","rule_id":"1.5.1","status":"pass","timestamp":"2026-08-07T05:48:12Z"}],"evidence_summary":"kernel.randomize_va_space = 2 (expected 2)","level":1,"profile":["server","workstation"],"remediation":"Set kernel.randomize_va_space = 2 in /etc/sysctl.conf or /etc/sysctl.d/*, then apply with sysctl -w kernel.randomize_va_space=2.","rule_id":"1.5.1","severity":"medium","source":"CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0, control 1.5.1","status":"pass","title":"Ensure address space layout randomization (ASLR) is enabled"}],"host":{"arch":"x86_64","elevated":true,"environment":"native","hostname":"demo-ubuntu","kernel":"5.15.0-91-generic","os_id":"ubuntu","os_name":"Ubuntu","os_version":"22.04","user":"root"},"report_id":"b3f1c2a4-9d7e-4c1a-8f2b-0a1c2d3e4f56","run":{"complete":true,"engine":"linux","engine_version":"0.1.0","evaluated":1,"finished_at":"2026-08-07T05:48:13Z","started_at":"2026-08-07T05:48:10Z","total_controls":1},"summary":{"error":0,"fail":0,"manual":0,"not_applicable":0,"pass":1},"target":"ubuntu2204_desktop"}
```
`content_hash` = `sha256(<the bytes above>)` = `7127f834f00f28c6cd8f84aa094dcefd7ae3090e9948544ca5bab81386eea829` → stored in `ledger/chain.jsonl`. (Verified: this line is the exact output of the §4 reference `canonical_bytes()`.)

---

## 6. Notes for reviewer (additions beyond the literal task field list)

Flagged so they can be trimmed if you disagree — none add a check_type or status:
- **`attestor_format_version`, `report_id`, `summary`, `target`, `run.engine*`** —
  added to the top level. `report_id` links `results.json` ↔ ledger ↔ report;
  `summary` and `target` are needed by the report/GUI; `format_version` future-proofs
  the contract.
- **`host.environment`** (`native|wsl|container`) — added to satisfy Open Risk #8.
- **`severity` and `automated`** carried into the control roll-up (from the rule) —
  the report prioritizes by severity and must show manual controls distinctly.
- **Roll-up precedence ladder (§2)** makes check-level `manual`/`not_applicable`
  precedence explicit; architecture §3 only covered pass/fail/error/automated.
- **No new status values were introduced.** Phase A adds the additive
  `config_block` check contract for network-device parsing; the five-status
  fail-closed contract remains unchanged.
