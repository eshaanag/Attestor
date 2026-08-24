# Rule Schema

Source of truth: [`schema/rule_schema.json`](../schema/rule_schema.json) (JSON Schema
draft-07). This document explains the **intent** of each field; the JSON file is
authoritative for exact types, patterns, and constraints. The validator
[`tests/validate_rules.py`](../tests/validate_rules.py) enforces it against every
`rules/**/*.yaml`.

Scope: Existing Windows/Linux CIS targets remain supported. The additive network
track uses `profile: [network_device]`, device metadata, and optional secondary
framework mappings without changing existing rule files.

## Top-level fields

| Field | Required | Intent |
|-------|----------|--------|
| `id` | yes | The CIS control ID in dotted-number form (e.g. `1.1.1.1`). Regex-constrained. This *is* the control number — there is no separate `cis_id`. |
| `title` | yes | Human-readable control title. |
| `description` | no | What the control checks and why, paraphrased from the benchmark. |
| `rationale` | no | Security reasoning for the control. |
| `benchmark` | yes | Name of the source CIS benchmark (e.g. `CIS Ubuntu Linux 22.04 LTS Benchmark`). |
| `benchmark_version` | yes | Version of that benchmark (e.g. `v2.0.0`). |
| `level` | yes | CIS profile level — integer `1` or `2`. |
| `profile` | yes | Non-empty array of applicable profiles. Allowed values: `server`, `workstation`, `standalone`, `enterprise`, `network_device`. |
| `device` | conditional | Required when `profile` contains `network_device`; identifies the vendor/platform and optional device role/config format. |
| `framework_mappings` | no | Secondary framework references, each with `framework`, `control_id`, and a traceable `source`. The primary CIS identity remains in `benchmark`/`benchmark_version`/`id`. |
| `automated` | yes | `true` if programmatically checkable; `false` for manual-review-only controls. |
| `severity` | yes | `low` / `medium` / `high` — report prioritization (borrowed from ComplianceAsCode). |
| `checks` | yes | Ordered array of checks. The control passes only if **all** checks pass. May be empty **only** when `automated: false`. |
| `remediation` | yes | Actionable fix text shown in the report. |
| `source` | yes | Traceable provenance — a CIS benchmark section reference or `manual verification on <OS> <date>`. Min length enforced; must never be empty or generic (the latter is a review-time obligation the schema cannot fully police). |

`additionalProperties` is `false` at the top level: unknown fields are rejected, so a
typo'd field name fails validation rather than being silently ignored.

## `checks[]` items

Each check is an object with at least a `type`. Type-specific parameters (e.g. `key`,
`expected`, `path`, `name`) are allowed and vary per check type, so `additionalProperties`
is `true` inside a check.

| Field | Required | Intent |
|-------|----------|--------|
| `type` | yes | The dispatcher/check type. Enum-constrained to the MVP list below. |
| `op` | no | Comparison operator when applicable: `equals`, `matches`, `absent`, `present`. |

### Allowed `type` values (MVP)

- **Ubuntu 22.04**: `kernel_module`, `sysctl`, `file_permission`, `package_installed`,
  `config_grep`, `service_state`
- **Windows 11 Standalone**: `registry`, `account_policy`, `secpol`, `audit_policy`,
  `service_state`
- **Network track**: existing `config_grep` for flat text checks and
  `config_block` for block-aware checks.

`config_block` additionally requires `context_type` (`line_vty` or
`interface`), a non-empty `header_pattern`, and `required_patterns` /
`forbidden_patterns` arrays of regex strings. This is a parser contract, not a
claim that a corresponding CIS control has been sourced or verified.

`service_state` is shared across both engines.

## Conditional rule

If `automated` is `true`, `checks` must contain at least one item (enforced via an
`if/then` block in the schema). This prevents an "automated" control from silently
passing with nothing to check. Manual controls (`automated: false`) may carry an empty
`checks` array but still require `id`, `title`, `remediation`, and `source`.

## Deviations from `docs/schema-research.md` field list (B)

The research doc's draft field list was adjusted to the explicit task requirements:

- `id` now holds the CIS control number directly (regex-constrained); the separate
  `cis_id` slug was dropped as redundant.
- `benchmark` + `benchmark_version` are top-level fields instead of a nested
  `references` object; the `section` sub-field was dropped (redundant with `id`).
- `profile` (array) was added as required.
- `description` and `rationale` were kept as optional recommended fields.

## Network rule example (shape only)

The following illustrates the additive fields; it is not a shipped control or
evidence for any benchmark claim:

```yaml
profile: [network_device]
device:
  vendor: Cisco
  platform: IOS
  roles: [router]
  config_format: running-config
framework_mappings:
  - framework: NIST SP 800-53
    version: Rev. 5
    control_id: IA-5
    relationship: supports
    source: "NIST SP 800-53 Rev. 5, IA-5, official publication"
```
