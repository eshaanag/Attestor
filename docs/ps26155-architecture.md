# Attestor for PS26155 - Architecture Brief

## Product boundary

PS26155 asks for an AI-assisted, vendor-agnostic network security compliance
auditor that ingests device configurations, normalizes diverse syntax, checks
security frameworks, learns unfamiliar commands through human training, and
produces actionable per-device reports.

Attestor delivers a competition-ready, evidence-first prototype:

- Cisco IOS/IOS-XE: 14 CIS-backed controls with NIST SP 800-53 mappings.
- Juniper Junos: four vendor-documentation-backed baseline controls. This is a
  scoped subset, not full Junos benchmark coverage.
- Fortinet FortiOS: three vendor-documentation-backed management-access
  controls. This is a scoped baseline, not a CIS FortiGate benchmark claim.
- Single and bulk saved-configuration upload with independent failure handling.
- Optional source-backed Cisco/Junos `show version` companion input for explicit
  model, serial, and software identity.
- Persistent local device inventory, scan history, device detail, and
  JSON/standalone HTML/PDF exports plus a hash/provenance evidence bundle.
- A privacy-safe Training Studio for unfamiliar vendor syntax.
- Published organization-defined vendor profiles that add flat exact-pattern
  checks without backend redeployment.
- Optional local hash chain and Ethereum Sepolia hash anchor. Blockchain is a
  bonus integrity proof, not the compliance decision engine.

Native DISA STIG and ISO/IEC 27001 rule packs, full coverage for the vendors in
the PS list, multi-user authentication, and real-device verification of the
implemented Netmiko collector remain outside the current evidence boundary. The current official Cisco IOS Router
and Switch STIG packages have been inspected, but no mapping was accepted
because the genuine corpus does not prove a complete pass and fail for the
applicable XCCDF checks. See `docs/disa-stig-evidence.md`.

## Runtime architecture

```text
Saved configuration(s) + optional paired show version output
        |
        v
Local ingestion boundary
count / size / UTF-8 validation
        |
        +--------------------------+
        |                          |
        v                          v
Built-in adapter              Published custom profile
Cisco flat/block parser       exact redacted full-line match
Junos brace parser            organization-defined assurance
FortiOS config/edit parser
        |                          |
        +------------+-------------+
                     v
       Deterministic fail-closed controls
       pass | fail | error | manual review
                     |
                     v
     Shared results.json + local SQLite projection
       |             |              |
       v             v              v
Offline HTML     ReportLab PDF   Device inventory/history
       \              /                 |
        +---- evidence bundle ZIP ------+
       |
       +----> optional SHA-256 chain / Sepolia hash-only anchor

Unfamiliar genuine config + vendor document
                     |
                     v
              Training Studio
redact -> normalize -> dry-run inventory -> cost estimate
                     |
         explicit capped Haiku suggestion
                     |
         human confirm/correct mapping
                     |
         draft -> sourced rules -> publish profile
```

The deterministic engine is authoritative. AI classification is discovery
metadata only and cannot create or change a compliance pass. Unreadable,
ambiguous, draft, unsourced, or unsupported input fails closed.

Device facts are identity metadata only. They are parsed from explicit vendor
labels, checked against the configuration hostname when both expose one, and
included in the existing report hash. Missing values remain unknown; no model,
serial, or version is inferred from filenames or vendor selection.

## Training and privacy boundary

Raw uploaded configuration bytes are hashed, processed temporarily, and
discarded. SQLite stores report projections, SHA-256 values, bounded redacted
document excerpts, and versioned redacted command patterns. It does not store
raw configurations or device credentials.

Upload analysis makes no provider call. Before an optional AI action, the UI
shows the uncached redacted pattern count and estimated Haiku-tier cost. The
operator must submit a hard `max_calls` cap. Missing credentials or an
insufficient cap stop the action before provider access. Actual calls, tokens,
and cost are persisted. Suggestions remain unconfirmed until a human accepts or
corrects them.

Organization-defined profiles require an attached knowledge-source hash, at
least one confirmed source-referenced rule, and explicit publication. Their
reports say they are not Attestor-verified vendor benchmarks. Hierarchical or
context-dependent syntax is not forced into the flat custom-profile engine.

## Extensibility and evidence gates

Every built-in vendor adapter emits the same results contract. Promoting a new
vendor from organization-defined to Attestor-verified requires:

1. A traceable corpus with source, license, retrieval date, and SHA-256.
2. Source-backed controls with no invented benchmark identifiers.
3. Parser behavior manually checked against raw configurations.
4. Both pass and fail corpus states for every control claimed as verified.

This design handles syntactic diversity through modular adapters and a training
loop while retaining a conservative compliance core.

## Verified evidence

- `121` automated tests pass.
- `221` real rule YAMLs validate; all negative fixtures fail as expected.
- Pinned canonical hash and ledger contracts pass unchanged.
- Cisco: ten source-backed configs; all 14 included controls have pass and fail
  evidence.
- Junos: six source-derived redacted configs; all four included controls have
  pass and fail evidence.
- FortiOS: eight licensed public captures; all three included controls have
  pass and fail evidence, while missing required sections remain errors.
- Live collection: fixed read-only Netmiko profiles, bounded output,
  credential non-persistence, error translation, and existing-engine handoff
  are tested. No successful real SSH collection is claimed yet.
- Device identity: five unmodified Apache-2.0 `show version` fixtures plus one
  source-derived hostname-matched Cisco integration config; manifest hashes and
  parser/report/dashboard behavior are covered by tests.
- Custom-profile workflow: genuine Cisco corpus train/confirm/publish plus one
  pass and one fail, with organization-defined labels in JSON, HTML, and PDF.
- Evidence bundles: successful built-in and organization-defined scans contain
  only JSON/HTML/PDF plus artifact hashes, provenance, privacy, and integrity
  metadata; the raw configuration file is excluded. Included report evidence
  may contain matched command text, so bundles remain sensitive local artifacts.
- Scan comparison: two genuine Cisco corpus configurations under one stable
  device ID produce five new failures and five fail-to-pass resolutions while
  preserving the first scan's JSON/HTML/PDF/ZIP bytes. Different framework
  views and missing software facts remain explicitly not comparable. The corpus
  does not prove a same-device software upgrade event.
- Real Sepolia proof for a Cisco report:
  `4b9515e22e18523f08685a1013f8dbf064f9b62f97136cbc0b39132cd174d750`.

Only a SHA-256 root and predecessor root are public on Sepolia. Configuration,
device identity, findings, evidence, and remediation remain local.
