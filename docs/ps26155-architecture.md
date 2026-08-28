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
- Single and bulk saved-configuration upload with independent failure handling.
- Persistent local device inventory, scan history, device detail, and
  JSON/standalone HTML/PDF exports.
- A privacy-safe Training Studio for unfamiliar vendor syntax.
- Published organization-defined vendor profiles that add flat exact-pattern
  checks without backend redeployment.
- Optional local hash chain and Ethereum Sepolia hash anchor. Blockchain is a
  bonus integrity proof, not the compliance decision engine.

Native DISA STIG and ISO/IEC 27001 rule packs, full coverage for the vendors in
the PS list, multi-user authentication, and verified live SSH collection remain
outside the current evidence boundary.

## Runtime architecture

```text
Saved configuration(s)
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

- `76` automated tests pass.
- `218` real rule YAMLs validate; all negative fixtures fail as expected.
- Pinned canonical hash and ledger contracts pass unchanged.
- Cisco: ten source-backed configs; all 14 included controls have pass and fail
  evidence.
- Junos: six source-derived redacted configs; all four included controls have
  pass and fail evidence.
- Custom-profile workflow: genuine Cisco corpus train/confirm/publish plus one
  pass and one fail, with organization-defined labels in JSON, HTML, and PDF.
- Real Sepolia proof for a Cisco report:
  `4b9515e22e18523f08685a1013f8dbf064f9b62f97136cbc0b39132cd174d750`.

Only a SHA-256 root and predecessor root are public on Sepolia. Configuration,
device identity, findings, evidence, and remediation remain local.
