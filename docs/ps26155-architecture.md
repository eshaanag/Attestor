# Attestor for PS26155 — Architecture Brief

## Problem and product boundary

PS26155 asks for an AI-assisted, vendor-agnostic network security compliance
auditor that ingests device configurations, normalizes vendor syntax, evaluates
security frameworks, supports human training for unfamiliar syntax, and emits
actionable reports.

Attestor implements a production-oriented first slice of that platform:

- Cisco IOS/IOS-XE: 14 CIS-backed controls with NIST SP 800-53 mappings.
- Juniper Junos: four vendor-documentation-backed baseline controls with NIST
  mappings. This is a scoped subset, not full Junos compliance coverage.
- Saved configuration upload for one device or a small batch.
- Shared JSON, offline HTML, and PDF reports with device identity, severity,
  evidence, and remediation fields.
- AI-assisted discovery for unmatched syntax, with redaction, caching, human
  confirmation, dry-run default, and a hard provider-call cap.
- Optional tamper evidence through a local SHA-256 chain and Ethereum Sepolia
  anchor. Only hashes are public; configuration and report content stay local.

Palo Alto, Fortinet, Arista, Check Point, DISA STIG, ISO/IEC 27001, broader
Junos coverage, fleet management, and live device collection remain roadmap.

## Runtime architecture

```text
Saved Cisco/Junos configuration
              |
              v
    Dashboard ingestion boundary
    size/count/encoding validation
              |
              v
 Vendor adapter and normalized model
 Cisco flat/block parser | Junos brace parser
              |
              v
 Schema-validated deterministic rules
 pass | fail | error | manual review
              |
       +------+------------------+
       |                         |
       v                         v
 AI discovery/remediation       Shared results.json
 redacted + cached + capped      device + controls + evidence
 advisory only                   |
                                 +----> Offline HTML report
                                 +----> PDF report
                                 +----> Optional hash chain/Sepolia proof
```

The deterministic rule engine is authoritative. AI runs only after deterministic
matching and cannot turn an unknown or failed state into a pass. Unreadable,
ambiguous, or unsupported input fails closed with an explicit error.

## Extensibility contract

Every vendor adapter emits the same `results.json` contract and optional
vendor-neutral `security_model`. Adding a vendor requires four evidence gates:

1. Traceable configuration corpus with source, license, date, and SHA-256.
2. Source-backed controls with no invented benchmark identifiers.
3. Parser behavior manually checked against raw configurations.
4. Both pass and fail corpus states for every control presented as verified.

This isolates syntactic diversity in vendor adapters while preserving shared
reporting, AI discovery, dashboard ingestion, and tamper-evidence components.

## Security and privacy boundaries

- Uploaded configurations are processed in a temporary local workspace and are
  not retained by the dashboard.
- Sensitive values are redacted before any AI provider request and are never
  stored in classification caches.
- Provider use is opt-in; dry-run is the default and hard call caps prevent
  accidental spend.
- AI-generated remediation is visibly labelled advisory and requires operator
  review.
- The public chain receives a SHA-256 root and predecessor root only. It cannot
  reconstruct device configuration, findings, identity, or remediation text.

## Verified evidence

- 218 schema-valid rules across all retained tracks.
- 49 automated tests passing.
- Cisco corpus: ten source-backed configurations; all 14 included controls have
  pass and fail evidence.
- Junos corpus: six source-derived redacted configurations; all four included
  controls have pass and fail evidence.
- Real Sepolia proof for a Cisco network report:
  `4b9515e22e18523f08685a1013f8dbf064f9b62f97136cbc0b39132cd174d750`.

The existing Windows 11 and Ubuntu VM audit tracks remain separate, working
inputs to the same report and ledger infrastructure.
