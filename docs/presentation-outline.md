# PS26155 Technical Presentation - 5 Slides

## Slide 1 - Problem and product

**Attestor: AI-assisted network configuration compliance without AI-made passes**

- Enterprise networks use incompatible Cisco, Juniper, firewall, cloud, and
  white-box configuration syntax.
- Manual audits are slow; vendor-locked suites are expensive and hard to extend.
- Attestor ingests saved configurations, evaluates deterministic controls, and
  uses a human training loop for syntax it does not recognize.

Visual: one organization network feeding a single Attestor evidence pipeline.

## Slide 2 - How it works

```text
Single/bulk config upload
        -> vendor adapter / published custom profile
        -> fail-closed deterministic controls
        -> normalized evidence + persistent device history
        -> JSON + offline HTML + PDF

Unmatched redacted syntax
        -> capped Haiku suggestion
        -> human confirm/correct
        -> sourced organization-defined profile
```

Key point: AI is an onboarding assistant, never the compliance authority.

## Slide 3 - What is built and verified

- Cisco IOS/IOS-XE: 14 CIS-backed controls with NIST SP 800-53 mappings.
- Juniper Junos: four source-backed baseline controls.
- Genuine traceable corpora with pass and fail evidence for every claimed rule.
- Persistent local inventory, bulk partial-failure handling, device drill-down,
  severity/evidence/remediation, and JSON/HTML/PDF exports.
- Training Studio: redaction, dry-run, pre-call cost, hard cap, cache, human
  confirmation, source attachment, draft/publish lifecycle.
- 76 automated tests; 218 validated rule files.

Scope label: custom profiles are organization-defined, not Attestor-verified.

## Slide 4 - Trust, privacy, and differentiator

- Unknown/unreadable/ambiguous state becomes `error`, never pass.
- Raw uploaded configurations are temporary and not stored in SQLite.
- AI sees only redacted patterns after explicit approval; actual usage/cost is
  recorded.
- Reports work offline.
- Optional SHA-256 chain + real Ethereum Sepolia proof. Only hashes are public,
  never device data or report content.

Sepolia transaction:
`4b9515e22e18523f08685a1013f8dbf064f9b62f97136cbc0b39132cd174d750`

## Slide 5 - Deployment and roadmap

**Prototype deployment:** local/self-hosted FastAPI + SQLite, no SPA build,
bounded uploads, same result/report contract for every adapter.

**Next verified increments:**

1. Real Netmiko collection against a reserved device.
2. Native source-backed DISA STIG and ISO/IEC 27001 packs.
3. Additional vendor adapters promoted only after corpus and pass/fail gates.
4. Authentication, RBAC, background jobs, encrypted secret handling, and
   Postgres for production fleet deployment.

Close: narrow verified coverage plus a reusable onboarding loop is more credible
than claiming every vendor with untested parsers.
