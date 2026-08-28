# Attestor - PS26155 Live Demo Script

Target: 4.5-5 minutes. Keep Windows/Linux and blockchain as proof of the
platform foundation; lead with the scored network-device workflow.

## Setup

1. Install dependencies: `python3 -m pip install -r requirements.txt`.
2. Start: `python3 -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8000`.
3. Open `http://127.0.0.1:8000` and the audit console.
4. Keep these genuine fixtures ready:
   - `tests/fixtures/network/cisco_ios/c4geeks_snmp_syslog_router_ios152.txt`
   - `tests/fixtures/network/cisco_ios/c4geeks_base_router_iosv.txt`
   - `tests/fixtures/network/cisco_ios/SOURCES.md`
   - `tests/fixtures/network/junos/junos_fabric01.conf`
   - `tests/fixtures/network/fortios/oxidized_fortigate_91g_7.4.7.txt`
5. Do not enable a real AI call during the competition demo unless the remaining
   cost and cap have been reviewed. Dry-run plus the recorded approved batch is
   sufficient to show the safety model.

## Sequence

### 1. Problem and boundary - 25 seconds

"Enterprises have many device vendors and no consistent, affordable source of
truth for configuration compliance. Attestor turns saved network configurations
into deterministic evidence, then uses AI only to help administrators understand
syntax the verified rules do not yet recognize."

State the honest scope: Cisco IOS/IOS-XE plus scoped Junos and FortiOS subsets
are built in. Other vendors use an organization-defined training path until they pass the same
corpus/source verification gates.

### 2. Bulk deterministic audit - 55 seconds

1. In **Audit Console**, choose Cisco IOS/IOS-XE and upload the two Cisco files.
2. Show independent per-file results and JSON/HTML/PDF links.
3. Open a device record: score, severity, evidence, remediation, history, hash.
4. Upload the Junos fixture and show the adapter filter.
5. Upload the FortiOS fixture and show one HTTP finding plus the verified
   administrator-account controls.

Say: "Missing or unreadable evidence is never a default pass. NIST is a mapped
view of source-backed checks, not a second invented benchmark pack."

### 3. AI training loop - 75 seconds

1. Open **Training Studio**.
2. Upload the genuine Cisco SNMP/syslog config as an unfamiliar platform and
   attach `SOURCES.md` as the vendor knowledge source.
3. Point out the configuration SHA-256 boundary and redacted patterns. Search
   visually for `service timestamps log datetime msec`.
4. Show the uncached pattern count, estimated Haiku cost, explicit call cap, and
   the statement that no raw configuration is available to the AI action.
5. Keep dry-run for the live demo. Explain that the approved 51-pattern batch
   cost `$0.019748`, actual usage is persisted, and every suggestion still needs
   human confirmation.
6. Confirm the timestamp pattern as `logging` with a source note.

### 4. Publish and reuse a vendor profile - 70 seconds

1. Create a draft organization baseline from the training session.
2. Add the confirmed timestamp pattern as a medium-severity rule, secure when
   present, with the exact committed source reference and operator remediation.
3. Publish the profile.
4. Return to the main console; show that the profile appears in the shared
   adapter selector.
5. Audit both Cisco files with this profile: the SNMP/syslog file passes and the
   base router fails.
6. Open the custom PDF and point out: organization-defined, not
   Attestor-verified; operator-defined remediation; no fake AI remediation.

### 5. Platform proof and close - 40 seconds

"The same result contract already supports 35 verified Ubuntu and 30 verified
Windows controls. Reports can be hash-chained, and a real Cisco report hash was
anchored on Ethereum Sepolia. Only the SHA-256 hash is public, never the report
or configuration."

Close with the evidence: `121` tests, `221` validated rules, three built-in vendor
adapters, a reusable human training loop, and offline JSON/HTML/PDF reporting.

## Judge questions

- **Is this really vendor-agnostic?** The shared ingestion, result, report,
  training, and profile contracts are vendor-neutral. Built-in verified coverage
  is deliberately narrow; custom profiles remain organization-defined until
  evidence gates are met.
- **Why AI if rules are deterministic?** AI reduces onboarding effort for
  unfamiliar syntax. It does not make compliance decisions.
- **What stops API overspend or secret leakage?** Dry-run default, redaction
  before provider use, explicit `max_calls`, pre-call cost display, caching, and
  persisted actual usage.
- **Do you support DISA and ISO?** The schema/report can carry mappings and the
  profile UI lets operators record sourced mappings, but native verified
  DISA/ISO packs are roadmap and are not claimed today.
- **Why blockchain?** It is an optional integrity seal. Only hashes are public.
- **Is live SSH implemented?** Yes. Netmiko runs fixed read-only commands and
  feeds temporary output into the same engine. Call it live-verified only after
  the presentation device completes the full collection/report path.

## Fallback

- Reports are offline and generated from committed genuine fixtures.
- Keep screenshots/PDFs of the bulk audit, Training Studio, profile publication,
  pass/fail custom audit, and the Sepolia transaction.
- If the dashboard server fails, run `python3 -m pytest -q` and show the saved
  report artifacts plus `docs/ps26155-architecture.md`.
