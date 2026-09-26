# Attestor

**Multi-vendor network security compliance auditing with AI-assisted vendor onboarding, offline reports, and tamper-evident audit trails.**

---

## What it does

Attestor reads network device configurations — Cisco IOS, Juniper Junos, Fortinet FortiOS — and checks them against CIS Benchmark security controls. You get a clear report showing which controls pass, which fail, and what to do about the ones that don't. Everything runs locally. No data leaves your network.

The core idea is simple: a sysadmin should be able to audit a router the same way they'd audit anything else — open a tool, get a clear answer, get told what to change.

---

## Why we built it this way

**AI helps, but doesn't decide.** The audit result comes from deterministic, source-backed rules. AI is used in two places: categorizing unfamiliar vendor syntax in the Training Studio, and generating remediation suggestions for failed controls. It cannot create a pass result or override the engine.

**New vendors don't require a code change.** The Training Studio lets a sysadmin teach Attestor about a completely new vendor — upload a config, let AI suggest command categories, confirm the mappings, write sourced rules, publish the profile. From that point on, any device from that vendor can be audited from the console without touching the backend.

**Raw configuration never leaves the machine.** Uploaded configs go into a temporary workspace and are discarded after the audit. SSH credentials stay in request memory. The database stores hashes, report projections, and redacted patterns — nothing sensitive.

---

## Supported vendors (built-in)

| Vendor | Controls | Framework |
|---|---|---|
| Cisco IOS / IOS-XE | 14 CIS-backed controls | CIS Benchmark + NIST SP 800-53 mappings |
| Juniper Junos | 4 baseline controls | Vendor security documentation |
| Fortinet FortiOS | 3 baseline controls | Vendor security documentation |

Additional vendors can be onboarded through the Training Studio without modifying any code.

---

## Getting started

**Prerequisites:** Python 3.10+

```bash
git clone https://github.com/eshaanag/Attestor.git
cd Attestor
python3 -m pip install -r requirements.txt
python3 -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in your browser.

---

## How to run an audit

**Option 1 — Upload a saved config file**

Open the console, select your vendor, upload the configuration file:
- Cisco: output of `show running-config`
- Junos: output of `show configuration | no-more`
- FortiOS: output of `show full-configuration`

**Option 2 — Connect to a live device via SSH**

Use the "Collect from a live device" form. Enter the host, port, vendor, and credentials. Attestor connects through Netmiko, runs only fixed read-only commands, and hands the collected config to the same audit engine. Credentials are never stored.

Both paths produce the same output.

---

## What you get

For each audited device, Attestor generates:

- **Offline HTML report** — self-contained, opens without internet access
- **PDF report** — includes device identity, findings by severity, evidence, and AI-generated remediation guidance per failed control
- **JSON** — machine-readable full audit data, suitable for SIEM integration
- **Evidence bundle ZIP** — packages all three formats plus a hash/provenance manifest; raw configuration is excluded

The dashboard also maintains a scan history per device so you can track compliance posture over time and see exactly what changed between scans.

---

## Training Studio

When Attestor encounters a vendor it doesn't recognize, Training Studio is how you onboard it:

1. Upload a genuine configuration file and enter the vendor name and version
2. Attestor extracts commands it doesn't know and strips all sensitive values before any further processing
3. Optionally request AI category suggestions — you see the estimated cost upfront and set a hard cap on API calls
4. Review and confirm every suggestion; nothing becomes a rule without explicit human approval
5. Write sourced rules for the vendor and publish the profile
6. The vendor now appears in the audit console for everyone — no redeploy needed

---

## Tamper-evident audit trail

Every report gets a SHA-256 hash computed from a canonical serialization of the results. Each new audit links its hash to the previous audit for that device, forming a chain. If anyone edits a historical report, the chain breaks and verification catches it immediately.

Optionally, the root hash can be anchored to an Ethereum Sepolia smart contract. Only the hash goes on-chain — configuration and findings stay local.

Contract: [`0xbd19e20aD6C216A8a793fdE3Bd46B9D291Bf5C41`](https://sepolia.etherscan.io/address/0xbd19e20aD6C216A8a793fdE3Bd46B9D291Bf5C41)

---

## Rules

Every security control is a plain YAML file under `rules/`. The schema in `schema/rule_schema.json` validates every rule at startup — a malformed rule is rejected before it participates in an audit.

To see exactly what any rule checks, open the YAML file. No compiled code to dig through.

```
rules/
├── cisco_ios/       — 14 CIS-backed rules
├── juniper_junos/   — 4 vendor-baseline rules
└── fortinet_fortios/ — 3 vendor-baseline rules
```

---

## Project structure

```
attestor/
├── dashboard/          — FastAPI web application (console, inventory, training, profiles)
├── engines/network/    — Cisco, Junos, FortiOS parsers + Netmiko SSH collector
├── rules/              — YAML rule packs, one file per control
├── schema/             — JSON Schema for rule validation
├── report/             — HTML, PDF, and evidence bundle generation
├── ai/                 — Pattern discovery, redaction, classification, and caching
├── ledger/             — SHA-256 hash chain and Sepolia anchoring
├── tests/              — Automated test suite and corpus fixtures
└── docs/               — Architecture, operator guide, and rule schema reference
```

---

## Tests

```bash
python3 -m pytest -q
python3 tests/validate_rules.py
```

Current gate: 122 tests passing, 221 rule files validated with zero failures.

---

## Live instance

[attestor-network.onrender.com](https://attestor-network.onrender.com)

---

## License

[MIT](LICENSE)
