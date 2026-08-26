# Attestor — Live Demo Script

Target time: 5-7 minutes. Fallback: 90-second pre-recorded video if live demo fails.

---

## Setup (before demo starts)

1. Ubuntu VM running (192.168.64.3, ssh ubuntu@...)
2. Windows VM running (192.168.64.4, ssh lab@...)
3. Repo cloned, dependencies installed on both VMs
4. Terminal open with two tabs: one SSH'd to Ubuntu, one SSH'd to Windows
5. Browser open to http://<ubuntu-vm-ip>:8080 (GUI server pre-started)

---

## Live Demo Sequence

### 1. Hook (30 seconds)
"We built Attestor — a compliance auditor for Windows, Linux, and selected
network devices. It evaluates real configurations against source-backed rules,
then produces evidence an auditor can inspect offline."

### 2. Show the rule pack (30 seconds)
```bash
# Show how controls are pure data, not hardcoded logic
cat rules/ubuntu2204_desktop/1.5.1_aslr.yaml
```
Point out: "Each control is a YAML file validated by a JSON Schema. 
Adding a new benchmark version = adding new YAML files, not rewriting code."

### 3. Run Linux audit via GUI (60 seconds)
- Click "Run Audit" in the browser (Ubuntu target, Level 1)
- Watch pass/fail stream in live (35 controls, ~3 seconds)
- Point out the live counters updating
- Click the report link when it appears
- Show the offline HTML report (no internet needed)

### 4. Audit network configurations (60 seconds)
- In the network panel choose Cisco IOS / IOS-XE and upload a genuine corpus
  file, then repeat with Juniper Junos and `junos_fabric01.conf`.
- Show the per-device pass/fail summary and open the generated PDF.
- Point out that Junos is explicitly a four-control source-backed subset; other
  vendors are roadmap, and NIST is a mapping view.

### 5. Run Windows audit via CLI (60 seconds)
```powershell
# On the Windows VM
.\engines\windows\run_audit.ps1 -Level 1 -Format json -Output C:\attestor\results.json
```
Show the summary: "30 controls, 12 pass, 18 fail, 0 errors. This is a 
default Windows 11 — most security policies aren't configured yet."

### 6. Show filtering (30 seconds)
```bash
# Run only 3 specific controls
python3 engines/linux/run_audit.py --include 1.5.1 3.3.1.1 5.1.20
# Exclude specific controls
python3 engines/linux/run_audit.py --exclude 1.1.1.1 1.1.1.2
```
"Customizable per organizational needs — run only what matters to you."

### 7. Tamper-evidence demo (60 seconds) — BONUS DIFFERENTIATOR
```python
# Append report to the hash chain
from ledger.chain import append, verify
append("results.json", "demo-host")

# Verify chain is intact
result = verify("demo-host")
# → intact=True

# Now tamper with the report (change a fail to pass)
# Re-verify:
result = verify("demo-host", results_dir=...)
# → intact=False, broken_at=0, reason="content_hash mismatch (report tampered)"
```
"If anyone silently edits a past report — changes a fail to a pass — 
the hash chain breaks and we detect exactly which report was altered. 
This is the blockchain component: every report is cryptographically 
linked to the one before it."

### 8. Summary (30 seconds)
"Attestor combines native Windows/Linux checks with verified Cisco IOS and
scoped Junos configuration auditing. Rules are schema-validated, reports are
offline, and AI suggestions are advisory and redacted. The optional blockchain
anchor publishes only a report hash, proving tamper-evidence without exposing
configuration data."

---

## Fallback Plan (if live demo fails)

### If VM is unreachable:
- Show the pre-generated `reports/sample-report.html` (already in the repo)
- Show the tamper-detection test output from `pytest tests/test_ledger_chain.py -v`
- Walk through `docs/interfaces.md` showing the contract-driven architecture

### If network issues:
- All reports open offline (no CDN/internet dependency)
- Pre-record a 90-second video covering steps 3-6 above

### Pre-recorded video contents (record NOW):
1. GUI "Run Audit" → live streaming → report link (Ubuntu)
2. Cisco and Junos uploads → PDF reports
3. Windows CLI run → summary
4. Tamper detection demo

---

## Key talking points for judges

- **"Why not just use CIS-CAT?"** — It's paywalled. We're free and open-source.
- **"Why not OpenSCAP?"** — It's XML-heavy (XCCDF/OVAL). Our rules are human-readable YAML.
- **"Is the blockchain real?"** — Yes. SHA-256 hash chain, every report linked to the previous. 
  Tamper = chain break detected at the exact altered link. Not a buzzword.
- **"How do you add new benchmarks?"** — Write YAML files. The engine and schema are target-agnostic.
- **"What about false positives?"** — No default-pass path. Unknown state = error, not pass. 
  We'd rather say "couldn't verify" than guess wrong.

---

## Numbers to cite

- 65 verified OS CIS controls (35 Ubuntu 22.04 + 30 Windows 11)
- 14 Cisco IOS CIS controls + 4 Junos vendor-baseline controls
- 10 check types implemented (sysctl, registry, kernel_module, etc.)
- 0 errors across full-pack runs on both real VMs
- Tamper detection proven: exact link identification when a report is altered
- One-command audit + HTML report via `--format html`
- Live GUI with real-time SSE streaming
