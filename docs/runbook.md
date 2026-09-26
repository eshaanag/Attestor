# Attestor — Complete Runbook (Cheat Sheet)

> Print this or keep it open during the demo. Every command you'll need.

---

## 🔧 SETUP (Before anything else)

### Start VMs
- Open UTM/VirtualBox → Start **Ubuntu VM** and **Windows VM**
- Wait for them to boot fully (~30 seconds)

### Enable SSH on Ubuntu VM (if not already)
Open terminal IN the Ubuntu VM:
```bash
sudo systemctl start ssh
sudo systemctl enable ssh
```

### Enable SSH on Windows VM (if not already)
Open **PowerShell as Administrator** IN the Windows VM:
```powershell
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```

### Allow PowerShell scripts on Windows (one-time)
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
```

### VM IP Addresses
| VM | IP | User | Password |
|----|----|------|----------|
| Ubuntu | 192.168.64.6 | ubuntu | ubuntu |
| Windows | 192.168.64.4 | lab | lab |

---

## 🐧 LINUX AUDIT

### SSH into Ubuntu from Mac
```bash
ssh ubuntu@192.168.64.6
# password: ubuntu
```

### Run full audit (35 verified Level 1 controls, with HTML report)
```bash
cd ~/attestor_run
sudo python3 engines/linux/run_audit.py --level 1 --format html --output results.json
```
This creates:
- `results.json` — raw data
- `results.html` — HTML report (open in browser)

### Run specific controls only
```bash
sudo python3 engines/linux/run_audit.py --include 1.5.1 3.3.1.1 5.1.20
```

### Run Level 2 only
```bash
sudo python3 engines/linux/run_audit.py --level 2 --format html --output results_l2.json
```

### Exclude specific controls
```bash
sudo python3 engines/linux/run_audit.py --exclude 1.1.1.1 1.1.1.2 --format html --output results.json
```

### View report IN the Ubuntu VM
```bash
firefox results.html
```

### Copy report to your Mac and open
```bash
# Run from your Mac terminal (NOT inside SSH)
scp ubuntu@192.168.64.6:~/attestor_run/results.html ~/Desktop/linux_report.html
open ~/Desktop/linux_report.html
```

### ⚠️ IMPORTANT: Always use `sudo`
Without sudo, some checks get "permission denied" → shows as errors.
With sudo, all 100 checks resolve to pass/fail (0 errors).

---

## 🪟 WINDOWS AUDIT

### SSH into Windows from Mac
```bash
ssh lab@192.168.64.4
# password: lab
```

### Run full audit (30 verified Level 1 controls)
```powershell
cd C:\attestor
.\engines\windows\run_audit.ps1 -RulesDir "C:\attestor\rules\windows11_standalone" -Level 1 -Format json -Output "C:\attestor\results.json"
```

### Generate HTML report
```powershell
python C:\attestor\report\generate_report.py "C:\attestor\results.json" -o "C:\attestor\report.html"
```

### Open the report
```powershell
start C:\attestor\report.html
```
(This opens it in the default browser)

### Run specific controls
```powershell
.\engines\windows\run_audit.ps1 -RulesDir "C:\attestor\rules\windows11_standalone" -Include "2.3.1.1","5.40","17.1.1" -Format json -Output "C:\attestor\results.json"
```

### Run Level 2 only
```powershell
.\engines\windows\run_audit.ps1 -RulesDir "C:\attestor\rules\windows11_standalone" -Level 2 -Format json -Output "C:\attestor\results_l2.json"
```

### Copy report to your Mac
```bash
# Run from your Mac terminal
scp lab@192.168.64.4:C:/attestor/report.html ~/Desktop/windows_report.html
open ~/Desktop/windows_report.html
```

### ⚠️ If you get "running scripts is disabled"
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
```
Then retry.

### ⚠️ If you get "python not found"
Use the full path:
```powershell
& "C:\Users\lab\AppData\Local\Programs\Python\Python312-arm64\python.exe" C:\attestor\report\generate_report.py "C:\attestor\results.json" -o "C:\attestor\report.html"
```

---

## 🌐 WEB GUI (Dashboard)

### Start the GUI server (from your Mac)
```bash
cd /Users/eshaanog/Documents/SIH/Attestor
python3 -m pip install -r requirements.txt
python3 -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8000
```

### Open in browser
```
http://127.0.0.1:8000
```

### Use it:
1. For a local OS audit, select the OS target and level, then click **Run Audit**.
2. For a built-in network audit, choose `Cisco IOS / IOS-XE`, `Juniper Junos`,
   or `Fortinet FortiOS`, then select one or more genuine saved configuration
   files.
3. Optionally select one matching `show version` text file per configuration.
   Companion files pair by selection order and are used only for model, serial,
   and software identity. A mismatch fails only that paired item.
4. Select source-backed, NIST-mapped, or combined report presentation.
5. Click **Upload and audit**.
6. Download the JSON, offline HTML, PDF, or evidence-bundle ZIP for each
   uploaded device and open its persistent inventory/detail record. The ZIP
   contains report hashes and provenance but not the raw configuration file.
   Treat it as sensitive because report evidence may contain matched commands.
7. Upload a later configuration using the same filename/device ID and framework
   view. Open the device detail to review new failures, resolved findings,
   score/configuration movement, and the unchanged historical report downloads.
   Software movement is shown only when both scans include explicit parsed
   `show version` facts.
8. For an unfamiliar vendor, open **Training Studio**, upload a genuine config
   plus text/PDF vendor documentation, and review the redacted patterns.
9. Dry-run is automatic. The page shows the estimated Haiku-tier cost before an
   optional real suggestion action. Real suggestions require
   `ANTHROPIC_API_KEY` and a hard `max_calls` cap.
10. Confirm or correct a pattern, create a draft profile, add a source-referenced
   rule, publish it, and select it from the main console upload selector.

### Collect and audit a real network device

1. Ensure the machine running Attestor can reach the device's SSH port.
2. Open **Collect from a live device** in the console.
3. Select the vendor and enter host/IP, port, username, password, and the Cisco
   enable secret only when the account needs `enable` for `show running-config`.
4. Select the framework view and click **Connect and audit**.
5. The fixed commands are Cisco `show running-config` + `show version`, Junos
   `show configuration | no-more` + `show version | no-more`, or FortiOS
   `show full-configuration`. There is no arbitrary-command field.
6. A successful Cisco verification requires the results page, a report with
   `device.config_source` equal to `netmiko-ssh`, parsed device facts where the
   device exposes them, and downloadable JSON/HTML/PDF/ZIP artifacts.

Credentials are never written to SQLite or report artifacts. Collected raw
configuration is temporary. Until the above succeeds against a reachable real
device, describe the connector as implemented and tested, not live-verified.

The standalone collector is available when an explicit owner-only capture is
needed for troubleshooting. Passwords are prompted or read from dedicated
environment variables, never command-line flags:

```bash
export ATTESTOR_DEVICE_PASSWORD='your-device-password'
export ATTESTOR_DEVICE_SECRET='optional-cisco-enable-secret'
python3 engines/network/netmiko_collector.py \
  --vendor cisco_ios --host 192.0.2.10 --port 22 --username auditor \
  --output running-config.txt --facts-output show-version.txt
unset ATTESTOR_DEVICE_PASSWORD ATTESTOR_DEVICE_SECRET
```

The same optional identity input is available from the CLI:

```bash
python3 engines/network/run_audit.py \
  --config running-config.txt \
  --device-facts show-version.txt \
  --output results.json

python3 engines/network/run_junos_audit.py \
  --config configuration.conf \
  --device-facts show-version.txt \
  --output results.json

python3 engines/network/run_fortios_audit.py \
  --config fortigate-show.txt \
  --output results.json
```

The NIST option shows documented mappings attached to source-backed checks; it
does not claim a separate NIST-native rule pack. Uploaded configurations are
processed locally and discarded. SQLite retains hashes, redacted patterns,
profiles, report projections, and scan history, not raw configs. The dashboard
uses real Netmiko SSH collection when the live form is submitted; it does not
simulate DevNet or device output. Cisco IOS provides 14 CIS-backed
controls; Junos provides four vendor-documentation-backed controls; FortiOS
provides three vendor-documentation-backed controls. Other vendors may use
organization-defined flat profiles, but are not claimed as
Attestor-verified coverage. Native DISA/ISO packs remain roadmap, while live
collection awaits real-device verification.

### ⚠️ GUI requirements:
- `python3 -m pip install -r requirements.txt` must be completed
- Saved network configuration auditing runs locally without either VM.
- The legacy Windows/Linux live audit buttons still require their respective
  real machines and existing engine prerequisites.
- Optional real AI suggestions require `ANTHROPIC_API_KEY`; all other dashboard
  workflows work offline after dependencies are installed.

### Stop the server
Press `Ctrl+C` in the terminal

---

## 📊 GENERATE REPORT (from any results.json)

### On your Mac
```bash
cd /Users/eshaanog/Documents/SIH/Attestor
python3 report/generate_report.py <path-to-results.json> -o report.html
open report.html
```

### Examples:
```bash
# From a Linux results file
python3 report/generate_report.py ~/Desktop/results_linux.json -o ~/Desktop/linux_report.html

# From a Windows results file  
python3 report/generate_report.py ~/Desktop/results_windows.json -o ~/Desktop/windows_report.html
```

---

## 🔗 BLOCKCHAIN / TAMPER EVIDENCE DEMO

### Show the hash chain
```bash
cd /Users/eshaanog/Documents/SIH/Attestor
python3 -c "
import sys; sys.path.insert(0, '.')
from ledger.chain import append, verify
from pathlib import Path

# Append a report to the chain
append('/tmp/results.json', 'demo-host')

# Verify chain is intact
result = verify('demo-host')
print(f'Chain intact: {result[\"intact\"]}')
print(f'Links: {result[\"links\"]}')
"
```

### Show the Ethereum Sepolia proof (just open the current contract/transaction URL)
```
Current deployed contract: https://sepolia.etherscan.io/address/0xbd19e20aD6C216A8a793fdE3Bd46B9D291Bf5C41

The earlier Polygon Amoy transaction is retained as legacy history only; the
current code path uses Ethereum Sepolia and `anchorReport(root, previousRoot)`.
```

### Anchor a new root (if you want to show live)
```bash
python3 ledger/anchor.py anchor --chain-file ledger/chain.jsonl
```

---

## ✅ VALIDATION (prove everything works)

### Run from your Mac
```bash
cd /Users/eshaanog/Documents/SIH/Attestor

# Validate all 221 current real rules and negative fixtures
python3 tests/validate_rules.py

# Run the full test suite (current verified gate: 122 passed)
python3 -m pytest -q

# Show help
python3 engines/linux/run_audit.py --help
```

---

## 🚨 TROUBLESHOOTING

| Problem | Solution |
|---------|----------|
| "ssh: Operation timed out" | VM is not running or SSH not started |
| "permission denied" on Linux | Use `sudo` before the python3 command |
| "running scripts is disabled" on Windows | `Set-ExecutionPolicy Bypass -Scope CurrentUser -Force` |
| "python not found" on Windows | Use full path: `C:\Users\lab\AppData\Local\Programs\Python\Python312-arm64\python.exe` |
| "No such file or directory" report | Deploy report generator: `scp report/generate_report.py lab@192.168.64.4:C:/attestor/report/` |
| GUI shows nothing | Make sure VMs are running and SSH is enabled |
| "Module not found: yaml" | Run `pip install pyyaml jsonschema jinja2` on that machine |
| Mac shows all errors | That's normal — Mac doesn't have sysctl/modprobe. Run on the VMs instead |

---

## 📋 DEMO FLOW (in order)

1. **Show a rule file** — `cat rules/ubuntu2204_desktop/1.5.1_aslr.yaml`
2. **Run Linux audit via GUI** — http://localhost:8000, select Ubuntu, Run
3. **Show the HTML report** — click report link
4. **Run Windows audit via CLI** — SSH to Windows, run the command
5. **Show filtering** — `--include 1.5.1 3.3.1.1` (only 2 run)
6. **Tamper evidence** — open the Ethereum Sepolia contract or the transaction
   URL printed by the current `--blockchain` flow
7. **Schema validation** — `python3 tests/validate_rules.py` (200 rules pass)

---

## 📊 EXPECTED RESULTS

| Target | Pass | Fail | Error | Total |
|--------|------|------|-------|-------|
| Ubuntu (with sudo) | ~43 | ~44 | 0 | 87* |
| Ubuntu (without sudo) | ~41 | ~55 | 4 | 100 |
| Windows | ~24 | ~74 | ~2 | 100 |

*Some rules may not load if there are duplicate CIS IDs — this is normal.

The mix of pass/fail is CORRECT — it means the system hasn't been fully hardened.
A 100% pass would mean someone already applied all CIS recommendations.
