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

### Run full audit (100 controls, with HTML report)
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

### Run full audit (100 controls)
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
python3 dashboard/app.py
```

### Open in browser
```
http://localhost:8000
```

### Use it:
1. Select target: **Ubuntu 22.04 Desktop** or **Windows 11 Standalone**
2. Select level: **Level 1** or **Level 2**
3. Click **"▶ Run Audit"**
4. Watch live results stream in (pass/fail counters update in real-time)
5. When done → click **"📄 View Full Report"** link

### ⚠️ GUI requirements:
- Both VMs must be running and SSH accessible
- `pip install fastapi uvicorn` must be done on your Mac
- Ubuntu GUI works directly (engine runs as subprocess via SSH)
- Windows GUI works via SSH to the Windows VM

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

# Validate all 200 rules pass schema
python3 tests/validate_rules.py

# Run test suite (10 tests)
python3 -m pytest tests/ -v

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
