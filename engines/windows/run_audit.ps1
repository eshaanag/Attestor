<#
.SYNOPSIS
    Attestor — Windows audit engine (Phase 2 skeleton).

.DESCRIPTION
    Loads a rule pack (rules/windows11_standalone/*.yaml), validates each rule
    against schema/rule_schema.json by shelling out to the Python validator
    (no duplicated validation logic — see DECISION FLAG below), dispatches each
    check to its check_type handler, streams one NDJSON line per check to stdout
    (docs/interfaces.md §1), and writes the final results.json (§3) to -Output.

    DECISION: Schema validation shells out to Python (tests/validate_rules.py).
    Rationale: PowerShell has no native JSON Schema draft-07 validator.
    Reimplementing validation in a second language is the drift AGENTS.md Rule C7
    warns against. Python is already a prerequisite on Windows hosts (report
    generation + ledger), so this adds no new dependency.

    Phase 2 scope (this skeleton):
      * IMPLEMENTED check_types: registry, secpol.
      * STUBBED check_types (return status=error, never a silent pass):
        account_policy, audit_policy, service_state.

    NOTHING here is "verified". Correctness requires running against a real
    Windows 11 VM (Phase 2 exit condition). This script on macOS/Linux only
    proves the plumbing, not control accuracy.

    Streams:
      * stdout  → live NDJSON, one per-check object per line.
      * -Output → final results.json.
      * stderr  → diagnostics, load errors, end-of-run summary.

.PARAMETER Target
    Rule-pack target folder name under rules/ (default: windows11_standalone).

.PARAMETER RulesDir
    Override rule directory (default: rules/<Target>).

.PARAMETER Rule
    Explicit rule file path(s) to evaluate (overrides -RulesDir).

.PARAMETER Output
    Path to write final results.json (default: ./results.json).
#>

[CmdletBinding()]
param(
    [string]$Target = "windows11_standalone",
    [string]$RulesDir = "",
    [string[]]$Rule = @(),
    [string]$Output = "results.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:ENGINE_NAME = "windows"
$script:ENGINE_VERSION = "0.1.0"
$script:FORMAT_VERSION = "1.0"
$script:REPO_ROOT = (Resolve-Path (Join-Path $PSScriptRoot ".." "..")).Path

# ─────────────────────────── helpers ───────────────────────────

function Get-UtcTimestamp {
    [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function New-CheckResult {
    param(
        [string]$RuleId,
        [int]$CheckIndex,
        [string]$Status,
        $Actual,
        $Expected,
        [string]$Evidence,
        [string]$Error = $null
    )
    $obj = [ordered]@{
        rule_id     = $RuleId
        check_index = $CheckIndex
        status      = $Status
        actual      = $Actual
        expected    = $Expected
        evidence    = $Evidence
        timestamp   = Get-UtcTimestamp
    }
    if ($Status -eq "error" -and $Error) {
        $obj["error"] = $Error
    }
    return $obj
}

function Write-NdjsonLine {
    param([hashtable]$Obj)
    # Emit one JSON line to stdout (NDJSON per interfaces.md §1).
    $json = $Obj | ConvertTo-Json -Compress -Depth 10
    [Console]::Out.WriteLine($json)
    [Console]::Out.Flush()
}

# ─────────────────────── check dispatchers ─────────────────────

function Invoke-RegistryCheck {
    param([string]$RuleId, [int]$Idx, [hashtable]$Check)

    $path = $Check["path"]
    $name = $Check["name"]
    $expected = $Check["expected"]
    $op = if ($Check.ContainsKey("op")) { $Check["op"] } else { "equals" }

    if (-not $path -or -not $name) {
        return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status "error" `
            -Actual $null -Expected $expected `
            -Evidence "registry check missing required 'path' or 'name' param" `
            -Error "malformed rule: 'path' and 'name' are required for registry"
    }

    $evidence = "Get-ItemProperty -Path '$path' -Name '$name'"
    try {
        $regValue = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop
        $actual = [string]($regValue.$name)
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status "error" `
            -Actual $null -Expected $expected `
            -Evidence $evidence -Error "registry path not found: $path"
    }
    catch [System.Management.Automation.PSArgumentException] {
        return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status "error" `
            -Actual $null -Expected $expected `
            -Evidence $evidence -Error "registry value not found: $name in $path"
    }
    catch {
        return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status "error" `
            -Actual $null -Expected $expected `
            -Evidence $evidence -Error $_.Exception.Message
    }

    $evidence = "$evidence => $actual"

    switch ($op) {
        "equals" {
            $status = if ($actual -eq [string]$expected) { "pass" } else { "fail" }
        }
        "matches" {
            $status = if ($actual -match [string]$expected) { "pass" } else { "fail" }
        }
        "present" {
            $status = "pass"  # We got here, so value exists.
        }
        "absent" {
            $status = "fail"  # Value exists but shouldn't.
        }
        default {
            return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status "error" `
                -Actual $actual -Expected $expected `
                -Evidence $evidence -Error "op '$op' not implemented for registry"
        }
    }

    return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status $status `
        -Actual $actual -Expected $expected -Evidence $evidence
}

function Invoke-SecpolCheck {
    param([string]$RuleId, [int]$Idx, [hashtable]$Check)

    $section = $Check["section"]   # e.g. "System Access", "Event Audit"
    $key = $Check["key"]           # e.g. "MinimumPasswordAge"
    $expected = $Check["expected"]
    $op = if ($Check.ContainsKey("op")) { $Check["op"] } else { "equals" }

    if (-not $section -or -not $key) {
        return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status "error" `
            -Actual $null -Expected $expected `
            -Evidence "secpol check missing required 'section' or 'key' param" `
            -Error "malformed rule: 'section' and 'key' are required for secpol"
    }

    # Export current security policy to a temp file.
    $tmpFile = [System.IO.Path]::GetTempFileName()
    $evidence = "secedit /export /cfg '$tmpFile' -> parse [$section] $key"
    try {
        $seceditOutput = & secedit /export /cfg $tmpFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status "error" `
                -Actual $null -Expected $expected `
                -Evidence $evidence -Error "secedit export failed: $seceditOutput"
        }

        # Parse INI-style output.
        $actual = $null
        $inSection = $false
        foreach ($line in Get-Content $tmpFile) {
            if ($line -match "^\[$([regex]::Escape($section))\]") {
                $inSection = $true
                continue
            }
            if ($inSection -and $line -match "^\[") {
                break  # Entered a new section.
            }
            if ($inSection -and $line -match "^\s*$([regex]::Escape($key))\s*=\s*(.+)$") {
                $actual = $Matches[1].Trim()
                break
            }
        }
    }
    catch {
        return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status "error" `
            -Actual $null -Expected $expected `
            -Evidence $evidence -Error $_.Exception.Message
    }
    finally {
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
    }

    if ($null -eq $actual) {
        return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status "error" `
            -Actual $null -Expected $expected `
            -Evidence $evidence -Error "key '$key' not found in section [$section]"
    }

    $evidence = "secedit [$section] $key = $actual"

    switch ($op) {
        "equals" {
            $status = if ($actual -eq [string]$expected) { "pass" } else { "fail" }
        }
        "matches" {
            $status = if ($actual -match [string]$expected) { "pass" } else { "fail" }
        }
        default {
            return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status "error" `
                -Actual $actual -Expected $expected `
                -Evidence $evidence -Error "op '$op' not implemented for secpol"
        }
    }

    return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status $status `
        -Actual $actual -Expected $expected -Evidence $evidence
}

function Invoke-StubCheck {
    param([string]$CheckType, [string]$RuleId, [int]$Idx, [hashtable]$Check)
    return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status "error" `
        -Actual $null -Expected $Check["expected"] `
        -Evidence "check_type '$CheckType' dispatched but not implemented" `
        -Error "check_type '$CheckType' is not implemented yet (Phase 2 skeleton)"
}

# Dispatch table: check_type → function.
$script:DISPATCH = @{
    "registry"         = { param($rid, $idx, $ck) Invoke-RegistryCheck $rid $idx $ck }
    "secpol"           = { param($rid, $idx, $ck) Invoke-SecpolCheck $rid $idx $ck }
    "account_policy"   = { param($rid, $idx, $ck) Invoke-StubCheck "account_policy" $rid $idx $ck }
    "audit_policy"     = { param($rid, $idx, $ck) Invoke-StubCheck "audit_policy" $rid $idx $ck }
    "service_state"    = { param($rid, $idx, $ck) Invoke-StubCheck "service_state" $rid $idx $ck }
}

function Invoke-Check {
    param([string]$RuleId, [int]$Idx, [hashtable]$Check)
    $ctype = $Check["type"]
    if (-not $script:DISPATCH.ContainsKey($ctype)) {
        return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status "error" `
            -Actual $null -Expected $Check["expected"] `
            -Evidence "no dispatcher for check_type '$ctype'" `
            -Error "unknown check_type: '$ctype'"
    }
    try {
        return & $script:DISPATCH[$ctype] $RuleId $Idx $Check
    }
    catch {
        return New-CheckResult -RuleId $RuleId -CheckIndex $Idx -Status "error" `
            -Actual $null -Expected $Check["expected"] `
            -Evidence "check_type '$ctype' raised during execution" `
            -Error "$($_.Exception.GetType().Name): $($_.Exception.Message)"
    }
}

# ─────────────────────── control roll-up ───────────────────────

function Get-ControlStatus {
    param([bool]$Automated, [array]$CheckResults)
    if (-not $Automated) { return "manual" }
    $statuses = $CheckResults | ForEach-Object { $_.status }
    if (-not $statuses) { return "error" }  # Defensive: automated + 0 checks = bug.
    if ($statuses -contains "error")          { return "error" }
    if ($statuses -contains "fail")           { return "fail" }
    if ($statuses -contains "manual")         { return "manual" }
    if (@($statuses | Where-Object { $_ -ne "not_applicable" }).Count -eq 0) { return "not_applicable" }
    return "pass"
}

function Get-EvidenceSummary {
    param([string]$ControlStatus, [bool]$Automated, [array]$CheckResults)
    if (-not $Automated) { return "manual review required (control marked automated: false)" }
    if (-not $CheckResults) { return "engine error: automated control has no checks" }
    if ($ControlStatus -eq "pass") {
        return ($CheckResults | ForEach-Object { $_.evidence }) -join "; " | Select-Object -First 500
    }
    # Surface the first offending check.
    $order = @{ "error" = 0; "fail" = 1; "manual" = 2; "not_applicable" = 3; "pass" = 4 }
    $worst = $CheckResults | Sort-Object { $order[$_.status] } | Select-Object -First 1
    $detail = if ($worst.error) { $worst.error } else { $worst.evidence }
    return "[$($worst.status)] $detail".Substring(0, [Math]::Min(500, "[$($worst.status)] $detail".Length))
}

# ─────────────────────── host metadata ─────────────────────────

function Get-HostMetadata {
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

    return [ordered]@{
        hostname    = $env:COMPUTERNAME
        os_name     = if ($os) { $os.Caption } else { "Windows 11" }
        os_version  = if ($os) { $os.Version } else { "unknown" }
        os_id       = "windows"
        kernel      = if ($os) { $os.BuildNumber } else { "unknown" }
        arch        = $env:PROCESSOR_ARCHITECTURE
        environment = "native"  # WSL detection not needed on the Windows side.
        elevated    = $elevated
        user        = $env:USERNAME
    }
}

# ─────────────────────── rule loading ──────────────────────────

function Test-RuleSchema {
    <#
    .SYNOPSIS
        Validate a single rule YAML file against the schema by calling the Python
        validator. Returns $true if valid, $false otherwise. Errors go to stderr.
    #>
    param([string]$FilePath)

    # Use a minimal Python one-liner that reuses the existing validator logic.
    $pyScript = @"
import sys, json, yaml
sys.path.insert(0, r'$($script:REPO_ROOT)')
from tests.validate_rules import load_validator, format_errors
v = load_validator()
doc = yaml.safe_load(open(r'$FilePath', encoding='utf-8').read())
errs = format_errors(v, doc)
if errs:
    for e in errs: print(e, file=sys.stderr)
    sys.exit(1)
sys.exit(0)
"@
    $result = & python3 -c $pyScript 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Schema validation failed for $FilePath`: $result"
        return $false
    }
    return $true
}

function Get-RuleFiles {
    if ($Rule.Count -gt 0) {
        return $Rule | ForEach-Object { Resolve-Path $_ }
    }
    $dir = if ($RulesDir) { $RulesDir } else { Join-Path $script:REPO_ROOT "rules" $Target }
    if (-not (Test-Path $dir)) {
        Write-Warning "Rules directory not found: $dir"
        return @()
    }
    return Get-ChildItem -Path $dir -Filter "*.yaml" | Sort-Object Name | ForEach-Object { $_.FullName }
}

function Import-Rules {
    param([string[]]$Paths)
    $validRules = @()
    $loadErrors = @()

    foreach ($path in $Paths) {
        # Parse YAML via Python (PowerShell has no built-in YAML parser).
        $pyParse = @"
import sys, json, yaml
sys.path.insert(0, r'$($script:REPO_ROOT)')
from tests.validate_rules import load_validator, format_errors
try:
    doc = yaml.safe_load(open(r'$path', encoding='utf-8').read())
except Exception as e:
    print(json.dumps({"error": str(e)}))
    sys.exit(1)
v = load_validator()
errs = format_errors(v, doc)
if errs:
    print(json.dumps({"error": "; ".join(errs)}))
    sys.exit(1)
print(json.dumps(doc, ensure_ascii=False))
sys.exit(0)
"@
        $raw = & python3 -c $pyParse 2>&1
        if ($LASTEXITCODE -ne 0) {
            $loadErrors += "$([System.IO.Path]::GetFileName($path)): $raw"
            continue
        }
        try {
            $rule = $raw | ConvertFrom-Json -AsHashtable
            $validRules += $rule
        }
        catch {
            $loadErrors += "$([System.IO.Path]::GetFileName($path)): JSON parse error from Python"
        }
    }
    return @{ Rules = $validRules; Errors = $loadErrors }
}

# ─────────────────────── evaluation ────────────────────────────

function Invoke-Rule {
    param([hashtable]$RuleObj)
    $ruleId = $RuleObj["id"]
    $automated = $RuleObj["automated"]
    $checkResults = @()

    if ($automated) {
        $checks = $RuleObj["checks"]
        for ($i = 0; $i -lt $checks.Count; $i++) {
            $ck = $checks[$i]
            # Convert PSCustomObject to hashtable if needed.
            if ($ck -is [System.Management.Automation.PSCustomObject]) {
                $ckHash = @{}
                $ck.PSObject.Properties | ForEach-Object { $ckHash[$_.Name] = $_.Value }
                $ck = $ckHash
            }
            $result = Invoke-Check -RuleId $ruleId -Idx $i -Check $ck
            Write-NdjsonLine $result
            $checkResults += $result
        }
    }
    # automated:false → no checks, no NDJSON lines (contract §1/§2).

    $status = Get-ControlStatus -Automated $automated -CheckResults $checkResults
    $summary = Get-EvidenceSummary -ControlStatus $status -Automated $automated -CheckResults $checkResults

    return [ordered]@{
        rule_id          = $ruleId
        title            = $RuleObj["title"]
        level            = [int]$RuleObj["level"]
        profile          = @($RuleObj["profile"])
        severity         = $RuleObj["severity"]
        automated        = $automated
        status           = $status
        checks           = $checkResults
        evidence_summary = $summary
        remediation      = $RuleObj["remediation"]
        source           = $RuleObj["source"]
    }
}

# ─────────────────────── main ──────────────────────────────────

function Main {
    $startedAt = Get-UtcTimestamp

    $rulePaths = Get-RuleFiles
    if ($rulePaths.Count -eq 0) {
        Write-Warning "0 rule files found for target '$Target'. Nothing to audit."
    }

    $loaded = Import-Rules -Paths $rulePaths
    $rules = $loaded.Rules
    $loadErrors = $loaded.Errors

    foreach ($err in $loadErrors) {
        Write-Host "LOAD ERROR (excluded): $err" -ForegroundColor Red
    }

    $controls = @()
    foreach ($rule in $rules) {
        $controls += Invoke-Rule -RuleObj $rule
    }

    # Sort controls by rule_id (dotted-int) per interfaces.md §4.
    $controls = $controls | Sort-Object {
        ($_.rule_id -split '\.' | ForEach-Object { [int]$_ }) -join '.'
    }

    # Build summary counts.
    $summary = [ordered]@{ pass = 0; fail = 0; error = 0; manual = 0; not_applicable = 0 }
    foreach ($c in $controls) { $summary[$c.status]++ }

    $complete = ($loadErrors.Count -eq 0) -and ($controls.Count -eq $rulePaths.Count)

    # Build results.json (§3).
    $results = [ordered]@{
        attestor_format_version = $script:FORMAT_VERSION
        report_id               = [guid]::NewGuid().ToString()
        target                  = $Target
        benchmark               = if ($rules.Count -gt 0) { $rules[0]["benchmark"] } else { "unknown" }
        benchmark_version       = if ($rules.Count -gt 0) { $rules[0]["benchmark_version"] } else { "unknown" }
        host                    = Get-HostMetadata
        run                     = [ordered]@{
            started_at     = $startedAt
            finished_at    = Get-UtcTimestamp
            complete       = $complete
            total_controls = $rulePaths.Count
            evaluated      = $controls.Count
            engine         = $script:ENGINE_NAME
            engine_version = $script:ENGINE_VERSION
        }
        summary                 = $summary
        controls                = $controls
    }

    # Write results.json.
    $results | ConvertTo-Json -Depth 20 | Set-Content -Path $Output -Encoding UTF8

    # Summary to stderr.
    $completeStr = if ($complete) { "COMPLETE" } else { "INCOMPLETE" }
    $msg = "Run $completeStr`: evaluated $($controls.Count)/$($rulePaths.Count) controls " +
        "(pass=$($summary.pass) fail=$($summary.fail) error=$($summary.error) " +
        "manual=$($summary.manual) n/a=$($summary.not_applicable)); " +
        "$($loadErrors.Count) load error(s). results.json -> $Output"
    Write-Host "`n$msg" -ForegroundColor Cyan

    if (-not $complete) { exit 1 }
    exit 0
}

Main
