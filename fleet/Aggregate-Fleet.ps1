# ============================================================================
#  HardTarget Fleet - Aggregator Tool
#  Reads scan JSONs from a directory and produces fleet-level reports
# ============================================================================
#
#  USAGE:
#    .\Aggregate-Fleet.ps1 -ScanDir \\server\HardTarget$\scans
#    .\Aggregate-Fleet.ps1 -ScanDir C:\ProgramData\HardTarget -OutputDir .\reports
#    .\Aggregate-Fleet.ps1 -ScanDir .\scans -LatestOnly
#
#  OUTPUTS:
#    fleet_summary.json    - Fleet-level posture, scenario exposure, top findings
#    fleet_machines.csv    - One row per machine with posture summary
#    fleet_findings.csv    - One row per finding per machine (for PowerBI/Splunk)
#    fleet_scenarios.csv   - Scenario exposure per machine
#    fleet_drift.csv       - If multiple scans per machine exist: posture over time
#
#  FLAGS:
#    -ScanDir      Path to directory containing HardTarget scan JSONs
#    -OutputDir    Where to write reports (default: current directory)
#    -LatestOnly   Only process latest_*.json files (one per machine)
#    -Since        Only include scans after this date (yyyy-MM-dd)
#    -MinVersion   Only include scans from HardTarget version >= this
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ScanDir,

    [string]$OutputDir = '.',

    [switch]$LatestOnly,

    [string]$Since,

    [string]$MinVersion
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# L-5 FIX (v0.45): CSV formula injection prevention.
# Fields starting with =, +, -, @, tab, or CR can trigger formulas in Excel/Sheets.
# Prefix with single quote (') which Excel treats as text indicator.
function Protect-CsvField {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    if ($Value[0] -in '=', '+', '-', '@', "`t", "`r") {
        return "'" + $Value
    }
    return $Value
}

function Protect-CsvObject {
    param([PSCustomObject]$Obj)
    $props = @{}
    foreach ($p in $Obj.PSObject.Properties) {
        if ($p.Value -is [string]) {
            $props[$p.Name] = Protect-CsvField $p.Value
        } else {
            $props[$p.Name] = $p.Value
        }
    }
    [PSCustomObject]$props
}

# ============================================================================
#  COMPLIANCE JSON CONVERTER
#  Converts flat compliance script output to full-scan-like format so the
#  aggregator can process both formats uniformly.
# ============================================================================
function Convert-ComplianceToScan {
    param($data, [string]$FileName)
    $checkDefs = @(
        @{key='BitLocker_On';       expect=$true;  title='BitLocker is OFF';                section='encryption'; sev='fail'}
        @{key='BitLocker_HasPIN';   expect=$true;  title='BitLocker has no pre-boot PIN';   section='encryption'; sev='fail'}
        @{key='EnhancedPIN_Enabled';expect=$true;  title='Enhanced BitLocker PIN not enabled';section='encryption';sev='warn'}
        @{key='BLNetworkUnlock_Disabled';expect=$true;title='BitLocker Network Unlock enabled';section='encryption';sev='fail'}
        @{key='SecureBoot';         expect=$true;  title='Secure Boot is DISABLED';         section='bios';       sev='fail'}
        @{key='S0_Active';          expect=$false; title='Modern Standby (S0) is ACTIVE';   section='sleep';      sev='fail'}
        @{key='ConnectedStandby';   expect=$false; title='Connected Standby is ENABLED';    section='sleep';      sev='fail'}
        @{key='FastStartup';        expect=$false; title='Fast Startup is ENABLED';         section='sleep';      sev='fail'}
        @{key='WakeTimers_Disabled';expect=$true;  title='Wake timers are ENABLED';         section='sleep';      sev='warn'}
        @{key='Hibernate';          expect=$false; title='Hibernation is ENABLED';          section='sleep';      sev='warn'}
        @{key='CrashDumps';         expect=$false; title='Crash dumps are ENABLED';         section='memory';     sev='fail'}
        @{key='NMIDumps';           expect=$false; title='NMI crash dumps are ENABLED';     section='memory';     sev='warn'}
        @{key='PagefileClearedAtShutdown';expect=$true;title='Pagefile NOT cleared at shutdown';section='memory'; sev='fail'}
        @{key='KernelInRAM';        expect=$true;  title='Kernel pages to disk';            section='memory';     sev='warn'}
        @{key='VBS_Running';        expect=$true;  title='VBS is NOT running';              section='dma';        sev='warn'}
        @{key='HVCI_Running';       expect=$true;  title='HVCI is NOT running';             section='dma';        sev='warn'}
        @{key='CredentialGuard_Running';expect=$true;title='Credential Guard NOT running';  section='dma';        sev='warn'}
        @{key='DMAGuard';           expect=$true;  title='DMA Guard not enforced';          section='dma';        sev='fail'; condition='HasDMAPorts'}
        @{key='RDP_Disabled';       expect=$true;  title='Remote Desktop is ENABLED';       section='access';     sev='fail'}
        @{key='AutoLogon_Disabled'; expect=$true;  title='Auto-logon is ENABLED';           section='access';     sev='fail'}
        @{key='ARSO_Disabled';      expect=$true;  title='ARSO is ENABLED';                 section='access';     sev='warn'}
        @{key='UAC_RequiresPassword';expect=$true;  title='UAC no password required';       section='access';     sev='warn'}
        @{key='ScreenTimeout_Compliant';expect=$true;title='Screen timeout too long';       section='access';     sev='warn'}
        @{key='BuiltinAdmin_Disabled';expect=$true;title='Built-in Admin is ENABLED';       section='access';     sev='fail'}
        @{key='AccountLockout_Set'; expect=$true;  title='Account lockout not set';         section='access';     sev='fail'}
        @{key='PasswordMinLength';  expect=$null;  title='Password min length too short';   section='access';     sev='warn'; isInt=$true; minVal=8}
        @{key='CtrlAltDel_Required';expect=$true;  title='Ctrl+Alt+Del not required';       section='access';     sev='warn'}
        @{key='LastUsername_Hidden'; expect=$true;  title='Last username shown';             section='access';     sev='warn'}
        @{key='LSAProtection_Enabled';expect=$true;title='LSA Protection OFF';              section='access';     sev='fail'}
        @{key='KernelDebug_Disabled';expect=$true; title='Kernel debugging ENABLED';        section='boot';       sev='fail'}
        @{key='TestSigning_Disabled';expect=$true; title='Test signing ENABLED';            section='boot';       sev='fail'}
        @{key='AutoRun_Disabled';   expect=$true;  title='AutoRun is ENABLED';              section='forensic';   sev='fail'}
        @{key='WinRM_Disabled';     expect=$true;  title='WinRM is ENABLED';                section='forensic';   sev='fail'}
        @{key='ActivityHistory_Disabled';expect=$true;title='Activity History tracking';     section='forensic';   sev='warn'}
        @{key='Prefetch_Disabled';  expect=$true;  title='Prefetch is ENABLED';             section='forensic';   sev='warn'}
    )

    $checks = @()
    $pass = 0; $warn = 0; $fail = 0
    foreach ($cd in $checkDefs) {
        # Skip conditional checks when condition not met
        if ($cd.condition -and -not $data.($cd.condition)) { continue }
        $val = $data.($cd.key)
        if ($cd.isInt) {
            # Integer comparison (e.g. PasswordMinLength >= 8)
            $ok = ($val -is [int] -or $val -is [long]) -and $val -ge $cd.minVal
        } elseif ($cd.key -eq 'PasswordMinLength') {
            $ok = ($val -is [int] -or $val -is [long]) -and $val -ge 8
        } else {
            $ok = $val -eq $cd.expect
        }
        $status = if ($ok) { 'pass' } else { $cd.sev }
        $checks += @{ id = $cd.key; title = $cd.title; section = $cd.section; status = $status }
        switch ($status) { 'pass' { $pass++ } 'warn' { $warn++ } 'fail' { $fail++ } }
    }

    $overallClass = if ($fail -gt 3) { 'exposed' } elseif ($fail -gt 0) { 'warn' } elseif ($warn -gt 2) { 'warn' } else { 'protected' }
    $overall = switch ($overallClass) { 'exposed' { 'EXPOSED' } 'warn' { 'CONDITIONAL' } 'protected' { 'HARDENED' } }

    return [PSCustomObject]@{
        computer  = if ($data._deviceName) { $data._deviceName } else { $FileName -replace '\.json$','' }
        generated = $data.ScanTime
        version   = $data.HardTargetVersion
        machine   = @{ os = $data.OS; edition = $data.Edition; manufacturer = ''; model = '' }
        hasDmaPorts = [bool]$data.HasDMAPorts
        summary   = @{ pass = $pass; warn = $warn; fail = $fail; condPass = 0; overall = $overall; overallClass = $overallClass }
        checks    = $checks
        scenarios = @()
    }
}

# ============================================================================
#  LOAD SCANS
# ============================================================================
Write-Host "HardTarget Fleet Aggregator" -ForegroundColor Cyan
Write-Host "Scan directory: $ScanDir"

if (-not (Test-Path $ScanDir)) {
    Write-Error "Scan directory not found: $ScanDir"
    exit 1
}

$pattern = if ($LatestOnly) { 'latest_*.json' } else { '*.json' }
$files = Get-ChildItem -Path $ScanDir -Filter $pattern -File -ErrorAction Stop

if ($files.Count -eq 0) {
    Write-Error "No JSON files found in $ScanDir matching pattern '$pattern'"
    exit 1
}

Write-Host "Found $($files.Count) JSON files"

$allScans = @()
$parseErrors = @()

foreach ($file in $files) {
    try {
        $raw = Get-Content -Path $file.FullName -Raw -Encoding UTF8
        $scan = $raw | ConvertFrom-Json -ErrorAction Stop

        # Validate and normalize: accept full scans or compliance JSON
        $normalized = $null
        if ($scan.summary -and $scan.checks) {
            # Full HardTarget scan format — use as-is
            $normalized = $scan
        } elseif ($scan.ScanTime) {
            # Compliance script format — convert to aggregatable format
            $normalized = Convert-ComplianceToScan $scan $file.Name
        } else {
            $parseErrors += "$($file.Name): missing summary/checks and no ScanTime (not a HardTarget output)"
            continue
        }

        if (-not $normalized) { continue }

        # Apply filters
        if ($Since -and $normalized.generated) {
            $scanDate = [datetime]::Parse($normalized.generated)
            $sinceDate = [datetime]::Parse($Since)
            if ($scanDate -lt $sinceDate) { continue }
        }

        if ($MinVersion -and $normalized.version) {
            if ([version]$normalized.version -lt [version]$MinVersion) { continue }
        }

        $allScans += $normalized
    } catch {
        $parseErrors += "$($file.Name): $_"
    }
}

if ($parseErrors.Count -gt 0) {
    Write-Host "`nParse warnings:" -ForegroundColor Yellow
    $parseErrors | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}

# Deduplicate: keep latest scan per computer
$byComputer = @{}
foreach ($scan in $allScans) {
    $name = $scan.computer
    if (-not $name) { $name = 'UNKNOWN' }
    if (-not $byComputer[$name] -or $scan.generated -gt $byComputer[$name].generated) {
        $byComputer[$name] = $scan
    }
}

$fleet = $byComputer.Values | Sort-Object { $_.computer }
Write-Host "Unique machines: $($fleet.Count)" -ForegroundColor Green

if ($fleet.Count -eq 0) {
    Write-Error "No valid scans after filtering."
    exit 1
}

# ============================================================================
#  AGGREGATE
# ============================================================================
$stats = @{
    generated      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    machineCount   = $fleet.Count
    exposed        = ($fleet | Where-Object { $_.summary.overallClass -eq 'exposed' }).Count
    warn           = ($fleet | Where-Object { $_.summary.overallClass -eq 'warn' }).Count
    conditionalPass = ($fleet | Where-Object { $_.summary.overallClass -eq 'conditional-pass' }).Count
    hardened       = ($fleet | Where-Object { $_.summary.overallClass -eq 'protected' }).Count
    totalFails     = ($fleet | ForEach-Object { $_.summary.fail } | Measure-Object -Sum).Sum
    totalWarns     = ($fleet | ForEach-Object { $_.summary.warn } | Measure-Object -Sum).Sum
}

# Top failing checks
$failCounts = @{}
foreach ($m in $fleet) {
    foreach ($c in $m.checks) {
        if ($c.status -eq 'fail') {
            if (-not $failCounts[$c.id]) {
                $failCounts[$c.id] = @{ id = $c.id; title = $c.title; section = $c.section; count = 0; machines = @() }
            }
            $failCounts[$c.id].count++
            $failCounts[$c.id].machines += $m.computer
        }
    }
}
$topFails = $failCounts.Values | Sort-Object { $_.count } -Descending

# Scenario exposure
$scenarioExposure = @{}
foreach ($m in $fleet) {
    foreach ($s in $m.scenarios) {
        if (-not $scenarioExposure[$s.id]) {
            $scenarioExposure[$s.id] = @{ id = $s.id; name = $s.name; exposed = 0; warn = 0; protected = 0 }
        }
        if ($s.status -eq 'exposed') { $scenarioExposure[$s.id].exposed++ }
        elseif ($s.status -eq 'warn') { $scenarioExposure[$s.id].warn++ }
        else { $scenarioExposure[$s.id].protected++ }
    }
}

$stats['topFails'] = @($topFails | Select-Object -First 20)
$stats['scenarioExposure'] = @($scenarioExposure.Values)

# ============================================================================
#  OUTPUT
# ============================================================================
if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

# --- fleet_summary.json ---
$summaryPath = Join-Path $OutputDir 'fleet_summary.json'
$stats | ConvertTo-Json -Depth 10 | Out-File -FilePath $summaryPath -Encoding UTF8
Write-Host "  fleet_summary.json" -ForegroundColor Gray

# --- fleet_machines.csv ---
$machineRows = foreach ($m in $fleet) {
    [PSCustomObject]@{
        Computer     = $m.computer
        Manufacturer = $m.machine.manufacturer
        Model        = $m.machine.model
        OS           = $m.machine.os
        Edition      = $m.machine.edition
        Overall      = $m.summary.overall
        OverallClass = $m.summary.overallClass
        Pass         = $m.summary.pass
        CondPass     = $m.summary.condPass
        Warn         = $m.summary.warn
        Fail         = $m.summary.fail
        HasDMAPorts  = $m.hasDmaPorts
        ScanTime     = $m.generated
        Version      = $m.version
    }
}
$machinesPath = Join-Path $OutputDir 'fleet_machines.csv'
($machineRows | ForEach-Object { Protect-CsvObject $_ }) | Export-Csv -Path $machinesPath -NoTypeInformation -Encoding UTF8
Write-Host "  fleet_machines.csv" -ForegroundColor Gray

# --- fleet_findings.csv ---
$findingRows = foreach ($m in $fleet) {
    foreach ($c in $m.checks) {
        if ($c.status -eq 'fail' -or $c.status -eq 'warn') {
            [PSCustomObject]@{
                Computer = $m.computer
                CheckID  = $c.id
                Title    = $c.title
                Section  = $c.section
                Status   = $c.status
                Detail   = if ($c.detail) { $c.detail } else { '' }
                ScanTime = $m.generated
            }
        }
    }
}
$findingsPath = Join-Path $OutputDir 'fleet_findings.csv'
($findingRows | ForEach-Object { Protect-CsvObject $_ }) | Export-Csv -Path $findingsPath -NoTypeInformation -Encoding UTF8
Write-Host "  fleet_findings.csv" -ForegroundColor Gray

# --- fleet_scenarios.csv ---
$scenarioRows = foreach ($m in $fleet) {
    foreach ($s in $m.scenarios) {
        [PSCustomObject]@{
            Computer   = $m.computer
            ScenarioID = $s.id
            Scenario   = $s.name
            Status     = $s.status
            Fails      = $s.failCount
            Warns      = $s.warnCount
            ScanTime   = $m.generated
        }
    }
}
$scenariosPath = Join-Path $OutputDir 'fleet_scenarios.csv'
($scenarioRows | ForEach-Object { Protect-CsvObject $_ }) | Export-Csv -Path $scenariosPath -NoTypeInformation -Encoding UTF8
Write-Host "  fleet_scenarios.csv" -ForegroundColor Gray

# --- fleet_drift.csv (if multiple scans per computer exist) ---
if (-not $LatestOnly) {
    $driftByComputer = @{}
    foreach ($scan in $allScans) {
        $name = $scan.computer
        if (-not $name) { continue }
        if (-not $driftByComputer[$name]) { $driftByComputer[$name] = @() }
        $driftByComputer[$name] += $scan
    }

    $hasDrift = $false
    $driftRows = foreach ($name in ($driftByComputer.Keys | Sort-Object)) {
        $scans = $driftByComputer[$name] | Sort-Object { $_.generated }
        if ($scans.Count -gt 1) {
            $hasDrift = $true
            foreach ($s in $scans) {
                [PSCustomObject]@{
                    Computer     = $name
                    ScanTime     = $s.generated
                    Overall      = $s.summary.overall
                    OverallClass = $s.summary.overallClass
                    Pass         = $s.summary.pass
                    Warn         = $s.summary.warn
                    Fail         = $s.summary.fail
                }
            }
        }
    }

    if ($hasDrift) {
        $driftPath = Join-Path $OutputDir 'fleet_drift.csv'
        ($driftRows | ForEach-Object { Protect-CsvObject $_ }) | Export-Csv -Path $driftPath -NoTypeInformation -Encoding UTF8
        Write-Host "  fleet_drift.csv" -ForegroundColor Gray
    }
}

# ============================================================================
#  CONSOLE SUMMARY
# ============================================================================
Write-Host ""
Write-Host "Fleet Posture:" -ForegroundColor Cyan
Write-Host "  Machines:    $($stats.machineCount)"

$expColor = if ($stats.exposed -gt 0) { 'Red' } else { 'Gray' }
Write-Host "  Exposed:     $($stats.exposed)" -ForegroundColor $expColor

$warnColor = if ($stats.warn -gt 0) { 'Yellow' } else { 'Gray' }
Write-Host "  Warn:        $($stats.warn)" -ForegroundColor $warnColor

$cpColor = if ($stats.conditionalPass -gt 0) { 'Cyan' } else { 'Gray' }
Write-Host "  Conditional: $($stats.conditionalPass)" -ForegroundColor $cpColor

$hColor = if ($stats.hardened -gt 0) { 'Green' } else { 'Gray' }
Write-Host "  Hardened:    $($stats.hardened)" -ForegroundColor $hColor

if ($topFails.Count -gt 0) {
    Write-Host "`nTop Failures:" -ForegroundColor Cyan
    $topFails | Select-Object -First 5 | ForEach-Object {
        Write-Host "  $($_.count)/$($stats.machineCount)  $($_.title)" -ForegroundColor Red
    }
}

# Scenario summary
$exposedScenarios = $scenarioExposure.Values | Where-Object { $_.exposed -gt 0 } | Sort-Object { $_.exposed } -Descending
if ($exposedScenarios.Count -gt 0) {
    Write-Host "`nExposed Scenarios:" -ForegroundColor Cyan
    $exposedScenarios | ForEach-Object {
        Write-Host "  $($_.exposed)/$($stats.machineCount) exposed  $($_.name)" -ForegroundColor Red
    }
}

Write-Host "`nReports written to: $((Resolve-Path $OutputDir).Path)" -ForegroundColor Green
Write-Host "Open fleet-dashboard.html and load these JSONs for the visual dashboard." -ForegroundColor Gray
