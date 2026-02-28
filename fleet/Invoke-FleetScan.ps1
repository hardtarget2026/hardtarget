# ============================================================================
#  HardTarget Fleet - Remote Scan Runner
#  Runs HardTarget scan on remote machines via PowerShell Remoting
# ============================================================================
#
#  USAGE:
#    # Single machine
#    .\Invoke-FleetScan.ps1 -ComputerName LAPTOP-01 -HardTargetPath \\share\tools\HardTarget.ps1
#
#    # Multiple machines from list
#    .\Invoke-FleetScan.ps1 -ComputerFile .\machines.txt -HardTargetPath \\share\tools\HardTarget.ps1
#
#    # AD group
#    .\Invoke-FleetScan.ps1 -ADGroup "Workstations-Security" -HardTargetPath \\share\tools\HardTarget.ps1
#
#    # Collect to Azure Blob
#    .\Invoke-FleetScan.ps1 -ComputerFile .\machines.txt -HardTargetPath \\share\tools\HardTarget.ps1 -AzureSasUrl "https://..."
#
#  PREREQUISITES:
#    - PowerShell Remoting enabled on target machines (Enable-PSRemoting)
#    - Admin credentials for target machines
#    - HardTarget.ps1 accessible from target machines (UNC path or local copy)
#
#  NOTE: For Intune-managed environments, use the compliance and remediation
#  scripts instead (HardTarget_Compliance.ps1, HardTarget_Detect*.ps1).
#  This tool is for SCCM, GPO, or manual fleet scanning.
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(ParameterSetName='Single')]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName='File')]
    [string]$ComputerFile,

    [Parameter(ParameterSetName='AD')]
    [string]$ADGroup,

    [Parameter(Mandatory)]
    [string]$HardTargetPath,

    [string]$OutputDir = '.\fleet-scans',

    [string]$AzureSasUrl,

    [int]$ThrottleLimit = 10,

    [PSCredential]$Credential,

    [string]$ExpectedHash
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ============================================================================
#  RESOLVE TARGET MACHINES
# ============================================================================
$targets = @()

if ($ComputerName) {
    $targets = $ComputerName
} elseif ($ComputerFile) {
    if (-not (Test-Path $ComputerFile)) {
        Write-Error "Computer file not found: $ComputerFile"
        exit 1
    }
    $targets = Get-Content -Path $ComputerFile | Where-Object { $_.Trim() -ne '' -and $_ -notmatch '^\s*#' }
} elseif ($ADGroup) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $targets = Get-ADGroupMember -Identity $ADGroup -Recursive |
            Where-Object { $_.objectClass -eq 'computer' } |
            ForEach-Object { $_.Name }
    } catch {
        Write-Error "Failed to query AD group '$ADGroup': $_"
        exit 1
    }
}

if ($targets.Count -eq 0) {
    Write-Error "No target machines specified."
    exit 1
}

Write-Host "HardTarget Fleet Scanner" -ForegroundColor Cyan
Write-Host "Targets: $($targets.Count) machines"
Write-Host "HardTarget: $HardTargetPath"
Write-Host "Output: $OutputDir"

# H-1 FIX: Verify script integrity before distributing to fleet
if ($ExpectedHash) {
    Write-Host "Verifying script integrity..." -ForegroundColor Gray
    try {
        $actualHash = (Get-FileHash -Path $HardTargetPath -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($actualHash -ne $ExpectedHash) {
            Write-Error "INTEGRITY FAILURE: Script hash mismatch.`n  Expected: $ExpectedHash`n  Actual:   $actualHash`n  Aborting fleet scan to prevent execution of untrusted code."
            exit 1
        }
        Write-Host "  Hash verified: $actualHash" -ForegroundColor Green
    } catch {
        Write-Error "Could not verify script hash: $_"
        exit 1
    }
} else {
    Write-Host "  WARNING: No -ExpectedHash provided. Script integrity is NOT verified." -ForegroundColor Yellow
    Write-Host "  Use -ExpectedHash (Get-FileHash '$HardTargetPath' -Algorithm SHA256).Hash" -ForegroundColor Yellow
    Write-Host "  to verify the script before distributing to $($targets.Count) machines." -ForegroundColor Yellow
}

Write-Host ""

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

# ============================================================================
#  REMOTE SCAN SCRIPTBLOCK
# ============================================================================
$scanBlock = {
    param($ScriptPath, $VerifyHash)

    $ErrorActionPreference = 'Stop'
    $localDir = 'C:\ProgramData\HardTarget'

    # Ensure local directory
    if (-not (Test-Path $localDir)) {
        New-Item -Path $localDir -ItemType Directory -Force | Out-Null
    }

    # Copy script locally if it's a UNC path (runs faster, no network dependency during scan)
    $localScript = Join-Path $localDir 'HardTarget.ps1'
    if ($ScriptPath -match '^\\\\') {
        Copy-Item -Path $ScriptPath -Destination $localScript -Force
    } elseif (Test-Path $ScriptPath) {
        $localScript = $ScriptPath
    } else {
        throw "HardTarget.ps1 not found at $ScriptPath"
    }

    # H-1 FIX: Verify integrity of script on remote machine before execution
    if ($VerifyHash) {
        $remoteHash = (Get-FileHash -Path $localScript -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($remoteHash -ne $VerifyHash) {
            throw "INTEGRITY FAILURE on $env:COMPUTERNAME: expected hash $VerifyHash, got $remoteHash. Script may have been tampered with during copy."
        }
    }

    # Run scan in report mode
    $scanArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $localScript,
        '-Audit', '-NoNVD', '-OutputDir', $localDir
    )

    $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $scanArgs `
        -Wait -NoNewWindow -PassThru -ErrorAction Stop

    # Find latest scan JSON
    $latest = Get-ChildItem -Path $localDir -Filter 'HardTarget_scan_*.json' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $latest) {
        # Try the stable latest file
        $latestPath = Join-Path $localDir 'HardTarget_latest.json'
        if (Test-Path $latestPath) {
            return (Get-Content -Path $latestPath -Raw -Encoding UTF8)
        }
        throw "No scan JSON produced (exit code: $($proc.ExitCode))"
    }

    return (Get-Content -Path $latest.FullName -Raw -Encoding UTF8)
}

# ============================================================================
#  EXECUTE
# ============================================================================
$results = @{
    success = @()
    failed  = @()
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# Build session parameters
$sessionParams = @{}
if ($Credential) { $sessionParams['Credential'] = $Credential }

# Process in batches
$batches = for ($i = 0; $i -lt $targets.Count; $i += $ThrottleLimit) {
    ,@($targets[$i..[Math]::Min($i + $ThrottleLimit - 1, $targets.Count - 1)])
}

$batchNum = 0
foreach ($batch in $batches) {
    $batchNum++
    Write-Host "Batch $batchNum/$($batches.Count): $($batch -join ', ')" -ForegroundColor Gray

    $jobs = @()
    foreach ($target in $batch) {
        try {
            $job = Invoke-Command -ComputerName $target -ScriptBlock $scanBlock `
                -ArgumentList $HardTargetPath, $ExpectedHash -AsJob @sessionParams -ErrorAction Stop
            $jobs += @{ Computer = $target; Job = $job }
        } catch {
            Write-Host "  SKIP $target (connection failed: $_)" -ForegroundColor Red
            $results.failed += @{ Computer = $target; Error = $_.ToString() }
        }
    }

    # Wait for batch to complete (5 minute timeout per machine)
    foreach ($j in $jobs) {
        try {
            # L-4 FIX (v0.45): Actually enforce the 5 minute timeout.
            # Receive-Job -Wait has no -Timeout parameter; use Wait-Job first.
            $null = Wait-Job -Job $j.Job -Timeout 300
            if ($j.Job.State -eq 'Running') {
                # Job exceeded timeout - force stop
                Stop-Job -Job $j.Job -ErrorAction SilentlyContinue
                Write-Host "  TIMEOUT  $($j.Computer) (exceeded 5 minute limit)" -ForegroundColor Yellow
                $j.Job | Remove-Job -Force -ErrorAction SilentlyContinue
                continue
            }
            $output = Receive-Job -Job $j.Job -AutoRemoveJob -ErrorAction Stop

            if ($output) {
                # Save JSON
                $filename = "HardTarget_$($j.Computer)_${timestamp}.json"
                $filepath = Join-Path $OutputDir $filename
                $output | Out-File -FilePath $filepath -Encoding UTF8

                # Also save as latest_COMPUTER.json
                $latestPath = Join-Path $OutputDir "latest_$($j.Computer).json"
                $output | Out-File -FilePath $latestPath -Encoding UTF8

                # Quick parse for console output
                try {
                    $scan = $output | ConvertFrom-Json
                    $status = $scan.summary.overall
                    $statusColor = switch ($scan.summary.overallClass) {
                        'exposed' { 'Red' }; 'warn' { 'Yellow' }
                        'conditional-pass' { 'Cyan' }; 'protected' { 'Green' }
                        default { 'White' }
                    }
                    Write-Host "  OK   $($j.Computer): $status (P:$($scan.summary.pass) W:$($scan.summary.warn) F:$($scan.summary.fail))" -ForegroundColor $statusColor
                } catch {
                    Write-Host "  OK   $($j.Computer): scan saved (couldn't parse summary)" -ForegroundColor Gray
                }

                $results.success += $j.Computer
            } else {
                Write-Host "  FAIL $($j.Computer): no output" -ForegroundColor Red
                $results.failed += @{ Computer = $j.Computer; Error = 'No output from scan' }
            }
        } catch {
            Write-Host "  FAIL $($j.Computer): $_" -ForegroundColor Red
            $results.failed += @{ Computer = $j.Computer; Error = $_.ToString() }
            if ($j.Job.State -ne 'Completed') {
                Remove-Job -Job $j.Job -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# ============================================================================
#  AZURE UPLOAD (optional)
# ============================================================================
if ($AzureSasUrl -and $results.success.Count -gt 0) {
    Write-Host "`nUploading to Azure Blob..." -ForegroundColor Gray
    foreach ($computer in $results.success) {
        $latestFile = Join-Path $OutputDir "latest_${computer}.json"
        if (Test-Path $latestFile) {
            try {
                # H-2 FIX: Sanitize computer name to prevent blob path injection
                $safeName = $computer -replace '[^a-zA-Z0-9_\-]', '_'
                $blobFilename = [Uri]::EscapeDataString("latest_${safeName}.json")
                # M-3 FIX (v0.45): Parse SAS URL properly with [System.Uri] instead of
                # fragile string replacement that breaks with encoded query params.
                $sasUri = [System.Uri]::new($AzureSasUrl)
                $blobUrl = "{0}://{1}{2}/{3}{4}" -f $sasUri.Scheme, $sasUri.Authority, $sasUri.AbsolutePath.TrimEnd('/'), $blobFilename, $sasUri.Query
                $content = Get-Content -Path $latestFile -Raw -Encoding UTF8
                $headers = @{ 'x-ms-blob-type' = 'BlockBlob'; 'Content-Type' = 'application/json' }
                Invoke-RestMethod -Uri $blobUrl -Method PUT -Headers $headers -Body $content -ErrorAction Stop
            } catch {
                Write-Host "  Azure upload failed for ${computer}: $_" -ForegroundColor Yellow
            }
        }
    }
    Write-Host "  Azure upload complete." -ForegroundColor Gray
}

# ============================================================================
#  SUMMARY
# ============================================================================
Write-Host ""
Write-Host "Fleet Scan Complete" -ForegroundColor Cyan
Write-Host "  Success: $($results.success.Count)/$($targets.Count)" -ForegroundColor Green

if ($results.failed.Count -gt 0) {
    Write-Host "  Failed:  $($results.failed.Count)/$($targets.Count)" -ForegroundColor Red
    $results.failed | ForEach-Object {
        Write-Host "    $($_.Computer): $($_.Error)" -ForegroundColor Red
    }
}

Write-Host "`nScan JSONs saved to: $((Resolve-Path $OutputDir).Path)" -ForegroundColor Green
Write-Host "Run Aggregate-Fleet.ps1 -ScanDir '$OutputDir' to generate fleet reports." -ForegroundColor Gray
Write-Host "Or open fleet-dashboard.html and load the JSON files directly." -ForegroundColor Gray
