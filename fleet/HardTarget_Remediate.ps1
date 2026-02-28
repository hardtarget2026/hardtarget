# ============================================================================
#  HardTarget Intune Integration - Remediation Script
#  Proactive Remediation: Physical Security Baseline (Tier 1)
# ============================================================================
#
#  SPDX-License-Identifier: BUSL-1.1
#  Copyright (c) 2026 HardTarget Contributors. All rights reserved.
#
#  PURPOSE: Applies Tier 1 fixes that are safe for unattended remote
#  remediation. All changes are registry writes or policy settings.
#  No reboots. No boot configuration changes. No destructive operations.
#
#  SECURITY MODEL:
#    Authorization: Intune admin with Device Configuration RBAC role
#    Execution:     SYSTEM context via Intune Management Extension
#    Approval:      Intune Proactive Remediation assignment (replaces
#                   HardTarget's console confirmation codes)
#    Verification:  Each fix verified after application
#    Audit trail:   Results in Intune portal + local Event Log
#
#  WHAT THIS DOES NOT DO:
#    - No bcdedit changes (kernel debug, test signing)
#    - No reagentc changes (WinRE)
#    - No service stops (SysMain, WSearch) -- too disruptive for silent push
#    - No VBS/HVCI/Credential Guard/DMA Guard (reboot required, Tier 2)
#    - No Modern Standby override (reboot required, Tier 2)
#    - No hibernation disable (user workflow impact, Tier 3)
# ============================================================================

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# M-8 FIX: Verify we're running elevated (SYSTEM or admin). If Intune
# misconfiguration runs this as the logged-in user, HKLM writes would
# either fail silently or produce inconsistent state with exit code 0.
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) {
    Write-Output "HardTarget Tier 1 Remediation: FAILED - not running as Administrator/SYSTEM. Check Intune script configuration (Run as: System, 64-bit)."
    exit 1
}

$applied = @()
$failed = @()
$skipped = @()

# Helper: safely set a registry value, creating the path if needed
function Set-HardenedValue {
    param(
        [string]$Id,
        [string]$Path,
        [string]$Name,
        [int]$Value,
        [int]$ExpectedValue = $Value
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop

        # Verify
        $check = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        if ($check.$Name -eq $ExpectedValue) {
            $script:applied += $Id
        } else {
            $script:failed += "$Id (written but verification failed - GPO override?)"
        }
    } catch {
        $script:failed += "$Id ($_)"
    }
}

# ============================================================================
#  TIER 1 FIXES
# ============================================================================

# ---- MEMORY RESIDUE ----

# Disable Fast Startup
$hiberboot = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -EA SilentlyContinue
if ($hiberboot -and $hiberboot.HiberbootEnabled -eq 1) {
    Set-HardenedValue -Id 'fast-startup' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' `
        -Name 'HiberbootEnabled' -Value 0
} else { $skipped += 'fast-startup (already compliant)' }

# Disable Crash Dumps
$crashDump = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name CrashDumpEnabled -EA SilentlyContinue
if ($crashDump -and $crashDump.CrashDumpEnabled -ne 0) {
    Set-HardenedValue -Id 'crash-dump' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' `
        -Name 'CrashDumpEnabled' -Value 0
} else { $skipped += 'crash-dump (already compliant)' }

# Disable NMI Crash Dumps
$nmi = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name NMICrashDump -EA SilentlyContinue
if ($nmi -and $nmi.NMICrashDump -ne 0) {
    Set-HardenedValue -Id 'nmi-dump' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' `
        -Name 'NMICrashDump' -Value 0
} else { $skipped += 'nmi-dump (already compliant)' }

# Clear Pagefile at Shutdown
$pf = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -EA SilentlyContinue
if (-not $pf -or $pf.ClearPageFileAtShutdown -ne 1) {
    Set-HardenedValue -Id 'clear-pagefile' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' `
        -Name 'ClearPageFileAtShutdown' -Value 1
} else { $skipped += 'clear-pagefile (already compliant)' }

# Keep Kernel in RAM (disable paging executive)
$kp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name DisablePagingExecutive -EA SilentlyContinue
if (-not $kp -or $kp.DisablePagingExecutive -ne 1) {
    Set-HardenedValue -Id 'kernel-paging' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' `
        -Name 'DisablePagingExecutive' -Value 1
} else { $skipped += 'kernel-paging (already compliant)' }

# ---- ACCESS CONTROL ----

# Disable RDP
$rdp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue
if ($rdp -and $rdp.fDenyTSConnections -eq 0) {
    Set-HardenedValue -Id 'rdp' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
        -Name 'fDenyTSConnections' -Value 1
} else { $skipped += 'rdp (already compliant)' }

# Disable Auto-Logon
$al = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -EA SilentlyContinue
if ($al -and $al.AutoAdminLogon -eq '1') {
    Set-HardenedValue -Id 'auto-logon' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
        -Name 'AutoAdminLogon' -Value 0
    # M-4 FIX: Clear all stored auto-logon credentials, not just DefaultPassword.
    # DefaultUserName and DefaultDomainName are also information leaks.
    try {
        $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        foreach ($credProp in @('DefaultPassword', 'DefaultUserName', 'DefaultDomainName')) {
            $existing = Get-ItemProperty -Path $winlogonPath -Name $credProp -EA SilentlyContinue
            if ($existing -and $existing.$credProp) {
                Remove-ItemProperty -Path $winlogonPath -Name $credProp -Force -EA Stop
            }
        }
    } catch {}
} else { $skipped += 'auto-logon (already compliant)' }

# Disable ARSO
$arso = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DisableAutomaticRestartSignOn -EA SilentlyContinue
if (-not $arso -or $arso.DisableAutomaticRestartSignOn -ne 1) {
    Set-HardenedValue -Id 'arso' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'DisableAutomaticRestartSignOn' -Value 1
} else { $skipped += 'arso (already compliant)' }

# Require Password for UAC Elevation
$uac = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -EA SilentlyContinue
if ($uac -and $uac.ConsentPromptBehaviorAdmin -notin @(1, 3)) {
    Set-HardenedValue -Id 'uac-credential-prompt' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'ConsentPromptBehaviorAdmin' -Value 1
} else { $skipped += 'uac-credential-prompt (already compliant)' }

# ---- DATA EXPOSURE SURFACE ----

# Disable Activity History (3 registry values)
$af = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableActivityFeed -EA SilentlyContinue
if (-not $af -or $af.EnableActivityFeed -ne 0) {
    $timelinePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    try {
        if (-not (Test-Path $timelinePath)) { New-Item -Path $timelinePath -Force | Out-Null }
        Set-ItemProperty -Path $timelinePath -Name 'EnableActivityFeed' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $timelinePath -Name 'PublishUserActivities' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $timelinePath -Name 'UploadUserActivities' -Value 0 -Type DWord -Force
        # Verify first value as representative
        $check = Get-ItemProperty -Path $timelinePath -Name EnableActivityFeed -EA Stop
        if ($check.EnableActivityFeed -eq 0) { $applied += 'fs-timeline' }
        else { $failed += 'fs-timeline (verification failed)' }
    } catch { $failed += "fs-timeline ($_)" }
} else { $skipped += 'fs-timeline (already compliant)' }

# Disable Prefetch
$pfe = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -EA SilentlyContinue
if ($pfe -and $pfe.EnablePrefetcher -ne 0) {
    Set-HardenedValue -Id 'fs-prefetch' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' `
        -Name 'EnablePrefetcher' -Value 0
} else { $skipped += 'fs-prefetch (already compliant)' }

# ---- v0.50: PHYSICAL ACCESS HARDENING ----

# Locale-independent helpers (Intune scripts are standalone)
function Get-HT-SecurityPolicy {
    $tmp = Join-Path $env:TEMP "ht_secpol_$(Get-Random).cfg"
    try {
        # Try merged (effective) policy — ground truth on domain machines
        $null = secedit /export /mergedpolicy /cfg $tmp /quiet 2>&1
        if (-not (Test-Path $tmp)) {
            # Fallback: local-only export
            $null = secedit /export /cfg $tmp /quiet 2>&1
        }
        if (-not (Test-Path $tmp)) { return @{} }
        $pol = @{}
        foreach ($line in (Get-Content $tmp -EA SilentlyContinue)) {
            if ($line -match '^(\w+)\s*=\s*(.+)$') { $pol[$matches[1].Trim()] = $matches[2].Trim() }
        }
        return $pol
    } catch { return @{} }
    finally { Remove-Item $tmp -Force -EA SilentlyContinue }
}

function Get-HT-PowerValue {
    param([string]$Sub, [string]$Set)
    try {
        $scheme = powercfg /getactivescheme 2>&1 | Out-String
        if ($scheme -notmatch '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') { return $null }
        $out = powercfg /query $matches[1] $Sub $Set 2>&1 | Out-String
        $hexVals = [regex]::Matches($out, ':\s+0x([0-9a-fA-F]+)') | ForEach-Object { [Convert]::ToInt32($_.Groups[1].Value, 16) }
        if ($hexVals.Count -ge 5) { return @{ AC = $hexVals[3]; DC = $hexVals[4] } }
        elseif ($hexVals.Count -ge 4) { return @{ AC = $hexVals[3]; DC = $null } }
        return $null
    } catch { return $null }
}

# Disable Wake Timers (via powercfg on active scheme)
try {
    $wtResult = Get-HT-PowerValue -Sub '238c9fa8-0aad-41ed-83f4-97be242c8f20' -Set 'bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d'
    if ($wtResult -and $wtResult.AC -gt 0) {
        $scheme = powercfg /getactivescheme 2>&1 | Out-String
        if ($scheme -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') {
            $sg = $matches[1]
            powercfg /setacvalueindex $sg 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0
            powercfg /setdcvalueindex $sg 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0
            powercfg /setactive $sg
            $applied += 'wake-timers'
        }
    } else { $skipped += 'wake-timers (already compliant)' }
} catch { $failed += "wake-timers ($_)" }

# Screen Timeout: set 5min AC / 3min DC
try {
    $stResult = Get-HT-PowerValue -Sub '7516b95f-f776-4464-8c53-06167f40cc99' -Set '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e'
    if ($stResult -and ($stResult.AC -eq 0 -or $stResult.AC -gt 300)) {
        powercfg /change monitor-timeout-ac 5
        powercfg /change monitor-timeout-dc 3
        $applied += 'screen-timeout'
    } else { $skipped += 'screen-timeout (already compliant)' }
} catch { $failed += "screen-timeout ($_)" }

# Disable Built-in Administrator
try {
    $admin = Get-LocalUser -Name 'Administrator' -EA SilentlyContinue
    if ($admin -and $admin.Enabled) {
        Disable-LocalUser -Name 'Administrator' -EA Stop
        $check = Get-LocalUser -Name 'Administrator' -EA Stop
        if (-not $check.Enabled) { $applied += 'builtin-admin' }
        else { $failed += 'builtin-admin (still enabled)' }
    } else { $skipped += 'builtin-admin (already compliant)' }
} catch { $failed += "builtin-admin ($_)" }

# Account Lockout Policy (v0.50: secedit for detection, net accounts for setting)
try {
    $secPol = Get-HT-SecurityPolicy
    $thresh = if ($secPol.ContainsKey('LockoutBadCount')) { [int]$secPol['LockoutBadCount'] } else { 0 }
    if ($thresh -eq 0) {
        net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 2>&1 | Out-Null
        $secPolCheck = Get-HT-SecurityPolicy
        $newThresh = if ($secPolCheck.ContainsKey('LockoutBadCount')) { [int]$secPolCheck['LockoutBadCount'] } else { 0 }
        if ($newThresh -gt 0) {
            $applied += 'account-lockout'
        } else { $failed += 'account-lockout (verification failed)' }
    } else { $skipped += 'account-lockout (already compliant)' }
} catch { $failed += "account-lockout ($_)" }

# Password Minimum Length (v0.50: secedit for detection, net accounts for setting)
try {
    if (-not $secPol) { $secPol = Get-HT-SecurityPolicy }
    $minLen = if ($secPol.ContainsKey('MinimumPasswordLength')) { [int]$secPol['MinimumPasswordLength'] } else { 0 }
    if ($minLen -lt 8) {
        net accounts /minpwlen:8 /uniquepw:5 2>&1 | Out-Null
        $secPolCheck = Get-HT-SecurityPolicy
        $newLen = if ($secPolCheck.ContainsKey('MinimumPasswordLength')) { [int]$secPolCheck['MinimumPasswordLength'] } else { 0 }
        if ($newLen -ge 8) {
            $applied += 'password-policy'
        } else { $failed += 'password-policy (verification failed)' }
    } else { $skipped += 'password-policy (already compliant)' }
} catch { $failed += "password-policy ($_)" }

# Require Ctrl+Alt+Del
$cadReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DisableCAD -EA SilentlyContinue
if ($cadReg -and $cadReg.DisableCAD -eq 1) {
    Set-HardenedValue -Id 'ctrl-alt-del' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'DisableCAD' -Value 0
} else { $skipped += 'ctrl-alt-del (already compliant)' }

# Hide Last Username
$luReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DontDisplayLastUserName -EA SilentlyContinue
if (-not $luReg -or $luReg.DontDisplayLastUserName -ne 1) {
    Set-HardenedValue -Id 'last-username' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'DontDisplayLastUserName' -Value 1
} else { $skipped += 'last-username (already compliant)' }

# Disable AutoRun
$arReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -EA SilentlyContinue
if (-not $arReg -or $arReg.NoDriveTypeAutoRun -lt 255) {
    Set-HardenedValue -Id 'autorun' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name 'NoDriveTypeAutoRun' -Value 255
} else { $skipped += 'autorun (already compliant)' }

# Enable Enhanced BitLocker PIN
$epReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name UseEnhancedPin -EA SilentlyContinue
if (-not $epReg -or $epReg.UseEnhancedPin -ne 1) {
    Set-HardenedValue -Id 'enhanced-pin' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' `
        -Name 'UseEnhancedPin' -Value 1
} else { $skipped += 'enhanced-pin (already compliant)' }

# Disable WinRM
try {
    $svc = Get-Service WinRM -EA SilentlyContinue
    if ($svc -and ($svc.Status -eq 'Running' -or $svc.StartType -ne 'Disabled')) {
        if ($svc.Status -eq 'Running') { Stop-Service WinRM -Force -EA Stop }
        Set-Service WinRM -StartupType Disabled -EA Stop
        $svcCheck = Get-Service WinRM -EA Stop
        if ($svcCheck.StartType -eq 'Disabled') { $applied += 'winrm' }
        else { $failed += 'winrm (still enabled)' }
    } else { $skipped += 'winrm (already compliant)' }
} catch { $failed += "winrm ($_)" }

# ============================================================================
#  RESULT
# ============================================================================

# Write to local event log for audit trail
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists('HardTarget')) {
        New-EventLog -LogName Application -Source 'HardTarget' -EA SilentlyContinue
    }
    $msg = "HardTarget Intune Remediation (Tier 1)`n"
    $msg += "Applied: $($applied.Count) ($($applied -join ', '))`n"
    $msg += "Failed: $($failed.Count) ($($failed -join ', '))`n"
    $msg += "Skipped: $($skipped.Count)"
    Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9010 -EntryType Information -Message $msg -EA SilentlyContinue
} catch {}

# Output for Intune portal (visible in Proactive Remediations > Device status)
$summary = "Applied: $($applied.Count)"
if ($failed.Count -gt 0) { $summary += " | Failed: $($failed.Count) ($($failed -join '; '))" }
if ($skipped.Count -gt 0) { $summary += " | Already compliant: $($skipped.Count)" }
Write-Output "HardTarget Tier 1 Remediation: $summary"

if ($failed.Count -gt 0) {
    exit 1
} else {
    exit 0
}
