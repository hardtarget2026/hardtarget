# ============================================================================
#  HardTarget Intune Integration - Detection Script
#  Proactive Remediation: Physical Security Baseline (Tier 1)
# ============================================================================
#
#  SPDX-License-Identifier: BUSL-1.1
#  Copyright (c) 2026 HardTarget Contributors. All rights reserved.
#
#  PURPOSE: Detects non-compliant physical security settings that are safe
#  for unattended remote remediation (Tier 1 fixes only).
#
#  INTUNE SETUP:
#    Proactive Remediations > Create > Custom
#    Detection script:    HardTarget_Detect.ps1 (this file)
#    Remediation script:  HardTarget_Remediate.ps1
#    Run as:              System (64-bit)
#    Schedule:            Daily
#
#  EXIT CODES:
#    0 = Compliant (all Tier 1 checks pass)
#    1 = Non-compliant (one or more Tier 1 checks fail, remediation needed)
#
#  TIER 1 (safe for silent remote push):
#    Registry writes, powercfg, net accounts, service disable. No boot impact,
#    fully reversible, no user-facing disruption.
#
#  CHECKS (21):
#    fast-startup, crash-dump, nmi-dump, clear-pagefile, kernel-paging,
#    rdp, auto-logon, arso, uac-credential-prompt, fs-timeline, fs-prefetch,
#    wake-timers, screen-timeout, builtin-admin, account-lockout,
#    password-policy, ctrl-alt-del, last-username, autorun, enhanced-pin, winrm
#
#  EXCLUDED from remote remediation:
#    - Tier 2 (reboot required: Modern Standby, VBS, HVCI, DMA Guard)
#    - Tier 3 (destructive/judgment: WinRE, Credential Guard, hibernation)
#    - Anything that requires bcdedit or reagentc
#    - Anything edition-dependent
# ============================================================================

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$findings = @()

# ---- MEMORY RESIDUE ----

# Fast Startup
try {
    $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -EA SilentlyContinue
    if ($val -and $val.HiberbootEnabled -eq 1) {
        $findings += 'fast-startup'
    }
} catch {}

# Crash Dumps
try {
    $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name CrashDumpEnabled -EA SilentlyContinue
    if ($val -and $val.CrashDumpEnabled -ne 0) {
        $findings += 'crash-dump'
    }
} catch {}

# NMI Crash Dumps
try {
    $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name NMICrashDump -EA SilentlyContinue
    if ($val -and $val.NMICrashDump -ne 0) {
        $findings += 'nmi-dump'
    }
} catch {}

# Pagefile clearing
try {
    $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -EA SilentlyContinue
    if (-not $val -or $val.ClearPageFileAtShutdown -ne 1) {
        $findings += 'clear-pagefile'
    }
} catch {}

# Kernel paging
try {
    $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name DisablePagingExecutive -EA SilentlyContinue
    if (-not $val -or $val.DisablePagingExecutive -ne 1) {
        $findings += 'kernel-paging'
    }
} catch {}

# ---- ACCESS CONTROL ----

# RDP enabled
try {
    $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue
    if ($val -and $val.fDenyTSConnections -eq 0) {
        $findings += 'rdp'
    }
} catch {}

# Auto-logon
try {
    $val = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -EA SilentlyContinue
    if ($val -and $val.AutoAdminLogon -eq '1') {
        $findings += 'auto-logon'
    }
} catch {}

# ARSO
try {
    $val = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DisableAutomaticRestartSignOn -EA SilentlyContinue
    if (-not $val -or $val.DisableAutomaticRestartSignOn -ne 1) {
        $findings += 'arso'
    }
} catch {}

# UAC credential prompt (consent-only or silent = non-compliant)
try {
    $val = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -EA SilentlyContinue
    if ($val -and $val.ConsentPromptBehaviorAdmin -notin @(1, 3)) {
        $findings += 'uac-credential-prompt'
    }
} catch {}

# ---- DATA EXPOSURE SURFACE (Tier 1 subset: policy settings only) ----

# Activity History
try {
    $val = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableActivityFeed -EA SilentlyContinue
    if (-not $val -or $val.EnableActivityFeed -ne 0) {
        $findings += 'fs-timeline'
    }
} catch {}

# Prefetch
try {
    $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -EA SilentlyContinue
    if ($val -and $val.EnablePrefetcher -ne 0) {
        $findings += 'fs-prefetch'
    }
} catch {}

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

# Wake Timers
try {
    $wtResult = Get-HT-PowerValue -Sub '238c9fa8-0aad-41ed-83f4-97be242c8f20' -Set 'bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d'
    if ($wtResult -and $wtResult.AC -gt 0) {
        $findings += 'wake-timers'
    }
} catch {}

# Screen Timeout (AC > 5 min or disabled = non-compliant)
try {
    $stResult = Get-HT-PowerValue -Sub '7516b95f-f776-4464-8c53-06167f40cc99' -Set '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e'
    if ($stResult) {
        if ($stResult.AC -eq 0 -or $stResult.AC -gt 300) {
            $findings += 'screen-timeout'
        }
    }
} catch {}

# Built-in Administrator enabled
try {
    $admin = Get-LocalUser -Name 'Administrator' -EA SilentlyContinue
    if ($admin -and $admin.Enabled) {
        $findings += 'builtin-admin'
    }
} catch {}

# Account Lockout not set (v0.50: secedit, locale-independent)
try {
    $secPol = Get-HT-SecurityPolicy
    $thresh = if ($secPol.ContainsKey('LockoutBadCount')) { [int]$secPol['LockoutBadCount'] } else { 0 }
    if ($thresh -eq 0) { $findings += 'account-lockout' }
} catch {}

# Password minimum length < 8 (v0.50: secedit, locale-independent)
try {
    if (-not $secPol) { $secPol = Get-HT-SecurityPolicy }
    $minLen = if ($secPol.ContainsKey('MinimumPasswordLength')) { [int]$secPol['MinimumPasswordLength'] } else { 0 }
    if ($minLen -lt 8) { $findings += 'password-policy' }
} catch {}

# Ctrl+Alt+Del not required
try {
    $val = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DisableCAD -EA SilentlyContinue
    if ($val -and $val.DisableCAD -eq 1) {
        $findings += 'ctrl-alt-del'
    }
} catch {}

# Last username shown
try {
    $val = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DontDisplayLastUserName -EA SilentlyContinue
    if (-not $val -or $val.DontDisplayLastUserName -ne 1) {
        $findings += 'last-username'
    }
} catch {}

# AutoRun enabled
try {
    $val = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -EA SilentlyContinue
    if (-not $val -or $val.NoDriveTypeAutoRun -lt 255) {
        $findings += 'autorun'
    }
} catch {}

# Enhanced BitLocker PIN not enabled
try {
    $val = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name UseEnhancedPin -EA SilentlyContinue
    if (-not $val -or $val.UseEnhancedPin -ne 1) {
        $findings += 'enhanced-pin'
    }
} catch {}

# WinRM running or enabled
try {
    $svc = Get-Service WinRM -EA SilentlyContinue
    if ($svc -and ($svc.Status -eq 'Running' -or $svc.StartType -ne 'Disabled')) {
        $findings += 'winrm'
    }
} catch {}

# ---- RESULT ----

if ($findings.Count -eq 0) {
    Write-Output "HardTarget Tier 1: COMPLIANT (all checks pass)"
    exit 0
} else {
    # Output is visible in Intune Proactive Remediations > Device status > Detection output
    Write-Output "HardTarget Tier 1: NON-COMPLIANT ($($findings.Count) findings: $($findings -join ', '))"
    exit 1
}
