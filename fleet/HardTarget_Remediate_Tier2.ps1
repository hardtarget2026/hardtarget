# ============================================================================
#  HardTarget Intune Integration - Remediation Script
#  Proactive Remediation: Advanced Hardening (Tier 2 - Reboot Required)
# ============================================================================
#
#  SPDX-License-Identifier: BUSL-1.1
#  Copyright (c) 2026 HardTarget Contributors. All rights reserved.
#
#  PURPOSE: Applies Tier 2 registry fixes. These require a reboot to take
#  effect. The script writes the registry values and exits. Reboot is
#  handled by Intune restart policy (not forced by this script).
#
#  NOTE: VBS and HVCI may fail to activate on hardware that lacks support.
#  Detection script checks RUNNING state, so non-compliance will persist
#  until a reboot confirms whether the hardware supports the feature.
#  After reboot, if the feature still isn't running, the detection script
#  will continue to report non-compliant. At that point the Intune admin
#  should exclude those devices from this remediation.
# ============================================================================

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# M-8 FIX: Verify we're running elevated (SYSTEM or admin).
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) {
    Write-Output "HardTarget Tier 2 Remediation: FAILED - not running as Administrator/SYSTEM. Check Intune script configuration (Run as: System, 64-bit)."
    exit 1
}

$applied = @()
$failed = @()
$skipped = @()

function Set-HardenedValue {    param([string]$Id, [string]$Path, [string]$Name, [int]$Value)
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
        $check = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        if ($check.$Name -eq $Value) {
            $script:applied += "$Id (pending reboot)"
        } else {
            $script:failed += "$Id (write failed - GPO override?)"
        }
    } catch {
        $script:failed += "$Id ($_)"
    }
}

# ============================================================================
#  TIER 2 FIXES (all require reboot)
# ============================================================================

# Modern Standby override (v0.50: registry-based, locale-independent)
$aoac = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name PlatformAoAcOverride -EA SilentlyContinue
if (-not $aoac -or $aoac.PlatformAoAcOverride -ne 0) {
    # Only apply if CsEnabled=1 (hardware supports Modern Standby)
    $csCheck = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name CsEnabled -EA SilentlyContinue
    if ($csCheck -and $csCheck.CsEnabled -eq 1) {
        Set-HardenedValue -Id 'platform-aoac' `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' `
            -Name 'PlatformAoAcOverride' -Value 0
    } else { $skipped += 'platform-aoac (S0 not available)' }
} else { $skipped += 'platform-aoac (already set)' }

# Connected Standby
$cs = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name CsEnabled -EA SilentlyContinue
if ($cs -and $cs.CsEnabled -eq 1) {
    Set-HardenedValue -Id 'cs-enabled' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' `
        -Name 'CsEnabled' -Value 0
} else { $skipped += 'cs-enabled (already compliant)' }

# M-2 FIX: Query DeviceGuard once and reuse for VBS and HVCI
$dgInstance = $null
try {
    $dgInstance = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -EA Stop
} catch {}

# VBS
if ($dgInstance -and $dgInstance.VirtualizationBasedSecurityStatus -ne 2) {
    Set-HardenedValue -Id 'vbs' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
        -Name 'EnableVirtualizationBasedSecurity' -Value 1
} else { $skipped += 'vbs (already running or unavailable)' }

# HVCI
if ($dgInstance) {
    $hvci = $dgInstance.SecurityServicesRunning -contains 2
    if (-not $hvci) {
        $hvciPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
        Set-HardenedValue -Id 'hvci' -Path $hvciPath -Name 'Enabled' -Value 1
    } else { $skipped += 'hvci (already running)' }
} else { $skipped += 'hvci (DeviceGuard unavailable)' }

# DMA Guard (only if DMA ports present)
# M-3 FIX: Unified DMA port detection matching scanner logic
try {
    $hasDMA = $false
    $dmaDevices = Get-PnpDevice -EA SilentlyContinue | Where-Object {
        $_.FriendlyName -match 'Thunderbolt|USB4|1394|FireWire' -or
        $_.Class -eq 'Thunderbolt' -or
        $_.InstanceId -match 'PCI.*Thunderbolt'
    }
    if ($dmaDevices) { $hasDMA = $true }

    if ($hasDMA) {
        $dmaP = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' -Name DeviceEnumerationPolicy -EA SilentlyContinue
        if (-not $dmaP -or $dmaP.DeviceEnumerationPolicy -ne 0) {
            Set-HardenedValue -Id 'dma-guard' `
                -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' `
                -Name 'DeviceEnumerationPolicy' -Value 0
        } else { $skipped += 'dma-guard (already set)' }
    } else { $skipped += 'dma-guard (no DMA ports)' }
} catch { $skipped += 'dma-guard (detection failed)' }

# ---- v0.50: Tier 2 additions ----

# LSA Protection (RunAsPPL) - reboot required
$lsaReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -EA SilentlyContinue
if (-not $lsaReg -or $lsaReg.RunAsPPL -lt 1) {
    Set-HardenedValue -Id 'lsa-protection' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'RunAsPPL' -Value 1
} else { $skipped += 'lsa-protection (already set)' }

# BitLocker Network Unlock disable - reboot required
$nkpReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name OSManageNKP -EA SilentlyContinue
if ($nkpReg -and $nkpReg.OSManageNKP -eq 1) {
    Set-HardenedValue -Id 'bl-network-unlock' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' `
        -Name 'OSManageNKP' -Value 0
} else { $skipped += 'bl-network-unlock (already compliant)' }

# ============================================================================
#  RESULT
# ============================================================================

try {
    if (-not [System.Diagnostics.EventLog]::SourceExists('HardTarget')) {
        New-EventLog -LogName Application -Source 'HardTarget' -EA SilentlyContinue
    }
    $msg = "HardTarget Intune Remediation (Tier 2 - Reboot Required)`n"
    $msg += "Applied: $($applied.Count) ($($applied -join ', '))`n"
    $msg += "Failed: $($failed.Count) ($($failed -join ', '))`n"
    $msg += "Skipped: $($skipped.Count)`n"
    $msg += "NOTE: Changes require reboot to take effect."
    Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9011 -EntryType Information -Message $msg -EA SilentlyContinue
} catch {}

$summary = "Applied: $($applied.Count)"
if ($applied.Count -gt 0) { $summary += " (REBOOT REQUIRED)" }
if ($failed.Count -gt 0) { $summary += " | Failed: $($failed.Count) ($($failed -join '; '))" }
Write-Output "HardTarget Tier 2 Remediation: $summary"

if ($failed.Count -gt 0) { exit 1 } else { exit 0 }
