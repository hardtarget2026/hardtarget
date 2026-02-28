# ============================================================================
#  HardTarget Intune Integration - Detection Script
#  Proactive Remediation: Advanced Hardening (Tier 2 - Reboot Required)
# ============================================================================
#
#  SPDX-License-Identifier: BUSL-1.1
#  Copyright (c) 2026 HardTarget Contributors. All rights reserved.
#
#  PURPOSE: Detects Tier 2 non-compliance. These fixes write registry values
#  that take effect after reboot. Deploy alongside an Intune reboot grace
#  period policy so users get advance notice.
#
#  INTUNE SETUP:
#    Proactive Remediations > Create > Custom
#    Detection:    HardTarget_Detect_Tier2.ps1 (this file)
#    Remediation:  HardTarget_Remediate_Tier2.ps1
#    Run as:       System (64-bit)
#    Schedule:     Weekly (less frequent -- changes need reboot to verify)
#
#  IMPORTANT: Pair with a device restart policy:
#    Devices > Configuration > Restart > Grace period (e.g. 24h)
#    Or use Update Rings to schedule restarts.
#
#  TIER 2 FIXES (7):
#    - Modern Standby override (PlatformAoAcOverride)
#    - Connected Standby disable (CsEnabled)
#    - VBS enable (hardware-dependent)
#    - HVCI enable (driver-dependent)
#    - DMA Guard (IOMMU-dependent)
#    - LSA Protection / RunAsPPL (reboot required)
#    - BitLocker Network Unlock disable (reboot required)
#
#  EXCLUDED (Tier 3 - never remote):
#    - WinRE disable (reagentc -- needs recovery USB prepared)
#    - Credential Guard (Enterprise-only, breaks some SSO)
#    - Kernel debug / test signing (bcdedit -- boot chain risk)
#    - Hibernation disable (workflow-dependent)
# ============================================================================

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$findings = @()

# Modern Standby (S0) -- v0.50: registry-based, locale-independent
# CsEnabled=1 means hardware supports Modern Standby. Check if override is set.
try {
    $csReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name CsEnabled -EA SilentlyContinue
    if ($csReg -and $csReg.CsEnabled -eq 1) {
        $aoac = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name PlatformAoAcOverride -EA SilentlyContinue
        if (-not $aoac -or $aoac.PlatformAoAcOverride -ne 0) {
            $findings += 'platform-aoac'
        }
    }
} catch {}

# Connected Standby
try {
    $cs = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name CsEnabled -EA SilentlyContinue
    if ($cs -and $cs.CsEnabled -eq 1) {
        $findings += 'cs-enabled'
    }
} catch {}

# M-2 FIX: Query DeviceGuard once and reuse for both VBS and HVCI checks.
# Previously queried twice independently -- if first succeeded but second failed
# (transient WMI error), HVCI was silently skipped and appeared compliant.
$dgInstance = $null
try {
    $dgInstance = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -EA Stop
} catch {}

# VBS (check running state, not just registry)
if ($dgInstance) {
    if ($dgInstance.VirtualizationBasedSecurityStatus -ne 2) {
        $findings += 'vbs'
    }
} else {
    # Cannot determine VBS state -- report as non-compliant (fail-safe)
    $findings += 'vbs'
}

# HVCI
if ($dgInstance) {
    $hvci = $dgInstance.SecurityServicesRunning -contains 2
    if (-not $hvci) { $findings += 'hvci' }
} else {
    $findings += 'hvci'
}

# DMA Guard (only if DMA ports present)
# M-3 FIX: Unified DMA port detection matching scanner and compliance script logic.
# Previously filtered Thunderbolt by Class -eq 'USB', missing controllers that
# enumerate under 'Thunderbolt' class or PCI bus (common on newer hardware).
try {
    $dmaDevices = Get-PnpDevice -EA SilentlyContinue | Where-Object {
        $_.FriendlyName -match 'Thunderbolt|USB4|1394|FireWire' -or
        $_.Class -eq 'Thunderbolt' -or
        $_.InstanceId -match 'PCI.*Thunderbolt'
    }
    if ($dmaDevices) {
        $dmaP = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' -Name DeviceEnumerationPolicy -EA SilentlyContinue
        if (-not $dmaP -or $dmaP.DeviceEnumerationPolicy -ne 0) {
            $findings += 'dma-guard'
        }
    }
} catch {}

# ---- v0.50: Tier 2 additions ----

# LSA Protection (RunAsPPL) - reboot required to take effect
try {
    $lsaReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -EA SilentlyContinue
    if (-not $lsaReg -or $lsaReg.RunAsPPL -lt 1) {
        $findings += 'lsa-protection'
    }
} catch {}

# BitLocker Network Unlock - reboot required
try {
    $nkpReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name OSManageNKP -EA SilentlyContinue
    if ($nkpReg -and $nkpReg.OSManageNKP -eq 1) {
        $findings += 'bl-network-unlock'
    }
} catch {}

if ($findings.Count -eq 0) {
    Write-Output "HardTarget Tier 2: COMPLIANT"
    exit 0
} else {
    Write-Output "HardTarget Tier 2: NON-COMPLIANT ($($findings.Count) findings: $($findings -join ', '))"
    exit 1
}
