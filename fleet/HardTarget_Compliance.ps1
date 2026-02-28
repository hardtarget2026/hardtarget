# ============================================================================
#  HardTarget Intune Custom Compliance - Discovery Script
# ============================================================================
#
#  This replaces the collection pipeline. Intune runs this script on each
#  endpoint, stores the JSON result, evaluates compliance rules against it,
#  and exposes everything via Graph API.
#
#  No blob. No file share. No extra infrastructure.
#
#  INTUNE SETUP:
#    Devices > Compliance > Scripts > Add (Windows 10 and later)
#    Upload this script. Then create a compliance policy that references it.
#
#  OUTPUT: JSON object with flat key-value pairs that Intune evaluates.
# ============================================================================

# H-4 FIX: Do NOT use global SilentlyContinue. Wrap each check explicitly
# so failures are tracked rather than silently producing compliant results.
$ErrorActionPreference = 'Stop'

$result = @{}
$checkErrors = @()

# Derive trusted paths from shell API (consistent with HardTarget.ps1 v0.83)
$TrustedSystemRoot = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::Windows)
if (-not $TrustedSystemRoot) { $TrustedSystemRoot = 'C:\Windows' }
$TrustedSystemDrive = $TrustedSystemRoot.Substring(0, 2)

# ---- SLEEP / POWER STATE ----

try {
    # v0.50: Registry-based S0 detection (locale-independent)
    $csReg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name CsEnabled -EA SilentlyContinue
    $aoac = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name PlatformAoAcOverride -EA SilentlyContinue
    $s0Capable = ($csReg -and $csReg.CsEnabled -eq 1)
    $result['S0_Active'] = $s0Capable -and (-not $aoac -or $aoac.PlatformAoAcOverride -ne 0)
} catch { $result['S0_Active'] = 'ERROR'; $checkErrors += "S0_Active: $_" }

try {
    $result['ConnectedStandby'] = [bool]($csReg -and $csReg.CsEnabled -eq 1)
} catch { $result['ConnectedStandby'] = 'ERROR'; $checkErrors += "ConnectedStandby: $_" }

try {
    $hb = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -EA SilentlyContinue
    $result['FastStartup'] = [bool]($hb -and $hb.HiberbootEnabled -eq 1)
} catch { $result['FastStartup'] = 'ERROR'; $checkErrors += "FastStartup: $_" }

try {
    $hibFile = Test-Path "$TrustedSystemDrive\hiberfil.sys"
    $result['Hibernate'] = $hibFile
} catch { $result['Hibernate'] = 'ERROR'; $checkErrors += "Hibernate: $_" }

# ---- MEMORY RESIDUE ----

try {
    $cd = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name CrashDumpEnabled -EA SilentlyContinue
    $result['CrashDumps'] = [bool]($cd -and $cd.CrashDumpEnabled -ne 0)
} catch { $result['CrashDumps'] = 'ERROR'; $checkErrors += "CrashDumps: $_" }

try {
    $nmi = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name NMICrashDump -EA SilentlyContinue
    $result['NMIDumps'] = [bool]($nmi -and $nmi.NMICrashDump -ne 0)
} catch { $result['NMIDumps'] = 'ERROR'; $checkErrors += "NMIDumps: $_" }

try {
    $pf = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -EA SilentlyContinue
    $result['PagefileClearedAtShutdown'] = [bool]($pf -and $pf.ClearPageFileAtShutdown -eq 1)
} catch { $result['PagefileClearedAtShutdown'] = 'ERROR'; $checkErrors += "PagefileClearedAtShutdown: $_" }

try {
    $kp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name DisablePagingExecutive -EA SilentlyContinue
    $result['KernelInRAM'] = [bool]($kp -and $kp.DisablePagingExecutive -eq 1)
} catch { $result['KernelInRAM'] = 'ERROR'; $checkErrors += "KernelInRAM: $_" }

# ---- DMA / VIRTUALIZATION ----

try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -EA Stop
    $result['VBS_Running'] = [bool]($dg -and $dg.VirtualizationBasedSecurityStatus -eq 2)
    $result['HVCI_Running'] = [bool]($dg -and ($dg.SecurityServicesRunning -contains 2))
    $result['CredentialGuard_Running'] = [bool]($dg -and ($dg.SecurityServicesRunning -contains 1))
} catch {
    $result['VBS_Running'] = 'ERROR'; $checkErrors += "VBS_Running: $_"
    $result['HVCI_Running'] = 'ERROR'; $checkErrors += "HVCI_Running: $_"
    $result['CredentialGuard_Running'] = 'ERROR'; $checkErrors += "CredentialGuard_Running: $_"
}

try {
    $dmaP = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' -Name DeviceEnumerationPolicy -EA SilentlyContinue
    $result['DMAGuard'] = [bool]($dmaP -and $dmaP.DeviceEnumerationPolicy -eq 0)
} catch { $result['DMAGuard'] = 'ERROR'; $checkErrors += "DMAGuard: $_" }

try {
    # M-3 FIX: Unified DMA port detection matching scanner logic
    $tb = Get-PnpDevice -EA SilentlyContinue | Where-Object {
        $_.FriendlyName -match 'Thunderbolt|USB4|1394|FireWire' -or
        $_.Class -eq 'Thunderbolt' -or
        $_.InstanceId -match 'PCI.*Thunderbolt'
    }
    $result['HasDMAPorts'] = [bool]$tb
} catch { $result['HasDMAPorts'] = 'ERROR'; $checkErrors += "HasDMAPorts: $_" }

# ---- ACCESS CONTROL ----

try {
    $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue
    $result['RDP_Disabled'] = [bool]($rdp -and $rdp.fDenyTSConnections -eq 1)
} catch { $result['RDP_Disabled'] = 'ERROR'; $checkErrors += "RDP_Disabled: $_" }

try {
    $al = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -EA SilentlyContinue
    $result['AutoLogon_Disabled'] = [bool](-not $al -or $al.AutoAdminLogon -ne '1')
} catch { $result['AutoLogon_Disabled'] = 'ERROR'; $checkErrors += "AutoLogon_Disabled: $_" }

try {
    $arso = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DisableAutomaticRestartSignOn -EA SilentlyContinue
    $result['ARSO_Disabled'] = [bool]($arso -and $arso.DisableAutomaticRestartSignOn -eq 1)
} catch { $result['ARSO_Disabled'] = 'ERROR'; $checkErrors += "ARSO_Disabled: $_" }

try {
    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -EA SilentlyContinue
    $result['UAC_RequiresPassword'] = [bool]($uac -and $uac.ConsentPromptBehaviorAdmin -in @(1, 3))
} catch { $result['UAC_RequiresPassword'] = 'ERROR'; $checkErrors += "UAC_RequiresPassword: $_" }

# ---- ENCRYPTION ----

try {
    $bl = Get-BitLockerVolume -MountPoint $TrustedSystemDrive -EA Stop
    $result['BitLocker_On'] = [bool]($bl -and $bl.ProtectionStatus -eq 'On')
    $result['BitLocker_HasPIN'] = [bool]($bl -and ($bl.KeyProtector | Where-Object { $_.KeyProtectorType -match 'Tpm.*Pin' }))
} catch {
    $result['BitLocker_On'] = 'ERROR'; $checkErrors += "BitLocker_On: $_"
    $result['BitLocker_HasPIN'] = 'ERROR'; $checkErrors += "BitLocker_HasPIN: $_"
}

try {
    $sb = Confirm-SecureBootUEFI -EA Stop
    $result['SecureBoot'] = [bool]$sb
} catch { $result['SecureBoot'] = 'ERROR'; $checkErrors += "SecureBoot: $_" }

# ---- v0.50: Locale-independent helpers (Intune scripts are standalone) ----

# secedit exports INI with fixed English keys regardless of OS language
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

# powercfg /query labels are localized but hex values always follow ": 0x" pattern
# For a single setting query, order is: min, max, increment, AC, DC
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

# ---- SLEEP / POWER (continued) ----

try {
    $wtResult = Get-HT-PowerValue -Sub '238c9fa8-0aad-41ed-83f4-97be242c8f20' -Set 'bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d'
    $result['WakeTimers_Disabled'] = [bool](-not $wtResult -or $wtResult.AC -eq 0)
} catch { $result['WakeTimers_Disabled'] = 'ERROR'; $checkErrors += "WakeTimers_Disabled: $_" }

# ---- ACCESS CONTROL (v0.50 additions) ----

try {
    $stResult = Get-HT-PowerValue -Sub '7516b95f-f776-4464-8c53-06167f40cc99' -Set '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e'
    $stCompliant = $false
    if ($stResult) {
        $stCompliant = ($stResult.AC -gt 0 -and $stResult.AC -le 300)
    }
    $result['ScreenTimeout_Compliant'] = $stCompliant
} catch { $result['ScreenTimeout_Compliant'] = 'ERROR'; $checkErrors += "ScreenTimeout_Compliant: $_" }

try {
    $builtinAdmin = Get-LocalUser -Name 'Administrator' -EA SilentlyContinue
    $result['BuiltinAdmin_Disabled'] = [bool]($builtinAdmin -and -not $builtinAdmin.Enabled)
} catch { $result['BuiltinAdmin_Disabled'] = 'ERROR'; $checkErrors += "BuiltinAdmin_Disabled: $_" }

try {
    $secPol = Get-HT-SecurityPolicy
    $lockThreshold = if ($secPol.ContainsKey('LockoutBadCount')) { [int]$secPol['LockoutBadCount'] } else { 0 }
    $result['AccountLockout_Set'] = [bool]($lockThreshold -gt 0)
} catch { $result['AccountLockout_Set'] = 'ERROR'; $checkErrors += "AccountLockout_Set: $_" }

try {
    if (-not $secPol) { $secPol = Get-HT-SecurityPolicy }
    $minPwLen = if ($secPol.ContainsKey('MinimumPasswordLength')) { [int]$secPol['MinimumPasswordLength'] } else { 0 }
    $result['PasswordMinLength'] = $minPwLen
} catch { $result['PasswordMinLength'] = 0; $checkErrors += "PasswordMinLength: $_" }

try {
    $cadReg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DisableCAD -EA SilentlyContinue
    $result['CtrlAltDel_Required'] = [bool](-not $cadReg -or $cadReg.DisableCAD -ne 1)
} catch { $result['CtrlAltDel_Required'] = 'ERROR'; $checkErrors += "CtrlAltDel_Required: $_" }

try {
    $luReg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DontDisplayLastUserName -EA SilentlyContinue
    $result['LastUsername_Hidden'] = [bool]($luReg -and $luReg.DontDisplayLastUserName -eq 1)
} catch { $result['LastUsername_Hidden'] = 'ERROR'; $checkErrors += "LastUsername_Hidden: $_" }

try {
    $lsaReg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -EA SilentlyContinue
    $result['LSAProtection_Enabled'] = [bool]($lsaReg -and $lsaReg.RunAsPPL -ge 1)
} catch { $result['LSAProtection_Enabled'] = 'ERROR'; $checkErrors += "LSAProtection_Enabled: $_" }

try {
    $arReg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -EA SilentlyContinue
    $result['AutoRun_Disabled'] = [bool]($arReg -and $arReg.NoDriveTypeAutoRun -ge 255)
} catch { $result['AutoRun_Disabled'] = 'ERROR'; $checkErrors += "AutoRun_Disabled: $_" }

try {
    $epReg = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name UseEnhancedPin -EA SilentlyContinue
    $result['EnhancedPIN_Enabled'] = [bool]($epReg -and $epReg.UseEnhancedPin -eq 1)
} catch { $result['EnhancedPIN_Enabled'] = 'ERROR'; $checkErrors += "EnhancedPIN_Enabled: $_" }

try {
    $winrmSvc = Get-Service WinRM -EA SilentlyContinue
    $result['WinRM_Disabled'] = [bool](-not $winrmSvc -or ($winrmSvc.Status -ne 'Running' -and $winrmSvc.StartType -eq 'Disabled'))
} catch { $result['WinRM_Disabled'] = 'ERROR'; $checkErrors += "WinRM_Disabled: $_" }

try {
    $bcdOut = bcdedit /enum 2>&1 | Out-String
    $result['KernelDebug_Disabled'] = [bool]($bcdOut -notmatch '(?m)^\s*debug\s')
} catch { $result['KernelDebug_Disabled'] = 'ERROR'; $checkErrors += "KernelDebug_Disabled: $_" }

try {
    $bcdOut2 = bcdedit /enum 2>&1 | Out-String
    $result['TestSigning_Disabled'] = [bool]($bcdOut2 -notmatch '(?m)^\s*testsigning\s')
} catch { $result['TestSigning_Disabled'] = 'ERROR'; $checkErrors += "TestSigning_Disabled: $_" }

try {
    $nkpReg = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name OSManageNKP -EA SilentlyContinue
    $result['BLNetworkUnlock_Disabled'] = [bool](-not $nkpReg -or $nkpReg.OSManageNKP -ne 1)
} catch { $result['BLNetworkUnlock_Disabled'] = 'ERROR'; $checkErrors += "BLNetworkUnlock_Disabled: $_" }

# ---- FORENSIC SURFACE ----

try {
    $af = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableActivityFeed -EA SilentlyContinue
    $result['ActivityHistory_Disabled'] = [bool]($af -and $af.EnableActivityFeed -eq 0)
} catch { $result['ActivityHistory_Disabled'] = 'ERROR'; $checkErrors += "ActivityHistory_Disabled: $_" }

try {
    $pfe = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -EA SilentlyContinue
    $result['Prefetch_Disabled'] = [bool]($pfe -and $pfe.EnablePrefetcher -eq 0)
} catch { $result['Prefetch_Disabled'] = 'ERROR'; $checkErrors += "Prefetch_Disabled: $_" }

# ---- METADATA ----

$result['ScanTime'] = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
$result['HardTargetVersion'] = '0.83'
$result['_deviceName'] = $env:COMPUTERNAME
try { $result['OS'] = (Get-CimInstance Win32_OperatingSystem -EA Stop).Caption } catch { $result['OS'] = 'Unknown' }
try { $result['Edition'] = (Get-WindowsEdition -Online -EA Stop).Edition } catch { $result['Edition'] = 'Unknown' }

# H-4 FIX: Track check errors so compliance policy can fail on incomplete scans
$result['CheckErrors'] = $checkErrors.Count
if ($checkErrors.Count -gt 0) {
    $result['CheckErrorDetails'] = ($checkErrors -join '; ').Substring(0, [Math]::Min(($checkErrors -join '; ').Length, 500))
}

$result | ConvertTo-Json -Compress
