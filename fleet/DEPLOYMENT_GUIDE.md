# HardTarget Fleet — Intune Deployment Guide

## Architecture

```
Intune Admin Portal
  ├── Custom Compliance Script    → HardTarget_Compliance.ps1
  │     (runs on each device, returns posture JSON)
  │     (Intune stores results, evaluates rules, feeds Conditional Access)
  │
  ├── Proactive Remediation T1   → Detect + Remediate (daily, silent)
  ├── Proactive Remediation T2   → Detect + Remediate (weekly, reboot)
  │
  └── Fleet Dashboard            → fleet-dashboard.html
        (signs in via Entra, reads compliance results from Graph API)
```

No blob storage. No file shares. No collection scripts. Everything flows through Intune.

---

## Step 1: Register an Entra app (one time)

The dashboard needs an Entra app registration to query Graph API.

1. Azure Portal → Entra ID → App registrations → New registration
2. Name: `HardTarget Fleet Dashboard`
3. Supported account types: Single tenant
4. Redirect URI: `Single-page application (SPA)` → your dashboard URL (or `http://localhost` for local use)
5. After creation, note the **Application (client) ID** and **Tenant ID**
6. API permissions → Add → Microsoft Graph → Delegated:
   - `DeviceManagementConfiguration.Read.All`
7. Grant admin consent

---

## Step 2: Upload compliance script

1. Intune → Devices → Compliance → Scripts → Add (Windows 10 and later)
2. Name: `HardTarget Physical Security`
3. Upload: `HardTarget_Compliance.ps1`
4. Run as: System
5. Run in 64-bit: Yes

---

## Step 3: Create compliance policy

1. Intune → Devices → Compliance → Policies → Create (Windows 10 and later)
2. Name: `HardTarget Physical Security Baseline`
3. Compliance settings → Custom compliance:
   - Select your HardTarget script from Step 2
   - Upload: `CompliancePolicy.json` (34 rules)
4. Actions for non-compliance:
   - Mark non-compliant: immediately (or grace period)
   - Optional: block access via Conditional Access
5. Assign to: All devices (or target group)

Non-compliant devices now appear in Intune compliance reports and can be blocked from corporate resources via Conditional Access.

---

## Step 4: Set up Tier 1 remediation

This fixes the easy wins silently. No reboot, no user disruption.

1. Intune → Devices → Remediations → Create script package
2. Name: `HardTarget - Tier 1 (Silent)`
3. Detection: `HardTarget_Detect.ps1`
4. Remediation: `HardTarget_Remediate.ps1`
5. Run as System, 64-bit: Yes
6. Schedule: Daily
7. Assign to: All managed devices

**Tier 1 fixes (21):** Fast Startup, crash dumps, NMI dumps, pagefile clearing, kernel paging, RDP, auto-logon, ARSO, UAC credential prompt, Activity History, Prefetch, wake timers, screen timeout, built-in admin, account lockout, password policy, Ctrl+Alt+Del, last username, AutoRun, enhanced PIN, WinRM.

---

## Step 5: Set up Tier 2 remediation (optional)

These require a reboot. Pair with a restart policy.

1. Create remediation with `HardTarget_Detect_Tier2.ps1` + `HardTarget_Remediate_Tier2.ps1`
2. Schedule: Weekly
3. Assign to: Pilot group first, then expand

**Tier 2 fixes (7):** Modern Standby override, Connected Standby, VBS, HVCI, DMA Guard, LSA Protection, BitLocker Network Unlock.

**Companion restart policy:**
Devices → Configuration → Settings catalog → search "Schedule the restart" → grace period 24h.

---

## Step 6: Open fleet dashboard

1. Open `fleet-dashboard.html` in a browser
2. Enter your Entra App (Client) ID from Step 1
3. Click "Sign in & connect"
4. Authenticate with your Intune admin account
5. Dashboard pulls compliance results from Graph → renders fleet view

---

## What you get

| Where | What |
|---|---|
| Intune compliance reports | Per-device pass/fail on each check |
| Conditional Access | Block non-compliant devices from corporate resources |
| Proactive Remediations | Automatic fix of Tier 1 + Tier 2 issues |
| Fleet dashboard | Visual overview, top findings, drill-down, CSV export |
| Intune device status | Detection/remediation output per device |
| Event log (per device) | EventId 9010/9011 remediation audit trail |

---

## Tier model

| Tier | Delivery | Reboot | Fixes |
|---|---|---|---|
| 1 | Silent Intune push (daily) | No | 21 checks: fast startup, crash dumps, NMI dumps, pagefile clearing, kernel paging, RDP, auto-logon, ARSO, UAC credential prompt, Activity History, Prefetch, wake timers, screen timeout, built-in admin, account lockout, password policy, Ctrl+Alt+Del, last username, AutoRun, enhanced PIN, WinRM |
| 2 | Intune push + restart policy (weekly) | Yes | 7 checks: Modern Standby override, Connected Standby, VBS, HVCI, DMA Guard, LSA Protection, BitLocker Network Unlock |
| 3 | Console only — never remote | Varies | WinRE, bcdedit, Credential Guard, hibernation |

---

## FAQ

**Q: Do I still need to deploy HardTarget.ps1 to endpoints?**
No. The compliance script (`HardTarget_Compliance.ps1`) is self-contained. It checks the same settings HardTarget checks, but outputs flat JSON for Intune. The full HardTarget scanner is still useful for detailed local assessment and Tier 3 fixes, but it's not required for fleet compliance.

**Q: What if a GPO overrides a remediation?**
Detection re-runs on schedule. If a GPO reverts a fix, the device goes non-compliant again. Resolve the policy conflict in GPO/Intune.

**Q: Can I customize which checks are required?**
Edit `CompliancePolicy.json` to add/remove rules. The compliance script outputs all checks; the policy decides which ones matter.

**Q: What about Conditional Access?**
Once the compliance policy is active, create a Conditional Access policy: require device compliance for access to Office 365, VPN, or any Entra-protected resource. Non-compliant devices get blocked until fixed.

---

## v0.83 upgrade notes

If upgrading from a previous version, re-upload all scripts and the compliance policy.

**Compliance policy expanded to 34 rules.** `CompliancePolicy.json` covers: BitLocker (on, PIN, enhanced PIN, network unlock), Secure Boot, sleep states (S0, Connected Standby, wake timers, fast startup), memory residue (crash dumps, NMI dumps, pagefile clearing, kernel paging, hibernate), virtualization security (VBS, HVCI, Credential Guard), access control (RDP, auto-logon, ARSO, UAC, screen timeout, built-in admin, account lockout, password length, Ctrl+Alt+Del, last username, LSA protection), boot integrity (kernel debug, test signing), data exposure (Activity History, Prefetch, AutoRun, WinRM), and a `CheckErrors` meta-rule that fails devices where any check errored.

**Trusted path derivation.** Compliance script now derives `$TrustedSystemDrive` from `[Environment]::GetFolderPath` instead of `$env:SystemDrive`, consistent with the main HardTarget scanner's environment trust boundary hardening.

**Version tracking.** Compliance script now reports `HardTargetVersion = 0.83` in its JSON output. Use the fleet dashboard or Graph API to verify all endpoints are running the current version.

### Historical: v0.44 upgrade notes

If upgrading from v0.43 or earlier, re-upload all scripts and the compliance policy.

**Compliance policy expanded (v0.44):** `CompliancePolicy.json` grew from 8 rules to 18. The new rules cover: VBS, HVCI, DMA Guard, NMI dumps, kernel paging, S0/Connected Standby, ARSO, Activity History, Prefetch, and a `CheckErrors` rule that fails devices where any check errored during the scan. Without re-uploading, devices with these issues will pass compliance.

**Compliance script error handling (v0.44):** `HardTarget_Compliance.ps1` now uses per-check try/catch instead of global `SilentlyContinue`. Checks that fail to execute report `ERROR` instead of silently appearing compliant. The `CheckErrors` compliance rule catches this.

**Remediation scripts verify SYSTEM context (v0.44):** Both remediation scripts now exit 1 immediately if not running as Administrator/SYSTEM. Verify your Intune Proactive Remediation is configured with **Run as: System** and **Run in 64-bit: Yes**.

**Fleet dashboard SRI hash (v0.44):** The MSAL script tag in `fleet-dashboard.html` does not include an `integrity` attribute by default. Before deploying to production, compute the SRI hash and add it:
```bash
curl -sL "https://alcdn.msauth.net/browser/2.38.0/js/msal-browser.min.js" | \
  openssl dgst -sha384 -binary | openssl base64 -A
```
Add `integrity="sha384-<computed_hash>" crossorigin="anonymous"` to the `<script>` tag.

**Invoke-FleetScan integrity verification (v0.44):** Fleet scans now support `-ExpectedHash` to verify script integrity before distributing to endpoints:
```powershell
$hash = (Get-FileHash .\HardTarget.ps1 -Algorithm SHA256).Hash
.\Invoke-FleetScan.ps1 -ComputerFile servers.txt -HardTargetPath \\share\HardTarget.ps1 -ExpectedHash $hash
```

---

## Testing without Intune

If you don't have an Intune tenant, you can validate the scripts locally:

**Compliance script:** Run from an elevated PowerShell prompt. It outputs JSON to stdout, which is what Intune captures.
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\HardTarget_Compliance.ps1
```
Verify the output contains all expected keys and no `ERROR` values. Pipe to `ConvertFrom-Json` to inspect:
```powershell
$json = powershell.exe -ExecutionPolicy Bypass -File .\HardTarget_Compliance.ps1 | ConvertFrom-Json
$json | Format-List
```

**Detection scripts:** Exit code 0 = compliant, exit code 1 = non-compliant (remediation needed).
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\HardTarget_Detect.ps1; echo "Exit: $LASTEXITCODE"
powershell.exe -ExecutionPolicy Bypass -File .\HardTarget_Detect_Tier2.ps1; echo "Exit: $LASTEXITCODE"
```

**Remediation scripts:** Run elevated. Check the Event Log entries afterward:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\HardTarget_Remediate.ps1
Get-WinEvent -FilterHashtable @{LogName='Application'; Id=9010,9011} -MaxEvents 20
```

**Compliance policy validation:** Use Intune's compliance JSON schema validator, or just verify the keys match:
```powershell
$policy = Get-Content .\CompliancePolicy.json | ConvertFrom-Json
$scan = powershell.exe -ExecutionPolicy Bypass -File .\HardTarget_Compliance.ps1 | ConvertFrom-Json
foreach ($rule in $policy.Rules) {
    $val = $scan.($rule.SettingName)
    Write-Host "$($rule.SettingName): $val (expected: $($rule.Operand))"
}
```

**Fleet dashboard:** Open `fleet-dashboard.html` in a browser. Without Intune, use the drag-and-drop zone to load scan JSON files exported from the main HardTarget scanner (`-Audit` mode outputs JSON).
