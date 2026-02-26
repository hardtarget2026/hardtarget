# HardTarget

**Your compliance tools check what policy says should be true. This checks what's actually true.**

Single PowerShell script. No dependencies. Runs in 4 seconds. Tells you the physical security posture of a Windows machine right now, on this hardware, after the last update.

## The problem

There is nothing built into Windows, SCCM, Intune, or any major MDM that checks the actual physical security state of a running machine. They check policy. Policy is a statement of intent. The machine is a statement of fact.

Windows Update reverts your hardening. A driver installation re-enables Modern Standby. A firmware update disables VBS. Your compliance baseline doesn't catch it because it's checking the registry key, not the running state.

The Dolos Group pulled BitLocker keys from a locked, "well-secured" corporate laptop with a $200 logic analyser. No soldering. The laptop passed every compliance check in the org's tooling.

## What it checks

77 checks across 8 security domains, mapped to 6 real-world attack scenarios.

**BIOS / Firmware** - Secure Boot, UEFI variable protection, kernel debug, test signing, Intel AMT, firmware CVE lookup against NIST NVD.

**Sleep States** - Modern Standby (S0) including firmware-forced S0 that policy cannot override. Connected Standby, Fast Startup, hibernation, wake timers.

**TPM** - Firmware TPM vs discrete TPM (discrete communicates over an external bus a $200 logic analyser can sniff; fTPM runs inside the CPU die). Lockout policy, enhanced PIN.

**DMA / Virtualization** - VBS `SecurityServicesRunning` (the actual running state, not the registry key), HVCI, Credential Guard, DMA Guard. Enumerates Thunderbolt, FireWire, and USB4 controllers.

**Encryption** - BitLocker status, encryption method, protector types, full-volume vs used-space-only, pre-boot PIN presence, enhanced PIN, BitLocker Network Unlock, removable drive encryption.

**Memory Residue** - Crash dumps, NMI dumps, pagefile clearing, kernel paging. Everything that determines whether RAM contents survive a power cycle on disk.

**Access Control** - Display timeout, RDP, WinRE, auto-logon, ARSO, UAC behaviour, account lockout, password policy, Ctrl+Alt+Del, last username display, local account passwords, LSA protection, WinRM, PowerShell language mode, built-in Administrator account, Bluetooth, Wi-Fi auto-connect, camera privacy, microphone privacy.

**Data Exposure Surface** - Recent Documents, Jump Lists, thumbnails, Prefetch, Superfetch, UserAssist, Activity History, search index, PowerShell history, BAM logs, network profiles, ShellBags, USB history, Amcache, ShimCache, SRUM, USN journal, shadow copies, WER crash reports, ETW autologgers, event logs, NTFS $MFT, key escrow, self-footprint.

## Attack scenarios

Every check maps to one or more real-world attack scenarios:

- **Cold Boot** - extracting credentials from hiberfil.sys, pagefile, or residual RAM
- **DMA / Thunderbolt** - plugging a device into a DMA-capable port to read live memory
- **Evil Maid** - brief physical access to modify boot chain or install backdoor
- **Sleep/Wake** - exploiting a Modern Standby laptop that wakes silently in your bag
- **Forensic Recovery** - offline analysis of crash dumps, pagefiles, hibernation files
- **Device Compromise** - adversary gains access to unlocked device; minimise forensic trail, gate privilege escalation

## Running it

```
# Double-click the BAT file (mode selection, then requests admin):
RUN_HardTarget.bat

# Or from PowerShell:
powershell -NoProfile -ExecutionPolicy Bypass -File .\HardTarget.ps1

# Read-only dashboard (recommended first run):
.\HardTarget.ps1 -ReadOnly

# JSON report only (no server):
.\HardTarget.ps1 -Audit

# Fully offline (skip NVD firmware CVE lookup):
.\HardTarget.ps1 -ReadOnly -NoNVD
```

### Requirements
- Windows 10 or 11
- PowerShell 5.1 (built into Windows)
- Run as Administrator
- Nothing else

## Fix engine (Expert mode)

The fix engine is in beta - review the source and test in your environment before relying on it.

56 of 77 checks have automated fixes. Each one shows what it does, impact warnings, and whether a reboot is required. Every fix requires a randomly generated confirmation code typed at the PowerShell console - there is no way to approve a fix from the browser. Every fix is verified after application. If a GPO reverts the change, the dashboard reports the verification failure rather than claiming success.

**Edition-aware**: fixes that require Group Policy (Pro/Enterprise) show explicit warnings on Windows Home. Fixes that require a reboot show `PENDING REBOOT` instead of a false green checkmark.

**Domain-aware**: on domain-joined machines, fixes that write local policy warn that domain GPO may override on next refresh.

**Fix All** applies safe fixes in batch but skips anything with caveats (WinRE, VBS, HVCI, Credential Guard). Those require individual review.

Create a System Restore Point before making changes.

## Drift monitor

Optional background service that detects when your security posture changes silently.

- Hourly scheduled task (SYSTEM context)
- Compares current state against baseline
- Windows notification + Event Log (EventId 9001) + NDJSON log on any change
- Shows up in Add/Remove Programs with multiple removal paths

Install: `.\HardTarget.ps1 -Install` | Status: `.\HardTarget.ps1 -Status` | Remove: `.\HardTarget.ps1 -Uninstall`

## What it isn't

Not a replacement for CHIPSEC. CHIPSEC inspects firmware registers with a kernel driver. HardTarget is the triage layer that tells you which machines need that level of inspection.

Not a compliance checkbox. Compliance asks "is this policy configured." HardTarget asks "is this protection actually running right now."

## What data does it send

None, by default. One optional HTTPS request to the NIST NVD for firmware CVE lookup (sends firmware vendor and version only). Skip with `-NoNVD`. No telemetry, no analytics, no phone-home.

## Security model

- Localhost-only HTTP listener (127.0.0.1)
- CSPRNG session token (console -> browser, never in URL)
- Constant-time token comparison
- Console-gated approval for all mutations
- Rate limiting on fix endpoints
- Read-only mode enforced server-side
- Full security headers (CORP, COOP, X-Frame-Options, CSP, nosniff)

HTTP is deliberate: all mutations require console confirmation codes that need physical keyboard access. TLS would protect confidentiality of scan results from other local processes, but any process that can sniff localhost traffic already has the access level HardTarget is assessing. See the threat model comments in the source (line ~3223).

## Architecture

Single `.ps1` file. No installer, no compiled binary, no external dependencies. You can read every line before you run it.

```
HardTarget.ps1        # Scanner, fix engine, dashboard, drift monitor
RUN_HardTarget.bat    # Mode selection launcher
```

## Compliance framework mapping

All 77 checks mapped to CIS Windows Benchmarks, NIST 800-171, ISO 27001:2022, and CMMC Level 2. Dashboard includes a compliance view with per-framework drill-down.

## Roadmap

Fleet deployment via Intune and PSRemoting is in testing.

## Version

v0.83. See [CHANGELOG](CHANGELOG.md).

## License

BSL 1.1. Copyright (c) 2026 HardTarget Contributors.

**Change Date:** 1 February 2030 (converts to MIT License).

**Use Grant:** Non-commercial educational, research, internal security assessment, and personal use. Commercial use requires a separate license.

**Intended audience:** Qualified security professionals and system administrators. Not designed for general consumers. Review the source code before running it.

**No warranty.** This software is provided "as is" without warranty of any kind. The entire risk as to quality, performance, and results remains with you. A passing scan does not mean your system is secure.

**Limitation of liability.** In no event shall any HardTarget Contributor be liable for any damages including system failure, boot failure, data loss, registry corruption, or decisions made in reliance on scan results. This limitation applies to the fullest extent permitted by applicable law.

**Not professional advice.** This tool is not a substitute for professional security assessment or compliance auditing.

See the header of `HardTarget.ps1` for the complete legal notice including indemnification, data processing, and trademark acknowledgments.
