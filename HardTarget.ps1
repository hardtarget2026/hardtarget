# ============================================================================
#  HardTarget  -  Windows Physical Security Scanner
#  Security Posture Scanner v0.83
#  Run as Administrator for full results
# ============================================================================
#
# ---------------------------------------------------------------------------
#  v0.55 CHANGES - Security hardening (31 findings)
# ---------------------------------------------------------------------------
#  HIGH: ProgramData directory ownership. Attacker pre-creates directory,
#    becomes CREATOR OWNER, restores access after DACL. FIX: SetOwner()
#    for BUILTIN\Administrators with SID verification; abort on failure.
#  HIGH: Self-integrity check bypass. Attacker overwrites monitor and deletes
#    hash check. FIX: external verify-and-run wrapper (HardTarget_Verify.ps1).
#  HIGH: BAT launcher TOCTOU. Attacker swaps PS1 during UAC prompt.
#    FIX: stage to %SystemRoot%\Temp\HardTarget\ with SHA256 verification.
#  CRITICAL: fs-wer junction attack. Attacker plants junction in WER directory
#    pointing to System32. Remove-Item -Recurse follows it. FIX: new
#    Remove-ItemSafeRecurse helper that skips all reparse points.
#  HIGH: Monitor JSON log symlink overwrite. Attacker plants symlinks in data
#    directory. SYSTEM process overwrites arbitrary files. FIX: symlink scan
#    at monitor startup; Write-SafeFile helper for critical writes.
#  HIGH: Uninstall -Purge junction attack. Attacker replaces data directory
#    with junction to C:\. FIX: Test-ReparsePoint check before recursive delete.
#  CRITICAL: BitLocker PIN plaintext leak. Read-Host echoes PIN to screen and
#    transcript logs. FIX: Read-Host -AsSecureString with BSTR comparison and
#    ZeroFreeBSTR cleanup.
#  HIGH: HKCU context mismatch. UAC elevation changes user context; forensic
#    wipes only clear admin's empty hive. FIX: enumerate all HKEY_USERS SIDs
#    and all C:\Users\ profiles for fs-user-assist, fs-ps-history, fs-shellbags.
#  HIGH: Predictable temp file. Get-Random seeded by TickCount; attacker
#    pre-creates symlink in C:\Windows\Temp. FIX: CSPRNG filename, write to
#    ACL-protected HardTarget directory instead of $env:TEMP.
#  CRITICAL: Unqualified binary paths in BAT launcher. Windows resolves bare
#    "powershell" via CWD before PATH. Attacker drops malicious powershell.exe
#    in Downloads. FIX: all binaries use %SystemRoot%\System32\... absolute paths.
#  HIGH: Blind admin lockout. Script disables built-in Admin without checking
#    if other admin accounts exist. FIX: enumerate Administrators group via
#    SID S-1-5-32-544; abort if *-500 is the only active admin.
#  HIGH: False-positive firmware-forced S0. Override + no S3 = no sleep state
#    = lid close triggers shutdown. Logic incorrectly treated this as "override
#    ineffective." FIX: override-set + no-S3 now correctly reports as pass.
#    True firmware-forced now only fires when override is NOT set.
#  CRITICAL: Staging directory LPE. Attacker pre-creates %SystemRoot%\Temp\
#    HardTarget, becomes CREATOR OWNER, retains WRITE_DAC after icacls.
#    FIX: use CSPRNG random subdirectory name + /setowner + abort-if-exists.
#  HIGH: Write-SafeFile dead code. Defined but never called; all monitor/scan
#    writes still used raw Out-File. FIX: all 18 Out-File calls replaced.
#  MEDIUM: BitLocker PIN in managed heap. PtrToStringBSTR created immutable
#    .NET string; nulling reference doesn't erase RAM. FIX: use
#    SecureString.Length + ReadInt16 BSTR pointer arithmetic, no managed strings.
#  HIGH: Install-HardTargetMonitor ACL junction attack. Attacker pre-creates
#    monDir as junction to System32. Set-Acl follows junction, strips permissions.
#    FIX: Test-ReparsePoint at start of install routine; delete link before ACL.
#  HIGH: Verify wrapper TOCTOU. Hash file on disk, launch file in new process;
#    attacker swaps between hash and launch. FIX: ReadAllBytes into memory, hash
#    the bytes, execute via [scriptblock]::Create() -- no second file read.
#  HIGH: Unqualified binaries in PS1. manage-bde, powercfg, bcdedit, secedit,
#    vssadmin callable via User PATH hijack after UAC merge. FIX: $script:Bin
#    hashtable with fully qualified %SystemRoot%\System32 paths for all binaries.
#  CRITICAL: Broken UAC TOCTOU. Hash computed AFTER elevation -- attacker swaps
#    PS1 during UAC, elevated process hashes the malicious file against itself.
#    FIX: Hash computed BEFORE UAC, passed to elevated process, staged copy
#    verified against pre-elevation baseline.
#  MEDIUM: TOCTOU in Remove-ItemSafeRecurse. Check-then-delete race on reparse
#    points. FIX: re-read attributes via GetAttributes() immediately before each
#    delete. Window narrowed to microseconds. True fix requires P/Invoke.
#  MEDIUM: TOCTOU in Write-SafeFile. Check-then-write race. FIX: FileStream
#    with FileMode.CreateNew for atomic creation, exclusive lock for append,
#    re-verify attributes while holding lock. True fix requires P/Invoke.
#  CRITICAL: Registry symlink arbitrary deletion. Standard users plant REG_LINK
#    in their HKEY_USERS hive pointing to HKLM\SYSTEM. Remove-Item follows link.
#    FIX: Test-RegistrySymlink + Remove-RegistryKeySafe helpers; compare resolved
#    key name against expected path before deleting.
#  HIGH: Unqualified powershell.exe in scheduled task and shortcut. Runs as
#    SYSTEM, vulnerable to PATH hijacking. FIX: fully qualified path via
#    $env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe.
#  MEDIUM: Session 0 UI deadlock. NotifyIcon balloon in SYSTEM monitor cannot
#    render on interactive desktop (Session 0 isolation). Blocks 16s per drift.
#    FIX: removed NotifyIcon entirely; rely on msg.exe + EventLog.
#  CRITICAL: Path injection in BAT staging. Directory names with PS syntax
#    (e.g. "A'; Invoke-Payload; '#") inject into powershell -Command. FIX:
#    all hashing via certutil -hashfile (treats path as literal, no injection).
#  CRITICAL: Localized BUILTIN\Administrators fails on non-English Windows.
#    NTAccount constructor throws, catch continues with insecure directory.
#    FIX: all ACL operations use well-known SIDs. Catch is now hard abort.
#  HIGH: Installer ACL TOCTOU. Untrusted owner can delete+junction between
#    check and Set-Acl. FIX: if untrusted owner, Move-Item aside atomically,
#    create fresh as SYSTEM (standard users lack Delete right).
#  HIGH: fs-ps-history TOCTOU. WriteAllBytes follows links after check.
#    FIX: FileStream with exclusive lock, re-verify while holding lock.
#  MEDIUM: Write-SafeFile hardlink in append. GetAttributes misses hardlinks.
#    FIX: append now uses read-delete-CreateNew pattern (never opens existing).
#  MEDIUM: Incomplete UAC context. fs-recent-docs, fs-jump-lists, fs-thumbnails
#    still only targeted HKCU. FIX: AllUsers flag iterates HKEY_USERS hives.
#  Also: command whitelist missing net/vssadmin; phantom bios-password.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.56 CHANGES - Fix regressions from v0.55 + red team findings
#  CRITICAL: Write-SafeFile SAM dump. Append mode read existing content via
#    ReadAllText after hardlink check -- attacker swaps for hardlink to SAM
#    between check and read. FIX: never read existing content. Write new only.
#  CRITICAL: BAT temp file hijacking. %RANDOM% is 0-32767, attacker pre-creates
#    all filenames with malicious hash. FIX: eliminated temp files entirely,
#    parse certutil output directly in for /f.
#  HIGH: fs-ps-history dead hardlink check. Get-Item inside FileShare.None lock
#    triggers sharing violation, silently fails. FIX: check before open.
#  HIGH: Monitor install junction race when dir doesn't exist. FIX: reparse
#    point checks immediately before AND after Set-Acl.
#  HIGH: Write-SafeFile CreateNew symlink race. FIX: post-create reparse check.
#  MEDIUM: AllUsers regex failure on PS 5.1. FIX: -like instead of -match.
#  MEDIUM: Remove-ItemSafeRecurse TOCTOU documented as inherent limitation.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.57 CHANGES - Architectural rewrite: eliminate BAT as security boundary
#  CRITICAL: Six versions of BAT hardening (v0.52-v0.56) each introduced new
#    attack surface. cmd.exe fundamentally lacks atomic file operations.
#    FIX: BAT reduced to 5-line launcher. All security logic moved to PS1.
#    Self-elevation uses FileStream(FileShare.Read) kernel-level lock to
#    prevent file modification during UAC prompt. Hash computed from locked
#    stream, verified by elevated process before execution continues.
#  CRITICAL: fs-ps-history TOCTOU was inherently unfixable for in-place
#    overwrite of user-controlled files. Every check-then-write pattern has a
#    race window. FIX: delete-only (no overwrite). File.Delete on hardlinks
#    removes the directory entry without affecting the linked target. Sacrifices
#    anti-forensic overwrite, but prevents SAM/LSA corruption.
#  HIGH: Write-SafeFile append mode destroyed drift monitor log every hour.
#    FIX: Restored in-place append for ACL-protected paths (standard users
#    can't create hardlinks there). Exclusive FileStream lock + reparse
#    re-check inside lock. Delete-then-CreateNew only for create/overwrite.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.58 CHANGES - P/Invoke atomic file deletion + regression fixes
#  CRITICAL: fs-ps-history/fs-wer hardlink race. Managed File.Delete and
#    Remove-Item cannot atomically verify link status before deletion.
#    FIX: P/Invoke SafeDeleteFile opens with FILE_FLAG_OPEN_REPARSE_POINT,
#    checks nNumberOfLinks and reparse attributes via GetFileInformationByHandle,
#    marks for deletion through the same locked handle. Zero TOCTOU window.
#  HIGH: Write-SafeFile append crashes on fresh install. FileMode.Open throws
#    FileNotFoundException when drift log doesn't exist yet.
#    FIX: Changed to FileMode.OpenOrCreate.
#  HIGH: builtin-admin Note used English 'Administrator'. Localized systems
#    would fail the re-enable command. FIX: SID-based PowerShell command.
#  MEDIUM: Get-SecurityPolicy fell back to $env:TEMP (user-writable as SYSTEM).
#    FIX: Removed fallback; create ACL-protected directory if missing.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.59 CHANGES - Localization fixes + P/Invoke degraded-mode warnings
#  HIGH: P/Invoke fallback silent. When SafeDeleteFile unavailable (constrained
#    language mode), no warning shown. FIX: Visible console warnings at
#    Add-Type failure and at each degraded-mode file deletion.
#  MEDIUM: vssadmin "Shadow Copy ID" localized. Non-English = false pass.
#    FIX: Replaced with Get-CimInstance Win32_ShadowCopy (structured, no locale).
#  MEDIUM: fsutil "Maximum Size" localized + bare binary name.
#    FIX: Positional hex parsing (output order is stable across locales).
#    Also fixed bare `fsutil` to use $script:Bin.fsutil (qualified path).
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.60 CHANGES - Enterprise readiness: constant-time hash, BIOS guidance, schema
#  MEDIUM: UAC hash comparison used standard string compare (-ne). Theoretical
#    timing side-channel. FIX: Inline XOR-accumulation on raw hash bytes.
#  FEATURE: OEM-specific BIOS guidance for S0 Modern Standby. Detection now
#    includes manufacturer-specific instructions (Lenovo, Dell, HP, ASUS,
#    Surface) for disabling S0 at the firmware level. DMA risk explanation.
#  FEATURE: JSON output includes schemaVersion=1 for fleet-scale reporting.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.61 CHANGES - WOW64 protection + localization straggler
#  CRITICAL: 32-bit PowerShell on 64-bit OS silently redirects all registry
#    reads/writes to WOW6432Node. Every check returns wrong data, every fix
#    writes to a location the OS ignores. FIX: BAT launcher detects WOW64 via
#    sysnative path existence; PS1 hard aborts if Is64BitOS + !Is64BitProcess.
#  HIGH: Get-LocalGroupMember -Group 'Administrators' fails on non-English
#    Windows. Straggler from v0.55 SID migration. FIX: Changed to -SID
#    'S-1-5-32-544'. Entire password check was silently skipped on localized OS.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.62 CHANGES - ACL Preservation LPE fix
#  CRITICAL: Full SYSTEM privilege escalation via ACL preservation. When the
#    global init created C:\ProgramData\HardTarget without custom ACLs, standard
#    users could pre-create trap .ps1 files. Copy-Item -Force and Set-Content
#    -Force overwrite content but PRESERVE the file's Security Descriptor --
#    attacker retains CREATOR OWNER FullControl. When the scheduled task runs
#    as SYSTEM, the attacker overwrites the verify wrapper with arbitrary code.
#    FIX (Part 1): Apply restrictive ACLs (SYSTEM + Administrators only) at
#    directory creation time in global init, not just during -Install.
#    FIX (Part 2): Explicitly Remove-Item existing script files before
#    Copy-Item/Set-Content in installer. Destroys the old file object and its
#    ACL; new file inherits the directory's restrictive permissions.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.63 CHANGES - Add-Type oplock hijacking fix
#  CRITICAL: SYSTEM privilege escalation via csc.exe temp file injection.
#    Add-Type writes .cs/.cmdline to $env:TEMP before invoking csc.exe.
#    As SYSTEM, $env:TEMP = C:\Windows\Temp (user-writable). Attacker monitors
#    for .cs creation, oplocks to suspend SYSTEM thread, injects malicious C#,
#    releases oplock -- csc.exe compiles and loads attacker payload into SYSTEM.
#    FIX: Redirect $env:TEMP to ACL-protected C:\ProgramData\HardTarget during
#    Add-Type compilation. Restored in finally block. Standard users cannot
#    read/write to this directory (SYSTEM + Administrators only since v0.62).
#  DOCS: CHANGELOG.md restructured. v0.52-v0.63 findings were under one heading
#    that kept getting renamed. Now split into per-version sections matching PS1
#    headers. v0.52-v0.54 absent (abandoned BAT hardening, replaced by v0.57).
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.64 CHANGES - Lock persistence + WER context fix
#  CRITICAL: Elevated process disposed FileStream immediately after hash verify,
#    dropping the kernel write lock. If attacker kills the non-elevated parent,
#    file becomes writable. Attacker swaps PS1; admin clicks Install Monitor;
#    malicious file is copied, hashed, registered, and runs as SYSTEM.
#    FIX: FileStream assigned to $script:IntegrityLock, never disposed. Lock
#    survives entire elevated session independently of parent process.
#  MEDIUM: fs-wer fix/verify/detect used $env:LOCALAPPDATA which resolves to
#    SYSTEM's profile under scheduled task. User crash dumps missed entirely.
#    FIX: Iterate C:\Users\* for all profiles (CrashDumps + WER per user).
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.65 CHANGES - Precompiled P/Invoke DLL
#  SECURITY: Replaced runtime Add-Type C# compilation with precompiled DLL
#    loaded via [Reflection.Assembly]::Load($bytes). Eliminates v0.63 oplock
#    attack surface permanently: zero csc.exe, zero temp files, zero disk I/O.
#    Also works in Constrained Language Mode where Add-Type is blocked.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.66 CHANGES - Auth token transcript fix + BitLocker locale fix
#  MEDIUM: Auth token printed to console is captured by GPO PowerShell
#    transcript logging, persisting permanently on disk. FIX: When transcript
#    logging detected, write token to ACL-protected file in ProgramData\HardTarget
#    instead of console. File deleted on server shutdown.
#  MEDIUM: bitlocker-fullvol detection parsed manage-bde output strings
#    ("Conversion Status", "Fully Encrypted") which are localized. Non-English
#    Windows silently skipped the check. FIX: Replaced with WMI
#    Win32_EncryptableVolume.GetConversionStatus() which returns structured
#    integers (ConversionStatus, EncryptionPercentage, EncryptionFlags).
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.67 CHANGES - Write-SafeFile handle check + JSON regex DoS + remediation gaps
#  CRITICAL: Write-SafeFile append-mode reparse check used path-based
#    GetAttributes() which queries the path string, not the open handle.
#    Attacker swaps symlink after FileStream opens (which locks the TARGET),
#    GetAttributes sees the replacement normal file and passes. FileStream
#    appends to the original target (arbitrary file corruption).
#    FIX: New HtNativeFile.IsHandleReparsePoint() queries kernel file object
#    via GetFileInformationByHandle on the open SafeFileHandle. Also applied
#    to create-mode verification. Degraded mode falls back to path check.
#  MEDIUM: JSON truncation regex matched type names anywhere in payload.
#    Attacker creates folder named "System.Collections.Hashtable" (ShellBags)
#    or Wi-Fi SSID matching the string. Scanner captures it, regex false-
#    positives, hard error permanently blinds the monitor task.
#    FIX: Anchored regex matches only standalone JSON values (PowerShell's
#    exact truncation format), not substrings within legitimate data.
#  LOW: fs-recent-docs and fs-jump-lists set registry policies to halt future
#    tracking but left existing .lnk and .automaticDestinations-ms files on
#    disk. Scanner permanently reports "Failed" even after fix applied.
#    FIX: Post-registry cleanup iterates C:\Users\* to delete historical files.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.68 CHANGES - Remove-ItemSafeRecurse handle lock + token always-secure
#  CRITICAL: Remove-ItemSafeRecurse TOCTOU allows arbitrary file deletion (LPE).
#    Get-ChildItem follows directory junctions transparently. Attacker swaps a
#    real directory for a junction to System32 between Test-ReparsePoint and
#    Get-ChildItem. Script enumerates System32 and deletes everything as SYSTEM.
#    Exploitable via fs-wer fix (user-writable WER directories).
#    FIX: New HtNativeFile.LockDirectory() opens directory with
#    FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS, excludes
#    FILE_SHARE_DELETE. While handle is held, directory cannot be renamed or
#    deleted. Junction swap blocked by STATUS_SHARING_VIOLATION. Files deleted
#    via SafeDeleteFile (atomic handle-based). Directories removed via new
#    SafeRemoveDirectory. DLL recompiled with LockDirectory + SafeRemoveDirectory.
#  LOW: Auth token transcript leak via Start-Transcript and HKCU GPO policy.
#    v0.66 only checked HKLM GPO. Token now ALWAYS written to ACL-protected
#    file, never to console. Console display only on file write failure.
#  MEDIUM: JSON truncation detection relied on post-serialization regex matching
#    against the output string. User-controlled data that happened to contain
#    type names was neutralized by string interpolation, but this was incidental
#    -- one future check serializing a bare variable would reopen the DoS.
#    FIX: New Test-ObjectDepth pre-serialization validator walks the object graph
#    and verifies no branch exceeds ConvertTo-Json -Depth before serialization.
#    Regex retained as defense-in-depth backup only.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.69 CHANGES - Init ACL bypass + regex removal
#  MEDIUM: Global init block only enforced ACLs inside if(-not(Test-Path)) gate.
#    Standard user pre-creates C:\ProgramData\HardTarget as directory junction;
#    Test-Path resolves through junction to target (e.g. System32), returns true,
#    ACL block skipped entirely. All subsequent Write-SafeFile calls write into
#    attacker-chosen directory. Write-SafeFile checks the FILE for reparse, not
#    the parent directory.
#    FIX: Init block now unconditionally checks for reparse points, verifies
#    ownership via SID, moves aside untrusted directories, and enforces ACLs
#    on every run -- mirroring Install-HardTargetMonitor's full security posture.
#  LOW: Post-serialization truncation regex removed. Test-ObjectDepth is the
#    sole truncation defense. The regex was fundamentally unable to distinguish
#    real truncation artifacts from legitimate strings matching the type name
#    pattern and added false positive risk with zero value beyond what the
#    structural validator already provides. Removed from both Get-ScanJson
#    and Send-JsonResponse.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.70 CHANGES - Write-SafeFile native opens + staging directory pattern
#  CRITICAL: Write-SafeFile v0.67 handle check was ineffective ("snake oil").
#    .NET FileStream follows symlinks before opening -- the SafeFileHandle belongs
#    to the TARGET (e.g. hal.dll), not the symlink. IsHandleReparsePoint checks
#    the target, which is always a normal file, and returns false. Attacker plants
#    symlink at drift log path, SYSTEM monitor appends JSON to hal.dll.
#    FIX: New SafeOpenForAppend and SafeCreateNew P/Invoke methods use native
#    CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT. Kernel opens the link itself.
#    Handle check detects reparse. Hardlinks rejected via nNumberOfLinks > 1.
#    SafeFileHandle wrapped in FileStream for managed write access.
#  MEDIUM: Init block and installer directory security used check-then-act pattern
#    vulnerable to TOCTOU race between Move-Item and Set-Acl. Attacker recreates
#    directory as junction in the gap, Set-Acl applied to junction target.
#    FIX: New Initialize-SecureDirectory helper implements staging directory
#    pattern. Creates directory with random name, applies ACLs while name is
#    unpredictable, renames atomically to final path. Both init block and
#    Install-HardTargetMonitor now use the same hardened helper.
#  DLL: HtNativeFile.dll recompiled 5632 -> 8192 bytes. New methods:
#    SafeOpenForAppend, SafeCreateNew, SafeRenameDirectory,
#    SafeRegistryDeleteTree (NtDeleteKey + REG_OPTION_OPEN_LINK).
#  CRITICAL: Remove-RegistryKeySafe TOCTOU -- arbitrary hive deletion.
#    Test-RegistrySymlink closes its handle before Remove-Item executes.
#    Attacker swaps key for REG_LINK to HKLM\SYSTEM in the gap. Remove-Item
#    follows the link transparently and deletes the entire system hive.
#    FIX: New SafeRegistryDeleteTree P/Invoke method opens every key with
#    REG_OPTION_OPEN_LINK (won't follow symlinks), checks for SymbolicLinkValue,
#    recursively deletes children through handles, and calls NtDeleteKey
#    (handle-based, atomic). No TOCTOU window because the handle used for
#    verification IS the handle used for deletion.
#  MEDIUM: Initialize-SecureDirectory trusted-owner fast path had TOCTOU.
#    Between Test-ReparsePoint and Get-Acl, attacker swaps normal directory
#    for junction. Get-Acl follows junction, reads System32 owner (trusted),
#    Set-Acl fires down junction, strips System32 inherited permissions.
#    FIX: LockDirectory holds directory handle with FILE_SHARE_DELETE excluded
#    during entire Get-Acl + Set-Acl sequence. Attacker cannot rename/delete
#    the directory while the handle is held.
#  MEDIUM: Global init catch block silently swallowed Initialize-SecureDirectory
#    failures when running elevated. If attacker holds oplock on target path,
#    staging rename fails, exception caught, script proceeds with attacker-owned
#    directory. Monitor scheduled task then executes attacker's trap files as SYSTEM.
#    FIX: Catch block now checks elevation status. If elevated and securing fails,
#    hard-aborts with SECURITY ABORT. Only tolerates failure when non-elevated.
#  CRITICAL: fs-recent-docs and fs-jump-lists fix handlers iterate user-owned
#    profile directories with raw Get-ChildItem + Remove-Item. User replaces
#    AutomaticDestinations or Recent with junction to System32; Get-ChildItem
#    follows junction, enumerates system binaries, Remove-Item deletes them.
#    Same class of bug fixed in fs-wer (v0.68) but reintroduced in v0.67.
#    FIX: LockDirectory holds parent directory handle (rejects junctions,
#    prevents swap), SafeDeleteFile for each file. Degraded: Test-ReparsePoint.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.83 CHANGES - Environment scrub fix + pipe hardening + parameter forwarding
#  v0.82 CHANGES - Pipe ACL + DOTNET_STARTUP_HOOKS + parameter elevation
#  MEDIUM: Named pipe ACL denied creator's own SID. The PipeSecurity only
#    granted Administrators FullControl, but the non-elevated creator lacks
#    the Administrators group. CreateNamedPipe fails, catch block fell back
#    to unrestricted default ACL. Any same-user process could connect first
#    (DoS) or inject content. FIX: ACL now grants both Administrators and
#    the creator's SID. PS7 fallback applies ACL post-creation via
#    SetAccessControl instead of leaving pipe unrestricted.
#  MEDIUM: DOTNET_STARTUP_HOOKS and DOTNET_ADDITIONAL_DEPS missing from
#    cmd.exe environment scrub. These .NET Core/5+ variables load arbitrary
#    assemblies before the entry point. FIX: Added to scrub chain.
#  MEDIUM: -Install and -Uninstall parameters skipped self-elevation.
#    needsMenu evaluated false, entire elevation block skipped. Operations
#    failed silently from unprivileged context. FIX: Dedicated elevation
#    block for mutating parameters when not already elevated.
#  LOW: UTF-8 BOM inconsistency. Bootstrapper stripped BOM before
#    [scriptblock]::Create but verify wrapper did not. FIX: Added BOM
#    stripping to verify wrapper.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.81 CHANGES - AppInfo environment rebuild + ProgramData + browser launch
#  CRITICAL: CLR profiler bypass via HKCU registry. v0.79 stripped COR_PROFILER
#    from the parent process env, but Start-Process -Verb RunAs delegates to
#    AppInfo, which calls CreateEnvironmentBlock to build a FRESH env block
#    from the registry (HKLM + HKCU\Environment). Attacker sets COR_PROFILER
#    in HKCU\Environment; it reappears in the elevated process regardless of
#    what the parent stripped. FIX: Elevate cmd.exe (native, CLR never loads)
#    with /c that explicitly clears CLR vars, then launches powershell.exe.
#    The child PowerShell inherits cmd.exe's scrubbed environment.
#  CRITICAL: ProgramData environment poisoning. Same vector class as
#    SystemRoot: attacker sets $env:ProgramData to attacker-controlled dir.
#    Monitor data, scheduled task scripts, auth tokens all redirect there.
#    Attacker owns the parent directory and can swap contents after ACL.
#    FIX: $script:TrustedProgramData from GetFolderPath(CommonApplicationData).
#  HIGH: SystemRoot GetEnvironmentVariable('SystemRoot','Machine') returns
#    $null on some configurations (kernel-injected, not in Session Manager).
#    FIX: Replaced with GetFolderPath(Windows) which calls native shell API.
#  HIGH: Browser launch via ShellExecute from elevated context. Start-Process
#    on http:// URL reads HKCU protocol handler; attacker registers malicious
#    exe as http handler, it launches as admin. FIX: Removed auto-launch.
#    Dashboard URL printed to console for manual opening.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.80 CHANGES - Bootstrapper scrub ordering + AST-sourced verified bytes
#  CRITICAL: Bootstrapper error-path auto-loader hijack. The PSModulePath and
#    PATH scrubs were placed after the named pipe Connect() call. If the
#    attacker kills the non-elevated process, the pipe server dies, Connect()
#    throws TimeoutException, and PowerShell's Extended Type System triggers
#    the module auto-loader to format the exception -- before the scrub fires.
#    Attacker's poisoned PSModulePath module executes as Administrator.
#    FIX: Environment scrubs moved to the absolute first two lines of the
#    bootstrapper, before any constructor or method call.
#  CRITICAL: Already-elevated execution TOCTOU. PowerShell reads the file,
#    builds the AST, closes the handle. The entry point code then re-reads the
#    file from disk into VerifiedScriptBytes. Between the initial parse and
#    the second read, the attacker swaps the file. The second read captures
#    attacker code. Install-HardTargetMonitor writes it to ProgramData as a
#    SYSTEM task. FIX: VerifiedScriptBytes now sourced from the executing
#    ScriptBlock ($MyInvocation.MyCommand.ScriptBlock.ToString()), which
#    contains the AST that PowerShell actually parsed. Disk is never re-read.
#  LOW: UNC path Substring(7) should be Substring(8). \\?\UNC\ is 8 chars.
#    Substring(7) preserves trailing backslash, producing \\\server\share.
#    Windows object manager collapses multiple slashes, but the path is
#    technically malformed. FIX: Changed to Substring(8).
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.79 CHANGES - .NET CLR profiler hijacking defense
#  CRITICAL: COR_ENABLE_PROFILING / COR_PROFILER_PATH DLL injection. The CLR
#    reads profiler environment variables during runtime initialization, BEFORE
#    any managed code (including PowerShell) executes. A standard user sets
#    COR_ENABLE_PROFILING=1 and COR_PROFILER_PATH=C:\...\Payload.dll in their
#    process environment. When Start-Process -Verb RunAs creates the elevated
#    powershell.exe, it inherits the poisoned environment. The CLR loads the
#    attacker's DLL into the admin process before the bootstrapper's first line.
#    Scrubbing inside the elevated process is too late -- the DLL is loaded.
#    FIX (UAC path): The non-elevated process strips all CLR profiler variables
#    (COR_ENABLE_PROFILING, COR_PROFILER, COR_PROFILER_PATH, CORECLR_*,
#    DOTNET_*, _NT_SYMBOL_PATH) from its own environment immediately before
#    calling Start-Process. The inherited block is clean.
#    FIX (already-elevated path): If COR_ENABLE_PROFILING=1 or
#    CORECLR_ENABLE_PROFILING=1 is detected while elevated, the script aborts
#    immediately. The DLL may already be loaded, but aborting prevents the
#    attacker from leveraging the scanner's elevated operations.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.78 CHANGES - SystemRoot trust boundary + pipe impersonation hardening
#  CRITICAL: $env:SystemRoot poisoning via DLL side-loading. All security-
#    critical execution paths ($script:PsExeFull, $script:Bin, scheduled task
#    actions) were derived from $env:SystemRoot, which standard users can set
#    in their own process environment. Attacker sets SystemRoot=C:\FakeWindows,
#    copies the real signed powershell.exe there, plants a side-loadable DLL
#    (e.g. version.dll) next to it. Start-Process -Verb RunAs launches the
#    real binary from the attacker's path; the DLL loads as admin. UAC shows
#    a trusted blue banner because the .exe is genuinely Microsoft-signed.
#    FIX: All security-critical paths now use $script:TrustedSystemRoot,
#    sourced from [Environment]::GetEnvironmentVariable('SystemRoot','Machine')
#    which reads from HKLM (standard users cannot modify). All remaining
#    $env:SystemRoot references (scan paths, display strings) also migrated.
#  MEDIUM: Named pipe client impersonation. The elevated bootstrapper's
#    NamedPipeClientStream used the default constructor, which on older .NET
#    Framework versions may not explicitly set TokenImpersonationLevel. If the
#    attacker controls the non-elevated process (via same-SID injection), the
#    malicious pipe server could attempt ImpersonateNamedPipeClient to steal
#    the admin token. FIX: Constructor now explicitly passes
#    TokenImpersonationLevel.Anonymous, guaranteeing the server cannot request
#    an impersonation token from the elevated client.
#  MEDIUM: Bootstrapper environment scrub ordering. PSModulePath and PATH
#    scrub occurred after the hash verification failure path, which calls
#    Write-Host and Read-Host. While these core cmdlets do not trigger the
#    auto-loader, any future modification to the error path could introduce
#    module hijacking. FIX: Environment scrub moved to immediately after
#    SHA256 computation, before any cmdlet execution including the error path.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.77 CHANGES - UAC context bleed: environment and COM trust boundary
#  CRITICAL: PSModulePath auto-loader hijacking. UAC elevation inherits the
#    standard user's HKCU registry hive. Attacker poisons HKCU\Environment\
#    PSModulePath with a directory containing a malicious module. When the
#    elevated script calls any cmdlet triggering module discovery, PowerShell's
#    auto-loader executes the attacker's module as Administrator. Zero race
#    condition required: the poisoned path persists across reboots.
#    FIX: Immediately after elevation check, replace $env:PSModulePath with
#    machine-scope only ([Environment]::GetEnvironmentVariable('PSModulePath',
#    'Machine')). Also applied in the bootstrapper before script execution.
#  HIGH: HKCU COM object hijacking. WScript.Shell COM object used for Start
#    Menu shortcut creation. COM resolution checks HKCU\Software\Classes\CLSID
#    before HKLM, so a standard user can plant a malicious CLSID entry that
#    gets instantiated as Administrator when the elevated script calls
#    New-Object -ComObject. FIX: Removed all COM object usage. Shortcut
#    creation eliminated; scheduled task and Add/Remove Programs entry provide
#    sufficient access points.
#  HIGH: PATH environment variable inheritance. Same vector as PSModulePath:
#    attacker poisons HKCU\Environment\PATH to shadow system binaries. All
#    binary calls already use fully qualified $script:Bin paths (v0.53), but
#    scrubbing PATH provides defense-in-depth. FIX: $env:PATH replaced with
#    machine-scope only alongside PSModulePath, in both bootstrapper and main
#    script elevated context.
#  DOCUMENTED: Same-SID memory injection. A standard user has
#    PROCESS_ALL_ACCESS to any process under the same SID. An attacker can
#    WriteProcessMemory into the non-elevated HardTarget process, overwriting
#    the in-memory script buffer between the disk read and the hash computation.
#    The bootstrapper would then verify and execute the attacker's code. This
#    is a fundamental OS boundary: no unprivileged process can defend its own
#    memory against a same-SID attacker. The only fix is a compiled, signed
#    launcher with Protected Process Light (PPL), which violates the single-file
#    PowerShell requirement. Documented as a known limitation.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.76 CHANGES - In-memory elevation via bootstrapper + named pipe
#  CRITICAL: UAC handle-theft TOCTOU. The non-elevated FileStream lock can be
#    stolen by a same-user attacker via DuplicateHandle(DUPLICATE_CLOSE_SOURCE),
#    since PROCESS_DUP_HANDLE is granted between same-SID processes. Once the
#    lock is dropped, the attacker overwrites the script file. When the admin
#    clicks Yes on the UAC prompt, the elevated process loads and executes the
#    attacker's code -- which simply ignores the -HtHash parameter. The hash
#    check only exists in OUR code. The attacker's code is not our code.
#    FIX: The elevated process never reads from disk. The non-elevated process
#    reads the script into memory, hashes it, creates an admin-only named pipe,
#    generates a tiny bootstrapper (pipe name + expected hash), Base64-encodes
#    it, and launches elevated via -EncodedCommand. After UAC approval, the
#    bootstrapper connects to the pipe, reads the script, verifies the hash,
#    and executes from memory via [scriptblock]::Create(). The disk file is
#    irrelevant after the initial read.
#  HIGH: Install-HardTargetMonitor copied script from disk path, which could
#    be swapped after in-memory verification. FIX: Write from verified in-memory
#    bytes ($script:VerifiedScriptBytes) when available, bypassing disk entirely.
#  HIGH: Already-elevated execution path (admin prompt, SCCM, Intune) skipped
#    the bootstrapper and never populated $script:VerifiedScriptBytes. If the
#    admin ran the script from a user-writable directory and left the dashboard
#    open, an attacker could swap the file and Install Monitor would copy the
#    attacker's payload into the ACL-protected directory as a SYSTEM scheduled
#    task (infinite TOCTOU window). FIX: Entry point now locks, reads into
#    memory, and populates $script:VerifiedScriptBytes for all execution paths.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.75 CHANGES - Atomic resolve-and-lock + Path canonicalization hardening
#  CRITICAL: String-based canonicalization TOCTOU. Resolve-CanonicalScriptPath
#    called CreateFileW, resolved the path via GetFinalPathNameByHandleW, then
#    CLOSED the native handle and returned the path as a string. FileStream::new
#    was then called on that string, opening a NEW handle. In the microsecond gap
#    between CloseHandle and FileStream::new, an attacker can rename the parent
#    directory and create a junction pointing to a payload directory. FileStream
#    follows junctions natively, locking and hashing the attacker's payload.
#    FIX: -Lock switch on Resolve-CanonicalScriptPath wraps the SAME native
#    handle in SafeFileHandle -> FileStream without ever closing it. Returns
#    hashtable with Path and Stream. Resolution and locking are atomic on the
#    same kernel handle. Applied at STEP A (elevated integrity check) and
#    STEP B (non-elevated launcher). The kernel lock on the file's parent
#    directory prevents renaming (STATUS_SHARING_VIOLATION), neutralizing
#    junction swap attacks entirely.
#  CRITICAL: UNC path truncation to relative path. GetFinalPathNameByHandleW
#    returns \\?\UNC\server\share\path for network shares. Substring(4) yields
#    UNC\server\share\path -- a RELATIVE path that PowerShell resolves against
#    CWD. Attacker creates matching directory structure under CWD with malicious
#    script. Elevated process executes it. FIX: Detect \\?\UNC\ prefix and
#    replace with \\ to produce correct UNC path \\server\share\path.
#  CRITICAL: Volume GUID path truncation to relative path. On volumes without
#    drive letters, GetFinalPathNameByHandleW returns \\?\Volume{GUID}\path.
#    Substring(4) yields Volume{GUID}\path -- a RELATIVE path, same class as
#    the UNC bug. FIX: Detect \\?\Volume{ prefix and keep it intact. The
#    \\?\Volume{GUID}\path form is already the canonical absolute path.
#  CRITICAL: Forced degradation via exclusive file lock. CreateFileW returning
#    INVALID_HANDLE_VALUE (-1) is a Win32 return value, not a .NET exception.
#    The catch block (Reflection.Emit failure) never fires. The if-handle block
#    is skipped. Execution falls to Attempt 2 (managed TOCTOU-vulnerable walk).
#    Attacker holds FILE_SHARE_NONE on the script, forces CreateFileW failure,
#    then releases the lock and wins the race in the managed fallback.
#    FIX: After the native if-handle block, if -Lock was specified and execution
#    reaches that point (success paths return early), exit 1 unconditionally.
#  CRITICAL: Path length buffer overflow downgrade. 1024-char StringBuilder
#    silently failed on deep directory structures (>1024 chars). Native
#    resolution returned null, falling through to TOCTOU-vulnerable heuristic.
#    FIX: Buffer size increased to 32767 (Windows MAX_PATH for extended paths).
#  CRITICAL: Environmental downgrade via Constrained Language Mode (CLM).
#    __PSLockdownPolicy=4 inherited across UAC boundary disables Reflection.Emit
#    and Assembly.Load. All native helpers fail silently, falling back to
#    vulnerable managed code. FIX: If elevated and native helpers fail to load,
#    hard abort (exit 1). Non-elevated context: warn and continue (installer
#    applies full protections during -Install).
#  CRITICAL: Asymmetric trust boundary across UAC. The CLM guard only aborted
#    when elevated ($isElevated check). Non-elevated process could degrade to
#    managed fallback, allowing attacker to spoof the hash via TOCTOU in the
#    walk-then-open heuristic. UAC strips user-level env vars (COR_PROFILER)
#    from elevated process, so native APIs succeed there. Elevated process
#    trusts the spoofed hash from the degraded non-elevated process.
#    FIX: Remove $isElevated check. If -Lock is specified and Reflection.Emit
#    fails, exit 1 unconditionally. Both sides of the UAC boundary must use
#    identical security primitives.
#  HIGH: $script:ScriptPath not set from verified canonical path. In STEP A
#    (elevated process), the canonicalized $selfPath was local-scoped. When the
#    dashboard's "Install Monitor" button called Install-HardTargetMonitor with
#    $script:ScriptPath, it read from the entry point assignment (~line 8008)
#    which uses $MyInvocation.MyCommand.Path (the unverified junction-based path
#    from Start-Process -File). FIX: $script:ScriptPath = $selfPath set
#    immediately after canonicalization in STEP A.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.74 CHANGES - Path canonicalization + Disk-free P/Invoke + Registry fail-closed
#  CRITICAL: UAC elevation TOCTOU via directory junction swap. FileStream locks
#    the real file through a junction, but the junction itself is swappable.
#    Attacker deletes junction during UAC prompt, creates normal directory with
#    malicious script. Elevated process loads attacker's file (no hash check in
#    the malicious script). Same root cause affects Install-HardTargetMonitor:
#    $script:ScriptPath resolves through the swapped junction, Copy-Item copies
#    the malicious file, Get-FileHash registers it as trusted baseline.
#    FIX: New Resolve-CanonicalScriptPath function uses GetFinalPathNameByHandle
#    P/Invoke via Reflection.Emit (disk-free, no csc.exe, no temp files) to
#    dereference all reparse points in the path. Applied at STEP A (elevated
#    integrity check), STEP B (non-elevated launcher), script entry point
#    ($script:ScriptPath), and all Install-HardTargetMonitor callers.
#    Fallback: walk directory components and abort if any is a reparse point.
#  MEDIUM: Auth token leaked via URL fragment in Start-Process command line.
#    Any standard user can query Win32_Process via WMI to read CommandLine of
#    all running processes, capturing the token from the browser launch process.
#    FIX: Token removed from URL fragment. Browser opened without token.
#    Dashboard shows manual auth prompt. Token delivered via ACL-protected
#    auth_token.txt and console display only. Hash and mode remain on the
#    elevated process command line by design: the hash is a public integrity
#    check (not a secret), and command-line args are IMMUTABLE after
#    Start-Process -- the kernel captures them before UAC. This immutability
#    is the security property that detects file swaps even if the parent is
#    killed. Named pipe IPC was evaluated and rejected: killing the parent
#    destroys the pipe, allowing spoofed pipe + fake hash attacks.
#  MEDIUM: SafeRegistryDeleteTree degradation attack. If native NtDeleteKey
#    sequence fails (deeply nested keys, key locking, resource exhaustion),
#    script fell back to TOCTOU-vulnerable managed check-then-act pattern.
#    Attacker can intentionally cause native failures to force degradation.
#    FIX: When native DLL is loaded and SafeRegistryDeleteTree returns -1,
#    fail CLOSED. Interactive mode: refuse operation, return $false. Monitor
#    mode (SYSTEM scheduled task): Environment.FailFast() for immediate
#    termination with WER forensic trail. Degraded managed mode only reachable
#    when native DLL was never loaded.
#  MEDIUM (v0.74 regression prevention): Resolve-CanonicalScriptPath uses
#    Reflection.Emit to define P/Invoke methods in a dynamic in-memory assembly.
#    Add-Type was explicitly avoided: it calls csc.exe which writes temp .cs
#    files to disk. When running as SYSTEM, an attacker can oplock the Temp
#    folder, pause the thread during .cs write, inject malicious C# payload,
#    release the lock, and get code compiled into SYSTEM context. Reflection.Emit
#    never touches the filesystem. This is the same pattern used by HtNativeFile
#    (v0.65) for the same reason.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.73 CHANGES - Staging directory bypass + Monitor path hardening
#  MEDIUM: GLOBALS section pre-created MonitorDataDir with bare New-Item before
#    Initialize-SecureDirectory was called (~850 lines later). On fresh install,
#    the directory existed with inherited BUILTIN\Users write ACLs when
#    Initialize-SecureDirectory ran. The function's $needsCreate=true staging
#    pattern (random name -> ACLs -> atomic rename) was never exercised; instead
#    the trusted-owner fast path applied Set-Acl to the already-existing dir.
#    Micro-TOCTOU window between New-Item and Set-Acl. Not currently exploitable
#    for LPE (Write-SafeFile neutralizes trap files) but defeats staging pattern.
#    FIX: Removed MonitorDataDir New-Item. Initialize-SecureDirectory now owns
#    the full creation lifecycle. UserOutputDir only created if it differs from
#    MonitorDataDir (external user-specified path).
#  MEDIUM: Monitor code path (-Monitor flag, runs as SYSTEM scheduled task)
#    used bare New-Item to recreate MonitorDataDir if missing. If an admin or
#    attacker deletes the ACL-protected directory, the SYSTEM task recreates it
#    with inherited ProgramData ACLs (standard-user writable). Subsequent scan
#    results and drift logs written to attacker-readable space.
#    FIX: Monitor path now calls Initialize-SecureDirectory. Failure aborts
#    the monitor process (headless SYSTEM -- cannot Read-Host).
#  LOW: Secedit export function had bare New-Item fallback for MonitorDataDir.
#    Runs after init so directory should always exist, but defense-in-depth
#    replacement with Initialize-SecureDirectory for mid-execution deletion.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.72 CHANGES - Registry TOCTOU + Init exception differentiation
#  CRITICAL: New-Item after Remove-RegistryKeySafe in fs-user-assist and
#    fs-shellbags created a TOCTOU window. Between atomic safe delete and
#    New-Item recreation, attacker plants REG_LINK pointing to HKLM\SYSTEM.
#    New-Item follows the link and wipes the target as NT AUTHORITY\SYSTEM.
#    FIX: All New-Item recreations removed. Explorer auto-rebuilds these
#    registry structures on next event. Affects: fs-user-assist (HKU + HKCU
#    Count keys), fs-shellbags (HKU + HKCU BagMRU/Bags keys).
#  HIGH: Init block catch-all swallowed IOException/UnauthorizedAccessException
#    when elevated, allowing script to continue with attacker-owned directory.
#    Auth token file and scan results written to attacker-readable space.
#    FIX: Catch now differentiates -- RuntimeException for type resolution
#    failures (PS 5.1 benign) warns and continues. IOException and
#    UnauthorizedAccessException while elevated trigger SECURITY ABORT.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.71 CHANGES - External CDN removal + DLL type resolution + auto-auth
#  LOW: index.html landing page imported Google Fonts via @import url(). A
#    physical security scanner targeting air-gapped and high-security environments
#    should not make outbound HTTP requests to third-party CDNs. While the auth
#    token is never in the URL (header-only since v0.43), the outbound request
#    leaks the machine's existence and timing to Google servers and corporate
#    proxy logs. Replaced with system font stacks: Cascadia Code/Consolas for
#    monospace, Charter/Cambria/Georgia for serif. Added <meta referrer=no-referrer>
#    as defense-in-depth. No visual quality loss -- these are high-quality fonts
#    that ship with Windows.
#  BUG: Initialize-SecureDirectory defined after its call site in GLOBALS section.
#    PowerShell scripts execute top-to-bottom; function didn't exist at call time.
#    Elevated child process crashed on launch (catch block + IsInRole = SECURITY
#    ABORT). Moved function definition and init call to after all helper function
#    definitions (Test-ReparsePoint, Remove-ItemSafeRecurse, Write-SafeFile).
#  BUG: [HtNativeFile] type literal unresolvable on PS 5.1. Assembly.Load(byte[])
#    loads into .NET's anonymous context; PS 5.1 type resolver can't find types
#    from that context. All 14 [HtNativeFile]::Method() calls replaced with
#    $script:HtNative::Method() using the Type object from $asm.GetType().
#    PowerShell resolves $TypeVar::Method() through the runtime object directly.
#  BUG: Init block SECURITY ABORT too aggressive -- type resolution failures
#    triggered same abort as genuine LPE attacks. Init catch now warns and
#    continues; installer applies full native protections during -Install.
#  BUG: Elevated process window vanished on crash with no error visible.
#    Added global trap at script scope that catches unhandled errors, displays
#    the error and line number, and pauses with Read-Host.
#  UX: Dashboard auto-auth via URL fragment. Browser opened with token in
#    fragment (#token) -- never sent in HTTP requests, invisible to proxies/logs.
#    JS reads location.hash, authenticates, clears via history.replaceState().
#    Replaces manual paste-from-file flow. Falls back to manual entry on failure.
# ---------------------------------------------------------------------------
#  BUG: Bluetooth verification re-disabled adapters instead of checking state.
#  BUG: Disable-LocalUser hardcoded English name 'Administrator'. Now SID *-500.
#  BUG: BitLocker operations hardcoded 'C:'. Now uses $env:SystemDrive.
#  DOMAIN: Detects domain-join (dsregcmd + WMI fallback). Warns that net accounts
#    writes LOCAL policy which domain GPO overrides on next refresh (~90 min).
#    Warning in console Apply-Fix and Intune remediation output.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.50 CHANGES - Windows edition awareness + ground truth fixes
# ---------------------------------------------------------------------------
#  Three-tier edition gating for fixes (blocked/degraded/full).
#  secedit /export /mergedpolicy replaces /cfg for effective policy.
#  S0 firmware-forced detection cross-checked with powercfg /a.
#  USB checks gated on edition (Home reports "GP not available").
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.49 CHANGES - Locale independence + password policy + Intune parity
# ---------------------------------------------------------------------------
#  Replaced all English-dependent CLI parsing with locale-safe alternatives.
#  Password policy threshold reduced from 12 to 8 chars (NIST 800-63B).
#  Intune sync: CompliancePolicy 18->34, Compliance script 22->42 outputs,
#  Detect/Remediate T1 11->21, Detect/Remediate T2 5->7.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.48 CHANGES - Physical access hardening (16 new checks)
# ---------------------------------------------------------------------------
#  Expanded scanner from 61 to 77 checks. 15 of 16 have automated fixes.
#  Total fixable: 56 of 77 (73%).
#  New checks: account-lockout, password-policy, ctrl-alt-del, last-username,
#  usb-storage, usb-install, autorun, bluetooth, wifi-autoconnect,
#  camera-privacy, mic-privacy, lsa-protection, winrm, ps-language-mode,
#  bl-network-unlock, removable-encrypt.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.47 CHANGES - New fix handlers (8 additional fixable checks)
# ---------------------------------------------------------------------------
#  Added fixes for: screen-timeout, builtin-admin, bitlocker-pin,
#  fs-shadow-copies, fs-wer, fs-amcache, fs-shimcache, fs-srum.
#  Total fixable checks: 41 of 61 (67%). 10 remaining are hardware/BIOS only.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.46 CHANGES - Compliance framework mapping
# ---------------------------------------------------------------------------
#  All 61 checks mapped to CIS, NIST 800-171, ISO 27001:2022, CMMC L2.
#  Dashboard compliance view with per-framework summary and drill-down.
#  Coverage: 34 NIST, 33 CMMC, 21 CIS, 14 ISO controls assessed.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.45 CHANGES - Security hardening (v0.44 red team assessment)
# ---------------------------------------------------------------------------
#  All 16 findings from the v0.44 red team assessment addressed (M-1/M-4 deferred).
#  0 CRITICAL, 3 HIGH, 4 MEDIUM, 5 LOW, 4 INFORMATIONAL.
#
#  HIGH:
#  - H-1: Fleet dashboard MSAL SRI placeholder removed (was blocking script
#         load entirely). Deployment guide updated with hash generation steps.
#  - H-2: DMA port detection now includes USB4 in main scanner, matching
#         compliance/detect scripts. Prevents inconsistent results.
#  - H-3: Monitor integrity check now fails-closed when InstalledHash is
#         missing but Uninstall registry key exists (prevents bypass via
#         registry deletion).
#
#  MEDIUM:
#  - M-2: Detects PowerShell transcript logging GPO and warns prominently
#         about auth token persistence in transcript files.
#  - M-3: Azure blob URL construction uses [System.Uri] parser instead of
#         fragile string replacement that broke with encoded query params.
#  - M-5: Auto-shutdown timer is non-resettable. Idle timer only updated
#         on authenticated requests (prevents indefinite keepalive).
#  - M-6: Send-JsonResponse depth increased from 5 to 10 (matches Get-ScanJson).
#         Added truncation detection for fix response serialization.
#
#  LOW:
#  - L-1: Port parameter warns when outside recommended 1024-65535 range.
#  - L-2: Replaced deprecated RNGCryptoServiceProvider with
#         RandomNumberGenerator.Create() in all 4 locations.
#  - L-3: NVD query results filtered to BIOS/firmware/UEFI descriptions,
#         reducing false positives from unrelated vendor products.
#  - L-4: Fleet scan job timeout enforced via Wait-Job -Timeout 300.
#         Previously comment-only; hung machines no longer block batch.
#  - L-5: CSV export sanitizes formula injection chars (=, +, -, @, tab, CR)
#         with single-quote prefix across all 4 fleet CSV exports.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  v0.44 CHANGES - Security hardening (v0.43 red team assessment)
# ---------------------------------------------------------------------------
#  All 25 findings from the v0.43 red team assessment addressed.
#  0 CRITICAL, 4 HIGH, 9 MEDIUM, 8 LOW, 4 INFORMATIONAL.
#  No changes to scan logic or check catalogue.
#
#  HIGH:
#  - H-1: Fleet scan script now verifies script hash before remote execution
#         (-ExpectedHash parameter + remote integrity check).
#  - H-2: Azure blob upload sanitizes hostname to prevent path injection.
#  - H-3: MSAL CDN script tag now requires SRI integrity attribute.
#  - H-4: Compliance script replaced global SilentlyContinue with per-check
#         try/catch. Failed checks now report ERROR instead of false-compliant.
#
#  MEDIUM:
#  - M-1: Constant-time compare uses SHA256 hashing to prevent length leakage.
#  - M-2: DeviceGuard queried once per script (was twice in Tier 2 scripts).
#  - M-3: DMA port detection unified across all scripts (scanner/detect/comply).
#  - M-4: Auto-logon fix now clears DefaultPassword, DefaultUserName,
#         DefaultDomainName in both scanner and Intune remediation.
#  - M-5: Fleet dashboard uses textContent + attribute-safe escaping (EA()).
#  - M-6: MSAL cache moved to memoryStorage (prevents extension theft).
#  - M-7: Monitor mode logs successful integrity verifications.
#  - M-8: Remediation scripts verify SYSTEM/admin context before proceeding.
#  - M-9: NVD API response validated before property access.
#
#  LOW:
#  - L-1: Fix endpoint idle lock uses separate activity timestamp.
#  - L-2: Compliance policy expanded from 8 to 18 rules (was missing 10).
#  - L-3: Placeholder GitHub URLs replaced in CompliancePolicy.json.
#  - L-4: Confirmation codes increased from 4 digits to 6 digits.
#  - L-5: PS history overwritten with random bytes before truncation.
#  - L-6: CSV export escapes newlines in device names.
#  - L-7: BAT launcher loops on invalid input instead of defaulting.
#  - L-8: UTF-8 encoding artifacts removed from fleet-dashboard.html.

#
# ---------------------------------------------------------------------------
#  v0.43 CHANGES
# ---------------------------------------------------------------------------
#  - NEW CHECK: UAC credential prompt behaviour (ConsentPromptBehaviorAdmin).
#    Detects whether admin elevation requires password re-entry or just a
#    consent click. Fixable: sets prompt-for-credentials mode.
#  - NEW CHECK: Local admin account password presence. Detects enabled local
#    admin accounts with no password set, including the built-in Administrator
#    account which bypasses UAC entirely.
#  - NEW CHECK: Intel AMT provisioning status (informational). Detects whether
#    the Management Engine interface or Local Management Service is active.
#    AMT does NOT bypass authentication; this is awareness that remote
#    physical-equivalent access may be configured.
#  - Updated attack scenario mappings for evil-maid and coercion scenarios.
# ---------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------
#  LEGAL NOTICE, DISCLAIMER, AND LICENSE
# ---------------------------------------------------------------------------
#
#  SPDX-License-Identifier: BUSL-1.1
#
#  Copyright (c) 2026 HardTarget Contributors. All rights reserved.
#
#  Licensed under the Business Source License 1.1 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://mariadb.com/bsl11/
#
#  Licensor:             HardTarget Contributors
#  Licensed Work:        HardTarget - Windows Physical Security Scanner
#  Additional Use Grant: You may use, copy, and redistribute this
#                        software for non-commercial educational,
#                        research, internal security assessment, and
#                        personal use purposes. "Non-commercial" means
#                        use that is not intended for or directed toward
#                        commercial advantage or monetary compensation.
#  Change Date:          2030-02-01
#  Change License:       MIT License
#
#  On the Change Date, this software becomes available under the terms
#  of the MIT License. Until that date, all rights not expressly
#  granted above are reserved by the Licensor. Commercial use -
#  including but not limited to incorporation into paid products,
#  managed services, or consulting deliverables - requires a separate
#  written license from the copyright holder.
#
#  INTENDED AUDIENCE AND EXPERTISE REQUIREMENT
#  This software is intended exclusively for qualified security
#  professionals, system administrators, and IT personnel who possess
#  the technical expertise to understand, evaluate, and accept the
#  consequences of system-level configuration changes to Windows
#  operating systems. It is NOT designed, tested, or intended for use
#  by general consumers, end users, or non-technical personnel.
#
#  Before running this software, you MUST thoroughly review the source
#  code to understand what it does, how it works, and what changes it
#  may make to your system. You are responsible for determining whether
#  this software is appropriate for your environment, hardware, and use
#  case. If you do not have the technical expertise to review and
#  understand this code, DO NOT RUN IT.
#
#  DEFENSIVE PURPOSE ONLY
#  This software identifies and optionally remediates physical-access
#  attack surfaces on Windows systems. It is intended solely for
#  defensive security assessment, education, and the improvement of
#  protective measures by authorised administrators. It is not intended
#  to facilitate, encourage, or enable unauthorised access to any
#  system, device, or data. Users are responsible for ensuring that
#  their use of this software complies with all applicable laws,
#  including the Computer Fraud and Abuse Act (18 U.S.C. ss 1030),
#  the UK Computer Misuse Act 1990, and equivalent legislation in
#  other jurisdictions. Unauthorised access to computer systems is a
#  criminal offence in most jurisdictions regardless of the method used.
#
#  BETA SOFTWARE NOTICE
#  This software is in active development and has not been exhaustively
#  tested across all hardware configurations, Windows editions, Group
#  Policy environments, or third-party software combinations. Behaviour
#  may change between versions without notice. No representation is
#  made that this software is free of defects, errors, or security
#  vulnerabilities.
#
#  The fix engine (Expert mode) is published for source code review and
#  transparency purposes. It is not recommended for production use until
#  it has been thoroughly reviewed and independently tested by qualified
#  professionals. If you choose to use it despite this recommendation,
#  you do so entirely at your own risk and against our stated guidance.
#
#  NATURE OF THIS SOFTWARE
#  This tool modifies Windows system settings at the registry, service,
#  boot configuration, and scheduled task level. Specifically, it may:
#    - Write to HKLM and HKCU registry hives
#    - Disable or reconfigure Windows services
#    - Modify boot configuration data (bcdedit)
#    - Disable Windows Recovery Environment (reagentc)
#    - Disable hibernation, fast startup, and sleep modes
#    - Create scheduled tasks running as NT AUTHORITY\SYSTEM
#    - Make outbound HTTPS requests to the NIST NVD API
#    - Start a localhost-only HTTP server for the dashboard
#
#  These changes can affect system stability, boot capability, driver
#  compatibility, power management, crash diagnostics, and recovery
#  options. Some changes require a reboot and may be difficult or
#  impossible to reverse without advanced technical knowledge. Improper
#  use may render a system unbootable or require a full reinstallation
#  of the operating system.
#
#  DATA PROCESSING
#  This tool reads local system configuration data including but not
#  limited to: WMI objects, registry values, BitLocker status, TPM
#  state, PnP device enumeration, boot configuration, scheduled tasks,
#  power configuration, and user-profile artifacts (HKCU hives,
#  PowerShell history, network profiles, USB history, ShellBags). All
#  data is processed locally. No personal or system data is transmitted
#  to any external service except for one HTTPS request to the
#  NIST National Vulnerability Database (NVD) API for firmware CVE
#  lookup, which transmits only the BIOS vendor name and version string.
#  This request can be disabled with the -NoNVD switch for fully offline
#  operation. There is no telemetry, analytics, phone-home, or update
#  mechanism.
#
#  DISCLAIMER OF WARRANTY
#  THIS SOFTWARE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT
#  WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
#  TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
#  PURPOSE, ACCURACY, COMPLETENESS, AND NON-INFRINGEMENT. THE ENTIRE
#  RISK AS TO THE QUALITY, PERFORMANCE, AND RESULTS OF THIS SOFTWARE
#  REMAINS WITH YOU. NO ORAL OR WRITTEN INFORMATION OR ADVICE GIVEN BY
#  HARDTARGET CONTRIBUTORS SHALL CREATE A WARRANTY.
#
#  LIMITATION OF LIABILITY
#  IN NO EVENT SHALL ANY AUTHOR, COPYRIGHT HOLDER, CONTRIBUTOR,
#  AFFILIATE, MAINTAINER, OR LICENSOR OF THIS SOFTWARE (COLLECTIVELY,
#  "HARDTARGET CONTRIBUTORS") BE LIABLE FOR ANY DIRECT, INDIRECT,
#  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING
#  BUT NOT LIMITED TO: PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#  LOSS OF USE, DATA, OR PROFITS; BUSINESS INTERRUPTION; SYSTEM
#  FAILURE; BOOT FAILURE; LOSS OF FUNCTIONALITY; REGISTRY CORRUPTION;
#  DATA LOSS; SECURITY INCIDENTS; REGULATORY FINES OR PENALTIES; LEGAL
#  FEES; REPUTATIONAL DAMAGE; OR DECISIONS MADE IN RELIANCE ON SCAN
#  RESULTS) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF OR INABILITY TO USE
#  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#  THIS LIMITATION APPLIES TO THE FULLEST EXTENT PERMITTED BY
#  APPLICABLE LAW. IN JURISDICTIONS THAT DO NOT PERMIT THE EXCLUSION
#  OR LIMITATION OF LIABILITY FOR CONSEQUENTIAL OR INCIDENTAL DAMAGES,
#  THE LIABILITY OF HARDTARGET CONTRIBUTORS SHALL BE LIMITED TO THE
#  MAXIMUM EXTENT PERMITTED BY LAW.
#
#  NOT PROFESSIONAL ADVICE
#  This tool is not a substitute for professional security assessment,
#  penetration testing, compliance auditing, or expert consultation.
#  No guarantee of security is made or implied. A passing scan does
#  not mean your system is secure. A failing scan does not mean your
#  system is insecure. Scan results should not be submitted to
#  auditors, assessors, or regulators as evidence of compliance
#  without independent verification by qualified professionals. Scan
#  results should not be relied upon as the sole basis for any
#  security, procurement, or policy decision.
#
#  INDEMNIFICATION
#  By using, copying, or redistributing this software, you agree to
#  indemnify, defend, and hold harmless all HardTarget Contributors
#  (as defined above) from and against any and all claims, damages,
#  losses, liabilities, costs, and expenses (including reasonable
#  legal fees) arising out of or related to: (a) your use of or
#  reliance on this software or its output; (b) your violation of any
#  applicable law, regulation, or third-party right; (c) any action
#  you take or fail to take based on the scan results or remediation
#  actions of this software; (d) your redistribution of this software
#  to third parties; or (e) any claim by a third party related to
#  your use of or reliance on this software.
#
#  ASSUMPTION OF RISK AND ACCEPTANCE
#  By running this software, you acknowledge and represent that:
#  (a) you have read and understood this entire notice; (b) you have
#  the technical expertise to evaluate the source code and understand
#  the consequences of the operations it performs; (c) you have
#  reviewed the source code to your satisfaction before execution;
#  (d) you are authorised to make system-level changes to this
#  computer; (e) you accept full responsibility for any and all
#  consequences of using this tool; and (f) you understand that no
#  HardTarget Contributor has any obligation to provide support,
#  maintenance, updates, or assistance of any kind.
#
#  TRADEMARKS
#  Windows, BitLocker, Microsoft, Thunderbolt, and Intel are trademarks
#  of their respective owners. AMD and Ryzen are trademarks of Advanced
#  Micro Devices, Inc. All other trademarks referenced herein are the
#  property of their respective owners. Use of these names is for
#  identification purposes only and does not imply endorsement,
#  sponsorship, or affiliation.
# ---------------------------------------------------------------------------

[CmdletBinding()]
param(
    [switch]$Monitor,       # Background mode: skip NVD, diff baseline, alert only on changes
    [switch]$Install,       # Register hourly scheduled task
    [switch]$Uninstall,     # Remove scheduled task
    [switch]$Status,        # Show monitoring status
    [switch]$DryRun,        # Show what each fix would do without applying
    [switch]$Audit,         # Scan + JSON only. No dashboard, no server, no fix engine.
    [switch]$ReadOnly,      # Dashboard + scan but no fix engine (audit mode)
    [switch]$NoNVD,         # Skip NIST NVD firmware CVE lookup (no outbound network requests)
    [switch]$Version,       # Print version and exit
    [string]$OutputDir,     # Override output directory (default: ProgramData\HardTarget)
    [int]$Port,             # Override server port (default: auto-select from 8080-8085, 9090-9091)
    # Internal: self-elevation parameters (set automatically, not for user use)
    # SECURITY (v0.76): These are now set by the in-memory bootstrapper, not by
    # -File command-line invocation. The bootstrapper is Base64-encoded into
    # -EncodedCommand and locked into the AppInfo RPC before the UAC prompt.
    # The elevated process receives the script content via named pipe and verifies
    # its hash against the value hardcoded in the bootstrapper before executing.
    # HtHash serves as both: (a) the integrity check hash that the bootstrapper
    # verified, and (b) a flag indicating this is a bootstrapper-elevated session.
    [string]$HtMode,        # 'audit', 'expert', 'report' -- set by bootstrapper
    [string]$HtHash         # SHA256 verified by bootstrapper before execution
)

Set-StrictMode -Version Latest

# SECURITY (v0.79): Detect .NET CLR profiler injection.
# If COR_ENABLE_PROFILING=1, the CLR has already loaded an attacker-controlled DLL
# into this process before any PowerShell code ran. We cannot unload it, but we can
# detect it and refuse to continue. For the UAC bootstrapper path, the non-elevated
# process strips these variables before calling Start-Process (so the elevated process
# never sees them). This check catches the already-elevated path: an admin running
# from a poisoned console, SCCM deployment with inherited env, etc.
if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($env:COR_ENABLE_PROFILING -eq '1' -or $env:CORECLR_ENABLE_PROFILING -eq '1') {
        Write-Host '' -ForegroundColor Red
        Write-Host '  SECURITY ABORT: .NET CLR profiler is active in this process.' -ForegroundColor Red
        Write-Host '  COR_ENABLE_PROFILING or CORECLR_ENABLE_PROFILING is set to 1.' -ForegroundColor Red
        Write-Host '  An attacker may have injected a DLL via profiler hijacking.' -ForegroundColor Red
        Write-Host '  Run HardTarget from a clean environment (new cmd/PowerShell window).' -ForegroundColor Red
        Write-Host ''
        Read-Host '  Press Enter to exit'
        exit 1
    }
}

# SECURITY (v0.77): Sever user environment trust boundary when elevated.
# UAC elevation inherits the standard user's HKCU registry hive and environment.
# An attacker can poison HKCU\Environment\PSModulePath with a directory containing
# a malicious module. PowerShell's auto-loader will implicitly execute it the first
# time the elevated process calls a cmdlet that triggers module discovery.
# Similarly, HKCU\Environment\PATH can be poisoned to shadow system binaries.
# All binary calls already use fully qualified $script:Bin paths (v0.53), but
# scrubbing PATH provides defense-in-depth for any implicit resolution.
# Fix: Replace PSModulePath and PATH with machine-scope only, removing all
# user-controlled directories. Only applied when elevated.
if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
    $env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
}

# SECURITY (v0.61): Hard abort if running as 32-bit PowerShell on a 64-bit OS.
# When launched from a 32-bit parent process (e.g., 32-bit SCCM agent), Windows
# silently redirects System32 to SysWOW64, running 32-bit PowerShell. In WOW64
# mode, all HKLM:\SOFTWARE reads are redirected to the WOW6432Node registry view.
# Every security check will read wrong data and every fix will write to a location
# the OS ignores. The BAT launcher handles this via sysnative, but if someone runs
# the PS1 directly from a 32-bit context, we must abort immediately.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Write-Host ''
    Write-Host '  FATAL: Running as 32-bit PowerShell on a 64-bit OS.' -ForegroundColor Red
    Write-Host '  Registry reads will be redirected to WOW6432Node (wrong data).' -ForegroundColor Red
    Write-Host '  Registry writes will land in WOW6432Node (ignored by OS).' -ForegroundColor Red
    Write-Host ''
    Write-Host '  Use RUN_HardTarget.bat or launch from 64-bit PowerShell:' -ForegroundColor Yellow
    Write-Host '    %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe' -ForegroundColor Yellow
    Write-Host ''
    Read-Host '  Press Enter to exit'
    exit 1
}

# -Version: print version string and exit immediately
if ($Version) {
    Write-Host 'HardTarget v0.83'
    exit 0
}

# ============================================================================
#  SECURITY (v0.74): PATH CANONICALIZATION
#  Resolves the script's own path through any directory junctions or symlinks
#  to the final filesystem target BEFORE applying FileStream locks or passing
#  the path to elevated processes.
#
#  The problem (v0.57-v0.73): FileStream natively follows reparse points. If
#  $selfPath contains a directory junction, the lock targets the REAL file, but
#  the junction itself remains swappable. Attacker can delete the junction and
#  replace it with a directory containing a malicious script. Start-Process
#  resolves the NEW path and executes the attacker's file. The lock and hash
#  check are completely bypassed because the elevated PowerShell loads the
#  attacker's script (which has no hash check) instead of the legitimate one.
#
#  The fix: Use GetFinalPathNameByHandle to resolve through all reparse points
#  at the kernel level. The resolved path points directly to the real file on
#  disk, not through any junctions. All subsequent operations (lock, hash,
#  Start-Process, Install-HardTargetMonitor) use this canonical path.
#  Fallback: walk each directory component and abort if any is a reparse point.
# ============================================================================
function Resolve-CanonicalScriptPath {
    param(
        [string]$RawPath,
        # SECURITY (v0.75): When -Lock is specified, the native handle is kept open
        # and wrapped in SafeFileHandle -> FileStream. The caller receives BOTH the
        # resolved canonical path AND a locked read-only stream from the SAME handle.
        # This eliminates the TOCTOU gap in v0.74 where the handle was closed after
        # resolution, allowing an attacker to swap a junction in the microsecond gap
        # before FileStream::new opened a NEW handle on the returned string path.
        # The kernel lock prevents renaming/deleting the file AND its parent directory
        # (STATUS_SHARING_VIOLATION), neutralizing junction swap attacks entirely.
        [switch]$Lock
    )
    if (-not $RawPath) { return $null }
    $fullPath = [System.IO.Path]::GetFullPath($RawPath)

    # Attempt 1: P/Invoke GetFinalPathNameByHandle (resolves ALL reparse points)
    # SECURITY (v0.74): Uses Reflection.Emit to define P/Invoke methods in a dynamic
    # in-memory assembly. This NEVER touches disk -- no csc.exe, no temp .cs files.
    # The previous Add-Type approach compiled C# via csc.exe which writes temp files
    # to the Temp folder. When running as SYSTEM, an attacker can oplock the Temp
    # folder, pause the SYSTEM thread when the .cs file is written, inject malicious
    # C# code, release the lock, and get their payload compiled into SYSTEM context.
    try {
        if (-not ([System.Management.Automation.PSTypeName]'HtKernel32').Type) {
            $asmName = New-Object System.Reflection.AssemblyName('HtDynPInvoke')
            $asmBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($asmName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $modBuilder = $asmBuilder.DefineDynamicModule('HtDynModule')
            $typeBuilder = $modBuilder.DefineType('HtKernel32', [System.Reflection.TypeAttributes]::Public -bor [System.Reflection.TypeAttributes]::Abstract -bor [System.Reflection.TypeAttributes]::Sealed)

            # CreateFileW(string, uint, uint, IntPtr, uint, uint, IntPtr) -> IntPtr
            $cfm = $typeBuilder.DefinePInvokeMethod(
                'CreateFileW', 'kernel32.dll',
                ([System.Reflection.MethodAttributes]::Public -bor [System.Reflection.MethodAttributes]::Static -bor [System.Reflection.MethodAttributes]::PinvokeImpl),
                [System.Reflection.CallingConventions]::Standard,
                [IntPtr],
                @([String], [UInt32], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr]),
                [System.Runtime.InteropServices.CallingConvention]::Winapi,
                [System.Runtime.InteropServices.CharSet]::Unicode
            )
            $cfm.SetImplementationFlags([System.Reflection.MethodImplAttributes]::PreserveSig)

            # GetFinalPathNameByHandleW(IntPtr, StringBuilder, uint, uint) -> uint
            $gfm = $typeBuilder.DefinePInvokeMethod(
                'GetFinalPathNameByHandleW', 'kernel32.dll',
                ([System.Reflection.MethodAttributes]::Public -bor [System.Reflection.MethodAttributes]::Static -bor [System.Reflection.MethodAttributes]::PinvokeImpl),
                [System.Reflection.CallingConventions]::Standard,
                [UInt32],
                @([IntPtr], [System.Text.StringBuilder], [UInt32], [UInt32]),
                [System.Runtime.InteropServices.CallingConvention]::Winapi,
                [System.Runtime.InteropServices.CharSet]::Unicode
            )
            $gfm.SetImplementationFlags([System.Reflection.MethodImplAttributes]::PreserveSig)

            # CloseHandle(IntPtr) -> bool
            $chm = $typeBuilder.DefinePInvokeMethod(
                'CloseHandle', 'kernel32.dll',
                ([System.Reflection.MethodAttributes]::Public -bor [System.Reflection.MethodAttributes]::Static -bor [System.Reflection.MethodAttributes]::PinvokeImpl),
                [System.Reflection.CallingConventions]::Standard,
                [Bool],
                @([IntPtr]),
                [System.Runtime.InteropServices.CallingConvention]::Winapi,
                [System.Runtime.InteropServices.CharSet]::Auto
            )
            $chm.SetImplementationFlags([System.Reflection.MethodImplAttributes]::PreserveSig)

            $null = $typeBuilder.CreateType()
        }

        # Share mode: if -Lock, FILE_SHARE_READ only (blocks writers/deleters/renamers).
        # If path-only, FILE_SHARE_READ|WRITE|DELETE (non-blocking, just for resolution).
        $shareMode = if ($Lock) { [uint32]1 } else { [uint32]7 }
        # GENERIC_READ=0x80000000 (must use decimal 2147483648 because PowerShell parses
        # hex literals as signed Int32, and 0x80000000 overflows to -2147483648 which
        # cannot be cast to UInt32). OPEN_EXISTING=3, FILE_FLAG_BACKUP_SEMANTICS=0x02000000.
        $GENERIC_READ = [uint32]2147483648
        $handle = [HtKernel32]::CreateFileW($fullPath, $GENERIC_READ, $shareMode, [IntPtr]::Zero, [uint32]3, [uint32]0x02000000, [IntPtr]::Zero)
        if ($handle -ne [IntPtr]::new(-1)) {
            $resolved = $null
            try {
                # SECURITY (v0.75): Buffer size 32767 = Windows MAX_PATH for extended-length paths.
                # Previous 1024-char buffer silently failed on deep directory structures,
                # falling through to the TOCTOU-vulnerable degraded heuristic mode.
                $sb = New-Object System.Text.StringBuilder(32767)
                $r = [HtKernel32]::GetFinalPathNameByHandleW($handle, $sb, [uint32]32767, [uint32]0)
                if ($r -gt 0 -and $r -lt 32767) {
                    $resolved = $sb.ToString()
                    # SECURITY (v0.75): Handle UNC paths correctly. GetFinalPathNameByHandleW
                    # returns \\?\UNC\server\share\path for network shares. Blindly stripping
                    # 4 chars yields UNC\server\share\path -- a RELATIVE path that PowerShell
                    # resolves against CWD. An attacker creates matching directory structure
                    # under CWD with a malicious script. Elevated process executes it.
                    if ($resolved.StartsWith('\\?\UNC\')) {
                        $resolved = '\\' + $resolved.Substring(8)
                    # SECURITY (v0.75): Volume GUID paths. On volumes without drive letters,
                    # GetFinalPathNameByHandleW returns \\?\Volume{GUID}\path. Stripping \\?\
                    # yields Volume{GUID}\path -- another RELATIVE path, same class as UNC.
                    # Keep the \\?\ prefix intact; it IS the canonical absolute form.
                    } elseif ($resolved.StartsWith('\\?\Volume{')) {
                        # No transformation needed -- \\?\Volume{GUID}\path is already absolute.
                    } elseif ($resolved.StartsWith('\\?\')) {
                        $resolved = $resolved.Substring(4)
                    }
                }
            } catch {
                $null = [HtKernel32]::CloseHandle($handle)
                throw
            }

            if ($resolved) {
                if ($Lock) {
                    # SECURITY (v0.75): Wrap the SAME handle in SafeFileHandle -> FileStream.
                    # The handle is never closed -- the FileStream now owns it ($ownsHandle=true).
                    # Resolution and locking are atomic: the same kernel handle that resolved
                    # the path IS the handle that holds the lock. No TOCTOU gap.
                    $safeHandle = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($handle, $true)
                    $lockFs = New-Object System.IO.FileStream($safeHandle, [System.IO.FileAccess]::Read)
                    return @{
                        Path   = $resolved
                        Stream = $lockFs
                    }
                } else {
                    $null = [HtKernel32]::CloseHandle($handle)
                    return $resolved
                }
            } else {
                $null = [HtKernel32]::CloseHandle($handle)
            }
        }
        # SECURITY (v0.75): If -Lock was specified and we reach this point, native
        # resolution failed WITHOUT throwing an exception (CreateFileW returned
        # INVALID_HANDLE_VALUE, or GetFinalPathNameByHandleW returned 0/$null).
        # Success paths hit 'return' above and never reach here.
        # An attacker can hold FILE_SHARE_NONE on the script to force CreateFileW
        # failure, degrading to the TOCTOU-vulnerable Attempt 2 fallback.
        # Fail closed: do not allow degradation on the security-critical path.
        if ($Lock) {
            Write-Host '' -ForegroundColor Red
            Write-Host '  SECURITY ABORT: Native file lock or resolution failed.' -ForegroundColor Red
            Write-Host '  An attacker may be holding an exclusive lock to force degradation.' -ForegroundColor Red
            Write-Host "  Path: $fullPath" -ForegroundColor Yellow
            Write-Host ''
            Read-Host '  Press Enter to exit'
            exit 1
        }
    } catch {
        # Reflection.Emit failed -- likely CLM, .NET profiler injection, or constrained runtime.
        # SECURITY (v0.75): If -Lock is specified, this is a security-critical path for BOTH
        # the non-elevated launcher AND the elevated process. The non-elevated process generates
        # the pre-elevation hash that the elevated process trusts. If the non-elevated process
        # degrades to the managed fallback, an attacker can exploit the TOCTOU gap to spoof
        # the hash of a malicious payload. The elevated process (where UAC strips user-level
        # env vars like COR_PROFILER) may then succeed with native APIs, resolve through the
        # attacker's junction, match the spoofed hash, and execute the payload as Admin.
        # This is an asymmetric trust boundary violation: the source of truth (non-elevated)
        # must use the same strict primitives as the consumer (elevated).
        # FIX: Fail closed regardless of elevation state. No asymmetric enforcement.
        if ($Lock) {
            Write-Host '' -ForegroundColor Red
            Write-Host '  SECURITY ABORT: Native path canonicalization unavailable.' -ForegroundColor Red
            Write-Host '  Cannot safely lock the execution path.' -ForegroundColor Red
            Write-Host '  Possible causes: Constrained Language Mode, .NET profiler injection,' -ForegroundColor Red
            Write-Host '  or severely constrained runtime. Check __PSLockdownPolicy, COR_PROFILER,' -ForegroundColor Red
            Write-Host '  and WDAC/AppLocker policies.' -ForegroundColor Red
            Write-Host "  Error: $_" -ForegroundColor Yellow
            Write-Host ''
            Read-Host '  Press Enter to exit'
            exit 1
        }
    }

    # Attempt 2: Walk directory components checking for reparse points (fail-closed)
    # If any component is a reparse point, we cannot safely resolve through it
    # without P/Invoke. Abort rather than trust a junction-based path.
    $current = $fullPath
    $components = @()
    while ($current) {
        $components += $current
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
    foreach ($component in $components) {
        try {
            $attrs = [System.IO.File]::GetAttributes($component)
            if ($attrs -band [System.IO.FileAttributes]::ReparsePoint) {
                Write-Host '' -ForegroundColor Red
                Write-Host "  SECURITY ABORT: Script path contains a reparse point (junction/symlink):" -ForegroundColor Red
                Write-Host "    $component" -ForegroundColor Yellow
                Write-Host "  Cannot safely resolve the canonical path without native API support." -ForegroundColor Red
                Write-Host "  Copy the script to a normal directory and re-run." -ForegroundColor Red
                Write-Host ''
                Read-Host '  Press Enter to exit'
                exit 1
            }
        } catch {
            # Component doesn't exist or access denied -- let downstream handle it
        }
    }
    # No reparse points found in any path component. If -Lock, open a FileStream
    # on the verified path. This is NOT as strong as the P/Invoke path (the check
    # and open are not atomic), but the reparse-point check means no junctions exist
    # to swap. An attacker would need to CREATE a junction after our check, which
    # requires renaming an existing directory component -- blocked by NTFS if we
    # open the file quickly.
    if ($Lock) {
        try {
            $fallbackFs = [System.IO.FileStream]::new(
                $fullPath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read
            )
            return @{
                Path   = $fullPath
                Stream = $fallbackFs
            }
        } catch {
            Write-Host "  SECURITY ABORT: Cannot lock script file: $_" -ForegroundColor Red
            Read-Host '  Press Enter to exit'
            exit 1
        }
    }
    return $fullPath
}

# ============================================================================
#  SECURITY (v0.76): IN-MEMORY SELF-ELEVATION VIA BOOTSTRAPPER + NAMED PIPE
#  Replaces the v0.57-v0.75 FileStream lock approach, which was vulnerable to
#  handle theft: a same-user attacker uses DuplicateHandle(DUPLICATE_CLOSE_SOURCE)
#  to rip the lock from the non-elevated process (same SID = PROCESS_DUP_HANDLE
#  access), swaps the script file, and the elevated process executes attacker
#  code that simply ignores the -HtHash parameter.
#
#  The new flow eliminates disk from the elevated process entirely:
#  1. Non-elevated PS1 shows the interactive menu (if no mode specified)
#  2. Atomically resolves AND locks own path via Resolve-CanonicalScriptPath -Lock
#  3. Reads entire script into memory from the locked stream
#  4. Releases the lock (content is in memory; disk file is irrelevant)
#  5. Computes SHA256 of the in-memory content
#  6. Creates an admin-only named pipe (maxInstances=1, Administrators ACL)
#  7. Generates a tiny bootstrapper script containing the pipe name and expected
#     hash as string literals. Encodes it as Base64 for -EncodedCommand.
#  8. Calls Start-Process -Verb RunAs -ArgumentList "-EncodedCommand $base64"
#     The encoded bootstrapper is locked into the AppInfo RPC at this moment.
#  9. After UAC approval, the elevated process runs the immutable bootstrapper.
#     The bootstrapper connects to the named pipe, reads the script content,
#     computes SHA256, compares to the hardcoded expected hash.
#  10. If match: executes the script from memory via [scriptblock]::Create()
#  11. If mismatch: hard abort (pipe content was tampered)
#
#  This is airtight because:
#  - The attacker cannot manipulate the bootstrapper (locked in AppInfo RPC)
#  - The attacker cannot manipulate the pipe content (hash check catches it)
#  - The attacker cannot connect to the pipe (admin-only ACL + maxInstances=1)
#  - The attacker cannot swap the disk file to any effect (elevated never reads it)
#  - If the attacker kills the non-elevated process, the pipe breaks and the
#    bootstrapper exits gracefully on connection timeout
# ============================================================================

# SECURITY (v0.78): Never derive security-critical execution paths from $env:SystemRoot.
# Standard users can set their own process environment variables. An attacker sets
# SystemRoot=C:\FakeWindows, copies the real powershell.exe there, and plants a
# side-loadable DLL next to it. Start-Process -Verb RunAs launches the attacker's
# path, the real signed binary loads the malicious DLL, and the attacker gets admin.
# SECURITY (v0.81): Use the native shell API via GetFolderPath instead of the Machine
# registry scope. Windows does not reliably store SystemRoot in HKLM\...\Environment
# on all configurations; GetFolderPath calls the Win32 shell API which always resolves
# correctly, including on systems where the OS is installed on a non-standard drive.
$script:TrustedSystemRoot = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::Windows)
if (-not $script:TrustedSystemRoot) {
    $script:TrustedSystemRoot = 'C:\Windows'
}
$script:PsExeFull = Join-Path $script:TrustedSystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

# SECURITY (v0.81): Same trust boundary for ProgramData. Standard users can poison
# $script:TrustedProgramData to redirect the monitor data directory, scheduled task scripts,
# and auth token storage to an attacker-controlled location. The attacker owns the
# parent directory and can swap contents after Initialize-SecureDirectory runs.
# GetFolderPath uses the shell API to resolve the real CommonApplicationData path.
$script:TrustedProgramData = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)
if (-not $script:TrustedProgramData) {
    $script:TrustedProgramData = 'C:\ProgramData'
}
# SECURITY (v0.83): Derive SystemDrive from trusted root, not $env:SystemDrive.
# AppInfo merges HKCU\Environment into elevated processes; a poisoned $env:SystemDrive
# would redirect BitLocker, hibernation, and user profile operations.
$script:TrustedSystemDrive = $script:TrustedSystemRoot.Substring(0, 2)

# --- STEP A: If we were relaunched elevated via in-memory bootstrapper, accept verified state ---
if ($HtHash) {
    # SECURITY (v0.76): In-memory elevation. The bootstrapper (launched via
    # -EncodedCommand, immutably locked in AppInfo RPC) already verified the
    # pipe content hash before executing this script. This code is running
    # from memory -- the disk file was never read by this elevated process.
    if ($global:HtVerifiedContent) {
        $script:ScriptPath = $global:HtSourcePath
        $script:VerifiedScriptBytes = $global:HtVerifiedContent
        # Clean up globals set by bootstrapper
        Remove-Variable -Name HtVerifiedContent -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name HtSourcePath -Scope Global -ErrorAction SilentlyContinue
    }
    else {
        # HtHash was passed without bootstrapper context. Someone manually invoked
        # the script with -HtHash, which is not a valid elevation path. Abort.
        Write-Host '' -ForegroundColor Red
        Write-Host '  SECURITY ABORT: -HtHash specified without in-memory bootstrapper.' -ForegroundColor Red
        Write-Host '  This parameter is internal to the elevation mechanism.' -ForegroundColor Red
        Write-Host '  If you are running from an elevated prompt, omit -HtHash.' -ForegroundColor Red
        Write-Host ''
        Read-Host '  Press Enter to exit'
        exit 1
    }
    # Map HtMode to the appropriate switch
    switch ($HtMode) {
        'audit'  { $ReadOnly = $true }
        'report' { $Audit = $true }
        'expert' { }
    }
}

# Global trap: pause on unhandled errors so the elevated window doesn't vanish.
# Only hard-exits in the elevated child process (identified by HtHash being set).
# In the non-elevated launcher, continues normally after displaying the error.
trap {
    if ($HtHash) {
        Write-Host '' -ForegroundColor Red
        Write-Host "  UNHANDLED ERROR: $_" -ForegroundColor Red
        Write-Host "  at line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -ForegroundColor Yellow
        Read-Host '  Press Enter to exit'
        exit 1
    }
    continue
}

# --- STEP B: If no mode specified, show interactive menu and self-elevate ---
# SECURITY (v0.82): If -Install or -Uninstall is specified without elevation,
# trigger self-elevation. Previously these parameters skipped the menu and the
# entire elevation block, causing silent failures from unprivileged context.
$needsElevationForParam = (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) -and ($Install -or $Uninstall)

if ($needsElevationForParam) {
    Write-Host '     Requesting administrator privileges for operation...'
    Write-Host ''
    $selfPath = $PSCommandPath
    if (-not $selfPath) { $selfPath = $MyInvocation.MyCommand.Path }
    $resolved = Resolve-CanonicalScriptPath $selfPath -Lock
    if (-not $resolved -or -not $resolved.Path) {
        Write-Host '     SECURITY ABORT: Cannot determine canonical script path.' -ForegroundColor Red
        exit 1
    }
    $lockFs = $resolved.Stream
    try {
        $scriptBytes = [byte[]]::new($lockFs.Length)
        $lockFs.Read($scriptBytes, 0, $scriptBytes.Length) | Out-Null
    }
    finally { if ($lockFs) { $lockFs.Dispose() } }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hashBytes = $sha.ComputeHash($scriptBytes); $preHash = -join ($hashBytes | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha.Dispose() }
    $paramMode = if ($Install) { 'install' } else { 'uninstall' }
    # SECURITY (v0.83): Forward user-provided parameters across UAC boundary.
    # Without this, -OutputDir and -Port are silently dropped during elevation.
    $extras = ''
    if ($OutputDir) { $extras += " -OutputDir '$($OutputDir -replace "'","''")'" }
    if ($Port) { $extras += " -Port $Port" }
    # Reuse the same bootstrapper+pipe mechanism as the menu path
    $pipeName = 'HT_' + ([System.IO.Path]::GetRandomFileName() -replace '\.','')
    # (Pipe creation with ACL is identical to STEP B menu path below)
    $pipeServer = $null
    try {
        $pipeSecurity = New-Object System.IO.Pipes.PipeSecurity
        $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $creatorSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $pipeSecurity.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($adminSid, [System.IO.Pipes.PipeAccessRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)))
        # SECURITY (v0.83): Creator gets FullControl MINUS ReadData. ReadData grants
        # client connection rights — any same-SID malware could connect and consume
        # the single pipe instance (DoS) or receive the script bytes.
        $serverOnly = [System.IO.Pipes.PipeAccessRights]::FullControl -band (-bnot [System.IO.Pipes.PipeAccessRights]::ReadData)
        $pipeSecurity.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($creatorSid, $serverOnly, [System.Security.AccessControl.AccessControlType]::Allow)))
        $pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::Out, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::None, 0, 0, $pipeSecurity)
    } catch {
        $pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::Out, 1)
        try {
            $ps = New-Object System.IO.Pipes.PipeSecurity
            $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($adminSid, [System.IO.Pipes.PipeAccessRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)))
            $sOnly = [System.IO.Pipes.PipeAccessRights]::FullControl -band (-bnot [System.IO.Pipes.PipeAccessRights]::ReadData)
            $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($creatorSid, $sOnly, [System.Security.AccessControl.AccessControlType]::Allow)))
            $pipeServer.SetAccessControl($ps)
        } catch {
            # SECURITY (v0.83): Cannot apply ACL — abort rather than leaving pipe
            # unrestricted. Hash verification alone does not prevent DoS via pipe theft.
            $pipeServer.Dispose(); $pipeServer = $null
            throw "SECURITY ABORT: Cannot create named pipe with restrictive ACL. Elevation requires PS 5.1 or PS 7.4+."
        }
    }
    try {
        $bootstrapper = @'
$env:PSModulePath=[Environment]::GetEnvironmentVariable('PSModulePath','Machine')
$env:PATH=[Environment]::GetEnvironmentVariable('PATH','Machine')
$p=[IO.Pipes.NamedPipeClientStream]::new('.','~~PIPE~~',[IO.Pipes.PipeDirection]::In,[IO.Pipes.PipeOptions]::None,[Security.Principal.TokenImpersonationLevel]::Anonymous)
$p.Connect(30000)
$ms=[IO.MemoryStream]::new()
$p.CopyTo($ms)
$p.Dispose()
$b=$ms.ToArray()
$ms.Dispose()
$sha=[Security.Cryptography.SHA256]::Create()
$h=-join($sha.ComputeHash($b)|%{$_.ToString('x2')})
$sha.Dispose()
if($h-ne'~~HASH~~'){Write-Host "`n  SECURITY ABORT: Pipe content integrity check failed." -ForegroundColor Red;exit 1}
$s=[Text.Encoding]::UTF8.GetString($b)
if($s.Length -gt 0 -and $s[0]-eq[char]65279){$s=$s.Substring(1)}
$global:HtVerifiedContent=$b
$global:HtSourcePath='~~PATH~~'
$sb=[scriptblock]::Create($s)
& $sb -~~PARAM~~ -HtHash '~~HASH~~'~~EXTRAS~~
'@
        $bootstrapper = $bootstrapper.Replace('~~PIPE~~', $pipeName).Replace('~~HASH~~', $preHash).Replace('~~PATH~~', ($resolved.Path -replace "'","''")).Replace('~~PARAM~~', $paramMode).Replace('~~EXTRAS~~', $extras)
        $cmdBytes = [System.Text.Encoding]::Unicode.GetBytes($bootstrapper)
        $encodedCmd = [Convert]::ToBase64String($cmdBytes)
        $cmdExe = Join-Path $script:TrustedSystemRoot 'System32\cmd.exe'
        $innerArgs = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCmd"
        # SECURITY (v0.83): No trailing spaces before '&' — cmd.exe includes them
        # in the variable value, causing .NET Core to parse " " as an assembly path.
        $scrubVars = 'set COR_ENABLE_PROFILING=&set COR_PROFILER=&set COR_PROFILER_PATH=&set CORECLR_ENABLE_PROFILING=&set CORECLR_PROFILER=&set CORECLR_PROFILER_PATH=&set _NT_SYMBOL_PATH=&set DOTNET_STARTUP_HOOKS=&set DOTNET_ADDITIONAL_DEPS=&set __PSLockdownPolicy='
        $cmdArgs = "/d /c `"$scrubVars& `"$($script:PsExeFull)`" $innerArgs`""
        $proc = Start-Process -FilePath $cmdExe -ArgumentList $cmdArgs -Verb RunAs -PassThru
        $pipeServer.WaitForConnection()
        $pipeServer.Write($scriptBytes, 0, $scriptBytes.Length)
        $pipeServer.Flush()
        $pipeServer.WaitForPipeDrain()
        $pipeServer.Dispose()
        $pipeServer = $null
        $proc.WaitForExit()
    }
    catch {
        if ($_.Exception.Message -match 'canceled by the user') { Write-Host '     UAC elevation was cancelled.' -ForegroundColor Yellow }
        else { Write-Host "     Elevation failed: $_" -ForegroundColor Red }
    }
    finally { if ($pipeServer) { $pipeServer.Dispose() } }
    exit 0
}

$needsMenu = (-not $Monitor -and -not $Install -and -not $Uninstall -and -not $Status `
    -and -not $Audit -and -not $ReadOnly -and -not $DryRun -and -not $HtMode)

if ($needsMenu) {
    # Show banner
    $host.UI.RawUI.WindowTitle = 'HardTarget v0.83'
    Write-Host ''
    Write-Host '     +-----------------------------------------------------------+'
    Write-Host '     |                                                           |'
    Write-Host '     |     __ __            ________                   __        |'
    Write-Host '     |    / // /__ ________/ /_  __/__ _______ ____ __/ /_       |'
    Write-Host '     |   / _  / _ `/ __/ _  / / / / _ `/ __/ _ `/ -_) __/        |'
    Write-Host '     |  /_//_/\_,_/_/  \_,_/ /_/  \_,_/_/  \_, /\__/\__/         |'
    Write-Host '     |                                    /___/          v0.83   |'
    Write-Host '     |                                                           |'
    Write-Host '     |     Windows Physical Security Scanner                     |'
    Write-Host '     |                                                           |'
    Write-Host '     +-----------------------------------------------------------+'
    Write-Host ''
    Write-Host '     +-----------------------------------------------------------+'
    Write-Host '     |  IMPORTANT NOTICE - FOR QUALIFIED EXPERTS ONLY            |'
    Write-Host '     +-----------------------------------------------------------+'
    Write-Host '     |                                                           |'
    Write-Host '     |  This is BETA SOFTWARE under active development.          |'
    Write-Host '     |  It has not been exhaustively tested across all           |'
    Write-Host '     |  hardware and software configurations.                    |'
    Write-Host '     |                                                           |'
    Write-Host '     |  THIS SOFTWARE IS INTENDED EXCLUSIVELY FOR                |'
    Write-Host '     |  QUALIFIED SECURITY PROFESSIONALS AND SYSTEM              |'
    Write-Host '     |  ADMINISTRATORS. It is NOT designed for general           |'
    Write-Host '     |  consumers or end users. You MUST review the              |'
    Write-Host '     |  source code before running it. If you lack the           |'
    Write-Host '     |  expertise to understand what this tool does at           |'
    Write-Host '     |  the registry and system level, DO NOT PROCEED.           |'
    Write-Host '     |                                                           |'
    Write-Host '     |  This tool can modify Windows system settings             |'
    Write-Host '     |  including registry values, boot configuration,           |'
    Write-Host '     |  services, and scheduled tasks. These changes             |'
    Write-Host '     |  can affect system stability, boot capability,            |'
    Write-Host '     |  and functionality. Improper use may render a             |'
    Write-Host '     |  system unbootable.                                       |'
    Write-Host '     |                                                           |'
    Write-Host '     |  The fix engine (Expert mode) is published for            |'
    Write-Host '     |  source code review only and is NOT RECOMMENDED           |'
    Write-Host '     |  for use until independently reviewed and                 |'
    Write-Host '     |  tested. Use at your own risk.                            |'
    Write-Host '     |                                                           |'
    Write-Host '     |  THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT                |'
    Write-Host '     |  WARRANTY OF ANY KIND. See HardTarget.ps1 for             |'
    Write-Host '     |  full legal terms including indemnity and                 |'
    Write-Host '     |  limitation of liability clauses.                         |'
    Write-Host '     |                                                           |'
    Write-Host '     |  By continuing, you represent that you are a              |'
    Write-Host '     |  qualified professional who has reviewed the              |'
    Write-Host '     |  source code and accepts full responsibility.             |'
    Write-Host '     |                                                           |'
    Write-Host '     +-----------------------------------------------------------+'
    Write-Host ''
    $accept = Read-Host '     Accept and continue? [Y/N]'
    if ($accept -ne 'Y' -and $accept -ne 'y') {
        Write-Host '     Exiting.'
        Start-Sleep -Seconds 1
        exit 0
    }
    # Mode selection
    Write-Host ''
    Write-Host '     Select scan mode:'
    Write-Host ''
    Write-Host '       [1]  Audit            Scan + read-only dashboard'
    Write-Host '                              View your security posture. No changes.'
    Write-Host ''
    Write-Host '       [2]  Expert           Scan + dashboard + fix engine'
    Write-Host '                              Apply fixes interactively. Beta.'
    Write-Host ''
    Write-Host '       [3]  Report           Scan + JSON file only'
    Write-Host '                              No dashboard, no server. File output.'
    Write-Host ''
    Write-Host '       [Q]  Quit'
    Write-Host ''
    $modeChoice = Read-Host '     Choose [1/2/3/Q]'
    $selectedMode = switch ($modeChoice) {
        '1' { 'audit' }
        '2' { 'expert' }
        '3' { 'report' }
        { $_ -in 'Q','q' } { Write-Host '     Exiting.'; exit 0 }
        default {
            Write-Host '     Invalid choice.' -ForegroundColor Yellow
            exit 1
        }
    }
    # Determine the mode display name
    $modeNames = @{ 'audit' = 'AUDIT (read-only dashboard)'; 'expert' = 'EXPERT (fixes enabled - beta)'; 'report' = 'REPORT (JSON output only)' }
    Write-Host ''
    Write-Host "     Mode: $($modeNames[$selectedMode])"

    # Check if already elevated
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin) {
        # Already elevated -- just set the mode switches and continue
        switch ($selectedMode) {
            'audit'  { $ReadOnly = $true }
            'report' { $Audit = $true }
            'expert' { }
        }
    }
    else {
        Write-Host '     Requesting administrator privileges...'
        Write-Host ''
        # SECURITY (v0.83): Forward user-provided parameters across UAC boundary.
        $extras = ''
        if ($OutputDir) { $extras += " -OutputDir '$($OutputDir -replace "'","''")'" }
        if ($Port) { $extras += " -Port $Port" }
        if ($DryRun) { $extras += ' -DryRun' }
        if ($NoNVD) { $extras += ' -NoNVD' }
        # Note: -ReadOnly and -Audit are set by -HtMode in the elevated process,
        # not forwarded as explicit parameters.

        # SECURITY (v0.76): In-memory elevation via encoded bootstrapper + named pipe.
        # The previous approach (-File with disk-based hash verification) was vulnerable
        # to handle theft: a same-user attacker uses DuplicateHandle with
        # DUPLICATE_CLOSE_SOURCE to rip the FileStream lock from this process (same SID
        # grants PROCESS_DUP_HANDLE), swaps the script file, and the elevated process
        # executes the attacker's code (which simply ignores the -HtHash parameter).
        #
        # The new approach eliminates disk from the elevated process entirely:
        #   1. Lock + read script into memory + hash + release lock (microsecond window)
        #   2. Create admin-only named pipe with cryptographic random name
        #   3. Generate tiny bootstrapper (pipe name + expected hash as literals)
        #   4. Base64-encode bootstrapper, launch elevated via -EncodedCommand
        #   5. Bootstrapper is locked into AppInfo RPC (immutable after Start-Process)
        #   6. After UAC approval, bootstrapper reads pipe, verifies hash, executes from memory
        #   7. Disk file is never read by the elevated process

        # Step 1: Resolve, lock, read into memory, hash, release
        $selfPath = $PSCommandPath
        if (-not $selfPath) { $selfPath = $MyInvocation.MyCommand.Path }
        $resolved = Resolve-CanonicalScriptPath $selfPath -Lock
        if (-not $resolved -or -not $resolved.Path) {
            Write-Host '     SECURITY ABORT: Cannot determine canonical script path.' -ForegroundColor Red
            Read-Host '     Press Enter to exit'
            exit 1
        }
        $selfPath = $resolved.Path
        $lockFs = $resolved.Stream
        try {
            $scriptBytes = [byte[]]::new($lockFs.Length)
            $lockFs.Read($scriptBytes, 0, $scriptBytes.Length) | Out-Null
        }
        finally {
            # Release lock immediately. Content is in memory; disk file no longer matters.
            # The attacker can swap the file now. It changes nothing.
            if ($lockFs) { $lockFs.Dispose() }
        }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha.ComputeHash($scriptBytes)
            $preHash = -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
        }
        finally { $sha.Dispose() }

        # Step 2: Create admin-only named pipe (maxInstances=1 prevents attacker cloning)
        $pipeName = 'HT_' + ([System.IO.Path]::GetRandomFileName() -replace '\.','')
        $pipeServer = $null
        try {
            # .NET Framework (PS 5.1): Constructor accepts PipeSecurity directly.
            # SECURITY (v0.82): Grant both Administrators (elevated client) and
            # the current user SID (non-elevated creator). Without the creator's
            # SID, the DACL denies the creating process and the pipe creation
            # throws UnauthorizedAccessException, falling into the insecure catch.
            $pipeSecurity = New-Object System.IO.Pipes.PipeSecurity
            $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $creatorSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $pipeRule = New-Object System.IO.Pipes.PipeAccessRule(
                $adminSid,
                [System.IO.Pipes.PipeAccessRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow)
            $pipeSecurity.AddAccessRule($pipeRule)
            # SECURITY (v0.83): Creator gets FullControl MINUS ReadData. ReadData grants
            # client connection rights — any same-SID malware could connect and consume
            # the single pipe instance (DoS) or receive the script bytes.
            $serverOnly = [System.IO.Pipes.PipeAccessRights]::FullControl -band (-bnot [System.IO.Pipes.PipeAccessRights]::ReadData)
            $creatorRule = New-Object System.IO.Pipes.PipeAccessRule(
                $creatorSid,
                $serverOnly,
                [System.Security.AccessControl.AccessControlType]::Allow)
            $pipeSecurity.AddAccessRule($creatorRule)
            $pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream(
                $pipeName,
                [System.IO.Pipes.PipeDirection]::Out,
                1,
                [System.IO.Pipes.PipeTransmissionMode]::Byte,
                [System.IO.Pipes.PipeOptions]::None,
                0, 0,
                $pipeSecurity)
        }
        catch {
            # .NET Core (PS 7+): PipeSecurity constructor unavailable.
            # SECURITY (v0.82): Apply ACL post-creation via SetAccessControl.
            # SECURITY (v0.83): TOCTOU between creation and ACL application is
            # unavoidable here; pipe exists briefly with default DACL. Fail-closed
            # if ACL application fails rather than leaving pipe unrestricted.
            $pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream(
                $pipeName,
                [System.IO.Pipes.PipeDirection]::Out,
                1)
            try {
                $ps = New-Object System.IO.Pipes.PipeSecurity
                $aSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
                $cSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($aSid, [System.IO.Pipes.PipeAccessRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)))
                $sOnly = [System.IO.Pipes.PipeAccessRights]::FullControl -band (-bnot [System.IO.Pipes.PipeAccessRights]::ReadData)
                $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($cSid, $sOnly, [System.Security.AccessControl.AccessControlType]::Allow)))
                $pipeServer.SetAccessControl($ps)
            } catch {
                # SECURITY (v0.83): Cannot apply ACL — abort rather than leaving pipe
                # unrestricted. Hash verification alone does not prevent DoS via pipe theft.
                $pipeServer.Dispose(); $pipeServer = $null
                throw "SECURITY ABORT: Cannot create named pipe with restrictive ACL. Elevation requires PS 5.1 or PS 7.4+."
            }
        }

        try {
            # Step 3: Build bootstrapper. Single-quoted here-string avoids all escaping.
            # Placeholders are replaced via [string]::Replace() (no regex interpretation).
            $bootstrapper = @'
$env:PSModulePath=[Environment]::GetEnvironmentVariable('PSModulePath','Machine')
$env:PATH=[Environment]::GetEnvironmentVariable('PATH','Machine')
$p=[IO.Pipes.NamedPipeClientStream]::new('.','~~PIPE~~',[IO.Pipes.PipeDirection]::In,[IO.Pipes.PipeOptions]::None,[Security.Principal.TokenImpersonationLevel]::Anonymous)
$p.Connect(30000)
$ms=[IO.MemoryStream]::new()
$p.CopyTo($ms)
$p.Dispose()
$b=$ms.ToArray()
$ms.Dispose()
$sha=[Security.Cryptography.SHA256]::Create()
$h=-join($sha.ComputeHash($b)|%{$_.ToString('x2')})
$sha.Dispose()
if($h-ne'~~HASH~~'){Write-Host "`n  SECURITY ABORT: Pipe content integrity check failed." -ForegroundColor Red;Write-Host "  Expected: ~~HASH~~" -ForegroundColor Yellow;Write-Host "  Got: $h" -ForegroundColor Yellow;Read-Host "`n  Press Enter to exit";exit 1}
$s=[Text.Encoding]::UTF8.GetString($b)
if($s.Length -gt 0 -and $s[0]-eq[char]65279){$s=$s.Substring(1)}
$global:HtVerifiedContent=$b
$global:HtSourcePath='~~PATH~~'
$sb=[scriptblock]::Create($s)
& $sb -HtMode '~~MODE~~' -HtHash '~~HASH~~'~~EXTRAS~~
'@
            $bootstrapper = $bootstrapper.Replace('~~PIPE~~', $pipeName)
            $bootstrapper = $bootstrapper.Replace('~~HASH~~', $preHash)
            $bootstrapper = $bootstrapper.Replace('~~PATH~~', ($selfPath -replace "'","''"))
            $bootstrapper = $bootstrapper.Replace('~~MODE~~', $selectedMode)
            $bootstrapper = $bootstrapper.Replace('~~EXTRAS~~', $extras)

            # Step 4: Base64-encode and launch elevated via -EncodedCommand.
            # The encoded bootstrapper is locked into the AppInfo RPC call at the moment
            # Start-Process is called. It is immutable after that point.
            # SECURITY (v0.81): Route elevation through cmd.exe to prevent CLR profiler
            # injection. The v0.79 approach of stripping COR_ENABLE_PROFILING from the
            # current process's environment is ineffective: Start-Process -Verb RunAs
            # delegates to the AppInfo service, which calls CreateEnvironmentBlock to
            # build a FRESH environment from the registry (merging HKLM and HKCU\Environment).
            # An attacker who sets COR_ENABLE_PROFILING=1 in HKCU\Environment poisons
            # every elevated process regardless of what the parent stripped.
            #
            # Fix: Elevate cmd.exe (native, CLR never loads) with /c that explicitly
            # clears all dangerous variables, then launches powershell.exe. The child
            # PowerShell inherits cmd.exe's scrubbed environment, not the registry-merged one.
            $cmdBytes = [System.Text.Encoding]::Unicode.GetBytes($bootstrapper)
            $encodedCmd = [Convert]::ToBase64String($cmdBytes)
            $cmdExe = Join-Path $script:TrustedSystemRoot 'System32\cmd.exe'
            $innerArgs = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCmd"
            # SECURITY (v0.83): No trailing spaces before '&' — cmd.exe includes them
            # in the variable value, causing .NET Core to parse " " as an assembly path.
            $scrubVars = 'set COR_ENABLE_PROFILING=&set COR_PROFILER=&set COR_PROFILER_PATH=&set CORECLR_ENABLE_PROFILING=&set CORECLR_PROFILER=&set CORECLR_PROFILER_PATH=&set _NT_SYMBOL_PATH=&set DOTNET_STARTUP_HOOKS=&set DOTNET_ADDITIONAL_DEPS=&set __PSLockdownPolicy='
            $cmdArgs = "/d /c `"$scrubVars& `"$($script:PsExeFull)`" $innerArgs`""
            $proc = Start-Process -FilePath $cmdExe -ArgumentList $cmdArgs -Verb RunAs -PassThru

            # Step 5: Send script content through pipe to elevated bootstrapper
            $pipeServer.WaitForConnection()
            $pipeServer.Write($scriptBytes, 0, $scriptBytes.Length)
            $pipeServer.Flush()
            $pipeServer.WaitForPipeDrain()
            $pipeServer.Dispose()
            $pipeServer = $null

            $proc.WaitForExit()
        }
        catch {
            if ($_.Exception.Message -match 'canceled by the user') {
                Write-Host '     UAC elevation was cancelled.' -ForegroundColor Yellow
            }
            else {
                Write-Host "     Elevation failed: $_" -ForegroundColor Red
            }
        }
        finally {
            if ($pipeServer) { $pipeServer.Dispose() }
        }
        exit 0
    }
}

# SECURITY (v0.39): Global ErrorActionPreference set to 'Stop' so security-critical
# operations (ACL application, registry writes, fix verification) cannot fail silently.
# Individual cmdlets where failure is expected use explicit -ErrorAction SilentlyContinue.
$ErrorActionPreference = 'Stop'

# ============================================================================
#  SECURITY (v0.53): Fully qualified system binary paths.
#  Prevents PATH hijacking: standard users can modify their User PATH, and
#  UAC elevation merges User PATH into System PATH. An attacker adds a
#  directory containing a malicious powercfg.exe / bcdedit.exe etc., and
#  bare command names resolve to the malicious copy.
# ============================================================================
# SECURITY (v0.78): Use trusted machine-scope SystemRoot, not $env:SystemRoot.
$script:Sys32 = Join-Path $script:TrustedSystemRoot 'System32'
$script:Bin = @{
    powercfg  = Join-Path $script:Sys32 'powercfg.exe'
    bcdedit   = Join-Path $script:Sys32 'bcdedit.exe'
    secedit   = Join-Path $script:Sys32 'secedit.exe'
    vssadmin  = Join-Path $script:Sys32 'vssadmin.exe'
    fsutil    = Join-Path $script:Sys32 'fsutil.exe'
    managebde = Join-Path $script:Sys32 'manage-bde.exe'
    cipher    = Join-Path $script:Sys32 'cipher.exe'
    reagentc  = Join-Path $script:Sys32 'reagentc.exe'
    net       = Join-Path $script:Sys32 'net.exe'
}

# ============================================================================
#  SECURITY (v0.58): P/Invoke helper for atomic link-safe file deletion.
#  PowerShell/.NET cannot safely delete files in user-writable directories
#  because [System.IO.File]::Delete() and Remove-Item have no option to
#  avoid following reparse points, and Get-Item hardlink detection requires
#  opening a separate handle (creating a TOCTOU window).
#
#  SafeDeleteFile uses native Win32 APIs:
#  1. CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT -- opens the link itself,
#     never follows it to the target.
#  2. GetFileInformationByHandle -- checks nNumberOfLinks (hardlinks) and
#     dwFileAttributes (reparse points) on the ACTUAL opened file object.
#  3. SetFileInformationByHandle(FileDispositionInfo) -- marks for deletion
#     through the same handle. File is atomically deleted when handle closes.
#
#  The handle is never released between the check and the delete mark, so
#  there is ZERO TOCTOU window. This is the only correct way to safely
#  delete files in directories where standard users have write access.
# ============================================================================
# SECURITY (v0.65): HtNativeFile.dll pre-compiled and base64-encoded.
# Previous approach (v0.58-v0.63) used Add-Type to compile C# at runtime,
# which writes temp .cs/.cmdline files to $env:TEMP and invokes csc.exe.
# When running as SYSTEM, $env:TEMP = C:\Windows\Temp (user-writable).
# Attacker can oplock the temp .cs file, inject malicious C#, and get it
# compiled+loaded into SYSTEM memory. v0.63 mitigated this by redirecting
# $env:TEMP to ACL-protected directory during compilation.
#
# This is the permanent fix: no csc.exe invocation, no temp files, no disk
# I/O. The DLL is loaded directly from memory via [Reflection.Assembly]::Load.
# Also works in Constrained Language Mode (CLM) where Add-Type is blocked,
# though CLM may also block Assembly.Load depending on the enforcement policy.
# If elevated and loading fails, the script hard-aborts (v0.75).
# DLL compiled from HtNativeFile.cs targeting netstandard2.0 (compatible with
# .NET Framework 4.5+ / PowerShell 5.1 and .NET Core / PowerShell 7+).
    $dllB64 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAM16m2kAAAAAAAAAAOAAIiALATAAABgAAAAGAAAAAAAAmjcAAAAgAAAAQAAAAAAAEAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACAAAAAAgAAAAAAAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAEg3AABPAAAAAEAAALgCAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAoBcAAAAgAAAAGAAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAALgCAAAAQAAAAAQAAAAaAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAGAAAAACAAAAHgAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAAB8NwAAAAAAAEgAAAACAAUAACYAAEgRAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACICKAYAAAoAKj4CKAYAAAoAAgN9AQAABCoAAAAbMAcApAAAAAEAABEAAiAAAAGAFn4HAAAKGSAAACAAfgcAAAooAwAABgoABm8IAAAKDQksBRYTBN5zBhIBKAQAAAYW/gETBREFLAUWEwTeXQd7GwAABCAABAAAXxb+AxMGEQYsBRYTBN5DB3siAAAEF/4DEwcRBywFFhME3i8SAhd9JQAABAYaEgLQBgAAAigJAAAKKAoAAAooBQAABhME3gsGLAcGbwsAAAoA3BEEKgEQAAACAB4AeJYACwAAAAATMAIAKAAAAAIAABEAAhIAKAQAAAYW/gELBywEFwwrEgZ7GwAABCAABAAAXxb+AwwrAAgqEzAHAHAAAAADAAARAAIgAAAAgBl+BwAAChkgAAAgAn4HAAAKKAMAAAYKBm8IAAAKDAgsBBQNK0IGEgEoBAAABhb+ARMEEQQsDAAGbwwAAAoAFA0rJQd7GwAABCAABAAAXxb+AxMFEQUsDAAGbwwAAAoAFA0rBAYNKwAJKhswBwCQAAAABAAAEQACIAAAAQAWfgcAAAoZIAAAIAJ+BwAACigDAAAGCgAGbwgAAAoNCSwFFhME3l8GEgEoBAAABhb+ARMFEQUsBRYTBN5JB3sbAAAEIAAEAABfFv4DEwYRBiwFFhME3i8SAhd9JQAABAYaEgLQBgAAAigJAAAKKAoAAAooBQAABhME3gsGLAcGbwsAAAoA3BEEKgEQAAACAB4AZIIACwAAAAATMAcAhwAAAAUAABEAAhoWfgcAAAoZIAAAIAB+BwAACigDAAAGCgZvCAAACgwILAQUDStdBhIBKAQAAAYW/gETBBEELAwABm8MAAAKABQNK0AHexsAAAQgAAQAAF8W/gMTBREFLAwABm8MAAAKABQNKx8HeyIAAAQX/gMTBhEGLAwABm8MAAAKABQNKwQGDSsACSoAEzAHAJgAAAAGAAARAAIoBwAABiYCIAAAAEAWfgcAAAoXIAAAIAB+BwAACigDAAAGCgZvCAAACgwILAQUDStjBhIBKAQAAAYW/gETBBEELAwABm8MAAAKABQNK0YHexsAAAQgAAQAAF8W/gMTBREFLC0AEgYXfSUAAAQGGhIG0AYAAAIoCQAACigKAAAKKAUAAAYmBm8MAAAKABQNKwQGDSsACSoTMAMADgAAAAcAABEAAgMXKAYAAAYKKwAGKgAAEzAGAC4AAAAIAAARABYKFgsCcgEAAHB+BwAAChIAfgcAAAoSASgLAAAGDAgtBgYc/gErARYNKwAJKgAAEzACAJIAAAAJAAARAAJvDQAACgsHciUAAHAoDgAACi0NB3ItAABwKA4AAAorARcMCCwIfhEAAAQKK1UHckMAAHAoDgAACi0NB3JNAABwKA4AAAorARcNCSwIfhAAAAQKKy4HcnMAAHAoDgAACi0NB3J9AABwKA4AAAorARcTBBEELAh+DwAABAorBRUTBSsLBgMoFgAABhMFKwARBSoAABswCAD5AAAACgAAEQACAx4gGQADABIAKAgAAAYLBxj+AQwILAcXDTjXAAAABxb+AxMEEQQsBxUNOMYAAAAAAAYoFAAABhMGEQYsBxYN3bEAAAA4hwAAAAAgAAEAAHMPAAAKEwcgAAEAABMIBhYRBxIIfgcAAAp+BwAACn4HAAAKfgcAAAooCgAABhMJEQkgAwEAAP4BEwwRDCwCK0kRCRb+AxMNEQ0sBBUN3lcRB28QAAAKEwoGEQooFgAABhMLEQsW/gETDhEOLAQWDd41EQsV/gETDxEPLAQVDd4mABcTEDhx////BigMAAAGEwURBSwDFSsBFw3eCgAGKAkAAAYmANwJKgAAAAEQAAACADIAu+0ACgAAAAC6IAEAAIBzEQAACoAPAAAEIAIAAIBzEQAACoAQAAAEIAMAAIBzEQAACoARAAAEKgBCU0pCAQABAAAAAAAMAAAAdjQuMC4zMDMxOQAAAAAFAGwAAAA0BgAAI34AAKAGAAAUCAAAI1N0cmluZ3MAAAAAtA4AAKQAAAAjVVMAWA8AABAAAAAjR1VJRAAAAGgPAADgAQAAI0Jsb2IAAAAAAAAAAgAAAVcdAhQJAgAAAPoBMwAWAAABAAAAEwAAAAYAAAAlAAAAFwAAADMAAAARAAAAFgAAAAkAAAAKAAAAAwAAAAoAAAABAAAAAQAAAAIAAAAAAEAFAQAAAAAABgB2BCcGBgCWBCcGBgBKBPUFDwBHBgAABgAXBCcGBgCqBFsFBgAdB1sFBgAyBFsFBgAuB1sFBgC+AlYGBgDTBWUHBgDsA1sFBgDuBVsFBgCzAggGBgD4A1sFBgDNAlsFBgALBQgGBgCnAlsFBgDKBFsFAAAAAAEAAAAAAAEAAQAAARAABQS1BhkAAQABAAABEABeBCcGGQABAAIAgQEQAFUDAAAlAAIAAwALARAA8wAAADEAGwAYAAsBEAAOAQAAMQAlABgAJgBiBfoAUYAbAP0AUYB+AP0AUYB0AP0AUYAKAP0AUYDHAP0AUYDPAf0AUYCyAf0AUYA2Af0AUYCVAf0AUYAoAP0AUYCMAP0AUYCtAP0AUYCeBfoAMQAkASQAMQBWACQAMQBlASQAUYDeAP0AUYA4AP0AUYB+Af0AUYCdAP0AUYBpAP0AUYDVAP0AUYBwAfoAUYBRAfoAUYBBAPoABgCHBv0ABgDMAwABBgDbAwABBgC8AwABBgC+Bf0ABgDRBP0ABgB/B/0ABgDMBv0ABgDfBP0ABgCMB/0ABgBKAwMBUCAAAAAAhhjhBQYAAQBZIAAAAACGGOEFAQABAAAAAACAAJEg2gEGAQEAAAAAAIAAkSDxAhIBCAAAAAAAgACRIAwDGwEKAAAAAACAAJEg8gEmAQ4AAAAAAIAAkSDmAS0BEQAAAAAAgACRIB0CMgESAAAAAACAAJEgqwc8ARcAAAAAAIAAkSAPAkEBGAAAAAAAgACRIP4BTwEgAAAAAACAAJEgtwc8ASYAbCAAAAAAlgBGAy0BJwAsIQAAAACWAFAHWwEoAGAhAAAAAJYA+gdhASkA3CEAAAAAlgDmBy0BKgCIIgAAAACWAF8CYQErABwjAAAAAJYAcQdhASwAwCMAAAAAlgDSB4sALQDcIwAAAACRAP4EZwEvABgkAAAAAJYAkAJsATAAuCQAAAAAkQATBXIBMgDQJQAAAACRGOcFeAE0AAAAAQB7AwAAAgANBwAAAwCEAgAABACYBgAABQCIBQAABgByBgAABwA4AwAAAQBiAwIAAgCyBQAAAQBiAwAAAgDwBgAAAwBqBQAABAC0BAAAAQBoAwAAAgCGAwAAAwCtBgAAAQB7AwAAAQDDBwAAAgCiBwAAAwDbBgAABAA7AgIABQA1BwAAAQDDBwAAAQDDBwAAAgCaBwAAAwCzAwAABACpAwAABQBGAgAABgAFBwAABwDlBgAACAC6AwAAAQDDBwAAAgCUAwAAAwBGAgIABAD2AwAABQA0AgAABgArAgAAAQAnAwAAAQD5BAAAAQAxAwAAAQD5BAAAAQD5BAAAAQD5BAAAAQD5BAAAAQB9AgAAAgB8BQAAAQDDBwAAAQCgAwAAAgDuBAAAAQDIBwAAAgDuBAkA4QUBABEA4QUGABkA4QUKACkA4QUGAEEA4QUQADEA4QUGAGkAuQUkAHEAUQInAHkA3wIrAIkAwQQyAJEA/QMGAHEA/QMGAJkAPweHAJkACAiLAFkA4QUBAEkAyASHAGkA4QUBAAkACACvAAkADAC0AAkAEAC5AAkAFAC+AAkAGADDAAkAHADIAAkAIADNAAkAJADSAAkAKADXAAkALADIAAkAMADcAAkANADIAAgAOAC+AAkASADhAAkATADmAAkAUADhAAkAVADIAAkAWAC5AAkAXADrAAgAYADwAAgAZAD1AAgAaADcACcAEgDUAS4ACwB8AS4AEwCFAS4AGwCkAUMAIwDIAEMACgDIAGMAIwDIAGMACgDIAGMAKwCtARYAOAA/AEsAWABlAHMAdwB+AJEAMwUmBVEFRAEHANoBAQBAAQkA8QIBAEABCwAMAwEARAENAPIBAQBEAQ8A5gEBAEQBEQAdAgIAQAETAKsHAgBEARUADwICAEQBFwD+AQIAAAEZALcHAwAEgAAAAAAAAAAAAAAAAAAAAABVAwAAAgABAAAAAAAAAAAApgBxAgAAAAAFAAQABgAEAAAAADxNb2R1bGU+AEZJTEVfQVBQRU5EX0RBVEEAR0VORVJJQ19SRUFEAEZJTEVfU0hBUkVfUkVBRABLRVlfUkVBRABFUlJPUl9GSUxFX05PVF9GT1VORABIS0VZX0xPQ0FMX01BQ0hJTkUAUkVHX0RFTEVURQBGU19ERUxFVEUAR0VORVJJQ19XUklURQBGSUxFX1NIQVJFX1dSSVRFAEtFWV9RVUVSWV9WQUxVRQBNT1ZFRklMRV9SRVBMQUNFX0VYSVNUSU5HAE9QRU5fRVhJU1RJTkcAUkVHX0xJTksAUkVHX09QVElPTl9PUEVOX0xJTksAQllfSEFORExFX0ZJTEVfSU5GT1JNQVRJT04ARklMRV9ESVNQT1NJVElPTl9JTkZPAEhLRVlfQ1VSUkVOVF9VU0VSAEZJTEVfRkxBR19CQUNLVVBfU0VNQU5USUNTAEVSUk9SX05PX01PUkVfSVRFTVMASEtFWV9VU0VSUwBFUlJPUl9TVUNDRVNTAEtFWV9FTlVNRVJBVEVfU1VCX0tFWVMARklMRV9BVFRSSUJVVEVfUkVQQVJTRV9QT0lOVABGSUxFX0ZMQUdfT1BFTl9SRVBBUlNFX1BPSU5UAENSRUFURV9ORVcAQ3JlYXRlRmlsZVcARGVsZXRlRmlsZVcATW92ZUZpbGVFeFcAUmVnUXVlcnlWYWx1ZUV4VwBSZWdFbnVtS2V5RXhXAFJlZ09wZW5LZXlFeFcAbHBjYkRhdGEAbHBEYXRhAHNhbURlc2lyZWQAbHBSZXNlcnZlZABnZXRfSXNJbnZhbGlkAFNhZmVPcGVuRm9yQXBwZW5kAG5ldHN0YW5kYXJkAHNvdXJjZQBkd1NoYXJlTW9kZQBTYWZlUmVnaXN0cnlEZWxldGVUcmVlAElEaXNwb3NhYmxlAFNhZmVIYW5kbGUAU2FmZUZpbGVIYW5kbGUAUnVudGltZVR5cGVIYW5kbGUAR2V0VHlwZUZyb21IYW5kbGUAR2V0RmlsZUluZm9ybWF0aW9uQnlIYW5kbGUAU2V0RmlsZUluZm9ybWF0aW9uQnlIYW5kbGUAS2V5SGFuZGxlAGhhbmRsZQBoVGVtcGxhdGVGaWxlAFNhZmVEZWxldGVGaWxlAEh0TmF0aXZlRmlsZQBoRmlsZQBscEV4aXN0aW5nRmlsZU5hbWUAbHBGaWxlTmFtZQBscE5ld0ZpbGVOYW1lAGxwVmFsdWVOYW1lAGhpdmVOYW1lAGxwY2NoTmFtZQBscE5hbWUAbHBmdExhc3RXcml0ZVRpbWUAZnRDcmVhdGlvblRpbWUAZnRMYXN0QWNjZXNzVGltZQBWYWx1ZVR5cGUAbHBUeXBlAERpc3Bvc2UARW1iZWRkZWRBdHRyaWJ1dGUAQ29tcGlsZXJHZW5lcmF0ZWRBdHRyaWJ1dGUAQXR0cmlidXRlVXNhZ2VBdHRyaWJ1dGUARGVidWdnYWJsZUF0dHJpYnV0ZQBSZWZTYWZldHlSdWxlc0F0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAGR3QnVmZmVyU2l6ZQBTaXplT2YAVG9TdHJpbmcAbkZpbGVTaXplSGlnaABuRmlsZUluZGV4SGlnaABzdWJLZXlQYXRoAHBhdGgASXNLZXlTeW1saW5rAE1hcnNoYWwARGVsZXRlVHJlZUludGVybmFsAGFkdmFwaTMyLmRsbABrZXJuZWwzMi5kbGwASHROYXRpdmVGaWxlLmRsbABudGRsbC5kbGwAU3lzdGVtAFZlcnNpb24AbHBGaWxlSW5mb3JtYXRpb24AZGVzdGluYXRpb24AZHdDcmVhdGlvbkRpc3Bvc2l0aW9uAEZpbGVEaXNwb3NpdGlvbkluZm8AbHBJbmZvAFplcm8AZHdWb2x1bWVTZXJpYWxOdW1iZXIAU3RyaW5nQnVpbGRlcgAuY3RvcgAuY2N0b3IASW50UHRyAFN5c3RlbS5EaWFnbm9zdGljcwBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBEZWJ1Z2dpbmdNb2RlcwBNaWNyb3NvZnQuV2luMzIuU2FmZUhhbmRsZXMAZHdGbGFnc0FuZEF0dHJpYnV0ZXMAZHdGaWxlQXR0cmlidXRlcwBscFNlY3VyaXR5QXR0cmlidXRlcwBkd0ZsYWdzAE1pY3Jvc29mdC5Db2RlQW5hbHlzaXMAbk51bWJlck9mTGlua3MAdWxPcHRpb25zAGxwY2NoQ2xhc3MARmlsZUluZm9ybWF0aW9uQ2xhc3MAbHBDbGFzcwBkd0Rlc2lyZWRBY2Nlc3MAQXR0cmlidXRlVGFyZ2V0cwBPYmplY3QAcGhrUmVzdWx0AFRvVXBwZXJJbnZhcmlhbnQASXNIYW5kbGVSZXBhcnNlUG9pbnQAU3lzdGVtLlRleHQAU2FmZUNyZWF0ZU5ldwBuRmlsZVNpemVMb3cAbkZpbGVJbmRleExvdwBkd0luZGV4AGxwU3ViS2V5AFJlZ0Nsb3NlS2V5AE50RGVsZXRlS2V5AGhLZXkAcGFyZW50S2V5AFNhZmVSZW5hbWVEaXJlY3RvcnkAU2FmZVJlbW92ZURpcmVjdG9yeQBMb2NrRGlyZWN0b3J5AG9wX0VxdWFsaXR5AAAjUwB5AG0AYgBvAGwAaQBjAEwAaQBuAGsAVgBhAGwAdQBlAAAHSABLAFUAABVIAEsARQBZAF8AVQBTAEUAUgBTAAAJSABLAEwATQAAJUgASwBFAFkAXwBMAE8AQwBBAEwAXwBNAEEAQwBIAEkATgBFAAAJSABLAEMAVQAAI0gASwBFAFkAXwBDAFUAUgBSAEUATgBUAF8AVQBTAEUAUgAAAAAAdh1mbRKhcEyN1j9JunTv/AAEIAEBCAMgAAEFIAEBEREFIAEBER0NBwgSKREUERgCAgICAgIGGAMgAAIGAAESPRFBBQABCBI9BgcDERQCAgsHBhIpERQCEikCAgwHBxIpERQRGAICAgIMBwcSKREUAhIpAgICDQcHEikRFAISKQICERgDBwECBgcECQkIAggHBhgOAgICCAMgAA4FAAICDg4UBxEYCAIIAggCEi0JCA4IAgICAgIIzHsT/80t3VEEAAAAgAQAAABABAAAAQAEBAAAAAQDAAAABAEAAAAEAAAgAAQAAAACBAAEAAAEAgAAAAQIAAAABBkAAgAEBgAAAAQAAAAABAMBAAACBggCBgkCBgoCBgILAAcSKQ4JCRgJCRgIAAICEikQERQKAAQCEikIEBEYCAYAAwIODgkEAAECDgkABQgYDgkJEBgEAAEIGA0ACAgYCRItEAkYGBgYCwAGCBgOGBAJGBAJBQABAhIpBQABEikOBAABAhgFAAIIDg4FAAIIGA4DAAABCAEACAAAAAAAHgEAAQBUAhZXcmFwTm9uRXhjZXB0aW9uVGhyb3dzAQgBAAcBAAAAACYBAAIAAAACAFQCDUFsbG93TXVsdGlwbGUAVAIJSW5oZXJpdGVkAAgBAAsAAAAAAAAAAHA3AAAAAAAAAAAAAIo3AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB8NwAAAAAAAAAAAAAAAF9Db3JEbGxNYWluAG1zY29yZWUuZGxsAAAAAAD/JQAgABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAEAAAABgAAIAAAAAAAAAAAAAAAAAAAAEAAQAAADAAAIAAAAAAAAAAAAAAAAAAAAEAAAAAAEgAAABYQAAAXAIAAAAAAAAAAAAAXAI0AAAAVgBTAF8AVgBFAFIAUwBJAE8ATgBfAEkATgBGAE8AAAAAAL0E7/4AAAEAAAAAAAAAAAAAAAAAAAAAAD8AAAAAAAAABAAAAAIAAAAAAAAAAAAAAAAAAABEAAAAAQBWAGEAcgBGAGkAbABlAEkAbgBmAG8AAAAAACQABAAAAFQAcgBhAG4AcwBsAGEAdABpAG8AbgAAAAAAAACwBLwBAAABAFMAdAByAGkAbgBnAEYAaQBsAGUASQBuAGYAbwAAAJgBAAABADAAMAAwADAAMAA0AGIAMAAAACwAAgABAEYAaQBsAGUARABlAHMAYwByAGkAcAB0AGkAbwBuAAAAAAAgAAAAMAAIAAEARgBpAGwAZQBWAGUAcgBzAGkAbwBuAAAAAAAwAC4AMAAuADAALgAwAAAAQgARAAEASQBuAHQAZQByAG4AYQBsAE4AYQBtAGUAAABIAHQATgBhAHQAaQB2AGUARgBpAGwAZQAuAGQAbABsAAAAAAAoAAIAAQBMAGUAZwBhAGwAQwBvAHAAeQByAGkAZwBoAHQAAAAgAAAASgARAAEATwByAGkAZwBpAG4AYQBsAEYAaQBsAGUAbgBhAG0AZQAAAEgAdABOAGEAdABpAHYAZQBGAGkAbABlAC4AZABsAGwAAAAAADQACAABAFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8AbgAAADAALgAwAC4AMAAuADAAAAA4AAgAAQBBAHMAcwBlAG0AYgBsAHkAIABWAGUAcgBzAGkAbwBuAAAAMAAuADAALgAwAC4AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAwAAACcNwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    $dllBytes = [Convert]::FromBase64String($dllB64)
    # SECURITY (v0.75): Assembly.Load failure when elevated = possible CLM attack.
    # But GetType failure is a benign PS 5.1 anonymous load context quirk.
    # These MUST be separate try/catch blocks.
    try {
        $asm = [Reflection.Assembly]::Load($dllBytes)
    }
    catch {
        # Assembly.Load itself failed -- CLM, constrained runtime, or tampered bytes.
        $initElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($initElevated) {
            Write-Host '' -ForegroundColor Red
            Write-Host '  SECURITY ABORT: Native file helper (Assembly.Load) unavailable in elevated context.' -ForegroundColor Red
            Write-Host '  Possible Constrained Language Mode (CLM) downgrade attack.' -ForegroundColor Red
            Write-Host '  Check __PSLockdownPolicy environment variable and WDAC/AppLocker policies.' -ForegroundColor Red
            Write-Host "  Error: $_" -ForegroundColor Yellow
            Write-Host ''
            Read-Host '  Press Enter to exit'
            exit 1
        }
        $script:HasNativeFileHelper = $false
        Write-Host '    [SECURITY WARNING] Native file helper (Assembly.Load) unavailable.' -ForegroundColor Yellow
        Write-Host '    File deletion in user-writable directories will use managed .NET APIs,' -ForegroundColor Yellow
        Write-Host '    which cannot atomically verify hardlink/symlink status before deletion.' -ForegroundColor Yellow
        $asm = $null
    }
    # Assembly.Load(byte[]) loads into the "anonymous" context. PowerShell 5.1's
    # type resolver cannot find types from this context via [TypeName] syntax,
    # even with type accelerator registration. The fix: store the Type object in
    # a script-scoped variable and call static methods through it. $Type::Method()
    # uses the runtime Type object directly, bypassing the type resolver entirely.
    if ($asm) {
        $script:HtNative = $asm.GetType('HtNativeFile')
        if ($null -eq $script:HtNative) {
            # Type not found -- PS 5.1 anonymous load context issue, not a security attack.
            # The assembly loaded successfully but the type resolver can't find the type.
            $script:HasNativeFileHelper = $false
            Write-Host '    [INFO] HtNativeFile type not resolved (PS 5.1 anonymous context).' -ForegroundColor DarkYellow
            Write-Host '    Native file operations will use managed fallbacks.' -ForegroundColor DarkYellow
        } else {
            $script:HasNativeFileHelper = $true
        }
    }

# ============================================================================
#  FIX DEFINITIONS - Central registry of all fixes
# ============================================================================
$script:FixDefs = @{
    # SLEEP / HIBERNATE
    'platform-aoac' = @{
        Name = 'Disable Modern Standby (AOAC Override)'
        Type = 'registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power'
        Key = 'PlatformAoAcOverride'
        Value = 0
        Reboot = $true
        Impact = 'Your laptop will no longer use instant-on sleep. Closing the lid may trigger shutdown or classic S3 sleep instead. You will lose the ability to receive notifications while sleeping.'
    }
    'cs-enabled' = @{
        Name = 'Disable Connected Standby'
        Type = 'registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power'
        Key = 'CsEnabled'
        Value = 0
        Reboot = $true
        Impact = 'Network activity during sleep will stop. Email sync, push notifications, and background updates will not work until you wake the device.'
    }
    'fast-startup' = @{
        Name = 'Disable Fast Startup'
        Type = 'registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
        Key = 'HiberbootEnabled'
        Value = 0
        Reboot = $false
        Impact = 'Cold boot will take a few seconds longer. This is the expected trade-off for a clean shutdown that does not persist kernel memory to disk.'
    }
    'hibernate' = @{
        Name = 'Disable Hibernation'
        Type = 'command'
        Command = "$($script:Bin.powercfg) /h off"
        Reboot = $false
        Impact = 'You will lose the ability to hibernate. Closing the lid will either sleep (S3) or shut down. Unsaved work will be lost on power loss during sleep.'
    }
    # MEMORY RESIDUE
    'kernel-paging' = @{
        Name = 'Keep Kernel in RAM'
        Type = 'registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
        Key = 'DisablePagingExecutive'
        Value = 1
        Reboot = $true
        Impact = 'Kernel code and data will not be paged to disk, using more physical RAM. On systems with limited memory (4GB or less) this may reduce available memory for applications.'
    }
    'clear-pagefile' = @{
        Name = 'Clear Pagefile at Shutdown'
        Type = 'registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
        Key = 'ClearPageFileAtShutdown'
        Value = 1
        Reboot = $false
        Impact = 'Shutdown will take longer as Windows zeroes the pagefile. Duration depends on pagefile size (can be 30 seconds to several minutes on large pagefiles).'
    }
    'crash-dump' = @{
        Name = 'Disable Crash Dumps'
        Type = 'registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
        Key = 'CrashDumpEnabled'
        Value = 0
        Reboot = $false
        Impact = 'Blue screen crashes will no longer produce dump files. This makes diagnosing driver issues or hardware failures significantly harder. If you experience frequent BSODs, keep this enabled until the root cause is found.'
    }
    'nmi-dump' = @{
        Name = 'Disable NMI Crash Dumps'
        Type = 'registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
        Key = 'NMICrashDump'
        Value = 0
        Reboot = $false
        Note = 'NMI crash dumps allow a physical button press or hardware signal to force a full memory dump. Useful for debugging hangs but also an attack vector for memory extraction.'
    }
    # DMA / VIRTUALIZATION
    'vbs' = @{
        Name = 'Enable Virtualization Based Security'
        Type = 'registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        Key = 'EnableVirtualizationBasedSecurity'
        Value = 1
        Reboot = $true
        Note = 'Requires UEFI + Secure Boot. May not activate on all hardware.'
        Impact = 'VBS reserves a portion of system resources for its secure kernel. Expect 5-15% performance reduction in CPU-intensive tasks. Some virtualization software (e.g. older VirtualBox) may conflict.'
    }
    'hvci' = @{
        Name = 'Enable HVCI (Memory Integrity)'
        Type = 'registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
        Key = 'Enabled'
        Value = 1
        Reboot = $true
        Note = 'Requires VBS active. Some drivers may be incompatible.'
        Impact = 'Can cause 5-25% performance drop in gaming and CPU-intensive workloads. Incompatible drivers (RGB controllers, older printers, specialised USB devices) will stop working. Check Device Manager after enabling.'
    }
    'credential-guard' = @{
        Name = 'Enable Credential Guard'
        Type = 'registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard'
        Key = 'Enabled'
        Value = 1
        Reboot = $true
        Note = 'Officially Enterprise-only. May work on Pro but unsupported.'
    }
    'dma-guard' = @{
        Name = 'Block DMA Devices'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'
        Key = 'DeviceEnumerationPolicy'
        Value = 0
        Reboot = $true
        Note = 'Requires hardware IOMMU support. May not work on all systems.'
    }
    # SLEEP (continued)
    'wake-timers' = @{
        Name = 'Disable Wake Timers'
        Type = 'command'
        Command = "$($script:Bin.powercfg) /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP RTCWAKE 0; $($script:Bin.powercfg) /SETDCVALUEINDEX SCHEME_CURRENT SUB_SLEEP RTCWAKE 0; $($script:Bin.powercfg) /SETACTIVE SCHEME_CURRENT"
        Reboot = $false
        Impact = 'Windows Update, scheduled maintenance, and background tasks will not wake the device from sleep. The device will remain asleep until you physically wake it.'
    }
    # ACCESS CONTROL
    'winre' = @{
        Name = 'Disable Windows Recovery Environment'
        Type = 'command'
        Command = "$($script:Bin.reagentc) /disable"
        Reboot = $false
        Note = 'Disables WinRE. You will not be able to use recovery options at boot. Re-enable with: reagentc /enable'
        Impact = 'If Windows fails to boot, you will have NO automatic repair, system restore, or startup recovery. You MUST have a separate USB recovery drive prepared before applying this fix. Without one, a boot failure means a full reinstall.'
    }
    'rdp' = @{
        Name = 'Disable Remote Desktop'
        Type = 'registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        Key = 'fDenyTSConnections'
        Value = 1
        Reboot = $false
        Impact = 'You will no longer be able to connect to this machine via Remote Desktop. If you rely on RDP for remote administration, ensure you have an alternative access method before applying.'
    }
    'auto-logon' = @{
        Name = 'Disable Auto-Logon'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Key = 'AutoAdminLogon'
        Value = 0
        Reboot = $false
        Note = 'Also manually clear DefaultPassword from Winlogon if present.'
    }
    'arso' = @{
        Name = 'Disable Automatic Restart Sign-On'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Key = 'DisableAutomaticRestartSignOn'
        Value = 1
        Reboot = $false
    }
    'uac-credential-prompt' = @{
        Name = 'Require Password for UAC Elevation'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Key = 'ConsentPromptBehaviorAdmin'
        Value = 1
        Reboot = $false
        Impact = 'Every UAC elevation will require you to re-enter your password, even if you are already logged in as an administrator. This adds friction to routine admin tasks but prevents an attacker at an unlocked session from silently elevating.'
    }
    # ENCRYPTION
    'enhanced-pin' = @{
        Name = 'Allow Enhanced BitLocker PIN'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        Key = 'UseEnhancedPin'
        Value = 1
        Reboot = $false
        Note = 'Enables alphanumeric PINs. You must manually change your PIN afterward: manage-bde -changepin C:'
    }
    # BOOT INTEGRITY
    'kernel-debug' = @{
        Name = 'Disable Kernel Debugging'
        Type = 'command'
        Command = "$($script:Bin.bcdedit) /debug off"
        Reboot = $true
    }
    'test-signing' = @{
        Name = 'Disable Test Signing Mode'
        Type = 'command'
        Command = "$($script:Bin.bcdedit) /set testsigning off"
        Reboot = $true
    }
    # - DATA EXPOSURE SURFACE --
    'fs-recent-docs' = @{
        Name = 'Disable Recent Documents Tracking'
        Type = 'registry'
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Key = 'NoRecentDocsHistory'
        Value = 1
        Reboot = $false
        AllUsers = $true   # SECURITY (v0.55): Apply to all loaded user hives, not just HKCU
    }
    'fs-jump-lists' = @{
        Name = 'Disable Jump Lists'
        Type = 'registry'
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Key = 'NoRecentDocsMenu'
        Value = 1
        Reboot = $false
        AllUsers = $true
    }
    'fs-thumbnails' = @{
        Name = 'Disable Thumbnail Cache'
        Type = 'registry'
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Key = 'DisableThumbnailCache'
        Value = 1
        Reboot = $false
        AllUsers = $true
    }
    'fs-prefetch' = @{
        Name = 'Disable Prefetch'
        Type = 'registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
        Key = 'EnablePrefetcher'
        Value = 0
        Reboot = $false
        Impact = 'Application launch times may increase slightly on first run.'
    }
    'fs-superfetch' = @{
        Name = 'Disable SysMain (Superfetch)'
        Type = 'service'
        Service = 'SysMain'
        StartType = 'Disabled'
        Reboot = $false
    }
    'fs-user-assist' = @{
        Name = 'Clear UserAssist History'
        Type = 'script'
        Reboot = $false
        Note = 'Windows re-records immediately on next program launch. Re-run periodically.'
    }
    'fs-timeline' = @{
        Name = 'Disable Activity History'
        Type = 'multi-registry'
        Steps = @(
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Key = 'EnableActivityFeed'; Value = 0 }
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Key = 'PublishUserActivities'; Value = 0 }
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Key = 'UploadUserActivities'; Value = 0 }
        )
        Reboot = $false
    }
    'fs-search-index' = @{
        Name = 'Disable Windows Search Indexing'
        Type = 'service'
        Service = 'WSearch'
        StartType = 'Disabled'
        Reboot = $false
        Impact = 'Start menu and Explorer search will be significantly slower.'
    }
    'fs-ps-history' = @{
        Name = 'Clear PowerShell History'
        Type = 'script'
        Reboot = $false
        Note = 'PSReadLine re-records on next PS session. Add "Set-PSReadLineOption -HistorySaveStyle SaveNothing" to your profile to disable permanently.'
        Impact = 'Only clears current user history. Other user profiles and PowerShell transcript logs (if GPO-enabled) are not affected. NTFS journal may retain fragments.'
    }
    'fs-bam' = @{
        Name = 'Clear BAM Execution History'
        Type = 'script'
        Reboot = $false
        Note = 'BAM repopulates on next program execution.'
    }
    'fs-network-profiles' = @{
        Name = 'Clear Network Profile History'
        Type = 'script'
        Reboot = $false
        Note = 'Active connection regenerates its profile. Wi-Fi passwords NOT affected.'
        Impact = 'May need to re-select network type (Public/Private) for known networks.'
    }
    'fs-shellbags' = @{
        Name = 'Clear ShellBags Folder History'
        Type = 'script'
        Reboot = $false
        Impact = 'Explorer folder view customisations (column widths, sort order) will reset.'
    }
    # v0.47: New fixes
    'screen-timeout' = @{
        Name = 'Set Display Timeout (5 min AC / 3 min DC)'
        Type = 'command'
        Command = "$($script:Bin.powercfg) /change monitor-timeout-ac 5; $($script:Bin.powercfg) /change monitor-timeout-dc 3"
        Reboot = $false
    }
    'builtin-admin' = @{
        Name = 'Disable Built-in Administrator Account'
        Type = 'script'
        Reboot = $false
        Note = 'Re-enable with: Get-LocalUser | Where-Object {$_.SID.Value -like "*-500"} | Enable-LocalUser'
        Impact = 'The built-in Administrator account will be disabled. If this is your only admin account, you will be locked out. Ensure another admin account exists first.'
    }
    'bitlocker-pin' = @{
        Name = 'Add BitLocker Pre-Boot PIN'
        Type = 'script'
        Reboot = $true
        Note = 'You will be prompted to type a PIN in the console. Minimum 6 digits. You MUST remember this PIN or you cannot boot.'
        Impact = 'Every boot will require you to enter the PIN before Windows loads. If you forget the PIN, you will need the BitLocker recovery key to access your machine. Ensure your recovery key is backed up before proceeding.'
    }
    'fs-shadow-copies' = @{
        Name = 'Delete All Volume Shadow Copies'
        Type = 'command'
        Command = "$($script:Bin.vssadmin) delete shadows /all /quiet"
        Reboot = $false
        Impact = 'All System Restore points will be permanently deleted. You will not be able to roll back to a previous system state. Create a manual backup before proceeding if needed.'
    }
    'fs-wer' = @{
        Name = 'Delete Windows Error Reports'
        Type = 'script'
        Reboot = $false
        Note = 'New crash reports will accumulate again. Re-run periodically.'
    }
    'fs-amcache' = @{
        Name = 'Clear Amcache Execution History'
        Type = 'script'
        Reboot = $false
        Note = 'Windows re-records program execution in Amcache on next launch. Re-run periodically.'
    }
    'fs-shimcache' = @{
        Name = 'Clear AppCompatCache (ShimCache)'
        Type = 'script'
        Reboot = $true
        Note = 'Cache regenerates on reboot from in-memory data. Full clearance requires reboot followed by re-running this fix.'
    }
    'fs-srum' = @{
        Name = 'Clear SRUM Resource Usage Database'
        Type = 'script'
        Reboot = $false
        Note = 'Stops the Diagnostic Policy Service temporarily. SRUM re-records usage after service restarts.'
        Impact = 'The SRUM database tracks per-application network, CPU, and energy usage for up to 30 days. Deleting it removes this telemetry. The DPS service will be restarted after deletion.'
    }
    # v0.48: Physical access fixes
    'account-lockout' = @{
        Name = 'Set Account Lockout (5 attempts / 30 min)'
        Type = 'command'
        Command = "$($script:Bin.net) accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30"
        Reboot = $false
    }
    'password-policy' = @{
        Name = 'Enforce Password Policy (8 char minimum)'
        Type = 'command'
        Command = "$($script:Bin.net) accounts /minpwlen:8 /uniquepw:5"
        Reboot = $false
        Note = 'Sets minimum 8 characters and 5 password history. NIST 800-63B recommends against complexity requirements (they produce predictable patterns like Password1!). Length matters more.'
        Impact = 'Existing passwords shorter than 8 characters remain valid until next change. New passwords must meet the minimum length.'
    }
    'ctrl-alt-del' = @{
        Name = 'Require Ctrl+Alt+Del at Login'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Key = 'DisableCAD'
        Value = 0
        Reboot = $false
    }
    'last-username' = @{
        Name = 'Hide Last Logged-in Username'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Key = 'DontDisplayLastUserName'
        Value = 1
        Reboot = $false
    }
    'lsa-protection' = @{
        Name = 'Enable LSA Protection (RunAsPPL)'
        Type = 'registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Key = 'RunAsPPL'
        Value = 1
        Reboot = $true
        Note = 'Some third-party security products may not be compatible with LSA PPL.'
        Impact = 'Credential providers, plug-ins, and drivers that are not signed by Microsoft may fail to load into LSASS. Test thoroughly before deploying to fleet.'
    }
    'usb-storage' = @{
        Name = 'Block USB Mass Storage Devices'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
        Key = 'Deny_All'
        Value = 1
        Reboot = $false
        Impact = 'USB flash drives, external hard drives, and SD cards will not be accessible. Keyboards, mice, and other non-storage USB devices are unaffected.'
    }
    'usb-install' = @{
        Name = 'Block New USB Device Installation'
        Type = 'multi-registry'
        Steps = @(
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'; Key = 'DenyUnspecified'; Value = 1 }
        )
        Reboot = $false
        Note = 'Blocks installation of new device classes not already present. Existing devices continue to work.'
        Impact = 'New USB peripherals (including legitimate ones) will not install until this policy is removed. Pre-connected devices are unaffected.'
    }
    'autorun' = @{
        Name = 'Disable AutoRun and AutoPlay'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Key = 'NoDriveTypeAutoRun'
        Value = 255
        Reboot = $false
    }
    'bluetooth' = @{
        Name = 'Disable Bluetooth'
        Type = 'script'
        Reboot = $false
        Note = 'Disables all Bluetooth adapters. Re-enable via Device Manager.'
        Impact = 'Bluetooth mice, keyboards, headphones, and all other Bluetooth devices will disconnect and stop working.'
    }
    'wifi-autoconnect' = @{
        Name = 'Disable Auto-Connect to Open Networks'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'
        Key = 'AutoConnectAllowedOEM'
        Value = 0
        Reboot = $false
    }
    'camera-privacy' = @{
        Name = 'Deny App Access to Camera'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'
        Key = 'Value'
        Value = 'Deny'
        RegType = 'String'
        Reboot = $false
        Note = 'Sets system-wide default to Deny. Individual apps can still be allowed in Settings > Privacy.'
        Impact = 'Video conferencing apps (Teams, Zoom) will need manual camera permission granted in Privacy settings.'
    }
    'mic-privacy' = @{
        Name = 'Deny App Access to Microphone'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone'
        Key = 'Value'
        Value = 'Deny'
        RegType = 'String'
        Reboot = $false
        Note = 'Sets system-wide default to Deny. Individual apps can still be allowed in Settings > Privacy.'
        Impact = 'Voice calls, dictation, and any app using the microphone will need manual permission granted in Privacy settings.'
    }
    'winrm' = @{
        Name = 'Disable WinRM Remote Management'
        Type = 'service'
        Service = 'WinRM'
        StartType = 'Disabled'
        Reboot = $false
        Impact = 'Remote PowerShell, Ansible, SCCM push installs, and any tool using WS-Management will stop working.'
    }
    'bl-network-unlock' = @{
        Name = 'Disable BitLocker Network Unlock'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        Key = 'OSManageNKP'
        Value = 0
        Reboot = $true
        Note = 'Prevents BitLocker from auto-unlocking when connected to the corporate network.'
    }
    'removable-encrypt' = @{
        Name = 'Require Encryption on Removable Drives'
        Type = 'registry'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        Key = 'RDVDenyWriteAccess'
        Value = 1
        Reboot = $false
        Impact = 'Unencrypted USB drives become read-only. Data cannot be written to removable media unless BitLocker To Go is enabled on the drive.'
    }
}

# ============================================================================
#  ATTACK SCENARIOS - Maps checks to real-world threats
# ============================================================================
$script:AttackScenarios = @(
    @{
        id = 'cold-boot'
        name = 'Cold Boot Attack'
        severity = 'high'
        icon = '[ICE]'
        description = 'Attacker steals your powered-off laptop and extracts credentials from hiberfil.sys, pagefile, or residual RAM.'
        contributing = @('bitlocker', 'bitlocker-pin', 'enhanced-pin', 'tpm-lockout', 'tpm-bus', 'auto-logon', 'fast-startup', 'hibernate', 'kernel-paging', 'clear-pagefile', 'crash-dump', 'bl-network-unlock')
        mitigation = 'Disable hibernation, fast startup, and ensure pagefile is cleared. BitLocker with pre-boot PIN adds significant protection.'
    }
    @{
        id = 'dma-attack'
        name = 'DMA / Thunderbolt Attack'
        severity = 'high'
        icon = '[ZAP]'
        description = 'If DMA-capable ports exist (Thunderbolt, FireWire), a malicious device can read entire RAM in seconds. VBS/HVCI provide defense even without external ports.'
        contributing = @('dma-guard', 'vbs', 'hvci', 'credential-guard', 'kernel-debug', 'bitlocker-pin', 'tpm-bus')
        mitigation = 'Enable VBS, HVCI, and Kernel DMA Protection if you have Thunderbolt. Credential Guard isolates credentials.'
    }
    @{
        id = 'evil-maid'
        name = 'Evil Maid Attack'
        severity = 'medium'
        icon = '[SPY]'
        description = 'Attacker with brief physical access modifies boot chain or installs backdoor while you are away.'
        contributing = @('secure-boot', 'uefi-vars', 'bitlocker', 'auto-logon', 'arso', 'winre', 'kernel-debug', 'test-signing', 'uac-credential-prompt', 'local-password', 'amt-provisioned', 'account-lockout', 'password-policy', 'ctrl-alt-del', 'last-username', 'usb-storage', 'usb-install', 'autorun', 'builtin-admin')
        mitigation = 'Enable Secure Boot, BitLocker with TPM+PIN, and set a BIOS password.'
    }
    @{
        id = 'sleep-wake'
        name = 'Sleep Wake Attack'
        severity = 'medium'
        icon = '[ZZZ]'
        description = 'Laptop in Modern Standby wakes silently in your bag, connects to hostile network, runs scheduled tasks.'
        contributing = @('s0-standby', 'platform-aoac', 'cs-enabled', 'wake-timers', 'bluetooth', 'wifi-autoconnect', 'camera-privacy', 'mic-privacy')
        mitigation = 'Disable Modern Standby (S0). Use classic S3 sleep or full shutdown.'
    }
    @{
        id = 'forensic'
        name = 'Forensic Recovery'
        severity = 'medium'
        icon = '[LAB]'
        description = 'After device sale, disposal, or seizure, the disk is analysed offline. If BitLocker is off or uses used-space-only encryption, deleted files are recoverable in plaintext from unencrypted free space. Memory dumps and hibernation files may contain credentials.'
        contributing = @('bitlocker', 'bitlocker-fullvol', 'fast-startup', 'hibernate', 'kernel-paging', 'clear-pagefile', 'crash-dump', 'nmi-dump', 'removable-encrypt')
        mitigation = 'Full-volume BitLocker encryption (not used-space-only), clear pagefile at shutdown, disable crash dumps, secure erase before disposal.'
    }
    @{
        id = 'coercion'
        name = 'Device Compromise / Post-Access'
        severity = 'high'
        icon = '[COE]'
        preview = $true
        description = 'If an attacker gains access to your unlocked device - via theft, coercion, or compelled unlock - how much historical activity can they reconstruct? Defence: minimise the data exposure surface so a compromised device reveals as little as possible.'
        contributing = @(
            'fs-recent-docs', 'fs-jump-lists', 'fs-thumbnails', 'fs-prefetch',
            'fs-superfetch', 'fs-user-assist', 'fs-timeline', 'fs-search-index',
            'fs-ps-history', 'fs-bam', 'fs-network-profiles', 'fs-shellbags', 'fs-usb-history',
            'fs-amcache', 'fs-shimcache', 'fs-srum', 'fs-shadow-copies', 'fs-wer',
            'crash-dump', 'clear-pagefile', 'hibernate', 'fast-startup',
            'uac-credential-prompt', 'local-password',
            'lsa-protection', 'winrm', 'ps-language-mode'
        )
        mitigation = 'Disable unnecessary data tracking (Prefetch, Recent Docs, Activity History). Reduce the information Windows accumulates about your activity. Key escrow to team admin (coming soon).'
    }
)

# ============================================================================
#  GLOBALS
# ============================================================================
$script:IsMonitorMode = $Monitor.IsPresent
$script:SkipNVD = $NoNVD.IsPresent -or $Monitor.IsPresent
$script:IsDryRun = $DryRun.IsPresent
$script:IsAuditMode = $Audit.IsPresent
$script:IsReadOnly = $ReadOnly.IsPresent
$script:MonitorDataDir = Join-Path $script:TrustedProgramData 'HardTarget'
if ($OutputDir) {
    $script:UserOutputDir = $OutputDir
} else {
    # SECURITY (v0.39): Default to ProgramData\HardTarget instead of Downloads.
    # Scan results contain detailed security posture (BitLocker status, TPM type,
    # DMA ports, Secure Boot state). Downloads folder is synced to OneDrive on many
    # corporate machines and is commonly shared inadvertently.
    $script:UserOutputDir = $script:MonitorDataDir
}
# SECURITY (v0.73): Do NOT pre-create MonitorDataDir here. Let Initialize-SecureDirectory
# (line ~2530) handle the full creation lifecycle. Pre-creating with New-Item bypasses the
# staging directory pattern (random name → apply ACLs → atomic rename) and leaves the
# directory with inherited BUILTIN\Users write access until Set-Acl runs ~850 lines later.
# Only create UserOutputDir if it's a separate user-specified path outside the protected dir.
if ($script:UserOutputDir -ne $script:MonitorDataDir -and -not (Test-Path $script:UserOutputDir)) {
    New-Item -Path $script:UserOutputDir -ItemType Directory -Force | Out-Null
}

$script:TotalPass = 0
$script:TotalCondPass = 0
$script:TotalWarn = 0
$script:TotalFail = 0
$script:JsonChecks = @()
$script:MachineInfo = @{}
$script:ServerPort = 0
$script:RestorePointCreated = $false
$script:HasDMAPorts = $false
$script:LastRequestTime = $null
$script:IdleTimeoutMinutes = 15
$script:FixRequestLog = @()
$script:AutoShutdownAt = $null
$script:ConsolePending = $false       # Prevents concurrent Read-Host blocking (fixes + monitor ops) (Read-Host blocks server)
$script:AppliedFixes = @()            # Tracks successfully applied fix IDs for auto-shutdown
$script:RequestedPort = if ($Port -gt 0) { $Port } else { 0 }  # User-specified port override (M-7)
# L-1 FIX (v0.45): Validate port range to prevent binding to privileged ports or invalid values
if ($script:RequestedPort -gt 0 -and ($script:RequestedPort -lt 1024 -or $script:RequestedPort -gt 65535)) {
    Write-Host "    WARNING: Port $script:RequestedPort is outside recommended range 1024-65535." -ForegroundColor Yellow
}
$script:LastFixActivityTime = $null   # L-1 FIX: Separate timestamp for fix-specific idle lock

# ============================================================================
#  ADMIN CHECK
# ============================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-NOT $isAdmin) {
    Write-Host ''
    Write-Host '  WARNING: Not running as Administrator!' -ForegroundColor Red
    Write-Host '  Some checks will fail. Right-click the BAT and Run as administrator.' -ForegroundColor Yellow
    Write-Host ''
    Start-Sleep -Seconds 2
}

# ============================================================================
#  MONITOR INSTALL / UNINSTALL HELPERS
# ============================================================================
$script:UninstallRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HardTarget'


function Install-HardTargetMonitor {
    param([string]$ScriptFilePath)
    
    if (-not $ScriptFilePath) { throw 'Script path unknown. Run from a saved .ps1 file.' }
    
    $taskName = 'HardTarget Monitor'
    $monDir = Join-Path $script:TrustedProgramData 'HardTarget'
    $protectedScript = Join-Path $monDir 'HardTarget_Monitor.ps1'
    $verifyScript = Join-Path $monDir 'HardTarget_Verify.ps1'
    
    # 1. Create protected directory with strict OWNERSHIP + ACLs BEFORE copying anything.
    # SECURITY (v0.70): Uses Initialize-SecureDirectory which implements the staging
    # directory pattern -- create with random name, apply ACLs, rename atomically.
    # This eliminates the TOCTOU race between New-Item and Set-Acl that existed in the
    # v0.55-v0.69 inline logic. Both the global init block and the installer now use
    # the same hardened helper.
    Initialize-SecureDirectory -Path $monDir
    
    # 2. Copy script to protected directory (ACL-protected before file lands)
    # SECURITY (v0.62): Explicitly delete existing file objects BEFORE writing.
    # Copy-Item -Force and Set-Content -Force overwrite content but PRESERVE the
    # file's Security Descriptor (ACL). If a standard user pre-created these files
    # before the directory was locked down, they retain CREATOR OWNER FullControl
    # even after the directory ACL is tightened. Remove-Item destroys the file
    # object entirely; the subsequent copy creates a new object inheriting the
    # directory's restrictive ACL. This closes the ACL Preservation LPE.
    try {
        if (Test-Path $protectedScript) { Remove-Item -Path $protectedScript -Force -ErrorAction Stop }
        if (Test-Path $verifyScript) { Remove-Item -Path $verifyScript -Force -ErrorAction Stop }
    } catch {
        throw "SECURITY ABORT: Could not remove existing script files in $monDir. An attacker may have set restrictive ACLs. Delete them manually and retry: $_"
    }
    try {
        # SECURITY (v0.76): Write from verified in-memory bytes when available.
        # The elevated process received the script via named pipe and verified its hash
        # before execution. Writing from $script:VerifiedScriptBytes bypasses the disk
        # file entirely, which may have been swapped after the initial read.
        if ($script:VerifiedScriptBytes) {
            [System.IO.File]::WriteAllBytes($protectedScript, $script:VerifiedScriptBytes)
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try { $hashBytes = $sha.ComputeHash($script:VerifiedScriptBytes) } finally { $sha.Dispose() }
            $srcHash = -join ($hashBytes | ForEach-Object { $_.ToString('x2') }).ToUpper()
        }
        else {
            # Fallback: already-elevated context (no bootstrapper). Copy from disk.
            Copy-Item -Path $ScriptFilePath -Destination $protectedScript -Force -ErrorAction Stop
            $srcHash = (Get-FileHash $ScriptFilePath -Algorithm SHA256 -ErrorAction Stop).Hash
        }
        $dstHash = (Get-FileHash $protectedScript -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($srcHash -ne $dstHash) {
            throw "Copy verification failed: hash mismatch"
        }
    } catch {
        throw "Could not copy script to protected directory: $_"
    }
    
    # 3. Generate external integrity verification wrapper.
    # SECURITY (v0.52): The previous design had the monitor script verify its own hash.
    # An attacker who overwrites the script simply removes the hash-checking code.
    # The scheduled task now points to this minimal wrapper which:
    #   a) reads the expected hash from the registry
    #   b) computes the SHA256 of the monitor script
    #   c) only invokes the monitor if they match
    # The wrapper is deliberately tiny (~30 lines) to minimise its own attack surface.
    # Both the wrapper hash and the monitor hash are stored in the registry.
    $verifyContent = @'
# HardTarget Verify-and-Run Wrapper (auto-generated at install)
# DO NOT MODIFY - this script is integrity-checked by its own hash.
# SECURITY (v0.53): Reads monitor script into memory, hashes the in-memory
# content, then executes from memory via ScriptBlock. This eliminates the
# TOCTOU race where an attacker swaps the file between hash check and execution.
param([switch]$Monitor,[string]$OutputDir)
$ErrorActionPreference = 'Stop'
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HardTarget'
$monDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$monScript = Join-Path $monDir 'HardTarget_Monitor.ps1'
$ndjson = Join-Path $monDir 'HardTarget_monitor.ndjson'
function Log($type,$msg){try{(@{timestamp=(Get-Date -Format 'o');type=$type;error=$msg;computer=$env:COMPUTERNAME}|ConvertTo-Json -Compress)|Out-File $ndjson -Append -Encoding UTF8}catch{}}
try {
    if (-not (Test-Path $monScript)) { Log 'integrity_failure' "Monitor script not found: $monScript"; exit 1 }
    $stored = (Get-ItemProperty -Path $regPath -Name 'InstalledHash' -EA Stop).InstalledHash
    if (-not $stored) { Log 'integrity_failure' 'InstalledHash missing from registry'; exit 1 }
    # Read entire script into memory - all subsequent operations use this copy
    $scriptBytes = [System.IO.File]::ReadAllBytes($monScript)
    # Hash the in-memory bytes (same algorithm as Get-FileHash uses)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hashBytes = $sha.ComputeHash($scriptBytes) } finally { $sha.Dispose() }
    $actual = [BitConverter]::ToString($hashBytes) -replace '-',''
    if ($actual -ne $stored) {
        $msg = "INTEGRITY FAILURE: Expected=$stored Got=$actual Path=$monScript"
        try { Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9999 -EntryType Error -Message "HardTarget $msg" -EA SilentlyContinue } catch {}
        Log 'integrity_failure' $msg
        exit 1
    }
    Log 'integrity_ok' "hash=$actual"
    try { Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9001 -EntryType Information -Message "HardTarget integrity verified: $actual" -EA SilentlyContinue } catch {}
    # Execute from the verified in-memory content - no second file read
    $scriptText = [System.Text.Encoding]::UTF8.GetString($scriptBytes)
    if ($scriptText.Length -gt 0 -and $scriptText[0] -eq [char]65279) { $scriptText = $scriptText.Substring(1) }
    $sb = [scriptblock]::Create($scriptText)
    $invokeArgs = @{ Monitor = $true }
    if ($OutputDir) { $invokeArgs['OutputDir'] = $OutputDir }
    & $sb @invokeArgs
} catch {
    Log 'integrity_check_error' "$_"
    try { Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9998 -EntryType Error -Message "HardTarget VERIFY ERROR: $_" -EA SilentlyContinue } catch {}
    exit 1
}
'@
    try {
        Set-Content -Path $verifyScript -Value $verifyContent -Encoding UTF8 -Force -ErrorAction Stop
        $verifyHash = (Get-FileHash $verifyScript -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        throw "Could not create verify wrapper: $_"
    }
    
    # 4. Scheduled task - points at VERIFY WRAPPER, not monitor script directly.
    # SECURITY (v0.52): The wrapper performs integrity verification externally,
    # so overwriting HardTarget_Monitor.ps1 cannot remove the hash check.
    # SECURITY (v0.53): Fully qualified PowerShell path. Scheduled task runs as
    # SYSTEM -- bare 'powershell.exe' is vulnerable to PATH hijacking.
    # SECURITY (v0.78): Use trusted machine-scope SystemRoot for scheduled task binary.
    $psExeFull = Join-Path $script:TrustedSystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action = New-ScheduledTaskAction -Execute $psExeFull `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$verifyScript`" -Monitor"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
        -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    # SECURITY (v0.40): Verify event log source exists after creation. If registration
    # fails (permission issue, name collision), all subsequent Write-EventLog calls
    # in the monitor silently fail - including integrity failure and drift alerting.
    try { New-EventLog -LogName Application -Source 'HardTarget' -ErrorAction SilentlyContinue } catch {}
    $script:EventLogAvailable = $false
    try {
        $script:EventLogAvailable = [System.Diagnostics.EventLog]::SourceExists('HardTarget')
    } catch {}
    if (-not $script:EventLogAvailable) {
        Write-Host "    [WARN] Could not register 'HardTarget' event log source. Event-based alerting disabled." -ForegroundColor Yellow
        # SECURITY (v0.43): Structured NDJSON fallback logging
        $evtWarnDir = Join-Path $script:TrustedProgramData 'HardTarget'
        if (Test-Path $evtWarnDir) {
            try { Write-SafeFile -Path (Join-Path $evtWarnDir 'HardTarget_monitor.ndjson') -Content (@{ timestamp = (Get-Date -Format 'o'); type = 'eventlog_unavailable'; error = "Event log source 'HardTarget' could not be registered. Monitor alerts will use file-based logging only."; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress) -Append } catch {}
        }
    }
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    
    # 4. Run immediately to create baseline (don't wait for first trigger)
    try { Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue } catch {}
    
    # 5. Start Menu shortcut
    # SECURITY (v0.77): Previous versions used New-Object -ComObject WScript.Shell
    # to create a .lnk shortcut. COM resolution checks HKCU\Software\Classes\CLSID
    # before HKLM, allowing a standard user to plant a malicious CLSID entry that
    # gets loaded as Administrator. Shortcut creation removed; the scheduled task
    # and Add/Remove Programs entry provide sufficient access points.
    
    # 6. Add/Remove Programs
    try {
        if (-not (Test-Path $script:UninstallRegPath)) {
            New-Item -Path $script:UninstallRegPath -Force | Out-Null
        }
        $uninstallCmd = "$psExeFull -NoProfile -ExecutionPolicy Bypass -File `"$protectedScript`" -Uninstall"
        Set-ItemProperty -Path $script:UninstallRegPath -Name 'DisplayName' -Value 'HardTarget Security Monitor'
        Set-ItemProperty -Path $script:UninstallRegPath -Name 'UninstallString' -Value $uninstallCmd
        Set-ItemProperty -Path $script:UninstallRegPath -Name 'DisplayVersion' -Value '0.83'
        Set-ItemProperty -Path $script:UninstallRegPath -Name 'Publisher' -Value 'HardTarget'
        Set-ItemProperty -Path $script:UninstallRegPath -Name 'InstallLocation' -Value $monDir
        Set-ItemProperty -Path $script:UninstallRegPath -Name 'NoModify' -Value 1 -Type DWord
        Set-ItemProperty -Path $script:UninstallRegPath -Name 'NoRepair' -Value 1 -Type DWord
        Set-ItemProperty -Path $script:UninstallRegPath -Name 'HelpLink' -Value 'https://github.com/hardtarget2026/hardtarget'
        Set-ItemProperty -Path $script:UninstallRegPath -Name 'DisplayIcon' -Value "$($script:TrustedSystemRoot)\System32\SecurityHealthAgent.dll,0"
        Set-ItemProperty -Path $script:UninstallRegPath -Name 'Comments' -Value 'Hourly security posture drift monitor.'
        Set-ItemProperty -Path $script:UninstallRegPath -Name 'InstalledHash' -Value $srcHash
        Set-ItemProperty -Path $script:UninstallRegPath -Name 'VerifyHash' -Value $verifyHash
    } catch {}
}

function Uninstall-HardTargetMonitor {
    param([switch]$Purge)
    
    $taskName = 'HardTarget Monitor'
    $monDir = Join-Path $script:TrustedProgramData 'HardTarget'
    $removed = $false
    
    # SECURITY (v0.40): Log uninstall event BEFORE removing components.
    # Creates audit trail even if event log source is later removed.
    $caller = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { 'unknown' }
    $uninstallMsg = "HardTarget Monitor uninstalled by $caller. Purge=$($Purge.IsPresent)"
    try { Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9003 -EntryType Warning -Message $uninstallMsg -ErrorAction SilentlyContinue } catch {}
    
    # 1. Scheduled task
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        $removed = $true
    } catch {}
    
    # 2. Start Menu shortcut
    $slPath = Join-Path $script:TrustedProgramData 'Microsoft\Windows\Start Menu\Programs\HardTarget Monitor.lnk'
    if (Test-Path $slPath) { Remove-Item $slPath -Force -ErrorAction SilentlyContinue }
    
    # 3. Add/Remove Programs entry
    if (Test-Path $script:UninstallRegPath) {
        Remove-Item $script:UninstallRegPath -Force -ErrorAction SilentlyContinue
    }
    
    # 4. Always remove the orphaned script copies
    $protectedScript = Join-Path $monDir 'HardTarget_Monitor.ps1'
    $verifyScript = Join-Path $monDir 'HardTarget_Verify.ps1'
    if (Test-Path $protectedScript) {
        Remove-Item $protectedScript -Force -ErrorAction SilentlyContinue
        $removed = $true
    }
    if (Test-Path $verifyScript) {
        Remove-Item $verifyScript -Force -ErrorAction SilentlyContinue
        $removed = $true
    }
    
    # 5. If purge requested, remove entire data directory
    # SECURITY (v0.52): Check if monDir is a junction/symlink before recursive delete.
    # An attacker could replace the directory with a junction pointing to C:\ - 
    # Remove-Item -Recurse would then delete the entire system drive.
    if ($Purge -and (Test-Path $monDir)) {
        if (Test-ReparsePoint $monDir) {
            Write-Host "    [SECURITY] $monDir is a reparse point (junction/symlink). Removing link only." -ForegroundColor Red
            try { [System.IO.Directory]::Delete($monDir, $false) } catch { Remove-Item $monDir -Force -ErrorAction SilentlyContinue }
        } else {
            Remove-ItemSafeRecurse -Path $monDir -RemoveRoot
        }
    }
    
    return $removed
}

# ============================================================================
#  HELPERS
# ============================================================================
function Compare-TokenConstantTime {
    # SECURITY (v0.39): Constant-time string comparison for auth tokens.
    # SECURITY (v0.44): M-1 FIX: Previously returned $false immediately on length
    # mismatch, leaking expected token length via timing. Now hashes both inputs
    # to fixed-length before comparison, eliminating the side channel.
    param([string]$A, [string]$B)
    if ([string]::IsNullOrEmpty($A) -or [string]::IsNullOrEmpty($B)) { return $false }
    # Hash both to fixed length to prevent length leakage
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashA = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($A))
        $hashB = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($B))
    } finally { $sha.Dispose() }
    $diff = 0
    for ($i = 0; $i -lt $hashA.Length; $i++) {
        $diff = $diff -bor ($hashA[$i] -bxor $hashB[$i])
    }
    return ($diff -eq 0)
}

function Sanitize-HtmlString {
    # Strip any HTML/script injection from strings that end up in the dashboard.
    # Used for NVD responses, WMI strings, or any external data rendered in innerHTML.
    param([string]$Text)
    if (-not $Text) { return '' }
    # IMPORTANT: & must be replaced FIRST to avoid double-encoding &lt; etc.
    $Text = $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
    return $Text
}

function Test-ReparsePoint {
    # SECURITY (v0.52): Checks if a path is a reparse point (junction, symlink, mount point).
    # Used to prevent junction-based arbitrary file deletion/overwrite attacks where an
    # attacker plants a junction in a user-writable directory that redirects admin-privilege
    # operations into critical system directories.
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    try {
        $item = Get-Item $Path -Force -ErrorAction Stop
        return ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    } catch { return $false }
}

function Test-RegistrySymlink {
    # SECURITY (v0.53): Detects registry symbolic links (REG_LINK).
    # Standard users can plant REG_LINK keys in their own hive (HKEY_USERS\{SID}\...)
    # using NtCreateKey with REG_OPTION_CREATE_LINK. PowerShell's Remove-Item follows
    # these links transparently, so our elevated SYSTEM process can be tricked into
    # deleting HKLM\SYSTEM, HKLM\SAM, or any other critical hive.
    # Detection: Open the key via .NET RegistryKey API (which also follows links), then
    # compare the resolved Name against the expected path. If they differ, it's a symlink.
    param(
        [string]$ExpectedPath,
        [string]$ProviderPath
    )
    try {
        # Normalize the expected path for comparison
        $cleaned = $ExpectedPath -replace '^Registry::', ''
        $cleaned = $cleaned -replace '^HKCU:\\', 'HKEY_CURRENT_USER\'
        $cleaned = $cleaned -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
        # Determine hive and subpath
        $hive = $null
        $subPath = ''
        if ($cleaned -match '^HKEY_USERS\\(.+)$') {
            $hive = [Microsoft.Win32.Registry]::Users
            $subPath = $Matches[1]
        }
        elseif ($cleaned -match '^HKEY_CURRENT_USER\\(.+)$') {
            $hive = [Microsoft.Win32.Registry]::CurrentUser
            $subPath = $Matches[1]
        }
        elseif ($cleaned -match '^HKEY_LOCAL_MACHINE\\(.+)$') {
            $hive = [Microsoft.Win32.Registry]::LocalMachine
            $subPath = $Matches[1]
        }
        if (-not $hive -or -not $subPath) { return $false }
        $key = $hive.OpenSubKey($subPath, $false)
        if (-not $key) { return $false }
        try {
            # .Name returns the REAL path after following links
            $resolvedName = $key.Name
            $expectedFull = $hive.Name + '\' + $subPath
            return ($resolvedName -ne $expectedFull)
        }
        finally {
            $key.Close()
        }
    }
    catch {
        # If we can't open it, treat it as suspicious and skip
        return $true
    }
}

function Remove-RegistryKeySafe {
    # SECURITY (v0.53/v0.70): Removes a registry key only after verifying it is not a
    # registry symbolic link (REG_LINK). Prevents elevated processes from being
    # tricked into deleting critical system registry hives.
    #
    # v0.70: Uses HtNativeFile.SafeRegistryDeleteTree for TOCTOU-safe deletion.
    # Opens every key with REG_OPTION_OPEN_LINK (won't follow symlinks), checks for
    # REG_LINK via SymbolicLinkValue query, recursively deletes children through
    # handles, and calls NtDeleteKey (handle-based, atomic). No race window between
    # check and delete because the handle used for checking IS the handle used for
    # deletion. Degraded mode falls back to the v0.53 check-then-act pattern.
    #
    # SECURITY (v0.74): When the native DLL IS loaded but SafeRegistryDeleteTree fails
    # (returns -1), fail CLOSED instead of falling back to the vulnerable degraded mode.
    # An attacker can intentionally trigger native failures (deeply nested keys exceeding
    # path limits, key locking, resource exhaustion) to force degradation into the
    # TOCTOU-vulnerable managed check-then-act pattern. If native protection is available,
    # a native failure is suspicious and must not silently downgrade security.
    # Degraded mode is ONLY used when the native DLL was never loaded.
    #
    # Returns $true if the key was removed or didn't exist, $false if skipped.
    param(
        [string]$ProviderPath,
        [switch]$Recurse
    )
    if (-not (Test-Path $ProviderPath)) { return $true }

    if ($script:HasNativeFileHelper) {
        # Parse provider path into (hiveName, subKeyPath) for P/Invoke
        $cleanPath = $ProviderPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
        $cleanPath = $cleanPath -replace '^Registry::', ''
        $cleanPath = $cleanPath -replace '^HKCU:\\', 'HKEY_CURRENT_USER\'
        $cleanPath = $cleanPath -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
        $cleanPath = $cleanPath -replace '^HKU:\\', 'HKEY_USERS\'

        $hiveName = $null
        $subKeyPath = $null
        if ($cleanPath -match '^(HKEY_USERS)\\(.+)$') {
            $hiveName = 'HKU'; $subKeyPath = $Matches[2]
        } elseif ($cleanPath -match '^(HKEY_CURRENT_USER)\\(.+)$') {
            $hiveName = 'HKCU'; $subKeyPath = $Matches[2]
        } elseif ($cleanPath -match '^(HKEY_LOCAL_MACHINE)\\(.+)$') {
            $hiveName = 'HKLM'; $subKeyPath = $Matches[2]
        }

        if ($hiveName -and $subKeyPath) {
            $result = $script:HtNative::SafeRegistryDeleteTree($hiveName, $subKeyPath)
            if ($result -eq 0) {
                Write-Host "    [SECURITY] Registry symlink detected at $ProviderPath -- skipping delete." -ForegroundColor Red
                return $false
            }
            if ($result -eq 1) { return $true }
            # SECURITY (v0.74): result == -1 with native DLL loaded = fail CLOSED.
            # Do NOT fall through to degraded mode. An attacker can force native failures
            # (deep nesting, key locks, resource exhaustion) to trigger the TOCTOU-vulnerable
            # check-then-act fallback. Refuse to delete rather than risk arbitrary hive wipe.
            if ($script:IsMonitorMode) {
                # SECURITY (v0.74): In Monitor/SYSTEM mode, a native security operation
                # failure is a strong signal of active tampering. FailFast terminates the
                # process immediately with no cleanup -- prevents any further execution in
                # a potentially compromised environment. FailFast writes to Windows Error
                # Reporting, creating a forensic trail.
                [System.Environment]::FailFast(
                    "SECURITY: Native registry delete failed for $ProviderPath. Possible forced-degradation attack. Monitor terminated.")
            }
            Write-Host "    [SECURITY] Native registry delete FAILED for $ProviderPath. Refusing to fall back to vulnerable mode." -ForegroundColor Red
            Write-Host "    [SECURITY] Key was NOT deleted. Manual cleanup may be required." -ForegroundColor Yellow
            return $false
        }
    }

    # Degraded mode: check-then-act (documented TOCTOU window)
    # ONLY reached when the native DLL was never loaded (PS 5.1 type resolution failure,
    # missing DLL, etc). Never reached as a fallback from a native operation failure.
    $expectedPath = $ProviderPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
    $expectedPath = $expectedPath -replace '^Registry::', ''
    if (Test-RegistrySymlink -ExpectedPath $expectedPath -ProviderPath $ProviderPath) {
        Write-Host "    [SECURITY] Registry symlink detected at $ProviderPath -- skipping delete." -ForegroundColor Red
        return $false
    }
    if ($Recurse) {
        $children = Get-ChildItem $ProviderPath -Recurse -ErrorAction SilentlyContinue
        foreach ($child in $children) {
            $childExpected = $child.Name
            if (Test-RegistrySymlink -ExpectedPath $childExpected -ProviderPath $child.PSPath) {
                Write-Host "    [SECURITY] Registry symlink detected at $($child.PSPath) -- skipping entire subtree." -ForegroundColor Red
                return $false
            }
        }
    }
    if ($Recurse) {
        Remove-Item $ProviderPath -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Remove-Item $ProviderPath -Force -ErrorAction SilentlyContinue
    }
    return $true
}

function Remove-ItemSafeRecurse {
    # SECURITY (v0.52-v0.68): Recursively deletes contents of a directory while refusing
    # to follow reparse points (junctions, symlinks, mount points).
    #
    # v0.68: Uses HtNativeFile.LockDirectory() to hold an open handle on each directory
    # with FILE_SHARE_READ|FILE_SHARE_WRITE but NOT FILE_SHARE_DELETE. While the handle
    # is held, no process can rename or delete the directory -- blocking the junction-swap
    # TOCTOU attack where an attacker replaces a real directory with a junction to System32
    # between the reparse check and Get-ChildItem enumeration.
    # Individual files are deleted via SafeDeleteFile (atomic open-check-delete via handle).
    # Empty directories are removed via SafeRemoveDirectory (same pattern).
    #
    # Degraded mode (no P/Invoke): Falls back to path-based GetAttributes checks with
    # the documented TOCTOU window. Parent directory ACLs are the primary defense.
    param([string]$Path, [switch]$RemoveRoot)
    if (-not (Test-Path $Path)) { return }

    if ($script:HasNativeFileHelper) {
        # SECURE PATH: Lock directory via handle, enumerate while locked
        $dirHandle = $script:HtNative::LockDirectory($Path)
        if ($null -eq $dirHandle) {
            # LockDirectory returns null for reparse points, missing dirs, or open failures
            Write-Host "    [SECURITY] Cannot safely lock directory (reparse point or access denied): $Path" -ForegroundColor Red
            return
        }
        try {
            Get-ChildItem $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.PSIsContainer) {
                    # Recurse into subdirectory (gets its own lock)
                    Remove-ItemSafeRecurse -Path $_.FullName -RemoveRoot
                } else {
                    # Atomic handle-based file deletion (won't follow symlinks or hardlinks)
                    if (-not $script:HtNative::SafeDeleteFile($_.FullName)) {
                        # SafeDeleteFile returns false for reparse points, hardlinks, locked files
                        $fileAttrs = try { [System.IO.File]::GetAttributes($_.FullName) } catch { $null }
                        if ($null -ne $fileAttrs -and ($fileAttrs -band [System.IO.FileAttributes]::ReparsePoint)) {
                            Write-Host "    [SECURITY] Skipping reparse point file: $($_.FullName)" -ForegroundColor Red
                        }
                        # else: file locked or already deleted -- not a security issue
                    }
                }
            }
        }
        finally {
            $dirHandle.Dispose()
        }
        if ($RemoveRoot) {
            # Atomic directory removal via handle (verifies not reparse, must be empty)
            $script:HtNative::SafeRemoveDirectory($Path) | Out-Null
        }
    } else {
        # DEGRADED PATH: Path-based checks (documented TOCTOU window)
        if (Test-ReparsePoint $Path) {
            Write-Host "    [SECURITY] Skipping reparse point: $Path" -ForegroundColor Red
            return
        }
        Get-ChildItem $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $freshAttrs = try { [System.IO.File]::GetAttributes($_.FullName) } catch { return }
            if ($freshAttrs -band [System.IO.FileAttributes]::ReparsePoint) {
                Write-Host "    [SECURITY] Skipping reparse point: $($_.FullName)" -ForegroundColor Red
            } elseif ($freshAttrs -band [System.IO.FileAttributes]::Directory) {
                Remove-ItemSafeRecurse -Path $_.FullName -RemoveRoot
            } else {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            }
        }
        if ($RemoveRoot) {
            $rootAttrs = try { [System.IO.File]::GetAttributes($Path) } catch { return }
            if ($rootAttrs -band [System.IO.FileAttributes]::ReparsePoint) {
                Write-Host "    [SECURITY] Root became reparse point during delete: $Path" -ForegroundColor Red
                return
            }
            $remaining = Get-ChildItem $Path -Force -ErrorAction SilentlyContinue
            if (-not $remaining) {
                Remove-Item $Path -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Test-ObjectDepth {
    # SECURITY (v0.68): Pre-serialization depth validator. Walks the object graph
    # and returns $true if all branches fit within the specified depth limit.
    # This replaces post-hoc regex matching on serialized JSON output.
    #
    # PowerShell's ConvertTo-Json -Depth N silently truncates objects beyond depth N
    # by calling .ToString(), producing strings like "System.Collections.Hashtable".
    # The previous approach detected this via regex on the output, but that regex
    # could be tricked by user-controlled strings or bypassed by future code changes.
    # Pre-validating the structure before serialization is immune to both.
    param(
        [object]$Obj,
        [int]$MaxDepth = 10,
        [int]$CurrentDepth = 0
    )
    if ($CurrentDepth -ge $MaxDepth) {
        # At or beyond depth limit. If this node is a primitive/string/null, it's fine.
        # If it's a complex object (hashtable, array, PSObject), truncation will occur.
        if ($null -eq $Obj) { return $true }
        if ($Obj -is [string] -or $Obj -is [int] -or $Obj -is [long] -or
            $Obj -is [double] -or $Obj -is [bool] -or $Obj -is [datetime]) { return $true }
        # Complex object at depth limit = will be truncated
        return $false
    }
    if ($null -eq $Obj) { return $true }
    if ($Obj -is [string] -or $Obj -is [int] -or $Obj -is [long] -or
        $Obj -is [double] -or $Obj -is [bool] -or $Obj -is [datetime]) { return $true }
    if ($Obj -is [System.Collections.IDictionary]) {
        foreach ($val in $Obj.Values) {
            if (-not (Test-ObjectDepth -Obj $val -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1))) {
                return $false
            }
        }
        return $true
    }
    if ($Obj -is [System.Collections.IEnumerable]) {
        foreach ($item in $Obj) {
            if (-not (Test-ObjectDepth -Obj $item -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1))) {
                return $false
            }
        }
        return $true
    }
    if ($Obj -is [PSCustomObject] -or $Obj.PSObject) {
        foreach ($prop in $Obj.PSObject.Properties) {
            if (-not (Test-ObjectDepth -Obj $prop.Value -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1))) {
                return $false
            }
        }
        return $true
    }
    # Unknown type at non-leaf position — assume safe (will serialize as string)
    return $true
}

function Write-SafeFile {
    # SECURITY (v0.52-v0.70): Writes content to a file while mitigating symlink/hardlink
    # overwrite attacks.
    #
    # v0.70: Uses native CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT for ALL file opens.
    # The .NET FileStream constructor follows symlinks transparently -- the returned handle
    # belongs to the target, not the link. The v0.67 IsHandleReparsePoint check was ineffective
    # because it checked the TARGET (e.g. hal.dll), which is always a normal file.
    #
    # APPEND: SafeOpenForAppend opens with FILE_FLAG_OPEN_REPARSE_POINT + FILE_APPEND_DATA.
    #   Kernel opens the link itself, not the target. Handle check detects reparse point.
    #   Rejects hardlinks (nNumberOfLinks > 1). Exclusive access.
    # CREATE: SafeCreateNew deletes existing file/link via DeleteFileW (removes link, not
    #   target), then creates with CREATE_NEW + FILE_FLAG_OPEN_REPARSE_POINT.
    #
    # Both return a SafeFileHandle which is wrapped in a .NET FileStream for writing.
    # Degraded mode (no P/Invoke): falls back to managed FileStream with path-based checks.
    # ACL-protected parent directories remain the primary defense in that mode.
    param([string]$Path, [string]$Content, [switch]$Append)
    $parentDir = Split-Path $Path -Parent
    if ($parentDir -and -not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force -ErrorAction SilentlyContinue | Out-Null
    }
    if ($Append) {
        $fs = $null
        try {
            if ($script:HasNativeFileHelper) {
                # If file doesn't exist yet (fresh install), create it first
                if (-not (Test-Path $Path)) {
                    $createHandle = $script:HtNative::SafeCreateNew($Path)
                    if ($null -eq $createHandle) {
                        Write-Host "    [SECURITY] Cannot safely create file: $Path" -ForegroundColor Red
                        return
                    }
                    $createHandle.Dispose()
                }
                $nativeHandle = $script:HtNative::SafeOpenForAppend($Path)
                if ($null -eq $nativeHandle) {
                    Write-Host "    [SECURITY] File is reparse point or hardlink (native check): $Path" -ForegroundColor Red
                    return
                }
                $fs = [System.IO.FileStream]::new($nativeHandle, [System.IO.FileAccess]::Write)
            } else {
                # Degraded mode: managed FileStream (follows symlinks -- ACL-protected dir is defense)
                $fs = [System.IO.FileStream]::new(
                    $Path, [System.IO.FileMode]::OpenOrCreate,
                    [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                $lockedAttrs = [System.IO.File]::GetAttributes($Path)
                if ($lockedAttrs -band [System.IO.FileAttributes]::ReparsePoint) {
                    Write-Host "    [SECURITY] File is reparse point during append: $Path" -ForegroundColor Red
                    return
                }
            }
            $fs.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content + "`r`n")
            $fs.Write($bytes, 0, $bytes.Length)
            $fs.Flush()
        }
        finally {
            if ($fs) { $fs.Dispose() }
        }
    }
    else {
        # CREATE/OVERWRITE
        $fs = $null
        try {
            if ($script:HasNativeFileHelper) {
                $nativeHandle = $script:HtNative::SafeCreateNew($Path)
                if ($null -eq $nativeHandle) {
                    Write-Host "    [SECURITY] Cannot safely create file: $Path" -ForegroundColor Red
                    return
                }
                $fs = [System.IO.FileStream]::new($nativeHandle, [System.IO.FileAccess]::Write)
            } else {
                # Degraded mode
                if (Test-Path $Path) { [System.IO.File]::Delete($Path) }
                $fs = [System.IO.FileStream]::new(
                    $Path, [System.IO.FileMode]::CreateNew,
                    [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                $postAttrs = [System.IO.File]::GetAttributes($Path)
                if ($postAttrs -band [System.IO.FileAttributes]::ReparsePoint) {
                    Write-Host "    [SECURITY] Symlink race detected at $Path -- aborting write." -ForegroundColor Red
                    $fs.Dispose(); $fs = $null
                    [System.IO.File]::Delete($Path)
                    return
                }
            }
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
            $fs.Write($bytes, 0, $bytes.Length)
            $fs.Flush()
        }
        finally {
            if ($fs) { $fs.Dispose() }
        }
    }
}

function Initialize-SecureDirectory {
    # SECURITY (v0.70): Creates or secures a directory with restrictive ACLs using a
    # staging pattern that eliminates the TOCTOU race in Test-Path → Set-Acl sequences.
    #
    # The problem: any check-then-act on a directory in C:\ProgramData is raceable.
    # Standard users can create directories there (inherited ACLs grant CreateDirectories).
    # Between Move-Item (removing hostile dir) and New-Item + Set-Acl (creating secure dir),
    # the attacker can recreate the directory and swap it for a junction before Set-Acl runs.
    #
    # The fix: Create a staging directory with a random name, apply restrictive ACLs to it
    # while it's inaccessible to attackers (random name = unpredictable), then atomically
    # rename it to the final path. The attacker cannot race because they don't know the
    # staging name, and the ACLs are applied BEFORE the directory is at the known path.
    param([string]$Path)
    $adminSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $adminAccount = $adminSid.Translate([System.Security.Principal.NTAccount])
    $systemAccount = $systemSid.Translate([System.Security.Principal.NTAccount])

    $parentDir = Split-Path $Path -Parent
    $needsCreate = $false

    if (Test-Path $Path) {
        if ($script:HasNativeFileHelper) {
            # SECURITY (v0.70): Lock the directory to prevent swap during checks.
            # LockDirectory opens with FILE_FLAG_OPEN_REPARSE_POINT (won't follow junctions)
            # and excludes FILE_SHARE_DELETE (attacker can't rename/delete while held).
            # If LockDirectory returns null, the path is a reparse point or missing.
            $dirHandle = $script:HtNative::LockDirectory($Path)
            if ($null -eq $dirHandle) {
                # Either a reparse point or open failed — treat as hostile
                Write-Host "    [SECURITY] $Path is a reparse point or cannot be locked. Removing." -ForegroundColor Red
                try { [System.IO.Directory]::Delete($Path, $false) } catch {
                    throw "SECURITY ABORT: Could not remove reparse point at $Path : $_"
                }
                $needsCreate = $true
            } else {
                try {
                    # Directory is locked. Attacker CANNOT swap it for a junction while
                    # we hold the handle (FILE_SHARE_DELETE excluded = no rename/delete).
                    $existingAcl = Get-Acl -Path $Path -ErrorAction Stop
                    $ownerSid = $existingAcl.GetOwner([System.Security.Principal.SecurityIdentifier])
                    if ($ownerSid.Value -notin @('S-1-5-32-544', 'S-1-5-18')) {
                        Write-Host "    [SECURITY] $Path has untrusted owner (SID: $($ownerSid.Value)). Moving aside." -ForegroundColor Red
                        # Must release lock before Move-Item (needs DELETE access)
                        $dirHandle.Dispose(); $dirHandle = $null
                        $junkName = "$Path.hostile_$([System.IO.Path]::GetRandomFileName())"
                        Move-Item -Path $Path -Destination $junkName -Force -ErrorAction Stop
                        $needsCreate = $true
                    } else {
                        # Trusted owner + locked. Safe to Set-Acl — directory can't be
                        # swapped because we hold the handle without FILE_SHARE_DELETE.
                        $acl = New-Object System.Security.AccessControl.DirectorySecurity
                        $acl.SetOwner($adminAccount)
                        $acl.SetAccessRuleProtection($true, $false)
                        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                            $systemAccount, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
                        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                            $adminAccount, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
                        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
                        return  # Already secure
                    }
                } catch {
                    if ($_.Exception.Message -match 'SECURITY ABORT') { throw }
                    Write-Host "    [SECURITY] Cannot read ACL on $Path -- treating as hostile." -ForegroundColor Red
                    if ($dirHandle) { $dirHandle.Dispose(); $dirHandle = $null }
                    try { Remove-ItemSafeRecurse -Path $Path -RemoveRoot } catch {}
                    $needsCreate = $true
                } finally {
                    if ($dirHandle) { $dirHandle.Dispose() }
                }
            }
        } else {
            # Degraded mode: path-based checks (documented TOCTOU window)
            if (Test-ReparsePoint $Path) {
                Write-Host "    [SECURITY] $Path is a reparse point. Removing link." -ForegroundColor Red
                try { [System.IO.Directory]::Delete($Path, $false) } catch {
                    throw "SECURITY ABORT: Could not remove reparse point at $Path : $_"
                }
                $needsCreate = $true
            } else {
                try {
                    $existingAcl = Get-Acl -Path $Path -ErrorAction Stop
                    $ownerSid = $existingAcl.GetOwner([System.Security.Principal.SecurityIdentifier])
                    if ($ownerSid.Value -notin @('S-1-5-32-544', 'S-1-5-18')) {
                        Write-Host "    [SECURITY] $Path has untrusted owner (SID: $($ownerSid.Value)). Moving aside." -ForegroundColor Red
                        $junkName = "$Path.hostile_$([System.IO.Path]::GetRandomFileName())"
                        Move-Item -Path $Path -Destination $junkName -Force -ErrorAction Stop
                        $needsCreate = $true
                    } else {
                        $acl = New-Object System.Security.AccessControl.DirectorySecurity
                        $acl.SetOwner($adminAccount)
                        $acl.SetAccessRuleProtection($true, $false)
                        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                            $systemAccount, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
                        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                            $adminAccount, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
                        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
                        return
                    }
                } catch {
                    if ($_.Exception.Message -match 'SECURITY ABORT') { throw }
                    Write-Host "    [SECURITY] Cannot read ACL on $Path -- treating as hostile." -ForegroundColor Red
                    try { Remove-ItemSafeRecurse -Path $Path -RemoveRoot } catch {}
                    $needsCreate = $true
                }
            }
        }
    } else {
        $needsCreate = $true
    }

    if ($needsCreate) {
        if ($script:HasNativeFileHelper) {
            # STAGING PATTERN: Create randomized staging dir, apply ACLs, rename atomically
            $stagingName = Join-Path $parentDir "HT_staging_$([System.IO.Path]::GetRandomFileName())"
            New-Item -ItemType Directory -Path $stagingName -Force | Out-Null
            $acl = New-Object System.Security.AccessControl.DirectorySecurity
            $acl.SetOwner($adminAccount)
            $acl.SetAccessRuleProtection($true, $false)
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $systemAccount, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $adminAccount, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            Set-Acl -Path $stagingName -AclObject $acl -ErrorAction Stop
            # Atomic rename to final path. If attacker created a directory at $Path
            # between our check and now, the rename will fail. That's safe -- we retry.
            if (Test-Path $Path) {
                # Attacker raced and created it. Move aside again.
                $junk2 = "$Path.hostile_$([System.IO.Path]::GetRandomFileName())"
                Move-Item -Path $Path -Destination $junk2 -Force -ErrorAction SilentlyContinue
            }
            $renamed = $script:HtNative::SafeRenameDirectory($stagingName, $Path)
            if (-not $renamed) {
                # SECURITY (v0.83): Do NOT fallback to managed Move-Item. If $Path exists
                # (attacker-created), Move-Item moves staging INTO it instead of replacing it,
                # leaving the attacker's permissive ACLs on the parent directory.
                try { Remove-Item -Path $stagingName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
                throw "SECURITY ABORT: Could not atomically rename staging directory to $Path. Target may be attacker-controlled."
            }
        } else {
            # Degraded mode: direct create + ACL (documented TOCTOU window)
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
            $acl = New-Object System.Security.AccessControl.DirectorySecurity
            $acl.SetOwner($adminAccount)
            $acl.SetAccessRuleProtection($true, $false)
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $systemAccount, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $adminAccount, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
        }
    }

    # Post-verify: ensure not a reparse point and ownership is correct
    if (Test-ReparsePoint $Path) {
        throw "SECURITY ABORT: $Path is a reparse point after initialization. Possible attack."
    }
    $verifyAcl = Get-Acl -Path $Path -ErrorAction Stop
    $verifySid = $verifyAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($verifySid -notin @('S-1-5-32-544', 'S-1-5-18')) {
        throw "SECURITY ABORT: $Path has untrusted owner after initialization (SID: $verifySid)."
    }
}

# ============================================================================
#  SECURE DIRECTORY INITIALIZATION
#  Must come after all helper function definitions (Test-ReparsePoint,
#  Remove-ItemSafeRecurse, Write-SafeFile) since Initialize-SecureDirectory
#  calls them. Cannot be in the GLOBALS section because PowerShell scripts
#  execute top-to-bottom -- functions must be defined before they are called.
# ============================================================================
# SECURITY (v0.70): Use Initialize-SecureDirectory for all directory security.
# Replaces the inline ACL enforcement that was vulnerable to TOCTOU races.
# The helper uses a staging directory pattern: create with random name, apply ACLs,
# rename atomically. Attacker can't race because the staging name is unpredictable.
try {
    Initialize-SecureDirectory -Path $script:MonitorDataDir
} catch {
    # SECURITY (v0.72): Differentiate exception types. Type resolution failures
    # (PS 5.1 anonymous load context) are benign -- warn and continue. But
    # IOException / UnauthorizedAccessException while elevated indicate active
    # directory tampering (attacker holding oplock, hostile ACLs, junction swap).
    # If we continue with an attacker-owned directory, the auth token file and
    # scan results land in attacker-readable space.
    $initElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $isTypeError = $_.Exception -is [System.Management.Automation.RuntimeException] -and "$_" -match 'Unable to find type'
    if ($initElevated -and -not $isTypeError) {
        Write-Host '' -ForegroundColor Red
        Write-Host "  SECURITY ABORT: Cannot secure $($script:MonitorDataDir) while running elevated." -ForegroundColor Red
        Write-Host "  Possible directory manipulation attack (oplock, junction, or hostile ACLs)." -ForegroundColor Red
        Write-Host "  Error: $_" -ForegroundColor Yellow
        Write-Host "  Type:  $($_.Exception.GetType().FullName)" -ForegroundColor DarkGray
        Write-Host '' -ForegroundColor Red
        Read-Host '  Press Enter to exit'
        exit 1
    }
    # Type resolution failure or non-elevated: warn and continue.
    # The installer applies full native protections during -Install.
    if ($initElevated) {
        Write-Host "    [INFO] Native file helper unavailable -- using basic directory security." -ForegroundColor DarkYellow
    }
}

# ============================================================================
#  COMPLIANCE FRAMEWORK MAPPING (v0.45)
#  Maps each check ID to CIS, NIST 800-171, ISO 27001:2022, CMMC L2 controls.
#  Used by Add-Check for automatic tagging. Flows through to JSON output.
# ============================================================================
$script:FrameworkMap = @{
    # --- BIOS / Firmware ---
    'bios-age'             = @{ cis = @(); nist = @('3.14.1'); iso = @('A.8.8'); cmmc = @('SI.L1-3.14.1') }
    'secure-boot'          = @{ cis = @(); nist = @('3.4.1','3.4.2','3.13.11'); iso = @('A.8.9'); cmmc = @('CM.L2-3.4.1','CM.L2-3.4.2','SC.L2-3.13.11') }
    'uefi-vars'            = @{ cis = @(); nist = @('3.4.5'); iso = @('A.8.9'); cmmc = @('CM.L2-3.4.5') }
    'kernel-debug'         = @{ cis = @(); nist = @('3.4.6','3.4.7'); iso = @('A.8.9'); cmmc = @('CM.L2-3.4.6','CM.L2-3.4.7') }
    'test-signing'         = @{ cis = @(); nist = @('3.4.6','3.4.7','3.14.4'); iso = @('A.8.9','A.8.19'); cmmc = @('CM.L2-3.4.6','SI.L2-3.14.4') }
    'amt-provisioned'      = @{ cis = @(); nist = @('3.10.2','3.10.6'); iso = @('A.7.9'); cmmc = @('PE.L1-3.10.2') }
    # --- Sleep States ---
    's0-standby'           = @{ cis = @(); nist = @('3.10.1','3.10.2'); iso = @('A.7.9','A.8.1'); cmmc = @('PE.L1-3.10.1','PE.L1-3.10.2') }
    'cs-enabled'           = @{ cis = @(); nist = @('3.10.1','3.13.8'); iso = @('A.7.9','A.8.20'); cmmc = @('PE.L1-3.10.1','SC.L2-3.13.8') }
    'fast-startup'         = @{ cis = @(); nist = @('3.8.9','3.13.16'); iso = @('A.8.24'); cmmc = @('MP.L2-3.8.9','SC.L2-3.13.16') }
    'wake-timers'          = @{ cis = @(); nist = @('3.10.1'); iso = @('A.7.9'); cmmc = @('PE.L1-3.10.1') }
    'hibernate'            = @{ cis = @(); nist = @('3.8.9','3.13.16'); iso = @('A.8.10','A.8.24'); cmmc = @('MP.L2-3.8.9','SC.L2-3.13.16') }
    'platform-aoac'        = @{ cis = @(); nist = @('3.10.1'); iso = @('A.7.9'); cmmc = @('PE.L1-3.10.1') }
    # --- TPM ---
    'tpm-present'          = @{ cis = @(); nist = @('3.13.11'); iso = @('A.8.24'); cmmc = @('SC.L2-3.13.11') }
    'tpm-active'           = @{ cis = @(); nist = @('3.13.11'); iso = @('A.8.24'); cmmc = @('SC.L2-3.13.11') }
    'tpm-lockout'          = @{ cis = @(); nist = @('3.1.8'); iso = @('A.8.5'); cmmc = @('AC.L2-3.1.8') }
    'tpm-bus'              = @{ cis = @(); nist = @('3.13.11','3.10.2'); iso = @('A.8.24','A.7.9'); cmmc = @('SC.L2-3.13.11','PE.L1-3.10.2') }
    # --- DMA / Virtualization ---
    'dma-ports'            = @{ cis = @(); nist = @('3.10.2','3.8.7'); iso = @('A.7.9','A.8.12'); cmmc = @('PE.L1-3.10.2','MP.L2-3.8.7') }
    'vbs'                  = @{ cis = @('18.9.5.1','18.9.5.2'); nist = @('3.13.11','3.4.1'); iso = @('A.8.9'); cmmc = @('SC.L2-3.13.11','CM.L2-3.4.1') }
    'hvci'                 = @{ cis = @('18.9.5.3'); nist = @('3.13.11','3.14.4'); iso = @('A.8.9','A.8.19'); cmmc = @('SC.L2-3.13.11','SI.L2-3.14.4') }
    'credential-guard'     = @{ cis = @('18.9.5.1'); nist = @('3.13.11','3.5.3'); iso = @('A.8.5','A.8.24'); cmmc = @('SC.L2-3.13.11','IA.L2-3.5.3') }
    'dma-guard'            = @{ cis = @('18.8.26.1'); nist = @('3.10.2','3.1.1'); iso = @('A.8.12'); cmmc = @('PE.L1-3.10.2','AC.L1-3.1.1') }
    # --- Encryption ---
    'bitlocker'            = @{ cis = @('18.10.9.1.5','18.10.9.2.1'); nist = @('3.13.16','3.8.6'); iso = @('A.8.24','A.8.10'); cmmc = @('SC.L2-3.13.16','MP.L2-3.8.6') }
    'bitlocker-pin'        = @{ cis = @('18.10.9.1.2'); nist = @('3.13.16','3.5.3','3.1.19'); iso = @('A.8.24','A.8.5','A.8.1'); cmmc = @('SC.L2-3.13.16','IA.L2-3.5.3','AC.L2-3.1.19') }
    'enhanced-pin'         = @{ cis = @('18.10.9.1.1'); nist = @('3.5.7','3.5.8'); iso = @('A.8.5'); cmmc = @('IA.L2-3.5.7','IA.L2-3.5.8') }
    'bitlocker-fullvol'    = @{ cis = @(); nist = @('3.13.16','3.8.9'); iso = @('A.8.24','A.8.10'); cmmc = @('SC.L2-3.13.16','MP.L2-3.8.9') }
    # --- Memory Residue ---
    'kernel-paging'        = @{ cis = @(); nist = @('3.13.16'); iso = @('A.8.24'); cmmc = @('SC.L2-3.13.16') }
    'clear-pagefile'       = @{ cis = @('2.3.10.12'); nist = @('3.13.16','3.8.9'); iso = @('A.8.10','A.8.24'); cmmc = @('SC.L2-3.13.16','MP.L2-3.8.9') }
    'crash-dump'           = @{ cis = @(); nist = @('3.13.16','3.8.9'); iso = @('A.8.10'); cmmc = @('SC.L2-3.13.16','MP.L2-3.8.9') }
    'nmi-dump'             = @{ cis = @(); nist = @('3.13.16'); iso = @('A.8.10'); cmmc = @('SC.L2-3.13.16') }
    # --- Access Control ---
    'rdp'                  = @{ cis = @('18.9.59.3.9.1'); nist = @('3.1.12','3.1.13','3.13.8'); iso = @('A.8.20'); cmmc = @('AC.L2-3.1.12','AC.L2-3.1.13','SC.L2-3.13.8') }
    'screen-timeout'       = @{ cis = @('18.8.28.3','19.1.3.1'); nist = @('3.1.10','3.1.11'); iso = @('A.7.7','A.8.1'); cmmc = @('AC.L2-3.1.10','AC.L2-3.1.11') }
    'auto-logon'           = @{ cis = @('18.9.97.1'); nist = @('3.1.1','3.5.1','3.5.2'); iso = @('A.8.5','A.8.2'); cmmc = @('AC.L1-3.1.1','IA.L1-3.5.1','IA.L1-3.5.2') }
    'arso'                 = @{ cis = @(); nist = @('3.1.1','3.5.2'); iso = @('A.8.5'); cmmc = @('AC.L1-3.1.1','IA.L1-3.5.2') }
    'builtin-admin'        = @{ cis = @('2.3.1.1','2.3.1.2','2.3.1.5'); nist = @('3.1.7','3.5.1'); iso = @('A.8.2','A.8.5'); cmmc = @('AC.L2-3.1.7','IA.L1-3.5.1') }
    'uac-credential-prompt'= @{ cis = @('2.3.17.1','2.3.17.2'); nist = @('3.1.7','3.5.2','3.5.3'); iso = @('A.8.2','A.8.5'); cmmc = @('AC.L2-3.1.7','IA.L1-3.5.2','IA.L2-3.5.3') }
    'local-password'       = @{ cis = @('1.1.5','1.1.6'); nist = @('3.5.7','3.5.8','3.5.10'); iso = @('A.8.5'); cmmc = @('IA.L2-3.5.7','IA.L2-3.5.8','IA.L2-3.5.10') }
    'winre'                = @{ cis = @(); nist = @('3.4.5','3.10.2'); iso = @('A.8.9','A.7.9'); cmmc = @('CM.L2-3.4.5','PE.L1-3.10.2') }
    # --- Forensic Surface (Data Exposure) ---
    'fs-jump-lists'        = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10'); cmmc = @('MP.L2-3.8.9') }
    'fs-thumbnails'        = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10'); cmmc = @('MP.L2-3.8.9') }
    'fs-prefetch'          = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10'); cmmc = @('MP.L2-3.8.9') }
    'fs-superfetch'        = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10'); cmmc = @('MP.L2-3.8.9') }
    'fs-user-assist'       = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10'); cmmc = @('MP.L2-3.8.9') }
    'fs-timeline'          = @{ cis = @('18.9.4.1'); nist = @('3.8.9','3.4.8'); iso = @('A.8.10','A.8.12'); cmmc = @('MP.L2-3.8.9','CM.L2-3.4.8') }
    'fs-search-index'      = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10','A.8.12'); cmmc = @('MP.L2-3.8.9') }
    'fs-ps-history'        = @{ cis = @(); nist = @('3.8.9','3.5.10'); iso = @('A.8.10','A.8.5'); cmmc = @('MP.L2-3.8.9','IA.L2-3.5.10') }
    'fs-bam'               = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10'); cmmc = @('MP.L2-3.8.9') }
    'fs-network-profiles'  = @{ cis = @(); nist = @('3.8.9','3.13.8'); iso = @('A.8.10','A.8.20'); cmmc = @('MP.L2-3.8.9','SC.L2-3.13.8') }
    'fs-shellbags'         = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10'); cmmc = @('MP.L2-3.8.9') }
    'fs-usb-history'       = @{ cis = @(); nist = @('3.8.7','3.8.8'); iso = @('A.8.10','A.8.12'); cmmc = @('MP.L2-3.8.7','MP.L2-3.8.8') }
    'fs-amcache'           = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10'); cmmc = @('MP.L2-3.8.9') }
    'fs-shimcache'         = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10'); cmmc = @('MP.L2-3.8.9') }
    'fs-srum'              = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10','A.8.20'); cmmc = @('MP.L2-3.8.9') }
    'fs-usn-journal'       = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10'); cmmc = @('MP.L2-3.8.9') }
    'fs-event-logs'        = @{ cis = @(); nist = @('3.3.1','3.3.2'); iso = @('A.8.15'); cmmc = @('AU.L2-3.3.1','AU.L2-3.3.2') }
    'fs-etw'               = @{ cis = @(); nist = @('3.3.1'); iso = @('A.8.15'); cmmc = @('AU.L2-3.3.1') }
    'fs-mft'               = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10'); cmmc = @('MP.L2-3.8.9') }
    'fs-shadow-copies'     = @{ cis = @(); nist = @('3.8.9','3.13.16'); iso = @('A.8.10','A.8.13'); cmmc = @('MP.L2-3.8.9','SC.L2-3.13.16') }
    'fs-wer'               = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10'); cmmc = @('MP.L2-3.8.9') }
    'fs-recent-docs'       = @{ cis = @(); nist = @('3.8.9'); iso = @('A.8.10'); cmmc = @('MP.L2-3.8.9') }
    'fs-self-footprint'    = @{ cis = @(); nist = @(); iso = @(); cmmc = @() }
    'fs-key-escrow'        = @{ cis = @(); nist = @('3.13.11'); iso = @('A.8.24'); cmmc = @('SC.L2-3.13.11') }
    # --- v0.48: Physical Access Checks ---
    'account-lockout'      = @{ cis = @('1.2.1','1.2.2','1.2.3'); nist = @('3.1.8'); iso = @('A.8.5'); cmmc = @('AC.L2-3.1.8') }
    'password-policy'      = @{ cis = @('1.1.1','1.1.2','1.1.3','1.1.4'); nist = @('3.5.7','3.5.8'); iso = @('A.8.5'); cmmc = @('IA.L2-3.5.7','IA.L2-3.5.8') }
    'ctrl-alt-del'         = @{ cis = @('2.3.7.1'); nist = @('3.5.2'); iso = @('A.8.5'); cmmc = @('IA.L1-3.5.2') }
    'last-username'        = @{ cis = @('2.3.7.4'); nist = @('3.5.2','3.1.1'); iso = @('A.8.5'); cmmc = @('IA.L1-3.5.2','AC.L1-3.1.1') }
    'lsa-protection'       = @{ cis = @('18.4.7'); nist = @('3.5.10','3.13.11'); iso = @('A.8.5','A.8.24'); cmmc = @('IA.L2-3.5.10','SC.L2-3.13.11') }
    'usb-storage'          = @{ cis = @(); nist = @('3.8.7','3.8.8'); iso = @('A.8.12'); cmmc = @('MP.L2-3.8.7','MP.L2-3.8.8') }
    'usb-install'          = @{ cis = @(); nist = @('3.8.7','3.4.6'); iso = @('A.8.12','A.8.9'); cmmc = @('MP.L2-3.8.7','CM.L2-3.4.6') }
    'autorun'              = @{ cis = @('18.9.8.1','18.9.8.2','18.9.8.3'); nist = @('3.4.6','3.14.2'); iso = @('A.8.9','A.8.19'); cmmc = @('CM.L2-3.4.6','SI.L1-3.14.2') }
    'bluetooth'            = @{ cis = @(); nist = @('3.1.16','3.13.8'); iso = @('A.8.20'); cmmc = @('AC.L2-3.1.16','SC.L2-3.13.8') }
    'wifi-autoconnect'     = @{ cis = @(); nist = @('3.1.16','3.13.8'); iso = @('A.8.20'); cmmc = @('AC.L2-3.1.16','SC.L2-3.13.8') }
    'camera-privacy'       = @{ cis = @(); nist = @('3.10.1','3.10.2'); iso = @('A.7.9'); cmmc = @('PE.L1-3.10.1','PE.L1-3.10.2') }
    'mic-privacy'          = @{ cis = @(); nist = @('3.10.1','3.10.2'); iso = @('A.7.9'); cmmc = @('PE.L1-3.10.1','PE.L1-3.10.2') }
    'winrm'                = @{ cis = @('18.9.102.1','18.9.102.2'); nist = @('3.1.12','3.4.6'); iso = @('A.8.20','A.8.9'); cmmc = @('AC.L2-3.1.12','CM.L2-3.4.6') }
    'ps-language-mode'     = @{ cis = @(); nist = @('3.4.6','3.4.7'); iso = @('A.8.19'); cmmc = @('CM.L2-3.4.6','CM.L2-3.4.7') }
    'bl-network-unlock'    = @{ cis = @(); nist = @('3.13.11','3.1.19'); iso = @('A.8.24'); cmmc = @('SC.L2-3.13.11','AC.L2-3.1.19') }
    'removable-encrypt'    = @{ cis = @('18.10.9.2.1'); nist = @('3.8.6','3.8.7'); iso = @('A.8.12','A.8.24'); cmmc = @('MP.L2-3.8.6','MP.L2-3.8.7') }
}

function Add-Check {
    param(
        [string]$Section,
        [string]$Id,
        [string]$Status,        # pass, conditional-pass, warn, fail, info, skip
        [string]$Title,
        [string]$Detail,
        [string]$FixId = '',    # References $script:FixDefs key
        [string[]]$Scenarios = @()  # Which attack scenarios this contributes to
    )
    
    $fixable = $false
    $fixDef = $null
    if ($FixId -and $script:FixDefs.ContainsKey($FixId)) {
        $fixable = $true
        $fixDef = $script:FixDefs[$FixId]
    }

    # Auto-lookup compliance framework mappings for this check
    $frameworks = @{}
    if ($script:FrameworkMap.ContainsKey($Id)) {
        $frameworks = $script:FrameworkMap[$Id]
    }
    
    $script:JsonChecks += @{
        section    = $Section
        id         = $Id
        status     = $Status
        title      = $Title
        detail     = $Detail
        fixId      = $FixId
        fixable    = $fixable
        scenarios  = $Scenarios
        frameworks = $frameworks
    }
    
    # Update counters (exclude data exposure surface from overall posture)
    if ($Section -ne 'forensic-surface') {
        switch ($Status) {
            'pass' { $script:TotalPass++ }
            'conditional-pass' { $script:TotalCondPass++ }
            'warn' { $script:TotalWarn++ }
            'fail' { $script:TotalFail++ }
        }
    }
}

function Write-Banner {
    Clear-Host
    Write-Host ''
    Write-Host '    +-----------------------------------------------------------+' -ForegroundColor Cyan
    Write-Host '    |                                                           |' -ForegroundColor Cyan
    Write-Host '    |     __ __            ________                   __        |' -ForegroundColor Cyan
    Write-Host '    |    / // /__ ________/ /_  __/__ _______ ____ __/ /_       |' -ForegroundColor Cyan
    Write-Host '    |   / _  / _ `/ __/ _  / / / / _ `/ __/ _ `/ -_) __/        |' -ForegroundColor Cyan
    Write-Host '    |  /_//_/\_,_/_/  \_,_/ /_/  \_,_/_/  \_, /\__/\__/         |' -ForegroundColor Cyan
    Write-Host '    |                                    /___/          v0.83   |' -ForegroundColor Cyan
    Write-Host '    |                                                           |' -ForegroundColor Cyan
    Write-Host '    |     Windows Physical Security Scanner                     |' -ForegroundColor Cyan
    Write-Host '    |                                                           |' -ForegroundColor Cyan
    Write-Host '    +-----------------------------------------------------------+' -ForegroundColor Cyan
    Write-Host ''
}

function Write-Section {
    param([string]$Title, [string]$Icon = '>')
    Write-Host ''
    Write-Host ('  ' + $Icon + ' ' + $Title) -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * 58)) -ForegroundColor DarkGray
}

# Locale-independent security policy reader (v0.51 ground truth fix)
# IMPORTANT: secedit /export /cfg shows LOCAL policy only. On domain-joined
# machines, domain GPO overrides local but plain /export wouldn't show it.
# secedit /export /mergedpolicy exports the EFFECTIVE policy after all GPO
# layers are resolved - this is ground truth. Falls back to local-only
# export if /mergedpolicy fails (very old Windows builds).
function Get-SecurityPolicy {
    # SECURITY (v0.52/v0.58): Use CSPRNG for temp filename and write to the ACL-protected
    # HardTarget directory. When running as SYSTEM, $env:TEMP resolves to C:\Windows\Temp
    # which is standard-user-writable. An attacker can pre-plant a symlink there.
    # v0.58: Removed $env:TEMP fallback entirely. If the protected directory doesn't
    # exist, create it. Never write security policy data to user-writable locations.
    $rndBytes = [byte[]]::new(16)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($rndBytes) } finally { $rng.Dispose() }
    $rndHex = [BitConverter]::ToString($rndBytes) -replace '-', ''
    $tmpDir = Join-Path $script:TrustedProgramData 'HardTarget'
    # SECURITY (v0.73): Use Initialize-SecureDirectory instead of bare New-Item.
    # This function runs after init has already secured the directory, so this is
    # defense-in-depth for the case where the directory was deleted mid-execution.
    if (-not (Test-Path $tmpDir)) {
        try { Initialize-SecureDirectory -Path $tmpDir } catch {
            Write-Host "    [SECURITY] Cannot recreate secure directory for secedit export." -ForegroundColor Red
            return @{}
        }
    }
    $tmpFile = Join-Path $tmpDir "ht_secpol_$rndHex.cfg"
    # Ensure the file doesn't already exist (pre-planted symlink)
    if (Test-Path $tmpFile) {
        if (Test-ReparsePoint $tmpFile) { [System.IO.File]::Delete($tmpFile) }
        else { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
    }
    try {
        # Try merged (effective) policy first - ground truth on domain machines
        $null = & $script:Bin.secedit /export /mergedpolicy /cfg $tmpFile /quiet 2>&1
        if (-not (Test-Path $tmpFile)) {
            # Fallback: local-only export (standalone machines, older builds)
            $null = & $script:Bin.secedit /export /cfg $tmpFile /quiet 2>&1
        }
        if (-not (Test-Path $tmpFile)) { return @{} }
        $policy = @{}
        foreach ($line in (Get-Content $tmpFile -ErrorAction SilentlyContinue)) {
            if ($line -match '^(\w+)\s*=\s*(.+)$') {
                $policy[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
        return $policy
    } catch { return @{} }
    finally { Remove-Item $tmpFile -Force -EA SilentlyContinue }
}

# Locale-independent powercfg value reader (v0.51)
# powercfg /query labels are localized but hex values always follow ": 0x" pattern.
# For a single setting query, the order is: min, max, increment, AC, DC.
function Get-PowerSettingValue {
    param([string]$SubgroupGuid, [string]$SettingGuid)
    try {
        $scheme = & $script:Bin.powercfg /getactivescheme 2>&1 | Out-String
        if ($scheme -notmatch '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') { return $null }
        $schemeGuid = $matches[1]
        $output = & $script:Bin.powercfg /query $schemeGuid $SubgroupGuid $SettingGuid 2>&1 | Out-String
        # Extract all hex values from lines matching ": 0x..."
        $hexValues = [regex]::Matches($output, ':\s+0x([0-9a-fA-F]+)') | ForEach-Object { [Convert]::ToInt32($_.Groups[1].Value, 16) }
        if ($hexValues.Count -ge 5) {
            return @{ AC = $hexValues[3]; DC = $hexValues[4] }
        } elseif ($hexValues.Count -ge 4) {
            return @{ AC = $hexValues[3]; DC = $null }
        }
        return $null
    } catch { return $null }
}

function Write-Check {
    param([string]$Status, [string]$Text, [string]$Detail = '')
    $colors = @{ pass = 'Green'; 'conditional-pass' = 'Cyan'; warn = 'Yellow'; fail = 'Red'; info = 'DarkCyan'; skip = 'DarkGray' }
    $symbols = @{ pass = '+'; 'conditional-pass' = '~'; warn = '!'; fail = 'X'; info = 'o'; skip = '-' }
    $color = $colors[$Status]
    $symbol = $symbols[$Status]
    Write-Host ('    [' + $symbol + '] ') -ForegroundColor $color -NoNewline
    Write-Host $Text -ForegroundColor White
    if ($Detail) {
        Write-Host ('        ' + $Detail) -ForegroundColor DarkGray
    }
}

# ============================================================================
#  SCAN: BIOS / FIRMWARE
# ============================================================================
function Test-BiosFirmware {
    Write-Section 'BIOS / FIRMWARE' '[BIOS]'
    
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    
    # Detect Windows edition
    $edition = 'Unknown'
    if ($os.Caption) {
        if ($os.Caption -match 'Enterprise') { $edition = 'Enterprise' }
        elseif ($os.Caption -match 'Education') { $edition = 'Education' }
        elseif ($os.Caption -match 'Pro') { $edition = 'Pro' }
        elseif ($os.Caption -match 'Home') { $edition = 'Home' }
        else { $edition = $os.Caption -replace 'Microsoft Windows \d+\s*', '' }
    }
    $script:WindowsEdition = $edition
    
    # v0.51: Detect domain membership for remediation warnings.
    # net accounts writes LOCAL policy. On domain-joined machines, domain GPO
    # overrides local on next refresh - remediation "succeeds" then gets reverted.
    $script:IsDomainJoined = $false
    try {
        $dsReg = dsregcmd /status 2>&1 | Out-String
        if ($dsReg -match 'DomainJoined\s*:\s*YES' -or $dsReg -match 'AzureAdJoined\s*:\s*YES') {
            $script:IsDomainJoined = $true
        }
    } catch {}
    # Fallback: WMI check
    if (-not $script:IsDomainJoined) {
        try {
            $csDomain = (Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue).PartOfDomain
            if ($csDomain) { $script:IsDomainJoined = $true }
        } catch {}
    }
    
    $script:MachineInfo = @{
        manufacturer = Sanitize-HtmlString $cs.Manufacturer
        model = Sanitize-HtmlString $cs.Model
        biosVersion = Sanitize-HtmlString $bios.SMBIOSBIOSVersion
        biosDate = $bios.ReleaseDate
        windowsEdition = Sanitize-HtmlString $edition
        windowsVersion = Sanitize-HtmlString $os.Caption
    }
    
    # BIOS age check + CVE lookup
    if ($bios.ReleaseDate) {
        $age = (Get-Date) - $bios.ReleaseDate
        $years = [math]::Round($age.Days / 365, 1)
        
        # Try NVD CVE lookup for this BIOS
        # NOTE: This is a keyword search against NVD API, not CPE matching.
        # May include false positives for common vendor names.
        $biosVendor = ($cs.Manufacturer -replace '\s+', ' ').Trim()
        $biosVer = ($bios.SMBIOSBIOSVersion -replace '\s+', ' ').Trim()
        # Sanitize for HTML rendering (these strings end up in dashboard innerHTML)
        # SECURITY (v0.40): BIOS strings are no longer pre-sanitized here.
        # All check title/detail fields are sanitized at output in Get-ScanJson.
        # Keeping raw strings here for correct console display via Write-Check.
        $hasCVEs = $false
        $cveCount = 0
        $cveSample = @()
        
        if (-not $script:SkipNVD) {
            try {
                $nvdQuery = [uri]::EscapeDataString("$biosVendor BIOS $biosVer")
                $nvdUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$nvdQuery&resultsPerPage=5"
                $nvdResp = Invoke-RestMethod -Uri $nvdUrl -TimeoutSec 8 -ErrorAction Stop
                # M-9 FIX: Validate response structure before accessing properties.
                # NVD API may return malformed JSON, error pages, or changed schema.
                if ($nvdResp -and $null -ne $nvdResp.totalResults -and $nvdResp.totalResults -is [int] -and $nvdResp.totalResults -gt 0 -and $null -ne $nvdResp.vulnerabilities) {
                    # L-3 FIX (v0.45): Filter results to reduce false positives.
                    # NVD keyword search may match unrelated products from the same vendor
                    # (e.g. Lenovo router firmware, Lenovo BMC). Only count CVEs whose
                    # description mentions BIOS, firmware, UEFI, or system BIOS.
                    $firmwarePattern = 'BIOS|firmware|UEFI|System Management Mode|SMM'
                    $filteredVulns = @($nvdResp.vulnerabilities | Where-Object {
                        $desc = ''
                        try { $desc = ($_.cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1).value } catch {}
                        $desc -match $firmwarePattern
                    })
                    if ($filteredVulns.Count -gt 0) {
                        $hasCVEs = $true
                        $cveCount = $filteredVulns.Count
                        $cveSample = $filteredVulns | Select-Object -First 3 | ForEach-Object {
                            # Sanitize: CVE IDs must match CVE-YYYY-NNNNN format only
                            $raw = [string]$_.cve.id
                            if ($raw -match '^CVE-\d{4}-\d{4,}$') { $raw } else { '[invalid-cve-id]' }
                        }
                    }
                }
            } catch { }
        }
        
        # Detect generic/custom-built PC vendor strings
        $genericVendors = @('To Be Filled', 'Default string', 'System manufacturer', 'OEM', 'Standard PC')
        $isGenericVendor = $false
        foreach ($gv in $genericVendors) {
            if ($biosVendor -match [regex]::Escape($gv)) { $isGenericVendor = $true; break }
        }
        $nvdCaveat = if ($isGenericVendor) { ' Note: your system reports a generic manufacturer string, so NVD results may be inaccurate. Check your motherboard manufacturer''s support page directly.' } else { '' }
        
        if ($hasCVEs) {
            $cveList = ($cveSample -join ', ')
            $cveDetail = "Found $cveCount known CVE(s) for $biosVendor BIOS. Examples: $cveList. Firmware vulnerabilities can bypass all OS-level protections. Update immediately.$nvdCaveat"
            Write-Check 'fail' "BIOS has $cveCount known CVE(s)" $cveList
            Add-Check -Section 'bios' -Id 'bios-age' -Status 'fail' `
                -Title "BIOS has $cveCount known CVE(s)" `
                -Detail $cveDetail `
                -Scenarios @('evil-maid')
        } elseif ($years -gt 1.5) {
            Write-Check 'conditional-pass' "BIOS is $years years old (no known CVEs found)"
            Add-Check -Section 'bios' -Id 'bios-age' -Status 'conditional-pass' `
                -Title "BIOS is $years years old (no known CVEs)" `
                -Detail "Firmware is over 18 months old but no known vulnerabilities were found in the National Vulnerability Database for $biosVendor $biosVer. This may be the latest available version for your hardware.$nvdCaveat"
        } else {
            Write-Check 'pass' "BIOS updated $years years ago"
            Add-Check -Section 'bios' -Id 'bios-age' -Status 'pass' -Title "BIOS is $years years old" -Detail "Firmware is recent and no known CVEs found.$nvdCaveat"
        }
    }
    
    # Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) {
            Write-Check 'pass' 'Secure Boot is ENABLED'
            Add-Check -Section 'bios' -Id 'secure-boot' -Status 'pass' -Title 'Secure Boot is ENABLED' -Detail 'Boot chain is cryptographically verified.' -Scenarios @('evil-maid')
        } else {
            Write-Check 'fail' 'Secure Boot is DISABLED'
            Add-Check -Section 'bios' -Id 'secure-boot' -Status 'fail' -Title 'Secure Boot is DISABLED' -Detail 'Bootkits and rootkits can persist undetected.' -Scenarios @('evil-maid')
        }
    } catch {
        Write-Check 'warn' 'Secure Boot status unknown (legacy BIOS?)'
        Add-Check -Section 'bios' -Id 'secure-boot' -Status 'warn' -Title 'Secure Boot status unknown' -Detail 'System may be using legacy BIOS mode.'
    }
    
    # UEFI Secure Boot variable protection (Setup Mode check)
    try {
        $setupMode = Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop
        $inSetupMode = $setupMode.Bytes[0] -eq 1
        if ($inSetupMode) {
            Write-Check 'fail' 'UEFI is in Setup Mode - Secure Boot keys can be replaced'
            Add-Check -Section 'bios' -Id 'uefi-vars' -Status 'fail' `
                -Title 'UEFI in Setup Mode (keys unprotected)' `
                -Detail 'UEFI is in Setup Mode. The Platform Key (PK), Key Exchange Keys (KEK), and signature databases (db/dbx) can be freely modified without authentication. An attacker with physical access can enroll their own keys and sign malicious bootloaders that Secure Boot will trust.' `
                -Scenarios @('evil-maid')
        } else {
            # Check for Platform Key presence
            try {
                $pk = Get-SecureBootUEFI -Name PK -ErrorAction Stop
                Write-Check 'pass' 'UEFI variables are protected (User Mode with PK enrolled)'
                Add-Check -Section 'bios' -Id 'uefi-vars' -Status 'pass' `
                    -Title 'UEFI variables protected (User Mode)' `
                    -Detail 'Platform Key is enrolled and UEFI is in User Mode. Secure Boot key databases cannot be modified without the PK owner''s authorisation.' `
                    -Scenarios @('evil-maid')
            } catch {
                Write-Check 'warn' 'UEFI in User Mode but Platform Key could not be read'
                Add-Check -Section 'bios' -Id 'uefi-vars' -Status 'warn' `
                    -Title 'UEFI User Mode (PK unverified)' `
                    -Detail 'UEFI is not in Setup Mode, but the Platform Key could not be read for verification. This is usually fine on consumer hardware but cannot be fully confirmed.' `
                    -Scenarios @('evil-maid')
            }
        }
    } catch {
        # Get-SecureBootUEFI not available (legacy BIOS or cmdlet missing)
    }
    
    # Kernel Debugging (v0.51: match element presence, not localized Yes/No)
    try {
        $bcdOutput = & $script:Bin.bcdedit /v 2>&1 | Out-String
        if ($bcdOutput -match '(?m)^\s*debug\s') {
            Write-Check 'fail' 'Kernel debugging is ENABLED' 'Full kernel access via debug cable'
            Add-Check -Section 'bios' -Id 'kernel-debug' -Status 'fail' `
                -Title 'Kernel debugging is ENABLED' `
                -Detail 'A debugger attached via serial, USB, or network can read/write all memory, bypass all security, and extract any secret. This is equivalent to giving an attacker full ring-0 access.' `
                -FixId 'kernel-debug' -Scenarios @('dma-attack', 'evil-maid')
        } else {
            Write-Check 'pass' 'Kernel debugging is disabled'
            Add-Check -Section 'bios' -Id 'kernel-debug' -Status 'pass' -Title 'Kernel debugging is disabled' -Detail '' -Scenarios @('dma-attack', 'evil-maid')
        }
        
        # Test Signing (v0.51: match element presence, not localized Yes/No)
        if ($bcdOutput -match '(?m)^\s*testsigning\s') {
            Write-Check 'fail' 'Test signing mode is ENABLED' 'Unsigned kernel drivers can load'
            Add-Check -Section 'bios' -Id 'test-signing' -Status 'fail' `
                -Title 'Test signing mode is ENABLED' `
                -Detail 'Any unsigned kernel driver can load. This completely bypasses HVCI and driver signature enforcement. Often enabled for game cheats or legacy hardware and forgotten.' `
                -FixId 'test-signing' -Scenarios @('evil-maid')
        } else {
            Write-Check 'pass' 'Test signing mode is disabled'
            Add-Check -Section 'bios' -Id 'test-signing' -Status 'pass' -Title 'Test signing mode is disabled' -Detail 'Only signed kernel drivers can load.' -Scenarios @('evil-maid')
        }
    } catch {
        Write-Check 'warn' 'Could not query boot configuration (bcdedit)'
        Add-Check -Section 'bios' -Id 'kernel-debug' -Status 'warn' -Title 'Boot config query failed' -Detail 'Run as administrator to check bcdedit settings.'
    }
    
    # Intel AMT / Management Engine provisioning status
    # SECURITY (v0.43): AMT provides out-of-band remote KVM, power control, and IDE
    # Redirection via the Management Engine - a separate processor inside the chipset
    # that operates independently of the OS. If provisioned, it gives remote
    # physical-equivalent access (keyboard, mouse, screen, remote boot).
    # AMT does NOT bypass authentication or escalate privileges. An attacker
    # gets the same view as sitting in front of the machine. If the machine is
    # hardened (BitLocker PIN, no auto-logon, locked screen), AMT access
    # still stops at the login prompt. The risk is that default MEBx passwords
    # ("admin") allow an attacker with brief physical access to provision AMT
    # silently, creating persistent remote physical access.
    try {
        $amtProvisioned = $false
        $amtDetail = ''
        
        # Method 1: WMI query for AMT status (Intel AMT SDK WMI provider)
        $amt = Get-CimInstance -Namespace 'root\Intel_ME' -ClassName ME_System -ErrorAction SilentlyContinue
        if ($amt) {
            $amtProvisioned = $true
            $amtDetail = "Intel ME interface detected via WMI (root\Intel_ME)."
        }
        
        # Method 2: Check for AMT-related services
        if (-not $amtProvisioned) {
            $lmsService = Get-Service -Name 'LMS' -ErrorAction SilentlyContinue
            if ($lmsService) {
                $amtProvisioned = $true
                $amtDetail = "Intel Local Management Service (LMS) is $($lmsService.Status). LMS provides the local interface for AMT management."
            }
        }
        
        # Method 3: Check for MEI/HECI driver (Management Engine Interface)
        if (-not $amtProvisioned) {
            $meiDevice = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
                $_.FriendlyName -match 'Management Engine|MEI|HECI' -and $_.Class -eq 'System'
            }
            if ($meiDevice) {
                # ME driver present but AMT may not be provisioned - informational
                $amtDetail = "Intel Management Engine Interface driver present but AMT provisioning status could not be confirmed."
                Write-Check 'info' 'Intel Management Engine detected (AMT status unknown)'
                Add-Check -Section 'bios' -Id 'amt-provisioned' -Status 'info' `
                    -Title 'Intel Management Engine present (AMT status unconfirmed)' `
                    -Detail "$amtDetail Most Intel systems have ME. AMT is the remote management feature built on ME. Check BIOS settings (MEBx) to verify AMT is not provisioned with a default password. Default MEBx password is typically ''admin'' - if you have not changed it, an attacker with brief physical access can enable AMT remotely." `
                    -Scenarios @('evil-maid')
            }
        }
        
        if ($amtProvisioned) {
            Write-Check 'warn' 'Intel AMT appears PROVISIONED' 'Remote physical-equivalent access'
            Add-Check -Section 'bios' -Id 'amt-provisioned' -Status 'warn' `
                -Title 'Intel AMT appears provisioned' `
                -Detail "$amtDetail AMT provides remote keyboard, mouse, screen (KVM), and boot control via the Management Engine. This operates below the OS on a separate processor with its own network stack. AMT does not bypass OS authentication - a locked screen is still locked remotely. However, if your MEBx password is still the default (''admin''), any attacker with brief physical access can reconfigure AMT. Verify the MEBx password has been changed and AMT is configured to your requirements in BIOS settings." `
                -Scenarios @('evil-maid')
        }
    } catch {
        # ME/AMT query failed - non-Intel system or access denied. Not a finding.
    }
}

# ============================================================================
#  SCAN: SLEEP STATES
# ============================================================================
function Test-SleepStates {
    Write-Section 'SLEEP STATES' '[SLEEP]'
    
    # v0.51: Primary S0 detection via registry (locale-independent)
    # CsEnabled=1 means hardware supports Modern Standby
    # PlatformAoAcOverride=0 means it's been disabled
    $csReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name CsEnabled -EA SilentlyContinue
    $aoacReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name PlatformAoAcOverride -EA SilentlyContinue
    $s0Capable = ($csReg -and $csReg.CsEnabled -eq 1)
    $s0Overridden = ($aoacReg -and $aoacReg.PlatformAoAcOverride -eq 0)
    $s0Active = $s0Capable -and -not $s0Overridden
    
    # v0.51 GROUND TRUTH: Cross-check with powercfg /a for firmware-forced S0.
    # ACPI state identifiers (S0, S3) are technical, not localized.
    # v0.52 FIX: The previous logic assumed that if powercfg /a still lists S0
    # after the override, the override failed. WRONG. powercfg /a reports firmware
    # CAPABILITIES, not what the OS is using. PlatformAoAcOverride=0 disables S0
    # at the OS level regardless of what firmware advertises. If no S3 fallback
    # exists, the machine has NO sleep state - lid close goes to shutdown.
    # That's the BEST security outcome, not a failure.
    # TRUE firmware-forced: CsEnabled=1, override NOT set, no S3 available,
    # and the fix would be ineffective because there's no S3 to fall back to.
    $s0FirmwareForced = $false
    $s3Available = $false
    $allSleepDisabled = $false
    try {
        $powerCfg = & $script:Bin.powercfg /a 2>&1 | Out-String
        # Check if S0 appears as available (before any "not" qualifier)
        $s0InPowercfg = ($powerCfg -match '\(S0' -and $powerCfg -notmatch '\(S0[^)]*not')
        $s3Available = ($powerCfg -match '\(S3\)' -and $powerCfg -notmatch '\(S3\)[^)]*not')
        
        # Override IS set + no S3 = no usable sleep state = machine shuts down on lid close.
        # This is a PASS (best security outcome), NOT a firmware-forced failure.
        if ($s0Overridden -and -not $s3Available) {
            $allSleepDisabled = $true
        }
        
        # TRUE firmware-forced: S0 capable, override NOT set (or not possible),
        # firmware only advertises S0, no S3 fallback. The fix (platform-aoac)
        # would disable S0 but leave no sleep state - we should still offer it
        # since shutdown-on-lid-close is the desired security outcome.
        if (-not $s0Overridden -and $s0Capable -and $s0InPowercfg -and -not $s3Available) {
            $s0FirmwareForced = $true
            # s0Active is already true from line above (capable + not overridden)
        }
        
        # Also catch: not S0 active, not S3, no hibernate = truly no sleep
        if (-not $s0Active -and -not $s3Available -and -not $allSleepDisabled) {
            $hiberFile = Join-Path $script:TrustedSystemDrive 'hiberfil.sys'
            if (-not (Test-Path $hiberFile)) { $allSleepDisabled = $true }
        }
    } catch { }
    
    # Modern Standby (S0)
    # v0.60: OEM-specific BIOS guidance for disabling S0 at the firmware level.
    # Software overrides (PlatformAoAcOverride) are fragile and can be reverted by
    # Windows Feature Updates or OEM driver installations. BIOS-level disable is
    # more persistent and ensures hardware buses (Thunderbolt/PCIe) fully power down.
    $biosGuidance = ''
    $mfr = if ($script:MachineInfo.manufacturer) { $script:MachineInfo.manufacturer } else { '' }
    $model = if ($script:MachineInfo.model) { $script:MachineInfo.model } else { '' }
    if ($mfr -match 'Lenovo') {
        $biosGuidance = ' BIOS: Enter Setup (F1 at boot) > Config > Power > Sleep State > set to "Linux" or "S3".'
    }
    elseif ($mfr -match 'Dell') {
        $biosGuidance = ' BIOS: Enter Setup (F2 at boot) > Power Management > Block Sleep > set to "Block S3" or disable Modern Standby.'
    }
    elseif ($mfr -match 'HP\b|Hewlett') {
        $biosGuidance = ' BIOS: Enter Setup (F10 at boot) > Advanced > Power Management > check for S3/S4 sleep options.'
    }
    elseif ($mfr -match 'Microsoft' -and $model -match 'Surface') {
        $biosGuidance = ' Surface UEFI: Hold Volume Up + Power at boot. Note: most Surface devices have no S3 option and cannot disable S0 in firmware.'
    }
    elseif ($mfr -match 'ASUS|ASUSTeK') {
        $biosGuidance = ' BIOS: Enter Setup (F2/Del at boot) > Advanced > Power Management > check for S3 sleep options.'
    }
    if ($biosGuidance -eq '' -and $mfr -and $mfr -notmatch 'To Be Filled|Default string|System manufacturer|OEM|Standard PC') {
        $biosGuidance = " Check $mfr BIOS/UEFI setup for sleep state or Modern Standby options."
    }
    $dmaNote = ' DMA risk: S0 keeps Thunderbolt/PCIe buses active during sleep, enabling hardware-based memory attacks.'
    if ($allSleepDisabled) {
        Write-Check 'pass' 'All sleep states DISABLED - system can only power on or off'
        Add-Check -Section 'sleep' -Id 's0-standby' -Status 'pass' `
            -Title 'All sleep states disabled' `
            -Detail 'No standby modes available. Lid close triggers shutdown or hibernate. Maximum security posture for sleep attacks.' `
            -Scenarios @()
    } elseif ($s0Active -and $s0FirmwareForced) {
        Write-Check 'warn' 'Modern Standby (S0) active - no S3 fallback' 'Fix will disable sleep entirely (lid close = shutdown)'
        Add-Check -Section 'sleep' -Id 's0-standby' -Status 'warn' `
            -Title 'Modern Standby (S0) active, firmware has no S3 fallback' `
            -Detail "Firmware only advertises S0 (no classic S3 sleep). Applying the software fix will disable all sleep states - lid close will trigger shutdown instead. This is the most secure outcome but means no quick resume.$dmaNote For a persistent fix, disable S0 in BIOS/UEFI.$biosGuidance" `
            -FixId 'platform-aoac' -Scenarios @('sleep-wake')
    } elseif ($s0Active) {
        Write-Check 'fail' 'Modern Standby (S0) is ACTIVE' 'Laptop can wake silently in your bag'
        Add-Check -Section 'sleep' -Id 's0-standby' -Status 'fail' `
            -Title 'Modern Standby (S0) is ACTIVE' `
            -Detail "Your laptop can wake while sleeping - wifi, camera, mic may activate without your knowledge.$dmaNote Recommended: disable S0 in BIOS/UEFI for a persistent fix that survives Windows updates.$biosGuidance" `
            -FixId 'platform-aoac' -Scenarios @('sleep-wake')
    } elseif ($s3Available) {
        Write-Check 'pass' 'Classic sleep (S3) - no Modern Standby'
        Add-Check -Section 'sleep' -Id 's0-standby' -Status 'pass' -Title 'Classic S3 sleep active' -Detail 'Using traditional suspend-to-RAM. CPU is fully off during sleep.'
    } else {
        Write-Check 'pass' 'No standby modes available'
        Add-Check -Section 'sleep' -Id 's0-standby' -Status 'pass' -Title 'No standby available' -Detail 'System does not support any standby modes.'
    }
    
    # Connected Standby registry
    $cs = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name CsEnabled -ErrorAction SilentlyContinue
    if ($cs -and $cs.CsEnabled -eq 1) {
        if ($allSleepDisabled) {
            Write-Check 'info' 'Connected Standby registry=1 but all sleep disabled'
            Add-Check -Section 'sleep' -Id 'cs-enabled' -Status 'pass' -Title 'Connected Standby: registry enabled but sleep disabled' -Detail 'Registry says enabled but no sleep states are available, so this has no effect.'
        } else {
            Write-Check 'fail' 'Connected Standby is ENABLED'
            Add-Check -Section 'sleep' -Id 'cs-enabled' -Status 'fail' `
                -Title 'Connected Standby is ENABLED' `
                -Detail 'System maintains network connectivity during sleep.' `
                -FixId 'cs-enabled' -Scenarios @('sleep-wake')
        }
    } elseif ($cs -and $cs.CsEnabled -eq 0) {
        Write-Check 'pass' 'Connected Standby is DISABLED'
        Add-Check -Section 'sleep' -Id 'cs-enabled' -Status 'pass' -Title 'Connected Standby is DISABLED' -Detail 'No network activity during sleep. Device is fully offline when sleeping.'
    }
    
    # AOAC Override
    $aoac = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name PlatformAoAcOverride -ErrorAction SilentlyContinue
    if ($aoac -and $aoac.PlatformAoAcOverride -eq 0) {
        Write-Check 'pass' 'Modern Standby override applied (PlatformAoAcOverride=0)'
        Add-Check -Section 'sleep' -Id 'platform-aoac' -Status 'pass' -Title 'Modern Standby override active' -Detail 'PlatformAoAcOverride=0 prevents S0 low power idle.' -Scenarios @('sleep-wake')
    }
    
    # Fast Startup
    $hiberboot = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction SilentlyContinue
    if ($hiberboot -and $hiberboot.HiberbootEnabled -eq 1) {
        Write-Check 'fail' 'Fast Startup is ENABLED' 'Shutdown writes memory to hiberfil.sys'
        Add-Check -Section 'sleep' -Id 'fast-startup' -Status 'fail' `
            -Title 'Fast Startup is ENABLED' `
            -Detail 'When you shutdown, Windows saves kernel memory to hiberfil.sys. An attacker with disk access can extract credentials.' `
            -FixId 'fast-startup' -Scenarios @('cold-boot', 'forensic')
    } else {
        Write-Check 'pass' 'Fast Startup is DISABLED'
        Add-Check -Section 'sleep' -Id 'fast-startup' -Status 'pass' -Title 'Fast Startup is DISABLED' -Detail 'Clean shutdown, no kernel memory persisted.'
    }
    
    # Wake Timers (v0.51: locale-independent via hex value extraction)
    try {
        $wakeResult = Get-PowerSettingValue -SubgroupGuid '238c9fa8-0aad-41ed-83f4-97be242c8f20' -SettingGuid 'bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d'
        if ($wakeResult) {
            $wakeVal = $wakeResult.AC
            if ($wakeVal -eq 0) {
                Write-Check 'pass' 'Wake timers DISABLED'
                Add-Check -Section 'sleep' -Id 'wake-timers' -Status 'pass' `
                    -Title 'Wake timers disabled' `
                    -Detail 'System will not wake from sleep for scheduled tasks or maintenance.'
            } elseif ($wakeVal -eq 1) {
                Write-Check 'warn' 'Wake timers ENABLED (Important only)'
                Add-Check -Section 'sleep' -Id 'wake-timers' -Status 'warn' `
                    -Title 'Wake timers enabled (Important Wake Timers Only)' `
                    -Detail 'System may wake from sleep for high-priority tasks. Firmware maintenance tasks can still wake the device.' `
                    -FixId 'wake-timers' -Scenarios @('sleep-wake')
            } else {
                Write-Check 'warn' 'Wake timers ENABLED'
                Add-Check -Section 'sleep' -Id 'wake-timers' -Status 'warn' `
                    -Title 'Wake timers enabled' `
                    -Detail 'System can wake from sleep for scheduled tasks, updates, and maintenance. Device may activate unattended.' `
                    -FixId 'wake-timers' -Scenarios @('sleep-wake')
            }
        }
    } catch { }
    
    # Hibernation
    $hiberFile = Join-Path $script:TrustedSystemDrive 'hiberfil.sys'
    if (Test-Path $hiberFile) {
        $size = [math]::Round((Get-Item $hiberFile -Force).Length / 1GB, 1)
        Write-Check 'fail' ('Hibernation file exists (' + $size + 'GB)') 'Full RAM snapshot on disk'
        Add-Check -Section 'sleep' -Id 'hibernate' -Status 'fail' `
            -Title ('Hibernation enabled (' + $size + 'GB hiberfil.sys)') `
            -Detail 'Hibernate saves entire RAM to disk including all passwords, encryption keys, and session tokens in cleartext. This bypasses all other memory protections.' `
            -FixId 'hibernate' -Scenarios @('cold-boot', 'forensic')
    } else {
        Write-Check 'pass' 'Hibernation is DISABLED'
        Add-Check -Section 'sleep' -Id 'hibernate' -Status 'pass' -Title 'Hibernation is DISABLED' -Detail 'No hiberfil.sys present.'
    }
}

# ============================================================================
#  SCAN: TPM
# ============================================================================
function Test-TPM {
    Write-Section 'TPM' '[TPM]'
    
    $tpm = Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    
    if (-not $tpm) {
        Write-Check 'fail' 'No TPM detected'
        Add-Check -Section 'tpm' -Id 'tpm-present' -Status 'fail' -Title 'No TPM detected' -Detail 'Hardware security module not available. BitLocker and Credential Guard require TPM.'
        return
    }
    
    Write-Check 'pass' ('TPM ' + $tpm.SpecVersion + ' detected')
    Add-Check -Section 'tpm' -Id 'tpm-present' -Status 'pass' -Title ('TPM ' + $tpm.SpecVersion + ' present') -Detail ('Manufacturer: ' + $tpm.ManufacturerIdTxt)
    
    if ($tpm.IsActivated_InitialValue) {
        Write-Check 'pass' 'TPM is activated'
        Add-Check -Section 'tpm' -Id 'tpm-active' -Status 'pass' -Title 'TPM is activated' -Detail ''
    } else {
        Write-Check 'fail' 'TPM is NOT activated'
        Add-Check -Section 'tpm' -Id 'tpm-active' -Status 'fail' -Title 'TPM is not activated' -Detail 'Enable in BIOS settings.'
    }
    
    # TPM lockout threshold
    try {
        $tpmInfo = Get-Tpm -ErrorAction Stop
        if ($null -ne $tpmInfo.LockoutMax) {
            $lockoutMax = $tpmInfo.LockoutMax
            $lockoutCount = if ($null -ne $tpmInfo.LockoutCount) { $tpmInfo.LockoutCount } else { 0 }
            $lockoutHeal = if ($null -ne $tpmInfo.LockoutHealTime) { $tpmInfo.LockoutHealTime } else { 'unknown' }
            
            # Check if enhanced (alphanumeric) PIN is enabled - mitigates lockout concerns
            $fveCheck = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name UseEnhancedPin -ErrorAction SilentlyContinue
            $hasEnhancedPin = $fveCheck -and $fveCheck.UseEnhancedPin -eq 1
            
            if ($lockoutMax -eq 0) {
                if ($hasEnhancedPin) {
                    Write-Check 'warn' 'TPM lockout disabled but enhanced PIN is on'
                    Add-Check -Section 'tpm' -Id 'tpm-lockout' -Status 'warn' `
                        -Title 'TPM lockout disabled (mitigated by enhanced PIN)' `
                        -Detail 'No limit on failed PIN attempts. However, alphanumeric enhanced PIN is enabled which makes brute-force impractical. Still recommended to enable lockout as defence in depth.' `
                        -Scenarios @('cold-boot')
                } else {
                    Write-Check 'fail' 'TPM lockout is disabled (unlimited attempts)'
                    Add-Check -Section 'tpm' -Id 'tpm-lockout' -Status 'fail' `
                        -Title 'TPM lockout disabled (unlimited attempts)' `
                        -Detail 'No limit on failed PIN attempts and PIN is numeric-only. A 6-digit numeric PIN can be brute-forced without any lockout delay. Enable lockout or switch to alphanumeric enhanced PIN.' `
                        -Scenarios @('cold-boot')
                }
            } elseif ($lockoutMax -gt 32) {
                Write-Check 'warn' "TPM lockout threshold: $lockoutMax attempts" 'Higher than default 32'
                Add-Check -Section 'tpm' -Id 'tpm-lockout' -Status 'warn' `
                    -Title "TPM lockout after $lockoutMax failed attempts (default: 32)" `
                    -Detail "Current: $lockoutMax attempts before lockout. The default is 32. A higher threshold gives attackers more guesses before the TPM locks. Failed so far: $lockoutCount." `
                    -Scenarios @('cold-boot')
            } else {
                Write-Check 'pass' "TPM lockout threshold: $lockoutMax attempts"
                Add-Check -Section 'tpm' -Id 'tpm-lockout' -Status 'pass' `
                    -Title "TPM lockout after $lockoutMax failed attempts" `
                    -Detail "TPM will lock after $lockoutMax bad PIN guesses. Failed so far: $lockoutCount. Heal time: $lockoutHeal." `
                    -Scenarios @('cold-boot')
            }
        }
    } catch { }
    
    # TPM bus sniffing resistance (fTPM vs dTPM)
    # Firmware TPM (fTPM) runs inside the CPU - immune to LPC/SPI bus interposer attacks
    # Discrete TPM (dTPM) is a separate chip - VMK can be sniffed on the bus during boot
    # TPM strings are sanitized at output in Get-ScanJson (v0.40 catch-all).
    # Raw values used here for correct console display and regex matching.
    $tpmManuf = if ($tpm.ManufacturerIdTxt) { $tpm.ManufacturerIdTxt.Trim() } else { '' }
    $specVer = if ($tpm.SpecVersion) { $tpm.SpecVersion } else { '' }
    $isFirmwareTPM = $tpmManuf -match '^(INTC|Intel|AMD|MSFT)$'
    
    if ($isFirmwareTPM) {
        Write-Check 'pass' "Firmware TPM ($tpmManuf) - immune to bus sniffing"
        Add-Check -Section 'tpm' -Id 'tpm-bus' -Status 'pass' `
            -Title "Firmware TPM (fTPM) by $tpmManuf" `
            -Detail 'fTPM runs inside the CPU die. There is no external bus to intercept, making LPC/SPI interposer attacks impossible. The BitLocker VMK cannot be captured in transit.' `
            -Scenarios @('cold-boot', 'dma-attack')
    } else {
        $dMsg = "Discrete TPM chip ($tpmManuf) communicates with CPU over an external bus (LPC/SPI)."
        if ($specVer -match '^2\.') {
            Write-Check 'conditional-pass' "Discrete TPM ($tpmManuf) - bus sniffing mitigated by PIN"
            Add-Check -Section 'tpm' -Id 'tpm-bus' -Status 'conditional-pass' `
                -Title "Discrete TPM (dTPM) by $tpmManuf" `
                -Detail "$dMsg A ~`$300 logic analyser can capture the BitLocker VMK in transit during boot. However, a pre-boot PIN prevents the TPM from releasing the VMK at all, fully neutralising this attack. TPM 2.0 parameter encryption also mitigates this but Windows does not enable it for BitLocker by default. PIN status is checked separately." `
                -Scenarios @('cold-boot', 'dma-attack')
        } else {
            Write-Check 'conditional-pass' "Discrete TPM 1.2 ($tpmManuf) - no parameter encryption"
            Add-Check -Section 'tpm' -Id 'tpm-bus' -Status 'conditional-pass' `
                -Title "Discrete TPM 1.2 by $tpmManuf (no parameter encryption)" `
                -Detail "$dMsg TPM 1.2 does not support parameter encryption. The BitLocker VMK travels in cleartext on the bus during every boot. A pre-boot PIN is essential - it prevents the TPM from releasing the key at all, making bus sniffing impossible. PIN status is checked separately." `
                -Scenarios @('cold-boot', 'dma-attack')
        }
    }
}

# ============================================================================
#  SCAN: DMA / VIRTUALIZATION SECURITY
# ============================================================================
function Test-DMAExposure {
    Write-Section 'DMA / VIRTUALIZATION' '[DMA]'
    
    # - Detect DMA-capable external ports --
    $script:HasDMAPorts = $false
    $dmaPortInfo = @()
    
    # H-2 FIX (v0.45): Added USB4 to match compliance/detect scripts (M-3 from v0.44).
    # USB4 ports are DMA-capable and increasingly common on modern laptops.
    $pnpDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $_.FriendlyName -match 'Thunderbolt|USB4|1394|FireWire' -or
        $_.Class -eq 'Thunderbolt' -or
        $_.InstanceId -match 'PCI.*Thunderbolt'
    }
    
    if ($pnpDevices) {
        $script:HasDMAPorts = $true
        $dmaPortInfo = @($pnpDevices | Select-Object -ExpandProperty FriendlyName -Unique)
        $portList = $dmaPortInfo -join ', '
        Write-Check 'info' ('DMA-capable ports found: ' + $portList)
        Add-Check -Section 'dma' -Id 'dma-ports' -Status 'info' `
            -Title ('DMA-capable ports: ' + $portList) `
            -Detail 'These ports allow direct memory access by external devices.'
    } else {
        Write-Check 'conditional-pass' 'No external DMA ports detected (conditional)'
        Add-Check -Section 'dma' -Id 'dma-ports' -Status 'conditional-pass' `
            -Title 'No external DMA-capable ports detected (conditional pass)' `
            -Detail 'No Thunderbolt or FireWire controllers found. External DMA attacks require opening the chassis to access internal PCIe/M.2 slots, which is a significantly more advanced attack. VBS and DMA Guard still provide additional defence in depth.'
    }
    
    # - Device Guard / VBS status (useful regardless of DMA ports) --
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction SilentlyContinue
    
    if ($dg) {
        # VBS
        if ($dg.VirtualizationBasedSecurityStatus -eq 2) {
            Write-Check 'pass' 'VBS is RUNNING'
            Add-Check -Section 'dma' -Id 'vbs' -Status 'pass' -Title 'Virtualization Based Security is RUNNING' -Detail 'Hypervisor isolates sensitive memory regions.' -Scenarios @('dma-attack')
        } else {
            $vbsDetail = 'VBS protects sensitive memory regions using the hypervisor.'
            if ($script:HasDMAPorts) {
                $vbsDetail = 'Without VBS, an external DMA device can read your entire RAM including passwords and keys.'
            }
            Write-Check 'warn' 'VBS is NOT running'
            Add-Check -Section 'dma' -Id 'vbs' -Status 'warn' `
                -Title 'VBS is NOT running' `
                -Detail $vbsDetail `
                -FixId 'vbs' -Scenarios @('dma-attack')
        }
        
        # HVCI
        $hvci = $dg.SecurityServicesRunning -contains 2
        if ($hvci) {
            Write-Check 'pass' 'HVCI (Memory Integrity) is ACTIVE'
            Add-Check -Section 'dma' -Id 'hvci' -Status 'pass' -Title 'HVCI is ACTIVE' -Detail 'Kernel code integrity enforced by hypervisor.' -Scenarios @('dma-attack')
        } else {
            Write-Check 'warn' 'HVCI is NOT active'
            Add-Check -Section 'dma' -Id 'hvci' -Status 'warn' `
                -Title 'HVCI is NOT active' `
                -Detail 'Unsigned kernel drivers can load. Some legitimate drivers may be incompatible with HVCI.' `
                -FixId 'hvci' -Scenarios @('dma-attack')
        }
        
        # Credential Guard
        $credGuard = $dg.SecurityServicesRunning -contains 1
        if ($credGuard) {
            Write-Check 'pass' 'Credential Guard is RUNNING'
            Add-Check -Section 'dma' -Id 'credential-guard' -Status 'pass' -Title 'Credential Guard is RUNNING' -Detail 'LSASS credentials isolated in secure enclave.' -Scenarios @('dma-attack')
        } else {
            # Determine appropriate severity based on edition and DMA port presence
            $cgEdition = $script:WindowsEdition
            $isEnterprise = ($cgEdition -eq 'Enterprise' -or $cgEdition -eq 'Education')
            
            if (-not $isEnterprise -and -not $script:HasDMAPorts) {
                # No DMA ports AND not Enterprise = informational only, not a real risk
                Write-Check 'info' 'Credential Guard unavailable (requires Enterprise, no DMA ports)'
                Add-Check -Section 'dma' -Id 'credential-guard' -Status 'info' `
                    -Title ('Credential Guard unavailable (Windows ' + $cgEdition + ')') `
                    -Detail ('Credential Guard requires Enterprise or Education edition. You have Windows ' + $cgEdition + '. With no DMA ports on this system, the risk is minimal.') `
                    -Scenarios @('dma-attack')
            } elseif (-not $isEnterprise) {
                # Has DMA ports but not Enterprise = warn (real risk they can''t mitigate)
                Write-Check 'warn' 'Credential Guard unavailable (requires Enterprise)'
                Add-Check -Section 'dma' -Id 'credential-guard' -Status 'warn' `
                    -Title ('Credential Guard unavailable (Windows ' + $cgEdition + ')') `
                    -Detail ('Credential Guard requires Enterprise or Education edition. You have Windows ' + $cgEdition + '. With DMA ports present, credentials in memory are at risk.') `
                    -FixId 'credential-guard' -Scenarios @('dma-attack')
            } else {
                # Enterprise but not enabled = warn with fix
                Write-Check 'warn' 'Credential Guard is NOT running'
                Add-Check -Section 'dma' -Id 'credential-guard' -Status 'warn' `
                    -Title 'Credential Guard is NOT running' `
                    -Detail 'Windows credentials are stored in normal memory. Your edition supports Credential Guard - enable it.' `
                    -FixId 'credential-guard' -Scenarios @('dma-attack')
            }
        }
    } else {
        Write-Check 'warn' 'Could not query Device Guard status'
        Add-Check -Section 'dma' -Id 'vbs' -Status 'warn' -Title 'Device Guard status unknown' -Detail ''
    }
    
    # Kernel DMA Protection (only relevant if DMA ports exist)
    if ($script:HasDMAPorts) {
        $dmaProtection = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' -Name DeviceEnumerationPolicy -ErrorAction SilentlyContinue
        if ($dmaProtection -and $dmaProtection.DeviceEnumerationPolicy -eq 0) {
            Write-Check 'pass' 'Kernel DMA Protection: Block All'
            Add-Check -Section 'dma' -Id 'dma-guard' -Status 'pass' -Title 'DMA Protection: Block All' -Detail 'External DMA devices are blocked.' -Scenarios @('dma-attack')
        } else {
            Write-Check 'fail' 'Kernel DMA Protection not enforced'
            Add-Check -Section 'dma' -Id 'dma-guard' -Status 'fail' `
                -Title 'Kernel DMA Protection not enforced' `
                -Detail 'External DMA devices can read memory. Requires hardware IOMMU support.' `
                -FixId 'dma-guard' -Scenarios @('dma-attack')
        }
    } else {
        Write-Check 'conditional-pass' 'DMA Protection: N/A (no external DMA ports)'
        Add-Check -Section 'dma' -Id 'dma-guard' -Status 'conditional-pass' -Title 'DMA Protection not needed (conditional)' -Detail 'No external DMA-capable ports detected. Internal PCIe/M.2 remain accessible if chassis is opened.'
    }
}

# ============================================================================
#  SCAN: ENCRYPTION
# ============================================================================
function Test-Encryption {
    Write-Section 'ENCRYPTION' '[CRYPT]'
    
    try {
        $bl = Get-BitLockerVolume -MountPoint $script:TrustedSystemDrive -ErrorAction Stop
        if ($bl.ProtectionStatus -eq 'On') {
            Write-Check 'pass' ('BitLocker ON - ' + $bl.EncryptionMethod)
            Add-Check -Section 'encryption' -Id 'bitlocker' -Status 'pass' -Title 'BitLocker is ON' -Detail ('Encryption: ' + $bl.EncryptionMethod) -Scenarios @('cold-boot', 'evil-maid')
            
            # Check for TPM+PIN
            $hasPin = $bl.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'TpmPin' }
            if ($hasPin) {
                Write-Check 'pass' 'BitLocker uses TPM + PIN'
                Add-Check -Section 'encryption' -Id 'bitlocker-pin' -Status 'pass' -Title 'BitLocker has pre-boot PIN' -Detail 'Keys require PIN before Windows loads. Strong cold boot protection.' -Scenarios @('cold-boot', 'dma-attack')
            } else {
                Write-Check 'fail' 'BitLocker has no pre-boot PIN' 'Stolen laptop = decrypted data'
                Add-Check -Section 'encryption' -Id 'bitlocker-pin' -Status 'fail' `
                    -Title 'BitLocker has no pre-boot PIN' `
                    -Detail 'TPM auto-unlocks at boot with no authentication. Anyone who steals this laptop can boot it and the disk decrypts automatically. Cold boot and DMA attacks can also extract the key from memory. A pre-boot PIN is the single most important BitLocker hardening step.' `
                    -FixId 'bitlocker-pin' -Scenarios @('cold-boot', 'dma-attack')
            }
            
            # Enhanced PIN (alphanumeric vs numeric-only)
            $fvePolicy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name UseEnhancedPin -ErrorAction SilentlyContinue
            if ($fvePolicy -and $fvePolicy.UseEnhancedPin -eq 1) {
                Write-Check 'pass' 'Enhanced PIN enabled (alphanumeric allowed)'
                Add-Check -Section 'encryption' -Id 'enhanced-pin' -Status 'pass' `
                    -Title 'Enhanced BitLocker PIN enabled' `
                    -Detail 'Alphanumeric PINs allowed. Much stronger than numeric-only (10^n vs 36^n keyspace).' `
                    -Scenarios @('cold-boot')
            } else {
                Write-Check 'conditional-pass' 'BitLocker PIN is numeric-only' 'Alphanumeric PINs are much stronger'
                Add-Check -Section 'encryption' -Id 'enhanced-pin' -Status 'conditional-pass' `
                    -Title 'BitLocker PIN is numeric-only' `
                    -Detail 'Default numeric PINs use only digits 0-9. A 6-digit numeric PIN has 1M combinations (up to ~19 years via TPM brute-force, but common PINs fall much sooner). Enable alphanumeric PINs and use 8+ characters for significantly stronger protection.' `
                    -FixId 'enhanced-pin' -Scenarios @('cold-boot')
            }
            
            # Full-disk vs used-space-only encryption
            # SECURITY (v0.66): Replaced manage-bde string parsing with Win32_EncryptableVolume
            # WMI. manage-bde output is fully localized -- "Conversion Status", "Fully Encrypted",
            # "Used Space Only", "Percentage Encrypted" are all English strings that don't appear
            # on non-English Windows. The check silently skipped (failed safe) but produced no
            # result at all for the majority of global Windows installations.
            # Win32_EncryptableVolume.GetConversionStatus() returns structured integers:
            #   ConversionStatus: 0=Decrypted, 1=FullyEncrypted, 2=EncryptionInProgress, etc.
            #   EncryptionPercentage: 0-100
            #   EncryptionFlags: 0x1=UsedSpaceOnly, 0x0=FullVolume
            try {
                $encVol = Get-CimInstance -Namespace 'Root\CIMV2\Security\MicrosoftVolumeEncryption' `
                    -ClassName 'Win32_EncryptableVolume' -Filter "DriveLetter='$($script:TrustedSystemDrive)'" -EA Stop
                $convResult = $encVol | Invoke-CimMethod -MethodName 'GetConversionStatus' -EA Stop
                $convStatus = $convResult.ConversionStatus  # 0=Decrypted, 1=Encrypted, 2=InProgress
                $encPct = $convResult.EncryptionPercentage
                $encFlags = $convResult.EncryptionFlags     # 0x1 = used-space-only
                if ($convStatus -eq 1) {
                    # Fully encrypted -- check if full volume or used-space-only
                    if ($encFlags -band 1) {
                        Write-Check 'conditional-pass' 'Used-space-only encryption' 'Free space unencrypted'
                        Add-Check -Section 'encryption' -Id 'bitlocker-fullvol' -Status 'conditional-pass' `
                            -Title ('Used-space-only encryption (' + $encPct + '% of used space)') `
                            -Detail 'Only sectors containing active data are encrypted. Free space is unencrypted, meaning files deleted BEFORE BitLocker was enabled may be recoverable in plaintext. Files created and deleted after encryption are safe (written as ciphertext). Risk diminishes as the disk overwrites old free space over time.' `
                            -Scenarios @('forensic')
                    } else {
                        Write-Check 'pass' 'Full-volume encryption active'
                        Add-Check -Section 'encryption' -Id 'bitlocker-fullvol' -Status 'pass' `
                            -Title ('Full-volume encryption (' + $encPct + '% encrypted)') `
                            -Detail 'Entire volume is encrypted including free space. Deleted files cannot be recovered from disk.' `
                            -Scenarios @('forensic')
                    }
                } elseif ($convStatus -eq 2) {
                    Write-Check 'warn' ('Encryption in progress (' + $encPct + '%)')
                    Add-Check -Section 'encryption' -Id 'bitlocker-fullvol' -Status 'warn' `
                        -Title ('Encryption in progress (' + $encPct + '%)') `
                        -Detail 'BitLocker is still encrypting. Unencrypted portions of the disk remain exposed.' `
                        -Scenarios @('forensic')
                }
            } catch { }
        } else {
            Write-Check 'fail' 'BitLocker is OFF'
            Add-Check -Section 'encryption' -Id 'bitlocker' -Status 'fail' -Title 'BitLocker is OFF' -Detail 'Your disk is not encrypted. Anyone with physical access can read all data.' -Scenarios @('cold-boot', 'evil-maid', 'forensic')
        }
    } catch {
        if ($script:WindowsEdition -eq 'Home') {
            Write-Check 'fail' 'BitLocker not available (Windows Home)'
            Add-Check -Section 'encryption' -Id 'bitlocker' -Status 'fail' `
                -Title 'BitLocker not available on Windows Home' `
                -Detail 'Windows Home does not include BitLocker. Some devices have Device Encryption (check Settings > Privacy & Security > Device Encryption). For full BitLocker with pre-boot PIN, upgrade to Pro.' `
                -Scenarios @('cold-boot', 'evil-maid', 'forensic')
        } else {
            Write-Check 'warn' 'Could not determine BitLocker status'
            Add-Check -Section 'encryption' -Id 'bitlocker' -Status 'warn' -Title 'BitLocker status unknown' -Detail ''
        }
    }
}

# ============================================================================
#  SCAN: MEMORY RESIDUE
# ============================================================================
function Test-MemoryResidue {
    Write-Section 'MEMORY RESIDUE' '[MEM]'
    
    # Kernel paging
    $mm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -ErrorAction SilentlyContinue
    if ($mm.DisablePagingExecutive -eq 1) {
        Write-Check 'pass' 'Kernel kept in RAM (DisablePagingExecutive=1)'
        Add-Check -Section 'memory' -Id 'kernel-paging' -Status 'pass' -Title 'Kernel kept in RAM' -Detail 'Kernel code and data won''t be written to pagefile.'
    } else {
        Write-Check 'fail' 'Kernel can be paged to disk'
        Add-Check -Section 'memory' -Id 'kernel-paging' -Status 'fail' `
            -Title 'Kernel can be paged to disk' `
            -Detail 'Sensitive kernel memory including credentials may be written to pagefile.' `
            -FixId 'kernel-paging' -Scenarios @('cold-boot', 'forensic')
    }
    
    # Clear pagefile
    if ($mm.ClearPageFileAtShutdown -eq 1) {
        Write-Check 'pass' 'Pagefile cleared at shutdown'
        Add-Check -Section 'memory' -Id 'clear-pagefile' -Status 'pass' -Title 'Pagefile cleared at shutdown' -Detail ''
    } else {
        Write-Check 'fail' 'Pagefile NOT cleared at shutdown'
        Add-Check -Section 'memory' -Id 'clear-pagefile' -Status 'fail' `
            -Title 'Pagefile NOT cleared at shutdown' `
            -Detail 'Old memory contents persist on disk after shutdown. Forensic recovery possible.' `
            -FixId 'clear-pagefile' -Scenarios @('cold-boot', 'forensic')
    }
    
    # Crash dumps
    $crash = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction SilentlyContinue
    if ($crash.CrashDumpEnabled -eq 0) {
        Write-Check 'pass' 'Crash dumps DISABLED'
        Add-Check -Section 'memory' -Id 'crash-dump' -Status 'pass' -Title 'Crash dumps disabled' -Detail ''
    } elseif ($crash.CrashDumpEnabled -eq 1) {
        Write-Check 'fail' 'Full memory dumps ENABLED' 'Crash writes entire RAM to disk'
        Add-Check -Section 'memory' -Id 'crash-dump' -Status 'fail' `
            -Title 'Full memory dumps enabled' `
            -Detail 'A crash (or forced crash) writes your entire RAM to disk - all secrets, all keys.' `
            -FixId 'crash-dump' -Scenarios @('cold-boot', 'forensic')
    } else {
        Write-Check 'warn' ('Crash dumps at level ' + $crash.CrashDumpEnabled)
        Add-Check -Section 'memory' -Id 'crash-dump' -Status 'warn' `
            -Title ('Partial crash dumps enabled (level ' + $crash.CrashDumpEnabled + ')') `
            -Detail 'Some memory may be written on crash.' `
            -FixId 'crash-dump' -Scenarios @('forensic')
    }
    
    # NMI crash dump
    $nmiVal = $null
    try { $nmiVal = $crash.PSObject.Properties['NMICrashDump'].Value } catch {}
    if ($nmiVal -eq 1) {
        Write-Check 'warn' 'NMI crash dumps ENABLED' 'Known forensic technique'
        Add-Check -Section 'memory' -Id 'nmi-dump' -Status 'warn' `
            -Title 'NMI crash dumps enabled' `
            -Detail 'An attacker with physical access can trigger a crash via keyboard to dump memory.' `
            -FixId 'nmi-dump' -Scenarios @('forensic')
    } else {
        Write-Check 'pass' 'NMI crash dumps disabled'
        Add-Check -Section 'memory' -Id 'nmi-dump' -Status 'pass' -Title 'NMI crash dumps disabled' -Detail ''
    }
}

# ============================================================================
#  SCAN: SCREEN LOCK / ACCESS
# ============================================================================
function Test-ScreenLock {
    Write-Section 'ACCESS CONTROL' '[ACCESS]'
    
    # RDP
    $rdp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue
    if ($rdp.fDenyTSConnections -eq 1) {
        Write-Check 'pass' 'Remote Desktop is DISABLED'
        Add-Check -Section 'access' -Id 'rdp' -Status 'pass' -Title 'Remote Desktop is DISABLED' -Detail ''
    } else {
        Write-Check 'fail' 'Remote Desktop is ENABLED'
        Add-Check -Section 'access' -Id 'rdp' -Status 'fail' `
            -Title 'Remote Desktop is ENABLED' `
            -Detail 'Machine accepts remote connections. Attack surface for brute force and credential stuffing.' `
            -FixId 'rdp'
    }
    
    # Screen lock timeout (v0.51: locale-independent via hex value extraction)
    try {
        $vidResult = Get-PowerSettingValue -SubgroupGuid '7516b95f-f776-4464-8c53-06167f40cc99' -SettingGuid '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e'
        if ($vidResult) {
            $seconds = $vidResult.AC
            $minutes = [math]::Round($seconds / 60)
            if ($minutes -eq 0) {
                Write-Check 'warn' 'Display never turns off'
                Add-Check -Section 'access' -Id 'screen-timeout' -Status 'warn' -Title 'Display never turns off' -Detail 'Consider enabling display timeout.' -FixId 'screen-timeout' -Scenarios @('evil-maid')
            } elseif ($minutes -le 5) {
                Write-Check 'pass' "Display timeout: $minutes minutes"
                Add-Check -Section 'access' -Id 'screen-timeout' -Status 'pass' -Title "Display timeout: $minutes minutes" -Detail ''
            } else {
                Write-Check 'warn' "Display timeout: $minutes minutes" 'Consider reducing'
                Add-Check -Section 'access' -Id 'screen-timeout' -Status 'warn' -Title "Display timeout: $minutes minutes" -Detail 'Long timeout increases exposure if you walk away.' -FixId 'screen-timeout' -Scenarios @('evil-maid')
            }
        }
    } catch { }
    
    # Windows Recovery Environment (v0.51: registry check, locale-independent)
    try {
        $winreReg = Get-ItemProperty 'HKLM:\SYSTEM\Setup\Recovery' -Name Enabled -EA SilentlyContinue
        if ($winreReg -and $winreReg.Enabled -eq 1) {
            Write-Check 'warn' 'Windows Recovery Environment is ENABLED'
            Add-Check -Section 'access' -Id 'winre' -Status 'warn' `
                -Title 'Windows Recovery Environment is ENABLED' `
                -Detail 'WinRE allows password resets and command prompt access at boot. An attacker with physical access can use it to bypass local authentication.' `
                -FixId 'winre' -Scenarios @('evil-maid')
        } elseif ($winreReg -and $winreReg.Enabled -eq 0) {
            Write-Check 'pass' 'Windows Recovery Environment is DISABLED'
            Add-Check -Section 'access' -Id 'winre' -Status 'pass' `
                -Title 'Windows Recovery Environment is DISABLED' `
                -Detail 'WinRE cannot be used to bypass local security.' `
                -Scenarios @('evil-maid')
        } else {
            Write-Check 'info' 'Could not determine WinRE status'
            Add-Check -Section 'access' -Id 'winre' -Status 'info' -Title 'WinRE status unknown' -Detail ''
        }
    } catch { }
    
    # Auto-logon check
    $winlogon = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    if ($winlogon.AutoAdminLogon -eq '1') {
        Write-Check 'fail' 'Auto-logon is ENABLED' 'Machine boots straight to desktop - no password'
        Add-Check -Section 'access' -Id 'auto-logon' -Status 'fail' `
            -Title 'Auto-logon is ENABLED' `
            -Detail 'Machine boots directly to desktop without authentication. BitLocker PIN is the only barrier. If no PIN is set, a thief gets full access by pressing the power button.' `
            -FixId 'auto-logon' -Scenarios @('evil-maid', 'cold-boot')
    } else {
        Write-Check 'pass' 'Auto-logon is disabled'
        Add-Check -Section 'access' -Id 'auto-logon' -Status 'pass' -Title 'Auto-logon is disabled' -Detail 'Password or Windows Hello required at login.' -Scenarios @('evil-maid', 'cold-boot')
    }
    
    # ARSO - Automatic Restart Sign-On
    $arso = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DisableAutomaticRestartSignOn -ErrorAction SilentlyContinue
    if ($arso -and $arso.DisableAutomaticRestartSignOn -eq 1) {
        Write-Check 'pass' 'ARSO is disabled'
        Add-Check -Section 'access' -Id 'arso' -Status 'pass' -Title 'Automatic Restart Sign-On is disabled' -Detail 'After Windows Update restarts, the lock screen is shown.' -Scenarios @('evil-maid')
    } else {
        Write-Check 'warn' 'ARSO may auto-login after Windows Update' 'Machine could restart to unlocked desktop'
        Add-Check -Section 'access' -Id 'arso' -Status 'warn' `
            -Title 'Automatic Restart Sign-On (ARSO) not disabled' `
            -Detail 'After a Windows Update reboot, Windows may automatically sign you back in and lock the screen. Your credentials are cached to enable this. On some configurations this can leave the session unlocked.' `
            -FixId 'arso' -Scenarios @('evil-maid')
    }
    
    # UAC elevation prompt behaviour
    # SECURITY (v0.43): By default, admin accounts get a consent-only UAC prompt
    # ("Yes/No"). An attacker at an unlocked admin session just clicks Yes.
    # ConsentPromptBehaviorAdmin=1 forces password entry on every elevation.
    # This check forms a chain with screen timeout and local password:
    #   Display timeout -> catches the unlocked window
    #   UAC credential prompt -> catches what they can do once at the session
    #   Local password exists -> catches whether the credential prompt is real
    $uacPolicy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    $consentBehavior = $uacPolicy.ConsentPromptBehaviorAdmin
    if ($consentBehavior -eq 1 -or $consentBehavior -eq 3) {
        # 1 = Prompt for credentials on secure desktop, 3 = Prompt for credentials
        Write-Check 'pass' 'UAC requires password for elevation'
        Add-Check -Section 'access' -Id 'uac-credential-prompt' -Status 'pass' `
            -Title 'UAC elevation requires password entry' `
            -Detail 'Admin elevation prompts require re-entering credentials. An attacker at an unlocked session cannot silently elevate to admin.' `
            -Scenarios @('evil-maid', 'coercion')
    } elseif ($consentBehavior -eq 0) {
        # 0 = Elevate without prompting (most dangerous)
        Write-Check 'fail' 'UAC silently elevates without ANY prompt'
        Add-Check -Section 'access' -Id 'uac-credential-prompt' -Status 'fail' `
            -Title 'UAC auto-elevates without prompting' `
            -Detail 'ConsentPromptBehaviorAdmin=0. Admin operations execute without any prompt. An attacker at an unlocked session has silent admin access to everything.' `
            -FixId 'uac-credential-prompt' -Scenarios @('evil-maid', 'coercion')
    } elseif ($consentBehavior -eq 5 -or $null -eq $consentBehavior) {
        # 5 = Prompt for consent (default) - just a Yes/No click
        Write-Check 'warn' 'UAC uses consent-only prompt (no password required)'
        Add-Check -Section 'access' -Id 'uac-credential-prompt' -Status 'warn' `
            -Title 'UAC elevation is consent-only (no password)' `
            -Detail 'The default UAC setting prompts admin users with a Yes/No dialog. An attacker at an unlocked admin session clicks Yes and gets full admin. Set ConsentPromptBehaviorAdmin=1 to require password re-entry on every elevation.' `
            -FixId 'uac-credential-prompt' -Scenarios @('evil-maid', 'coercion')
    } else {
        # 2 = Prompt for consent on secure desktop, 4 = Prompt for consent (non-Windows binaries)
        Write-Check 'warn' "UAC prompt behaviour: consent-only (level $consentBehavior)"
        Add-Check -Section 'access' -Id 'uac-credential-prompt' -Status 'warn' `
            -Title "UAC elevation is consent-only (ConsentPromptBehaviorAdmin=$consentBehavior)" `
            -Detail "Current UAC setting uses a consent prompt (Yes/No) without password re-entry. An attacker at an unlocked admin session can elevate by clicking a button. Set ConsentPromptBehaviorAdmin=1 to require credentials." `
            -FixId 'uac-credential-prompt' -Scenarios @('evil-maid', 'coercion')
    }
    
    # Local account password check
    # SECURITY (v0.43): A credential prompt is meaningless if the account has no password.
    # Check all enabled local admin accounts for password presence. Domain accounts
    # are managed by AD password policy and are not checked here.
    try {
        $localAdmins = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | Where-Object {
            $_.ObjectClass -eq 'User' -and $_.PrincipalSource -eq 'Local'
        }
        $noPasswordAccounts = @()
        foreach ($admin in $localAdmins) {
            try {
                $username = $admin.Name -replace '^[^\\]*\\', ''
                $user = Get-LocalUser -Name $username -ErrorAction Stop
                if ($user.Enabled -and -not $user.PasswordRequired) {
                    $noPasswordAccounts += $username
                }
                # Also check if password was never set (PasswordLastSet is null/epoch)
                if ($user.Enabled -and $user.PasswordRequired -and $null -eq $user.PasswordLastSet) {
                    $noPasswordAccounts += "$username (password required but never set)"
                }
            } catch { }
        }
        
        if ($noPasswordAccounts.Count -gt 0) {
            $acctList = $noPasswordAccounts -join ', '
            Write-Check 'fail' "Local admin account(s) with no password: $acctList"
            Add-Check -Section 'access' -Id 'local-password' -Status 'fail' `
                -Title "Local admin account(s) without password: $acctList" `
                -Detail "These enabled local administrator accounts have no password set or no password required. Any UAC credential prompt, lock screen, or login prompt is bypassed by pressing Enter. Set a strong password on all admin accounts." `
                -Scenarios @('evil-maid', 'coercion')
        } else {
            # Check current user specifically
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -replace '^[^\\]*\\', ''
            $currentLocalUser = Get-LocalUser -Name $currentUser -ErrorAction SilentlyContinue
            if ($currentLocalUser -and $currentLocalUser.Enabled -and -not $currentLocalUser.PasswordRequired) {
                Write-Check 'fail' "Current user ($currentUser) has no password requirement"
                Add-Check -Section 'access' -Id 'local-password' -Status 'fail' `
                    -Title "Current user ($currentUser) does not require a password" `
                    -Detail 'Your active account does not require a password. The lock screen and UAC credential prompt can be bypassed by pressing Enter.' `
                    -Scenarios @('evil-maid', 'coercion')
            } elseif ($localAdmins.Count -gt 0) {
                Write-Check 'pass' 'All local admin accounts have passwords'
                Add-Check -Section 'access' -Id 'local-password' -Status 'pass' `
                    -Title 'All local admin accounts have passwords set' `
                    -Detail 'All enabled local administrator accounts require a password. UAC credential prompts and lock screen authentication are effective.' `
                    -Scenarios @('evil-maid', 'coercion')
            }
        }
        
        # Also check built-in Administrator account specifically (often enabled and left blank)
        # v0.51: SID-based lookup - built-in Admin is always *-500 but has localized name
        try {
            $builtinAdmin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1
            if ($builtinAdmin -and $builtinAdmin.Enabled) {
                if (-not $builtinAdmin.PasswordRequired -or $null -eq $builtinAdmin.PasswordLastSet) {
                    Write-Check 'fail' 'Built-in Administrator account is ENABLED with no password'
                    Add-Check -Section 'access' -Id 'builtin-admin' -Status 'fail' `
                        -Title 'Built-in Administrator account enabled without password' `
                        -Detail 'The built-in Administrator account is enabled and has no password (or password not required). This account bypasses UAC entirely - it never shows a UAC prompt. An attacker who can reach the login screen can sign in as Administrator with a blank password and has unrestricted system access.' `
                        -FixId 'builtin-admin' -Scenarios @('evil-maid', 'coercion')
                } else {
                    Write-Check 'info' 'Built-in Administrator account is enabled (password set)'
                    Add-Check -Section 'access' -Id 'builtin-admin' -Status 'info' `
                        -Title 'Built-in Administrator account is enabled' `
                        -Detail 'The built-in Administrator account is enabled but has a password set. Note: this account bypasses UAC entirely. Consider disabling it if not needed.' `
                        -Scenarios @('evil-maid')
                }
            }
        } catch { }
    } catch {
        # Get-LocalUser/Get-LocalGroupMember not available (Server Core, etc.)
        Write-Check 'info' 'Could not enumerate local accounts'
        Add-Check -Section 'access' -Id 'local-password' -Status 'info' `
            -Title 'Local account password check unavailable' `
            -Detail 'Could not query local user accounts. Verify manually that all admin accounts have strong passwords.'
    }

    # ========================================================================
    #  v0.51: PHYSICAL ACCESS HARDENING CHECKS
    # ========================================================================
    
    # Account Lockout Policy (v0.51: uses secedit for locale independence)
    try {
        $secPol = Get-SecurityPolicy
        $lockoutThreshold = if ($secPol.ContainsKey('LockoutBadCount')) { [int]$secPol['LockoutBadCount'] } else { 0 }
        if ($lockoutThreshold -eq 0) {
            Write-Check 'fail' 'No account lockout policy' 'Unlimited brute force at login screen'
            Add-Check -Section 'access' -Id 'account-lockout' -Status 'fail' `
                -Title 'No account lockout policy configured' `
                -Detail 'An attacker at the login screen can try unlimited passwords. Set a lockout threshold to limit brute force attempts.' `
                -FixId 'account-lockout' -Scenarios @('evil-maid')
        } elseif ($lockoutThreshold -gt 10) {
            Write-Check 'warn' "Lockout after $lockoutThreshold attempts" 'Consider reducing'
            Add-Check -Section 'access' -Id 'account-lockout' -Status 'warn' `
                -Title "Account lockout after $lockoutThreshold attempts" `
                -Detail "Lockout threshold is set but high. NIST recommends 3-5 attempts." `
                -FixId 'account-lockout' -Scenarios @('evil-maid')
        } else {
            Write-Check 'pass' "Account lockout after $lockoutThreshold attempts"
            Add-Check -Section 'access' -Id 'account-lockout' -Status 'pass' `
                -Title "Account lockout after $lockoutThreshold attempts" -Detail '' -Scenarios @('evil-maid')
        }
    } catch {}
    
    # Password Policy (v0.51: uses secedit for locale independence)
    try {
        if (-not $secPol) { $secPol = Get-SecurityPolicy }
        $minLen = if ($secPol.ContainsKey('MinimumPasswordLength')) { [int]$secPol['MinimumPasswordLength'] } else { 0 }
        if ($minLen -lt 8) {
            Write-Check 'fail' "Minimum password length: $minLen" 'Below NIST 800-63B minimum of 8'
            Add-Check -Section 'access' -Id 'password-policy' -Status 'fail' `
                -Title "Minimum password length: $minLen characters" `
                -Detail "NIST 800-63B recommends minimum 8 characters. Passwords under 8 characters are trivially brutable at the login screen." `
                -FixId 'password-policy' -Scenarios @('evil-maid')
        } else {
            Write-Check 'pass' "Minimum password length: $minLen"
            Add-Check -Section 'access' -Id 'password-policy' -Status 'pass' `
                -Title "Minimum password length: $minLen characters" -Detail '' -Scenarios @('evil-maid')
        }
    } catch {}
    
    # Ctrl+Alt+Del required
    try {
        $cadReg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DisableCAD -ErrorAction SilentlyContinue
        if ($cadReg -and $cadReg.DisableCAD -eq 1) {
            Write-Check 'conditional-pass' 'Ctrl+Alt+Del not required at login' 'CIS 2.3.7.1 recommends enabling'
            Add-Check -Section 'access' -Id 'ctrl-alt-del' -Status 'conditional-pass' `
                -Title 'Ctrl+Alt+Del not required at login' `
                -Detail 'CIS recommends requiring the secure attention sequence to prevent fake login screen overlays. Low risk on modern systems with Windows Hello but recommended for shared or high-security environments.' `
                -FixId 'ctrl-alt-del' -Scenarios @('evil-maid')
        } else {
            Write-Check 'pass' 'Ctrl+Alt+Del required at login'
            Add-Check -Section 'access' -Id 'ctrl-alt-del' -Status 'pass' `
                -Title 'Ctrl+Alt+Del required at login' -Detail '' -Scenarios @('evil-maid')
        }
    } catch {}
    
    # Last username displayed
    try {
        $luReg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DontDisplayLastUserName -ErrorAction SilentlyContinue
        if (-not $luReg -or $luReg.DontDisplayLastUserName -ne 1) {
            Write-Check 'conditional-pass' 'Last logged-in username shown at login' 'CIS 2.3.7.4 recommends hiding'
            Add-Check -Section 'access' -Id 'last-username' -Status 'conditional-pass' `
                -Title 'Last logged-in username displayed at login' `
                -Detail 'CIS recommends hiding the last username. Showing it gives an attacker half the credential pair, but on single-user personal devices the username is obvious anyway.' `
                -FixId 'last-username' -Scenarios @('evil-maid')
        } else {
            Write-Check 'pass' 'Last username hidden at login'
            Add-Check -Section 'access' -Id 'last-username' -Status 'pass' `
                -Title 'Last logged-in username hidden' -Detail '' -Scenarios @('evil-maid')
        }
    } catch {}
    
    # LSA Protection (RunAsPPL)
    try {
        $lsaReg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue
        if ($lsaReg -and $lsaReg.RunAsPPL -ge 1) {
            Write-Check 'pass' 'LSA Protection (RunAsPPL) enabled'
            Add-Check -Section 'access' -Id 'lsa-protection' -Status 'pass' `
                -Title 'LSA Protection (RunAsPPL) is ENABLED' -Detail 'LSASS runs as Protected Process Light. Credential dumping tools like Mimikatz cannot attach.' `
                -Scenarios @('coercion')
        } else {
            Write-Check 'fail' 'LSA Protection (RunAsPPL) disabled' 'Mimikatz can dump all credentials'
            Add-Check -Section 'access' -Id 'lsa-protection' -Status 'fail' `
                -Title 'LSA Protection (RunAsPPL) is DISABLED' `
                -Detail 'Without RunAsPPL, an attacker with admin access can run Mimikatz or comsvcs.dll to dump every credential from LSASS memory - domain passwords, Kerberos tickets, NTLM hashes. This is the single most common post-access credential theft technique.' `
                -FixId 'lsa-protection' -Scenarios @('coercion')
        }
    } catch {}
    
    # USB Mass Storage Policy
    # v0.51 GROUND TRUTH: On Home, this GP key exists but nothing enforces it.
    # Reading Deny_All=1 on Home is a false pass - USB drives still work.
    try {
        if ($script:WindowsEdition -eq 'Home') {
            Write-Check 'conditional-pass' 'USB mass storage policy not available on Home' 'Requires Group Policy (Pro/Enterprise)'
            Add-Check -Section 'dma' -Id 'usb-storage' -Status 'conditional-pass' `
                -Title 'USB mass storage: Group Policy not available (Windows Home)' `
                -Detail 'Removable Storage Access policy requires the Group Policy engine which is not present on Windows Home. USB mass storage cannot be restricted through policy on this edition. Consider third-party endpoint management or physical port security.' `
                -Scenarios @('evil-maid')
        } else {
            $usbDeny = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' -Name Deny_All -ErrorAction SilentlyContinue
            if ($usbDeny -and $usbDeny.Deny_All -eq 1) {
                Write-Check 'pass' 'USB mass storage blocked by policy'
                Add-Check -Section 'dma' -Id 'usb-storage' -Status 'pass' `
                    -Title 'USB mass storage blocked by policy' -Detail '' -Scenarios @('evil-maid')
            } else {
                Write-Check 'conditional-pass' 'USB mass storage devices allowed' 'NIST 3.8.7 recommends restricting'
                Add-Check -Section 'dma' -Id 'usb-storage' -Status 'conditional-pass' `
                    -Title 'USB mass storage devices are allowed' `
                    -Detail 'NIST 3.8.7/3.8.8 recommend controlling removable media. Blocking USB storage prevents data exfiltration but also prevents legitimate USB drive use. Appropriate for managed environments handling sensitive data.' `
                    -FixId 'usb-storage' -Scenarios @('evil-maid')
            }
        }
    } catch {}
    
    # USB Device Install Restriction
    # v0.51 GROUND TRUTH: Same GP dependency as usb-storage.
    try {
        if ($script:WindowsEdition -eq 'Home') {
            Write-Check 'conditional-pass' 'USB install restriction not available on Home' 'Requires Group Policy (Pro/Enterprise)'
            Add-Check -Section 'dma' -Id 'usb-install' -Status 'conditional-pass' `
                -Title 'USB device installation: Group Policy not available (Windows Home)' `
                -Detail 'Device Installation Restrictions require the Group Policy engine which is not present on Windows Home. New USB device classes cannot be blocked through policy on this edition.' `
                -Scenarios @('evil-maid')
        } else {
            $usbInstall = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions' -Name DenyUnspecified -ErrorAction SilentlyContinue
            if ($usbInstall -and $usbInstall.DenyUnspecified -eq 1) {
                Write-Check 'pass' 'New USB device installation restricted'
                Add-Check -Section 'dma' -Id 'usb-install' -Status 'pass' `
                    -Title 'New USB device installation restricted' -Detail '' -Scenarios @('evil-maid')
            } else {
                Write-Check 'conditional-pass' 'New USB devices can install freely' 'NIST 3.8.7 recommends restricting'
                Add-Check -Section 'dma' -Id 'usb-install' -Status 'conditional-pass' `
                    -Title 'New USB devices can install without restriction' `
                    -Detail 'NIST 3.8.7 recommends controlling removable media installation. Blocking new device classes prevents rogue devices but also blocks legitimate new peripherals.' `
                    -FixId 'usb-install' -Scenarios @('evil-maid')
            }
        }
    } catch {}
    
    # AutoRun / AutoPlay
    try {
        $autorun = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue
        if ($autorun -and $autorun.NoDriveTypeAutoRun -ge 255) {
            Write-Check 'pass' 'AutoRun/AutoPlay disabled'
            Add-Check -Section 'dma' -Id 'autorun' -Status 'pass' `
                -Title 'AutoRun/AutoPlay is disabled' -Detail '' -Scenarios @('evil-maid')
        } else {
            Write-Check 'fail' 'AutoRun/AutoPlay enabled' 'USB payload auto-executes'
            Add-Check -Section 'dma' -Id 'autorun' -Status 'fail' `
                -Title 'AutoRun/AutoPlay is enabled' `
                -Detail 'Inserting a USB drive or CD can auto-execute code without user interaction. Classic malware delivery vector.' `
                -FixId 'autorun' -Scenarios @('evil-maid')
        }
    } catch {}
    
    # Bluetooth
    try {
        $btAdapters = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' }
        if ($btAdapters -and @($btAdapters).Count -gt 0) {
            Write-Check 'info' "Bluetooth active ($(@($btAdapters).Count) adapter(s))"
            Add-Check -Section 'dma' -Id 'bluetooth' -Status 'info' `
                -Title "Bluetooth active ($(@($btAdapters).Count) adapter(s))" `
                -Detail 'Bluetooth is enabled. Known vulnerabilities (BlueBorne) have been patched since 2017. Disable only if you do not use any Bluetooth peripherals and want to eliminate this wireless surface entirely.' `
                -FixId 'bluetooth' -Scenarios @('sleep-wake')
        } else {
            Write-Check 'pass' 'No active Bluetooth adapters'
            Add-Check -Section 'dma' -Id 'bluetooth' -Status 'pass' `
                -Title 'No active Bluetooth adapters' -Detail '' -Scenarios @('sleep-wake')
        }
    } catch {}
    
    # WiFi Auto-Connect to Open Networks
    try {
        $wifiAuto = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name AutoConnectAllowedOEM -ErrorAction SilentlyContinue
        if ($wifiAuto -and $wifiAuto.AutoConnectAllowedOEM -eq 0) {
            Write-Check 'pass' 'WiFi auto-connect to open networks disabled'
            Add-Check -Section 'access' -Id 'wifi-autoconnect' -Status 'pass' `
                -Title 'Auto-connect to open WiFi networks disabled' -Detail '' -Scenarios @('sleep-wake')
        } else {
            Write-Check 'info' 'WiFi auto-connect to open networks may be enabled'
            Add-Check -Section 'access' -Id 'wifi-autoconnect' -Status 'info' `
                -Title 'WiFi auto-connect setting not restricted' `
                -Detail 'The WiFi Sense auto-connect feature was removed in Windows 10 1803. On modern builds this setting has no effect. Listed for awareness on older systems only.' `
                -FixId 'wifi-autoconnect' -Scenarios @('sleep-wake')
        }
    } catch {}
    
    # Camera Privacy
    try {
        $camReg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' -Name Value -ErrorAction SilentlyContinue
        if ($camReg -and $camReg.Value -eq 'Deny') {
            Write-Check 'pass' 'Camera access denied by default'
            Add-Check -Section 'access' -Id 'camera-privacy' -Status 'pass' `
                -Title 'Camera access denied by default' -Detail '' -Scenarios @('sleep-wake')
        } else {
            Write-Check 'info' 'Camera access allowed by default'
            Add-Check -Section 'access' -Id 'camera-privacy' -Status 'info' `
                -Title 'Camera access allowed by default' `
                -Detail 'The system default allows apps to access the camera. This is the normal Windows configuration required for video calls. Restricting to Deny breaks Teams/Zoom until individually re-allowed. Only relevant if malware is already running on the device.' `
                -FixId 'camera-privacy' -Scenarios @('sleep-wake')
        }
    } catch {}
    
    # Microphone Privacy
    try {
        $micReg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone' -Name Value -ErrorAction SilentlyContinue
        if ($micReg -and $micReg.Value -eq 'Deny') {
            Write-Check 'pass' 'Microphone access denied by default'
            Add-Check -Section 'access' -Id 'mic-privacy' -Status 'pass' `
                -Title 'Microphone access denied by default' -Detail '' -Scenarios @('sleep-wake')
        } else {
            Write-Check 'info' 'Microphone access allowed by default'
            Add-Check -Section 'access' -Id 'mic-privacy' -Status 'info' `
                -Title 'Microphone access allowed by default' `
                -Detail 'The system default allows apps to access the microphone. This is the normal Windows configuration required for calls and dictation. Restricting to Deny adds friction to every audio app. Only relevant if malware is already running on the device.' `
                -FixId 'mic-privacy' -Scenarios @('sleep-wake')
        }
    } catch {}
    
    # WinRM Remote Management
    try {
        $winrmSvc = Get-Service WinRM -ErrorAction SilentlyContinue
        if ($winrmSvc -and $winrmSvc.Status -eq 'Running') {
            Write-Check 'fail' 'WinRM remote management is running'
            Add-Check -Section 'access' -Id 'winrm' -Status 'fail' `
                -Title 'WinRM remote management is RUNNING' `
                -Detail 'An attacker at the keyboard can use WinRM to establish persistent remote access or pivot to other machines. If Basic authentication is enabled, credentials may transit in cleartext.' `
                -FixId 'winrm' -Scenarios @('coercion')
        } elseif ($winrmSvc -and $winrmSvc.StartType -ne 'Disabled') {
            Write-Check 'warn' 'WinRM enabled but not running'
            Add-Check -Section 'access' -Id 'winrm' -Status 'warn' `
                -Title 'WinRM is enabled (not currently running)' `
                -Detail 'WinRM service is not disabled. It can be started by an attacker or triggered by policy refresh.' `
                -FixId 'winrm' -Scenarios @('coercion')
        } else {
            Write-Check 'pass' 'WinRM is disabled'
            Add-Check -Section 'access' -Id 'winrm' -Status 'pass' `
                -Title 'WinRM remote management is disabled' -Detail '' -Scenarios @('coercion')
        }
    } catch {}
    
    # PowerShell Language Mode
    try {
        $langMode = $ExecutionContext.SessionState.LanguageMode
        if ($langMode -eq 'ConstrainedLanguage') {
            Write-Check 'pass' 'PowerShell in Constrained Language Mode'
            Add-Check -Section 'access' -Id 'ps-language-mode' -Status 'pass' `
                -Title 'PowerShell in Constrained Language Mode' -Detail 'Limits available .NET types and cmdlets, reducing attack surface for post-access exploitation.' `
                -Scenarios @('coercion')
        } else {
            Write-Check 'info' "PowerShell in $langMode mode"
            Add-Check -Section 'access' -Id 'ps-language-mode' -Status 'info' `
                -Title "PowerShell in $langMode mode" `
                -Detail 'Full Language Mode is the default and is required for this scanner to operate. Constrained Language Mode requires a WDAC or AppLocker policy and cannot be set via registry. Listed for awareness only.' `
                -Scenarios @('coercion')
        }
    } catch {}
    
    # BitLocker Network Unlock
    try {
        $nkpReg = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name OSManageNKP -ErrorAction SilentlyContinue
        if ($nkpReg -and $nkpReg.OSManageNKP -eq 1) {
            Write-Check 'warn' 'BitLocker Network Unlock is enabled'
            Add-Check -Section 'encryption' -Id 'bl-network-unlock' -Status 'warn' `
                -Title 'BitLocker Network Unlock is enabled' `
                -Detail 'BitLocker auto-unlocks on the corporate network without requiring PIN. A stolen laptop brought within range of the corporate network (e.g. parking lot) unlocks automatically.' `
                -FixId 'bl-network-unlock' -Scenarios @('cold-boot')
        } else {
            Write-Check 'pass' 'BitLocker Network Unlock not configured'
            Add-Check -Section 'encryption' -Id 'bl-network-unlock' -Status 'pass' `
                -Title 'BitLocker Network Unlock is not configured' -Detail '' -Scenarios @('cold-boot')
        }
    } catch {}
    
    # Removable Drive Encryption Policy
    try {
        $rdvReg = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name RDVDenyWriteAccess -ErrorAction SilentlyContinue
        if ($rdvReg -and $rdvReg.RDVDenyWriteAccess -eq 1) {
            Write-Check 'pass' 'Removable drives require encryption for write'
            Add-Check -Section 'encryption' -Id 'removable-encrypt' -Status 'pass' `
                -Title 'Removable drives require BitLocker for write access' -Detail '' -Scenarios @('forensic')
        } else {
            Write-Check 'conditional-pass' 'Removable drives can be written without encryption' 'CIS 18.10.9.2.1 recommends requiring encryption'
            Add-Check -Section 'encryption' -Id 'removable-encrypt' -Status 'conditional-pass' `
                -Title 'Removable drives writable without encryption' `
                -Detail 'CIS and NIST 3.8.6 recommend encrypting portable storage. Enabling this makes unencrypted USB drives read-only, which prevents casual use of thumb drives.' `
                -FixId 'removable-encrypt' -Scenarios @('forensic')
        }
    } catch {}
}
function Get-ConsoleApproval {
    param([string]$Action, [string]$Detail)
    # SECURITY (v0.39): Use CSPRNG for confirmation codes (defense-in-depth)
    # SECURITY (v0.40): Wrap in try/finally to ensure Dispose() on exception
    # L-4 FIX: Increased from 4 digits (9,000 values) to 6 digits (900,000 values)
    $codeBytes = [byte[]]::new(4)
    $codeRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()  # L-2 FIX (v0.45): Use non-deprecated API
    try { $codeRng.GetBytes($codeBytes) } finally { $codeRng.Dispose() }
    $code = 100000 + ([BitConverter]::ToUInt32($codeBytes, 0) % 900000)
    Write-Host ''
    Write-Host "    >> $Action" -ForegroundColor Yellow
    if ($Detail) { Write-Host "       $Detail" -ForegroundColor DarkGray }
    Write-Host ''
    Write-Host "       Confirmation code: " -NoNewline -ForegroundColor White
    Write-Host "$code" -ForegroundColor Cyan
    Write-Host ''
    $approval = Read-Host "       Type $code to approve, or N to decline"
    if ($approval -eq "$code") { return $true }
    Write-Host '       [DECLINED]' -ForegroundColor DarkGray
    return $false
}

function Apply-Fix {
    param(
        [string]$FixId,
        [switch]$SkipApproval,    # Used by Fix All batch (already approved at batch level)
        [switch]$BatchMode        # Suppress per-fix console output in batch
    )
    
    if (-not $script:FixDefs.ContainsKey($FixId)) {
        return @{ success = $false; message = "Unknown fix: $FixId"; verified = $null; verifyState = 'error' }
    }
    
    $fix = $script:FixDefs[$FixId]
    
    $fixReboot = if ($fix.ContainsKey('Reboot')) { $fix.Reboot } else { $false }
    $fixNote   = if ($fix.ContainsKey('Note'))   { $fix.Note }   else { '' }
    
    # DRY RUN: show what would happen without applying
    if ($script:IsDryRun) {
        $action = switch ($fix.Type) {
            'registry'       { "SET $($fix.Path)\$($fix.Key) = $($fix.Value) [DWORD]" }
            'command'        { "RUN $($fix.Command)" }
            'multi-registry' { ($fix.Steps | ForEach-Object { "SET $($_.Path)\$($_.Key) = $($_.Value)" }) -join '; ' }
            'service'        { "SET-SERVICE $($fix.Service) -StartupType $($fix.StartType)" }
            'script'         { "EXECUTE: $($fix.Name)" }
        }
        $rb = if ($fixReboot) { ' [REBOOT REQUIRED]' } else { '' }
        Write-Host "    [DRY RUN] $($fix.Name)$rb" -ForegroundColor Cyan
        Write-Host "      $action" -ForegroundColor DarkGray
        if ($fixNote) { Write-Host "      NOTE: $fixNote" -ForegroundColor Yellow }
        if ($fix.ContainsKey('Impact') -and $fix.Impact) { Write-Host "      IMPACT: $($fix.Impact)" -ForegroundColor Yellow }
        return @{ success = $true; message = "DRY RUN: $action"; reboot = $false; dryRun = $true; verified = $null; verifyState = 'dryrun' }
    }
    
    # EDITION CHECK (v0.51): three-tier gating
    # Tier 1: BLOCKED - feature requires specific edition, fix cannot work
    $editionBlocked = @{
        'credential-guard' = @('Enterprise','Education')
        'enhanced-pin'     = @('Pro','Enterprise','Education')
        'vbs'              = @('Pro','Enterprise','Education')
        'hvci'             = @('Pro','Enterprise','Education')
        'bitlocker-pin'    = @('Pro','Enterprise','Education')
        'dma-guard'        = @('Pro','Enterprise','Education')
        'removable-encrypt'= @('Pro','Enterprise','Education')
        'bl-network-unlock'= @('Pro','Enterprise','Education')
    }
    # Tier 2: DEGRADED - writes to Group Policy registry paths that the GP engine
    # processes on Pro/Enterprise but NOT on Home. Registry write succeeds and
    # verifies, but the actual protection is NOT enforced. This is a false positive.
    $editionDegraded = @{
        'usb-storage'  = 'Removable Storage Access policy requires Group Policy (Pro/Enterprise). On Home, USB drives remain fully accessible despite the registry key.'
        'usb-install'  = 'Device Installation Restrictions require Group Policy (Pro/Enterprise). On Home, new USB devices will still auto-install.'
    }
    if ($editionBlocked.ContainsKey($FixId)) {
        $allowed = $editionBlocked[$FixId]
        if ($script:WindowsEdition -notin $allowed) {
            Write-Host "    [EDITION] This fix requires Windows $($allowed -join '/') but you have Windows $($script:WindowsEdition)" -ForegroundColor Yellow
            Write-Host "    The registry key will be written but may have no effect." -ForegroundColor Yellow
        }
    }
    if ($editionDegraded.ContainsKey($FixId) -and $script:WindowsEdition -eq 'Home') {
        Write-Host ''
        Write-Host '    +--------------------------------------------------------------+' -ForegroundColor Red
        Write-Host '    |  WARNING: THIS FIX WILL NOT WORK ON WINDOWS HOME            |' -ForegroundColor Red
        Write-Host '    +--------------------------------------------------------------+' -ForegroundColor Red
        Write-Host "    $($editionDegraded[$FixId])" -ForegroundColor Yellow
        Write-Host "    The registry write will succeed and verify, but the protection" -ForegroundColor Yellow
        Write-Host "    is NOT active. This is a known limitation of Windows Home." -ForegroundColor Yellow
        Write-Host ''
    }
    
    # v0.51: DOMAIN POLICY WARNING for net accounts-based fixes.
    # These write LOCAL policy. On domain-joined machines, domain GPO overrides
    # local on next group policy refresh (~90 min). Fix "succeeds" then reverts.
    $domainPolicyFixes = @('account-lockout', 'password-policy')
    if ($script:IsDomainJoined -and $FixId -in $domainPolicyFixes) {
        Write-Host ''
        Write-Host '    +--------------------------------------------------------------+' -ForegroundColor Yellow
        Write-Host '    |  NOTE: THIS MACHINE IS DOMAIN-JOINED                        |' -ForegroundColor Yellow
        Write-Host '    +--------------------------------------------------------------+' -ForegroundColor Yellow
        Write-Host '    This fix writes LOCAL policy via net accounts. Domain Group' -ForegroundColor Yellow
        Write-Host '    Policy may override it on next refresh (~90 min or gpupdate).' -ForegroundColor Yellow
        Write-Host '    For persistent changes on domain machines, configure the' -ForegroundColor Yellow
        Write-Host '    setting in the domain GPO instead.' -ForegroundColor Yellow
        Write-Host ''
    }
    
    # CONSOLE APPROVAL: require confirmation code for all mutations
    if (-not $SkipApproval -and -not $script:IsMonitorMode) {
        $impactText = ''
        if ($fixReboot) { $impactText += '[REBOOT REQUIRED] ' }
        if ($fix.ContainsKey('Impact') -and $fix.Impact) { $impactText += $fix.Impact }
        if ($fixNote) { $impactText += " Note: $fixNote" }
        $approved = Get-ConsoleApproval -Action "FIX REQUEST: $($fix.Name)" -Detail $impactText
        if (-not $approved) {
            return @{ success = $false; message = 'Declined by operator.'; declined = $true; reboot = $false; verified = $null; verifyState = 'declined' }
        }
    }
    
    # APPLY THE FIX
    $message = ''
    try {
        if ($fix.Type -eq 'registry') {
            $path = $fix.Path
            # SECURITY (v0.55/v0.56): If AllUsers flag is set and path is HKCU, iterate
            # all loaded user hives via HKEY_USERS. Fixes UAC context mismatch where
            # HKCU points to the admin's hive, leaving the actual user's data untouched.
            # v0.56: Use -like instead of -match to avoid regex backslash escaping
            # issues in PowerShell 5.1 that caused this check to silently fail.
            $regPaths = @($path)
            if ($fix.ContainsKey('AllUsers') -and $fix.AllUsers -and ($path -like 'HKCU:\*')) {
                $hkcuSuffix = $path.Substring(6)  # Strip 'HKCU:\' prefix (6 chars)
                $userSids = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' }
                foreach ($sidKey in $userSids) {
                    $regPaths += "Registry::HKEY_USERS\$($sidKey.PSChildName)\$hkcuSuffix"
                }
            }
            foreach ($rp in $regPaths) {
                if (-not (Test-Path $rp)) {
                    New-Item -Path $rp -Force -ErrorAction Stop | Out-Null
                }
                $regType = if ($fix.ContainsKey('RegType')) { $fix.RegType } else { 'DWord' }
                Set-ItemProperty -Path $rp -Name $fix.Key -Value $fix.Value -Type $regType -Force -ErrorAction Stop
            }
            $message = "Set $($fix.Key) = $($fix.Value)"
            if ($regPaths.Count -gt 1) { $message += " (across $($regPaths.Count) user hives)" }
            
            # M-4 FIX: Clear stored credentials when disabling auto-logon.
            # Setting AutoAdminLogon=0 stops the bypass but the plaintext password
            # remains in the registry, recoverable by any admin process or forensic tool.
            if ($FixId -eq 'auto-logon') {
                $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                foreach ($credProp in @('DefaultPassword', 'DefaultUserName', 'DefaultDomainName')) {
                    try {
                        $existing = Get-ItemProperty -Path $winlogonPath -Name $credProp -EA SilentlyContinue
                        if ($existing -and $existing.$credProp) {
                            Remove-ItemProperty -Path $winlogonPath -Name $credProp -Force -EA Stop
                            $message += "; Cleared $credProp"
                        }
                    } catch { $message += "; WARNING: could not clear $credProp" }
                }
            }

            # SECURITY (v0.67/v0.70): Purge existing forensic artifacts after setting registry
            # policies. The registry keys prevent FUTURE tracking but leave historical
            # .lnk files and .automaticDestinations-ms files on disk.
            # v0.70: User profile directories are user-owned. A standard user can replace
            # AutomaticDestinations or Recent with a junction to C:\Windows\System32.
            # Get-ChildItem follows junctions transparently, populating $destFiles with
            # system binaries. Remove-Item then deletes them as admin. Fix: Lock each
            # directory with LockDirectory (rejects junctions, holds handle to prevent
            # swap), then use SafeDeleteFile for each file. Degraded mode uses
            # Test-ReparsePoint with documented TOCTOU window.
            if ($FixId -eq 'fs-recent-docs') {
                $cleanedCount = 0
                $userProfiles = Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue
                foreach ($profile in $userProfiles) {
                    $recentDir = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\Recent'
                    if (Test-Path $recentDir) {
                        if ($script:HasNativeFileHelper) {
                            $lockHandle = $script:HtNative::LockDirectory($recentDir)
                            if ($null -ne $lockHandle) {
                                try {
                                    $lnkFiles = Get-ChildItem $recentDir -Filter '*.lnk' -File -EA SilentlyContinue
                                    foreach ($lnk in $lnkFiles) {
                                        if ($script:HtNative::SafeDeleteFile($lnk.FullName)) { $cleanedCount++ }
                                    }
                                } finally { $lockHandle.Dispose() }
                            } else {
                                Write-Host "    [SECURITY] Skipping $recentDir (reparse point or locked)." -ForegroundColor Yellow
                            }
                        } else {
                            if (-not (Test-ReparsePoint $recentDir)) {
                                $lnkFiles = Get-ChildItem $recentDir -Filter '*.lnk' -File -EA SilentlyContinue
                                foreach ($lnk in $lnkFiles) {
                                    Remove-Item $lnk.FullName -Force -EA SilentlyContinue
                                    $cleanedCount++
                                }
                            }
                        }
                    }
                }
                if ($cleanedCount -gt 0) { $message += "; Deleted $cleanedCount .lnk files from Recent Documents" }
            }
            if ($FixId -eq 'fs-jump-lists') {
                $cleanedCount = 0
                $userProfiles = Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue
                foreach ($profile in $userProfiles) {
                    $autoDestDir = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations'
                    $customDestDir = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations'
                    foreach ($destDir in @($autoDestDir, $customDestDir)) {
                        if (Test-Path $destDir) {
                            if ($script:HasNativeFileHelper) {
                                $lockHandle = $script:HtNative::LockDirectory($destDir)
                                if ($null -ne $lockHandle) {
                                    try {
                                        $destFiles = Get-ChildItem $destDir -File -EA SilentlyContinue
                                        foreach ($df in $destFiles) {
                                            if ($script:HtNative::SafeDeleteFile($df.FullName)) { $cleanedCount++ }
                                        }
                                    } finally { $lockHandle.Dispose() }
                                } else {
                                    Write-Host "    [SECURITY] Skipping $destDir (reparse point or locked)." -ForegroundColor Yellow
                                }
                            } else {
                                if (-not (Test-ReparsePoint $destDir)) {
                                    $destFiles = Get-ChildItem $destDir -File -EA SilentlyContinue
                                    foreach ($df in $destFiles) {
                                        Remove-Item $df.FullName -Force -EA SilentlyContinue
                                        $cleanedCount++
                                    }
                                }
                            }
                        }
                    }
                }
                if ($cleanedCount -gt 0) { $message += "; Deleted $cleanedCount Jump List files" }
            }
        }
        elseif ($fix.Type -eq 'command') {
            # Safe execution: only whitelisted executables (fully qualified paths)
            $allowedExes = @($script:Bin.powercfg, $script:Bin.reagentc, $script:Bin.bcdedit, $script:Bin.net, $script:Bin.vssadmin)
            $commands = $fix.Command -split '\s*;\s*'
            $allOutput = @()
            foreach ($cmd in $commands) {
                $parts = $cmd -split '\s+', 2
                $exe = $parts[0]
                if ($exe -notin $allowedExes) {
                    throw "Blocked: '$exe' is not in the allowed executable list."
                }
                $cmdArgs = if ($parts.Count -gt 1) { $parts[1] -split '\s+' } else { @() }
                $allOutput += & $exe @cmdArgs 2>&1
            }
            $output = $allOutput -join "`n"
            $message = "Executed: $($fix.Command)"
        }
        elseif ($fix.Type -eq 'multi-registry') {
            foreach ($step in $fix.Steps) {
                if (-not (Test-Path $step.Path)) { New-Item -Path $step.Path -Force -ErrorAction Stop | Out-Null }
                Set-ItemProperty -Path $step.Path -Name $step.Key -Value $step.Value -Type DWord -Force -ErrorAction Stop
            }
            $message = "Set $($fix.Steps.Count) registry values"
        }
        elseif ($fix.Type -eq 'service') {
            $svc = Get-Service $fix.Service -ErrorAction Stop
            if ($svc.Status -eq 'Running') { Stop-Service $fix.Service -Force -ErrorAction SilentlyContinue }
            Set-Service $fix.Service -StartupType $fix.StartType -ErrorAction Stop
            $message = "Service $($fix.Service) set to $($fix.StartType)"
        }
        elseif ($fix.Type -eq 'script') {
            switch ($FixId) {
                'fs-user-assist' {
                    # SECURITY (v0.52): Enumerate ALL user hives, not just HKCU.
                    # SECURITY (v0.53): Use Remove-RegistryKeySafe to detect REG_LINK
                    # symlinks. Standard users can plant registry symlinks in their own
                    # hive pointing to HKLM\SYSTEM or HKLM\SAM. Remove-Item follows
                    # these links, causing our SYSTEM process to delete critical hives.
                    $userSids = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' }
                    foreach ($sidKey in $userSids) {
                        $uaBase = "Registry::HKEY_USERS\$($sidKey.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
                        if (Test-Path $uaBase) {
                            Get-ChildItem $uaBase -ErrorAction SilentlyContinue | ForEach-Object {
                                $countPath = Join-Path $_.PSPath 'Count'
                                if (Test-Path $countPath) {
                                    # SECURITY (v0.72): Delete only. Do NOT recreate with New-Item.
                                    # Between Remove-RegistryKeySafe and New-Item, a standard user
                                    # can win the race and plant a REG_LINK at the path. New-Item
                                    # follows the link and overwrites the target (e.g. HKLM\SYSTEM)
                                    # as NT AUTHORITY\SYSTEM. Windows Explorer auto-rebuilds the
                                    # Count key on next program launch.
                                    Remove-RegistryKeySafe -ProviderPath $countPath -Recurse | Out-Null
                                }
                            }
                        }
                    }
                    # Also handle HKCU for edge cases where HKU enumeration misses the current user
                    $uaBase = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
                    Get-ChildItem $uaBase -ErrorAction SilentlyContinue | ForEach-Object {
                        $countPath = Join-Path $_.PSPath 'Count'
                        if (Test-Path $countPath) {
                            Remove-RegistryKeySafe -ProviderPath $countPath -Recurse | Out-Null
                        }
                    }
                }
                'fs-ps-history' {
                    # SECURITY (v0.52): Enumerate ALL user profiles, not just $env:APPDATA.
                    # UAC elevation changes the user context - $env:APPDATA points to the
                    # admin's profile, leaving the actual user's PS history untouched.
                    $profileDirs = @()
                    try {
                        $profileDirs = Get-ChildItem (Join-Path $script:TrustedSystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } |
                            ForEach-Object { $_.FullName }
                    } catch {}
                    # Always include current user's APPDATA as fallback
                    $histPaths = @($profileDirs | ForEach-Object {
                        Join-Path $_ 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
                    })
                    $histPaths += Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
                    $histPaths = $histPaths | Select-Object -Unique
                    foreach ($histFile in $histPaths) {
                        if (Test-Path $histFile) {
                            # SECURITY (v0.58): Atomic link-safe deletion via P/Invoke.
                            # User-controlled paths cannot be safely overwritten or deleted
                            # using managed .NET APIs because they follow reparse points and
                            # cannot detect hardlinks atomically. The native helper opens with
                            # FILE_FLAG_OPEN_REPARSE_POINT, checks nNumberOfLinks via
                            # GetFileInformationByHandle, and marks for deletion through the
                            # same locked handle. Zero TOCTOU window.
                            try {
                                if ($script:HasNativeFileHelper) {
                                    $deleted = $script:HtNative::SafeDeleteFile($histFile)
                                    if (-not $deleted) {
                                        Write-Host "    [SECURITY] Skipping linked/locked file: $histFile" -ForegroundColor Red
                                    }
                                }
                                else {
                                    # Fallback: managed delete (less safe, but best available
                                    # when Add-Type is blocked by constrained language mode)
                                    Write-Host "    [SECURITY DEGRADED] Using managed File.Delete for: $histFile" -ForegroundColor Yellow
                                    Write-Host "    Hardlink/symlink attacks cannot be prevented in this mode." -ForegroundColor Yellow
                                    [System.IO.File]::Delete($histFile)
                                }
                            } catch {}
                        }
                    }
                }
                'fs-bam' {
                    foreach ($basePath in @(
                        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
                        'HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings'
                    )) {
                        if (Test-Path $basePath) {
                            Get-ChildItem $basePath -ErrorAction SilentlyContinue | ForEach-Object {
                                $props = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).PSObject.Properties |
                                    Where-Object { $_.Name -notin @('Version', 'SequenceNumber', 'PSPath', 'PSParentPath', 'PSChildName', 'PSProvider', 'PSDrive') }
                                foreach ($p in $props) { Remove-ItemProperty $_.PSPath -Name $p.Name -Force -ErrorAction SilentlyContinue }
                            }
                        }
                    }
                }
                'fs-network-profiles' {
                    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures' -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles' -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                }
                'fs-shellbags' {
                    # SECURITY (v0.52): Enumerate ALL user hives via HKEY_USERS.
                    # SECURITY (v0.53): Use Remove-RegistryKeySafe for REG_LINK detection.
                    $userSids = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' }
                    foreach ($sidKey in $userSids) {
                        $huBase = "Registry::HKEY_USERS\$($sidKey.PSChildName)"
                        $huClassesBase = "Registry::HKEY_USERS\$($sidKey.PSChildName)_Classes"
                        foreach ($shellPath in @(
                            "$huBase\Software\Microsoft\Windows\Shell\BagMRU",
                            "$huBase\Software\Microsoft\Windows\Shell\Bags"
                        )) {
                            # SECURITY (v0.72): Delete only. Do NOT recreate with New-Item.
                            # Same TOCTOU as fs-user-assist: attacker plants REG_LINK between
                            # delete and recreate, New-Item follows link to HKLM\SYSTEM.
                            # Explorer auto-rebuilds these keys on next folder navigation.
                            Remove-RegistryKeySafe -ProviderPath $shellPath -Recurse | Out-Null
                        }
                        foreach ($shellPath in @(
                            "$huClassesBase\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
                            "$huClassesBase\Local Settings\Software\Microsoft\Windows\Shell\Bags"
                        )) {
                            Remove-RegistryKeySafe -ProviderPath $shellPath -Recurse | Out-Null
                        }
                    }
                    # Also handle HKCU as fallback
                    foreach ($shellPath in @(
                        'HKCU:\Software\Microsoft\Windows\Shell\BagMRU',
                        'HKCU:\Software\Microsoft\Windows\Shell\Bags'
                    )) {
                        Remove-RegistryKeySafe -ProviderPath $shellPath -Recurse | Out-Null
                    }
                    Remove-RegistryKeySafe -ProviderPath 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU' -Recurse | Out-Null
                    Remove-RegistryKeySafe -ProviderPath 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags' -Recurse | Out-Null
                }
                # v0.47 new fixes
                'builtin-admin' {
                    # v0.51: SID-based lookup, not hardcoded English name.
                    # Built-in Administrator is always SID *-500 but has a localized name.
                    $admin500 = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1
                    if (-not $admin500) { throw 'Could not find built-in Administrator (SID *-500)' }
                    # SECURITY (v0.52): Verify at least one OTHER active admin exists before
                    # disabling the built-in account. If *-500 is the only admin (common in
                    # kiosks, labs, legacy deployments), disabling it permanently locks out
                    # all administrative access, requiring offline SAM edits to recover.
                    # Use Administrators group SID S-1-5-32-544 for locale independence.
                    $adminGroupSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
                    $adminGroupName = $adminGroupSid.Translate([System.Security.Principal.NTAccount]).Value
                    $otherAdmins = @()
                    try {
                        # Get-LocalGroupMember returns all members (local users, domain users, nested groups)
                        $members = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop
                        foreach ($member in $members) {
                            # Skip the built-in admin itself
                            if ($member.SID.Value -like '*-500') { continue }
                            # For local users, check if they're enabled
                            if ($member.ObjectClass -eq 'User') {
                                try {
                                    $localUser = Get-LocalUser -SID $member.SID -ErrorAction Stop
                                    if ($localUser.Enabled) { $otherAdmins += $member.Name }
                                } catch {
                                    # Domain user or unresolvable SID - assume active
                                    $otherAdmins += $member.Name
                                }
                            } else {
                                # Groups (including domain groups) - count as valid admin source
                                $otherAdmins += "$($member.Name) (group)"
                            }
                        }
                    } catch {
                        throw "SAFETY ABORT: Could not enumerate Administrators group ($adminGroupName). Cannot safely determine if other admin accounts exist: $_"
                    }
                    if ($otherAdmins.Count -eq 0) {
                        throw "SAFETY ABORT: The built-in Administrator (*-500) is the ONLY active admin account on this machine. Disabling it would permanently lock out all administrative access. Create another admin account first."
                    }
                    Write-Host "    [OK] Found $($otherAdmins.Count) other admin(s): $($otherAdmins -join ', ')" -ForegroundColor DarkGray
                    Disable-LocalUser -SID $admin500.SID -ErrorAction Stop
                }
                'bitlocker-pin' {
                    # Safety: verify a recovery key protector exists before touching anything
                    $bl = Get-BitLockerVolume -MountPoint $script:TrustedSystemDrive -ErrorAction Stop
                    $recoveryKey = $bl.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
                    if (-not $recoveryKey) {
                        throw "SAFETY ABORT: No BitLocker recovery key protector found on $($script:TrustedSystemDrive). Add a recovery key first (manage-bde -protectors -add $($script:TrustedSystemDrive) -RecoveryPassword) before changing PIN protectors."
                    }
                    # Enable the TPM+PIN policy (required before adding PIN protector)
                    $fvePath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
                    if (-not (Test-Path $fvePath)) { New-Item -Path $fvePath -Force | Out-Null }
                    Set-ItemProperty -Path $fvePath -Name 'UseTPMPIN' -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $fvePath -Name 'UseAdvancedStartup' -Value 1 -Type DWord -Force
                    # Prompt user for PIN in the console
                    # SECURITY (v0.52): Use -AsSecureString to prevent plaintext PIN from:
                    #   a) being visible on screen (shoulder surfing)
                    #   b) being captured in PowerShell transcript logs (which the script
                    #      explicitly detects and warns about)
                    #   c) persisting in process memory as a managed string
                    Write-Host ''
                    Write-Host '    ==========================================================' -ForegroundColor Yellow
                    Write-Host '     BITLOCKER PIN SETUP' -ForegroundColor Yellow
                    Write-Host '    ==========================================================' -ForegroundColor Yellow
                    Write-Host '    Enter a PIN (minimum 6 digits). You will need this PIN' -ForegroundColor White
                    Write-Host '    EVERY TIME you boot the machine, BEFORE Windows loads.' -ForegroundColor White
                    Write-Host '    If you forget the PIN you will need your recovery key.' -ForegroundColor White
                    Write-Host "    Recovery key ID: $($recoveryKey.KeyProtectorId)" -ForegroundColor DarkGray
                    Write-Host ''
                    $securePin = Read-Host '    Enter BitLocker PIN' -AsSecureString
                    $securePinConfirm = Read-Host '    Confirm PIN' -AsSecureString
                    # SECURITY (v0.52): Validate length and equality WITHOUT creating managed
                    # strings. .NET strings are immutable - once created, the plaintext PIN
                    # lives in the managed heap until GC overwrites it, which is unbounded.
                    # SecureString.Length gives us the character count directly.
                    # For equality, we compare BSTR pointers character-by-character using
                    # Marshal.ReadInt16 (2 bytes per UTF-16 char), then ZeroFreeBSTR both.
                    if ($securePin.Length -lt 6) { throw 'PIN must be at least 6 characters. Aborting.' }
                    if ($securePin.Length -ne $securePinConfirm.Length) { throw 'PINs do not match. Aborting.' }
                    $bstrPin = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePin)
                    $bstrConfirm = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePinConfirm)
                    try {
                        $mismatch = $false
                        for ($i = 0; $i -lt $securePin.Length; $i++) {
                            $c1 = [System.Runtime.InteropServices.Marshal]::ReadInt16($bstrPin, $i * 2)
                            $c2 = [System.Runtime.InteropServices.Marshal]::ReadInt16($bstrConfirm, $i * 2)
                            if ($c1 -ne $c2) { $mismatch = $true }
                            # Don't break early - constant-time comparison
                        }
                        if ($mismatch) { throw 'PINs do not match. Aborting.' }
                    } finally {
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrPin)
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrConfirm)
                    }
                    # Add TPM+PIN FIRST, then remove TPM-only AFTER verifying new protector exists
                    Add-BitLockerKeyProtector -MountPoint $script:TrustedSystemDrive -TpmAndPinProtector -Pin $securePin -ErrorAction Stop
                    # Verify the TPM+PIN protector was added before removing old one
                    $bl2 = Get-BitLockerVolume -MountPoint $script:TrustedSystemDrive -ErrorAction Stop
                    $newPinProtector = $bl2.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'TpmPin' }
                    if (-not $newPinProtector) {
                        throw 'TPM+PIN protector was not added successfully. TPM-only protector left intact.'
                    }
                    # Now safe to remove the TPM-only protector
                    $tpmProtector = $bl2.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Tpm' } | Select-Object -First 1
                    if ($tpmProtector) {
                        Remove-BitLockerKeyProtector -MountPoint $script:TrustedSystemDrive -KeyProtectorId $tpmProtector.KeyProtectorId -ErrorAction Stop
                    }
                }
                'fs-wer' {
                    # SECURITY (v0.52): Use junction-safe deletion. WER directories are
                    # user-writable (BUILTIN\Users can create subdirs in ReportArchive).
                    # An attacker plants a junction to C:\Windows\System32 inside the
                    # directory. Remove-Item -Recurse follows it and deletes System32.
                    # SECURITY (v0.64): $env:LOCALAPPDATA resolves to SYSTEM's profile
                    # when running as scheduled task. Iterate all user profiles instead.
                    $werDirs = @(
                        "$script:TrustedProgramData\Microsoft\Windows\WER\ReportArchive",
                        "$script:TrustedProgramData\Microsoft\Windows\WER\ReportQueue"
                    )
                    $userProfiles = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue
                    foreach ($profile in $userProfiles) {
                        $werDirs += Join-Path $profile.FullName 'AppData\Local\CrashDumps'
                        $werDirs += Join-Path $profile.FullName 'AppData\Local\Microsoft\Windows\WER'
                    }
                    foreach ($werDir in $werDirs) {
                        if (Test-Path $werDir) {
                            Remove-ItemSafeRecurse -Path $werDir
                        }
                    }
                }
                'fs-amcache' {
                    # Amcache.hve is locked by the system. Clear the most recent entries via registry.
                    # The InventoryApplication* keys under the mounted hive store program execution records.
                    $amcPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications'
                    # Primary approach: delete the file during next boot via PendingFileRenameOperations
                    $amcFile = Join-Path $script:TrustedSystemRoot 'appcompat\Programs\Amcache.hve'
                    if (Test-Path $amcFile) {
                        # Stop the Application Experience service which holds the lock
                        Stop-Service 'AeLookupSvc' -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 500
                        try {
                            Remove-Item $amcFile -Force -ErrorAction Stop
                        } catch {
                            # File still locked - schedule removal at next boot
                            $pfr = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
                            $existing = (Get-ItemProperty $pfr -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
                            $newEntries = @("\??\$amcFile", '')
                            if ($existing) { $newEntries = $existing + $newEntries }
                            Set-ItemProperty $pfr -Name PendingFileRenameOperations -Value $newEntries -ErrorAction SilentlyContinue
                        }
                    }
                }
                'fs-shimcache' {
                    # Clear the AppCompatCache registry value
                    $shimPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
                    Remove-ItemProperty -Path $shimPath -Name 'AppCompatCache' -Force -ErrorAction Stop
                }
                'bluetooth' {
                    Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' } | ForEach-Object {
                        Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                    }
                }
                'fs-srum' {
                    $srumPath = Join-Path $script:TrustedSystemRoot 'System32\sru\SRUDB.dat'
                    if (Test-Path $srumPath) {
                        # Stop the DPS service which holds the SRUM database lock
                        Stop-Service 'DPS' -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 500
                        try {
                            Remove-Item $srumPath -Force -ErrorAction Stop
                        } catch {
                            # Schedule for next boot if still locked
                            $pfr = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
                            $existing = (Get-ItemProperty $pfr -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
                            $newEntries = @("\??\$srumPath", '')
                            if ($existing) { $newEntries = $existing + $newEntries }
                            Set-ItemProperty $pfr -Name PendingFileRenameOperations -Value $newEntries -ErrorAction SilentlyContinue
                        }
                        # Restart DPS
                        Start-Service 'DPS' -ErrorAction SilentlyContinue
                    }
                }
            }
            $message = "Executed: $($fix.Name)"
        }
        
        # ====================================================================
        #  POST-FIX VERIFICATION: read back the actual machine state
        # ====================================================================
        $verified = $null     # $true = confirmed, $false = failed, $null = could not verify
        $verifyMessage = ''
        
        try {
            switch ($fix.Type) {
                'registry' {
                    $actual = (Get-ItemProperty -Path $fix.Path -Name $fix.Key -ErrorAction Stop).$($fix.Key)
                    $isStringType = $fix.ContainsKey('RegType') -and $fix.RegType -eq 'String'
                    $valuesMatch = if ($isStringType) { "$actual" -eq "$($fix.Value)" } else { [int]$actual -eq [int]$fix.Value }
                    if ($valuesMatch) {
                        $verified = $true
                        $verifyMessage = "Verified: $($fix.Key) = $actual"
                    } else {
                        $verified = $false
                        $verifyMessage = "VERIFICATION FAILED: expected $($fix.Value), got $actual (GPO override or policy conflict)"
                    }
                }
                'multi-registry' {
                    $allOk = $true; $failedSteps = @()
                    foreach ($step in $fix.Steps) {
                        $actual = (Get-ItemProperty -Path $step.Path -Name $step.Key -ErrorAction Stop).$($step.Key)
                        if ([int]$actual -ne [int]$step.Value) {
                            $allOk = $false
                            $failedSteps += "$($step.Key): expected $($step.Value), got $actual"
                        }
                    }
                    $verified = $allOk
                    $verifyMessage = if ($allOk) { "Verified: all $($fix.Steps.Count) values set" } else { "FAILED: $($failedSteps -join '; ')" }
                }
                'service' {
                    $svcNow = Get-Service $fix.Service -ErrorAction Stop
                    if ($svcNow.StartType.ToString() -eq $fix.StartType) {
                        $verified = $true
                        $verifyMessage = "Verified: $($fix.Service) startup = $($svcNow.StartType)"
                    } else {
                        $verified = $false
                        $verifyMessage = "VERIFICATION FAILED: $($fix.Service) startup = $($svcNow.StartType), expected $($fix.StartType)"
                    }
                }
                'command' {
                    switch ($FixId) {
                        'hibernate' {
                            $hiberFile = Join-Path $script:TrustedSystemDrive 'hiberfil.sys'
                            if (-not (Test-Path $hiberFile)) {
                                $verified = $true; $verifyMessage = 'Verified: hibernation disabled'
                            } else {
                                $verified = $null; $verifyMessage = 'Applied but hiberfil.sys still present. File will be removed on next reboot.'
                            }
                        }
                        'wake-timers' {
                            $wtResult = Get-PowerSettingValue -SubgroupGuid '238c9fa8-0aad-41ed-83f4-97be242c8f20' -SettingGuid 'bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d'
                            if ($wtResult -and $wtResult.AC -eq 0) {
                                $verified = $true; $verifyMessage = 'Verified: wake timers disabled (AC)'
                            } else {
                                $verified = $null; $verifyMessage = 'Applied but could not confirm wake timer state'
                            }
                        }
                        'winre' {
                            $winreCheck = Get-ItemProperty 'HKLM:\SYSTEM\Setup\Recovery' -Name Enabled -EA SilentlyContinue
                            if ($winreCheck -and $winreCheck.Enabled -eq 0) {
                                $verified = $true; $verifyMessage = 'Verified: WinRE disabled'
                            } else {
                                $verified = $false; $verifyMessage = 'VERIFICATION FAILED: WinRE still enabled in registry'
                            }
                        }
                        'kernel-debug' {
                            $bcdOut = & $script:Bin.bcdedit /enum '{current}' 2>&1 | Out-String
                            if ($bcdOut -notmatch '(?m)^\s*debug\s') {
                                $verified = $true; $verifyMessage = 'Verified: kernel debug off'
                            } else {
                                $verified = $null; $verifyMessage = 'Applied - verify after reboot'
                            }
                        }
                        'test-signing' {
                            $bcdOut = & $script:Bin.bcdedit /enum '{current}' 2>&1 | Out-String
                            if ($bcdOut -notmatch '(?m)^\s*testsigning\s') {
                                $verified = $true; $verifyMessage = 'Verified: test signing off'
                            } else {
                                $verified = $null; $verifyMessage = 'Applied - verify after reboot'
                            }
                        }
                        'screen-timeout' {
                            $stResult = Get-PowerSettingValue -SubgroupGuid '7516b95f-f776-4464-8c53-06167f40cc99' -SettingGuid '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e'
                            if ($stResult) {
                                $secs = $stResult.AC
                                $verified = ($secs -gt 0 -and $secs -le 300)
                                $verifyMessage = if ($verified) { "Verified: display timeout $([math]::Round($secs/60)) min" } else { "Timeout is $([math]::Round($secs/60)) min" }
                            } else { $verified = $null; $verifyMessage = 'Could not read power settings' }
                        }
                        'account-lockout' {
                            $secPolCheck = Get-SecurityPolicy
                            $lockCheck = if ($secPolCheck.ContainsKey('LockoutBadCount')) { [int]$secPolCheck['LockoutBadCount'] } else { 0 }
                            if ($lockCheck -gt 0) {
                                $verified = $true; $verifyMessage = "Verified: lockout after $lockCheck attempts"
                            } else { $verified = $false; $verifyMessage = 'Lockout threshold still not set' }
                        }
                        'password-policy' {
                            $secPolCheck = Get-SecurityPolicy
                            $pwCheck = if ($secPolCheck.ContainsKey('MinimumPasswordLength')) { [int]$secPolCheck['MinimumPasswordLength'] } else { 0 }
                            if ($pwCheck -ge 8) {
                                $verified = $true; $verifyMessage = "Verified: minimum length $pwCheck"
                            } else { $verified = $null; $verifyMessage = "Length is $pwCheck, expected 8+" }
                        }
                        'fs-shadow-copies' {
                            $scRemain = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue).Count
                            $verified = ($scRemain -eq 0)
                            $verifyMessage = if ($verified) { 'Verified: all shadow copies deleted' } else { "$scRemain shadow copies remain" }
                        }
                        default { $verified = $null; $verifyMessage = 'Applied (no automated verification for this command)' }
                    }
                }
                'script' {
                    switch ($FixId) {
                        'fs-user-assist' {
                            $remaining = 0
                            @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count',
                              'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count') | ForEach-Object {
                                if (Test-Path $_) {
                                    $remaining += ((Get-ItemProperty $_ -EA SilentlyContinue).PSObject.Properties |
                                        Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider','PSDrive') }).Count
                                }
                            }
                            $verified = ($remaining -le 2)
                            $verifyMessage = if ($verified) { "Verified: UserAssist cleared" } else { "Partial: $remaining entries remain (Windows may re-record)" }
                        }
                        'fs-ps-history' {
                            $histFile = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
                            $lines = 0; if (Test-Path $histFile) { $lines = (Get-Content $histFile -EA SilentlyContinue | Measure-Object).Count }
                            $verified = ($lines -le 1)
                            $verifyMessage = if ($verified) { 'Verified: history cleared' } else { "Partial: $lines lines remain" }
                        }
                        'fs-bam' {
                            $bamLeft = 0
                            @('HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
                              'HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings') | ForEach-Object {
                                if (Test-Path $_) {
                                    Get-ChildItem $_ -EA SilentlyContinue | ForEach-Object {
                                        $bamLeft += ((Get-ItemProperty $_.PSPath -EA SilentlyContinue).PSObject.Properties |
                                            Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider','PSDrive','Version','SequenceNumber') }).Count
                                    }
                                }
                            }
                            $verified = ($bamLeft -eq 0)
                            $verifyMessage = if ($verified) { 'Verified: BAM entries cleared' } else { "$bamLeft entries remain (may repopulate)" }
                        }
                        'fs-network-profiles' {
                            $npLeft = 0
                            try { $npLeft = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles' -EA SilentlyContinue | Measure-Object).Count } catch {}
                            $verified = ($npLeft -le 1)  # Active connection regenerates
                            $verifyMessage = if ($verified) { "Verified: profiles cleared ($npLeft remaining - active connection)" } else { "$npLeft profiles remain" }
                        }
                        'fs-shellbags' {
                            $sbLeft = 0
                            try { if (Test-Path 'HKCU:\Software\Microsoft\Windows\Shell\BagMRU') {
                                $sbLeft = ((Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\BagMRU' -EA SilentlyContinue).PSObject.Properties.Count - 2)
                            }} catch {}
                            $verified = ($sbLeft -le 0)
                            $verifyMessage = if ($verified) { 'Verified: ShellBags cleared' } else { "$sbLeft entries remain" }
                        }
                        'builtin-admin' {
                            try {
                                $admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1
                                $verified = ($admin -and -not $admin.Enabled)
                                $verifyMessage = if ($verified) { 'Verified: Administrator account disabled' } else { 'FAILED: account still enabled' }
                            } catch { $verified = $null; $verifyMessage = 'Could not query account status' }
                        }
                        'bitlocker-pin' {
                            try {
                                $bl = Get-BitLockerVolume -MountPoint $script:TrustedSystemDrive -EA Stop
                                $hasPin = $bl.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'TpmPin' }
                                $verified = ($null -ne $hasPin)
                                $verifyMessage = if ($verified) { 'Verified: TPM+PIN protector active' } else { 'PIN protector not detected - reboot may be required' }
                            } catch { $verified = $null; $verifyMessage = 'Could not verify BitLocker status' }
                        }
                        'fs-wer' {
                            $werLeft = 0
                            # SECURITY (v0.64): Iterate all user profiles, not just $env:LOCALAPPDATA
                            $werVerifyPaths = @("$script:TrustedProgramData\Microsoft\Windows\WER\ReportArchive","$script:TrustedProgramData\Microsoft\Windows\WER\ReportQueue")
                            $vProfiles = Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue
                            foreach ($vp in $vProfiles) {
                                $werVerifyPaths += Join-Path $vp.FullName 'AppData\Local\CrashDumps'
                                $werVerifyPaths += Join-Path $vp.FullName 'AppData\Local\Microsoft\Windows\WER'
                            }
                            foreach ($wp in $werVerifyPaths) {
                                if (Test-Path $wp) { $werLeft += (Get-ChildItem $wp -Recurse -File -EA SilentlyContinue | Measure-Object).Count }
                            }
                            $verified = ($werLeft -le 5)
                            $verifyMessage = if ($verified) { "Verified: WER reports cleared ($werLeft remaining)" } else { "$werLeft files remain" }
                        }
                        'fs-amcache' {
                            $amcFile = Join-Path $script:TrustedSystemRoot 'appcompat\Programs\Amcache.hve'
                            $verified = (-not (Test-Path $amcFile))
                            $verifyMessage = if ($verified) { 'Verified: Amcache.hve deleted' } else { 'File still present (locked - scheduled for removal at next boot)' }
                        }
                        'fs-shimcache' {
                            try {
                                $shimVal = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -EA Stop
                                $verified = $false; $verifyMessage = 'AppCompatCache still present (may regenerate from memory until reboot)'
                            } catch {
                                $verified = $true; $verifyMessage = 'Verified: AppCompatCache cleared'
                            }
                        }
                        'bluetooth' {
                            $btActive = Get-PnpDevice -Class Bluetooth -EA SilentlyContinue | Where-Object { $_.Status -eq 'OK' }
                            $verified = ($null -eq $btActive -or $btActive.Count -eq 0)
                            $verifyMessage = if ($verified) { 'Verified: all Bluetooth adapters disabled' } else { "Still active: $($btActive.Count) Bluetooth device(s)" }
                        }
                'fs-srum' {
                            $srumPath = Join-Path $script:TrustedSystemRoot 'System32\sru\SRUDB.dat'
                            $verified = (-not (Test-Path $srumPath))
                            $verifyMessage = if ($verified) { 'Verified: SRUM database deleted' } else { 'File still present (locked - scheduled for removal at next boot)' }
                        }
                        default { $verified = $null; $verifyMessage = 'Applied (no automated verification)' }
                    }
                }
            }
        } catch {
            $verified = $null
            $verifyMessage = "Could not verify: $_"
        }
        
        # Determine verification state for dashboard
        # CRITICAL: if fix requires reboot and registry write verified, the change is NOT yet active.
        # Report 'pending_reboot' instead of 'verified' so dashboard does not show green checkmark.
        if ($fixReboot -and $verified -eq $true) {
            $verifyState = 'pending_reboot'
            $verifyMessage = "$verifyMessage - reboot required for change to take effect"
            $vColor = 'Yellow'
        } elseif ($verified -eq $true) {
            $verifyState = 'verified'
            $vColor = 'Green'
        } elseif ($verified -eq $false) {
            $verifyState = 'failed_verification'
            $vColor = 'Red'
        } else {
            $verifyState = 'unverified'
            $vColor = 'Yellow'
        }
        $needsReboot = if ($fixReboot) { ' (reboot required)' } else { '' }
        
        if (-not $BatchMode) {
            if ($verifyState -eq 'pending_reboot') {
                Write-Host "    [APPLIED] $($fix.Name) - REBOOT REQUIRED" -ForegroundColor Yellow
            } else {
                Write-Host "    [FIXED] $($fix.Name)$needsReboot" -ForegroundColor Green
            }
            Write-Host "    [$($verifyState.ToUpper())] $verifyMessage" -ForegroundColor $vColor
        }
        
        return @{ 
            success       = $true
            message       = $message
            reboot        = [bool]$fixReboot
            note          = [string]$fixNote
            verified      = $verified
            verifyMessage = $verifyMessage
            verifyState   = $verifyState
        }
    }
    catch {
        Write-Host "    [ERROR] $($fix.Name): $_" -ForegroundColor Red
        return @{ success = $false; message = 'Fix failed. Check the PowerShell console for details.'; reboot = $false; verified = $false; verifyMessage = 'Exception during fix application'; verifyState = 'error' }
    }
}

# ============================================================================
#  HTTP SERVER FOR LIVE FIXES
# ============================================================================
# SECURITY THREAT MODEL (v0.39):
# The dashboard runs on plain HTTP over localhost (127.0.0.1). TLS is not used.
# Any local process with network visibility (raw sockets, WFP filters, browser
# extensions, local proxy software) can intercept the auth token from X-HT-Auth
# headers and make authenticated requests to read security posture data (/data)
# or trigger server shutdown (/shutdown). Fix operations still require console
# approval (Read-Host), providing defense-in-depth against token theft.
# 
# Accepted risks:
#   - /data endpoint leaks full security posture to any local process with token
#   - /shutdown can be triggered remotely on localhost with token
# Mitigations:
#   - Localhost-only binding (127.0.0.1)
#   - Console-gated approval for all fix operations
#   - 15-minute idle timeout
#   - Token delivered via ACL-protected file only (v0.74 - no URL/process-list exposure)
# ============================================================================
function Start-FixServer {
    param([string]$HtmlContent, [string]$JsonPath)
    
    # SECURITY (v0.39): Support explicit -Port parameter to prevent port-squatting DoS.
    # If user specified a port, try that first; if not, fall back to candidate list.
    $ports = @(8080, 8081, 8082, 8083, 8084, 8085, 9090, 9091)
    if ($script:RequestedPort -gt 0) {
        $ports = @($script:RequestedPort) + $ports
    }
    $listener = $null
    
    foreach ($port in $ports) {
        try {
            $testListener = New-Object System.Net.HttpListener
            $testListener.Prefixes.Add("http://127.0.0.1:$port/")
            $testListener.Start()
            $listener = $testListener
            $script:ServerPort = $port
            break
        } catch {
            if ($testListener) { 
                try { $testListener.Close() } catch { }
            }
        }
    }
    
    if (-not $listener) {
        Write-Host ''
        Write-Host '    Could not start local server on any port.' -ForegroundColor Red
        Write-Host '    Try closing other apps using ports 8080-8085 or 9090-9091,' -ForegroundColor Yellow
        Write-Host '    or specify a custom port: .\HardTarget.ps1 -Port 12345' -ForegroundColor Yellow
        Read-Host '    Press Enter to exit'
        return
    }
    
    $script:ServerStartTime = Get-Date
    $script:ShutdownRequested = $false
    
    # Generate auth token to prevent cross-site request forgery on mutating endpoints
    # SECURITY (v0.40): Use hex encoding for fixed 32-char token length. Base64 with
    # character stripping produced variable-length tokens (26-32 chars), leaking token
    # length via timing side-channel in Compare-TokenConstantTime. Hex is always 2N chars.
    # Also wrap CSPRNG in try/finally to ensure Dispose() on exception.
    $tokenBytes = [byte[]]::new(16)  # 16 bytes = 32 hex chars = 128 bits entropy
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()  # L-2 FIX (v0.45): Use non-deprecated API
    try {
        $rng.GetBytes($tokenBytes)
    } finally {
        $rng.Dispose()
    }
    $script:AuthToken = [BitConverter]::ToString($tokenBytes) -replace '-', ''
    # Auth token is NOT embedded in HTML - user must paste from console
    # This prevents token leakage via process args or HTML source scraping
    
    
    # Detect monitor status
    $monInstalled = $false
    $monState = 'not installed'
    try {
        $task = Get-ScheduledTask -TaskName 'HardTarget Monitor' -ErrorAction Stop
        $monInstalled = $true
        $monState = $task.State.ToString()
    } catch {}
    $monDir = Join-Path $script:TrustedProgramData 'HardTarget'
    
    # == Console status panel ==
    $modeLabel = if ($script:IsReadOnly) { 'AUDIT (read-only)' } else { 'EXPERT (fixes enabled)' }
    $modeColor = if ($script:IsReadOnly) { 'Cyan' } else { 'Yellow' }
    Write-Host ''
    Write-Host '    ==========================================================' -ForegroundColor DarkCyan
    Write-Host '     HardTarget SERVER RUNNING' -ForegroundColor Cyan
    Write-Host '    ==========================================================' -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host "    Mode:          " -NoNewline -ForegroundColor DarkGray
    Write-Host $modeLabel -ForegroundColor $modeColor
    Write-Host "    Dashboard:     " -NoNewline -ForegroundColor DarkGray
    Write-Host "http://127.0.0.1:$script:ServerPort" -ForegroundColor Cyan
    Write-Host "    Server:        " -NoNewline -ForegroundColor DarkGray
    if ($script:IsReadOnly) {
        Write-Host "ACTIVE" -NoNewline -ForegroundColor Green
        Write-Host " - read-only dashboard (no fixes)" -ForegroundColor DarkGray
    } else {
        Write-Host "ACTIVE" -NoNewline -ForegroundColor Green
        Write-Host " - listening for fix commands" -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '    Files:' -ForegroundColor DarkGray
    Write-Host "      Scan JSON:   $JsonPath" -ForegroundColor DarkGray
    Write-Host "      Output dir:  $($script:UserOutputDir)" -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '    Drift Monitor: ' -NoNewline -ForegroundColor DarkGray
    if ($monInstalled) {
        $stateColor = if ($monState -eq 'Ready') { 'Green' } else { 'Yellow' }
        Write-Host $monState.ToUpper() -ForegroundColor $stateColor
        Write-Host "      Data dir:    $monDir" -ForegroundColor DarkGray
        Write-Host '      Manage from the dashboard or run with -Uninstall' -ForegroundColor DarkGray
    } else {
        Write-Host 'NOT INSTALLED' -ForegroundColor Yellow
        Write-Host '      Enable from the dashboard (monitor bar) or run with -Install' -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '    ----------------------------------------------------------' -ForegroundColor DarkGray
    Write-Host '    Press Enter here to stop the server and exit.' -ForegroundColor White
    Write-Host '    Or click STOP SERVER in the dashboard.' -ForegroundColor DarkGray
    Write-Host '    ----------------------------------------------------------' -ForegroundColor DarkGray
    # SECURITY (v0.39): Explicitly inform operator about HTTP threat model
    Write-Host '    SECURITY: Dashboard uses plain HTTP. Any local process with' -ForegroundColor DarkYellow
    Write-Host '    network visibility can read security posture data. Fixes still' -ForegroundColor DarkYellow
    Write-Host '    require console approval.' -ForegroundColor DarkYellow
    Write-Host ''
    
    # SECURITY (v0.43): Print auth token BEFORE opening browser so operator can see it
    # immediately. Previously the browser opened first, showing the auth prompt before
    # the token was visible in the console - forcing an alt-tab back.
    # M-2 FIX (v0.45): Detect transcript logging and warn more prominently about token persistence.
    # SECURITY (v0.74): Token no longer passed via URL fragment. The v0.71 fragment approach
    # (#token) was invisible to HTTP servers and proxies, but Start-Process passes the full
    # URL (including fragment) as a command-line argument to the browser executable. Any
    # standard user can query Win32_Process via WMI to read command-line arguments of all
    # running processes, capturing the token from the transient browser launch process.
    # Token is now ONLY delivered via the ACL-protected auth_token.txt file. The dashboard
    # shows a manual auth prompt where the operator pastes the token from the console or
    # reads it from the file. This eliminates all process-list, history, and proxy leakage.
    $tokenFilePath = Join-Path (Join-Path $script:TrustedProgramData 'HardTarget') 'auth_token.txt'
    try {
        Write-SafeFile -Path $tokenFilePath -Content $script:AuthToken
        $script:TokenFilePath = $tokenFilePath
        Write-Host "    Token file: $tokenFilePath" -ForegroundColor DarkGray
    } catch { }
    Write-Host "    AUTH TOKEN: $($script:AuthToken)" -ForegroundColor Cyan
    Write-Host "    Paste this into the dashboard when prompted." -ForegroundColor DarkGray
    Write-Host ''
    
    # SECURITY (v0.81/v0.82): Do NOT call Start-Process on a URL directly from
    # the elevated context. ShellExecute reads HKCU protocol handlers; a malicious
    # handler would inherit the admin token. Instead, launch via explorer.exe which
    # always runs at medium integrity (non-elevated), so the browser process it
    # spawns is also non-elevated. The admin token is never passed to the handler.
    Start-Sleep -Milliseconds 500
    Write-Host ''
    Write-Host "    Dashboard: http://127.0.0.1:$($script:ServerPort)/" -ForegroundColor Cyan
    try {
        $explorerPath = Join-Path $script:TrustedSystemRoot 'explorer.exe'
        Start-Process -FilePath $explorerPath -ArgumentList "http://127.0.0.1:$($script:ServerPort)/"
    } catch {
        Write-Host '    Could not auto-open browser. Open the URL above manually.' -ForegroundColor DarkGray
    }
    Write-Host ''
    
    # Security headers helper - blocks cross-origin reads and common attacks
    function Set-SecurityHeaders {
        param($Response)
        $Response.Headers.Add('Cross-Origin-Resource-Policy', 'same-origin')
        $Response.Headers.Add('Cross-Origin-Opener-Policy', 'same-origin')
        $Response.Headers.Add('X-Frame-Options', 'DENY')
        $Response.Headers.Add('X-Content-Type-Options', 'nosniff')
        $Response.Headers.Add('Referrer-Policy', 'no-referrer')
        $Response.Headers.Add('Cache-Control', 'no-store, no-cache, must-revalidate')
        # CSP: inline scripts/styles needed (single-file architecture with onclick handlers).
        # Nonce-based CSP is not viable here because browsers that see a nonce ignore
        # 'unsafe-inline' entirely, which breaks all onclick/onkeydown event handlers.
        # The localhost-only binding + auth token mitigate the XSS risk that CSP would cover.
        $Response.Headers.Add('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'none'")
    }
    
    # Helper to send JSON response
    function Send-JsonResponse {
        param($Response, $Data, [int]$StatusCode = 200)
        try {
            Set-SecurityHeaders $Response
            $Response.StatusCode = $StatusCode
            # M-6 FIX (v0.45): Increased from depth 5 to 10 for consistency with Get-ScanJson.
            # v0.69: Pre-validate structure. Regex removed (same rationale as Get-ScanJson).
            if (-not (Test-ObjectDepth -Obj $Data -MaxDepth 10)) {
                $json = '{"success":false,"message":"Response data exceeds serialization depth"}'
            } else {
                $json = $Data | ConvertTo-Json -Compress -Depth 10
                if (-not $json) { $json = '{"success":false,"message":"Empty response"}' }
            }
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
            $Response.ContentType = 'application/json; charset=utf-8'
            $Response.ContentLength64 = $buffer.Length
            $Response.OutputStream.Write($buffer, 0, $buffer.Length)
        } catch {
            $errJson = '{"success":false,"message":"Serialization error"}'
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($errJson)
            $Response.StatusCode = 500
            $Response.ContentType = 'application/json; charset=utf-8'
            $Response.ContentLength64 = $buffer.Length
            $Response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
    }
    
    $script:LastRequestTime = Get-Date
    
    # Serve requests (check both for HTTP requests and Enter key)
    while ($listener.IsListening -and -not $script:ShutdownRequested) {
        try {
            $contextTask = $listener.GetContextAsync()
            while (-not $contextTask.AsyncWaitHandle.WaitOne(200)) {
                # Check if Enter was pressed in console
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq 'Enter') {
                        $script:ShutdownRequested = $true
                        break
                    }
                }
                # Idle timeout
                $idleMin = ((Get-Date) - $script:LastRequestTime).TotalMinutes
                if ($idleMin -gt $script:IdleTimeoutMinutes) {
                    Write-Host ''
                    Write-Host "    [Idle timeout: no requests for $($script:IdleTimeoutMinutes) min]" -ForegroundColor Yellow
                    $script:ShutdownRequested = $true
                    break
                }
                # Auto-shutdown after all fixes applied
                # M-5 FIX (v0.45): Non-resettable timer. Once all fixes are applied,
                # the server shuts down after 60s regardless of subsequent requests.
                if ($script:AutoShutdownAt -and (Get-Date) -gt $script:AutoShutdownAt) {
                    Write-Host '    [Auto-shutdown: all fixes applied]' -ForegroundColor Green
                    $script:ShutdownRequested = $true
                    break
                }
                if ($script:ShutdownRequested) { break }
            }
            if ($script:ShutdownRequested) { break }
            $context = $contextTask.GetAwaiter().GetResult()
            $request = $context.Request
            $response = $context.Response
            # M-5 FIX (v0.45): Don't update idle timer here. Only authenticated
            # requests should defer the idle timeout. Moved to per-endpoint below.
            
            $urlPath = $request.Url.LocalPath
            
            try {
                Set-SecurityHeaders $response
                
                # Auth token check for mutating endpoints
                $mutatingPaths = @('/fix', '/fix-all', '/restore-point', '/monitor-install', '/monitor-uninstall', '/shutdown')
                $tokenValid = $true
                if ($urlPath -in $mutatingPaths) {
                    # SECURITY (v0.43): Enforce POST method on all mutation endpoints.
                    # Prevents accidental triggering via GET (e.g. prefetch, <img src>, redirects).
                    # Not currently exploitable (token is header-only) but defense-in-depth.
                    if ($request.HttpMethod -ne 'POST') {
                        $tokenValid = $false
                        Send-JsonResponse $response @{ success = $false; message = 'Method not allowed. Use POST.' } -StatusCode 405
                    }
                    # SECURITY (v0.39): Origin + Sec-Fetch-Site check for browser CSRF defense-in-depth.
                    # Browsers always send Sec-Fetch-Site; non-browser tools (curl, PS) don't send either header.
                    # Auth token remains the primary protection; this blocks browser-based cross-origin attacks.
                    if ($tokenValid) {
                        $origin = $request.Headers['Origin']
                        $secFetchSite = $request.Headers['Sec-Fetch-Site']
                        if ($origin) {
                            # Origin header present: must match exactly
                            if ($origin -ne "http://127.0.0.1:$($script:ServerPort)") {
                                $tokenValid = $false
                                Send-JsonResponse $response @{ success = $false; message = 'Cross-origin request blocked.' } -StatusCode 403
                            }
                        } elseif ($secFetchSite -and $secFetchSite -ne 'same-origin') {
                            # Browser request without Origin but with Sec-Fetch-Site not same-origin
                            $tokenValid = $false
                            Send-JsonResponse $response @{ success = $false; message = 'Cross-site request blocked.' } -StatusCode 403
                        }
                    }
                    # Read token from custom header ONLY (no query string - prevents URL leakage to logs/history/referrer)
                    if ($tokenValid) {
                        $reqToken = $request.Headers['X-HT-Auth']
                        if (-not (Compare-TokenConstantTime $reqToken $script:AuthToken)) {
                            $tokenValid = $false
                            Send-JsonResponse $response @{ success = $false; message = 'Invalid or missing auth token.' } -StatusCode 403
                        }
                    }
                    # Rate limiting on fix endpoints
                    if ($tokenValid -and ($urlPath -eq '/fix' -or $urlPath -eq '/fix-all')) {
                        # SECURITY (v0.40): Server-side idle lock. Dashboard lock at 10 min
                        # is client-only and bypassable with a stolen token. Reject fix
                        # requests server-side if no authenticated request in 10+ minutes.
                        # L-1 FIX: Use $LastFixActivityTime instead of $LastRequestTime.
                        # The current request itself updates LastRequestTime (line ~2418),
                        # so the old check always passed. LastFixActivityTime tracks when the
                        # last actual fix/data interaction happened.
                        $lockRef = if ($script:LastFixActivityTime) { $script:LastFixActivityTime } else { $script:ServerStartTime }
                        $idleSinceLastFix = ((Get-Date) - $lockRef).TotalMinutes
                        if ($idleSinceLastFix -gt 10) {
                            $tokenValid = $false
                            Send-JsonResponse $response @{ success = $false; message = 'Session idle for 10+ minutes. Reload the dashboard to unlock.' } -StatusCode 403
                        }
                        $now = Get-Date
                        $script:FixRequestLog = @($script:FixRequestLog | Where-Object { ($now - $_).TotalSeconds -lt 60 })
                        if ($script:FixRequestLog.Count -ge 20) {
                            $tokenValid = $false
                            Send-JsonResponse $response @{ success = $false; message = 'Rate limited. Too many fix requests.' } -StatusCode 429
                        } else {
                            $script:FixRequestLog += $now
                        }
                    }
                }
                
                if (-not $tokenValid) {
                    # Already sent error response above
                    # M-5 FIX (v0.45): Idle timer NOT updated for failed auth
                }
                # Read-only mode: block all fix/mutation endpoints (audit dashboard only)
                elseif ($script:IsReadOnly -and $urlPath -in @('/fix', '/fix-all', '/restore-point', '/monitor-install', '/monitor-uninstall')) {
                    Send-JsonResponse $response @{ success = $false; message = 'Server is in read-only audit mode. Fix operations are disabled.' } -StatusCode 403
                }
                elseif ($urlPath -eq '/' -or $urlPath -eq '/index.html') {
                    # Serve dashboard HTML without auth token. Token is delivered via the
                    # ACL-protected auth_token.txt file or console paste (v0.74).
                    # v0.71-v0.73 used URL fragment (#token) but this leaked via WMI.
                    $script:LastRequestTime = Get-Date
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($HtmlContent)
                    $response.ContentType = 'text/html; charset=utf-8'
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
                elseif ($urlPath -eq '/fix') {
                    # Block concurrent fix requests (Read-Host blocks the server)
                    $script:LastRequestTime = Get-Date
                    if ($script:ConsolePending) {
                        Send-JsonResponse $response @{ success = $false; message = 'Another fix is awaiting console approval. Complete it first.' } -StatusCode 409
                    } else {
                    $fixId = $request.QueryString['id']
                    if (-not $fixId) {
                        $qs = $request.Url.Query
                        if ($qs -match '[?&]id=([^&]+)') { $fixId = $matches[1] }
                    }
                    
                    # Validate fix ID against known definitions (prevents injection)
                    if (-not $fixId) {
                        Send-JsonResponse $response @{ success = $false; message = 'No fix ID provided' }
                    } elseif ($fixId -notmatch '^[a-z0-9\-]{1,50}$') {
                        Send-JsonResponse $response @{ success = $false; message = 'Invalid fix ID format' } -StatusCode 400
                    } elseif (-not $script:FixDefs.ContainsKey($fixId)) {
                        Send-JsonResponse $response @{ success = $false; message = 'Unknown fix ID' } -StatusCode 400
                    } else {
                        # Apply-Fix will prompt console for approval (Read-Host)
                        # Dashboard shows "Waiting for console approval..." while this blocks
                        $script:ConsolePending = $true
                        try {
                        $result = Apply-Fix -FixId $fixId
                        $cleanResult = @{
                            success       = [bool]$result.success
                            message       = [string]$result.message
                            reboot        = [bool]$result.reboot
                            verified      = $result.verified
                            verifyMessage = [string]$result.verifyMessage
                            verifyState   = [string]$result.verifyState
                        }
                        if ($result.ContainsKey('declined') -and $result.declined) { $cleanResult.declined = $true }
                        # Update check status in memory BEFORE responding (so /data refresh gets current state)
                        if ($result.success -and $result.verifyState -eq 'verified') {
                            foreach ($check in $script:JsonChecks) {
                                if ($check.fixId -eq $fixId -and $check.status -ne 'pass') {
                                    $check.status = 'pass'
                                    $check.detail = "Fixed by HardTarget (verified)"
                                    $check.fixable = $false
                                    break
                                }
                            }
                            $script:AppliedFixes += $fixId
                        }
                        # pending_reboot: registry confirmed but change not active until reboot
                        # Keep current fail/warn status but disable re-apply
                        if ($result.success -and $result.verifyState -eq 'pending_reboot') {
                            foreach ($check in $script:JsonChecks) {
                                if ($check.fixId -eq $fixId) {
                                    $check.detail = "Applied by HardTarget - reboot required to take effect"
                                    $check.fixable = $false
                                    break
                                }
                            }
                        }
                        Send-JsonResponse $response $cleanResult
                        } finally { $script:ConsolePending = $false }
                    }
                    }  # end FixPending else
                }
                elseif ($urlPath -eq '/fix-all') {
                    # Block concurrent fix requests
                    if ($script:ConsolePending) {
                        Send-JsonResponse $response @{ success = $false; message = 'Another fix is awaiting console approval. Complete it first.' } -StatusCode 409
                    } else {
                    $script:ConsolePending = $true
                    try {
                    # Build the batch list first
                    $fixBatch = @()
                    foreach ($check in $script:JsonChecks) {
                        if ($check.fixable -and $check.status -ne 'pass' -and $check.status -ne 'info' -and $check.fixId) {
                            $fixDef = $script:FixDefs[$check.fixId]
                            $hasCaveat = ($fixDef.ContainsKey('Note') -and $fixDef.Note -ne '')
                            if (-not $hasCaveat) {
                                $fixBatch += $check
                            }
                        }
                    }
                    
                    if ($fixBatch.Count -eq 0) {
                        Send-JsonResponse $response @{ success = $true; applied = @(); errors = @(); reboot = $false; count = 0; message = 'Nothing to fix' }
                    } else {
                        # Console batch approval - confirmation code for entire batch
                        Write-Host ''
                        Write-Host '    ==========================================================' -ForegroundColor Yellow
                        Write-Host "     FIX ALL: $($fixBatch.Count) fixes (caveated items skipped)" -ForegroundColor Yellow
                        Write-Host '    ==========================================================' -ForegroundColor Yellow
                        $i = 0
                        foreach ($check in $fixBatch) {
                            $i++
                            $fd = $script:FixDefs[$check.fixId]
                            $rb = if ($fd.Reboot) { ' [REBOOT]' } else { '' }
                            Write-Host "     $($i.ToString().PadLeft(2)). $($fd.Name)$rb" -ForegroundColor White
                        }
                        # SECURITY (v0.39): Use CSPRNG for confirmation codes
                        # SECURITY (v0.40): Wrap in try/finally
                        # L-4 FIX: 6-digit codes (900,000 values)
                        $bcBytes = [byte[]]::new(4)
                        $bcRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()  # L-2 FIX (v0.45): Use non-deprecated API
                        try { $bcRng.GetBytes($bcBytes) } finally { $bcRng.Dispose() }
                        $batchCode = 100000 + ([BitConverter]::ToUInt32($bcBytes, 0) % 900000)
                        Write-Host ''
                        Write-Host "       Confirmation code: " -NoNewline -ForegroundColor White
                        Write-Host "$batchCode" -ForegroundColor Cyan
                        Write-Host ''
                        $batchApproval = Read-Host "    Type $batchCode to apply all $($fixBatch.Count), or N to decline"
                        
                        if ($batchApproval -ne "$batchCode") {
                            Write-Host '    [DECLINED]' -ForegroundColor DarkGray
                            Send-JsonResponse $response @{ success = $false; message = 'Declined by operator.'; declined = $true; applied = @(); errors = @(); count = 0; reboot = $false }
                        } else {
                            $applied = @()
                            $errors = @()
                            $verified = @()
                            $failedVerify = @()
                            $pendingReboot = @()
                            $needReboot = $false
                            
                            foreach ($check in $fixBatch) {
                                Write-Host "    Applying: $($check.fixId)" -ForegroundColor Yellow
                                $r = Apply-Fix -FixId $check.fixId -SkipApproval -BatchMode
                                if ($r.success) {
                                    $applied += $check.fixId
                                    if ($r.reboot) { $needReboot = $true }
                                    if ($r.verifyState -eq 'pending_reboot') { $pendingReboot += $check.fixId }
                                    elseif ($r.verified -eq $true) { $verified += $check.fixId }
                                    elseif ($r.verified -eq $false) { $failedVerify += "$($check.fixId): $($r.verifyMessage)" }
                                } else {
                                    $errors += "$($check.fixId): $($r.message)"
                                }
                            }
                            
                            $verifiedCount = $verified.Count
                            $failedCount = $failedVerify.Count
                            $pendingRebootCount = $pendingReboot.Count
                            $unverifiedCount = $applied.Count - $verifiedCount - $failedCount - $pendingRebootCount
                            
                            Write-Host ''
                            Write-Host "    === FIX ALL DONE ===" -ForegroundColor $(if($failedVerify.Count -gt 0){'Red'}elseif($errors.Count -gt 0){'Yellow'}else{'Green'})
                            Write-Host "    Applied: $($applied.Count)  |  Verified: $verifiedCount  |  Pending Reboot: $pendingRebootCount  |  Unverified: $unverifiedCount  |  Failed: $failedCount  |  Errors: $($errors.Count)" -ForegroundColor White
                            if ($pendingRebootCount -gt 0) {
                                Write-Host "    PENDING REBOOT ($pendingRebootCount changes take effect after restart):" -ForegroundColor Yellow
                                foreach ($pr in $pendingReboot) { Write-Host "      - $pr" -ForegroundColor Yellow }
                            }
                            if ($failedVerify.Count -gt 0) {
                                Write-Host '    FAILED VERIFICATIONS (GPO override or policy conflict):' -ForegroundColor Red
                                foreach ($fv in $failedVerify) { Write-Host "      - $fv" -ForegroundColor Red }
                            }
                            
                            # Update check statuses in memory BEFORE responding (so /data returns fresh state)
                            # ONLY mark verified fixes as pass - failed verifications keep original status
                            foreach ($verifiedFixId in $verified) {
                                foreach ($check in $script:JsonChecks) {
                                    if ($check.fixId -eq $verifiedFixId -and $check.status -ne 'pass') {
                                        $check.status = 'pass'
                                        $check.detail = "Fixed by HardTarget (verified)"
                                        $check.fixable = $false
                                        break
                                    }
                                }
                                $script:AppliedFixes += $verifiedFixId
                            }
                            # Mark pending-reboot fixes: keep fail/warn status, disable re-apply
                            foreach ($prFixId in $pendingReboot) {
                                foreach ($check in $script:JsonChecks) {
                                    if ($check.fixId -eq $prFixId) {
                                        $check.detail = "Applied by HardTarget - reboot required to take effect"
                                        $check.fixable = $false
                                        break
                                    }
                                }
                            }
                            # Mark failed verifications with an explicit status
                            foreach ($fv in $failedVerify) {
                                $fvId = ($fv -split ':')[0].Trim()
                                foreach ($check in $script:JsonChecks) {
                                    if ($check.fixId -eq $fvId) {
                                        $check.detail = "Applied but verification failed (GPO override or policy conflict)"
                                        break
                                    }
                                }
                            }
                            Send-JsonResponse $response @{
                                success = ($errors.Count -eq 0)
                                applied = $applied
                                errors = $errors
                                reboot = $needReboot
                                count = $applied.Count
                                verifiedCount = $verifiedCount
                                pendingRebootCount = $pendingRebootCount
                                failedVerifyCount = $failedCount
                                unverifiedCount = $unverifiedCount
                                failedVerifications = $failedVerify
                                pendingReboots = $pendingReboot
                            }
                            # Check if any fixable checks remain AFTER updating statuses
                            $remainingFixable = $script:JsonChecks | Where-Object {
                                $_.fixable -and $_.status -notin @('pass', 'info') -and $_.fixId
                            }
                            if ($applied.Count -gt 0 -and $remainingFixable.Count -eq 0) {
                                Write-Host '    All available fixes applied. Server will shut down in 60s.' -ForegroundColor Green
                                $script:AutoShutdownAt = (Get-Date).AddSeconds(60)
                            }
                        }
                    }
                    } finally { $script:ConsolePending = $false }
                    }  # end FixPending else
                }
                elseif ($urlPath -eq '/restore-point') {
                    if ($script:ConsolePending) {
                        Send-JsonResponse $response @{ success = $false; message = 'Console is busy with another approval. Complete it first.' } -StatusCode 409
                    } else {
                    $script:ConsolePending = $true
                    try {
                    $rpApproved = Get-ConsoleApproval -Action 'RESTORE POINT REQUEST' -Detail 'Creates a System Restore Point before applying fixes.'
                    if (-not $rpApproved) {
                        Write-Host '       [DECLINED]' -ForegroundColor DarkGray
                        Send-JsonResponse $response @{ success = $false; message = 'Declined by operator.'; declined = $true }
                    } else {
                    try {
                        Enable-ComputerRestore -Drive "$script:TrustedSystemDrive\" -ErrorAction Stop
                        Checkpoint-Computer -Description 'HardTarget pre-fix backup' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
                        $script:RestorePointCreated = $true
                        Write-Host "    [OK] Restore point created." -ForegroundColor Green
                        Send-JsonResponse $response @{ success = $true; message = 'Restore point created' }
                    } catch {
                        $errMsg = $_.Exception.Message
                        # Windows throttles restore points to one per 24h on client SKUs
                        if ($errMsg -match 'throttle|frequency|already.*created') {
                            $script:RestorePointCreated = $true
                            Write-Host "    [OK] Recent restore point already exists." -ForegroundColor Green
                            Send-JsonResponse $response @{ success = $true; message = 'A recent restore point already exists (Windows limits to 1 per 24h)' }
                        } else {
                            Write-Host "    [ERROR] Restore point failed: $errMsg" -ForegroundColor Red
                            Send-JsonResponse $response @{ success = $false; message = 'Restore point failed. Check the PowerShell console for details.' }
                        }
                    }
                    }
                    } finally { $script:ConsolePending = $false }
                    }  # end ConsolePending else
                }
                elseif ($urlPath -eq '/data') {
                    $reqToken = $request.Headers['X-HT-Auth']
                    if (-not (Compare-TokenConstantTime $reqToken $script:AuthToken)) {
                        Send-JsonResponse $response @{ success = $false; message = 'Auth required' } -StatusCode 403
                    } else {
                        # L-1 FIX: Track authenticated activity for fix idle lock
                        $script:LastFixActivityTime = Get-Date
                        # M-5 FIX (v0.45): Only authenticated requests defer idle timeout
                        $script:LastRequestTime = Get-Date
                        $json = Get-ScanJson
                        $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
                        $response.ContentType = 'application/json; charset=utf-8'
                        $response.ContentLength64 = $buffer.Length
                        $response.OutputStream.Write($buffer, 0, $buffer.Length)
                    }
                }
                elseif ($urlPath -eq '/status') {
                    # Heartbeat: unauthenticated response is minimal (alive + uptime + port only)
                    # Full operational data (monitor state) requires auth token
                    $uptime = [math]::Round(((Get-Date) - $script:ServerStartTime).TotalSeconds)
                    $reqToken = $request.Headers['X-HT-Auth']
                    if (Compare-TokenConstantTime $reqToken $script:AuthToken) {
                        # Authenticated: return full status including monitor operational data
                        $mInstalled = $false; $mState = 'not installed'; $mLast = ''; $mNext = ''; $mDrift = 0
                        try {
                            $t = Get-ScheduledTask -TaskName 'HardTarget Monitor' -ErrorAction Stop
                            $mInstalled = $true; $mState = $t.State.ToString()
                            $ti = Get-ScheduledTaskInfo -TaskName 'HardTarget Monitor' -ErrorAction SilentlyContinue
                            if ($ti.LastRunTime -and $ti.LastRunTime -gt [datetime]'2000-01-01') { $mLast = $ti.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss') }
                            if ($ti.NextRunTime -and $ti.NextRunTime -gt [datetime]'2000-01-01') { $mNext = $ti.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss') }
                            $dp = Join-Path $script:TrustedProgramData 'HardTarget\HardTarget_drift.ndjson'
                            if (Test-Path $dp) { $mDrift = (Get-Content $dp | Measure-Object).Count }
                        } catch {}
                        Send-JsonResponse $response @{
                            alive = $true; uptime = $uptime; port = $script:ServerPort
                            monitorInstalled = $mInstalled; monitorState = $mState
                            monitorLastRun = $mLast; monitorNextRun = $mNext; monitorDriftEvents = $mDrift
                        }
                    } else {
                        # SECURITY (v0.40): Unauthenticated /status returns 404 instead of
                        # heartbeat data. Prevents local process reconnaissance (discovering
                        # HardTarget is running, uptime, and port).
                        $response.StatusCode = 404
                        $buffer = [System.Text.Encoding]::UTF8.GetBytes('Not Found')
                        $response.ContentLength64 = $buffer.Length
                        $response.OutputStream.Write($buffer, 0, $buffer.Length)
                    }
                }
                elseif ($urlPath -eq '/monitor-install') {
                    if ($script:ConsolePending) {
                        Send-JsonResponse $response @{ success = $false; message = 'Console is busy with another approval. Complete it first.' } -StatusCode 409
                    } else {
                    $script:ConsolePending = $true
                    try {
                    $mApproved = Get-ConsoleApproval -Action 'MONITOR INSTALL REQUEST' -Detail 'Creates hourly scheduled task running as SYSTEM. Script copied to C:\ProgramData\HardTarget\ (ACL-protected).'
                    if (-not $mApproved) {
                        Write-Host '       [DECLINED]' -ForegroundColor DarkGray
                        Send-JsonResponse $response @{ success = $false; message = 'Declined by operator.'; declined = $true }
                    } else {
                        try {
                            Install-HardTargetMonitor -ScriptFilePath $script:ScriptPath
                            Write-Host '    [OK] Drift monitor installed.' -ForegroundColor Green
                            Send-JsonResponse $response @{ success = $true; message = 'Drift monitor installed. Visible in Add/Remove Programs and Start Menu.' }
                        } catch {
                            Write-Host "    [ERROR] Monitor install: $_" -ForegroundColor Red
                            Send-JsonResponse $response @{ success = $false; message = 'Monitor install failed. Check the PowerShell console for details.' }
                        }
                    }
                    } finally { $script:ConsolePending = $false }
                    }  # end ConsolePending else
                }
                elseif ($urlPath -eq '/monitor-uninstall') {
                    if ($script:ConsolePending) {
                        Send-JsonResponse $response @{ success = $false; message = 'Console is busy with another approval. Complete it first.' } -StatusCode 409
                    } else {
                    $script:ConsolePending = $true
                    try {
                    $muApproved = Get-ConsoleApproval -Action 'MONITOR UNINSTALL REQUEST' -Detail 'Removes scheduled task, Start Menu shortcut, script copy. Drift logs in C:\ProgramData\HardTarget are kept.'
                    if (-not $muApproved) {
                        Write-Host '       [DECLINED]' -ForegroundColor DarkGray
                        Send-JsonResponse $response @{ success = $false; message = 'Declined by operator.'; declined = $true }
                    } else {
                        try {
                            Uninstall-HardTargetMonitor
                            Write-Host '    [OK] Drift monitor removed. Data files kept in C:\ProgramData\HardTarget.' -ForegroundColor Green
                            Send-JsonResponse $response @{ success = $true; message = 'Monitor removed. Data files kept in C:\ProgramData\HardTarget. Run with -Uninstall from console to delete data.' }
                        } catch {
                            Write-Host "    [ERROR] Monitor uninstall: $_" -ForegroundColor Red
                            Send-JsonResponse $response @{ success = $false; message = 'Monitor uninstall failed. Check the PowerShell console for details.' }
                        }
                    }
                    } finally { $script:ConsolePending = $false }
                    }  # end ConsolePending else
                }
                elseif ($urlPath -eq '/shutdown') {
                    # SECURITY (v0.39): Log shutdown source for audit trail.
                    # Shutdown via dashboard only requires auth token (no console approval)
                    # because gating shutdown behind Read-Host would block the server thread.
                    Write-Host "    [Dashboard shutdown requested at $(Get-Date -Format 'HH:mm:ss')]" -ForegroundColor Yellow
                    Send-JsonResponse $response @{ success = $true; message = 'Server shutting down' }
                    $script:ShutdownRequested = $true
                }
                else {
                    $response.StatusCode = 404
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes('Not Found')
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
            }
            catch {
                Write-Host "    [Handler error: $_]" -ForegroundColor Red
                try {
                    $response.StatusCode = 500
                    Send-JsonResponse $response @{ success = $false; message = 'Internal server error' }
                } catch { }
            }
            finally {
                try { $response.Close() } catch { }
            }
        }
        catch [System.Net.HttpListenerException] {
            # Listener stopped
            break
        }
        catch {
            # Log but continue
            Write-Host "    [Server error: $_]" -ForegroundColor DarkGray
        }
    }
    
    try { $listener.Stop() } catch { }
    $script:AuthToken = ''
    # SECURITY (v0.66): Delete token file if it was created (transcript mode)
    if ($script:TokenFilePath -and (Test-Path $script:TokenFilePath)) {
        Remove-Item $script:TokenFilePath -Force -EA SilentlyContinue
        $script:TokenFilePath = $null
    }
    # SECURITY (v0.43): Explicitly notify operator that the token is dead.
    # v0.68: Token file is deleted above. Console scrollback note only relevant
    # if token was displayed via console fallback.
    Write-Host ''
    Write-Host '    Server stopped. Auth token has been invalidated.' -ForegroundColor DarkGray
}

# ============================================================================
#  JSON EXPORT
# ============================================================================
function Get-ScanJson {
    $sections = @(
        @{ id = 'bios'; name = 'BIOS / Firmware'; icon = '[BIOS]' }
        @{ id = 'sleep'; name = 'Sleep States'; icon = '[SLEEP]' }
        @{ id = 'tpm'; name = 'TPM'; icon = '[TPM]' }
        @{ id = 'dma'; name = 'DMA / Virtualization'; icon = '[DMA]' }
        @{ id = 'encryption'; name = 'Encryption'; icon = '[CRYPT]' }
        @{ id = 'memory'; name = 'Memory Residue'; icon = '[MEM]' }
        @{ id = 'access'; name = 'Access Control'; icon = '[ACCESS]' }
        @{ id = 'forensic-surface'; name = 'Data Exposure Surface'; icon = '[TRACE]'; preview = $true }
    )
    
    # Calculate scenario severity
    # NOTE: 'info' checks are excluded - they provide context only and have no
    # remediation path. Including them would permanently inflate scenario exposure
    # for scan-only checks (USB history, Amcache, NTFS $MFT, etc.).
    $scenarioStatus = @{}
    foreach ($scenario in $script:AttackScenarios) {
        $failCount = 0
        $warnCount = 0
        $condPassCount = 0
        foreach ($check in $script:JsonChecks) {
            if ($check.scenarios -contains $scenario.id -and $check.status -ne 'info') {
                switch ($check.status) {
                    'fail' { $failCount++ }
                    'warn' { $warnCount++ }
                    'conditional-pass' { $condPassCount++ }
                }
            }
        }
        $sStatus = 'protected'
        if ($condPassCount -gt 0) { $sStatus = 'conditional-pass' }
        if ($warnCount -gt 0) { $sStatus = 'warn' }
        if ($failCount -gt 0) { $sStatus = 'exposed' }
        
        $scenarioStatus[$scenario.id] = @{
            fails = $failCount
            warns = $warnCount
            condPasses = $condPassCount
            status = $sStatus
        }
    }
    
    # No external DMA ports = entire DMA attack vector is conditional
    if (-not $script:HasDMAPorts -and $scenarioStatus.ContainsKey('dma-attack')) {
        $scenarioStatus['dma-attack'].status = 'conditional-pass'
    }
    
    # Recalculate summary from CURRENT check states (not stale scan-time counters)
    # This ensures the posture updates correctly after fixes are applied
    $livePass = 0; $liveCondPass = 0; $liveWarn = 0; $liveFail = 0
    foreach ($check in $script:JsonChecks) {
        if ($check.section -ne 'forensic-surface') {
            switch ($check.status) {
                'pass' { $livePass++ }
                'conditional-pass' { $liveCondPass++ }
                'warn' { $liveWarn++ }
                'fail' { $liveFail++ }
            }
        }
    }
    
    $overall = 'HARDENED'
    $overallClass = 'protected'
    if ($liveCondPass -gt 0) { $overall = 'CONDITIONAL PASS'; $overallClass = 'conditional-pass' }
    if ($liveWarn -gt 0) { $overall = 'WARN'; $overallClass = 'warn' }
    if ($liveFail -gt 0) { $overall = 'EXPOSED'; $overallClass = 'exposed' }
    
    # Build scenario context notes
    $scenarioContext = @{}
    if (-not $script:HasDMAPorts) {
        $scenarioContext['dma-attack'] = 'No DMA-capable external ports (Thunderbolt, FireWire) were detected on this system. The physical DMA attack vector does not apply to your hardware. The software protections below still provide defense-in-depth against internal/PCIe-based threats.'
    }
    
    # Detect monitor status
    $monitorStatus = @{ installed = $false; state = 'not installed'; lastRun = ''; nextRun = ''; driftEvents = 0 }
    try {
        $task = Get-ScheduledTask -TaskName 'HardTarget Monitor' -ErrorAction Stop
        $monitorStatus.installed = $true
        $monitorStatus.state = $task.State.ToString()
        $taskInfo = Get-ScheduledTaskInfo -TaskName 'HardTarget Monitor' -ErrorAction SilentlyContinue
        if ($taskInfo.LastRunTime -and $taskInfo.LastRunTime -gt [datetime]'2000-01-01') {
            $monitorStatus.lastRun = $taskInfo.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        if ($taskInfo.NextRunTime -and $taskInfo.NextRunTime -gt [datetime]'2000-01-01') {
            $monitorStatus.nextRun = $taskInfo.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        $driftPath = Join-Path $script:TrustedProgramData 'HardTarget\HardTarget_drift.ndjson'
        if (Test-Path $driftPath) {
            $monitorStatus.driftEvents = (Get-Content $driftPath | Measure-Object).Count
        }
    } catch {}
    
    $data = @{
        schemaVersion = 1  # v0.60: Versioned schema for fleet-scale reporting compatibility.
        version = '0.71'
        generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        # SECURITY (v0.39): Sanitize computer name before including in JSON.
        # Computer names are controlled by local admins and can contain
        # characters that would be interpreted as HTML when rendered via innerHTML.
        computer = (Sanitize-HtmlString $env:COMPUTERNAME)
        machine = $script:MachineInfo
        hasDmaPorts = [bool]$script:HasDMAPorts
        summary = @{
            overall = $overall
            overallClass = $overallClass
            pass = $livePass
            condPass = $liveCondPass
            warn = $liveWarn
            fail = $liveFail
        }
        sections = $sections
        # SECURITY (v0.40): Output-side sanitization catch-all. All check title and detail
        # fields are sanitized before serialization, regardless of whether input-side
        # sanitization was applied. This prevents any future check from introducing XSS
        # if a developer forgets to sanitize a new WMI/PnP/external string at the source.
        checks = $script:JsonChecks | ForEach-Object {
            $c = $_
            @{
                section    = $c.section
                id         = $c.id
                status     = $c.status
                title      = Sanitize-HtmlString $c.title
                detail     = Sanitize-HtmlString $c.detail
                fixId      = $c.fixId
                fixable    = $c.fixable
                scenarios  = $c.scenarios
                frameworks = $c.frameworks
            }
        }
        # SECURITY (v0.43): Sanitize scenario fields rendered via innerHTML in dashboard.
        # Same principle as the check title/detail catch-all (v0.40) and fix metadata (v0.43).
        scenarios = $script:AttackScenarios | ForEach-Object {
            $s = $_
            $status = $scenarioStatus[$s.id]
            $ctx = ''
            if ($scenarioContext.ContainsKey($s.id)) { $ctx = Sanitize-HtmlString $scenarioContext[$s.id] }
            @{
                id = $s.id
                name = Sanitize-HtmlString $s.name
                severity = $s.severity
                icon = $s.icon
                preview = $(if ($s.ContainsKey('preview')) { $s.preview } else { $false })
                description = Sanitize-HtmlString $s.description
                mitigation = Sanitize-HtmlString $s.mitigation
                contributing = $s.contributing
                status = $status.status
                failCount = $status.fails
                warnCount = $status.warns
                condPassCount = $status.condPasses
                context = $ctx
            }
        }
        fixes = @{}
        monitor = $monitorStatus
    }

    # Build compliance framework summary: per-framework control coverage
    $frameworkSummary = @{}
    foreach ($fwName in @('cis', 'nist', 'iso', 'cmmc')) {
        $controlMap = @{}  # control ID -> best status across all checks
        foreach ($check in $script:JsonChecks) {
            if ($check.frameworks -and $check.frameworks.ContainsKey($fwName)) {
                foreach ($ctrl in $check.frameworks[$fwName]) {
                    if (-not $ctrl) { continue }
                    # Keep the worst status per control (fail > warn > conditional-pass > pass)
                    $existing = if ($controlMap.ContainsKey($ctrl)) { $controlMap[$ctrl] } else { $null }
                    $statusRank = @{ 'fail' = 4; 'warn' = 3; 'conditional-pass' = 2; 'pass' = 1; 'info' = 0 }
                    $newRank = if ($statusRank.ContainsKey($check.status)) { $statusRank[$check.status] } else { 0 }
                    $oldRank = if ($existing -and $statusRank.ContainsKey($existing)) { $statusRank[$existing] } else { -1 }
                    if ($newRank -gt $oldRank) { $controlMap[$ctrl] = $check.status }
                }
            }
        }
        $ctrlPass = @($controlMap.Values | Where-Object { $_ -eq 'pass' }).Count
        $ctrlCondPass = @($controlMap.Values | Where-Object { $_ -eq 'conditional-pass' }).Count
        $ctrlWarn = @($controlMap.Values | Where-Object { $_ -eq 'warn' }).Count
        $ctrlFail = @($controlMap.Values | Where-Object { $_ -eq 'fail' }).Count
        $ctrlInfo = @($controlMap.Values | Where-Object { $_ -eq 'info' }).Count
        $frameworkSummary[$fwName] = @{
            controlsAssessed = $controlMap.Count
            pass = $ctrlPass
            condPass = $ctrlCondPass
            warn = $ctrlWarn
            fail = $ctrlFail
            info = $ctrlInfo
            controls = $controlMap
        }
    }
    $data.compliance = $frameworkSummary

    foreach ($fk in $script:FixDefs.Keys) {
        $fd = $script:FixDefs[$fk]
        $rbVal = $false; if ($fd.ContainsKey('Reboot')) { $rbVal = $fd.Reboot }
        # SECURITY (v0.43): Sanitize fix metadata for dashboard innerHTML rendering.
        # Fix Name/Note/Impact are hardcoded today but must be covered by the same
        # output-side catch-all applied to check title/detail (v0.40). Prevents XSS
        # if a future version constructs fix descriptions from dynamic data sources.
        $clean = @{ Name = (Sanitize-HtmlString $fd.Name); Type = $fd.Type; Reboot = $rbVal }
        if ($fd.ContainsKey('Note') -and $fd.Note) { $clean.Note = Sanitize-HtmlString $fd.Note }
        if ($fd.ContainsKey('Impact') -and $fd.Impact) { $clean.Impact = Sanitize-HtmlString $fd.Impact }
        $data.fixes[$fk] = $clean
    }

    # SECURITY (v0.68): Pre-validate object depth before serialization. This is the
    # primary truncation defense. Walks the data structure and verifies no branch exceeds
    # ConvertTo-Json's -Depth limit. Immune to user-controlled strings, folder names,
    # SSIDs, or any future code changes that might serialize bare variables.
    if (-not (Test-ObjectDepth -Obj $data -MaxDepth 10)) {
        $truncMsg = "HardTarget JSON TRUNCATION: data structure exceeds depth 10. Posture data would be incorrect."
        if ($script:IsMonitorMode) {
            $truncLogPath = Join-Path $script:MonitorDataDir 'HardTarget_monitor.ndjson'
            try { Write-SafeFile -Path $truncLogPath -Content (@{ timestamp = (Get-Date -Format 'o'); type = 'json_truncation'; error = $truncMsg; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress) -Append } catch {}
        } else {
            Write-Host '    [ERROR] JSON data structure exceeds serialization depth limit.' -ForegroundColor Red
            Write-Host '    Dashboard data would be incorrect. Increase -Depth in Get-ScanJson.' -ForegroundColor Red
            throw 'JSON serialization truncated: scan data integrity compromised.'
        }
    }

    $jsonOutput = ($data | ConvertTo-Json -Depth 10)
    # v0.69: Post-serialization regex removed. Test-ObjectDepth (above) is the sole
    # truncation defense. The regex was fundamentally unable to distinguish real truncation
    # from legitimate strings matching the type name pattern and added false positive risk
    # with no value beyond what the structural validator already provides.
    return $jsonOutput
}

# ============================================================================
#  SUMMARY
# ============================================================================
function Write-Summary {
    Write-Host ''
    Write-Host '  ==========================================================' -ForegroundColor DarkGray
    Write-Host ''
    
    $overall = 'HARDENED'
    $color = 'Green'
    if ($script:TotalCondPass -gt 0) { $overall = 'CONDITIONAL PASS'; $color = 'Cyan' }
    if ($script:TotalWarn -gt 0) { $overall = 'WARN'; $color = 'Yellow' }
    if ($script:TotalFail -gt 0) { $overall = 'EXPOSED'; $color = 'Red' }
    
    Write-Host '    POSTURE: ' -NoNewline
    Write-Host $overall -ForegroundColor $color
    Write-Host ''
    Write-Host "    PASS: $($script:TotalPass)  COND: $($script:TotalCondPass)  WARN: $($script:TotalWarn)  FAIL: $($script:TotalFail)" -ForegroundColor DarkGray
    Write-Host ''
}

# ============================================================================
#  HTML DASHBOARD
# ============================================================================
function Get-DashboardHtml {
    # NOTE: scan data is NOT embedded in HTML - fetched via /data after auth
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HardTarget Security Dashboard</title>
<style>
:root {
  --bg: #080c18;
  --card: #0d1424;
  --border: rgba(255,255,255,0.06);
  --text: #e2e8f0;
  --dim: #64748b;
  --pass: #22c55e;
  --cond-pass: #2dd4bf;
  --warn: #f59e0b;
  --fail: #ef4444;
  --info: #94a3b8;
  --accent: #38bdf8;
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Segoe UI', system-ui, sans-serif;
  line-height: 1.6;
  padding: 40px 20px;
}
.container { max-width: 920px; margin: 0 auto; }
.header { margin-bottom: 36px; }
.header h1 { font-size: 32px; font-weight: 300; letter-spacing: 6px; text-transform: uppercase; }
.header h1 span { color: var(--accent); }
.acronym { color: var(--dim); font-size: 11px; letter-spacing: 2px; text-transform: uppercase; margin-top: 2px; }
.acronym b { color: var(--accent); font-weight: 700; }
.machine-info { color: var(--dim); font-size: 12px; letter-spacing: 0.5px; margin-top: 6px; }
.machine-info .edition-badge {
  display: inline-block; padding: 1px 7px; border-radius: 3px;
  font-size: 10px; font-weight: 700; letter-spacing: 0.5px; margin-left: 4px; vertical-align: middle;
}
.edition-badge.enterprise, .edition-badge.education { background: rgba(34,197,94,0.15); color: var(--pass); }
.edition-badge.pro { background: rgba(56,189,248,0.15); color: var(--accent); }
.edition-badge.home { background: rgba(245,158,11,0.15); color: var(--warn); }
.summary-cards { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 20px; }
.summary-card {
  padding: 20px 16px; background: var(--card); border: 1px solid var(--border);
  border-radius: 10px; text-align: center;
}
.summary-card .value { font-size: 28px; font-weight: 700; }
.summary-card .label { font-size: 10px; color: var(--dim); text-transform: uppercase; letter-spacing: 1.5px; margin-top: 4px; }
.summary-card.pass .value { color: var(--pass); }
.summary-card.protected .value { color: var(--pass); }
.summary-card.conditional-pass .value { color: var(--cond-pass); }
.summary-card.warn .value { color: var(--warn); }
.summary-card.fail .value { color: var(--fail); }
.summary-card.exposed .value { color: var(--fail); }
.summary-card.posture .value { font-size: 20px; font-weight: 800; }
.status-key { display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 16px; padding: 8px 12px; background: var(--surface); border-radius: 6px; border: 1px solid var(--border); }
.monitor-bar { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; padding: 10px 14px; background: var(--surface); border-radius: 6px; border: 1px solid var(--border); font-size: 12px; color: var(--dim); }
.monitor-bar .monitor-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
.monitor-bar .monitor-dot.active { background: var(--pass); box-shadow: 0 0 6px var(--pass); animation: pulse 2s infinite; }
.monitor-bar .monitor-dot.inactive { background: #475569; }
.monitor-bar .monitor-label { font-weight: 600; color: var(--text); white-space: nowrap; }
.monitor-bar .monitor-detail { color: var(--dim); flex: 1; }
.monitor-bar .mon-btn { padding: 4px 10px; border-radius: 4px; font-size: 10px; font-weight: 700; letter-spacing: 0.5px; cursor: pointer; white-space: nowrap; }
.monitor-bar .mon-install { background: rgba(34,197,94,0.12); border: 1px solid rgba(34,197,94,0.4); color: #22c55e; }
.monitor-bar .mon-install:hover { background: rgba(34,197,94,0.25); }
.monitor-bar .mon-uninstall { background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.4); color: #ef4444; }
.monitor-bar .mon-uninstall:hover { background: rgba(239,68,68,0.25); }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
.key-item { display: flex; align-items: center; gap: 6px; font-size: 11px; color: var(--dim); letter-spacing: 0.5px; }
.key-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.key-dot.pass { background: var(--pass); }
.key-dot.conditional-pass { background: var(--cond-pass); }
.key-dot.warn { background: var(--warn); }
.key-dot.fail { background: var(--fail); }
.key-dot.info { background: var(--info); }
.fix-all-bar {
  display: flex; align-items: center; gap: 14px;
  margin-bottom: 36px; padding: 14px 18px;
  background: var(--card); border: 1px solid var(--border); border-radius: 10px;
}
.fix-all-bar .fix-all-info { flex: 1; font-size: 12px; color: var(--dim); }
.fix-all-bar .fix-all-info strong { color: var(--text); }
.expert-warning {
  display: none; margin: 16px 0; padding: 14px 18px; border-radius: 8px;
  background: rgba(245,158,11,0.06); border: 1px solid rgba(245,158,11,0.25);
  font-size: 11px; line-height: 1.6; color: #fbbf24;
}
.expert-warning strong { color: #fbbf24; font-weight: 700; }
.expert-warning .warn-icon { font-size: 16px; margin-right: 8px; vertical-align: middle; }
.console-hint {
  display: none; margin: 10px 0 6px 0; padding: 8px 14px; border-radius: 6px;
  background: rgba(56,189,248,0.06); border: 1px solid rgba(56,189,248,0.2);
  font-size: 11px; color: #7dd3fc;
}
.console-hint .hint-icon { margin-right: 6px; }
.fix-all-btn {
  padding: 8px 22px; border-radius: 6px;
  border: 1px solid rgba(250,204,21,0.4); background: rgba(250,204,21,0.1);
  color: #facc15; font-size: 12px; font-weight: 700; letter-spacing: 0.5px;
  cursor: pointer; transition: all 0.15s; white-space: nowrap;
}
.fix-all-btn:hover { background: rgba(250,204,21,0.2); border-color: #facc15; }
.fix-all-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.fix-all-btn.done { border-color: var(--pass); color: var(--pass); background: rgba(34,197,94,0.1); }
.fix-all-result { font-size: 11px; color: var(--pass); display: none; }
.fix-all-result.show { display: block; }
.section-heading { font-size: 15px; font-weight: 600; margin-bottom: 14px; color: var(--dim); letter-spacing: 0.5px; }
.scenarios { display: grid; gap: 12px; margin-bottom: 40px; }
.scenario {
  background: var(--card); border: 1px solid var(--border); border-radius: 10px;
  padding: 18px 20px; cursor: pointer; transition: all 0.15s; border-left: 3px solid var(--border);
}
.scenario:hover { border-color: rgba(255,255,255,0.1); background: #0f1830; }
.scenario.exposed { border-left-color: var(--fail); }
.scenario.warn { border-left-color: var(--warn); }
.scenario.conditional-pass { border-left-color: var(--cond-pass); }
.scenario.protected { border-left-color: var(--pass); }
.scenario-header { display: flex; align-items: center; gap: 12px; }
.scenario-icon { font-size: 22px; width: 32px; text-align: center; }
.scenario-title { font-size: 15px; font-weight: 600; flex: 1; }
.scenario-badge {
  padding: 3px 10px; border-radius: 4px; font-size: 10px;
  font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px;
}
.scenario-badge.exposed { background: rgba(239,68,68,0.12); color: var(--fail); }
.scenario-badge.warn { background: rgba(245,158,11,0.12); color: var(--warn); }
.scenario-badge.conditional-pass { background: rgba(45,212,191,0.12); color: var(--cond-pass); }
.scenario-badge.protected { background: rgba(34,197,94,0.12); color: var(--pass); }
.scenario.preview { border-left-color: #475569; border-style: dashed; opacity: 0.85; }
.preview-badge { display:inline-block; padding:2px 8px; border-radius:3px; font-size:9px; font-weight:700; letter-spacing:1px; text-transform:uppercase; background:rgba(56,189,248,0.08); color:#38bdf8; border:1px dashed rgba(56,189,248,0.4); margin-left:8px; vertical-align:middle; }
.section.preview { opacity: 0.85; }
.section.preview .section-title::after { content:'IN DEVELOPMENT'; display:inline-block; margin-left:10px; padding:2px 8px; border-radius:3px; font-size:9px; font-weight:700; letter-spacing:1px; background:rgba(100,116,139,0.2); color:#94a3b8; border:1px dashed #475569; vertical-align:middle; }
.check-item.coming-soon { opacity: 0.7; border-left: 2px solid rgba(56,189,248,0.3); }
.check-item.coming-soon .check-dot { background: #0ea5e9; box-shadow: 0 0 4px rgba(14,165,233,0.4); }
.coming-soon-label { display:inline-block; padding:2px 8px; border-radius:3px; font-size:9px; font-weight:700; letter-spacing:1px; text-transform:uppercase; background:rgba(56,189,248,0.12); color:#38bdf8; border:1px solid rgba(56,189,248,0.25); margin-left:8px; }
.scenario-desc { color: var(--dim); font-size: 12px; margin-top: 8px; padding-left: 44px; }
.scenario-context {
  margin-top: 10px; padding: 10px 14px 10px 44px; font-size: 11px; line-height: 1.55;
}
.scenario-context .ctx-box {
  background: rgba(56,189,248,0.05); border: 1px solid rgba(56,189,248,0.15);
  border-radius: 8px; padding: 10px 14px; color: #7dd3fc;
}
.scenario-context .ctx-icon { margin-right: 6px; }
.scenario-details { display: none; margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--border); }
.scenario.open .scenario-details { display: block; }
.scenario-expand { font-size: 10px; color: #475569; transition: transform 0.2s; margin-left: 8px; }
.scenario.open .scenario-expand { transform: rotate(90deg); color: var(--accent); }
.mitigation {
  background: rgba(34,197,94,0.04); border: 1px solid rgba(34,197,94,0.15);
  border-radius: 8px; padding: 12px 14px; margin-bottom: 14px;
  font-size: 12px; color: #86efac; line-height: 1.5;
}
.contributing-title { font-size: 11px; color: var(--dim); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }
.check-item { background: rgba(0,0,0,0.25); border-radius: 6px; margin-bottom: 4px; overflow: hidden; }
.check-row { display: flex; align-items: center; gap: 10px; padding: 9px 12px; }
.check-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.check-dot.pass { background: var(--pass); }
.check-dot.conditional-pass { background: var(--cond-pass); }
.check-dot.warn { background: var(--warn); }
.check-dot.fail { background: var(--fail); }
.check-dot.info { background: var(--info); }
.check-text { flex: 1; font-size: 12px; }
.check-expand { font-size: 10px; color: #475569; transition: transform 0.15s; flex-shrink: 0; margin-left: 4px; }
.check-item.expanded .check-expand { transform: rotate(90deg); color: var(--accent); }
.check-detail { color: var(--dim); font-size: 11px; margin-top: 2px; display: none; }
.check-item { cursor: pointer; user-select: none; transition: background 0.1s; }
.check-item.expanded { background: rgba(0,0,0,0.35); }
.check-item.expanded .check-detail { display: block; }
.check-item.expanded .info-panel { display: block; }
.check-item.coming-soon .check-detail { display: block; }

.edition-tag {
  display: inline-block; padding: 1px 6px; border-radius: 3px;
  font-size: 9px; font-weight: 700; letter-spacing: 0.5px;
  background: rgba(167,139,250,0.12); color: var(--info); margin-left: 6px; vertical-align: middle;
}
.gp-tag {
  display: inline-block; padding: 1px 6px; border-radius: 3px;
  font-size: 9px; font-weight: 700; letter-spacing: 0.5px;
  background: rgba(245,158,11,0.15); color: var(--warn); margin-left: 6px; vertical-align: middle;
}
.no-ports-tag {
  display: inline-block; padding: 1px 6px; border-radius: 3px;
  font-size: 9px; font-weight: 700; letter-spacing: 0.5px;
  background: rgba(56,189,248,0.12); color: var(--accent); margin-left: 6px; vertical-align: middle;
}
.info-panel {
  display: none; padding: 10px 14px 12px 29px; border-top: 1px solid var(--border);
  font-size: 11px; line-height: 1.65; color: #94a3b8;
}
.info-panel.open { display: block; }
.info-panel strong { color: var(--accent); font-weight: 600; }
.info-panel em { color: var(--warn); font-style: normal; font-weight: 500; }
.fix-btn {
  padding: 5px 14px; border-radius: 4px;
  border: 1px solid rgba(250,204,21,0.3); background: rgba(250,204,21,0.08);
  color: #facc15; font-size: 10px; font-weight: 700; letter-spacing: 0.5px;
  cursor: pointer; transition: all 0.15s; white-space: nowrap;
}
.fix-btn:hover { background: rgba(250,204,21,0.18); border-color: #facc15; }
.fix-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.fix-btn.done { border-color: var(--pass); color: var(--pass); background: rgba(34,197,94,0.08); }
.impact-warning { display: none; margin: 6px 0 2px 20px; padding: 6px 10px; font-size: 11px; line-height: 1.5; color: #fbbf24; background: rgba(251,191,36,0.06); border-left: 2px solid #f59e0b; border-radius: 0 4px 4px 0; }
.check-item.expanded .impact-warning { display: block; }
.section { margin-bottom: 28px; }
.section-title { font-size: 13px; font-weight: 600; color: var(--dim); margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
.footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); text-align: center; color: var(--dim); font-size: 11px; letter-spacing: 0.5px; margin-bottom: 60px; }
.status-bar { position: fixed; bottom: 0; left: 0; right: 0; background: #0a0f1a; border-top: 1px solid var(--border); padding: 8px 20px; display: flex; align-items: center; gap: 16px; font-size: 11px; z-index: 1500; }
.status-bar .conn-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.status-bar .conn-dot.live { background: var(--pass); box-shadow: 0 0 6px var(--pass); }
.status-bar .conn-dot.dead { background: var(--fail); box-shadow: 0 0 6px var(--fail); }
.status-bar .conn-label { color: var(--text); font-weight: 600; white-space: nowrap; }
.status-bar .conn-detail { color: var(--dim); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.status-bar .stop-btn { background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.4); color: #ef4444; padding: 4px 12px; border-radius: 4px; font-size: 10px; font-weight: 700; letter-spacing: 0.5px; cursor: pointer; white-space: nowrap; }
.status-bar .stop-btn:hover { background: rgba(239,68,68,0.25); }
.status-bar .stop-btn.stopped { background: rgba(100,116,139,0.12); border-color: rgba(100,116,139,0.3); color: #64748b; cursor: default; }
.reboot-notice {
  position: fixed; bottom: 20px; right: 20px;
  background: #f59e0b; color: #000; padding: 10px 18px; border-radius: 8px;
  font-weight: 600; font-size: 13px; display: none; box-shadow: 0 4px 20px rgba(0,0,0,0.4);
}
.reboot-notice.show { display: block; }
@media (max-width: 600px) {
  .summary-cards { grid-template-columns: repeat(2, 1fr); }
}
/* Compliance mapping view */
.fw-grid{display:flex;flex-direction:column;gap:12px;margin-bottom:20px}
.fw-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;cursor:pointer;transition:border-color .15s}
.fw-card:hover{border-color:var(--border-light)}
.fw-card.open{border-color:var(--accent)}
.fw-name{font-size:11px;font-weight:700;letter-spacing:1.5px;color:var(--dim);text-transform:uppercase;margin-bottom:8px}
.fw-stats{display:flex;gap:10px;flex-wrap:wrap}
.fw-stat{font-size:18px;font-weight:700}.fw-stat.pass{color:var(--pass)}.fw-stat.fail{color:var(--fail)}.fw-stat.warn{color:var(--warn)}.fw-stat.cp{color:var(--cond-pass)}
.fw-stat-label{font-size:9px;color:var(--dimmer);text-transform:uppercase;letter-spacing:0.5px}
.fw-total{font-size:11px;color:var(--dim);margin-top:6px}
.fw-controls{display:none;margin-top:16px;border-top:1px solid var(--border);padding-top:12px}
.fw-card.open .fw-controls{display:block}
.ctrl-block{margin-bottom:14px;padding-bottom:14px;border-bottom:1px solid rgba(255,255,255,0.03)}
.ctrl-block:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0}
.ctrl-header{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.ctrl-id{font-family:'Cascadia Code','Fira Code',monospace;font-size:11px;color:var(--accent);font-weight:600}
.ctrl-label{font-size:11px;color:var(--dim);font-style:italic}
.ctrl-check{display:flex;align-items:center;gap:8px;padding:3px 0 3px 20px;font-size:12px}
.ctrl-check-title{color:var(--text);flex:1}
.ctrl-fix{display:inline-block;padding:2px 8px;border-radius:3px;background:rgba(56,189,248,0.1);border:1px solid rgba(56,189,248,0.3);color:#38bdf8;font-size:9px;font-weight:700;letter-spacing:0.5px;cursor:pointer;flex-shrink:0}
.ctrl-fix:hover{background:rgba(56,189,248,0.2)}
.fw-bar{height:4px;border-radius:2px;background:rgba(255,255,255,0.05);margin-top:8px;overflow:hidden;display:flex}
.fw-bar-pass{background:var(--pass)}.fw-bar-cp{background:var(--cond-pass)}.fw-bar-warn{background:var(--warn)}.fw-bar-fail{background:var(--fail)}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1><span>HardTarget</span></h1>
    <div class="acronym">Windows Physical Security Scanner</div>
    <div class="machine-info" id="machine-info">Loading...</div>
  </div>

  <div class="summary-cards" id="summary"></div>
  <div class="status-key">
    <span class="key-item"><span class="key-dot pass"></span> Pass</span>
    <span class="key-item"><span class="key-dot conditional-pass"></span> Conditional Pass</span>
    <span class="key-item"><span class="key-dot warn"></span> Warn</span>
    <span class="key-item"><span class="key-dot fail"></span> Fail</span>
    <span class="key-item"><span class="key-dot info"></span> Info</span>
  </div>
  <div class="monitor-bar" id="monitor-bar"></div>
  <div class="expert-warning" id="expert-warning">
    <span class="warn-icon">&#x26A0;&#xFE0F;</span>
    <strong>FIX ENGINE - BETA: NOT RECOMMENDED FOR USE</strong><br>
    The fix engine is published for source code review and transparency only. It has not been
    exhaustively tested across all hardware configurations, Windows editions, or Group Policy
    environments. If you choose to apply fixes despite this recommendation, you do so entirely at
    your own risk and against our stated guidance. All fixes require approval in the PowerShell
    console and are verified after application. Create a System Restore Point before making any changes.
  </div>
  <div class="console-hint" id="console-hint">
    <span class="hint-icon">&#x1F4BB;</span>
    <strong>All fix operations require approval in the PowerShell console window.</strong>
    When you click FIX or FIX ALL, check the PowerShell window to approve or decline each change.
  </div>
  <div class="fix-all-bar" id="fix-all-bar" style="display:none">
    <div class="fix-all-info" id="fix-all-info"></div>
    <button class="fix-all-btn" id="fix-all-btn" onclick="fixAll()">FIX ALL</button>
    <div class="fix-all-result" id="fix-all-result"></div>
  </div>

  <div class="section-heading">ATTACK SURFACE ANALYSIS</div>
  <div class="scenarios" id="scenarios"></div>

  <div class="section-heading">ALL CHECKS</div>
  <div id="checks"></div>

  <div class="section-heading">COMPLIANCE MAPPING</div>
  <div id="compliance"></div>

  <div class="footer">
    HardTarget v0.83  &#x2022; Windows Physical Security Scanner
  </div>
</div>
<div class="reboot-notice" id="reboot">&#x26A0;&#xFE0F; Reboot required for some changes</div>
<div id="restore-status" style="display:none;position:fixed;bottom:50px;left:20px;background:var(--card);border:1px solid var(--border);padding:10px 18px;border-radius:8px;font-size:12px;z-index:999;"></div>
<div class="status-bar" id="status-bar">
  <span class="conn-dot live" id="conn-dot"></span>
  <span class="conn-label" id="conn-label">CONNECTED</span>
  <span class="conn-detail" id="conn-detail">Starting...</span>
  <button class="stop-btn" id="stop-btn" onclick="stopServer()">STOP SERVER</button>
</div>
<div id="fix-modal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);backdrop-filter:blur(6px);z-index:2000;align-items:center;justify-content:center;">
  <div style="background:#0d1424;border:1px solid rgba(245,158,11,0.3);border-radius:12px;padding:32px;max-width:520px;width:90%;box-shadow:0 0 60px rgba(0,0,0,0.5);">
    <div style="font-size:18px;font-weight:700;color:#e2e8f0;margin-bottom:16px;" id="fix-modal-title"></div>
    <div id="fix-modal-desc" style="font-size:13px;color:#94a3b8;line-height:1.7;margin:0 0 12px 0;"></div>
    <div id="fix-modal-impact" style="display:none;margin:0 0 12px 0;padding:8px 12px;font-size:12px;line-height:1.6;color:#fbbf24;background:rgba(251,191,36,0.06);border-left:2px solid #f59e0b;border-radius:0 4px 4px 0;"></div>
    <div id="fix-modal-note" style="display:none;margin:0 0 12px 0;padding:8px 12px;font-size:12px;line-height:1.6;color:#94a3b8;background:rgba(148,163,184,0.06);border-left:2px solid #475569;border-radius:0 4px 4px 0;"></div>
    <div id="fix-modal-restore-info" style="margin:0 0 20px 0;padding:10px 12px;font-size:12px;line-height:1.6;color:#e2e8f0;background:rgba(34,197,94,0.06);border-left:2px solid #22c55e;border-radius:0 4px 4px 0;"></div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;">
      <button id="fix-modal-restore-btn" onclick="fixWithRestore()" style="flex:1;padding:12px 16px;border-radius:6px;border:1px solid rgba(34,197,94,0.5);background:rgba(34,197,94,0.15);color:#22c55e;font-size:11px;font-weight:700;letter-spacing:0.5px;cursor:pointer;min-width:140px;"></button>
      <button onclick="fixSkipRestore()" style="flex:1;padding:12px 16px;border-radius:6px;border:1px solid rgba(245,158,11,0.3);background:rgba(245,158,11,0.06);color:#f59e0b;font-size:11px;font-weight:600;letter-spacing:0.5px;cursor:pointer;min-width:100px;">SKIP RESTORE &amp; APPLY</button>
      <button onclick="hideFixModal()" style="padding:12px 16px;border-radius:6px;border:1px solid rgba(255,255,255,0.1);background:rgba(255,255,255,0.03);color:#64748b;font-size:11px;font-weight:600;letter-spacing:0.5px;cursor:pointer;">GO BACK</button>
    </div>
  </div>
</div>

<script>
var DATA = null;
var AUTH_TOKEN = '';
var READONLY = false;
var needsReboot = false;
var restoreCreated = false;
var pendingAction = null;

// Console prompt popup - shown when any write action needs console approval
function showConsolePrompt(action) {
  var existing = document.getElementById('console-prompt-overlay');
  if (existing) existing.remove();
  var d = document.createElement('div');
  d.id = 'console-prompt-overlay';
  d.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);backdrop-filter:blur(4px);z-index:5000;display:flex;align-items:center;justify-content:center;';
  d.innerHTML = '<div style="background:#0d1424;border:1px solid rgba(56,189,248,0.3);border-radius:12px;padding:32px;max-width:440px;width:90%;text-align:center;box-shadow:0 0 60px rgba(0,0,0,0.5);">'
    + '<div style="font-size:40px;margin-bottom:12px;">&#x1F4BB;</div>'
    + '<div style="font-size:16px;font-weight:700;color:#e2e8f0;margin-bottom:8px;">Check PowerShell Console</div>'
    + '<div style="font-size:12px;color:#94a3b8;margin-bottom:16px;line-height:1.6;">' + (action || 'An action') + ' requires your approval.<br>Switch to the <strong style="color:#7dd3fc;">PowerShell window</strong> and enter the <strong style="color:#7dd3fc;">confirmation code</strong> to approve or type N to decline.</div>'
    + '<div style="padding:10px 16px;border-radius:6px;background:rgba(56,189,248,0.08);border:1px solid rgba(56,189,248,0.2);color:#7dd3fc;font-size:11px;">Waiting for console response...</div>'
    + '</div>';
  document.body.appendChild(d);
}
function hideConsolePrompt() {
  var d = document.getElementById('console-prompt-overlay');
  if (d) d.remove();
}

// Auth: check URL fragment for token (legacy v0.71-v0.73 approach, kept for backward compat).
// v0.74: Token is no longer passed via URL fragment due to WMI process command-line leakage.
// Browser is opened without token; user pastes from console or reads from auth_token.txt.
// Fragment check kept in case user manually navigates with a fragment from an older workflow.
(function() {
  var fragment = window.location.hash ? window.location.hash.substring(1) : '';
  if (fragment && fragment.length >= 16) {
    // Clear fragment from address bar immediately (prevents shoulder-surfing / history leakage)
    try { history.replaceState(null, '', '/'); } catch(e) {}
    AUTH_TOKEN = fragment;
    fetch('/data', {headers:{'X-HT-Auth':AUTH_TOKEN}})
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(json) {
        if (json) { DATA = json; render(); }
        else { AUTH_TOKEN = ''; showManualAuth('Auto-auth failed. Paste token manually.'); }
      })
      .catch(function() { AUTH_TOKEN = ''; showManualAuth('Server unreachable.'); });
    return;
  }
  showManualAuth(null);
})();
function showManualAuth(errMsg) {
  AUTH_TOKEN = '';
  var o = document.createElement('div');
  o.id = 'auth-overlay';
  o.style.cssText = 'position:fixed;inset:0;background:#0f172a;z-index:10000;display:flex;align-items:center;justify-content:center;';
  o.innerHTML = '<div style="text-align:center;max-width:400px;padding:24px;">'
    + '<div style="font-size:36px;margin-bottom:12px;">&#x1F512;</div>'
    + '<div style="font-size:16px;font-weight:600;color:#e2e8f0;margin-bottom:6px;">Console Authentication Required</div>'
    + (READONLY ? '<div style="display:inline-block;padding:3px 10px;border-radius:4px;background:rgba(56,189,248,0.12);border:1px solid rgba(56,189,248,0.3);color:#38bdf8;font-size:10px;font-weight:700;letter-spacing:1px;margin-bottom:10px;">AUDIT MODE &bull; READ-ONLY</div>' : '<div style="display:inline-block;padding:3px 10px;border-radius:4px;background:rgba(250,204,21,0.12);border:1px solid rgba(250,204,21,0.3);color:#facc15;font-size:10px;font-weight:700;letter-spacing:1px;margin-bottom:10px;">EXPERT MODE &bull; FIXES ENABLED</div>')
    + '<div style="font-size:12px;color:#94a3b8;margin-bottom:16px;">Paste the auth token from the PowerShell console.</div>'
    + '<input id="auth-input" type="text" placeholder="Paste token here" spellcheck="false" autocomplete="off" '
    + 'style="width:100%;padding:10px 12px;border-radius:6px;border:1px solid rgba(56,189,248,0.3);background:rgba(15,23,42,0.8);color:#e2e8f0;font-family:monospace;font-size:13px;text-align:center;outline:none;box-sizing:border-box;margin-bottom:10px;" />'
    + '<div id="auth-error" style="font-size:11px;color:#f87171;margin-bottom:10px;display:' + (errMsg ? 'block' : 'none') + ';">' + (errMsg || '') + '</div>'
    + '<button onclick="doAuth()" style="padding:8px 24px;border-radius:6px;border:1px solid rgba(56,189,248,0.4);background:rgba(56,189,248,0.12);color:#38bdf8;font-size:12px;font-weight:700;cursor:pointer;">AUTHENTICATE</button>'
    + '</div>';
  document.body.appendChild(o);
  setTimeout(function() { var i = document.getElementById('auth-input'); if(i)i.focus(); }, 100);
}
document.addEventListener('keydown', function(e) {
  if (e.key === 'Enter' && document.getElementById('auth-overlay')) doAuth();
});
function doAuth() {
  var t = (document.getElementById('auth-input').value || '').trim();
  var err = document.getElementById('auth-error');
  if (!t) { err.textContent = 'Token required.'; err.style.display = 'block'; return; }
  fetch('/data', {headers:{'X-HT-Auth':t}})
    .then(function(r) {
      if (!r.ok) { err.textContent = 'Invalid token. Check the PowerShell console.'; err.style.display = 'block'; return null; }
      return r.json();
    })
    .then(function(json) {
      if (!json) return;
      AUTH_TOKEN = t;
      DATA = json;
      var o = document.getElementById('auth-overlay'); if(o)o.remove();
      render();
    })
    .catch(function() { err.textContent = 'Server unreachable.'; err.style.display = 'block'; });
}

// Refresh dashboard data from server (called after fixes to update status)
function refreshData() {
  if (!AUTH_TOKEN) return;
  fetch('/data', {headers:{'X-HT-Auth':AUTH_TOKEN}})
    .then(function(r) { return r.ok ? r.json() : null; })
    .then(function(json) {
      if (json) { DATA = json; render(); }
    })
    .catch(function() {});
}

// Idle lock - disable fix controls after 10 min of no user interaction
var IDLE_LOCK_MS = 10 * 60 * 1000;
var lastUserAction = Date.now();
var isLocked = false;
document.addEventListener('click', function() { lastUserAction = Date.now(); });
document.addEventListener('keydown', function() { lastUserAction = Date.now(); });
document.addEventListener('mousemove', (function() {
  var last = 0;
  return function() { var n = Date.now(); if (n - last > 1000) { lastUserAction = n; last = n; } };
})());
setInterval(function() {
  if (isLocked || !serverAlive) return;
  var idle = Date.now() - lastUserAction;
  if (idle >= IDLE_LOCK_MS) {
    isLocked = true;
    document.querySelectorAll('.fix-btn, .fix-all-btn, .mon-btn').forEach(function(b) { b.disabled = true; });
    var o = document.createElement('div');
    o.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.88);z-index:9999;display:flex;align-items:center;justify-content:center;';
    o.innerHTML = '<div style="text-align:center;color:#94a3b8;"><div style="font-size:40px;margin-bottom:12px;">&#x1F512;</div><div style="font-size:16px;font-weight:600;color:#e2e8f0;margin-bottom:6px;">Dashboard locked</div><div style="font-size:12px;margin-bottom:16px;max-width:300px;">Idle for 10+ minutes. Fix controls disabled.<br>Scan results are still visible behind this overlay.</div><button onclick="location.reload()" style="padding:8px 20px;border-radius:6px;border:1px solid rgba(56,189,248,0.4);background:rgba(56,189,248,0.08);color:#38bdf8;font-size:11px;font-weight:700;cursor:pointer;">RELOAD TO UNLOCK</button></div>';
    document.body.appendChild(o);
  }
  var rem = Math.ceil((IDLE_LOCK_MS - idle) / 60000);
  if (rem <= 2 && rem > 0 && idle > 0) {
    var det = document.getElementById('conn-detail');
    if (det && det.textContent.indexOf('Lock') < 0) det.textContent += ' \u2022 Auto-lock in ' + rem + 'min';
  }
}, 5000);

var ICONS = {
  'cold-boot':'&#x1F9CA;','dma-attack':'&#x26A1;','evil-maid':'&#x1F575;&#xFE0F;',
  'sleep-wake':'&#x1F634;','forensic':'&#x1F52C;','coercion':'&#x1F6E1;&#xFE0F;',
  'bios':'&#x1F527;','sleep':'&#x26A1;','tpm':'&#x1F510;',
  'dma':'&#x1F50C;','encryption':'&#x1F6E1;&#xFE0F;','memory':'&#x1F9E0;',
  'access':'&#x1F5A5;&#xFE0F;','forensic-surface':'&#x1F50D;'
};

var INFO = {
  'bios-age':'<strong>BIOS/UEFI firmware</strong> is the first code that runs when your computer powers on, before Windows loads. Manufacturers release updates that patch security vulnerabilities. HardTarget queries the <em>NIST National Vulnerability Database (NVD)</em> for known CVEs using a keyword search against your BIOS vendor and version. If CVEs are found, this is a <strong>critical fail</strong> - firmware vulnerabilities can bypass all OS-level protections. If no CVEs are found, firmware over 18 months old gets a conditional pass (it may be the latest available for your hardware). Under 18 months with no CVEs is a full pass.<br><br><strong>NVD lookup limitation:</strong> This is a keyword search, not CPE matching. Results may include false positives. Your system\'s manufacturer string and BIOS version as reported by Windows. On custom-built PCs, these strings are often generic (e.g. "To Be Filled By O.E.M.") and may not match NVD entries accurately. A clean result does not guarantee no vulnerabilities exist - always cross-check your specific motherboard model on the manufacturer\'s support page.',
  'secure-boot':'<strong>Secure Boot</strong> is a UEFI feature that verifies every piece of code loaded during startup (bootloader, drivers, OS kernel) against trusted signatures. Without it, an attacker with brief physical access could replace your bootloader with a malicious "bootkit" that runs <em>before</em> your OS and antivirus, capturing passwords and encryption keys invisibly. Secure Boot is required for Credential Guard and most enterprise compliance standards (NIST 800-171, CMMC).',
  'uefi-vars':'<strong>UEFI variable protection</strong> ensures the Secure Boot key databases cannot be tampered with. UEFI has two modes: <strong>Setup Mode</strong> (keys can be freely written) and <strong>User Mode</strong> (keys are locked by the Platform Key). In Setup Mode, an attacker with physical access can enroll their own Platform Key and signing certificates, then sign malicious bootloaders that Secure Boot will trust. This completely undermines Secure Boot without disabling it - the system still shows "Secure Boot: ON" while booting attacker-controlled code.<br><br>The <strong>Platform Key (PK)</strong> is the root of trust. It is set by the OEM and authorises all changes to the Key Exchange Keys (KEK) and signature databases (db/dbx). If the PK is present and UEFI is in User Mode, the boot chain is properly locked down. A BIOS supervisor password adds further protection by preventing an attacker from entering UEFI setup and resetting to Setup Mode.',
  'bios-password':'<strong>BIOS/UEFI password</strong> prevents unauthorized changes to firmware settings. Without it, an attacker can disable Secure Boot, change boot order to USB, or disable TPM - undermining all other security controls.',
  's0-standby':'<strong>Modern Standby (S0 Low Power Idle)</strong> replaced classic S3 sleep on most laptops since ~2019. Unlike S3 where the CPU is fully off, S0 keeps the CPU in ultra-low-power state that can <em>wake at any time</em> to check email, sync data, and maintain WiFi/Bluetooth connections. Your laptop in a bag could silently connect to hostile WiFi, respond to Bluetooth probes, or run scheduled tasks. Microphone and camera subsystems may also remain powered. Disabling all sleep states (lid-close = shutdown) is the most secure configuration.',
  'cs-enabled':'<strong>Connected Standby</strong> enables network activity during sleep. When CsEnabled=1, Windows maintains network connections during Modern Standby for push notifications, email sync, and tile updates. The network stack is active while the device appears "off". Combined with Modern Standby, remote code execution vulnerabilities could be exploited against a sleeping device.',
  'platform-aoac':'<strong>PlatformAoAcOverride</strong> tells Windows to ignore the firmware\'s "Always On, Always Connected" (AOAC) declaration. Setting it to 0 forces Windows to not use Modern Standby even if hardware supports it. This is the primary mechanism for disabling S0 on machines where firmware doesn\'t offer S3 as alternative.',
  'wake-timers':'<strong>Wake Timers</strong> allow Windows to wake your device from sleep for scheduled tasks, Windows Update, maintenance, and other background activities. Even if Modern Standby is disabled, wake timers can bring the device out of S3 sleep to run tasks unattended. On some Modern Standby systems, firmware-level maintenance tasks can wake the device even when OS-level wake timers are off. <em>Disable if you want the device to stay asleep until you physically wake it.</em>',
  'fast-startup':'<strong>Fast Startup</strong> (Hybrid Shutdown) saves the kernel session to hiberfil.sys at shutdown for faster boot. The security problem: "shutting down" doesn\'t actually clear RAM from disk. The hibernation file contains kernel memory including <em>cached credentials, encryption keys, and NTLM hashes</em>. An attacker who steals your "powered off" laptop can extract these from hiberfil.sys without logging in.',
  'hibernate':'<strong>Hibernation</strong> saves your entire RAM to disk (hiberfil.sys) and powers off. This creates a complete memory snapshot including <em>every password, encryption key, browser session, and decrypted file</em> you had open. The file is as large as your RAM (e.g. 16GB). With disk access, an attacker can parse it offline to extract credentials. Disabling hibernation deletes hiberfil.sys.',
  'tpm-present':'<strong>TPM (Trusted Platform Module)</strong> is a dedicated security chip providing hardware-based cryptographic operations. It stores encryption keys, generates random numbers, and measures the boot process. TPM 2.0 is required for Windows 11, BitLocker auto-encryption, and Credential Guard. The TPM seals secrets to a specific boot configuration - if someone modifies the bootloader, the TPM refuses to release the BitLocker key.',
  'tpm-active':'<strong>TPM activation</strong> means the chip is powered on and performing cryptographic operations. Some systems ship with TPM deactivated in BIOS. An inactive TPM cannot protect BitLocker keys, perform boot measurements, or support Credential Guard.',
  'tpm-lockout':'<strong>TPM lockout threshold</strong> limits how many wrong PIN/password attempts are allowed before the TPM locks out and refuses further attempts for a cooldown period. The Windows default is 32 attempts with a ~10 minute heal time per attempt. With a 6-digit numeric PIN and default lockout, exhausting all 1,000,000 combinations would take <em>up to</em> ~19 years - but that is the worst case. On average, a random PIN is found halfway through (~9.5 years). Common PINs (000000, 123456, birthdates) would fall in early attempts. A well-resourced or state-level adversary could run automated brute-force hardware indefinitely, making weak or short PINs a real risk. <strong>Recommendation: use an 8+ digit PIN</strong> (100 million combinations, ~190 years worst case) or enable enhanced alphanumeric PINs for significantly stronger protection. Note: lockout only protects against brute-force <em>through</em> the TPM. Attacks that bypass the TPM entirely (cold boot, bus sniffing) are not affected by lockout settings.',
  'tpm-bus':'<strong>TPM bus sniffing</strong> is a hardware attack where an attacker places a logic analyser (~`$300) on the LPC or SPI bus between a discrete TPM chip and the CPU. During boot, the TPM sends the BitLocker Volume Master Key (VMK) to the CPU over this bus. On discrete TPMs (dTPM), this transfer can be intercepted in real-time, giving the attacker full disk decryption without knowing the PIN.<br><br><strong>Firmware TPMs (fTPM)</strong> run inside the CPU itself (Intel PTT, AMD fTPM). There is no external bus to tap - the key never leaves the CPU die. This makes fTPM immune to interposer attacks.<br><br><strong>TPM 2.0 parameter encryption</strong> can encrypt the session between OS and TPM, but Windows does not enable this for BitLocker by default. Even on TPM 2.0 discrete chips, the VMK may travel unencrypted. A <strong>pre-boot PIN</strong> is the strongest mitigation: the TPM will not release the VMK at all until the correct PIN is entered, so there is nothing to sniff.',
  'dma-ports':'<strong>DMA (Direct Memory Access)</strong> ports like Thunderbolt, FireWire, and ExpressCard allow external devices to read and write system memory directly without CPU involvement. A malicious device (modified Thunderbolt adapter) can <em>dump entire RAM in seconds</em>, including passwords, encryption keys, and everything open on screen. If no external DMA ports are detected, this is a conditional pass: an attacker would need to open the chassis and access internal PCIe or M.2 slots, which is a significantly more advanced attack requiring the machine to be powered on. VBS, HVCI, and Kernel DMA Protection remain valuable defence-in-depth measures regardless.',
  'vbs':'<strong>Virtualization Based Security (VBS)</strong> uses CPU hardware virtualization (Intel VT-x / AMD-V) to create isolated memory that even the Windows kernel cannot access. A small hypervisor runs below the OS. Even with kernel-level access (ring 0), attackers cannot read VBS-protected secrets. VBS enables Credential Guard and HVCI. <em>Requires UEFI, Secure Boot, and hardware virtualization in BIOS.</em><br><br><strong>Performance impact:</strong> VBS reserves system resources for its secure kernel. Expect a 5-15% overhead on CPU-intensive tasks. Some virtualization software (older VirtualBox, VMware Workstation) may conflict or require reconfiguration.',
  'hvci':'<strong>HVCI (Hypervisor-Enforced Code Integrity)</strong>, called "Memory Integrity" in Windows Security, uses VBS to verify all kernel-mode code is properly signed before execution. Prevents loading malicious kernel drivers even with admin access. Without HVCI, a compromised driver can read all memory, disable security, and persist across reboots.<br><br><strong>Performance impact:</strong> HVCI adds overhead to every kernel-mode code load. Expect 5-25% performance reduction in gaming and intensive workloads, particularly on older CPUs. <em>Incompatible drivers (RGB controllers, older printers, specialised USB devices) will stop working entirely.</em> Check Device Manager after enabling.',
  'credential-guard':'<strong>Credential Guard</strong> uses VBS to isolate Windows credential storage (LSASS) in a virtual container the kernel cannot access. Without it, tools like Mimikatz dump all cached passwords, NTLM hashes, and Kerberos tickets in seconds with admin access. <em>Requires Windows Enterprise or Education edition.</em> If your system has no DMA-capable external ports, the primary physical attack vector for credential extraction is absent, making this less critical. On Windows Pro, the registry key may partially work but is unsupported by Microsoft.',
  'dma-guard':'<strong>Kernel DMA Protection</strong> uses IOMMU (Intel VT-d / AMD-Vi) to block unauthorized DMA access from external ports. Only verified, driver-matched devices can perform DMA. Defeats Thunderbolt/PCIe attacks where malicious devices read RAM directly. <em>Requires hardware IOMMU support</em> and may not be available on older systems.',
  'bitlocker':'<strong>BitLocker</strong> is Windows drive encryption. By default, it encrypts <em>used space only</em> - sectors containing active data are protected, but deleted file remnants in free space may remain as plaintext (see the full-volume check below). With full-volume encryption enabled, every sector on your system drive is encrypted with AES (128 or 256-bit). Without BitLocker at all, anyone who steals your laptop or removes the drive can read all files including the credential database (SAM), browser passwords, and cached domain credentials. BitLocker uses the TPM to seal the encryption key to your specific hardware and boot configuration.',
  'bitlocker-pin':'<strong>BitLocker pre-boot PIN</strong> adds a second factor before the TPM releases the encryption key. Without a PIN, TPM auto-decrypts at boot. A cold boot or DMA attack can then extract the key from memory. With a PIN, the TPM <em>will not release the key</em> until you type it, blocking automated extraction. This is considered the single most important BitLocker hardening step for physical security.<br><br><strong>Bus sniffing note:</strong> On systems with a discrete TPM (dTPM), the PIN also prevents the most dangerous hardware attack: sniffing the BitLocker VMK from the LPC/SPI bus with a logic analyser. Without a PIN, the key is released automatically at boot and can be captured in transit. With a PIN, nothing is released until you authenticate. On firmware TPMs (fTPM/Intel PTT/AMD fTPM), bus sniffing is not possible regardless, but the PIN still protects against cold boot and DMA attacks.',
  'kernel-paging':'<strong>Kernel Paging (DisablePagingExecutive)</strong> controls whether Windows writes kernel code and data to the pagefile. When enabled (=1), kernel and drivers stay locked in RAM. When disabled, sensitive kernel memory including <em>cached credentials, crypto keys, and security tokens</em> may be written to pagefile.sys and recovered with disk access.',
  'clear-pagefile':'<strong>Clear Pagefile at Shutdown</strong> overwrites pagefile.sys with zeros at shutdown. The pagefile stores memory pages that didn\'t fit in RAM and can contain <em>passwords, decrypted documents, browser sessions, and encryption keys</em>. Without clearing, these remain on disk after shutdown for forensic extraction.',
  'crash-dump':'<strong>Crash Dumps</strong> are files Windows creates on blue-screen. A full dump writes <em>entire RAM</em> to disk. Even partial dumps contain sensitive kernel memory. An attacker can <em>force a crash</em> (NMI, driver exploit, key combo) to trigger a dump, then steal the file. Level 0 = disabled, 1 = full dump (most dangerous), 2 = kernel, 3 = minidump.',
  'nmi-dump':'<strong>NMI (Non-Maskable Interrupt) Crash Dump</strong> allows triggering a BSOD via keyboard shortcut or hardware button. This is a known forensic technique: investigator holds a key combo, system crashes, memory dump is written to disk containing everything in RAM. Disabling prevents this physical access attack vector.',
  'rdp':'<strong>Remote Desktop Protocol (RDP)</strong> allows remote control over the network on port 3389. RDP has been targeted by critical vulnerabilities (BlueKeep, DejaBlue) and is a primary ransomware vector. Even with strong passwords, brute-force, credential stuffing, and pass-the-hash attacks apply. <em>Disable unless actively needed; use VPN + NLA if required.</em>',
  'screen-timeout':'<strong>Display timeout</strong> determines how long the screen stays on when idle. Shorter timeout means the lock screen engages sooner when you walk away. <em>5 minutes or less recommended.</em> Longer timeouts give anyone passing an unattended laptop a wider access window.',
  'winre':'<strong>Windows Recovery Environment (WinRE)</strong> is a built-in recovery partition that loads when Windows fails to boot, or when triggered manually (hold Shift + Restart). An attacker with physical access can use WinRE to access a command prompt, reset local account passwords using the "Sticky Keys" exploit, modify system files, or disable security features. With BitLocker and pre-boot PIN, WinRE is less dangerous because the drive is encrypted, but if BitLocker unlocks automatically (no PIN), WinRE becomes a potent attack surface. <em>Disable with: reagentc /disable</em>',
  'auto-logon':'<strong>Auto-logon (AutoAdminLogon)</strong> tells Windows to skip the login screen entirely and boot straight to the desktop using stored credentials. This completely bypasses Windows authentication. If BitLocker has no pre-boot PIN, a thief powers on your laptop and lands on your desktop with full access to everything. Even with a BitLocker PIN, auto-logon means the PIN is the <em>only</em> barrier - there is no second factor at the OS level. Auto-logon also stores the password in the registry in a reversible format.',
  'arso':'<strong>Automatic Restart Sign-On (ARSO)</strong> is a Windows feature that caches your credentials before a Windows Update reboot, then automatically signs you back in and locks the screen after the update completes. While Microsoft designed this for convenience, it means your credentials are stored in a retrievable form during the update cycle. On some configurations (particularly with auto-logon or no lock screen password), the machine may end up at an unlocked desktop after an unattended update. <em>Disable via Group Policy or registry to ensure every reboot requires manual authentication.</em>',
  'uac-credential-prompt':'<strong>UAC Elevation Prompt Behaviour</strong> determines what happens when an admin user triggers a User Account Control elevation. The default setting (<code>ConsentPromptBehaviorAdmin=5</code>) shows a simple Yes/No consent dialog - an attacker at an unlocked admin session just clicks Yes and gets full administrator privileges.<br><br>Setting this to <strong>Prompt for credentials</strong> (<code>ConsentPromptBehaviorAdmin=1</code>) forces a password re-entry on every elevation, even for users who are already admins. This is the critical difference between "walk up to unlocked laptop, click Yes, install keylogger" and "walk up to unlocked laptop, get stopped by a password prompt."<br><br>This forms a defence chain with display timeout and account passwords: the screen lock limits the access window, the credential prompt gates elevation, and the password makes the gate real. <em>All three must hold.</em> Set via Group Policy: Computer Configuration &gt; Windows Settings &gt; Security Settings &gt; Local Policies &gt; Security Options &gt; User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode.',
  'local-password':'<strong>Local Account Password</strong> is the most basic authentication control. If any enabled local administrator account has no password set or no password required, then every other access control - lock screen, UAC credential prompt, Remote Desktop authentication - can be bypassed by pressing Enter at the password prompt.<br><br>The built-in Administrator account is especially dangerous when enabled without a password because it <strong>bypasses UAC entirely</strong>. Unlike regular admin accounts which get consent or credential prompts, the built-in Administrator runs everything elevated by default with no prompt at all.<br><br>Common scenarios where this fails: the built-in Administrator account was enabled for troubleshooting and never disabled; a local admin account was created for testing with a blank password; password-required policy was not applied to local accounts on non-domain machines.',
  'builtin-admin':'<strong>Built-in Administrator Account</strong> is a special Windows account (SID ending in -500) that bypasses UAC entirely - no consent prompts, no credential prompts, every process runs fully elevated. If this account is enabled without a password, an attacker at the login screen can sign in and has immediate unrestricted system access with no UAC friction. <em>Best practice: keep the built-in Administrator account disabled. If it must be enabled, set a strong unique password and audit its usage.</em>',
  'amt-provisioned':'<strong>Intel Active Management Technology (AMT)</strong> provides out-of-band remote management through the Intel Management Engine (ME), a separate processor embedded in the chipset with its own network stack that operates independently of the main CPU, OS, and power state.<br><br>When provisioned, AMT gives remote keyboard/video/mouse (KVM) control, power management (power on, off, reset), Serial Over LAN, and IDE Redirection (boot from a remote image). Importantly, <strong>AMT does not bypass OS authentication</strong>. An attacker sees whatever the monitor shows - if the machine is at a locked login screen, they see a locked login screen.<br><br>The physical security risk is the MEBx (Management Engine BIOS Extension) password. On most machines, the default is <em>admin</em> and nobody changes it. An attacker with 30 seconds of physical access can enter MEBx at boot, set their own password, and provision AMT - giving them persistent remote physical-equivalent access that survives OS reinstalls and is invisible to all OS-level security tools.<br><br><em>Mitigation: change the MEBx password from default, or disable AMT in BIOS if not needed. If using AMT, provision it through Intel EMA with proper authentication.</em>',
  'enhanced-pin':'<strong>Enhanced BitLocker PIN</strong> controls whether BitLocker pre-boot PINs can use the full keyboard (letters, numbers, symbols) or only digits 0-9. The default is numeric-only, which severely limits keyspace: a 6-digit numeric PIN has 1,000,000 combinations. With TPM lockout this takes up to ~19 years to exhaust, but common PINs (000000, 123456, birthdates) fall in early attempts. With enhanced PIN enabled, a 6-character alphanumeric PIN has roughly 2 billion combinations. <strong>Recommendation: use 8+ characters</strong> whether numeric or alphanumeric. An 8-digit numeric PIN has 100 million combinations; an 8-character alphanumeric PIN has ~2.8 trillion. Set via Group Policy: Computer Configuration &gt; Administrative Templates &gt; BitLocker &gt; Operating System Drives &gt; Allow enhanced PINs for startup.',
  'bitlocker-fullvol':'<strong>Full-volume vs used-space-only encryption.</strong> BitLocker offers two modes: <em>full-volume</em> encrypts every sector including free space; <em>used-space-only</em> encrypts only sectors with active data.<br><br>The risk with used-space-only is specific: files deleted <strong>before</strong> BitLocker was enabled may still exist as plaintext in unencrypted free space. Files created and deleted <strong>after</strong> encryption was enabled are written as ciphertext and remain protected even after deletion.<br><br>This risk diminishes naturally over time as the OS overwrites free space with new (encrypted) data. On a heavily used drive, most pre-encryption remnants will be overwritten within months.<br><br><strong>To fix:</strong> Decrypt the volume (<code>manage-bde -off C:</code>), then re-encrypt with full-volume mode via Group Policy (Computer Configuration &gt; Administrative Templates &gt; BitLocker &gt; Operating System Drives &gt; Enforce drive encryption type &gt; Full encryption). Or accept the diminishing risk if the machine was freshly installed before encryption.',
  'kernel-debug':'<strong>Kernel debugging</strong> allows a debugger to attach to the Windows kernel, giving complete access to all memory, all processes, and all security mechanisms. It is meant for driver development but is a catastrophic security hole if left enabled: an attacker with physical access can attach a kernel debugger via serial, USB, or network and read all credentials, disable security features, and inject code. <em>Kernel debugging should always be disabled on production machines.</em> Check with: bcdedit /v',
  'fs-recent-docs':'<strong>Recent Documents</strong> records every file opened in Explorer with full path and timestamp. Forensic examiners use this to reconstruct file access patterns.',
  'fs-jump-lists':'<strong>Jump Lists</strong> are per-application file access histories stored in AutomaticDestinations. They survive file deletion and record which documents each app opened.',
  'fs-thumbnails':'<strong>Thumbnail Cache</strong> stores image thumbnails in thumbcache_*.db files. These persist after the original images are deleted, revealing what images existed on the system.',
  'fs-prefetch':'<strong>Prefetch</strong> records every executable launched with timestamps, frequency, and loaded DLLs. Located in C:\\Windows\\Prefetch as .pf files.',
  'fs-superfetch':'<strong>SysMain (Superfetch)</strong> monitors application launch patterns to preload frequently used apps. Records usage data that reveals your daily application habits.',
  'fs-user-assist':'<strong>UserAssist</strong> logs every program launched via Explorer shell. Entries are ROT13-encoded (trivially reversible) and include run counts and last-execution timestamps.',
  'fs-timeline':'<strong>Activity History</strong> records apps used, documents opened, and websites visited. May sync to Microsoft cloud via cross-device timeline. Stored in ActivitiesCache.db.',
  'fs-search-index':'<strong>Windows Search Index</strong> stores indexed content of documents, emails, and files in a database. Searchable text persists even after the original files are deleted.',
  'fs-ps-history':'<strong>PowerShell History</strong> (PSReadLine) saves every command typed across all sessions to a plaintext file. Often contains passwords, paths, and commands revealing activity.',
  'fs-bam':'<strong>Background Activity Moderator (BAM)</strong> records executable paths with last-execution timestamps in the registry. Used by forensic tools to build program execution timelines.',
  'fs-network-profiles':'<strong>Network Profiles</strong> record every Wi-Fi and Ethernet network joined with first and last connection dates. Reveals location history and travel patterns.',
  'fs-shellbags':'<strong>ShellBags</strong> record every folder navigated in Explorer, including folders on removable media and network shares that have since been disconnected.',
  'fs-usb-history':'<strong>USB Device History</strong> (USBSTOR) records every USB storage device ever connected, with serial numbers, vendor IDs, and connection timestamps.',
  'fs-key-escrow':'<strong>Key Escrow to Team Admin</strong><br><br><em>How it will work:</em> Before entering a high-risk jurisdiction, HardTarget rotates your BitLocker PIN to a new random value and sends it to your designated team administrator. You no longer know the PIN yourself.<br><br><strong>1. Pre-travel lockout:</strong> HardTarget generates a new random PIN, sets it on the device via <code>manage-bde</code>, and transmits the PIN plus the recovery key to your team admin through a secure channel. If border agents or adversaries demand you unlock the device, you truthfully cannot - you do not possess the PIN. This is the strongest form of compelled-access defence available: you cannot be forced to reveal what you do not know.<br><br><strong>2. Remote unlock:</strong> When you reach a safe location, your team admin sends the PIN back through a verified channel (encrypted message, voice call, or internal portal). You enter it and resume normal use. If the device was seized, your admin simply never sends the PIN - the device remains locked.<br><br><strong>3. Emergency recovery:</strong> If the PIN channel fails, your admin holds the BitLocker recovery key as a backup path. This also covers lost devices, hardware failures, and lockout scenarios.<br><br>Key escrow uses your existing team infrastructure - no third-party services, no external dependencies, zero liability.',
  'fs-amcache':'<strong>Amcache</strong> is a registry hive that records every executable, driver, and installer with SHA1 hashes, file paths, publisher info, and timestamps. Proves specific software was executed even after the program has been deleted.',
  'fs-shimcache':'<strong>AppCompatCache (ShimCache)</strong> is stored in the SYSTEM registry hive and records executable paths with file sizes and timestamps. Persists across reboots. One of the top forensic artifacts for establishing which programs were run.',
  'fs-srum':'<strong>System Resource Usage Monitor (SRUM)</strong> tracks per-application network bytes, energy consumption, CPU time, and execution duration over 30-60 days. Reveals not just which apps were run but how actively they were used.',
  'fs-usn-journal':'<strong>NTFS USN Journal</strong> logs every file system change (create, delete, rename, modify) with timestamps. Records the changes HardTarget itself makes. Cannot be disabled without breaking core Windows services.',
  'fs-event-logs':'<strong>Windows Event Logs</strong> record logons, privilege use, and every PowerShell script executed. Clearing Event Logs creates Event ID 1102 - itself treated as evidence of tampering. HardTarget does not modify Event Logs.',
  'fs-etw':'<strong>Event Tracing for Windows (ETW)</strong> provides kernel-level tracing of process creation, network connections, and registry access. Autologger sessions start at boot. Most cannot be safely disabled.',
  'fs-mft':'<strong>NTFS `$MFT</strong> is the filesystem index of every file. Contains timestamps and names for all files including deleted ones. Cannot be cleared without reformatting the volume.',
  'fs-shadow-copies':'<strong>Volume Shadow Copies</strong> are point-in-time snapshots. An examiner can mount a previous copy to access system state from before any hardening was applied, effectively undoing changes.',
  'fs-wer':'<strong>Windows Error Reporting</strong> stores crash reports that can contain mini-dumps with process memory, loaded modules, and sensitive data from the time of crash.',
  'fs-self-footprint':'<strong>Running HardTarget creates traces.</strong> This scan generates Prefetch, BAM, Amcache, USN journal, and PowerShell log entries. An examiner will see a security scanner was run and when.',


  'account-lockout':'<strong>Account Lockout Policy</strong> limits how many wrong passwords an attacker can try at the login screen before the account is temporarily locked. Without a lockout policy, there is nothing stopping automated brute force - a Rubber Ducky can try thousands of PINs per hour. The <strong>lockout threshold</strong> sets how many failures are allowed (recommended: 3-5). The <strong>lockout duration</strong> sets how long the lockout lasts. The <strong>observation window</strong> sets how long failed attempts are counted before resetting. Set via <code>net accounts</code> or Group Policy: Computer Configuration &gt; Windows Settings &gt; Security Settings &gt; Account Policies &gt; Account Lockout Policy.',
  'password-policy':'<strong>Password Policy</strong> sets minimum requirements for password strength. A short or simple password can be brute-forced at the login screen even with lockout policies (the attacker just waits out each lockout). <strong>Minimum length</strong> is the most impactful setting: each additional character multiplies the keyspace. NIST 800-63B recommends minimum 8 characters and explicitly advises <em>against</em> complexity requirements (uppercase+lowercase+digit+symbol) because they produce predictable patterns like <code>Password1!</code> and <code>Summer2024!</code>. Length and checking against breached password lists are what actually matter. <strong>Password history</strong> prevents reuse of recent passwords. Set via <code>net accounts</code> or Group Policy: Computer Configuration &gt; Windows Settings &gt; Security Settings &gt; Account Policies &gt; Password Policy.',
  'ctrl-alt-del':'<strong>Secure Attention Sequence (Ctrl+Alt+Del)</strong> is a hardware interrupt that cannot be intercepted by user-mode software. When required at login, it guarantees the real Windows login screen is displayed - not a fake overlay placed by malware or an attacker. Without it, a malicious program could display a pixel-perfect copy of the login screen to capture credentials. This is a low-effort, high-value setting that costs nothing in usability.',
  'last-username':'<strong>Hide Last Username</strong> prevents the login screen from displaying which user account was most recently signed in. By default, Windows shows the last username, meaning an attacker at the login screen already has half the credential pair. Hiding it forces the attacker to guess both the username and the password. Set via Group Policy: Computer Configuration &gt; Windows Settings &gt; Security Settings &gt; Local Policies &gt; Security Options &gt; Interactive logon: Don\'t display last signed-in.',
  'lsa-protection':'<strong>LSA Protection (RunAsPPL)</strong> runs the Local Security Authority Subsystem Service (LSASS) as a Protected Process Light. This means only specially signed Microsoft code can read LSASS memory. Without it, an attacker with administrator access can use tools like <strong>Mimikatz</strong>, <code>comsvcs.dll</code> MiniDump, or <code>procdump</code> to extract <em>every credential in memory</em>: plaintext passwords, NTLM hashes, Kerberos tickets, cached domain credentials.<br><br>This is the <strong>single most common credential theft technique</strong> in real-world attacks. Enabling RunAsPPL does not require Enterprise edition and has minimal compatibility impact on modern systems. Set via registry: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1</code>.',
  'usb-storage':'<strong>USB Mass Storage Policy</strong> controls whether USB flash drives, external hard drives, and SD cards can be accessed. Without restriction, an attacker with brief physical access can plug in a drive and exfiltrate files in seconds, or drop malware onto the machine. The <strong>Deny_All</strong> policy blocks all removable storage device classes while leaving keyboards, mice, and other non-storage USB devices working normally. Set via Group Policy: Computer Configuration &gt; Administrative Templates &gt; System &gt; Removable Storage Access.',
  'usb-install':'<strong>USB Device Install Restriction</strong> controls whether Windows will install drivers for new USB device classes. Without restriction, plugging in a rogue USB device (like a network adapter that routes traffic through an attacker, or a HID keyboard that types commands) triggers automatic driver installation. The <strong>DenyUnspecified</strong> policy blocks new device classes while allowing already-installed devices to continue working.',
  'autorun':'<strong>AutoRun / AutoPlay</strong> allows removable media (USB drives, CDs) to auto-execute programs when inserted. This was the delivery mechanism for the Conficker worm and countless other malware campaigns. Setting <code>NoDriveTypeAutoRun=255</code> disables AutoRun for all drive types. Modern Windows has some AutoRun protections built in, but the policy provides defense in depth. There is no legitimate reason to have AutoRun enabled on a security-hardened machine.',
  'bluetooth':'<strong>Bluetooth</strong> exposes a wireless attack surface within physical proximity (~30 feet, potentially more with directional antennas). Known attacks include <strong>BlueBorne</strong> (remote code execution without pairing), <strong>KNOB</strong> (key negotiation downgrade), BLE tracking, and HID injection via spoofed Bluetooth keyboards. During Modern Standby, Bluetooth remains powered and discoverable. If you do not actively use Bluetooth peripherals, disabling the adapter eliminates this entire attack surface.',
  'wifi-autoconnect':'<strong>WiFi Auto-Connect</strong> allows Windows to automatically connect to suggested open WiFi hotspots. An attacker can create an evil twin access point with a common SSID (like "Free WiFi" or a known hotspot name) and your device connects automatically, routing all network traffic through the attacker. This is especially dangerous during Modern Standby when the device connects without your knowledge. Disable auto-connect to open networks; manually connect only to known, trusted networks.',
  'camera-privacy':'<strong>Camera Privacy</strong> controls whether apps can access the webcam by default. When set to Allow, any app with camera permissions can activate the camera without a per-use prompt. Combined with Modern Standby (where the camera subsystem remains powered), malware could record video while the device appears to be asleep. Setting the system default to Deny requires apps to be individually granted camera access in Privacy settings.',
  'mic-privacy':'<strong>Microphone Privacy</strong> controls whether apps can access the microphone by default. The risks mirror the camera: during Modern Standby, the audio subsystem remains powered. Malware with microphone access can use the device as a listening device while it appears off in a bag or on a desk. Setting the system default to Deny adds a permission gate that limits ambient audio surveillance.',
  'winrm':'<strong>Windows Remote Management (WinRM)</strong> enables remote PowerShell sessions, WMI queries, and management tool connectivity (Ansible, SCCM, etc.). If WinRM is running when an attacker gains keyboard access, they can configure persistent remote access, create a reverse shell, or pivot to other machines on the network. With Basic authentication enabled, credentials may transit in cleartext. Unless actively used for management, WinRM should be disabled.',
  'ps-language-mode':'<strong>PowerShell Language Mode</strong> determines what .NET types and features are available in a PowerShell session. <strong>Full Language Mode</strong> (the default) allows unrestricted access to the entire .NET framework - an attacker can compile C# in memory, load Mimikatz via reflection, use PowerSploit, and execute arbitrary code. <strong>Constrained Language Mode</strong> restricts available types and prevents most attack tools from functioning. CLM is enforced automatically when a WDAC (Windows Defender Application Control) or AppLocker policy is active. It cannot be set via a simple registry key - it requires an application control policy.',
  'bl-network-unlock':'<strong>BitLocker Network Unlock</strong> allows BitLocker to automatically unlock the OS drive when connected to the corporate network, bypassing the pre-boot PIN requirement. This is designed for unattended server reboots and desktop environments. The security risk: a stolen laptop brought within range of the corporate WiFi or plugged into the corporate network auto-decrypts without any PIN entry. For mobile devices, Network Unlock should be disabled so the PIN is always required.',
  'removable-encrypt':'<strong>Removable Drive Encryption (BitLocker To Go)</strong> policy denies write access to removable drives (USB flash drives, external hard drives) unless they are encrypted with BitLocker. Without this policy, sensitive data can be copied to unencrypted removable media and lost or stolen. With the policy active, you can still read from unencrypted drives but cannot write to them - forcing encryption before any data leaves the machine.',

  'test-signing':'<strong>Test signing mode</strong> allows Windows to load kernel drivers that are not signed by a trusted certificate authority. This is intended for driver development and testing. In production, it allows an attacker to load a malicious kernel driver that can read all memory, keylog, disable antivirus, or persist as a rootkit. Test signing also bypasses HVCI protections. <em>Should always be disabled on production machines.</em>'
};

var EDITION_CHECKS = {
  'credential-guard': 'Enterprise',
  'bitlocker': 'Pro',
  'bitlocker-pin': 'Pro',
  'bitlocker-fullvol': 'Pro',
  'enhanced-pin': 'Pro',
  'dma-guard': 'Pro',
  'removable-encrypt': 'Pro',
  'bl-network-unlock': 'Pro'
};
// v0.51: GP-dependent checks that write registry but aren't enforced on Home
var GP_CHECKS = {
  'usb-storage': 'Removable Storage policy requires Group Policy',
  'usb-install': 'Device Installation policy requires Group Policy'
};

function render() {
  var m = DATA.machine || {};
  var ed = m.windowsEdition || 'Unknown';
  var edClass = ed.toLowerCase();
  var machineText = DATA.computer + ' \u2022 ' + (m.manufacturer || '') + ' ' + (m.model || '');
  machineText += ' \u2022 ' + DATA.generated + ' \u2022 v' + DATA.version;
  var mi = document.getElementById('machine-info');
  mi.innerHTML = machineText + ' <span class="edition-badge ' + edClass + '">Windows ' + ed + '</span>'
    + (READONLY ? ' <span style="padding:2px 8px;border-radius:3px;background:rgba(56,189,248,0.12);border:1px solid rgba(56,189,248,0.25);color:#38bdf8;font-size:9px;font-weight:700;letter-spacing:0.5px;vertical-align:middle;">AUDIT</span>' : ' <span style="padding:2px 8px;border-radius:3px;background:rgba(250,204,21,0.12);border:1px solid rgba(250,204,21,0.25);color:#facc15;font-size:9px;font-weight:700;letter-spacing:0.5px;vertical-align:middle;">EXPERT</span>');

  var pc = DATA.summary.overallClass || 'warn';
  var sh = '';
  sh += '<div class="summary-card posture ' + pc + '"><div class="value">' + DATA.summary.overall + '</div><div class="label">Posture</div></div>';
  sh += '<div class="summary-card pass"><div class="value">' + DATA.summary.pass + '</div><div class="label">Pass</div></div>';
  sh += '<div class="summary-card conditional-pass"><div class="value">' + (DATA.summary.condPass || 0) + '</div><div class="label">Cond. Pass</div></div>';
  sh += '<div class="summary-card warn"><div class="value">' + DATA.summary.warn + '</div><div class="label">Warn</div></div>';
  sh += '<div class="summary-card fail"><div class="value">' + DATA.summary.fail + '</div><div class="label">Fail</div></div>';
  document.getElementById('summary').innerHTML = sh;

  // Monitor status bar - rendered dynamically from /status poll
  renderMonitorBar(DATA.monitor || {});

  // Fix All bar (hidden in read-only audit mode)
  var fixable = DATA.checks.filter(function(c) { return c.fixable && c.status !== 'pass' && c.status !== 'info'; });
  if (!READONLY && fixable.length > 0) {
    document.getElementById('expert-warning').style.display = 'block';
    document.getElementById('console-hint').style.display = 'block';
    var bar = document.getElementById('fix-all-bar');
    bar.style.display = 'flex';
    var names = fixable.map(function(c) { return c.title.split(' is ')[0].split(' has ')[0].split(' can ')[0]; });
    var safe = fixable.filter(function(c) {
      var f = DATA.fixes[c.fixId]; return f && !f.Note;
    });
    var caveats = fixable.filter(function(c) {
      var f = DATA.fixes[c.fixId]; return f && f.Note;
    });
    var info = '<strong>' + fixable.length + ' fixable issue' + (fixable.length > 1 ? 's' : '') + '</strong>';
    if (safe.length > 0) info += ' \u2022 ' + safe.length + ' safe to auto-apply';
    if (caveats.length > 0) info += ' \u2022 ' + caveats.length + ' with caveats (skipped by Fix All - apply individually)';
    document.getElementById('fix-all-info').innerHTML = info;
  }

  var html = '';
  var STATUS_LABELS = {'exposed':'EXPOSED','warn':'WARN','conditional-pass':'CONDITIONAL PASS','protected':'PROTECTED'};
  function orderByContributing(checks, contributing) {
    var ordered = [];
    var added = {};
    (contributing || []).forEach(function(id) {
      checks.forEach(function(c) {
        if (c.id === id && !added[c.id]) { ordered.push(c); added[c.id] = true; }
      });
    });
    checks.forEach(function(c) { if (!added[c.id]) { ordered.push(c); } });
    return ordered;
  }
  DATA.scenarios.forEach(function(s) {
    var rawChecks = DATA.checks.filter(function(c) { return c.scenarios && c.scenarios.indexOf(s.id) >= 0; });
    var checks = orderByContributing(rawChecks, s.contributing);
    if (checks.length === 0) return;
    var ico = ICONS[s.id] || '';
    var badgeLabel = STATUS_LABELS[s.status] || s.status;
    html += '<div class="scenario ' + s.status + (s.preview ? ' preview' : '') + '" onclick="toggleScenario(this)">';
    html += '<div class="scenario-header">';
    html += '<span class="scenario-icon">' + ico + '</span>';
    html += '<span class="scenario-title">' + s.name + '</span>';
    html += '<span class="scenario-badge ' + s.status + '">' + badgeLabel + '</span>';
    html += '<span class="scenario-expand">\u25B6</span>';
    if (s.preview) html += '<span class="preview-badge">IN DEVELOPMENT</span>';
    html += '</div>';
    html += '<div class="scenario-desc">' + s.description + '</div>';
    if (s.context) {
      html += '<div class="scenario-context"><div class="ctx-box"><span class="ctx-icon">&#x2139;&#xFE0F;</span> ' + s.context + '</div></div>';
    }
    html += '<div class="scenario-details">';
    html += '<div class="mitigation">&#x1F4A1; ' + s.mitigation + '</div>';
    html += '<div class="contributing-title">Contributing Factors</div>';
    checks.forEach(function(c) {
      var inf = INFO[c.id] || '';
      var reqEd = EDITION_CHECKS[c.id] || '';
      html += '<div class="check-item" onclick="event.stopPropagation();toggleCheckDetail(event,this)">';
      html += '<div class="check-row">';
      html += '<div class="check-dot ' + c.status + '"></div>';
      html += '<div class="check-text">' + c.title;
      if (reqEd && ed !== reqEd && ed !== 'Education') html += ' <span class="edition-tag">REQUIRES ' + reqEd.toUpperCase() + '</span>';
      if (GP_CHECKS[c.id] && ed === 'Home' && c.status !== 'pass') html += ' <span class="gp-tag">NO GROUP POLICY</span>';
      if (c.id === 'dma-guard' && !DATA.hasDmaPorts) html += ' <span class="no-ports-tag">NO DMA PORTS</span>';
      html += '</div>';
      html += '<span class="check-expand">\u25B6</span>';

      if (!READONLY && c.fixable && c.status !== 'pass' && c.status !== 'info') {
        html += '<button class="fix-btn" id="fix-' + c.id + '" onclick="event.stopPropagation();applyFix(\'' + c.fixId + '\',\'' + c.id + '\')">FIX</button>';
      }
      html += '</div>';
      if (c.fixId && DATA.fixes[c.fixId] && DATA.fixes[c.fixId].Impact) {
        html += '<div class="impact-warning">&#x26A0;&#xFE0F; <strong>Side effect:</strong> ' + DATA.fixes[c.fixId].Impact + '</div>';
      }
      if (inf) html += '<div class="info-panel">' + inf + '</div>';
      html += '</div>';
    });
    html += '</div></div>';
  });
  document.getElementById('scenarios').innerHTML = html;

  var ch = '';
  DATA.sections.forEach(function(sec) {
    var checks = DATA.checks.filter(function(c) { return c.section === sec.id; });
    if (checks.length === 0) return;
    var ico = ICONS[sec.id] || '';
    var isPreview = sec.preview || false;
    ch += '<div class="section' + (isPreview ? ' preview' : '') + '">';
    ch += '<div class="section-title">' + ico + ' ' + sec.name + '</div>';
    checks.forEach(function(c) {
      var inf = INFO[c.id] || '';
      var reqEd = EDITION_CHECKS[c.id] || '';
      var isComing = (c.status === 'info' && c.detail && c.detail.indexOf('COMING SOON') === 0);
      ch += '<div class="check-item' + (isComing ? ' coming-soon' : '') + '" onclick="toggleCheckDetail(event,this)">';
      ch += '<div class="check-row">';
      ch += '<div class="check-dot ' + c.status + '"></div>';
      ch += '<div class="check-text">' + c.title;
      if (isComing) ch += '<span class="coming-soon-label">COMING SOON</span>';
      if (reqEd && ed !== reqEd && ed !== 'Education') ch += ' <span class="edition-tag">REQUIRES ' + reqEd.toUpperCase() + '</span>';
      if (GP_CHECKS[c.id] && ed === 'Home' && c.status !== 'pass') ch += ' <span class="gp-tag">NO GROUP POLICY</span>';
      if (c.id === 'dma-guard' && !DATA.hasDmaPorts) ch += ' <span class="no-ports-tag">NO DMA PORTS</span>';
      if (c.detail && !isComing) ch += '<div class="check-detail">' + c.detail + '</div>';
      if (isComing) ch += '<div class="check-detail">' + c.detail.replace('COMING SOON - ','') + '</div>';
      ch += '</div>';
      ch += '<span class="check-expand">\u25B6</span>';

      if (!READONLY && c.fixable && c.status !== 'pass' && c.status !== 'info') {
        ch += '<button class="fix-btn" id="fixall-' + c.id + '" onclick="event.stopPropagation();applyFix(\'' + c.fixId + '\',\'' + c.id + '\')">FIX</button>';
      }
      ch += '</div>';
      if (c.fixId && DATA.fixes[c.fixId] && DATA.fixes[c.fixId].Impact) {
        ch += '<div class="impact-warning">&#x26A0;&#xFE0F; <strong>Side effect:</strong> ' + DATA.fixes[c.fixId].Impact + '</div>';
      }
      if (inf) ch += '<div class="info-panel">' + inf + '</div>';
      ch += '</div>';
    });
    ch += '</div>';
  });
  document.getElementById('checks').innerHTML = ch;

  // Compliance framework mapping view
  var comp = DATA.compliance || {};
  var FW_LABELS = {
    nist: {name:'NIST 800-171', desc:'CUI Protection (CMMC prerequisite)'},
    cmmc: {name:'CMMC Level 2', desc:'Defense contractor certification'},
    cis:  {name:'CIS Benchmarks', desc:'Windows hardening baseline'},
    iso:  {name:'ISO 27001:2022', desc:'Annex A controls'}
  };
  // Human-readable control names
  var CTRL_NAMES = {
    // ISO 27001:2022 Annex A
    'A.7.7':'Clear screen policy','A.7.9':'Security of assets off-premises',
    'A.8.1':'User endpoint devices','A.8.2':'Privileged access rights','A.8.5':'Secure authentication',
    'A.8.7':'Protection against malware','A.8.8':'Management of technical vulnerabilities',
    'A.8.9':'Configuration management','A.8.10':'Information deletion','A.8.12':'Data leakage prevention',
    'A.8.13':'Information backup','A.8.15':'Logging','A.8.19':'Installation of software on operational systems',
    'A.8.20':'Networks security','A.8.24':'Use of cryptography',
    // NIST 800-171 families
    '3.1.1':'Limit system access','3.1.7':'Limit privileges','3.1.8':'Unsuccessful logon attempts',
    '3.1.10':'Session lock','3.1.11':'Session termination','3.1.12':'Control remote access',
    '3.1.13':'Encrypt remote access','3.1.19':'Encrypt CUI on mobile',
    '3.3.1':'Create audit records','3.3.2':'Audit record content',
    '3.4.1':'Establish baselines','3.4.2':'Enforce security configs','3.4.5':'Define access restrictions for change',
    '3.4.6':'Least functionality','3.4.7':'Restrict nonessential programs','3.4.8':'Deny-by-exception policy',
    '3.5.1':'Identify system users','3.5.2':'Authenticate users','3.5.3':'Multi-factor authentication',
    '3.5.7':'Password complexity','3.5.8':'Password reuse','3.5.10':'Cryptographic password storage',
    '3.8.6':'Encrypt CUI on portable storage','3.8.7':'Control removable media','3.8.8':'Restrict removable media',
    '3.8.9':'Protect backup CUI','3.10.1':'Limit physical access','3.10.2':'Protect physical facility',
    '3.10.6':'Enforce safeguards for CUI at alternate work sites',
    '3.13.8':'Deny network traffic by default','3.13.11':'Encrypt CUI','3.13.16':'Protect CUI at rest',
    '3.14.1':'Flaw remediation','3.14.4':'Update malicious code protection',
    // CIS references (section numbers)
    '1.1.5':'Password history','1.1.6':'Minimum password age',
    '2.3.1.1':'Rename administrator account','2.3.1.2':'Rename guest account','2.3.1.5':'Disable guest account',
    '2.3.10.12':'Clear virtual memory pagefile','2.3.17.1':'UAC admin prompt','2.3.17.2':'UAC user prompt',
    '18.8.26.1':'DMA Guard policy','18.8.28.3':'Screen saver timeout',
    '18.9.4.1':'Activity history publishing','18.9.5.1':'VBS enabled','18.9.5.2':'Platform security level',
    '18.9.5.3':'HVCI enabled','18.9.59.3.9.1':'Disable Remote Desktop',
    '18.9.97.1':'Disable auto-logon','18.10.9.1.1':'Enhanced PIN','18.10.9.1.2':'Require startup PIN',
    '3.1.16':'Wireless access restrictions','3.14.2':'Malicious code protection at entry/exit',
    '1.2.1':'Account lockout duration','1.2.2':'Account lockout threshold','1.2.3':'Reset account lockout counter',
    '1.1.1':'Password history','1.1.2':'Maximum password age','1.1.3':'Minimum password age','1.1.4':'Minimum password length',
    '2.3.7.1':'Interactive logon: require CAD','2.3.7.4':'Interactive logon: do not display last user',
    '18.4.7':'Configure LSA Protection','18.9.8.1':'Turn off AutoPlay','18.9.8.2':'Default AutoRun behavior','18.9.8.3':'Turn off AutoPlay for all drives',
    '18.9.102.1':'Allow remote server management via WinRM','18.9.102.2':'Allow unencrypted traffic',
    'SI.L1-3.14.2':'Malicious code protection',
    '18.10.9.1.5':'BitLocker OS drive encryption','18.10.9.2.1':'BitLocker fixed drive encryption',
    '19.1.3.1':'Screen saver activation'
  };
  // CMMC names map from NIST (strip prefix)
  var fwOrder = ['nist','cmmc','cis','iso'];
  var fhtml = '<div class="fw-grid">';
  fwOrder.forEach(function(fk) {
    var fw = comp[fk];
    if (!fw) return;
    var total = fw.controlsAssessed || 0;
    var pPct = total ? Math.round(fw.pass/total*100) : 0;
    var cpPct = total ? Math.round((fw.condPass||0)/total*100) : 0;
    var wPct = total ? Math.round(fw.warn/total*100) : 0;
    var fPct = total ? Math.round(fw.fail/total*100) : 0;
    var label = FW_LABELS[fk] || {name:fk, desc:''};
    fhtml += '<div class="fw-card" id="fw-'+fk+'" onclick="this.classList.toggle(\'open\')">';
    fhtml += '<div class="fw-name">'+label.name+'</div>';
    fhtml += '<div class="fw-stats">';
    fhtml += '<div><div class="fw-stat pass">'+fw.pass+'</div><div class="fw-stat-label">Pass</div></div>';
    if (fw.condPass) fhtml += '<div><div class="fw-stat cp">'+(fw.condPass||0)+'</div><div class="fw-stat-label">Cond.</div></div>';
    fhtml += '<div><div class="fw-stat warn">'+fw.warn+'</div><div class="fw-stat-label">Warn</div></div>';
    fhtml += '<div><div class="fw-stat fail">'+fw.fail+'</div><div class="fw-stat-label">Fail</div></div>';
    fhtml += '</div>';
    fhtml += '<div class="fw-total">'+total+' controls assessed \u2022 '+label.desc+'</div>';
    fhtml += '<div class="fw-bar">';
    if (pPct) fhtml += '<div class="fw-bar-pass" style="width:'+pPct+'%"></div>';
    if (cpPct) fhtml += '<div class="fw-bar-cp" style="width:'+cpPct+'%"></div>';
    if (wPct) fhtml += '<div class="fw-bar-warn" style="width:'+wPct+'%"></div>';
    if (fPct) fhtml += '<div class="fw-bar-fail" style="width:'+fPct+'%"></div>';
    fhtml += '</div>';
    // Control detail list (shown when card is expanded)
    fhtml += '<div class="fw-controls">';
    var ctrls = fw.controls || {};
    var ctrlKeys = Object.keys(ctrls).sort(function(a,b) {
      var rank = {'fail':0,'warn':1,'conditional-pass':2,'pass':3,'info':4};
      return (rank[ctrls[a]]||5) - (rank[ctrls[b]]||5);
    });
    ctrlKeys.forEach(function(ctrlId) {
      var st = ctrls[ctrlId];
      // Look up human name - for CMMC, strip prefix to get NIST ID
      var lookupId = ctrlId;
      if (fk === 'cmmc') {
        var parts = ctrlId.split('-'); if (parts.length >= 2) lookupId = parts.slice(1).join('-');
      }
      var ctrlName = CTRL_NAMES[ctrlId] || CTRL_NAMES[lookupId] || '';
      // Find contributing checks
      var contributing = [];
      DATA.checks.forEach(function(c) {
        if (c.frameworks && c.frameworks[fk]) {
          var fwCtrls = c.frameworks[fk];
          if (fwCtrls && fwCtrls.indexOf(ctrlId) >= 0) contributing.push(c);
        }
      });
      fhtml += '<div class="ctrl-block">';
      fhtml += '<div class="ctrl-header"><div class="check-dot '+st+'"></div>';
      fhtml += '<div class="ctrl-id">'+ctrlId+'</div>';
      if (ctrlName) fhtml += '<div class="ctrl-label">'+ctrlName+'</div>';
      fhtml += '</div>';
      // Individual checks with their own status
      contributing.forEach(function(c) {
        var fixTag = '';
        if (!READONLY && c.fixable && c.status !== 'pass' && c.status !== 'info') {
          fixTag = '<span class="ctrl-fix" onclick="event.stopPropagation();applyFix(\''+c.fixId+'\',\''+c.id+'\')">FIX</span>';
        }
        fhtml += '<div class="ctrl-check"><div class="check-dot '+c.status+'"></div>';
        fhtml += '<span class="ctrl-check-title">'+c.title+'</span>';
        fhtml += fixTag+'</div>';
      });
      fhtml += '</div>';
    });
    fhtml += '</div>';
    fhtml += '</div>';
  });
  fhtml += '</div>';
  document.getElementById('compliance').innerHTML = fhtml;
}

function toggleScenario(el) { el.classList.toggle('open'); }

function toggleCheckDetail(e, el) {
  if (e.target.tagName === 'BUTTON') return;
  var item = el || e.currentTarget;
  if (!item || !item.classList.contains('check-item')) item = item.closest('.check-item');
  if (!item) return;
  item.classList.toggle('expanded');
}

function showFixModal(fixId, checkId, isFixAll) {
  if (READONLY) return;
  var fix = DATA.fixes[fixId] || {};
  var check = null;
  if (checkId) {
    DATA.checks.forEach(function(c) { if (c.id === checkId) check = c; });
  }
  pendingAction = isFixAll ? {type:'fixAll'} : {type:'fix', fixId:fixId, checkId:checkId};

  var title = fix.Name || fixId;
  document.getElementById('fix-modal-title').innerHTML = '&#x1F527; Apply Fix: ' + title;

  var desc = '';
  if (check && check.detail) desc += check.detail;
  if (isFixAll) desc = 'This will apply all safe fixes (those without caveats) in one batch. Each fix modifies system registry values or runs system commands.';
  document.getElementById('fix-modal-desc').innerHTML = desc;

  var impactEl = document.getElementById('fix-modal-impact');
  if (fix.Impact) {
    impactEl.innerHTML = '<strong>&#x26A0;&#xFE0F; Side effect:</strong> ' + fix.Impact;
    impactEl.style.display = 'block';
  } else { impactEl.style.display = 'none'; }

  var noteEl = document.getElementById('fix-modal-note');
  if (fix.Note) {
    noteEl.innerHTML = '<strong>&#x2139;&#xFE0F; Note:</strong> ' + fix.Note;
    noteEl.style.display = 'block';
  } else { noteEl.style.display = 'none'; }

  var restoreInfo = document.getElementById('fix-modal-restore-info');
  var restoreBtn = document.getElementById('fix-modal-restore-btn');
  if (!restoreCreated) {
    restoreInfo.innerHTML = '<strong>Recommended:</strong> Create a system restore point before making changes. This lets you undo every change with one click if anything goes wrong.';
    restoreBtn.innerHTML = '&#x2713; CREATE RESTORE &amp; APPLY';
  } else {
    restoreInfo.innerHTML = '&#x2713; A restore point was already created this session. You can create another if you want a checkpoint before this specific change.';
    restoreInfo.style.borderColor = '#22c55e';
    restoreBtn.innerHTML = '&#x2713; CREATE ANOTHER RESTORE &amp; APPLY';
  }

  document.getElementById('fix-modal').style.display = 'flex';
}

function hideFixModal() {
  document.getElementById('fix-modal').style.display = 'none';
  pendingAction = null;
}

function fixWithRestore() {
  document.getElementById('fix-modal').style.display = 'none';
  document.getElementById('restore-status').textContent = 'CHECK CONSOLE \u25B8 Approve restore point in PowerShell';
  document.getElementById('restore-status').style.display = 'block';
  document.getElementById('restore-status').style.color = '#7dd3fc';
  showConsolePrompt('Create System Restore Point');
  fetch('/restore-point', {method:'POST', headers:{'X-HT-Auth':AUTH_TOKEN}})
    .then(function(r) { return r.json(); })
    .then(function(result) {
      hideConsolePrompt();
      if (result.declined) {
        document.getElementById('restore-status').textContent = '\u26A0 Restore point declined by operator';
        document.getElementById('restore-status').style.color = '#f59e0b';
        setTimeout(function() { executePending(); }, 600);
        return;
      }
      restoreCreated = true;
      if (result.success) {
        document.getElementById('restore-status').textContent = '\u2713 ' + result.message;
        document.getElementById('restore-status').style.color = '#22c55e';
      } else {
        document.getElementById('restore-status').textContent = '\u26A0 ' + result.message;
        document.getElementById('restore-status').style.color = '#f59e0b';
      }
      setTimeout(function() { executePending(); }, 600);
    })
    .catch(function(err) {
      hideConsolePrompt();
      document.getElementById('restore-status').textContent = '\u26A0 Could not create restore point';
      document.getElementById('restore-status').style.color = '#f59e0b';
      setTimeout(function() { executePending(); }, 600);
    });
}

function fixSkipRestore() {
  document.getElementById('fix-modal').style.display = 'none';
  executePending();
}

function executePending() {
  if (!pendingAction) return;
  if (pendingAction.type === 'fix') {
    doApplyFix(pendingAction.fixId, pendingAction.checkId);
  } else if (pendingAction.type === 'fixAll') {
    doFixAll();
  }
  pendingAction = null;
}

function applyFix(fixId, checkId) {
  showFixModal(fixId, checkId, false);
}

function doApplyFix(fixId, checkId) {
  var btns = document.querySelectorAll('[id^="fix-' + checkId + '"],[id^="fixall-' + checkId + '"]');
  btns.forEach(function(b) { b.disabled = true; b.textContent = 'CHECK CONSOLE \u25B8'; b.style.minWidth = '140px'; });
  var fixName = (DATA.fixes[fixId] || {}).Name || fixId;
  showConsolePrompt('Fix: ' + fixName);
  fetch('/fix?id=' + fixId, {method:'POST', headers:{'X-HT-Auth':AUTH_TOKEN}})
    .then(function(r) { return r.json(); })
    .then(function(result) {
      hideConsolePrompt();
      btns.forEach(function(b) {
        if (result.declined) {
          b.textContent = 'DECLINED';
          b.disabled = false;
          b.title = 'Declined by console operator';
        } else if (result.success) {
          var vs = result.verifyState || 'unverified';
          if (vs === 'verified') {
            b.textContent = 'VERIFIED \u2713';
            b.classList.add('done');
            b.style.borderColor = 'rgba(34,197,94,0.5)';
          } else if (vs === 'failed_verification') {
            b.textContent = 'FAILED \u2717';
            b.style.borderColor = 'rgba(239,68,68,0.5)';
            b.style.color = '#f87171';
            b.title = result.verifyMessage || 'Verification failed - GPO override?';
          } else if (vs === 'pending_reboot') {
            b.textContent = 'REBOOT PENDING \u21BB';
            b.style.borderColor = 'rgba(245,158,11,0.5)';
            b.style.color = '#f59e0b';
            b.title = result.verifyMessage || 'Registry set correctly. Reboot required for change to take effect.';
          } else {
            b.textContent = 'APPLIED';
            b.classList.add('done');
            b.title = result.verifyMessage || 'Applied but could not auto-verify';
          }
          if (result.reboot) { needsReboot = true; document.getElementById('reboot').classList.add('show'); }
        } else {
          b.textContent = 'ERR';
          b.disabled = false;
          b.title = result.message || 'Unknown error';
        }
      });
      // Refresh dashboard data after fix to update posture/scenarios
      if (result.success) setTimeout(refreshData, 500);
    })
    .catch(function(err) {
      hideConsolePrompt();
      btns.forEach(function(b) { b.textContent = 'ERR'; b.disabled = false; b.title = err.message || 'Network error'; });
    });
}

function fixAll() {
  showFixModal('fix-all', null, true);
}

function doFixAll() {
  var btn = document.getElementById('fix-all-btn');
  btn.disabled = true;
  btn.textContent = 'CHECK CONSOLE \u25B8';
  showConsolePrompt('Fix All');
  fetch('/fix-all', {method:'POST', headers:{'X-HT-Auth':AUTH_TOKEN}})
    .then(function(r) { return r.json(); })
    .then(function(result) {
      hideConsolePrompt();
      if (result.declined) {
        btn.textContent = 'DECLINED';
        btn.disabled = false;
        btn.title = 'Declined by console operator';
        return;
      }
      if (result.count > 0) {
        var vCount = result.verifiedCount || 0;
        var fCount = result.failedVerifyCount || 0;
        var uCount = result.unverifiedCount || 0;
        if (fCount > 0) {
          btn.textContent = result.count + ' APPLIED (' + fCount + ' FAILED VERIFY)';
          btn.style.borderColor = 'rgba(239,68,68,0.5)';
        } else if ((result.pendingRebootCount || 0) > 0) {
          var pCount = result.pendingRebootCount || 0;
          btn.textContent = (result.count - pCount) + ' VERIFIED, ' + pCount + ' PENDING REBOOT';
          btn.style.borderColor = 'rgba(245,158,11,0.5)';
          btn.style.color = '#f59e0b';
          btn.classList.add('done');
        } else {
          btn.textContent = result.count + ' VERIFIED \u2713';
          btn.classList.add('done');
        }
        // Refresh dashboard to show updated posture
        setTimeout(refreshData, 500);
        (result.applied || []).forEach(function(fixId) {
          var isFailed = false;
          (result.failedVerifications || []).forEach(function(fv) { if (fv.indexOf(fixId) === 0) isFailed = true; });
          var isPending = false;
          (result.pendingReboots || []).forEach(function(pr) { if (pr === fixId) isPending = true; });
          document.querySelectorAll('.fix-btn').forEach(function(b) {
            if (b.getAttribute('onclick') && b.getAttribute('onclick').indexOf(fixId) >= 0) {
              if (isFailed) {
                b.textContent = 'FAILED \u2717';
                b.style.borderColor = 'rgba(239,68,68,0.5)';
                b.style.color = '#f87171';
              } else if (isPending) {
                b.textContent = 'REBOOT PENDING \u21BB';
                b.style.borderColor = 'rgba(245,158,11,0.5)';
                b.style.color = '#f59e0b';
              } else {
                b.textContent = 'VERIFIED \u2713';
                b.classList.add('done');
              }
              b.disabled = true;
            }
          });
        });
        if (result.reboot) { needsReboot = true; document.getElementById('reboot').classList.add('show'); }
      } else {
        btn.textContent = 'NONE APPLIED';
        btn.disabled = false;
      }
      var res = document.getElementById('fix-all-result');
      var parts = [];
      if (result.verifiedCount > 0) parts.push(result.verifiedCount + ' verified');
      if (result.pendingRebootCount > 0) parts.push(result.pendingRebootCount + ' pending reboot');
      if (result.unverifiedCount > 0) parts.push(result.unverifiedCount + ' unverified');
      if (result.failedVerifyCount > 0) parts.push(result.failedVerifyCount + ' FAILED verification (GPO override?)');
      if (result.errors && result.errors.length > 0) parts.push(result.errors.length + ' error(s)');
      if (parts.length > 0) {
        res.textContent = parts.join(' | ');
        res.style.color = (result.failedVerifyCount > 0) ? '#f87171' : (result.errors && result.errors.length > 0) ? '#f59e0b' : '#34d399';
      }
      res.classList.add('show');
    })
    .catch(function(err) {
      hideConsolePrompt();
      btn.textContent = 'ERROR';
      btn.disabled = false;
      btn.title = err.message || 'Network error';
    });
}

// render() is called after successful auth in doAuth()

// == Monitor bar rendering ==
function renderMonitorBar(mon) {
  var bar = document.getElementById('monitor-bar');
  if (!mon) { mon = {}; }
  var mh = '';
  if (mon.installed || mon.monitorInstalled) {
    var state = mon.state || mon.monitorState || 'unknown';
    var isActive = state === 'Ready' || state === 'Running';
    mh += '<span class="monitor-dot ' + (isActive ? 'active' : 'inactive') + '"></span>';
    mh += '<span class="monitor-label">DRIFT MONITOR: ' + (isActive ? 'ACTIVE' : state.toUpperCase()) + '</span>';
    var details = [];
    var lastRun = mon.lastRun || mon.monitorLastRun;
    var nextRun = mon.nextRun || mon.monitorNextRun;
    var driftN = mon.driftEvents || mon.monitorDriftEvents || 0;
    if (lastRun) details.push('Last: ' + lastRun);
    if (nextRun) details.push('Next: ' + nextRun);
    details.push(driftN > 0 ? driftN + ' drift event' + (driftN > 1 ? 's' : '') : 'No drift detected');
    var monDir = mon.monitorDir || 'C:\\ProgramData\\HardTarget';
    details.push('Logs: ' + monDir);
    mh += '<span class="monitor-detail">' + details.join(' &bull; ') + '</span>';
    if (!READONLY) mh += '<button class="mon-btn mon-uninstall" onclick="monitorUninstall()">STOP &amp; REMOVE</button>';
  } else {
    mh += '<span class="monitor-dot inactive"></span>';
    mh += '<span class="monitor-label">DRIFT MONITOR: OFF</span>';
    mh += '<span class="monitor-detail">Hourly background scan that detects when Windows Updates or policy changes silently weaken your security. Runs independently - no window, no browser needed. Logs to C:\\ProgramData\\HardTarget.</span>';
    if (!READONLY) mh += '<button class="mon-btn mon-install" onclick="monitorInstall()">ENABLE</button>';
  }
  bar.innerHTML = mh;
}

function monitorInstall() {
  if (!serverAlive) { alert('Server is not running. Cannot install monitor.'); return; }
  if (!confirm('Install the HardTarget Drift Monitor?\n\nThis creates a Windows Scheduled Task that:\n\u2022 Runs every hour silently in the background\n\u2022 Scans your security posture\n\u2022 Logs any changes to C:\\ProgramData\\HardTarget\n\u2022 You can remove it any time from this dashboard\n\nYou will need to approve this in the PowerShell console.')) return;
  var btn = document.querySelector('.mon-install');
  if (btn) { btn.textContent = 'CHECK CONSOLE \u25B8'; btn.disabled = true; }
  showConsolePrompt('Install Drift Monitor');
  fetch('/monitor-install', {method:'POST', headers:{'X-HT-Auth':AUTH_TOKEN}})
    .then(function(r) { return r.json(); })
    .then(function(result) {
      hideConsolePrompt();
      if (result.declined) { if (btn) { btn.textContent = 'DECLINED'; btn.disabled = false; } return; }
      if (result.success) { pollStatus(); }
      else { alert('Install failed: ' + result.message); if (btn) { btn.textContent = 'ENABLE'; btn.disabled = false; } }
    })
    .catch(function(err) { hideConsolePrompt(); alert('Error: ' + err.message); if (btn) { btn.textContent = 'ENABLE'; btn.disabled = false; } });
}

function monitorUninstall() {
  if (!serverAlive) { alert('Server is not running. Cannot remove monitor.'); return; }
  if (!confirm('Remove the HardTarget Drift Monitor?\n\nThis stops the hourly background scan. Your existing drift logs in C:\\ProgramData\\HardTarget are kept.\n\nYou will need to approve this in the PowerShell console.')) return;
  var btn = document.querySelector('.mon-uninstall');
  if (btn) { btn.textContent = 'CHECK CONSOLE \u25B8'; btn.disabled = true; }
  showConsolePrompt('Remove Drift Monitor');
  fetch('/monitor-uninstall', {method:'POST', headers:{'X-HT-Auth':AUTH_TOKEN}})
    .then(function(r) { return r.json(); })
    .then(function(result) {
      hideConsolePrompt();
      if (result.declined) { if (btn) { btn.textContent = 'DECLINED'; btn.disabled = false; } return; }
      if (result.success) { pollStatus(); }
      else { alert('Remove failed: ' + result.message); if (btn) { btn.textContent = 'STOP & REMOVE'; btn.disabled = false; } }
    })
    .catch(function(err) { hideConsolePrompt(); alert('Error: ' + err.message); if (btn) { btn.textContent = 'STOP & REMOVE'; btn.disabled = false; } });
}

// == Server heartbeat ==
var serverAlive = true;
var heartbeatFails = 0;

function formatUptime(s) {
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s/60) + 'm ' + (s%60) + 's';
  return Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm';
}

function pollStatus() {
  fetch('/status', {headers:{'X-HT-Auth':AUTH_TOKEN}, signal: AbortSignal.timeout(2000)})
    .then(function(r) { return r.json(); })
    .then(function(st) {
      heartbeatFails = 0;
      if (!serverAlive) {
        serverAlive = true;
        document.getElementById('conn-dot').className = 'conn-dot live';
        document.getElementById('conn-label').textContent = 'CONNECTED';
        document.getElementById('stop-btn').className = 'stop-btn';
        document.getElementById('stop-btn').textContent = 'STOP SERVER';
      }
      var parts = [];
      parts.push('Uptime ' + formatUptime(st.uptime));
      parts.push('Port ' + st.port);
      document.getElementById('conn-detail').textContent = parts.join(' \u2022 ');
      // Update monitor bar from live state
      renderMonitorBar(st);
    })
    .catch(function() {
      heartbeatFails++;
      if (heartbeatFails >= 2) {
        serverAlive = false;
        document.getElementById('conn-dot').className = 'conn-dot dead';
        document.getElementById('conn-label').textContent = 'DISCONNECTED';
        document.getElementById('conn-detail').textContent = 'Server is no longer running. The PowerShell window was closed or the server was stopped.';
        document.getElementById('stop-btn').className = 'stop-btn stopped';
        document.getElementById('stop-btn').textContent = 'STOPPED';
      }
    });
}

function stopServer() {
  if (!serverAlive) return;
  if (!confirm('Stop the HardTarget server? The dashboard will become read-only and fix buttons will stop working.')) return;
  document.getElementById('stop-btn').textContent = 'STOPPING...';
  document.getElementById('stop-btn').disabled = true;
  fetch('/shutdown', {method:'POST', headers:{'X-HT-Auth':AUTH_TOKEN}})
    .then(function() {
      serverAlive = false;
      document.getElementById('conn-dot').className = 'conn-dot dead';
      document.getElementById('conn-label').textContent = 'STOPPED';
      document.getElementById('conn-detail').textContent = 'Server shut down from dashboard. You can close this tab.';
      document.getElementById('stop-btn').className = 'stop-btn stopped';
      document.getElementById('stop-btn').textContent = 'STOPPED';
    })
    .catch(function() {});
}

pollStatus();
setInterval(pollStatus, 3000);
</script>
</body>
</html>
"@
    
    # No scan data embedded in HTML - fetched via authenticated /data endpoint after auth
    # This prevents unauthenticated local processes from scraping scan results
    
    # Inject read-only mode flag into dashboard JS
    if ($script:IsReadOnly) {
        $html = $html.Replace('var READONLY = false;', 'var READONLY = true;')
    }
    
    return $html
}


# ============================================================================
#  SCAN: DATA EXPOSURE SURFACE
# ============================================================================
function Test-ForensicSurface {
    Write-Section 'DATA EXPOSURE SURFACE' '[TRACE]'
    Write-Host '        Data exposure checks [IN DEVELOPMENT] - not included in overall posture' -ForegroundColor DarkGray
    Write-Host ''
    
    # Recent Documents tracking
    $recentPolicy = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoRecentDocsHistory -ErrorAction SilentlyContinue
    if ($recentPolicy -and $recentPolicy.NoRecentDocsHistory -eq 1) {
        Write-Check 'pass' 'Recent Documents tracking is DISABLED'
        Add-Check -Section 'forensic-surface' -Id 'fs-recent-docs' -Status 'pass' -Title 'Recent Documents tracking disabled' -Detail 'Windows will not record which files you open.' -Scenarios @('coercion')
    } else {
        Write-Check 'fail' 'Recent Documents tracking is ENABLED' 'Every opened file is logged'
        Add-Check -Section 'forensic-surface' -Id 'fs-recent-docs' -Status 'fail' `
            -Title 'Recent Documents tracking is ENABLED' `
            -Detail 'Windows records every file you open with timestamps. A forensic examiner can reconstruct your file access history.' `
            -FixId 'fs-recent-docs' -Scenarios @('coercion')
    }
    
    # Jump Lists
    $jumpPolicy = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoRecentDocsMenu -ErrorAction SilentlyContinue
    if ($jumpPolicy -and $jumpPolicy.NoRecentDocsMenu -eq 1) {
        Write-Check 'pass' 'Jump Lists are DISABLED'
        Add-Check -Section 'forensic-surface' -Id 'fs-jump-lists' -Status 'pass' -Title 'Jump Lists disabled' -Detail 'Per-application file access history is not recorded.' -Scenarios @('coercion')
    } else {
        $jlPath = Join-Path $env:APPDATA 'Microsoft\Windows\Recent\AutomaticDestinations'
        $jlCount = 0
        if (Test-Path $jlPath) { $jlCount = (Get-ChildItem $jlPath -File -ErrorAction SilentlyContinue | Measure-Object).Count }
        $jlDetail = 'Jump Lists record per-application file access history.'
        if ($jlCount -gt 0) { $jlDetail += " Found $jlCount jump list files." }
        Write-Check 'fail' 'Jump Lists are ENABLED' 'Per-app file history recorded'
        Add-Check -Section 'forensic-surface' -Id 'fs-jump-lists' -Status 'fail' `
            -Title 'Jump Lists are ENABLED' `
            -Detail $jlDetail `
            -FixId 'fs-jump-lists' -Scenarios @('coercion')
    }
    
    # Thumbnail cache
    $thumbPolicy = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name DisableThumbnailCache -ErrorAction SilentlyContinue
    if ($thumbPolicy -and $thumbPolicy.DisableThumbnailCache -eq 1) {
        Write-Check 'pass' 'Thumbnail caching is DISABLED'
        Add-Check -Section 'forensic-surface' -Id 'fs-thumbnails' -Status 'pass' -Title 'Thumbnail cache disabled' -Detail 'Image thumbnails are not persisted to disk.' -Scenarios @('coercion')
    } else {
        $thumbPath = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Explorer'
        $thumbCount = 0
        if (Test-Path $thumbPath) { $thumbCount = (Get-ChildItem $thumbPath -Filter 'thumbcache_*.db' -ErrorAction SilentlyContinue | Measure-Object).Count }
        $thumbDetail = 'Thumbnails of viewed images persist on disk after the original files are deleted.'
        if ($thumbCount -gt 0) { $thumbDetail += " Found $thumbCount thumbnail databases." }
        Write-Check 'fail' 'Thumbnail caching is ENABLED' 'Image previews persist after file deletion'
        Add-Check -Section 'forensic-surface' -Id 'fs-thumbnails' -Status 'fail' `
            -Title 'Thumbnail caching is ENABLED' `
            -Detail $thumbDetail `
            -FixId 'fs-thumbnails' -Scenarios @('coercion')
    }
    
    # Prefetch
    $pfParams = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -ErrorAction SilentlyContinue
    $pfEnabled = $true
    if ($pfParams -and ($pfParams.PSObject.Properties.Name -contains 'EnablePrefetcher') -and $pfParams.EnablePrefetcher -eq 0) { $pfEnabled = $false }
    if (-not $pfEnabled) {
        Write-Check 'pass' 'Prefetch is DISABLED'
        Add-Check -Section 'forensic-surface' -Id 'fs-prefetch' -Status 'pass' -Title 'Prefetch disabled' -Detail 'No program launch history recorded in Prefetch.' -Scenarios @('coercion')
    } else {
        $pfPath = Join-Path $script:TrustedSystemRoot 'Prefetch'
        $pfCount = 0
        if (Test-Path $pfPath) { $pfCount = (Get-ChildItem $pfPath -Filter '*.pf' -ErrorAction SilentlyContinue | Measure-Object).Count }
        $pfDetail = 'Prefetch records every executable launched with timestamps and frequency.'
        if ($pfCount -gt 0) { $pfDetail += " Found $pfCount prefetch files." }
        Write-Check 'fail' 'Prefetch is ENABLED' 'Every program launch is logged'
        Add-Check -Section 'forensic-surface' -Id 'fs-prefetch' -Status 'fail' `
            -Title 'Prefetch is ENABLED' `
            -Detail $pfDetail `
            -FixId 'fs-prefetch' -Scenarios @('coercion')
    }
    
    # Superfetch / SysMain
    $sfEnabled = $true
    if ($pfParams -and ($pfParams.PSObject.Properties.Name -contains 'EnableSuperfetch') -and $pfParams.EnableSuperfetch -eq 0) { $sfEnabled = $false }
    $sysMainSvc = Get-Service -Name SysMain -ErrorAction SilentlyContinue
    if ($sysMainSvc -and $sysMainSvc.StartType -eq 'Disabled') { $sfEnabled = $false }
    if (-not $sfEnabled) {
        Write-Check 'pass' 'Superfetch/SysMain is DISABLED'
        Add-Check -Section 'forensic-surface' -Id 'fs-superfetch' -Status 'pass' -Title 'Superfetch/SysMain disabled' -Detail 'App launch patterns are not recorded.' -Scenarios @('coercion')
    } else {
        Write-Check 'warn' 'Superfetch/SysMain is ENABLED' 'Records app launch patterns'
        Add-Check -Section 'forensic-surface' -Id 'fs-superfetch' -Status 'warn' `
            -Title 'Superfetch/SysMain is ENABLED' `
            -Detail 'SysMain pre-loads frequently used applications and records usage patterns for prediction.' `
            -FixId 'fs-superfetch' -Scenarios @('coercion')
    }
    
    # UserAssist
    $uaPath1 = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count'
    $uaPath2 = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count'
    $uaCount = 0
    try {
        if (Test-Path $uaPath1) { $uaCount += (Get-ItemProperty -Path $uaPath1 -ErrorAction SilentlyContinue).PSObject.Properties.Count - 2 }
        if (Test-Path $uaPath2) { $uaCount += (Get-ItemProperty -Path $uaPath2 -ErrorAction SilentlyContinue).PSObject.Properties.Count - 2 }
    } catch {}
    if ($uaCount -le 0) {
        Write-Check 'pass' 'UserAssist history is empty'
        Add-Check -Section 'forensic-surface' -Id 'fs-user-assist' -Status 'pass' -Title 'UserAssist history is empty' -Detail 'No ROT13-encoded program launch records found.' -Scenarios @('coercion')
    } else {
        Write-Check 'warn' "UserAssist has $uaCount entries" 'ROT13-encoded list of every program launched'
        Add-Check -Section 'forensic-surface' -Id 'fs-user-assist' -Status 'warn' `
            -Title "UserAssist records $uaCount program launches" `
            -Detail 'UserAssist stores a ROT13-encoded list of every program launched with run counts and timestamps. Trivially decoded by forensic tools.' `
            -FixId 'fs-user-assist' -Scenarios @('coercion')
    }
    
    # Windows Timeline / Activity History
    $actFeed = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableActivityFeed -ErrorAction SilentlyContinue
    $actPublish = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name PublishUserActivities -ErrorAction SilentlyContinue
    $timelineOff = ($actFeed -and $actFeed.EnableActivityFeed -eq 0) -or ($actPublish -and $actPublish.PublishUserActivities -eq 0)
    if ($timelineOff) {
        Write-Check 'pass' 'Windows Timeline/Activity History is DISABLED'
        Add-Check -Section 'forensic-surface' -Id 'fs-timeline' -Status 'pass' -Title 'Activity History disabled' -Detail 'Cross-device activity feed is not recorded.' -Scenarios @('coercion')
    } else {
        Write-Check 'warn' 'Windows Timeline/Activity History may be ENABLED'
        Add-Check -Section 'forensic-surface' -Id 'fs-timeline' -Status 'warn' `
            -Title 'Windows Timeline/Activity History not disabled' `
            -Detail 'Activity History records app usage, document access, and browsing across devices. May sync to Microsoft cloud.' `
            -FixId 'fs-timeline' -Scenarios @('coercion')
    }
    
    # Windows Search Indexing
    $wsearch = Get-Service -Name WSearch -ErrorAction SilentlyContinue
    if ($wsearch -and $wsearch.Status -eq 'Running') {
        Write-Check 'warn' 'Windows Search Indexing is RUNNING' 'Indexes document contents'
        Add-Check -Section 'forensic-surface' -Id 'fs-search-index' -Status 'warn' `
            -Title 'Windows Search Indexing is RUNNING' `
            -Detail 'Windows Search indexes the content of documents, emails, and files. The index database persists searchable text even after files are deleted.' `
            -FixId 'fs-search-index' -Scenarios @('coercion')
    } else {
        Write-Check 'pass' 'Windows Search Indexing is stopped or disabled'
        Add-Check -Section 'forensic-surface' -Id 'fs-search-index' -Status 'pass' -Title 'Windows Search stopped/disabled' -Detail 'Search indexing is not active.' -Scenarios @('coercion')
    }
    
    # PowerShell history
    $psHistoryPath = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    $psHistoryExists = Test-Path $psHistoryPath
    $psHistoryLines = 0
    if ($psHistoryExists) {
        try { $psHistoryLines = (Get-Content $psHistoryPath -ErrorAction SilentlyContinue | Measure-Object).Count } catch {}
    }
    if (-not $psHistoryExists -or $psHistoryLines -eq 0) {
        Write-Check 'pass' 'PowerShell history is empty or absent'
        Add-Check -Section 'forensic-surface' -Id 'fs-ps-history' -Status 'pass' -Title 'PowerShell history clean' -Detail 'No command history file found.' -Scenarios @('coercion')
    } else {
        Write-Check 'warn' "PowerShell history has $psHistoryLines commands" 'Every PS command you have typed'
        Add-Check -Section 'forensic-surface' -Id 'fs-ps-history' -Status 'warn' `
            -Title "PowerShell history: $psHistoryLines commands recorded" `
            -Detail 'PSReadLine saves every PowerShell command to a plaintext file. Contains passwords, paths, and commands that reveal your activities.' `
            -FixId 'fs-ps-history' -Scenarios @('coercion')
    }
    
    # BAM (Background Activity Moderator)
    $bamPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
    $bamEntries = 0
    try {
        if (Test-Path $bamPath) {
            Get-ChildItem $bamPath -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                $bamEntries += ($props.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider','PSDrive','Version','SequenceNumber') }).Count
            }
        }
    } catch {}
    if ($bamEntries -le 0) {
        Write-Check 'pass' 'Background Activity Monitor is clean'
        Add-Check -Section 'forensic-surface' -Id 'fs-bam' -Status 'pass' -Title 'BAM/DAM state is clean' -Detail 'No executable run history in Background Activity Moderator.' -Scenarios @('coercion')
    } else {
        Write-Check 'warn' "BAM has $bamEntries executable entries" 'Records program paths with timestamps'
        Add-Check -Section 'forensic-surface' -Id 'fs-bam' -Status 'warn' `
            -Title "BAM records $bamEntries executable runs" `
            -Detail 'Background Activity Moderator records executable paths with last-run timestamps. Used by forensic examiners to establish program execution timeline.' `
            -FixId 'fs-bam' -Scenarios @('coercion')
    }
    
    # Network Profiles
    $netProfilePath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
    $netProfiles = 0
    try {
        if (Test-Path $netProfilePath) {
            $netProfiles = (Get-ChildItem $netProfilePath -ErrorAction SilentlyContinue | Measure-Object).Count
        }
    } catch {}
    if ($netProfiles -le 1) {
        Write-Check 'pass' 'Network profile history is minimal'
        Add-Check -Section 'forensic-surface' -Id 'fs-network-profiles' -Status 'pass' -Title 'Network history minimal' -Detail "Only $netProfiles network profile(s) recorded." -Scenarios @('coercion')
    } else {
        Write-Check 'warn' "$netProfiles network profiles recorded" 'Every WiFi/Ethernet network joined with dates'
        Add-Check -Section 'forensic-surface' -Id 'fs-network-profiles' -Status 'warn' `
            -Title "$netProfiles network profiles recorded" `
            -Detail 'Windows records every network you have joined with first/last connect timestamps. Reveals your location history.' `
            -FixId 'fs-network-profiles' -Scenarios @('coercion')
    }
    
    # ShellBags
    $shellBagPath = 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\BagMRU'
    $shellBagCount = 0
    try {
        if (Test-Path $shellBagPath) {
            $shellBagCount = (Get-ItemProperty -Path $shellBagPath -ErrorAction SilentlyContinue).PSObject.Properties.Count - 2
        }
    } catch {}
    if ($shellBagCount -le 0) {
        Write-Check 'pass' 'ShellBags history is empty'
        Add-Check -Section 'forensic-surface' -Id 'fs-shellbags' -Status 'pass' -Title 'ShellBags clean' -Detail 'No folder navigation history recorded.' -Scenarios @('coercion')
    } else {
        Write-Check 'warn' "ShellBags has $shellBagCount entries" 'Records every folder you browsed'
        Add-Check -Section 'forensic-surface' -Id 'fs-shellbags' -Status 'warn' `
            -Title "ShellBags records $shellBagCount folder entries" `
            -Detail 'ShellBags record every folder you navigated in Explorer, including deleted or dismounted volumes.' `
            -FixId 'fs-shellbags' -Scenarios @('coercion')
    }
    
    # USB Device History
    $usbHistPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    $usbDevices = 0
    try {
        if (Test-Path $usbHistPath) {
            $usbDevices = (Get-ChildItem $usbHistPath -ErrorAction SilentlyContinue | Measure-Object).Count
        }
    } catch {}
    if ($usbDevices -le 0) {
        Write-Check 'pass' 'No USB storage device history'
        Add-Check -Section 'forensic-surface' -Id 'fs-usb-history' -Status 'pass' -Title 'USB device history clean' -Detail 'No historical USB storage entries found.' -Scenarios @('coercion')
    } else {
        Write-Check 'info' "$usbDevices USB storage device types in history"
        Add-Check -Section 'forensic-surface' -Id 'fs-usb-history' -Status 'info' `
            -Title "$usbDevices USB storage device types recorded" `
            -Detail 'Windows records every USB storage device ever connected, with serial numbers and timestamps.' `
            -Scenarios @('coercion')
    }

    # Amcache - SHA1 hashes of every executed program
    $amcachePath = Join-Path $script:TrustedSystemRoot 'AppCompat\Programs\Amcache.hve'
    if (Test-Path $amcachePath) {
        try {
            $amcacheSize = [math]::Round((Get-Item $amcachePath -Force).Length / 1KB)
            $amcacheAge = [math]::Round(((Get-Date) - (Get-Item $amcachePath -Force).LastWriteTime).TotalDays)
        } catch { $amcacheSize = 0; $amcacheAge = 0 }
        Write-Check 'warn' "Amcache present (${amcacheSize}KB, modified ${amcacheAge}d ago)" 'SHA1 hashes of every program run'
        Add-Check -Section 'forensic-surface' -Id 'fs-amcache' -Status 'warn' `
            -Title "Amcache records program execution history (${amcacheSize}KB)" `
            -Detail "Amcache.hve stores SHA1 hashes, file paths, sizes, and timestamps for every executed program, installed application, and loaded driver. Last modified ${amcacheAge} days ago. Proves specific software was run even after deletion." `
            -FixId 'fs-amcache' -Scenarios @('coercion')
    } else {
        Write-Check 'pass' 'Amcache.hve not found'
        Add-Check -Section 'forensic-surface' -Id 'fs-amcache' -Status 'pass' -Title 'Amcache not found' -Detail '' -Scenarios @('coercion')
    }

    # AppCompatCache (ShimCache) - persists program execution across reboots
    try {
        $shimData = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction Stop
        $shimSizeKB = [math]::Round($shimData.AppCompatCache.Length / 1KB, 1)
        Write-Check 'warn' "AppCompatCache active (${shimSizeKB}KB)" 'Program execution persists across reboots'
        Add-Check -Section 'forensic-surface' -Id 'fs-shimcache' -Status 'warn' `
            -Title "AppCompatCache (ShimCache) records program execution (${shimSizeKB}KB)" `
            -Detail "Logs executable paths, file sizes, and timestamps in the SYSTEM registry hive. Persists across reboots. One of the top forensic artifacts for establishing which programs were run." `
            -FixId 'fs-shimcache' -Scenarios @('coercion')
    } catch {
        Write-Check 'info' 'Could not read AppCompatCache'
        Add-Check -Section 'forensic-surface' -Id 'fs-shimcache' -Status 'info' -Title 'AppCompatCache status unknown' -Detail 'Could not read the ShimCache registry value.' -Scenarios @('coercion')
    }

    # SRUM - per-application network/energy/CPU usage for 30-60 days
    $srumPath = Join-Path $script:TrustedSystemRoot 'System32\sru\SRUDB.dat'
    if (Test-Path $srumPath) {
        try {
            $srumSize = [math]::Round((Get-Item $srumPath -Force).Length / 1MB, 1)
        } catch { $srumSize = 0 }
        Write-Check 'warn' "SRUM database present (${srumSize}MB)" 'Per-app network and energy usage history'
        Add-Check -Section 'forensic-surface' -Id 'fs-srum' -Status 'warn' `
            -Title "SRUM tracks per-application resource usage (${srumSize}MB)" `
            -Detail "System Resource Usage Monitor logs network bytes sent/received, energy usage, and execution time per application over 30-60 days. Reveals which apps were actively used and how much data they transferred." `
            -FixId 'fs-srum' -Scenarios @('coercion')
    } else {
        Write-Check 'pass' 'SRUM database not found'
        Add-Check -Section 'forensic-surface' -Id 'fs-srum' -Status 'pass' -Title 'SRUM not found' -Detail '' -Scenarios @('coercion')
    }

    # USN Journal - records every file system change
    # SECURITY (v0.59): Uses positional hex parsing instead of English labels.
    # fsutil output labels like "Maximum Size" are localized, but the hex values
    # and their order are consistent across all locales. The output always has:
    #   line 1: Journal ID, line 2: First Usn, line 3: Next Usn,
    #   line 4: Lowest Valid Usn, line 5: Max Usn, line 6: Maximum Size,
    #   line 7: Allocation Delta
    # We collect all 0x hex values and use the 6th as Maximum Size.
    try {
        $usnInfo = & $script:Bin.fsutil usn queryjournal $script:TrustedSystemDrive 2>&1 | Out-String
        $hexValues = [regex]::Matches($usnInfo, '0x[0-9a-fA-F]+')
        if ($hexValues.Count -ge 1 -and $usnInfo -notmatch 'error') {
            $maxSize = ''
            if ($hexValues.Count -ge 6) {
                $maxBytes = [Convert]::ToInt64($hexValues[5].Value, 16)
                $maxSize = "$([math]::Round($maxBytes / 1MB))MB max"
            }
            Write-Check 'info' "USN Journal active ($maxSize)" 'Records every file/folder change'
            Add-Check -Section 'forensic-surface' -Id 'fs-usn-journal' -Status 'info' `
                -Title "NTFS USN Journal is active ($maxSize)" `
                -Detail 'Logs every file creation, deletion, modification, and rename on this volume. Includes registry hive changes made by security tools. Cannot be disabled without breaking Windows.' `
                -Scenarios @('coercion')
        }
    } catch { }

    # Event Logs - primary forensic data source
    $logSummary = @()
    foreach ($logName in @('Security', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-TaskScheduler/Operational')) {
        try {
            $logInfo = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $sizeMB = [math]::Round($logInfo.FileSize / 1MB, 1)
            if ($sizeMB -gt 0 -and $logInfo.IsEnabled) {
                $shortName = if ($logName -eq 'Security') { 'Security' } elseif ($logName -match 'PowerShell') { 'PowerShell' } else { 'TaskSched' }
                $logSummary += "${shortName}: ${sizeMB}MB"
            }
        } catch { }
    }
    if ($logSummary.Count -gt 0) {
        $totalSummary = $logSummary -join ', '
        Write-Check 'info' "Event Logs: $totalSummary"
        Add-Check -Section 'forensic-surface' -Id 'fs-event-logs' -Status 'info' `
            -Title "Windows Event Logs ($totalSummary)" `
            -Detail 'Security log records logons and privilege use. PowerShell log records every script and command. Clearing Event Logs creates Event ID 1102 which is itself evidence of tampering. HardTarget does not clear or modify Event Logs.' `
            -Scenarios @('coercion')
    }

    # ETW Autologger sessions - kernel-level tracing
    $autologgers = @()
    try {
        $alPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger'
        if (Test-Path $alPath) {
            $autologgers = Get-ChildItem $alPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
        }
    } catch {}
    $secLoggers = @($autologgers | Where-Object { $_ -match 'DiagTrack|EventLog-Security|DefenderApi|DefenderAudit|SQMLogger|WiFiSession' })
    if ($secLoggers.Count -gt 0) {
        Write-Check 'info' "$($secLoggers.Count) ETW autologger sessions active"
        Add-Check -Section 'forensic-surface' -Id 'fs-etw' -Status 'info' `
            -Title "$($secLoggers.Count) ETW autologger sessions run at boot" `
            -Detail "Event Tracing for Windows generates kernel-level traces including process creation, network connections, and registry access. Active sessions: $($secLoggers -join ', '). Most cannot be safely disabled." `
            -Scenarios @('coercion')
    }

    # NTFS $MFT - inherent filesystem metadata
    Write-Check 'info' 'NTFS $MFT records all file existence history'
    Add-Check -Section 'forensic-surface' -Id 'fs-mft' -Status 'info' `
        -Title 'NTFS $MFT records all file existence history' `
        -Detail 'The Master File Table contains timestamps and names for every file that has ever existed on this volume, including deleted files. Cannot be cleared without reformatting. Any examiner with raw disk access will find file existence evidence here.' `
        -Scenarios @('coercion')

    # Volume Shadow Copies - can restore cleared data
    # SECURITY (v0.59): Uses Win32_ShadowCopy CIM class instead of parsing vssadmin
    # text output. vssadmin labels like "Shadow Copy ID" are localized (e.g.,
    # "ID de instantanea" on Spanish Windows), causing false passes on non-English systems.
    $shadowCount = 0
    try {
        $shadowCount = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop).Count
    } catch {}
    if ($shadowCount -gt 0) {
        Write-Check 'warn' "$shadowCount Volume Shadow Copy/Copies" 'Can restore previous system state'
        Add-Check -Section 'forensic-surface' -Id 'fs-shadow-copies' -Status 'warn' `
            -Title "$shadowCount Volume Shadow Copy snapshots exist" `
            -Detail 'Shadow copies contain point-in-time snapshots of the volume. An examiner can mount previous copies to recover data from before any hardening was performed.' `
            -FixId 'fs-shadow-copies' -Scenarios @('coercion')
    } else {
        Write-Check 'pass' 'No Volume Shadow Copies'
        Add-Check -Section 'forensic-surface' -Id 'fs-shadow-copies' -Status 'pass' -Title 'No shadow copies' -Detail '' -Scenarios @('coercion')
    }

    # WER - crash reports may contain process memory
    $werCount = 0
    try {
        $werPaths = @(
            (Join-Path $script:TrustedProgramData 'Microsoft\Windows\WER')
        )
        # SECURITY (v0.64): Iterate all user profiles instead of $env:LOCALAPPDATA
        # (which resolves to SYSTEM's profile when running as scheduled task)
        $dProfiles = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue
        foreach ($dp in $dProfiles) {
            $werPaths += Join-Path $dp.FullName 'AppData\Local\Microsoft\Windows\WER'
            $werPaths += Join-Path $dp.FullName 'AppData\Local\CrashDumps'
        }
        foreach ($wp in $werPaths) {
            if (Test-Path $wp) { $werCount += (Get-ChildItem $wp -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count }
        }
    } catch {}
    if ($werCount -gt 10) {
        Write-Check 'warn' "$werCount WER crash report files" 'May contain memory dumps'
        Add-Check -Section 'forensic-surface' -Id 'fs-wer' -Status 'warn' `
            -Title "$werCount Windows Error Reporting files" `
            -Detail 'Crash reports can contain mini-dumps with process memory, loaded modules, and sensitive data from the time of crash.' `
            -FixId 'fs-wer' -Scenarios @('coercion')
    } else {
        Write-Check 'pass' "WER reports minimal ($werCount files)"
        Add-Check -Section 'forensic-surface' -Id 'fs-wer' -Status 'pass' -Title 'WER reports minimal' -Detail '' -Scenarios @('coercion')
    }

    # Self-awareness: this scan creates its own traces
    Write-Check 'info' 'This scan itself creates forensic traces'
    Add-Check -Section 'forensic-surface' -Id 'fs-self-footprint' -Status 'info' `
        -Title 'Running HardTarget leaves its own traces' `
        -Detail 'This scan creates Prefetch, BAM, Amcache, USN journal, and PowerShell log entries. An examiner will see that a security scanner was run and when. Factor this into your threat model.'

    # Coming soon
    Write-Host ''
    Write-Host '        Coming soon:' -ForegroundColor DarkCyan
    Write-Host '         - Key escrow to team admin' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '        Data exposure checks do not affect overall posture score.' -ForegroundColor DarkGray
    Write-Host ''

    Add-Check -Section 'forensic-surface' -Id 'fs-key-escrow' -Status 'info' -Title 'Key escrow to team admin' -Detail 'COMING SOON - Escrow BitLocker recovery key to your team administrator. Enables remote unlock if compelled to change credentials, and key rotation before high-risk travel.' -Scenarios @('coercion')
}
# ============================================================================
#  MAIN
# ============================================================================
function Run-FullScan {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    Write-Host '    [Step 1/11] BIOS...' -ForegroundColor DarkGray
    try { Test-BiosFirmware } catch { Write-Host "    [ERROR] BIOS scan: $_" -ForegroundColor Red }
    
    Write-Host '    [Step 2/11] Sleep...' -ForegroundColor DarkGray
    try { Test-SleepStates } catch { Write-Host "    [ERROR] Sleep scan: $_" -ForegroundColor Red }
    
    Write-Host '    [Step 3/11] TPM...' -ForegroundColor DarkGray
    try { Test-TPM } catch { Write-Host "    [ERROR] TPM scan: $_" -ForegroundColor Red }
    
    Write-Host '    [Step 4/11] DMA...' -ForegroundColor DarkGray
    try { Test-DMAExposure } catch { Write-Host "    [ERROR] DMA scan: $_" -ForegroundColor Red }
    
    Write-Host '    [Step 5/11] Encryption...' -ForegroundColor DarkGray
    try { Test-Encryption } catch { Write-Host "    [ERROR] Encryption scan: $_" -ForegroundColor Red }
    
    Write-Host '    [Step 6/11] Memory...' -ForegroundColor DarkGray
    try { Test-MemoryResidue } catch { Write-Host "    [ERROR] Memory scan: $_" -ForegroundColor Red }
    
    Write-Host '    [Step 7/11] Access...' -ForegroundColor DarkGray
    try { Test-ScreenLock } catch { Write-Host "    [ERROR] Access scan: $_" -ForegroundColor Red }
    
    Write-Host '    [Step 8/11] Data Exposure Surface...' -ForegroundColor DarkGray
    try { Test-ForensicSurface } catch { Write-Host "    [ERROR] Data exposure scan: $_" -ForegroundColor Red }
    
    $sw.Stop()
    
    # v0.51: Post-processing - append edition context for GP-dependent checks on Home
    if ($script:WindowsEdition -eq 'Home') {
        $gpDependentChecks = @{
            'usb-storage'      = 'Requires Group Policy (Pro/Enterprise). Cannot be enforced on Windows Home.'
            'usb-install'      = 'Requires Group Policy (Pro/Enterprise). Cannot be enforced on Windows Home.'
            'removable-encrypt'= 'Requires BitLocker + Group Policy. Not available on Windows Home.'
            'bl-network-unlock'= 'Requires BitLocker + Group Policy. Not available on Windows Home.'
        }
        for ($i = 0; $i -lt $script:JsonChecks.Count; $i++) {
            $check = $script:JsonChecks[$i]
            if ($gpDependentChecks.ContainsKey($check.id) -and $check.status -ne 'pass') {
                $edNote = $gpDependentChecks[$check.id]
                $script:JsonChecks[$i].detail = $check.detail + " [EDITION: $edNote]"
                $script:JsonChecks[$i]['editionLimited'] = $true
            }
        }
    }
    
    Write-Summary
    
    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    Write-Host "    Scan completed in $elapsed seconds." -ForegroundColor DarkGray
    
    # Save JSON
    Write-Host '    [Step 9/11] Saving JSON...' -ForegroundColor DarkGray
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $jsonPath = Join-Path $script:UserOutputDir "HardTarget_scan_$timestamp.json"
    try {
        $jsonContent = Get-ScanJson
        Write-SafeFile -Path $jsonPath -Content ($jsonContent)
        Write-Host "    Saved: $jsonPath" -ForegroundColor Green
        # SECURITY (v0.39): Remind operator that scan results are sensitive
        Write-Host '    NOTE: Scan results contain detailed security posture. Store securely.' -ForegroundColor DarkGray
    } catch {
        Write-Host "    [ERROR] Could not save JSON: $_" -ForegroundColor Red
        $jsonPath = $null
    }
    
    # Audit mode: scan + JSON only, no dashboard, no server
    if ($script:IsAuditMode) {
        Write-Host ''
        Write-Host '    Report mode: scan complete. JSON saved. No dashboard, no server.' -ForegroundColor Cyan
        if ($jsonPath) { Write-Host "    JSON: $jsonPath" -ForegroundColor Green }
        Write-Host ''
        return
    }
    
    # DryRun mode: show what fixes would do, then exit
    if ($script:IsDryRun) {
        Write-Host ''
        Write-Host '    === DRY RUN: Fix Preview ===' -ForegroundColor Cyan
        $fixableChecks = $script:JsonChecks | Where-Object { $_.fixable -and $_.status -notin @('pass', 'info') -and $_.fixId }
        if ($fixableChecks.Count -eq 0) {
            Write-Host '    No fixes needed.' -ForegroundColor Green
        } else {
            foreach ($check in $fixableChecks) {
                Apply-Fix -FixId $check.fixId | Out-Null
            }
        }
        Write-Host ''
        Write-Host "    $($fixableChecks.Count) fixes previewed. No changes made." -ForegroundColor Cyan
        Write-Host ''
        return
    }
    
    # Generate HTML
    Write-Host '    [Step 10/11] Generating dashboard...' -ForegroundColor DarkGray
    try {
        $html = Get-DashboardHtml
        Write-Host "    Dashboard HTML generated ($(($html.Length / 1024).ToString('0.0')) KB)" -ForegroundColor Green
    } catch {
        Write-Host "    [ERROR] Dashboard generation failed: $_" -ForegroundColor Red
        Read-Host '    Press Enter to exit'
        return
    }
    
    # Start server (blocks until Enter or dashboard Stop)
    Write-Host '    [Step 11/11] Starting server...' -ForegroundColor DarkGray
    try {
        Start-FixServer -HtmlContent $html -JsonPath $jsonPath
    } catch {
        Write-Host "    [ERROR] Server failed: $_" -ForegroundColor Red
    }
    
    Write-Host ''
    Write-Host '    Goodbye.' -ForegroundColor DarkGray
    Start-Sleep -Seconds 1
}

# Entry point
# SECURITY (v0.39): $MyInvocation.MyCommand.Path can be $null when script is run
# from a string, ScriptBlock, or piped input. Guard against this.
# SECURITY (v0.76): When running via in-memory bootstrapper, $MyInvocation.MyCommand
# is a ScriptBlock (no .Path property). STEP A already set $script:ScriptPath and
# $script:VerifiedScriptBytes from the bootstrapper. Skip disk-based resolution.
# SECURITY (v0.76): When running already-elevated (admin prompt, SCCM, Intune),
# the bootstrapper path is skipped. We MUST still populate $script:VerifiedScriptBytes
# here, or Install-HardTargetMonitor will fall back to copying from disk -- which
# may have been swapped during the dashboard session (infinite TOCTOU window).
if (-not $script:ScriptPath) {
    $rawPath = if ($PSCommandPath) { $PSCommandPath }
               elseif ($MyInvocation.MyCommand -is [System.Management.Automation.ExternalScriptInfo]) { $MyInvocation.MyCommand.Path }
               else { $null }
    if (-not $rawPath) {
        try {
            $def = $MyInvocation.MyCommand.Definition
            if ($def -and (Test-Path $def -ErrorAction SilentlyContinue)) {
                $rawPath = $def
            }
        } catch {}
    }
    if ($rawPath) {
        # Resolve path canonically for display and Install-HardTargetMonitor destination.
        $epResolved = $null
        try { $epResolved = Resolve-CanonicalScriptPath $rawPath } catch {}
        $script:ScriptPath = if ($epResolved) { $epResolved } else { $rawPath }
    }
    # SECURITY (v0.80): Populate VerifiedScriptBytes from the EXECUTING ScriptBlock,
    # not by re-reading the disk file. PowerShell reads the file, builds the AST, and
    # closes the handle before our code runs. An attacker can swap the file between
    # that initial read and our entry point. Reading from disk here would capture the
    # attacker's payload. $MyInvocation.MyCommand.ScriptBlock contains the AST that
    # is actually executing -- it is immune to disk swaps after parse time.
    if (-not $script:VerifiedScriptBytes) {
        try {
            $executingText = $MyInvocation.MyCommand.ScriptBlock.ToString()
            $script:VerifiedScriptBytes = [System.Text.Encoding]::UTF8.GetBytes($executingText)
        }
        catch {
            # ScriptBlock.ToString() unavailable (shouldn't happen, but fail-closed)
            # Leave VerifiedScriptBytes null; Install-HardTargetMonitor will use disk fallback
        }
    }
}
try {
    if ($Monitor) {
        # Background mode: run scan, compare to baseline, output drift events
        # SECURITY (v0.43): Removed blanket $ErrorActionPreference = 'SilentlyContinue'.
        # v0.40 suppressed all non-terminating errors for the entire monitor execution,
        # undoing the v0.39 fix. Individual operations now use explicit -ErrorAction
        # where failure is expected. The integrity check and scan functions already
        # have their own try/catch blocks; baseline/drift logic below does too.
        # The monitor-safe catch below ensures any unhandled error exits cleanly
        # instead of reaching the outer catch which calls Read-Host (hangs headless SYSTEM).
        try {
        $monitorDir = if ($OutputDir) { $OutputDir } else { Join-Path $script:TrustedProgramData 'HardTarget' }
        # SECURITY (v0.73): Use Initialize-SecureDirectory instead of bare New-Item.
        # The monitor runs as NT AUTHORITY\SYSTEM via scheduled task. If an attacker
        # deletes the ACL-protected directory (requires admin), the old New-Item would
        # recreate it with inherited ProgramData ACLs (BUILTIN\Users writable).
        # Initialize-SecureDirectory applies the staging pattern or fast-path ACL lock.
        try { Initialize-SecureDirectory -Path $monitorDir } catch {
            # Monitor runs headless as SYSTEM -- cannot Read-Host. Log and abort.
            try { [System.Environment]::Exit(1) } catch { exit 1 }
        }
        
        # SECURITY (v0.39): Verify script integrity before running as SYSTEM.
        # Compare running script's hash against the InstalledHash stored at install time.
        # If mismatch, log critical event and abort - creates audit trail for tampering.
        # SECURITY (v0.40): FAIL-CLOSED integrity check. Default to $false, only set
        # $true on confirmed hash match or when verification is inapplicable.
        # v0.39 defaulted to $true - any exception silently bypassed the check.
        $integrityOk = $false
        try {
            $runningScript = if ($MyInvocation.MyCommand -is [System.Management.Automation.ExternalScriptInfo]) { $MyInvocation.MyCommand.Path } else { $null }
            if (-not $runningScript) {
                # No script path (piped input / string invocation) - can't verify, allow.
                # Scheduled task always has a path, so this only fires in manual scenarios.
                $integrityOk = $true
            } else {
                $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HardTarget'
                $storedHash = (Get-ItemProperty -Path $regPath -Name 'InstalledHash' -ErrorAction SilentlyContinue).InstalledHash
                if (-not $storedHash) {
                    # H-3 FIX (v0.45): Check if Uninstall key exists (proves prior install).
                    # If key exists but hash is missing, an attacker may have deleted it.
                    # Only allow "no stored hash" when the entire Uninstall key is absent.
                    if (Test-Path $regPath) {
                        # Uninstall key exists but InstalledHash is missing = suspicious
                        $tamperMsg = "HardTarget INTEGRITY FAILURE: InstalledHash missing from registry but Uninstall key exists. Possible tampering. Re-install the monitor to restore integrity checking."
                        try { Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9999 -EntryType Error -Message $tamperMsg -ErrorAction SilentlyContinue } catch {}
                        $monNdjsonPath = Join-Path $monitorDir 'HardTarget_monitor.ndjson'
                        try { Write-SafeFile -Path $monNdjsonPath -Content (@{ timestamp = (Get-Date -Format 'o'); type = 'integrity_failure'; error = $tamperMsg; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress) -Append } catch {}
                        # $integrityOk remains $false - fail closed
                    } else {
                        # No Uninstall key at all = legacy install (pre-v0.39) or registry cleared. Allow.
                        $integrityOk = $true
                    }
                } else {
                    $currentHash = (Get-FileHash $runningScript -Algorithm SHA256 -ErrorAction Stop).Hash
                    if ($currentHash -eq $storedHash) {
                        $integrityOk = $true
                        # M-7 FIX: Log successful verification too, creating continuous audit trail
                        $monNdjsonPath = Join-Path $monitorDir 'HardTarget_monitor.ndjson'
                        try { Write-SafeFile -Path $monNdjsonPath -Content (@{ timestamp = (Get-Date -Format 'o'); type = 'integrity_ok'; hash = $currentHash; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress) -Append } catch {}
                    } else {
                        # Hash mismatch - script modified since installation
                        $tamperMsg = "HardTarget INTEGRITY FAILURE: Monitor script hash mismatch. Expected=$storedHash Got=$currentHash Path=$runningScript"
                        try { Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9999 -EntryType Error -Message $tamperMsg -ErrorAction SilentlyContinue } catch {}
                        # SECURITY (v0.43): Structured NDJSON logging for integrity events
                        $monNdjsonPath = Join-Path $monitorDir 'HardTarget_monitor.ndjson'
                        try { Write-SafeFile -Path $monNdjsonPath -Content (@{ timestamp = (Get-Date -Format 'o'); type = 'integrity_failure'; error = $tamperMsg; expectedHash = $storedHash; actualHash = $currentHash; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress) -Append } catch {}
                    }
                }
            }
        } catch {
            # SECURITY (v0.40): Log integrity check errors instead of silently passing.
            # File locked, permission denied, Get-FileHash failure - all result in abort.
            $errMsg = "HardTarget INTEGRITY CHECK ERROR: $_ (script will not run)"
            try { Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9998 -EntryType Error -Message $errMsg -ErrorAction SilentlyContinue } catch {}
            # SECURITY (v0.43): Structured NDJSON logging
            $monNdjsonPath = Join-Path $monitorDir 'HardTarget_monitor.ndjson'
            try { Write-SafeFile -Path $monNdjsonPath -Content (@{ timestamp = (Get-Date -Format 'o'); type = 'integrity_check_error'; error = "$_"; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress) -Append } catch {}
        }
        
        if (-not $integrityOk) {
            # Abort monitor run - script has been modified since installation
            exit 1
        }
        
        # SECURITY (v0.52): Validate monitor directory and data files are not symlinks.
        # An attacker who pre-creates the directory (or files within it) as symlinks can
        # redirect SYSTEM-level writes to arbitrary locations (e.g., overwrite system DLLs
        # with JSON data). Check the directory itself and all expected output files.
        if (Test-ReparsePoint $monitorDir) {
            $symlinkMsg = "HardTarget SECURITY: Monitor directory is a reparse point (junction/symlink). Aborting. Path=$monitorDir"
            try { Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9997 -EntryType Error -Message $symlinkMsg -EA SilentlyContinue } catch {}
            exit 1
        }
        # Scan all existing files in the directory for reparse points and remove them
        $monitorFiles = @(
            'HardTarget_monitor.ndjson', 'HardTarget_latest.json',
            'HardTarget_baseline.json', 'HardTarget_golden_baseline.json',
            'HardTarget_drift.ndjson'
        )
        foreach ($mf in $monitorFiles) {
            $mfPath = Join-Path $monitorDir $mf
            if ((Test-Path $mfPath) -and (Test-ReparsePoint $mfPath)) {
                $symlinkMsg = "HardTarget SECURITY: Removing symlink/junction planted at $mfPath"
                try { Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9997 -EntryType Error -Message $symlinkMsg -EA SilentlyContinue } catch {}
                try { [System.IO.File]::Delete($mfPath) } catch { [System.IO.Directory]::Delete($mfPath, $false) }
            }
        }
        
        # Need UserOutputDir set for scan functions that reference it
        $script:UserOutputDir = $monitorDir
        
        # Silent scan (WindowStyle Hidden means console output goes nowhere)
        $script:JsonChecks = @()
        $script:TotalPass = 0; $script:TotalCondPass = 0; $script:TotalWarn = 0; $script:TotalFail = 0
        $script:HasDMAPorts = $false
        
        # SECURITY (v0.43): Log scan errors instead of silently swallowing them.
        # Each scan function runs in its own try/catch so one failure doesn't block others.
        $scanErrors = @()
        $scanFunctions = @(
            @{ Name = 'Test-BiosFirmware'; Fn = { Test-BiosFirmware } }
            @{ Name = 'Test-SleepStates';  Fn = { Test-SleepStates } }
            @{ Name = 'Test-TPM';          Fn = { Test-TPM } }
            @{ Name = 'Test-DMAExposure';  Fn = { Test-DMAExposure } }
            @{ Name = 'Test-Encryption';   Fn = { Test-Encryption } }
            @{ Name = 'Test-MemoryResidue'; Fn = { Test-MemoryResidue } }
            @{ Name = 'Test-ScreenLock';   Fn = { Test-ScreenLock } }
            @{ Name = 'Test-ForensicSurface'; Fn = { Test-ForensicSurface } }
        )
        foreach ($sf in $scanFunctions) {
            try { & $sf.Fn } catch {
                $scanErrors += @{ function = $sf.Name; error = $_.ToString(); timestamp = (Get-Date -Format 'o') }
            }
        }
        if ($scanErrors.Count -gt 0) {
            $errLogPath = Join-Path $monitorDir 'HardTarget_monitor.ndjson'
            $scanErrors | ForEach-Object {
                @{ timestamp = $_.timestamp; type = 'scan_error'; function = $_.function; error = $_.error; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress
            } | ForEach-Object { Write-SafeFile -Path $errLogPath -Content $_ -Append }
        }
        
        # v0.51: Post-processing - append edition context for GP-dependent checks on Home
        if ($script:WindowsEdition -eq 'Home') {
            $gpDependentChecks = @{
                'usb-storage'      = 'Requires Group Policy (Pro/Enterprise). Cannot be enforced on Windows Home.'
                'usb-install'      = 'Requires Group Policy (Pro/Enterprise). Cannot be enforced on Windows Home.'
                'removable-encrypt'= 'Requires BitLocker + Group Policy. Not available on Windows Home.'
                'bl-network-unlock'= 'Requires BitLocker + Group Policy. Not available on Windows Home.'
            }
            for ($i = 0; $i -lt $script:JsonChecks.Count; $i++) {
                $check = $script:JsonChecks[$i]
                if ($gpDependentChecks.ContainsKey($check.id) -and $check.status -ne 'pass') {
                    $edNote = $gpDependentChecks[$check.id]
                    $script:JsonChecks[$i].detail = $check.detail + " [EDITION: $edNote]"
                    $script:JsonChecks[$i]['editionLimited'] = $true
                }
            }
        }
        
        # Build current state
        $currentState = @{}
        foreach ($c in $script:JsonChecks) { $currentState[$c.id] = $c.status }
        
        # Load baseline(s)
        # SECURITY (v0.39): Maintain TWO baselines to prevent baseline ratchet attacks.
        # Golden baseline: created on first run, never overwritten. Shows cumulative drift.
        # Incremental baseline: overwritten each run. Shows changes since last check.
        # An attacker making one small change per hour would silently ratchet the old
        # baseline to the weakened state. The golden baseline preserves the original posture.
        $baselinePath = Join-Path $monitorDir 'HardTarget_baseline.json'
        $goldenPath = Join-Path $monitorDir 'HardTarget_golden_baseline.json'
        $driftEvents = @()
        $timestamp = Get-Date -Format 'o'
        
        # Create golden baseline on first run (never overwritten automatically)
        # SECURITY (v0.40): Detect and log golden baseline creation vs recreation.
        # If golden baseline was deleted and recreated, an attacker could reset
        # drift detection to the current (weakened) state. Log an event to create
        # an audit trail distinguishing first creation from recreation.
        if (-not (Test-Path $goldenPath)) {
            try {
                Write-SafeFile -Path $goldenPath -Content ($currentState | ConvertTo-Json)
            $goldenHash = (Get-FileHash $goldenPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HardTarget'
            $storedGoldenHash = (Get-ItemProperty -Path $regPath -Name 'GoldenBaselineHash' -ErrorAction SilentlyContinue).GoldenBaselineHash
            if ($storedGoldenHash) {
                # Recreation - golden baseline was deleted after initial creation
                $reMsg = "HardTarget GOLDEN BASELINE RECREATED: Previous hash=$storedGoldenHash New hash=$goldenHash. If you did not delete this file, investigate immediately."
                try { Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9002 -EntryType Warning -Message $reMsg -ErrorAction SilentlyContinue } catch {}
            } else {
                # First creation
                $crMsg = "HardTarget golden baseline created: hash=$goldenHash checks=$($currentState.Count)"
                try { Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9002 -EntryType Information -Message $crMsg -ErrorAction SilentlyContinue } catch {}
            }
            # Store hash in registry so we can detect recreation even if event log is cleared
            try { Set-ItemProperty -Path $regPath -Name 'GoldenBaselineHash' -Value $goldenHash -ErrorAction SilentlyContinue } catch {}
            } catch {
                $monNdjsonPath = Join-Path $monitorDir 'HardTarget_monitor.ndjson'
                try { Write-SafeFile -Path $monNdjsonPath -Content (@{ timestamp = (Get-Date -Format 'o'); type = 'golden_baseline_error'; error = "$_"; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress) -Append } catch {}
            }
        }
        
        if (Test-Path $baselinePath) {
            try {
            $baseline = Get-Content $baselinePath -Raw | ConvertFrom-Json
            $baselineState = @{}
            foreach ($prop in $baseline.PSObject.Properties) { $baselineState[$prop.Name] = $prop.Value }
            
            # Compare against incremental baseline (changes since last run)
            foreach ($id in $currentState.Keys) {
                $prev = $baselineState[$id]
                $curr = $currentState[$id]
                if ($prev -and $prev -ne $curr) {
                    $driftEvents += @{
                        timestamp = $timestamp
                        computer  = $env:COMPUTERNAME
                        check     = $id
                        previous  = $prev
                        current   = $curr
                        severity  = if ($curr -eq 'fail') { 'critical' } elseif ($curr -eq 'warn') { 'high' } else { 'info' }
                        driftType = 'incremental'
                    }
                }
            }
            } catch {
                # SECURITY (v0.43): Corrupted/locked baseline must not crash the headless monitor.
                # Log the error; drift detection is skipped this run but scan data is still saved.
                $blErr = "Incremental baseline read failed: $_"
                $monNdjsonPath = Join-Path $monitorDir 'HardTarget_monitor.ndjson'
                try { Write-SafeFile -Path $monNdjsonPath -Content (@{ timestamp = (Get-Date -Format 'o'); type = 'baseline_error'; error = $blErr; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress) -Append } catch {}
            }
            
            # Also compare against golden baseline for cumulative drift detection
            if (Test-Path $goldenPath) {
                try {
                    $golden = Get-Content $goldenPath -Raw | ConvertFrom-Json
                    $goldenState = @{}
                    foreach ($prop in $golden.PSObject.Properties) { $goldenState[$prop.Name] = $prop.Value }
                    $cumulativeDrifts = 0
                    foreach ($id in $currentState.Keys) {
                        $orig = $goldenState[$id]
                        $curr = $currentState[$id]
                        if ($orig -and $orig -ne $curr) { $cumulativeDrifts++ }
                    }
                    if ($cumulativeDrifts -gt 0) {
                        $driftEvents += @{
                            timestamp       = $timestamp
                            computer        = $env:COMPUTERNAME
                            check           = '_cumulative_summary'
                            previous        = 'golden_baseline'
                            current         = "$cumulativeDrifts checks differ from original baseline"
                            severity        = if ($cumulativeDrifts -ge 5) { 'critical' } elseif ($cumulativeDrifts -ge 3) { 'high' } else { 'medium' }
                            driftType       = 'cumulative'
                        }
                    }
                } catch {}
            }
        }
        
        # Save current as incremental baseline (golden baseline preserved separately)
        try {
            Write-SafeFile -Path $baselinePath -Content ($currentState | ConvertTo-Json)
        } catch {
            $monNdjsonPath = Join-Path $monitorDir 'HardTarget_monitor.ndjson'
            try { Write-SafeFile -Path $monNdjsonPath -Content (@{ timestamp = (Get-Date -Format 'o'); type = 'baseline_save_error'; error = "$_"; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress) -Append } catch {}
        }
        
        # Append drift events to SIEM log (newline-delimited JSON)
        if ($driftEvents.Count -gt 0) {
            $siemPath = Join-Path $monitorDir 'HardTarget_drift.ndjson'
            # SECURITY (v0.39): Log rotation to prevent unbounded disk growth.
            # Rotate at 10MB, keep one backup.
            if (Test-Path $siemPath) {
                $logSize = (Get-Item $siemPath -ErrorAction SilentlyContinue).Length
                if ($logSize -gt 10MB) {
                    $backupPath = Join-Path $monitorDir 'HardTarget_drift.ndjson.1'
                    try {
                        if (Test-Path $backupPath) { Remove-Item $backupPath -Force -ErrorAction SilentlyContinue }
                        Rename-Item $siemPath $backupPath -Force -ErrorAction SilentlyContinue
                    } catch {}
                }
            }
            try {
                Write-SafeFile -Path $siemPath -Content ($driftEvents | ForEach-Object { $_ | ConvertTo-Json -Compress }) -Append
            } catch {}
            
            # Build human-readable summary
            $summary = ($driftEvents | ForEach-Object { "  - $($_.check): $($_.previous) -> $($_.current)" }) -join "`n"
            $alertText = @"
HardTarget SECURITY DRIFT DETECTED
================================
Time:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Machine: $env:COMPUTERNAME
Changes: $($driftEvents.Count)

$summary

Run HardTarget to review your full security posture.
Logs:    $monitorDir
Stop:    Search 'HardTarget' in Start Menu, or run: .\HardTarget_Monitor.ps1 -Uninstall
"@
            
            # 1. Pop up a message dialog on the user's desktop (works from SYSTEM)
            try {
                $msgExe = Join-Path $script:TrustedSystemRoot 'System32\msg.exe'
                if (Test-Path $msgExe) {
                    $popupMsg = "HardTarget: $($driftEvents.Count) security change(s) detected.`n`n$summary`n`nRun HardTarget to review. Search 'HardTarget' in Start Menu."
                    & $msgExe * /TIME:120 $popupMsg 2>$null
                }
            } catch {}
            
            # 2. Write human-readable alert file (timestamped, easy to find)
            try {
                $alertPath = Join-Path $monitorDir 'HardTarget_alert.txt'
                Write-SafeFile -Path $alertPath -Content ($alertText)
            } catch {}
            
            # NOTE (v0.53): Removed System.Windows.Forms.NotifyIcon balloon notification.
            # The scheduled task runs as SYSTEM in Session 0. Session 0 isolation (since
            # Vista) prevents UI elements from rendering on the interactive user's desktop.
            # The balloon would silently fail to appear, and Start-Sleep -Seconds 16
            # would needlessly block the monitor on every drift detection. User-visible
            # alerting is handled by msg.exe above (which can target interactive sessions)
            # and the EventLog entries below (for SIEM ingestion).
            
            # 3. Windows Event Log entry for SIEM ingestion
            try {
                foreach ($evt in $driftEvents) {
                    $msg = "HardTarget drift: [$($evt.check)] $($evt.previous) -> $($evt.current) (severity: $($evt.severity))"
                    Write-EventLog -LogName Application -Source 'HardTarget' -EventId 9001 -EntryType Warning -Message $msg -ErrorAction SilentlyContinue
                }
            } catch {}
        }
        
        # Also save full scan JSON every run
        try {
            $scanJson = Get-ScanJson
            $scanPath = Join-Path $monitorDir "HardTarget_latest.json"
            Write-SafeFile -Path $scanPath -Content ($scanJson)
        } catch {
            $monNdjsonPath = Join-Path $monitorDir 'HardTarget_monitor.ndjson'
            try { Write-SafeFile -Path $monNdjsonPath -Content (@{ timestamp = (Get-Date -Format 'o'); type = 'scan_save_error'; error = "$_"; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress) -Append } catch {}
        }
        
        exit
        } catch {
            # SECURITY (v0.43): Monitor-safe catch boundary. Any unhandled error in the
            # monitor path exits cleanly here instead of reaching the outer catch which
            # calls Read-Host (would hang the headless SYSTEM process indefinitely).
            # Use $monitorDir if already set (line ~4405), else fall back to default path.
            $crashLogDir = if ($monitorDir -and (Test-Path $monitorDir -ErrorAction SilentlyContinue)) { $monitorDir } else { Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'HardTarget' }
            $monNdjsonPath = Join-Path $crashLogDir 'HardTarget_monitor.ndjson'
            try { Write-SafeFile -Path $monNdjsonPath -Content (@{ timestamp = (Get-Date -Format 'o'); type = 'monitor_crash'; error = "$_"; computer = $env:COMPUTERNAME } | ConvertTo-Json -Compress) -Append } catch {}
            exit 1
        }
    }

    if ($Install) {
        $scriptPath = if ($MyInvocation.MyCommand -is [System.Management.Automation.ExternalScriptInfo]) { $MyInvocation.MyCommand.Path } else { $null }
        if (-not $scriptPath) { $scriptPath = $script:ScriptPath }
        # SECURITY (v0.74): Canonicalize through junctions before copying to protected dir
        if ($scriptPath) {
            try {
                $canonInstPath = Resolve-CanonicalScriptPath $scriptPath
                if ($canonInstPath) { $scriptPath = $canonInstPath }
            } catch {}
        }
        
        try {
            Install-HardTargetMonitor -ScriptFilePath $scriptPath
            $monDir = Join-Path $script:TrustedProgramData 'HardTarget'
            
            Write-Host ''
            Write-Host '  HardTarget Monitor installed successfully.' -ForegroundColor Green
            Write-Host ''
            Write-Host "  Task:           HardTarget Monitor (every 1 hour, runs as SYSTEM)" -ForegroundColor Cyan
            Write-Host "  Installed to:   $monDir\HardTarget_Monitor.ps1" -ForegroundColor Cyan
            Write-Host "  Source:         $scriptPath" -ForegroundColor DarkGray
            Write-Host "  Protection:     SYSTEM + Administrators only (ACL-protected)" -ForegroundColor DarkGray
            Write-Host ''
            Write-Host '  Where files go:' -ForegroundColor DarkGray
            Write-Host "    Drift log:    $monDir\HardTarget_drift.ndjson" -ForegroundColor DarkGray
            Write-Host "    Latest scan:  $monDir\HardTarget_latest.json" -ForegroundColor DarkGray
            Write-Host "    Event Log:    Application > Source: HardTarget (EventId 9001)" -ForegroundColor DarkGray
            Write-Host ''
            Write-Host '  How to know it is running:' -ForegroundColor White
            Write-Host '    - Search "HardTarget" in Start Menu' -ForegroundColor DarkGray
            Write-Host '    - Look in Settings > Apps > Installed apps (Add/Remove Programs)' -ForegroundColor DarkGray
            Write-Host '    - You will get a Windows notification if anything changes' -ForegroundColor DarkGray
            Write-Host '    - Run this script again (it will tell you)' -ForegroundColor DarkGray
            Write-Host ''
            Write-Host '  How to stop it:' -ForegroundColor White
            Write-Host '    - Uninstall from Settings > Apps (like any normal program)' -ForegroundColor DarkGray
            Write-Host '    - Search "HardTarget" in Start Menu > choose Uninstall' -ForegroundColor DarkGray
            Write-Host '    - Run: .\HardTarget_Monitor.ps1 -Uninstall' -ForegroundColor DarkGray
            Write-Host '    - Or use the dashboard (run the scanner, use STOP & REMOVE)' -ForegroundColor DarkGray
            Write-Host ''
        } catch {
            Write-Host "  [ERROR] Could not install: $_" -ForegroundColor Red
        }
        exit
    }

    if ($Uninstall) {
        $removed = Uninstall-HardTargetMonitor
        Write-Host ''
        if ($removed) {
            Write-Host '  HardTarget Monitor removed.' -ForegroundColor Green
            Write-Host '  Removed: Scheduled task, Start Menu shortcut, Add/Remove Programs entry, script copy.' -ForegroundColor DarkGray
            $monDir = Join-Path $script:TrustedProgramData 'HardTarget'
            if (Test-Path $monDir) {
                Write-Host ''
                Write-Host "  Data files remain in $monDir" -ForegroundColor DarkGray
                Write-Host '  (baseline, drift log, latest scan)' -ForegroundColor DarkGray
                Write-Host ''
                $purge = Read-Host '  Delete all data files too? [Y/N]'
                if ($purge -eq 'Y' -or $purge -eq 'y') {
                    if (Test-ReparsePoint $monDir) {
                        Write-Host "    [SECURITY] $monDir is a reparse point. Removing link only." -ForegroundColor Red
                        try { [System.IO.Directory]::Delete($monDir, $false) } catch {}
                    } else { Remove-ItemSafeRecurse -Path $monDir -RemoveRoot }
                    Write-Host "  Deleted $monDir" -ForegroundColor Green
                } else {
                    Write-Host "  Data files kept in $monDir" -ForegroundColor DarkGray
                }
            }
        } else {
            Write-Host '  HardTarget Monitor is not installed. Nothing to remove.' -ForegroundColor Yellow
        }
        Write-Host ''
        exit
    }

    if ($Status) {
        $taskName = 'HardTarget Monitor'
        Write-Host ''
        Write-Host '    ==========================================================' -ForegroundColor DarkCyan
        Write-Host '     HardTarget DRIFT MONITOR' -ForegroundColor Cyan
        Write-Host '    ==========================================================' -ForegroundColor DarkCyan
        Write-Host ''
        
        $isInstalled = $false
        try {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
            $isInstalled = $true
            
            $stateColor = if ($task.State -eq 'Ready') { 'Green' } else { 'Yellow' }
            Write-Host "    Status:        " -NoNewline -ForegroundColor DarkGray
            Write-Host $task.State.ToString().ToUpper() -ForegroundColor $stateColor
            Write-Host '    Schedule:      Every 1 hour (runs silently as SYSTEM)' -ForegroundColor DarkGray
            if ($taskInfo.LastRunTime -and $taskInfo.LastRunTime -gt [datetime]'2000-01-01') {
                Write-Host "    Last scan:     $($taskInfo.LastRunTime)" -ForegroundColor DarkGray
            }
            if ($taskInfo.NextRunTime -and $taskInfo.NextRunTime -gt [datetime]'2000-01-01') {
                Write-Host "    Next scan:     $($taskInfo.NextRunTime)" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host '    Status:        ' -NoNewline -ForegroundColor DarkGray
            Write-Host 'NOT INSTALLED' -ForegroundColor Yellow
        }
        
        $monDir = Join-Path $script:TrustedProgramData 'HardTarget'
        $driftPath = Join-Path $monDir 'HardTarget_drift.ndjson'
        Write-Host ''
        Write-Host "    Log directory:  $monDir" -ForegroundColor DarkGray
        if (Test-Path $driftPath) {
            $lines = (Get-Content $driftPath | Measure-Object).Count
            $size = [math]::Round((Get-Item $driftPath).Length / 1KB, 1)
            Write-Host "    Drift events:  $lines ($($size) KB)" -ForegroundColor DarkGray
            if ($lines -gt 0) {
                Write-Host ''
                Write-Host '    Recent drift:' -ForegroundColor White
                Get-Content $driftPath -Tail 5 | ForEach-Object {
                    try {
                        $evt = $_ | ConvertFrom-Json
                        $col = if ($evt.severity -eq 'critical') { 'Red' } elseif ($evt.severity -eq 'high') { 'Yellow' } else { 'DarkGray' }
                        Write-Host "      [$($evt.severity.ToUpper().PadRight(8))] $($evt.check): $($evt.previous) -> $($evt.current)  ($($evt.timestamp))" -ForegroundColor $col
                    } catch {}
                }
            }
        } else {
            Write-Host '    Drift events:  None yet' -ForegroundColor DarkGray
        }
        
        Write-Host ''
        Write-Host '    ----------------------------------------------------------' -ForegroundColor DarkGray
        if ($isInstalled) {
            Write-Host '    [U] Uninstall monitor    [Q] Quit' -ForegroundColor White
        } else {
            Write-Host '    [I] Install monitor       [Q] Quit' -ForegroundColor White
        }
        Write-Host '    ----------------------------------------------------------' -ForegroundColor DarkGray
        Write-Host ''
        
        $choice = Read-Host '    Choice'
        if ($choice -eq 'U' -or $choice -eq 'u') {
            if ($isInstalled) {
                Uninstall-HardTargetMonitor
                Write-Host ''
                Write-Host '    Monitor removed (task, shortcut, registry, script copy).' -ForegroundColor Green
                $monDir = Join-Path $script:TrustedProgramData 'HardTarget'
                if (Test-Path $monDir) {
                    $purge = Read-Host '    Delete data files too? [Y/N]'
                    if ($purge -eq 'Y' -or $purge -eq 'y') {
                        if (Test-ReparsePoint $monDir) {
                        Write-Host "    [SECURITY] $monDir is a reparse point. Removing link only." -ForegroundColor Red
                        try { [System.IO.Directory]::Delete($monDir, $false) } catch {}
                    } else { Remove-ItemSafeRecurse -Path $monDir -RemoveRoot }
                        Write-Host "    Deleted $monDir" -ForegroundColor Green
                    } else {
                        Write-Host "    Data files kept in $monDir" -ForegroundColor DarkGray
                    }
                }
            }
        } elseif ($choice -eq 'I' -or $choice -eq 'i') {
            if (-not $isInstalled) {
                $sp = $script:ScriptPath
                if (-not $sp -and $MyInvocation.MyCommand -is [System.Management.Automation.ExternalScriptInfo]) { $sp = $MyInvocation.MyCommand.Path }
                # SECURITY (v0.74): Canonicalize through junctions
                if ($sp) { try { $csp = Resolve-CanonicalScriptPath $sp; if ($csp) { $sp = $csp } } catch {} }
                if ($sp) {
                    try {
                        Install-HardTargetMonitor -ScriptFilePath $sp
                        Write-Host ''
                        Write-Host '    Monitor installed. Visible in Add/Remove Programs and Start Menu.' -ForegroundColor Green
                    } catch {
                        Write-Host "    [ERROR] Could not install: $_" -ForegroundColor Red
                    }
                } else {
                    Write-Host '    [ERROR] Cannot determine script path.' -ForegroundColor Red
                }
            }
        }
        
        Write-Host ''
        exit
    }

    # Normal interactive mode
    Write-Banner
    
    # == If monitor is installed, tell the user IMMEDIATELY ==
    try {
        $existingTask = Get-ScheduledTask -TaskName 'HardTarget Monitor' -ErrorAction Stop
        $existingInfo = Get-ScheduledTaskInfo -TaskName 'HardTarget Monitor' -ErrorAction SilentlyContinue
        
        Write-Host ''
        Write-Host '    ==========================================================' -ForegroundColor DarkCyan
        Write-Host '     DRIFT MONITOR IS RUNNING' -ForegroundColor Cyan
        Write-Host '    ==========================================================' -ForegroundColor DarkCyan
        Write-Host ''
        Write-Host '    A background service is scanning your security posture' -ForegroundColor White
        Write-Host '    every hour and will notify you if anything changes.' -ForegroundColor White
        Write-Host ''
        $stateColor = if ($existingTask.State -eq 'Ready') { 'Green' } else { 'Yellow' }
        Write-Host "    Status:     " -NoNewline -ForegroundColor DarkGray
        Write-Host $existingTask.State.ToString().ToUpper() -ForegroundColor $stateColor
        if ($existingInfo.LastRunTime -and $existingInfo.LastRunTime -gt [datetime]'2000-01-01') {
            Write-Host "    Last scan:  $($existingInfo.LastRunTime)" -ForegroundColor DarkGray
        }
        Write-Host "    Logs:       $(Join-Path $script:TrustedProgramData 'HardTarget')" -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '    [C] Continue to scan    [S] Stop & remove monitor    [Q] Quit' -ForegroundColor White
        Write-Host ''
        
        $monChoice = Read-Host '    Choice'
        if ($monChoice -eq 'S' -or $monChoice -eq 's') {
            Uninstall-HardTargetMonitor
            Write-Host ''
            Write-Host '    Monitor removed (task, shortcut, registry, script copy).' -ForegroundColor Green
            $monDir = Join-Path $script:TrustedProgramData 'HardTarget'
            if (Test-Path $monDir) {
                $purge = Read-Host '    Delete data files too? [Y/N]'
                if ($purge -eq 'Y' -or $purge -eq 'y') {
                    if (Test-ReparsePoint $monDir) {
                        Write-Host "    [SECURITY] $monDir is a reparse point. Removing link only." -ForegroundColor Red
                        try { [System.IO.Directory]::Delete($monDir, $false) } catch {}
                    } else { Remove-ItemSafeRecurse -Path $monDir -RemoveRoot }
                    Write-Host "    Deleted $monDir" -ForegroundColor Green
                } else {
                    Write-Host "    Data files kept in $monDir" -ForegroundColor DarkGray
                }
            }
            Write-Host ''
        } elseif ($monChoice -eq 'Q' -or $monChoice -eq 'q') {
            exit
        }
        # C or anything else = continue to scan
        Write-Host ''
    } catch {
        # Monitor not installed - that's fine, continue silently
    }
    
    Run-FullScan
    
    # Drift monitor install/uninstall is handled via the dashboard buttons
    # and the /monitor-install, /monitor-uninstall endpoints (console approval required).
} catch {
    Write-Host ''
    Write-Host '  ===================================================' -ForegroundColor Red
    Write-Host '  CRASH DETECTED' -ForegroundColor Red
    Write-Host '  ===================================================' -ForegroundColor Red
    Write-Host ''
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ''
    Write-Host "  Location: $($_.InvocationInfo.PositionMessage)" -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Please report this error.' -ForegroundColor DarkGray
    Write-Host ''
    Read-Host '  Press Enter to exit'
}
