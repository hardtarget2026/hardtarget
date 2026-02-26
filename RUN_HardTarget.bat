@echo off
:: =========================================================================
::  HardTarget v0.83 - Windows Physical Security Scanner
::  LAUNCHER ONLY - All security logic is in HardTarget.ps1
:: =========================================================================
::
::  SPDX-License-Identifier: BUSL-1.1
::  Copyright (c) 2026 HardTarget Contributors. All rights reserved.
::  Licensed under the Business Source License 1.1.
::  See HardTarget.ps1 for full license text and legal terms.
::
::  THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
::  Intended for qualified security professionals only. Not designed
::  for general consumers. Review the source code before running.
::  See HardTarget.ps1 for complete legal notice including
::  INDEMNIFICATION and LIMITATION OF LIABILITY clauses.
::
::  SECURITY NOTE (v0.71):
::  This file is intentionally trivial. It launches PowerShell and nothing
::  else. All elevation, hashing, staging, and integrity verification logic
::  has been moved into HardTarget.ps1, where PowerShell's .NET FileStream
::  locks provide kernel-level file integrity guarantees that cmd.exe cannot.
::  Previous versions (v0.52-v0.56) attempted to secure the UAC boundary
::  using Batch, but each fix introduced new attack surface due to cmd.exe's
::  lack of atomic file operations and secure I/O primitives.
:: =========================================================================

title HardTarget v0.83

:: SECURITY (v0.71): If launched from a 32-bit process (e.g., 32-bit SCCM agent,
:: 32-bit file manager), %SystemRoot%\System32 silently redirects to SysWOW64,
:: launching 32-bit PowerShell. In 32-bit mode, registry reads/writes hit
:: WOW6432Node instead of the real 64-bit hive -- every check returns wrong
:: data and every fix writes to a location the OS ignores.
:: %SystemRoot%\sysnative is a virtual path that only exists inside WOW64
:: processes and points to the real 64-bit System32.
if exist "%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" (
    set "PS_EXE=%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe"
) else (
    :: SECURITY: Fully qualified path prevents CWD-based executable planting.
    set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
)

:: Launch HardTarget.ps1. Menu, elevation, and all security logic are inside.
:: -File treats the path as a literal filename (no injection possible).
:: %* forwards any command-line arguments (e.g., -Audit, -ReadOnly).
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0HardTarget.ps1" %*

pause
