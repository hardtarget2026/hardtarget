@echo off
:::  HardTarget v0.83 - Intune Compliance Local Test
:::  Runs the compliance script and saves JSON for dashboard testing
:::  Right-click > Run as Administrator

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   This script requires Administrator privileges.
    echo   Right-click and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

title HardTarget v0.83 - Compliance Test

echo.
echo   HardTarget Compliance - Local Test
echo   ===================================
echo.
echo   Running compliance scan...
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "$json = powershell.exe -NoProfile -ExecutionPolicy Bypass -File '%~dp0HardTarget_Compliance.ps1'; $json | Out-File -FilePath '%~dp0compliance_result.json' -Encoding UTF8; $result = $json | ConvertFrom-Json; Write-Host ''; Write-Host '  Results:' -ForegroundColor Cyan; Write-Host '  --------'; $policy = Get-Content '%~dp0CompliancePolicy.json' | ConvertFrom-Json; $pass=0; $fail=0; foreach ($rule in $policy.Rules) { $actual = $result.($rule.SettingName); $ok = switch ($rule.Operator) { 'IsEquals' { $actual -eq $rule.Operand } 'GreaterEquals' { $actual -ge $rule.Operand } }; if ($ok) { Write-Host ('  PASS  ' + $rule.SettingName) -ForegroundColor Green; $pass++ } else { Write-Host ('  FAIL  ' + $rule.SettingName + '  (got: ' + $actual + ', expected: ' + $rule.Operand + ')') -ForegroundColor Red; $fail++ } }; Write-Host ''; Write-Host \"  Score: $pass pass / $fail fail out of $($policy.Rules.Count) rules\" -ForegroundColor $(if($fail -eq 0){'Green'}else{'Yellow'}); Write-Host ''; Write-Host '  JSON saved to: %~dp0compliance_result.json' -ForegroundColor Cyan; Write-Host '  Drag this file onto fleet-dashboard.html to view in the dashboard.' -ForegroundColor DarkGray; Write-Host ''"

echo.
pause
