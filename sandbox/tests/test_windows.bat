@echo off
setlocal enabledelayedexpansion

set "SANDBOX=%~1"
if not defined SANDBOX (
    echo Usage: test_windows.bat ^<path-to-sandbox.exe^>
    exit /b 2
)

set "EXIT_CODE=0"

:: Setup temp dirs
set "WS=%TEMP%\sandbox_test_ws_%RANDOM%"
set "OUTSIDE=%TEMP%\sandbox_test_outside_%RANDOM%"
mkdir "%WS%" 2>nul
mkdir "%OUTSIDE%" 2>nul

echo ============================================
echo  AI Sandbox - Windows Integration Tests
echo ============================================
echo.

:: Default-shell (powershell) cases drive powershell.exe under the
:: write-restricted token. The restricting SID set must include the logon SID
:: and Everyone or process initialization fails (0xC0000142); on some
:: environments (GitHub runners) the same startup instead blocks. CI therefore
:: sets SANDBOX_TEST_SKIP_DEFAULT_SHELL to run the cmd-only subset; run this
:: script without the variable for full coverage.
if defined SANDBOX_TEST_SKIP_DEFAULT_SHELL goto cmd_shell_tests

echo === Test 1: Default shell (PowerShell) - write inside workspace (should succeed) ===
"%SANDBOX%" -c "echo hello > test.txt" --workspace "%WS%"
if !ERRORLEVEL! EQU 0 (
    if exist "%WS%\test.txt" (
        echo [PASS] Write inside workspace
    ) else (
        echo [FAIL] Write inside workspace - file not created
        set "EXIT_CODE=1"
    )
) else (
    echo [FAIL] Write inside workspace - exit code !ERRORLEVEL!
    set "EXIT_CODE=1"
)

echo === Test 2: Default shell (PowerShell) - write outside workspace (should fail) ===
"%SANDBOX%" -c "echo hello > $env:OUTSIDE\test.txt" --workspace "%WS%"
if !ERRORLEVEL! NEQ 0 (
    echo [PASS] Write outside workspace denied
) else (
    echo [FAIL] Write outside workspace - should have been denied
    set "EXIT_CODE=1"
)

echo === Test 3: Read-only mode (should fail) ===
"%SANDBOX%" -c "echo hello > test2.txt" --workspace "%WS%" --read-only
if !ERRORLEVEL! NEQ 0 (
    echo [PASS] Read-only mode denies write
) else (
    echo [FAIL] Read-only mode - should have been denied
    set "EXIT_CODE=1"
)

echo === Test 4: Exit code passthrough ===
"%SANDBOX%" -c "exit 42" --workspace "%WS%"
if !ERRORLEVEL! EQU 42 (
    echo [PASS] Exit code passthrough
) else (
    echo [FAIL] Exit code passthrough - got !ERRORLEVEL!, expected 42
    set "EXIT_CODE=1"
)

:: Guards against a silent regression where the default shell falls back to
:: cmd: this command is valid PowerShell only and exits non-zero under cmd.
:: It also fails with 0xC0000142 when the restricting SID set is too narrow.
echo === Test 5: Default shell really is PowerShell (PS-only syntax) ===
"%SANDBOX%" -c "if ($PSVersionTable.PSVersion.Major -ge 5) { exit 0 } else { exit 9 }" --workspace "%WS%"
if !ERRORLEVEL! EQU 0 (
    echo [PASS] Default shell executed PowerShell syntax
) else (
    echo [FAIL] Default shell did not run PowerShell - exit code !ERRORLEVEL!
    set "EXIT_CODE=1"
)

:: Exercise the Restricted Token fallback explicitly: on Win11 24H2+ the
:: Sandbox API backend is attempted first, so the fallback (and its restricting
:: SID requirements) only gets coverage through this switch.
set "SANDBOX_FORCE_RESTRICTED_TOKEN=1"

echo === Test 6: Default shell (PowerShell) under Restricted-Token backend - write inside (should succeed) ===
"%SANDBOX%" -c "echo hello > rt_test.txt" --workspace "%WS%"
if !ERRORLEVEL! EQU 0 (
    if exist "%WS%\rt_test.txt" (
        echo [PASS] Restricted-Token backend: write inside workspace
    ) else (
        echo [FAIL] Restricted-Token backend: write inside workspace - file not created
        set "EXIT_CODE=1"
    )
) else (
    echo [FAIL] Restricted-Token backend: write inside workspace - exit code !ERRORLEVEL!
    set "EXIT_CODE=1"
)

echo === Test 7: Default shell (PowerShell) under Restricted-Token backend - write outside (should fail) ===
"%SANDBOX%" -c "echo hello > $env:OUTSIDE\rt_test.txt" --workspace "%WS%"
if !ERRORLEVEL! NEQ 0 (
    echo [PASS] Restricted-Token backend: write outside workspace denied
) else (
    echo [FAIL] Restricted-Token backend: write outside workspace - should have been denied
    set "EXIT_CODE=1"
)

set "SANDBOX_FORCE_RESTRICTED_TOKEN="

:cmd_shell_tests
echo === Test 8: --shell cmd - write inside workspace (should succeed) ===
"%SANDBOX%" --shell cmd -c "echo hello > cmd_test.txt" --workspace "%WS%"
if !ERRORLEVEL! EQU 0 (
    if exist "%WS%\cmd_test.txt" (
        echo [PASS] cmd shell write inside workspace
    ) else (
        echo [FAIL] cmd shell write inside workspace - file not created
        set "EXIT_CODE=1"
    )
) else (
    echo [FAIL] cmd shell write inside workspace - exit code !ERRORLEVEL!
    set "EXIT_CODE=1"
)

echo === Test 9: --shell cmd - write outside workspace (should fail) ===
"%SANDBOX%" --shell cmd -c "echo hello > %OUTSIDE%\cmd_test.txt" --workspace "%WS%"
if !ERRORLEVEL! NEQ 0 (
    echo [PASS] cmd shell write outside workspace denied
) else (
    echo [FAIL] cmd shell write outside workspace - should have been denied
    set "EXIT_CODE=1"
)

:: Counterpart to Test 5: proves the default shell is not cmd, i.e. that the
:: PowerShell cases above actually exercised PowerShell.
echo === Test 10: --shell cmd rejects PowerShell-only syntax ===
"%SANDBOX%" --shell cmd -c "Write-Output hello" --workspace "%WS%" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo [PASS] cmd shell rejects PowerShell syntax
) else (
    echo [FAIL] cmd shell accepted PowerShell syntax - exit code !ERRORLEVEL!
    set "EXIT_CODE=1"
)

set "SANDBOX_FORCE_RESTRICTED_TOKEN=1"

echo === Test 11: --shell cmd under Restricted-Token backend - write inside (should succeed) ===
"%SANDBOX%" --shell cmd -c "echo hello > rt_cmd_test.txt" --workspace "%WS%"
if !ERRORLEVEL! EQU 0 (
    if exist "%WS%\rt_cmd_test.txt" (
        echo [PASS] Restricted-Token backend: cmd shell write inside workspace
    ) else (
        echo [FAIL] Restricted-Token backend: cmd shell write inside workspace - file not created
        set "EXIT_CODE=1"
    )
) else (
    echo [FAIL] Restricted-Token backend: cmd shell write inside workspace - exit code !ERRORLEVEL!
    set "EXIT_CODE=1"
)

echo === Test 12: --shell cmd under Restricted-Token backend - write outside (should fail) ===
"%SANDBOX%" --shell cmd -c "echo hello > %OUTSIDE%\rt_cmd_test.txt" --workspace "%WS%"
if !ERRORLEVEL! NEQ 0 (
    echo [PASS] Restricted-Token backend: cmd shell write outside workspace denied
) else (
    echo [FAIL] Restricted-Token backend: cmd shell write outside workspace - should have been denied
    set "EXIT_CODE=1"
)

set "SANDBOX_FORCE_RESTRICTED_TOKEN="

:: Cleanup
rd /s /q "%WS%" 2>nul
rd /s /q "%OUTSIDE%" 2>nul

echo.
if !EXIT_CODE! EQU 0 (
    echo === All tests passed ===
) else (
    echo === Some tests FAILED ===
)
exit /b !EXIT_CODE!
