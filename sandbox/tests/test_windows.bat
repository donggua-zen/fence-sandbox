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

echo === Test 5: --shell cmd - write inside workspace (should succeed) ===
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

echo === Test 6: --shell cmd - write outside workspace (should fail) ===
"%SANDBOX%" --shell cmd -c "echo hello > %OUTSIDE%\cmd_test.txt" --workspace "%WS%"
if !ERRORLEVEL! NEQ 0 (
    echo [PASS] cmd shell write outside workspace denied
) else (
    echo [FAIL] cmd shell write outside workspace - should have been denied
    set "EXIT_CODE=1"
)

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