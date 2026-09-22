@echo off
setlocal enabledelayedexpansion

:: Regression tests for the per-backend workspace-grant lifecycle.
::
:: The two Windows backends have deliberately DIFFERENT grant lifecycles:
::
::   Restricted Token  derives its capability SID from the canonical workspace
::                     path, so the SID is stable across runs and the workspace
::                     ACE is granted STANDING — the cross-run reuse cache that
::                     makes every later invocation O(1) instead of an eager
::                     full-tree re-propagation.
::   AppContainer      must use a fresh profile name every run (the engine
::                     rejects a reused identity), so its SID is fresh every
::                     run and its ACE is per-run state that must be REVOKED,
::                     or each invocation would leave a dead entry behind.
::
:: The security-critical case for both: a later read-only run on the SAME
:: workspace must still DENY writes. The standing Restricted-Token grant must
:: not re-open writes, which is why the workspace capability SID is kept out of
:: the read-only restricting list.
::
:: Usage: test_standing_grant_windows.bat <path-to-sandbox.exe>

set "SANDBOX=%~1"
if not defined SANDBOX (
    echo Usage: test_standing_grant_windows.bat ^<path-to-sandbox.exe^>
    exit /b 2
)
if not exist "%SANDBOX%" (
    echo sandbox binary not found: "%SANDBOX%"
    exit /b 2
)

set "EXIT_CODE=0"
set "PASS=0"
set "FAIL=0"

:: On D: so the workspace is not a permissive %TEMP% volume.
set "WS=D:\AI\sandbox\test_standing_grant_ws"
set "OUTSIDE=D:\AI\sandbox\test_standing_grant_outside"

rd /s /q "%WS%" 2>nul
rd /s /q "%OUTSIDE%" 2>nul
mkdir "%WS%" 2>nul
mkdir "%OUTSIDE%" 2>nul

:: A handful of children so the first grant has something to propagate over.
for /L %%i in (1,1,50) do echo x > "%WS%\seed%%i.txt"

:: Normalize the outside dir so the DENY cases measure the sandbox rather than
:: the host ACLs (same rationale as the other Windows test scripts).
icacls "%OUTSIDE%" /inheritance:r >nul 2>nul
icacls "%OUTSIDE%" /grant:r "%USERNAME%:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" >nul 2>nul

echo ============================================
echo  AI Sandbox - Workspace Grant Lifecycle Tests
echo ============================================
echo.

set "SANDBOX_FORCE_RESTRICTED_TOKEN=1"

echo --- Test 1: Restricted-Token workspace-write succeeds ---
"%SANDBOX%" --shell cmd -c "echo hi > t1.txt" --workspace "%WS%" >nul 2>nul
if exist "%WS%\t1.txt" (
    echo [PASS] write inside workspace
    set /a PASS+=1
) else (
    echo [FAIL] write inside workspace failed
    set /a FAIL+=1 & set "EXIT_CODE=1"
)

echo --- Test 2: capability ACE materialized (S-1-4-*) ---
call :captureAce RT1 "S-1-4-[0-9]"
if defined RT1 (
    echo [PASS] workspace capability ACE present
    set /a PASS+=1
) else (
    echo [FAIL] no S-1-4-* capability ACE on the workspace
    set /a FAIL+=1 & set "EXIT_CODE=1"
)

echo --- Test 3: capability ACE is STANDING (survives the run) ---
if defined RT1 (
    echo [PASS] ACE survived the run ^(the cross-run reuse cache^)
    set /a PASS+=1
) else (
    echo [FAIL] no standing ACE to check
    set /a FAIL+=1 & set "EXIT_CODE=1"
)

echo --- Test 4: capability identity is STABLE across runs ---
"%SANDBOX%" --shell cmd -c "echo hi > t4.txt" --workspace "%WS%" >nul 2>nul
call :captureAce RT2 "S-1-4-[0-9]"
if defined RT1 if defined RT2 (
    if "!RT1!"=="!RT2!" (
        echo [PASS] capability ACE unchanged across runs
        set /a PASS+=1
    ) else (
        echo [FAIL] capability ACE changed between runs
        echo        run1: !RT1!
        echo        run2: !RT2!
        set /a FAIL+=1 & set "EXIT_CODE=1"
    )
) else (
    echo [FAIL] capability ACE missing after the second run
    set /a FAIL+=1 & set "EXIT_CODE=1"
)

:: The security-critical case: the standing grant must not re-open writes when
:: a later run asks for read-only on the same workspace.
echo --- Test 5: read-only on the SAME workspace DENIES (Restricted Token) ---
"%SANDBOX%" --shell cmd -c "echo nope > t5.txt" --workspace "%WS%" --read-only >nul 2>nul
if exist "%WS%\t5.txt" (
    echo [FAIL] read-only wrote despite the standing workspace grant
    set /a FAIL+=1 & set "EXIT_CODE=1"
) else (
    echo [PASS] read-only denied the write
    set /a PASS+=1
)

echo --- Test 6: re-upgrade to workspace-write still works ---
"%SANDBOX%" --shell cmd -c "echo hi > t6.txt" --workspace "%WS%" >nul 2>nul
if exist "%WS%\t6.txt" (
    echo [PASS] workspace-write re-upgrade succeeded
    set /a PASS+=1
) else (
    echo [FAIL] workspace-write failed after a read-only period
    set /a FAIL+=1 & set "EXIT_CODE=1"
)

set "SANDBOX_FORCE_RESTRICTED_TOKEN="

echo --- Test 7: AppContainer workspace-write succeeds (opt-in backend) ---
set "SANDBOX_FORCE_APPCONTAINER=1"
"%SANDBOX%" --shell cmd -c "echo hi > t7.txt" --workspace "%WS%" >nul 2>nul
if exist "%WS%\t7.txt" (
    echo [PASS] write inside workspace
    set /a PASS+=1
) else (
    echo [FAIL] write inside workspace failed
    set /a FAIL+=1 & set "EXIT_CODE=1"
)

:: The AppContainer identity is fresh every run, so its ACE is per-run state:
:: leaving it behind would accumulate one dead entry per invocation.
echo --- Test 8: AppContainer leaves NO standing capability ACE ---
call :countAce AC_BEFORE "S-1-15-2-[0-9]"
"%SANDBOX%" --shell cmd -c "echo hi > t8.txt" --workspace "%WS%" >nul 2>nul
call :countAce AC_AFTER "S-1-15-2-[0-9]"
if "!AC_AFTER!"=="!AC_BEFORE!" (
    echo [PASS] per-run AppContainer grant was revoked ^(no accumulation^)
    set /a PASS+=1
) else (
    echo [FAIL] AppContainer ACE accumulated: !AC_BEFORE! -^> !AC_AFTER!
    set /a FAIL+=1 & set "EXIT_CODE=1"
)

echo --- Test 9: read-only on the SAME workspace DENIES (AppContainer) ---
"%SANDBOX%" --shell cmd -c "echo nope > t9.txt" --workspace "%WS%" --read-only >nul 2>nul
if exist "%WS%\t9.txt" (
    echo [FAIL] read-only wrote
    set /a FAIL+=1 & set "EXIT_CODE=1"
) else (
    echo [PASS] read-only denied the write
    set /a PASS+=1
)
set "SANDBOX_FORCE_APPCONTAINER="

echo --- Test 10: write outside the workspace is still DENIED ---
"%SANDBOX%" --shell cmd -c "echo hacked > %OUTSIDE%\evil.txt" --workspace "%WS%" >nul 2>nul
if exist "%OUTSIDE%\evil.txt" (
    echo [FAIL] write outside workspace was allowed
    set /a FAIL+=1 & set "EXIT_CODE=1"
) else (
    echo [PASS] write outside workspace denied
    set /a PASS+=1
)

:: Cleanup. Deleting the workspace removes any standing ACEs with it.
rd /s /q "%WS%" 2>nul
rd /s /q "%OUTSIDE%" 2>nul

echo.
echo === %PASS% passed, %FAIL% failed ===
if "%FAIL%" NEQ "0" set "EXIT_CODE=1"
exit /b %EXIT_CODE%

:: ---------------------------------------------------------------------------
:: captureAce <varname> <findstr-regex> — first matching ACE line on the root.
:: ---------------------------------------------------------------------------
:captureAce
set "%~1="
for /f "delims=" %%L in ('icacls "%WS%" 2^>nul ^| findstr /R /C:"%~2"') do (
    if not defined %~1 set "%~1=%%L"
)
exit /b 0

:: ---------------------------------------------------------------------------
:: countAce <varname> <findstr-regex> — number of matching ACE lines.
:: ---------------------------------------------------------------------------
:countAce
set /a %~1=0
for /f "delims=" %%L in ('icacls "%WS%" 2^>nul ^| findstr /R /C:"%~2"') do set /a %~1+=1
exit /b 0
