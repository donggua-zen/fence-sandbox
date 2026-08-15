@echo off
setlocal enabledelayedexpansion

set "SANDBOX=D:\AI\sandbox\build\bin\sandbox.exe"
set "PASS=0"
set "FAIL=0"

:: Setup test dirs on D: drive (avoids %TEMP% permissive ACLs)
set "WS=D:\AI\sandbox\test_ws_run"
set "WS2=D:\AI\sandbox\test_ws2_run"
set "OUTSIDE=D:\AI\sandbox\test_outside_run"
rd /s /q "%WS%" 2>nul
rd /s /q "%WS2%" 2>nul
rd /s /q "%OUTSIDE%" 2>nul
mkdir "%WS%" 2>nul
mkdir "%WS2%" 2>nul
mkdir "%OUTSIDE%" 2>nul

echo ============================================
echo  AI Sandbox - Windows Security Tests
echo ============================================
echo.

echo --- Test 1: Write file inside workspace (ALLOW) ---
"%SANDBOX%" --shell cmd -c "echo test > file.txt" --workspace "%WS%" 2>nul
if exist "%WS%\file.txt" ( echo [PASS] & set /a PASS+=1 ) else ( echo [FAIL] & set /a FAIL+=1 )

echo --- Test 2: Write file outside workspace (DENY) ---
"%SANDBOX%" --shell cmd -c "echo hacked > %OUTSIDE%\evil.txt" --workspace "%WS%" 2>nul
if exist "%OUTSIDE%\evil.txt" ( echo [FAIL] & set /a FAIL+=1 ) else ( echo [PASS] & set /a PASS+=1 )

echo --- Test 3: Delete file outside workspace (DENY) ---
echo dummy > "%OUTSIDE%\dummy.txt"
"%SANDBOX%" --shell cmd -c "del %OUTSIDE%\dummy.txt" --workspace "%WS%" 2>nul
if exist "%OUTSIDE%\dummy.txt" ( echo [PASS] & set /a FAIL+=0 & set /a PASS+=1 ) else ( echo [FAIL] & set /a FAIL+=1 )

echo --- Test 4: Delete file inside workspace (ALLOW) ---
echo dummy > "%WS%\todelete.txt"
"%SANDBOX%" --shell cmd -c "del todelete.txt" --workspace "%WS%" 2>nul
if exist "%WS%\todelete.txt" ( echo [FAIL] & set /a FAIL+=1 ) else ( echo [PASS] & set /a PASS+=1 )

echo --- Test 5: Create directory inside workspace (ALLOW) ---
"%SANDBOX%" --shell cmd -c "mkdir newdir" --workspace "%WS%" 2>nul
if exist "%WS%\newdir\" ( echo [PASS] & set /a PASS+=1 ) else ( echo [FAIL] & set /a FAIL+=1 )

echo --- Test 6: Create directory outside workspace (DENY) ---
"%SANDBOX%" --shell cmd -c "mkdir %OUTSIDE%\evil_dir" --workspace "%WS%" 2>nul
if exist "%OUTSIDE%\evil_dir\" ( echo [FAIL] & set /a FAIL+=1 ) else ( echo [PASS] & set /a PASS+=1 )

echo --- Test 7: Read file outside workspace (ALLOW) ---
echo secret > "%OUTSIDE%\readable.txt"
"%SANDBOX%" --shell cmd -c "type %OUTSIDE%\readable.txt" --workspace "%WS%" 2>nul
if !ERRORLEVEL! EQU 0 ( echo [PASS] & set /a PASS+=1 ) else ( echo [FAIL] & set /a FAIL+=1 )

echo --- Test 8: Read-only mode - write inside workspace (DENY) ---
"%SANDBOX%" --shell cmd -c "echo test > ro.txt" --workspace "%WS%" --read-only 2>nul
if exist "%WS%\ro.txt" ( echo [FAIL] & set /a FAIL+=1 ) else ( echo [PASS] & set /a PASS+=1 )

echo --- Test 9: Read-only mode - read file (ALLOW) ---
echo secret > "%WS%\readable.txt"
"%SANDBOX%" --shell cmd -c "type readable.txt" --workspace "%WS%" --read-only 2>nul
if !ERRORLEVEL! EQU 0 ( echo [PASS] & set /a PASS+=1 ) else ( echo [FAIL] & set /a FAIL+=1 )

echo --- Test 10: Multi-workspace - write to first workspace (ALLOW) ---
"%SANDBOX%" --shell cmd -c "echo test > ws1.txt" --workspace "%WS%,%WS2%" 2>nul
if exist "%WS%\ws1.txt" ( echo [PASS] & set /a PASS+=1 ) else ( echo [FAIL] & set /a FAIL+=1 )

echo --- Test 11: Multi-workspace - write to second workspace (ALLOW) ---
"%SANDBOX%" --shell cmd -c "echo test > %WS2%\ws2.txt" --workspace "%WS%,%WS2%" 2>nul
if exist "%WS2%\ws2.txt" ( echo [PASS] & set /a PASS+=1 ) else ( echo [FAIL] & set /a FAIL+=1 )

echo --- Test 12: Exit code passthrough (expect 42) ---
"%SANDBOX%" --shell cmd -c "exit 42" --workspace "%WS%" 2>nul
if !ERRORLEVEL! EQU 42 ( echo [PASS] & set /a PASS+=1 ) else ( echo [FAIL] got !ERRORLEVEL! & set /a FAIL+=1 )

echo --- Test 13: Exit code 0 passthrough ---
"%SANDBOX%" --shell cmd -c "exit 0" --workspace "%WS%" 2>nul
if !ERRORLEVEL! EQU 0 ( echo [PASS] & set /a PASS+=1 ) else ( echo [FAIL] got !ERRORLEVEL! & set /a FAIL+=1 )

echo --- Test 14: Move file from workspace to outside (DENY) ---
echo test > "%WS%\move.txt"
"%SANDBOX%" --shell cmd -c "move %WS%\move.txt %OUTSIDE%\moved.txt" --workspace "%WS%" 2>nul
if exist "%OUTSIDE%\moved.txt" ( echo [FAIL] & set /a FAIL+=1 ) else ( echo [PASS] & set /a PASS+=1 )

echo --- Test 15: Overwrite existing file inside workspace (ALLOW) ---
echo old > "%WS%\overwrite.txt"
"%SANDBOX%" --shell cmd -c "echo new > overwrite.txt" --workspace "%WS%" 2>nul
findstr "new" "%WS%\overwrite.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 ( echo [PASS] & set /a PASS+=1 ) else ( echo [FAIL] & set /a FAIL+=1 )

echo --- Test 16: Default shell (PowerShell) - write inside workspace (ALLOW) ---
"%SANDBOX%" -c "echo test > ps.txt" --workspace "%WS%" 2>nul
if exist "%WS%\ps.txt" ( echo [PASS] & set /a PASS+=1 ) else ( echo [FAIL] & set /a FAIL+=1 )

echo --- Test 17: Default shell (PowerShell) - write outside workspace (DENY) ---
"%SANDBOX%" -c "echo hacked > $env:OUTSIDE\evil_ps.txt" --workspace "%WS%" 2>nul
if exist "%OUTSIDE%\evil_ps.txt" ( echo [FAIL] & set /a FAIL+=1 ) else ( echo [PASS] & set /a PASS+=1 )

echo --- Test 18: Default shell (PowerShell) - read-only mode (DENY) ---
"%SANDBOX%" -c "echo test > ro_ps.txt" --workspace "%WS%" --read-only 2>nul
if exist "%WS%\ro_ps.txt" ( echo [FAIL] & set /a FAIL+=1 ) else ( echo [PASS] & set /a PASS+=1 )

echo --- Test 19: Default shell (PowerShell) - exit code passthrough (expect 42) ---
"%SANDBOX%" -c "exit 42" --workspace "%WS%" 2>nul
if !ERRORLEVEL! EQU 42 ( echo [PASS] & set /a PASS+=1 ) else ( echo [FAIL] got !ERRORLEVEL! & set /a FAIL+=1 )

echo.
echo ============================================
echo  Results: !PASS! passed, !FAIL! failed
echo ============================================

:: Cleanup
rd /s /q "%WS%" 2>nul
rd /s /q "%WS2%" 2>nul
rd /s /q "%OUTSIDE%" 2>nul
rd /s /q "D:\AI\sandbox\test_outside_check" 2>nul

exit /b !FAIL!
