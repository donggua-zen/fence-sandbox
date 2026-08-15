@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

echo === Detecting Visual Studio ===

:: Try vswhere first (covers VS 2017+)
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VSINSTALL=%%i"
    )
    if defined VSINSTALL (
        set "VCVARS=!VSINSTALL!\VC\Auxiliary\Build\vcvars64.bat"
        if exist "!VCVARS!" goto :found
    )
)

:: Fallback: check common paths
for %%v in (2022 2019 2025 18 17 16) do (
    for %%e in (Community Professional Enterprise BuildTools) do (
        if exist "C:\Program Files\Microsoft Visual Studio\%%v\%%e\VC\Auxiliary\Build\vcvars64.bat" (
            set "VCVARS=C:\Program Files\Microsoft Visual Studio\%%v\%%e\VC\Auxiliary\Build\vcvars64.bat"
            goto :found
        )
        if exist "D:\Program Files\Microsoft Visual Studio\%%v\%%e\VC\Auxiliary\Build\vcvars64.bat" (
            set "VCVARS=D:\Program Files\Microsoft Visual Studio\%%v\%%e\VC\Auxiliary\Build\vcvars64.bat"
            goto :found
        )
    )
)

echo ERROR: Visual Studio with C++ tools not found.
echo Please install Visual Studio 2019+ with "Desktop development with C++" workload.
exit /b 1

:found
echo Found: %VCVARS%
call "%VCVARS%" > nul
if %ERRORLEVEL% NEQ 0 (
    echo Failed to initialize MSVC environment.
    exit /b %ERRORLEVEL%
)

echo.
echo === Step 1: CMake Configure with NMake Makefiles ===
cmake -S sandbox -B build -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
if %ERRORLEVEL% NEQ 0 (
    echo CMake configure failed!
    exit /b %ERRORLEVEL%
)

echo.
echo === Step 2: CMake Build ===
cmake --build build --config Release
if %ERRORLEVEL% NEQ 0 (
    echo CMake build failed!
    exit /b %ERRORLEVEL%
)

echo.
echo === Build Complete ===
echo Output: %CD%\build\bin\
dir "%CD%\build\bin\" /b
