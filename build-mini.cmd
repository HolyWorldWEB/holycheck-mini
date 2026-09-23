@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 exit /b 1
set "VS_TOOLS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VS_TOOLS%" (
    echo Visual Studio 2022 Build Tools not found.
    exit /b 1
)
call "%VS_TOOLS%" >nul
if errorlevel 1 exit /b 1

if not exist build mkdir build
if errorlevel 1 exit /b 1
rc /nologo /fo "build\HolyCheckMini.res" "HolyCheckMini.rc"
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /EHsc /O2 /MT /utf-8 /DUNICODE /D_UNICODE /Fo"build\HolyCheckMini.obj" "main.cpp" "build\HolyCheckMini.res" /Fe:"build\HolyCheckMini.exe" /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib comctl32.lib shell32.lib shlwapi.lib winhttp.lib ole32.lib oleaut32.lib uuid.lib dwmapi.lib gdiplus.lib advapi32.lib
if errorlevel 1 exit /b 1
echo Built build\HolyCheckMini.exe
