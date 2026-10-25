@echo off
setlocal
pushd "%~dp0.."
where cl >nul 2>nul
if errorlevel 1 (echo Run from Visual Studio Developer Command Prompt. & popd & exit /b 1)
rc /nologo /fo HolyCheck.res parts\app_icon.rc
if errorlevel 1 (popd & exit /b 1)
cl /nologo /std:c++17 /EHsc /O2 /MT /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DNTDDI_VERSION=0x0A000000 main.cpp HolyCheck.res /Fe:HolyCheck.exe /link /SUBSYSTEM:WINDOWS
set "result=%errorlevel%"
popd
exit /b %result%
