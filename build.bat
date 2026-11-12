@echo off
setlocal
set CFG=Release
set PLAT=x64
msbuild "%~dp0fortesp.sln" /m /nologo /p:Configuration=%CFG% /p:Platform=%PLAT% /v:minimal
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)
echo BUILD OK
dir /b "%~dp0out\*.dll" "%~dp0out\*.exe"