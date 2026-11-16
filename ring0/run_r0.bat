@echo off
:: ring0 runner - starts the DBUtil_2_3 driver and launches fortesp_r0.exe
::
:: SAFETY RULES (learned the hard way - DBUtil_2_3 bugchecks this box):
;;
::  1. NEVER `sc stop` this driver. It is NOT_STOPPABLE / IGNORES_SHUTDOWN.
::     Stopping it fails, leaves the service half-deleted, and the driver
::     stays loaded with no owner. That is a BSOD waiting to happen.
::  2. NEVER `sc delete` it while it is running.
::  3. NEVER overwrite the .sys image while an instance is loaded - the
::     on-disk image and the mapped image diverge.
::  4. NEVER start a second instance. IoCreateDevice(\Device\DBUtil_2_3)
::     fails on the second one and the driver half-initialises.
::
:: So: load it once, leave it running, and let a reboot unload it. If it is
:: already loaded this script does nothing to the driver at all - it just
:: runs the tool.
::
:: The driver image goes in ring0\driver\dbutil_2_3.sys
:: (driver\fetch_driver.ps1 downloads and hash-verifies it).

setlocal enabledelayedexpansion
cd /d "%~dp0"

:: ---- self-elevate (loading a kernel driver needs admin) ----
net session >nul 2>&1
if errorlevel 1 (
    echo [*] requesting elevation...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    exit /b 0
)

:: ---- is the driver already loaded? ----
:: Look for our service name in the kernel-driver list.
set "SVC=DBUtil_2_3"
set "LOADED="
for /f "tokens=2 delims=:" %%S in ('sc.exe query type= driver state= all ^| findstr /i /c:"SERVICE_NAME: %SVC%"') do (
    set "LOADED=%%S"
)

if defined LOADED (
    echo [*] driver already loaded as "%LOADED%" - leaving it alone.
) else (
    :: ---- locate the driver image ----
    set "SYS="
    if defined DBUTIL_SYS ( if exist "!DBUTIL_SYS!" set "SYS=!DBUTIL_SYS!" )
    if not defined SYS if exist "%~dp0driver\dbutil_2_3.sys" set "SYS=%~dp0driver\dbutil_2_3.sys"
    if not defined SYS if exist "%~dp0driver\DBUtil_2_3.sys"   set "SYS=%~dp0driver\DBUtil_2_3.sys"
    if not defined SYS if exist "%SystemRoot%\System32\drivers\DBUtil_2_3.sys" set "SYS=%SystemRoot%\System32\drivers\DBUtil_2_3.sys"

    if not defined SYS (
        echo [!] driver image not found. Run:
        echo       powershell -ExecutionPolicy Bypass -File driver\fetch_driver.ps1
        echo     or set DBUTIL_SYS to a full path.
        exit /b 1
    )

    echo [*] driver image: %SYS%

    :: Copy only if the target does not exist yet. Overwriting an image that
    :: a loaded instance is mapped from is exactly what we must not do.
    if not exist "%SystemRoot%\System32\drivers\DBUtil_2_3.sys" (
        copy /y "%SYS%" "%SystemRoot%\System32\drivers\DBUtil_2_3.sys" >nul
    ) else (
        echo [*] driver image already present - not overwriting it
    )

    sc.exe create "%SVC%" type= kernel start= demand binPath= "%SystemRoot%\System32\drivers\DBUtil_2_3.sys" >nul
    sc.exe start "%SVC%" >nul
    if errorlevel 1 (
        echo [!] the service failed to start.
        echo     Likely: the vulnerable-driver blocklist now enforces on this build,
        echo     or Secure Boot refuses the image.
    ) else (
        echo [*] driver loaded. It will stay loaded until reboot - do NOT stop it.
    )
)

:: ---- run ----
:: Log to a file so the output survives the elevated console closing.
if not exist out mkdir out
out\fortesp_r0.exe %* > out\run.log 2>&1
type out\run.log

:: NOTE: deliberately no `sc stop` and no `sc delete` here. See the rules at
:: the top of this file.
endlocal
