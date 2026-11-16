@echo off
:: ring0 runner - starts the DBUtil_2_3 driver and launches fortesp_r0.exe
::
:: SAFETY RULES (learned the hard way - DBUtil_2_3 bugchecks this box):
::
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
:: ALREADY RUNNING this script does nothing to the driver at all - it just
:: runs the tool. A service that exists but is STOPPED never had a live
:: instance, so retrying `sc start` is safe; the old version treated mere
:: existence as "loaded" and then silently did nothing.
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

:: ---- HVCI / blocklist preflight ----
:: With Memory Integrity on, the Microsoft vulnerable-driver blocklist is
:: enforced by CI and this image will not load at all. Check, don't guess.
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled >nul 2>&1
if not errorlevel 1 (
    for /f "tokens=3" %%V in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled 2^>nul ^| findstr /i /c:"Enabled"') do (
        if /i "%%V"=="0x1" (
            echo [!] HVCI (Memory Integrity) is ON.
            echo     The Microsoft vulnerable-driver blocklist is enforced and
            echo     dbutil_2_3.sys will be rejected at load. Turn Memory
            echo     Integrity off and reboot, or use a different backend.
        )
    )
)

:: ---- is the driver already RUNNING? ----
:: State, not existence: query the service state and only treat RUNNING as
:: "loaded". STOPPED means no live instance, so a start is safe.
set "SVC=DBUtil_2_3"
set "EXISTS="
set "LOADED="
for /f "tokens=2 delims=:" %%S in ('sc.exe query "%SVC%" 2^>nul ^| findstr /i /c:"SERVICE_NAME"') do set "EXISTS=%%S"
if defined EXISTS (
    set "STATE="
    for /f "tokens=2 delims=:" %%S in ('sc.exe query "%SVC%" 2^>nul ^| findstr /i /c:"STATE"') do set "STATE=%%S"
    echo !STATE! | findstr /i /c:"RUNNING" /c:"START_PENDING" >nul && set "LOADED=1"
)

if defined LOADED (
    echo [*] driver is RUNNING - leaving it alone.
) else (
    if defined EXISTS echo [*] service exists but is not running (state !STATE!) - starting it.

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

    if not defined EXISTS (
        sc.exe create "%SVC%" type= kernel start= demand binPath= "%SystemRoot%\System32\drivers\DBUtil_2_3.sys" >nul
    )
    sc.exe start "%SVC%" >nul

    :: Confirm it actually reached RUNNING before launching the tool.
    set "STATE="
    for /f "tokens=2 delims=:" %%S in ('sc.exe query "%SVC%" 2^>nul ^| findstr /i /c:"STATE"') do set "STATE=%%S"
    echo !STATE! | findstr /i /c:"RUNNING" /c:"START_PENDING" >nul
    if errorlevel 1 (
        echo [!] the service did not reach RUNNING (state !STATE!).
        echo     Likely: the vulnerable-driver blocklist enforces on this build
        echo     (HVCI), or Secure Boot refuses the image. The tool will fail
        echo     its read probe; nothing was touched in kernel memory.
        exit /b 1
    )
    echo [*] driver loaded and RUNNING. It stays loaded until reboot - do NOT stop it.

    :: The device is exclusive (one open at a time). If this fails while the
    :: service is RUNNING, something else already holds it.
    powershell -NoProfile -Command "try { $f=[IO.File]::Open('\\.\DBUtil_2_3','Open','ReadWrite','ReadWrite'); $f.Close(); exit 0 } catch { exit 1 }" >nul 2>&1
    if errorlevel 1 echo [!] \\.\DBUtil_2_3 could not be opened - another process may hold it.
)

:: ---- run ----
:: Log to a file so the output survives the elevated console closing.
if not exist out mkdir out
out\fortesp_r0.exe %* > out\run.log 2>&1
type out\run.log

:: NOTE: deliberately no `sc stop` and no `sc delete` here. See the rules at
:: the top of this file.
endlocal