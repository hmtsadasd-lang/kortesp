@echo off
:: ring0 runner - starts the DBUtil_2_3 driver and launches fortesp_r0.exe
::
:: SAFETY RULES (learned the hard way - DBUtil_2_3 bugchecks this box):
::
::  1. NEVER `sc stop` this driver. It is NOT_STOPPABLE / IGNORES_SHUTDOWN.
::     Stopping it fails, leaves the service half-deleted, and the driver
::     stays loaded with no owner. That is a BSOD waiting to happen.
::  2. NEVER `sc delete` it while it is running. This script only deletes a
::     service that is not RUNNING (no live instance, so nothing is mapped).
::  3. NEVER overwrite the .sys image while an instance is loaded - the
::     on-disk image and the mapped image diverge. The copy below is skipped
::     if the target already exists.
::  4. NEVER start a second instance. IoCreateDevice(\Device\DBUtil_2_3)
::     fails on the second one and the driver half-initialises.
::
:: So: load it once, leave it running, and let a reboot unload it. If it is
:: ALREADY RUNNING this script does nothing to the driver at all - it just
:: runs the tool. A service that exists but is STOPPED never had a live
:: instance, so retrying `sc start` is safe; the old version treated mere
:: existence as "loaded" and then silently did nothing.
::
:: RENAMING (the cheapest thing that defeats a name check):
::   set FORTESP_SVC=SomeSvcName
::   set FORTESP_IMAGE=SomeName.sys
:: before running. The loader copies the image to
:: %SystemRoot%\System32\drivers\%FORTESP_IMAGE% and creates the service from
:: it, then passes --driver-name so the cloak's KLDR matcher looks for the
:: right suffix. The DRIVER'S OWN DEVICE NAME stays \Device\DBUtil_2_3 (it is
:: hardcoded in the image) and so does the \??\DBUtil_2_3 symlink - renaming
:: the file does not hide those.
::
:: Decide the name BEFORE the first load. Changing it later means recreating
:: the service, which this script only does while it is not running, i.e.
:: after a reboot.
::
:: HVCI: with Memory Integrity on, the Microsoft vulnerable-driver blocklist
:: is enforced and this image will not load. This is a hard abort unless
:: DBUTIL_FORCE=1 is set.
::
:: The driver image goes in ring0\driver\dbutil_2_3.sys
:: (driver\fetch_driver.ps1 downloads and hash-verifies it).

setlocal enabledelayedexpansion
cd /d "%~dp0"

rem ---- self-elevate (loading a kernel driver needs admin) ----
rem Pure token query: the High Mandatory Level SID is present only in an
rem elevated token. Do NOT use `net session` here - it goes through the SMB
rem stack, and this box runs a WinDivert-based network filter and has a
rem history of hangs right after SMB/SCM commands. `fltmc` is equally off
rem limits: it loads the filter-manager stack.
rem ---- elevation check: must be run from an elevated shell ---::
:: `whoami /groups` contains S-1-16-12288 only when the process is
:: running with SeDebugPrivilege (i.e. true admin/elevated token).
:: `ver` alone is NOT a valid test (always returns 0/errorlevel 0).
whoami /groups > "%TEMP%\_fg_groups.tmp" 2>nul
findstr /c:"S-1-16-12288" "%TEMP%\_fg_groups.tmp" >nul
if errorlevel 1 (
    echo [x] this runner must be started in an elevated (admin) session.
    echo     right-click the bat and choose "Run as administrator".
    goto :fail
)
if errorlevel 1 (
    echo [*] requesting elevation...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    exit /b 0
)

rem ---- identity: service name and image name ----
set "SVC=%FORTESP_SVC%"
if not defined SVC set "SVC=DBUtil_2_3"
set "IMAGE=%FORTESP_IMAGE%"
if not defined IMAGE set "IMAGE=DBUtil_2_3.sys"
:: Accept "name" or "name.sys"; the loader and the cloak must agree, and the
:: file needs an extension Windows will load a driver from.
:: (Substring compare, not `echo|findstr /e`: the space before the pipe becomes
:: part of the echoed line, so an end-of-line match never matches.)
if /i not "%IMAGE:~-4%"==".sys" set "IMAGE=%IMAGE%.sys"
set "DST=%SystemRoot%\System32\drivers\%IMAGE%"
rem No second source of truth: --driver-name (built from %IMAGE% at the bottom)
rem is the only way the tool learns the image name. Exporting
rem FORTESP_DRIVER_IMAGE here as well would let the two drift apart, and a
rem mismatch makes our_base() silently match nothing in the cloak.

echo [*] service: %SVC%
echo [*] image  : %IMAGE%

rem ---- HVCI / blocklist preflight ----
:: With Memory Integrity on, the Microsoft vulnerable-driver blocklist is
:: enforced by CI and this image will not load at all. Check, don't guess.
set "HVCI="
for /f "tokens=3" %%V in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled 2^>nul ^| findstr /i /c:"Enabled"') do set "HVCI=%%V"
if /i "!HVCI!"=="0x1" (
    echo [x] HVCI - Memory Integrity - is ON.
    echo     The vulnerable-driver blocklist is enforced and %IMAGE% will be
    echo     rejected at load. Turn Memory Integrity off and reboot, or use a
    echo     different backend.
    if /i not "%DBUTIL_FORCE%"=="1" (
        echo [x] aborting. Set DBUTIL_FORCE=1 to try anyway.
        exit /b 1
    )
    echo [x] DBUTIL_FORCE=1 - continuing despite HVCI.
)

rem FORTESP_NOLOAD=1: driver is already loaded (or you are testing the script
:: itself) - do not touch the service at all, just run the tool.
if "%FORTESP_NOLOAD%"=="1" (
    echo [*] FORTESP_NOLOAD=1 - not touching the driver.
    goto run_tool
)

rem ---- is the driver already RUNNING? ----
:: State, not existence: query the service state and only treat RUNNING as
:: "loaded". STOPPED means no live instance, so a start is safe.
set "EXISTS="
set "LOADED="
set "BUSY="
for /f "tokens=2 delims=:" %%S in ('sc.exe query "%SVC%" 2^>nul ^| findstr /i /c:"SERVICE_NAME"') do set "EXISTS=%%S"
if defined EXISTS (
    set "STATE="
    for /f "tokens=2 delims=:" %%S in ('sc.exe query "%SVC%" 2^>nul ^| findstr /i /c:"STATE"') do set "STATE=%%S"
    echo !STATE! | findstr /i /c:"RUNNING" /c:"START_PENDING" >nul && set "LOADED=1"
    echo !STATE! | findstr /i /c:"STOP_PENDING" >nul && set "BUSY=1"
)

if defined BUSY (
    echo [x] service %SVC% is STOP_PENDING - not touching it. Wait and re-run.
    exit /b 1
)

rem The service's configured image. If it does not match what we are about to
:: run, a running instance has the wrong name for the cloak matcher and a
:: stopped one has to be recreated.
set "BINPATH="
set "BINNAME="
if defined EXISTS (
    for /f "tokens=2,*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\%SVC%" /v ImagePath 2^>nul ^| findstr /i /c:"ImagePath"') do set "BINPATH=%%B"
)
:: Extract just the file name, then compare. `echo path | findstr /e` does not
:: work: the space before the pipe becomes part of the echoed line, so an
:: end-of-line match never matches (fails closed - but wrongly).
if defined BINPATH for %%I in ("!BINPATH!") do set "BINNAME=%%~nxI"

if defined LOADED (
    echo [*] driver is RUNNING - leaving it alone.
    if defined BINNAME (
        if /i not "!BINNAME!"=="%IMAGE%" (
            echo [x] the running service is configured for a different image:
            echo       !BINPATH!
            echo     The cloak matches on "%IMAGE%" and would not find itself.
            echo     Do NOT stop it. Reboot, then re-run to recreate the service.
            goto :fail
        )
    )
) else (
    if defined EXISTS (
        echo [*] service exists but is not running - it will be recreated.
        rem Not RUNNING means no mapped image; deleting the service is safe.
        rem (Rule 2 only forbids deleting a *running* one.)
        call :delete_service
        if errorlevel 1 goto :fail
        set "EXISTS="
    )

    rem ---- locate the driver image ----
    set "SYS="
    if defined DBUTIL_SYS ( if exist "!DBUTIL_SYS!" set "SYS=!DBUTIL_SYS!" )
    if not defined SYS if exist "%~dp0driver\dbutil_2_3.sys" set "SYS=%~dp0driver\dbutil_2_3.sys"
    if not defined SYS if exist "%~dp0driver\DBUtil_2_3.sys"   set "SYS=%~dp0driver\DBUtil_2_3.sys"
    if not defined SYS if exist "%SystemRoot%\System32\drivers\DBUtil_2_3.sys" set "SYS=%SystemRoot%\System32\drivers\DBUtil_2_3.sys"

    if not defined SYS (
        echo [x] driver image not found. Run:
        echo       powershell -ExecutionPolicy Bypass -File driver\fetch_driver.ps1
        echo     or set DBUTIL_SYS to a full path.
        goto :fail
    )

    echo [*] source image: !SYS!

    rem ---- verify the image before it is ever mapped ----
    rem The on-disk file is what gets loaded, so a stale or corrupted copy in
    rem driver\ is a silent wrong-driver. Default hash is the published
    rem dbutil_2_3.sys value; DBUTIL_SHA256 overrides it, and
    rem FORTESP_SKIP_HASH=1 bypasses the check.
    rem
    rem These are `rem`, not `::`: inside a parenthesised block `::` is a label,
    rem and cmd prints "Sistem belirtilen surucuyu bulamiyor." once per such
    rem line on stderr. Cosmetic, but it hides real errors in run.log.
    rem
    rem The check itself lives in a subroutine because `exit /b N` inside a
    rem doubly-nested block returns 0 on this cmd build (reproduced), which
    rem would turn a rejected image into a successful-looking run.
    call :verify_image "!SYS!"
    if errorlevel 1 goto :fail

    rem Copy only if the target does not exist yet. Overwriting an image that
    rem a loaded instance is mapped from is exactly what we must not do.
    if not exist "%DST%" (
        copy /y "!SYS!" "%DST%" >nul
        if errorlevel 1 (
            echo [x] could not copy the image to %DST%
            goto :fail
        )
        echo [*] installed as %DST%
    ) else (
        echo [*] target image already present - not overwriting it
    )

    if not defined EXISTS (
        sc.exe create "%SVC%" type= kernel start= demand binPath= "%DST%" >nul
        if errorlevel 1 (
            echo [x] sc create failed for %SVC%
            goto :fail
        )
    )
    sc.exe start "%SVC%" >nul

    rem Confirm it actually reached RUNNING before launching the tool.
    set "STATE=unreported"
    for /f "tokens=2 delims=:" %%S in ('sc.exe query "%SVC%" 2^>nul ^| findstr /i /c:"STATE"') do set "STATE=%%S"
    echo [*] service state: !STATE!
    echo !STATE! | findstr /i /c:"RUNNING" /c:"START_PENDING" >nul
    if errorlevel 1 (
        echo [x] the service did not reach RUNNING.
        echo     Likely: the vulnerable-driver blocklist enforces on this build
        echo     HVCI, or Secure Boot refuses the image. The tool will fail
        echo     its read probe; nothing was touched in kernel memory.
        goto :fail
    )
    echo [*] driver loaded and RUNNING. It stays loaded until reboot - do NOT stop it.

    rem The device is exclusive (one open at a time). If this fails while the
    rem service is RUNNING, something else already holds it.
    powershell -NoProfile -Command "try { $f=[IO.File]::Open('\\.\DBUtil_2_3','Open','ReadWrite','ReadWrite'); $f.Close(); exit 0 } catch { exit 1 }" >nul 2>&1
    if errorlevel 1 echo [x] \\.\DBUtil_2_3 could not be opened - another process may hold it.
)

:run_tool
:: ---- run ----
:: Log to a file so the output survives the elevated console closing.
:: --driver-name comes after %* so the runner's answer always wins: it knows
:: the name the service was actually created with.
if not exist out mkdir out
out\fortesp_r0.exe %* --driver-name "%IMAGE%" > out\run.log 2>&1
set "RC=%ERRORLEVEL%"
type out\run.log

rem NOTE: deliberately no `sc stop` and no `sc delete` here. See the rules at
rem the top of this file.
rem Propagate the tool's exit code (0 pass / 1 fail) to the caller.
endlocal & exit /b %RC%

rem ---------------------------------------------------------------------------
:: Delete a service that is NOT running, and wait for it to disappear.
:: Returns 1 if it is still registered after ~10s (caller aborts rather than
:: starting a half-deleted service).
:: ---------------------------------------------------------------------------
:delete_service
sc.exe delete "%SVC%" >nul 2>&1
set /a WAIT=0
:wait_delete
sc.exe query "%SVC%" >nul 2>&1
if not errorlevel 1 (
    set /a WAIT+=1
    if !WAIT! GEQ 10 goto :del_fail
    timeout /t 1 /nobreak >nul
    goto wait_delete
)
exit /b 0
:del_fail
echo [x] service %SVC% is still registered after delete.
echo     Reboot and re-run; not starting a half-deleted service.
exit /b 1

rem ---------------------------------------------------------------------------
:: Verify one driver image: :verify_image <full path>
:: Returns 0 for ok/skipped, 1 for mismatch.
:: Deliberately flat: no nested blocks, because `exit /b N` inside one returns
:: 0 on this cmd build when it is nested two levels deep.
:: ---------------------------------------------------------------------------
:verify_image
if "%FORTESP_SKIP_HASH%"=="1" (
    echo [*] hash check skipped - FORTESP_SKIP_HASH=1
    exit /b 0
)
set "WANT=%DBUTIL_SHA256%"
if not defined WANT set "WANT=0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5"
set "GOT="
for /f "skip=1 tokens=* delims=" %%H in ('certutil -hashfile "%~1" SHA256 2^>nul') do (
    if not defined GOT set "GOT=%%H"
)
if not defined GOT goto :vi_bad
set "GOT=%GOT: =%"
if /i "%GOT%"=="%WANT%" goto :vi_ok
:vi_bad
echo [x] image hash mismatch.
echo       want: %WANT%
echo       got : %GOT%
echo     Set DBUTIL_SHA256 to the expected value, or FORTESP_SKIP_HASH=1.
exit /b 1
:vi_ok
echo [*] image hash ok
exit /b 0

rem ---------------------------------------------------------------------------
:: Single abort exit. Reached with `goto` from inside the load block, so the
:: errorlevel is set at file scope and actually reaches the caller.
:: ---------------------------------------------------------------------------
:fail
echo [x] refusing to continue - the driver was NOT started by this run.
endlocal & exit /b 1

