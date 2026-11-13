@echo off
rem Hijack VERSION.dll in the game directory.
rem
rem The game loads VERSION.dll (the EOS SDK imports it statically) and the
rem loader searches the application directory first, so a proxy placed there
rem is loaded into the game process. The real system copy is kept next to it
rem under version_real.dll and the forwarders point at that.
rem
rem The game must be closed while the files are put in place.
setlocal
set ROOT=C:\dev\fortesp
set GAMEDIR=C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64
set NAME=version

if not exist "%GAMEDIR%" (
    echo [deploy] %GAMEDIR% not found
    exit /b 1
)

if not exist "%GAMEDIR%\%NAME%_real.dll" (
    copy /y C:\Windows\System32\%NAME%.dll "%GAMEDIR%\%NAME%_real.dll" > nul
    echo [deploy] system %NAME%.dll -> %NAME%_real.dll
) else (
    echo [deploy] %NAME%_real.dll already present, keeping it
)

copy /y "%ROOT%\out\%NAME%.dll" "%GAMEDIR%\%NAME%.dll" > nul
if errorlevel 1 (
    echo [deploy] FAILED to copy the proxy
    exit /b 1
)
echo [deploy] proxy   -> %NAME%.dll

copy /y "%ROOT%\out\payload.dll" "%GAMEDIR%\payload.dll" > nul
echo [deploy] payload -> payload.dll

dir /-c "%GAMEDIR%\%NAME%.dll"
dir /-c "%GAMEDIR%\%NAME%_real.dll"
dir /-c "%GAMEDIR%\payload.dll"
echo [deploy] done
endlocal
