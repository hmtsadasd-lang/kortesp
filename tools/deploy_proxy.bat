@echo off
rem Deploy the proxy into the game directory.
rem
rem   <name>.dll       <- out\<name>.dll (the proxy), forwards to <name>_real.dll
rem   <name>_real.dll  <- the original library, kept under a new name
rem   payload.dll      <- the payload the proxy maps into the game
rem
rem The game must be closed: the original DLL is mapped while it runs.
rem Run elevated: the game directory is under Program Files.
setlocal
if "%~1"=="" set NAME=EOSSDK-Win64-Shipping
set ROOT=C:\dev\fortesp
set GAMEDIR=C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64

if not exist "%GAMEDIR%" (
    echo [deploy] %GAMEDIR% not found
    exit /b 1
)

echo [deploy] target: %GAMEDIR%

rem cleanup of the first attempt: put Epic's dbghelp back
if exist "%GAMEDIR%\dbghelp_real.dll" (
    if exist "%GAMEDIR%\dbghelp.dll" copy /y "%GAMEDIR%\dbghelp_real.dll" "%GAMEDIR%\dbghelp.dll" > nul
    del /f /q "%GAMEDIR%\dbghelp_real.dll"
    echo [deploy] original dbghelp.dll restored
)

if exist "%GAMEDIR%\%NAME%_real.dll" (
    echo [deploy] %NAME%_real.dll already present, keeping it
) else (
    if exist "%GAMEDIR%\%NAME%.dll" (
        move /y "%GAMEDIR%\%NAME%.dll" "%GAMEDIR%\%NAME%_real.dll" > nul
        echo [deploy] original %NAME%.dll -> %NAME%_real.dll
    ) else (
        echo [deploy] no original %NAME%.dll found
    )
)

copy /y "%ROOT%\out\%NAME%.dll" "%GAMEDIR%\%NAME%.dll" > nul
if errorlevel 1 (
    echo [deploy] FAILED to copy the proxy (is the game still running?)
    exit /b 1
)
echo [deploy] proxy   -> %NAME%.dll

copy /y "%ROOT%\out\payload.dll" "%GAMEDIR%\payload.dll" > nul
echo [deploy] payload -> payload.dll

dir /-c "%GAMEDIR%\%NAME%.dll" "%GAMEDIR%\%NAME%_real.dll" "%GAMEDIR%\payload.dll"
echo [deploy] done
endlocal
