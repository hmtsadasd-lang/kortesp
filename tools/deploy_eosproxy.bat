@echo off
rem Deploy the EOS SDK proxy into the game directory.
rem
rem   EOSSDK-Win64-Shipping.dll       <- out\EOSSDK-Win64-Shipping.dll (proxy)
rem   EOSSDK-Win64-Shipping_real.dll  <- the original SDK, kept under a new name
rem   payload.dll                     <- the payload the proxy maps into the game
rem
rem The game must be closed: the original DLL is mapped while it runs.
rem Run elevated: the game directory is under Program Files.
setlocal
set NAME=EOSSDK-Win64-Shipping
set ROOT=C:\dev\fortesp
set GAMEDIR=C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64

if not exist "%GAMEDIR%" (
    echo [deploy] %GAMEDIR% not found
    exit /b 1
)

echo [deploy] target: %GAMEDIR%

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
    echo [deploy] FAILED to copy the proxy
    exit /b 1
)
echo [deploy] proxy   -> %NAME%.dll

copy /y "%ROOT%\out\payload.dll" "%GAMEDIR%\payload.dll" > nul
echo [deploy] payload -> payload.dll

dir /-c "%GAMEDIR%\%NAME%.dll"
dir /-c "%GAMEDIR%\%NAME%_real.dll"
dir /-c "%GAMEDIR%\payload.dll"
dir /-c "%GAMEDIR%\dbghelp.dll"
echo [deploy] done
endlocal
