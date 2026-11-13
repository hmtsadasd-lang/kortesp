@echo off
rem Remove the proxy files from the game directory and put everything back.
setlocal
set GAMEDIR=C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64

if exist "%GAMEDIR%\version_real.dll" (
    move /y "%GAMEDIR%\version_real.dll" "%GAMEDIR%\version.dll" > nul
    echo [restore] version.dll restored from version_real.dll
)
if exist "%GAMEDIR%\EOSSDK-Win64-Shipping_real.dll" (
    move /y "%GAMEDIR%\EOSSDK-Win64-Shipping_real.dll" "%GAMEDIR%\EOSSDK-Win64-Shipping.dll" > nul
    echo [restore] EOSSDK-Win64-Shipping.dll restored
)
if exist "%GAMEDIR%\dbghelp_real.dll" (
    move /y "%GAMEDIR%\dbghelp_real.dll" "%GAMEDIR%\dbghelp.dll" > nul
    echo [restore] dbghelp.dll restored
)
del /f /q "%GAMEDIR%\payload.dll" 2>nul
echo [restore] payload.dll removed

dir /-c "%GAMEDIR%\version.dll"
dir /-c "%GAMEDIR%\EOSSDK-Win64-Shipping.dll"
dir /-c "%GAMEDIR%\dbghelp.dll"
echo [restore] done
endlocal
