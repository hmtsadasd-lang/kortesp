@echo off
rem Generate the .def for a system DLL we hijack in the game directory.
rem usage: gen_def.bat <dll-name> [<real-name>]
setlocal
cd /d C:\dev\fortesp
set DLL=%~1
if "%DLL%"=="" set DLL=version
set REALNAME=%~2
if "%REALNAME%"=="" set REALNAME=%DLL%_real

set GAMEDIR=C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64
set REAL=%GAMEDIR%\%DLL%.dll
if not exist "%REAL%" set REAL=%GAMEDIR%\%REALNAME%.dll
if not exist "%REAL%" set REAL=C:\Windows\System32\%DLL%.dll
if not exist "%REAL%" (
    echo [gen_def] cannot find %DLL%
    exit /b 1
)

python tools\mkfwd.py "%REAL%" --exports %REALNAME%.dll %DLL% > loader\src\%DLL%.def
echo rc=%errorlevel%
echo [gen_def] source: %REAL%
echo [gen_def] def:    loader\src\%DLL%.def
endlocal
