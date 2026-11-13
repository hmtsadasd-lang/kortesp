@echo off
rem Stage the hook DLL and the payload in the game directory.
rem
rem Only additions - no game file is replaced, so nothing the anti-cheat
rem validates is touched.
setlocal
set GD=C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64
set ROOT=C:\dev\fortesp

copy /y "%ROOT%\out\FortHook.dll" "%GD%\FortHook.dll" > nul
echo [deploy] FortHook.dll  rc=%errorlevel%
copy /y "%ROOT%\out\payload.dll" "%GD%\payload.dll" > nul
echo [deploy] payload.dll  rc=%errorlevel%

dir /-c "%GD%\FortHook.dll" "%GD%\payload.dll"
echo [deploy] done
endlocal
