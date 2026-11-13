@echo off
rem Run the hook-type delivery elevated and capture its output.
rem
rem The client runs at high integrity, and a hook installed from a
rem lower-integrity process is never injected into a higher one.
del /q C:\Users\Public\fortesp_hook.log 2>nul
del /q C:\Users\Public\fort_channel.out 2>nul
powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','C:\dev\fortesp\out\hook_types.exe C:\dev\fortesp\out\FortHook.dll 180 cbt,idle,get > C:\dev\fortesp\hook_types.out 2>&1' -Verb RunAs -WindowStyle Minimized -Wait"
echo rc=%errorlevel%
type C:\dev\fortesp\hook_types.out
