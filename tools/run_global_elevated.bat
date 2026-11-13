@echo off
rem Global hook sweep: tid=0 for every type.
rem
rem A global hook injects the DLL into every process that triggers it. The
rem payload is guarded (only FortniteClient-Win64-Shipping.exe maps it), so
rem this is safe - the log shows exactly which processes the mechanism
rem reached.
del /q C:\Users\Public\fortesp_hook.log 2>nul
del /q C:\Users\Public\fort_channel.out 2>nul
powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','C:\dev\fortesp\out\hook_types.exe C:\dev\fortesp\out\FortHook.dll 240 get,hw,cbt,msg 0 > C:\dev\fortesp\hook_types.out 2>&1' -Verb RunAs -WindowStyle Minimized -Wait"
echo rc=%errorlevel%
type C:\dev\fortesp\hook_types.out
