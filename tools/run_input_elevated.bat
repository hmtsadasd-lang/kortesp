@echo off
rem Run the input-hook delivery elevated and capture its output.
rem
rem The client runs at high integrity (its manifest asks for it), and a hook
rem installed from a lower-integrity process is never injected into a higher
rem one - so the hook has to come from the same level.
del /q C:\Users\Public\fortesp_hook.log 2>nul
del /q C:\Users\Public\fort_channel.out 2>nul
powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','C:\dev\fortesp\out\hook_input.exe C:\dev\fortesp\out\FortHook.dll 180 both > C:\dev\fortesp\hook_input.out 2>&1' -Verb RunAs -WindowStyle Minimized -Wait"
echo rc=%errorlevel%
type C:\dev\fortesp\hook_input.out
