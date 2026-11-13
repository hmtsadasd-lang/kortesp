@echo off
rem Start the INCONTEXT winevent hook from an elevated process.
rem
rem The client's manifest requires elevation (direct CreateProcess answers
rem 740), so the client runs at high integrity - and an unelevated hook is
rem never injected into a higher integrity process. The hook has to come from
rem the same level.
powershell -NoProfile -Command "Start-Process -FilePath 'C:\dev\fortesp\out\winevent_deliver.exe' -ArgumentList 'C:\dev\fortesp\out\FortHook.dll','600' -Verb RunAs -WindowStyle Minimized"
echo rc=%errorlevel%
echo [test] elevated winevent deliver started
