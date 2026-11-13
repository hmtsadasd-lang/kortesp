@echo off
rem Live confirmation: run the hook matrix against the client that is already
rem running, elevated, and against the whole desktop in a global sweep.
rem
rem The client's manifest elevates it, and a hook installed from a
rem lower-integrity process is never injected into a higher one - so this has
rem to run from the same level. The result is the client's row next to the
rem fixture's row in LIVE_TEST_RESULTS.md section 10.
del /q C:\Users\Public\fortesp_hook.log 2>nul
powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','C:\dev\fortesp\tools\matrix_live.bat' -Verb RunAs -WindowStyle Minimized -Wait"
echo rc=%errorlevel%
echo === thread-local (client tid) ===
type C:\dev\fortesp\hook_matrix_client.out
echo === global sweep ===
type C:\dev\fortesp\hook_matrix_client_global.out
