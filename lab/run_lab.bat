@echo off
rem Decision-table lab: thin wrapper around lab\run_all.ps1.
rem
rem   MockGame.exe  64 bit, DACL caps every handle at 0x11F145 (no VM rights)
rem   MockHost.exe  32 bit, stands in for the anti-cheat service
rem
rem The suite asserts granted=0x0011F145, alloc=0x0, lasterr=5,
rem decision=not_whitelisted and prints PASS/FAIL for every case.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_all.ps1" %*
exit /b %ERRORLEVEL%
