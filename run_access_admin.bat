@echo off
schtasks.exe /Create /TN FortespAccess /TR "C:\dev\fortesp\run_access.bat" /SC ONCE /ST 23:59 /RU SYSTEM /F
schtasks.exe /Run /TN FortespAccess
ping -n 6 127.0.0.1 >nul
schtasks.exe /Delete /TN FortespAccess /F
