@echo off
rem build_proxy_mingw.bat <dll-name>
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_proxy_mingw.ps1" -Name %1
exit /b %errorlevel%
