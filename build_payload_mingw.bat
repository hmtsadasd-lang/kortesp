@echo off
rem Thin wrapper: the real build logic lives in build_payload_mingw.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_payload_mingw.ps1" %*
exit /b %errorlevel%
