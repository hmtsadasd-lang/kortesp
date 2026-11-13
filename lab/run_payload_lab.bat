@echo off
rem Payload delivery lab: thin wrapper around lab\run_all.ps1.
rem
rem Same suite as run_lab.bat; the payload cases (entered / target mode /
rem worker up) and the mapper trace run unless -Quick is passed.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_all.ps1" %*
exit /b %ERRORLEVEL%
