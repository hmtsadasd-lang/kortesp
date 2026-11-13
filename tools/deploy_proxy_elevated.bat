@echo off
rem Lift the proxy deployment into an elevated session (UAC prompt).
powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','C:\dev\fortesp\tools\deploy_proxy.bat > C:\dev\fortesp\deploy_proxy.out 2>&1' -Verb RunAs -Wait"
echo rc=%errorlevel%
type C:\dev\fortesp\deploy_proxy.out
