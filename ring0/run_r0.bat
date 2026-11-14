@echo off
:: ring0 runner – starts DBUtil_2_3 driver and launches fortesp_r0.exe
:: The driver .sys must sit alongside this script.

:: Ensure the service exists and is started
sc query DBUtil_2_3 >nul 2>&1 ||
(
    echo Creating DBUtil_2_3 service...
    copy /y DBUtil_2_3.sys %SystemRoot%\System32\drivers\ >nul
    sc create DBUtil_2_3 type= kernel start= demand ^
        binPath= %SystemRoot%\System32\drivers\DBUtil_2_3.sys >nul
)

sc start DBUtil_2_3 2>nul

:: Launch the compiled EXE with --probe flag
echo Starting fortesp_r0.exe --probe...
cd /d "%~dp0"
out\fortesp_r0.exe --probe