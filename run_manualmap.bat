@echo off
del /f /q "C:\Users\Public\fortesp2.log" >nul 2>&1
"C:\dev\fortesp\out\loader.exe" "C:\dev\fortesp\out\payload.dll" > "C:\dev\fortesp\manualmap.out" 2>&1
echo exit=%errorlevel% >> "C:\dev\fortesp\manualmap.out"
