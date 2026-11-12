@echo off
del /f /q "C:\Users\Public\fortesp2.log" >nul 2>&1
"C:\dev\fortesp\out\loader.exe" --hosttest FortniteClient-Win64-Shipping_EAC_EOS.exe "C:\dev\fortesp\out\payload.dll" start > "C:\dev\fortesp\hosttest.out" 2>&1
echo exit=%errorlevel% >> "C:\dev\fortesp\hosttest.out"
