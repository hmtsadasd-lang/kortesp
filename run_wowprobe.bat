@echo off
"C:\dev\fortesp\out\loader.exe" --wowprobe EasyAntiCheat_EOS.exe > "C:\dev\fortesp\wowprobe.out" 2>&1
echo exit=%errorlevel% >> "C:\dev\fortesp\wowprobe.out"
