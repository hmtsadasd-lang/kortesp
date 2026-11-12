@echo off
cd /d C:\dev\fortesp
del /q wowprobe.out 2>nul
out\loader.exe --wowprobe > wowprobe.out 2>&1
echo exit=%errorlevel% >> wowprobe.out
