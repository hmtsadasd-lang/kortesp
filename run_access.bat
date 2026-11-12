@echo off
whoami /user > C:\dev\fortesp\access.out 2>&1
whoami /groups >> C:\dev\fortesp\access.out 2>&1
"C:\dev\fortesp\out\loader.exe" --access >> C:\dev\fortesp\access.out 2>&1
