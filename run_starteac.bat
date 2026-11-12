@echo off
sc.exe start EasyAntiCheat_EOS > C:\dev\fortesp\eacstart.out 2>&1
sc.exe query EasyAntiCheat_EOS >> C:\dev\fortesp\eacstart.out 2>&1
