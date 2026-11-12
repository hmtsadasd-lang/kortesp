@echo off
del /f /q "C:\dev\fortesp\access_probe.out" >nul 2>&1
sc.exe stop EasyAntiCheat_EOS > "C:\dev\fortesp\svc_swap.out" 2>&1
sc.exe config EasyAntiCheat_EOS binPath= "C:\dev\fortesp\out\loader.exe --access" >> "C:\dev\fortesp\svc_swap.out" 2>&1
sc.exe query EasyAntiCheat_EOS >> "C:\dev\fortesp\svc_swap.out" 2>&1
sc.exe start EasyAntiCheat_EOS >> "C:\dev\fortesp\svc_swap.out" 2>&1
ping -n 6 127.0.0.1 >nul
sc.exe stop EasyAntiCheat_EOS >> "C:\dev\fortesp\svc_swap.out" 2>&1
sc.exe config EasyAntiCheat_EOS binPath= "\"C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe\"" >> "C:\dev\fortesp\svc_swap.out" 2>&1
sc.exe qc EasyAntiCheat_EOS >> "C:\dev\fortesp\svc_swap.out" 2>&1
