@echo off
:: elevated; the driver must already sit next to this script
sc query DBUtil_2_3 >nul 2>&1 || (
  copy /y DBUtil_2_3.sys %SystemRoot%\System32\drivers\ >nul
  sc create DBUtil_2_3 type= kernel start= demand binPath= System32\drivers\DBUtil_2_3.sys
)
sc start DBUtil_2_3
out\fortesp_r0.exe