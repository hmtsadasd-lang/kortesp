@echo off
setlocal
set OBD=C:\tmp\w64devkit\w64devkit\bin\objdump.exe
if not exist "%OBD%" (echo NO OBJDUMP & exit /b 1)
"%OBD%" -d -M intel "C:\dev\fortesp\ring0\driver\dbutil_2_3.sys" > "%TEMP%\dbutil.asm" 2>&1
echo === file size ===
dir /b "%TEMP%\dbutil.asm"
echo.
echo === immediate compares in the 0x0022xxxx range (FILE_DEVICE_UNKNOWN) ===
findstr /r /c:"cmp.*0x[0-9a-f]*2[0-9a-f]2[0-9a-f]" "%TEMP%\dbutil.asm"
echo.
echo === all distinct cmp-immediates over 0x1000 ===
findstr /r /c:"cmp.*0x[0-9a-f]\{5,\}" "%TEMP%\dbutil.asm"
endlocal
