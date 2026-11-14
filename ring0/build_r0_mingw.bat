@echo off
cd C:\dev\fortesp\ring0
set W64DK=C:\tmp\w64devkit\w64devkit
set PATH=%W64DK%\bin;%PATH%
if not exist out mkdir out
echo Building Fortnite ESP ring0 driver...
echo.
"C:\tmp\w64devkit\w64devkit\bin\g++.exe" ^
    -std=c++17 -O2 -municode ^
    -Iinclude ^
    -o out\fortesp_r0.exe ^
    src\main.cpp src\vmm.cpp src\r0.cpp src\esp.cpp src\ov.cpp src\cloak.cpp ^
    -ld3d11 -ldxgi -ld3dcompiler -lgdi32 -luser32 -lole32
if errorlevel 1 (
    echo Build FAILED
    pause
    exit /b 1
)
echo Build succeeded.