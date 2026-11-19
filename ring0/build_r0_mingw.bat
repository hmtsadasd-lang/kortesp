@echo off
setlocal
cd /d C:\dev\fortesp\ring0
if "%W64DK%"=="" set W64DK=C:\tmp\w64devkit\w64devkit
set PATH=%W64DK%\bin;%PATH%
if not exist out mkdir out

echo Building fortesp_r0.exe (MinGW-w64)...
"%W64DK%\bin\g++.exe" -std=c++17 -O2 -municode -mconsole -Wall -Wextra ^
    -Wno-unused-parameter -Wno-cast-function-type ^
    -Iinclude -Isrc ^
    -o out\fortesp_r0.exe ^
    src\main.cpp src\vmm.cpp src\r0.cpp src\esp.cpp src\cloak.cpp src\mock.cpp src\mem.cpp ^
    -ld3d11 -ldxgi -ld3dcompiler -lgdi32 -luser32 -lole32 -static-libgcc -static-libstdc++
if errorlevel 1 (
    echo Build FAILED
    exit /b 1
)
echo Build succeeded: out\fortesp_r0.exe
