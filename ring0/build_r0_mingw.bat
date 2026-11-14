@echo off
set W64DK=C:\tmp\w64devkit\w64devkit
set PATH=%W64DK%\bin;%PATH%
if not exist out mkdir out
g++ -std=c++17 -O2 -municode -static -o out\fortesp_r0.exe ^
    ring0\src\main.cpp ring0\src\vmm.cpp ring0\src\r0.cpp ring0\src\esp.cpp ring0\src\ov.cpp ^
    -ld3d11 -ldxgi -ld3dcompiler -lgdi32 -luser32 -lole32