@echo off
cd C:\dev\fortesp\ring0
"C:\tmp\w64devkit\w64devkit\bin\g++.exe" -std=c++17 -O2 -municode -I"C:\dev\fortesp\ring0\include" -o out\fortesp_r0.exe src\main.cpp src\vmm.cpp src\r0.cpp src\esp.cpp src\ov.cpp -ld3d11 -ldxgi -ld3dcompiler -lgdi32 -luser32 -lole32