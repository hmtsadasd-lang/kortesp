@echo off
rem The live matrix, both passes, run elevated (see run_matrix_elevated.bat).
set HM=C:\dev\fortesp\out\lab\hook_matrix.exe
"%HM%" --attach FortniteClient-Win64-Shipping.exe UnrealWindow 60 tl     > C:\dev\fortesp\hook_matrix_client.out 2>&1
"%HM%" --attach FortniteClient-Win64-Shipping.exe UnrealWindow 60 global > C:\dev\fortesp\hook_matrix_client_global.out 2>&1
