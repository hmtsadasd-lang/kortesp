@echo off
rem Elevated harness wrapper: run_wowprobe.bat itself stays exactly as specified.
rem This wrapper only adds the privilege context the probe needs to tell
rem "unelevated" apart from "protected", and runs the sibling probes in the
rem same elevated session.
echo === start EAC service (if stopped) ===
sc query EasyAntiCheat_EOS | findstr /i "STATE"
sc start EasyAntiCheat_EOS
timeout /t 3 /nobreak > nul
sc query EasyAntiCheat_EOS | findstr /i "STATE"
echo === running elevated batch ===
cd /d C:\dev\fortesp
cmd /c "C:\dev\fortesp\run_wowprobe.bat"
echo wowprobe_exit=%errorlevel%
echo === wowprobe.out ===
type C:\dev\fortesp\wowprobe.out
echo === dupprobe ===
out\loader.exe --dupprobe > dupprobe_run.out 2>&1
type dupprobe_run.out
echo ALL_DONE
