@echo off
rem Remove every file of ours from the game directory.
rem
rem A foreign file in the game directory is what made the client refuse to
rem start ("EAC unload timeout") on the first restart, so the directory is
rem kept pristine: the hook DLL is injected from out\ and the payload is
rem read from out\ as well.
setlocal
set GD=C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64
for %%F in (FortHook.dll payload.dll) do (
    if exist "%GD%\%%F" (
        del /f /q "%GD%\%%F"
        echo [clean] removed %%F
    ) else (
        echo [clean] %%F not present
    )
)
echo [clean] remaining non-Epic entries:
for %%F in ("%GD%\*") do echo   %%~nxF
endlocal
