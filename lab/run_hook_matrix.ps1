# The hook-injection matrix: does a target with the *client's* I/O design drive
# the hook families that stay silent in the game?
#
# This is the discriminator between the two explanations for the game's silence:
#
#   A. the client's PeekMessage/raw-input design never drives those hooks, or
#   B. the injection (LoadLibrary of FortHook.dll) is refused inside the client.
#
# It builds the hook DLL, the matrix harness and the fixtures, then runs the
# matrix against:
#   * out\lab\mock_gui.exe     - GetMessage control (everything must fire)
#   * out\lab\mock_client.exe  - get    : GetMessage loop
#   * out\lab\mock_client.exe  - peek   : PeekMessage loop, legacy input
#   * out\lab\mock_client.exe  - raw    : PeekMessage + RIDEV_NOLEGACY (the
#                                          real client's design)
#   * the same raw target with a global (tid=0) instal
#
# Results land in lab\matrix_*.out. No elevation is needed: the fixtures are
# not elevated, so a hook from this process can reach them. The live client is
# a different story (its manifest elevates it) and is measured separately.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File lab\run_hook_matrix.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$lab  = Join-Path $root 'out\lab'
$out  = Join-Path $root 'out'
$bin  = 'C:\tmp\w64devkit\w64devkit\bin'
$gcc  = Join-Path $bin 'gcc.exe'
$gpp  = Join-Path $bin 'g++.exe'

Set-Location $root
if (-not (Test-Path $lab)) { New-Item -ItemType Directory -Path $lab | Out-Null }

function Build([string]$Exe, [string[]]$ToolArgs, [string]$What) {
    & $Exe @ToolArgs 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "build failed: $What" }
    Write-Host ("[build] {0}" -f $What)
}

Write-Host '=== building hook DLL and tools ==='
$bh = Start-Process -FilePath 'powershell.exe' -NoNewWindow -Wait -PassThru `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $root 'build_hook.ps1')`"")
if ($bh.ExitCode -ne 0) { throw 'build_hook.ps1 failed' }

Write-Host '=== building fixtures ==='
Build $gcc @('-m64', '-O2', '-static', '-o', (Join-Path $lab 'mock_gui.exe'),    (Join-Path $PSScriptRoot 'mock_gui.c'),    '-luser32') 'mock_gui'
Build $gcc @('-m64', '-O2', '-static', '-o', (Join-Path $lab 'mock_client.exe'), (Join-Path $PSScriptRoot 'mock_client.c'), '-luser32') 'mock_client'
Build $gpp @('-std=c++20', '-O2', '-static', '-municode', '-o', (Join-Path $lab 'hook_matrix.exe'), (Join-Path $PSScriptRoot 'hook_matrix.cpp'), '-luser32') 'hook_matrix'

$matrix = Join-Path $lab 'hook_matrix.exe'

function Run([string]$File, [string]$Target, [string]$Class, [string]$Mode, [int]$Secs, [string]$Scope) {
    Write-Host ("--- {0} ({1} {2} {3}) ---" -f (Split-Path -Leaf $File), $Class, $Mode, $Scope)
    $a = @($Target, $Class, $Mode, "$Secs", $Scope) | Where-Object { $_ -ne '' }
    $o = & $matrix @a 2>&1 | Out-String
    $o | Set-Content -Path (Join-Path $lab $File) -Encoding UTF8
    # Print just the result table, not the install dump.
    ($o -split "`r?`n" | Where-Object { $_ -match '^(DllMain|family|GetMsgProc|CallWndProc|CbtProc|IdleProc|KbdProc|MouseProc|HwProc|HookProc|WinEventProc|\[\*\] mock|\[\*\] raw input|\[\*\] ticks)' }) | ForEach-Object { Write-Host $_ }
}

$gui    = Join-Path $lab 'mock_gui.exe'
$client = Join-Path $lab 'mock_client.exe'

Run 'matrix_gui.out'        $gui    'MockGuiTarget'    ''     8  'tl'
Run 'matrix_client_get.out' $client 'MockClientWindow' 'get'  8  'tl'
Run 'matrix_client_peek.out' $client 'MockClientWindow' 'peek' 8 'tl'
Run 'matrix_client_raw.out' $client 'MockClientWindow' 'raw'  8  'tl'
Run 'matrix_client_raw_global.out' $client 'MockClientWindow' 'raw' 8 'global'

Write-Host ''
Write-Host ("results in {0}\matrix_*.out" -f $lab)
