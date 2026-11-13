# Build FortHook.dll (the desktop-hook delivery module) and hook_deliver.exe.
#
#   build_hook.ps1   -> out\FortHook.dll, out\hook_deliver.exe
param(
    [string]$W64DK = $env:W64DK,
    [string]$Root = 'C:\dev\fortesp'
)
$ErrorActionPreference = 'Stop'
if (-not $W64DK) { $W64DK = 'C:\tmp\w64devkit\w64devkit' }
$tc = Join-Path $W64DK 'bin'
$gpp = Join-Path $tc 'g++.exe'
$obj = Join-Path $Root 'out\obj\hook'
New-Item -ItemType Directory -Force -Path $obj | Out-Null

function Invoke-Tool([string]$exe, [string[]]$toolArgs, [string]$label) {
    Write-Host "[build] $label"
    $p = Start-Process -FilePath $exe -ArgumentList $toolArgs -NoNewWindow -Wait -PassThru
    if ($p.ExitCode -ne 0) { Write-Host "[build] FAILED: $label"; exit $p.ExitCode }
}

$flags = @(
    '-std=c++20', '-c', '-O2', '-DNDEBUG', '-DWIN32', '-D_WINDOWS', '-DWIN32_LEAN_AND_MEAN', '-DNOMINMAX', '-DWIN64',
    "-I$(Join-Path $Root 'shared\include')"
)

Invoke-Tool $gpp ($flags + @((Join-Path $Root 'tools\FortHook.cpp'), '-o', (Join-Path $obj 'FortHook.o'))) 'compiling FortHook.cpp'
Invoke-Tool $gpp ($flags + @((Join-Path $Root 'shared\src\map_host.cpp'), '-o', (Join-Path $obj 'map_host.o'))) 'compiling map_host.cpp'
Invoke-Tool $gpp (@('-shared', '-static-libgcc', '-static-libstdc++', '-o', (Join-Path $Root 'out\FortHook.dll'),
    (Join-Path $obj 'FortHook.o'), (Join-Path $obj 'map_host.o'), (Join-Path $Root 'tools\FortHook.def'))) 'linking FortHook.dll'

$inc = (Join-Path $Root 'shared\include')
Invoke-Tool $gpp (@('-std=c++20', '-O2', '-DNDEBUG', '-municode', '-I' + $inc,
    (Join-Path $Root 'tools\hook_deliver.cpp'), '-o', (Join-Path $Root 'out\hook_deliver.exe'))) 'linking hook_deliver.exe'
Invoke-Tool $gpp (@('-std=c++20', '-O2', '-DNDEBUG', '-municode',
    (Join-Path $Root 'tools\hook_survey.cpp'), '-o', (Join-Path $Root 'out\hook_survey.exe'))) 'linking hook_survey.exe'
Write-Host "[build] done -> out\FortHook.dll, out\hook_deliver.exe, out\hook_survey.exe"
