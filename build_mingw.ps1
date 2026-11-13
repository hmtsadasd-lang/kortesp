# MinGW-w64 build for the loader.
#
# The MSVC solution (fortesp.sln) is still the reference build; this script
# exists because this box has no MSVC toolchain. It produces an equivalent
# x64 loader.exe with the same console subsystem.
#
# Toolchain: w64devkit (x86_64-w64-mingw32).
#   $env:W64DK = 'C:\tools\w64devkit\w64devkit'
param(
    [string]$W64DK = $env:W64DK,
    [string]$Root = 'C:\dev\fortesp'
)

$ErrorActionPreference = 'Stop'
if (-not $W64DK) { $W64DK = 'C:\tmp\w64devkit\w64devkit' }
$tc = Join-Path $W64DK 'bin'
$gpp = Join-Path $tc 'g++.exe'
if (-not (Test-Path $gpp)) {
    Write-Host "[build] no g++ at $gpp"
    Write-Host "[build] set W64DK to a w64devkit or mingw-w64 x64 install root"
    exit 1
}

$obj = Join-Path $Root 'out\obj\loader_mingw'
New-Item -ItemType Directory -Force -Path $obj | Out-Null

function Invoke-Tool([string]$exe, [string[]]$toolArgs, [string]$label) {
    Write-Host "[build] $label"
    $p = Start-Process -FilePath $exe -ArgumentList $toolArgs -NoNewWindow -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        Write-Host "[build] FAILED: $label (exit $($p.ExitCode))"
        exit $p.ExitCode
    }
}

$cxxFlags = @(
    '-mconsole', '-municode', '-std=c++20', '-c', '-O2',
    '-DNDEBUG', '-DWIN32', '-D_WINDOWS', '-DWIN32_LEAN_AND_MEAN', '-DNOMINMAX', '-DWIN64',
    "-I$(Join-Path $Root 'shared\include')", "-I$(Join-Path $Root 'loader\src')"
)

Invoke-Tool $gpp ($cxxFlags + @((Join-Path $Root 'loader\src\main.cpp'), '-o', (Join-Path $obj 'main.o'))) 'compiling main.cpp'
Invoke-Tool $gpp ($cxxFlags + @((Join-Path $Root 'loader\src\handle.cpp'), '-o', (Join-Path $obj 'handle.o'))) 'compiling handle.cpp'
Invoke-Tool $gpp ($cxxFlags + @((Join-Path $Root 'shared\src\map_host.cpp'), '-o', (Join-Path $obj 'map_host.o'))) 'compiling map_host.cpp'
Invoke-Tool $gpp ($cxxFlags + @((Join-Path $Root 'shared\src\lateral.cpp'), '-o', (Join-Path $obj 'lateral.o'))) 'compiling lateral.cpp'

Invoke-Tool $gpp (@(
    '-mconsole', '-municode', '-static', '-static-libgcc', '-static-libstdc++',
    '-o', (Join-Path $Root 'out\loader.exe'),
    (Join-Path $obj 'main.o'), (Join-Path $obj 'handle.o'), (Join-Path $obj 'map_host.o'), (Join-Path $obj 'lateral.o'),
    '-ladvapi32', '-lshell32'
)) 'linking loader.exe'

Write-Host "[build] done -> $(Join-Path $Root 'out\loader.exe')"
