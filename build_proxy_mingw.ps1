# MinGW-w64 build for the proxy DLL.
#
# The proxy is named after the DLL it shadows (EOSSDK-Win64-Shipping.dll by
# default - it is the only DLL the Fortnite client loads from its own
# directory) and carries the forwarders from loader\src\<name>.def, so the
# game keeps working while the payload is mapped into it.
#
#   build_proxy_mingw.bat [name]      -> out\<name>.dll
param(
    [string]$W64DK = $env:W64DK,
    [string]$Root = 'C:\dev\fortesp',
    [string]$Name = 'EOSSDK-Win64-Shipping'
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

$obj = Join-Path $Root "out\obj\proxy_mingw"
New-Item -ItemType Directory -Force -Path $obj | Out-Null

function Invoke-Tool([string]$exe, [string[]]$toolArgs, [string]$label) {
    Write-Host "[build] $label"
    $p = Start-Process -FilePath $exe -ArgumentList $toolArgs -NoNewWindow -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        Write-Host "[build] FAILED: $label (exit $($p.ExitCode))"
        exit $p.ExitCode
    }
}

$def = Join-Path $Root "loader\src\$Name.def"
if (-not (Test-Path $def)) {
    Write-Host "[build] missing $def - run tools\gen_def.bat $Name"
    exit 1
}

$cxxFlags = @(
    '-std=c++20', '-c', '-O2',
    '-DNDEBUG', '-DWIN32', '-D_WINDOWS', '-DWIN32_LEAN_AND_MEAN', '-DNOMINMAX', '-DWIN64',
    "-I$(Join-Path $Root 'shared\include')", "-I$(Join-Path $Root 'loader\src')",
    "-I$obj"
)

# The name of the real library is baked into a header: it contains dashes and
# would not survive a command line definition.
$cfg = Join-Path $obj 'proxy_config.h'
@(
    '#pragma once',
    ('#define PROXY_REAL_NAME "' + $Name + '_real.dll"')
) | Set-Content -Path $cfg -Encoding ascii
Write-Host "[build] proxy real name: ${Name}_real.dll"

Invoke-Tool $gpp ($cxxFlags + @((Join-Path $Root 'loader\src\proxy.cpp'), '-o', (Join-Path $obj 'proxy.o'))) 'compiling proxy.cpp'
Invoke-Tool $gpp ($cxxFlags + @((Join-Path $Root 'shared\src\map_host.cpp'), '-o', (Join-Path $obj 'map_host.o'))) 'compiling map_host.cpp'

$outDll = Join-Path $Root "out\$Name.dll"
Invoke-Tool $gpp (@(
    '-shared', '-static-libgcc', '-static-libstdc++',
    '-o', $outDll,
    (Join-Path $obj 'proxy.o'), (Join-Path $obj 'map_host.o'), $def
)) "linking $Name.dll (proxy)"

# ld always numbers exports from 1; the DLL we shadow may start elsewhere, so
# the ordinal base is copied over from the original.
$orig = Join-Path $Root "out\${Name}_original.dll"
if (-not (Test-Path $orig)) {
    $gameroot = 'C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64'
    $src = Join-Path $gameroot "$Name.dll"
    if (-not (Test-Path $src)) { $src = Join-Path $gameroot "${Name}_real.dll" }
    if (-not (Test-Path $src)) { $src = "C:\Windows\System32\$Name.dll" }
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $orig -Force
        Write-Host "[build] original copied from $src"
    }
}
if (Test-Path $orig) {
    Invoke-Tool 'python' @((Join-Path $Root 'tools\patch_exports.py'), $outDll, $orig) 'patching export ordinal base'
}

Write-Host "[build] done -> $outDll"
