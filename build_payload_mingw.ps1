# MinGW-w64 build for the payload DLL.
#
# Mirrors payload.vcxproj: freestanding (no CRT), custom entry point
# "start", MASM stubs replaced by shared/src/stubs_gas.S for the GNU
# assembler.
param(
    [string]$W64DK = $env:W64DK,
    [string]$Root = 'C:\dev\fortesp'
)

$ErrorActionPreference = 'Stop'
if (-not $W64DK) { $W64DK = 'C:\tmp\w64devkit\w64devkit' }
$tc = Join-Path $W64DK 'bin'
$gpp = Join-Path $tc 'g++.exe'
$gcc = Join-Path $tc 'gcc.exe'
if (-not (Test-Path $gpp)) {
    Write-Host "[build] no g++ at $gpp"
    Write-Host "[build] set W64DK to a w64devkit or mingw-w64 x64 install root"
    exit 1
}

$obj = Join-Path $Root 'out\obj\payload_mingw'
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
    '-municode', '-std=c++20', '-c', '-O2', '-fno-threadsafe-statics',
    '-DNDEBUG', '-DWIN32', '-D_WINDOWS', '-DWIN32_LEAN_AND_MEAN', '-DNOMINMAX', '-DWIN64',
    "-I$(Join-Path $Root 'shared\include')", "-I$(Join-Path $Root 'payload\include')",
    "-I$(Join-Path $Root 'payload\src')"
)

$units = @('entry', 'game', 'hide', 'log', 'map', 'render', 'libc_min')
foreach ($u in $units) {
    Invoke-Tool $gpp ($cxxFlags + @((Join-Path $Root "payload\src\$u.cpp"), '-o', (Join-Path $obj "$u.o"))) "compiling $u.cpp"
}
Invoke-Tool $gpp ($cxxFlags + @((Join-Path $Root 'shared\src\crt.cpp'), '-o', (Join-Path $obj 'crt.o'))) 'compiling crt.cpp'
Invoke-Tool $gpp ($cxxFlags + @((Join-Path $Root 'shared\src\syscall.cpp'), '-o', (Join-Path $obj 'syscall.o'))) 'compiling syscall.cpp'
Invoke-Tool $gcc @('-c', (Join-Path $Root 'shared\src\stubs_gas.S'), '-o', (Join-Path $obj 'stubs.o')) 'assembling stubs_gas.S'

$linkArgs = @(
    '-shared', '-nostdlib', '-Wl,--entry=start', '-Wl,--subsystem=windows',
    '-o', (Join-Path $Root 'out\payload.dll')
)
foreach ($u in $units) { $linkArgs += (Join-Path $obj "$u.o") }
$linkArgs += (Join-Path $obj 'crt.o')
$linkArgs += (Join-Path $obj 'syscall.o')
$linkArgs += (Join-Path $obj 'stubs.o')
$linkArgs += @('-ld3d11', '-ldxgi', '-luser32', '-lgdi32', '-lntdll', '-lkernel32', '-ladvapi32', '-lshell32')
Invoke-Tool $gpp $linkArgs 'linking payload.dll'

Write-Host "[build] done -> $(Join-Path $Root 'out\payload.dll')"
