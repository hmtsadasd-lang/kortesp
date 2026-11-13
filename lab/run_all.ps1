# Regression suite for the Fortnite research toolkit.
#
# Builds the lab, runs the probes and asserts the facts the project already
# measured. Every case prints PASS or FAIL <case> <expected> <got>; the exit
# code is the number of failed cases.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File lab\run_all.ps1
#   powershell ... -File lab\run_all.ps1 -Quick      # skip the mapper case
#   powershell ... -File lab\run_all.ps1 -KeepUp     # leave the mocks running
#
# The two .bat scripts in this folder are thin wrappers around this file.

param(
    [switch]$Quick,
    [switch]$KeepUp
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$lab  = Join-Path $root 'out\lab'
$out  = Join-Path $root 'out'
$tc   = 'C:\tmp\w64devkit\w64devkit\bin\gcc.exe'

$script:failed = 0
$script:passed = 0

function Case {
    param([string]$Name, [string]$Expected, [string]$Got)
    if ($Got -eq $Expected) {
        $script:passed++
        Write-Host ("PASS {0}" -f $Name)
    } else {
        $script:failed++
        Write-Host ("FAIL {0} expected={1} got={2}" -f $Name, $Expected, $Got)
    }
}

function CaseMatch {
    param([string]$Name, [string]$Pattern, [string]$Got)
    # -match on a here-string is fine; the split is only there because a
    # multi-line value must match line by line, not as one blob.
    $hit = ($Got -split "`r?`n" | Where-Object { $_ -match $Pattern }).Count -gt 0
    if ($hit) {
        $script:passed++
        Write-Host ("PASS {0}" -f $Name)
    } else {
        $script:failed++
        Write-Host ("FAIL {0} expected~={1} got={2}" -f $Name, $Pattern, $Got)
    }
}

# The field of the last "key=value" line the probe printed.
function Field {
    param([string]$Text, [string]$Key)
    $m = [regex]::Matches($Text, "(?m)(?:^|\s)" + [regex]::Escape($Key) + "=([^ \r\n]+)")
    if ($m.Count -eq 0) { return '<absent>' }
    return $m[$m.Count - 1].Groups[1].Value
}

function Build([string]$Out, [string[]]$Flags, [string]$What) {
    if (-not (Test-Path $tc)) { throw "toolchain missing: $tc" }
    $all = @($Flags) + @('-o', $Out)
    & $tc @all 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "build failed: $What" }
    Write-Host ("[build] {0}" -f (Split-Path -Leaf $Out))
}

function StartMock([string]$Name) {
    $p = Join-Path $lab $Name
    Start-Process -FilePath $p -WindowStyle Minimized | Out-Null
    Start-Sleep -Milliseconds 1500
    $proc = Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($Name)) -ErrorAction SilentlyContinue
    if (-not $proc) { throw "$Name did not start" }
    return $proc[0].Id
}

function StopMocks {
    $kill = Join-Path $lab 'kill_mask.exe'
    foreach ($n in 'MockGame.exe', 'MockHost.exe') {
        if (Test-Path $kill) { & $kill $n | Out-Null } else {
            Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($n)) -ErrorAction SilentlyContinue |
                Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 500
}

Write-Host '=== fort esp regression suite ==='

# ---------------------------------------------------------------- build ----
if (-not (Test-Path $lab)) { New-Item -ItemType Directory -Path $lab | Out-Null }

# The mocks must be gone before their images are rebuilt: a running MockGame
# holds its own exe open, and ld answers with "Permission denied".
StopMocks

Build (Join-Path $lab 'kill_mask.exe') @('-O2', '-static', (Join-Path $PSScriptRoot 'kill_mask.c')) 'kill_mask'
Build (Join-Path $lab 'MockGame.exe')  @('-m64', '-O2', '-static', (Join-Path $PSScriptRoot 'mock_game.c'), '-ladvapi32') 'MockGame'
Build (Join-Path $lab 'MockHost.exe')  @('-m32', '-O2', '-static', (Join-Path $PSScriptRoot 'mock_host.c')) 'MockHost'
Build (Join-Path $lab 'probe_thread.exe') @('-m64', '-O2', '-static', (Join-Path $PSScriptRoot 'probe_thread.c')) 'probe_thread'

foreach ($s in 'build_mingw.ps1', 'build_payload_mingw.ps1') {
    $script = Join-Path $root $s
    $p = Start-Process -FilePath 'powershell.exe' -NoNewWindow -Wait -PassThru `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$script`"")
    if ($p.ExitCode -ne 0) { throw "build failed: $s" }
    Write-Host ("[build] {0}" -f $s)
}
Case 'loader exists'  'True' ([string](Test-Path (Join-Path $out 'loader.exe')))
Case 'payload exists' 'True' ([string](Test-Path (Join-Path $out 'payload.dll')))

# ------------------------------------------------------- decision table ----
# The mock game masks every handle at 0x11F145, the same mask the real client
# reports, so the probe has to take the not_whitelisted branch here as well.
StopMocks
$null = StartMock 'MockGame.exe'
$script:hostPid = StartMock 'MockHost.exe'

$probe = & (Join-Path $out 'loader.exe') --wowprobe MockHost.exe MockGame.exe 2>&1 | Out-String
$probeFile = Join-Path $lab 'probe.out'
$probe | Set-Content -Path $probeFile -Encoding UTF8
Write-Host ("[run] --wowprobe -> {0}" -f $probeFile)

# The "facts" line is the probe's own summary of the branch it took, so the
# assertions read it instead of the per-call lines above it.
# $probe is one string; split it, keep the summary line, and drop the
# carriage return so the last field is not "5`r".
$factLine = ($probe -split "`n" | Where-Object { $_ -match '^facts ' } | Select-Object -Last 1)
$facts = "$factLine".Trim()
Case 'granted mask'      '0x0011F145' (Field $facts 'granted')
Case 'VirtualAllocEx'    '0x0'        (Field $facts 'alloc')
Case 'last error'        '5'          (Field $facts 'lasterr')
Case 'wow64 detected'    '1'          (Field $probe 'wow64')
CaseMatch 'decision branch' '^decision=not_whitelisted' $probe
CaseMatch 'stub reached the game' '^stub whitelist_handle=0x[0-9A-F]+' $probe

# The same three facts, measured from inside the 32 bit host by the stub.
$stub = ($probe -split "`n" | Where-Object { $_ -match '^stub whitelist_' }) -join "`n"
Case 'stub granted mask' '0x0011F145' (Field $stub 'whitelist_granted')
Case 'stub alloc'        '0x0'        (Field $stub 'whitelist_alloc')
Case 'stub last error'   '5'          (Field $stub 'whitelist_lasterr')

# ------------------------------------------------------------ open paths ----
# Both masks are probed against both processes; a DACL that caps at 0x11F145
# must answer ALL_ACCESS with the capped mask, not with a refusal.
# A DACL that caps at 0x11F145 refuses ALL_ACCESS outright (0xC0000022) and
# grants the capped mask when that mask is asked for exactly.
CaseMatch 'game ALL_ACCESS refused' '^open_path GAME ALL_ACCESS .*ntstatus=0xC0000022' $probe
CaseMatch 'game 0x11F145 granted'   '^open_path GAME 0x11F145 .*granted=0x0011F145' $probe

# ------------------------------------------------------ thread hygiene ------
# A thread handle created by NtCreateThreadEx is not a handle the context
# APIs accept; a DUP_HANDLE duplicate is. This is the finding the WOW64
# fallback depends on.
# Usage: probe_thread.exe <pid of a 32 bit process>
$pt = (& (Join-Path $lab 'probe_thread.exe') $script:hostPid 2>&1 | Out-String).Trim()
$pt | Set-Content -Path (Join-Path $lab 'probe_thread.out') -Encoding UTF8
Write-Host '[run] probe_thread'
CaseMatch 'local thread created'        'NtCreateThreadEx st=0x00000000' $pt
CaseMatch 'local context readable'      'NtGetContextThread\(x86\) st=0x00000000' $pt
# probe_thread's own run: the raw handle is accepted for a thread created
# suspended in a host that does not police it. The loader's 0xC0000005 on the
# same call is measured there, not here, so this case asserts the control:
# both handles behave alike for a thread this process started.
# The host run is reported, not asserted: a 32 bit host that refuses a
# foreign thread start answers differently from one that does not, and both
# are informative (see docs/SESSION_NOTES.md, item 1d).
Write-Host ('[info] probe_thread: ' + (($pt -split "`r?`n" | Where-Object { $_ -match '^\[host' }) -join ' | '))

# ------------------------------------------------------------ manual map ----
# Skipped with -Quick: the mapper runs a whole DLL's entry point in a spawned
# process and takes minutes.
if (-not $Quick) {
    $log = 'C:\Users\Public\fortesp2.log'
    if (Test-Path $log) { Remove-Item $log -Force }
    $map = & (Join-Path $out 'loader.exe') --maptest (Join-Path $out 'payload.dll') 2>&1 | Out-String
    $map | Set-Content -Path (Join-Path $lab 'maptest.out') -Encoding UTF8
    Write-Host '[run] --maptest'
    # The mapper's trace is the assertion that matters: the payload's TLS
    # callback ran (A0) and its entry reached the branch selector (B0). The
    # thread's own exit code is reported for the record, not asserted - a
    # 64 bit host is not a client and the payload is expected to bail out.
    # The entry thread has to run the image and finish with exit 0. It used to
    # be asserted only that it exited at all, because the real answer was
    # 0xC0000005; now the payload degrades off-client and returns cleanly, so a
    # non-zero exit is a regression.
    CaseMatch 'mapped entry point ran'  'mm: thread exit=' $map
    CaseMatch 'entry thread exited 0'   'mm: thread exit=0 ' $map
    CaseMatch 'maptest reported success' 'maptest ran=1 exit=0 ' $map
    CaseMatch 'export directory copied'  'export directory copied to rva' $map
    Write-Host ('[info] maptest: ' + (($map -split "`n" | Where-Object { $_ -match 'mm: (thread exit|trace)' }) -join ' | '))

    # The payload's target mode has to come up, and its game::init() has to
    # degrade visibly instead of hanging or crashing. The payload writes its
    # log with CreateFileW(UTF-16 path), so it reads back as Unicode.
    $text = ''
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        # Read it with .NET, not Get-Content: the payload writes UTF-16LE with
        # no BOM, and Get-Content -Encoding Unicode on a file another process
        # still holds open comes back empty on this build - which reads as
        # "the payload never logged" when the file is right there.
        if (Test-Path $log) {
            try {
                $fs = [System.IO.File]::Open($log, 'Open', 'Read', 'ReadWrite')
                $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::Unicode)
                $text = $sr.ReadToEnd()
                $sr.Dispose(); $fs.Dispose()
            } catch { $text = '' }
        }
        if ($text -and $text -match 'worker up') { break }
    }
    if (-not $text) { $text = '' }
    $text | Set-Content -Path (Join-Path $lab 'payload.log.txt') -Encoding UTF8
    Write-Host '[run] payload log'
    # The log is the payload's own; its absence is a finding, not a broken
    # assertion. `entered` is the one line that must always be there.
    CaseMatch 'payload entered'    'entered' $text
    if ($text -match 'target mode') { $script:passed++; Write-Host 'PASS target mode chosen' }
    else { $script:failed++; Write-Host 'FAIL target mode chosen (payload did not get that far)' }
    if ($text -match 'worker up') { $script:passed++; Write-Host 'PASS worker started' }
    else { $script:failed++; Write-Host 'FAIL worker started (payload did not get that far)' }
    # The worker thread has to be created and resumed, and game::init() has to
    # degrade with a reason instead of faulting.
    if ($text -match 'worker laundered') { $script:passed++; Write-Host 'PASS worker thread resumed' }
    else { $script:failed++; Write-Host 'FAIL worker thread resumed' }
    # Off-client game::init must refuse the chain and say why. The wording moved
    # when the base started coming from the client module (found by name) instead
    # of from this image, so both refusals are accepted.
    if ($text -match 'game::init: (.*not the client|GEngine address outside the client image|client module not found)') { $script:passed++; Write-Host 'PASS game::init degrades off-client' }
    else { $script:failed++; Write-Host 'FAIL game::init degrades off-client' }
    if ($text -match 'degraded exit') { $script:passed++; Write-Host 'PASS worker exits cleanly' }
    else { $script:failed++; Write-Host 'FAIL worker exits cleanly' }
}

if (-not $KeepUp) { StopMocks }

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:passed, $script:failed)
exit $script:failed
