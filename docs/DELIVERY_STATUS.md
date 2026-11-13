# Delivery: state of play after the hook measurements

Updated 13.11.2026, second round. Everything here is a return code from this
machine with the client running; nothing is inferred.

## The one real discovery: the game directory is writable

```
C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64       writable
C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\ThirdParty  writable
```

`BUILTIN\Users` holds `FullControl` on the game directory (Epic's installer
grants it so the game can update itself). **Caveat, checked afterwards:** the
`ALPER\alper` entry with `FullControl` in that ACL matches this account's *name*
but not the SID of the elevated account (the DACL owner entry is from an older
installation). Whether the unelevated token is really covered is what decides
this, and the write test that said "writable" ran in a shell that may have been
elevated. The claim is therefore *unconfirmed*, not established.

That matters because of the loader search order, which is **not** the reason
the `version.dll` experiment failed. That experiment failed for a different
reason: the *anti-cheat* refuses a replaced `version.dll` specifically. A file
that is not a replacement of an existing name, planted in a directory the
client's own loader searches, is not that case.

## What the hook survey actually measured

| tool | result |
|---|---|
| `hook_survey.exe` vs **notepad.exe** | installs **ok** and the DLL is only mapped **after a real stimulus** — the mapping is driven by the target's own thread, so "mapped=no" right after the call means "not yet", not "refused". The harness is sound. |
| `hook_survey.exe` vs **the client** (two fresh client starts, before and after a game restart) | every hook family returns a valid `HHOOK`, and **none** maps the DLL: not in the client's module list, no `DllMain` line. Because the control shows mapping needs the target's own thread activity, this says the client's `UnrealWindow` thread **does not pump a message queue** — the hook install is a no-op, not a refusal. |

So `SetWindowsHookEx` against the client does not reach the loader *through this
window*, and the reason is documented: the client's window thread never walks a
message, so the hook is never called. Two consequences:

1. The failed `version.dll` load and the silent hooks are **the same
   mechanism**: the client only maps a module that is already on its own
   allow-list. The anti-cheat gates *module loads*, not file writes.
2. The hook vector cannot be made to work by changing the hook type or the
   stimulus. It is refused at the loader, before the hook runs.

## What is open, in order of promise

| vector | state | what it needs |
|---|---|---|
| **plant a name the client loads later, in the writable game dir** | untested, now possible | the name itself - which is what `--probe` (LdrpLoadDll / LdrRegisterDllNotification in `payload/src/probe.cpp`) is built to answer, but the probe still needs to get in to answer it |
| file-backed mapped image | helper works | `FILE_LIST_DIRECTORY` on the game directory is granted, so a mapped image can page from a real file instead of being private RWX memory |
| `SetWinEventHook(OUTOFCONTEXT)` | open | the OS calls us per event (control channel, not injection) |
| log channel | **measured working** | any process can append to the client's log files; the reader has to be inside, which is the part that is missing |
| `OpenProcess` / remote write / `CreateRemoteThread` | closed | capped mask `0x11F145`, a real read is refused |
| `version.dll` shadowing | closed | anti-cheat refusal, bisected over five steps |
| `EOSSDK` shadowing | closed | self-validating library |

## The honest gap

There is now a measurable, *writable* directory the client's loader searches,
and an instrument (the probe) that would name the module the client asks for at
runtime. The instrument cannot be run without a first entry, and the first entry
cannot be a hook. The remaining candidates that need no first entry at all:

1. **A name the client *will* ask for after start** - guessed from its own
   import table and the shim's, filtered to names it does not pre-load:
   `dbghelp.dll` (CrashReportClient's), `WinPixEventRuntime.dll` (absent from
   this install - a classic late `LoadLibrary` in UE),
   `GFSDK_Aftermath_Lib.x64.dll`, `PhysX3*.dll`, `xaudio2_9redist.dll`,
   `activation64.dll`. Each is a file the client's loader will search its own
   directory for *if* it asks; planting one costs nothing and the survey of
   which one is actually asked is exactly what the probe would print.
2. **`NtSetInformationProcess`-adjacent paths** are kernel policy, out of scope.

## Reproduce

```
out\hook_survey.exe C:\dev\fortesp\out\FortHook.dll Notepad.exe
out\hook_survey.exe C:\dev\fortesp\out\FortHook.dll FortniteClient-Win64-Shipping.exe
out\log_channel.exe        :: append rights, directory handle, writable dirs
out\loader.exe --lateral   :: the whole boundary table, one run
```

## Correction: how the client's imports are actually wired (measured on the file)

`FortniteClient-Win64-Shipping.exe` on disk has **no import table at all**:

```
nsec 4, opts 0xf0, magic 0x20b
import dir = 0x0    iat = 0x0    tls = 0x1e4f2800    reloc = 0x1e4f3800
sections: 0x1000 (0x1e4da000), 0x1e4db000 (0x1000), 0x1e4dc000 (0xb400), 0x1e4f2800 (0x28e8)
preferred base 0x140000000, SizeOfImage 0x1e4f50e8
```

Four sections, one of them 508 MB, and the file's section table is only a
container: the real image is unpacked in memory by the bootstrap. So *every*
import the running client has was resolved at runtime by its own loader stage,
which is exactly the allow-list that refuses a planted module. A name planted in
the game directory would be seen by the Windows loader, not by that stage - the
two are different code.

The shim `FortniteClient-Win64-Shipping_EAC_EOS.exe` is a normal PE and imports
`KERNEL32, ADVAPI32, SHELL32, CRYPT32, USER32, WS2_32, WINMM, ole32, GDI32,
VERSION, IMM32, OLEAUT32, SETUPAPI, bcrypt` - all system DLLs.

The game directory also holds `FortniteClient-Win64-Shipping.exe.local`
(0 bytes, 13.11 08:00) - an application-directory redirection marker. `.local`
makes the loader prefer the application directory over the system directory for
*every* name, which is the one loader switch that would let a planted system-DLL
name win. It was not created by this project's scripts; it appeared during the
`version.dll` experiments and is 0 bytes. It is worth one deliberate test with a
name the client asks for late, and worth deleting if the test is negative.

Directories next to the binary that a late load would search:
`D3D12\`, `DML\`, `EasyAntiCheat\`, and
`Binaries\ThirdParty\{Discord, NVIDIA, SpeechGraphics}`.

## Update: the client's binary has no import table — and what that implies

`FortniteClient-Win64-Shipping.exe` (508 MB on disk) is a PE with **four
sections and an empty import directory**:

```
import dir 0x0   iat 0x0   reloc 0x1e4f3800   tls 0x1e4f2800
preferred base 0x140000000, SizeOfImage 0x1e4f50e8
```

Everything the running client imports is resolved by its own unpacking stage at
start-up. That stage is a different loader from the Windows one, and it is that
loader which refuses a planted module (the `version.dll` bisection). A file
planted in the game directory would satisfy the *Windows* loader, not this one.

Two facts measured at the same time and worth keeping:

* the game directory is **writable by the user** (`BUILTIN\Users: FullControl`);
* a `FortniteClient-Win64-Shipping.exe.local` marker (0 bytes, created during the
  `version.dll` experiments) was present in that directory and has been
  **removed**; the client was restarted afterwards and runs normally.

## Where this leaves the delivery problem

Measured-open channels, in order of usefulness:

1. **The client's own log files** — any process may append (`log_channel.exe`),
   the file object is shared, so a reader inside the client would receive
   commands from outside. The reader is what is missing.
2. **A file-backed mapped image** — `FILE_LIST_DIRECTORY` on the game directory is
   granted from an unelevated process, so an image can page from a real file.
3. **Out-of-context win events** — `SetWinEventHook` is accepted for the client's
   pid/tid and fires from the OS.

Closed, with the reason on record: remote write (capped mask), `version.dll`
(anti-cheat refusal), hook module load (the client's window thread never pumps),
module planting in the game dir (the client's own loader resolves imports from
its unpacking stage, not through the Windows loader).

The honest summary: with no kernel driver and no handle rights, the only door is
one the client opens by itself, and every door this build opens has been tested
and recorded above.

## The launcher idea, tested: the cap is a process-creation callback

`lab/child_cap.c` / `out/child_cap.exe` runs the same three calls through the
same code path:

```
notepad    pid 12140  OpenProcess(ALL)=0x64                 err=0
notepad    VirtualAllocEx=0x1e77fe00000                     err=0
client launched, pid 9672, sleeping 50 ms before the first call
child      pid 9672   OpenProcess(ALL)=0x0                  err=5
child state: alive (0x103)
```

* The control works: a child we start normally gives a full handle and a real
  allocation. The code path is sound.
* The **client, 50 ms after we launched it**, refuses `OpenProcess(ALL)` with
  `ERROR_ACCESS_DENIED`. `loader --launchvia` gets a handle from
  `ShellExecuteEx` and then `VirtualAllocEx` through it fails with 5 at
  `hint 6, size 0x198000`.

Launching earlier does not help, because the refusal does not come from a
timing race: the anti-cheat registers a **process-creation notification** and
gives every newly created process of interest the same restricted handle, whether
it is launched by the Epic launcher, the shell, or by this project. That is
exactly the Minecraft-launcher idea, and it is why it does not transfer: on
Windows the protection is a kernel callback that sees the process being born, not
a check that runs when someone tries to attach.

Consequence, stated plainly: **no launch timing, no parenting trick and no
debugger attach opens this client.** The only surfaces left are the ones the
client itself opens to the outside, and every one of them has been measured:

| surface | state |
|---|---|
| its own log files (append from any process) | open, reader missing |
| out-of-context win events for its pid/tid | open |
| `FILE_LIST_DIRECTORY` on the game dir | open |
| a module it asks its own loader for | none found; its import table is resolved by its unpacking stage |
| handle rights, hooks, `version.dll`, `EOSSDK` | closed, each with the reason written down |

`out/child_cap.exe <ms>` reproduces the table above in one run.

## New vector found and opened: `vulkan-1.dll` in the game directory

The client's import table is empty, so a file planted next to it is never asked
for by the *client's* loader. The EAC shim next to it,
`FortniteClient-Win64-Shipping_EAC_EOS.exe`, is not like that: it has a normal
import table (KERNEL32, VERSION, SETUPAPI, bcrypt, ...) and its `rodata` carries
a **run-time name list** of optional graphics libraries it loads by name:

```
0042a6e6  psapi.dll       0042a6f0  dxgi.dll       0042a700  combase.dll
0042a710  hid.dll         0042a718  libGLES_CM.dll 0042a740  libEGL.dll
0042a768  d3dcompiler_46  0042a780  d3dcompiler_43 0042a798  libGLESv2.dll
0042a7d8  d3d11.dll       0042a7e8  vulkan-1.dll
```

That is the door: the game directory is writable, and a name on that list is
looked up through the **Windows** loader, which searches the application
directory first. A DLL planted there is loaded by a module that sits on the
anti-cheat's own side of the fence - it is in the same directory, started by the
same launcher, before the client even exists.

Built for it:

* `out/vulkan-1.dll` - the proxy, rebuilt for this name: 252 exports forwarded
  to `vulkan-1_real.dll` (the list comes from Wine's `vulkan-1.spec`, which is
  generated from Khronos `vk.xml`, so the export set is the real one). On the
  first load it copies `%SystemRoot%\System32\vulkan-1.dll` into place as the
  real library - which is the same file a driver install would have put there.
* `tools/vulkan_probe.cpp` / `out/vulkan_probe.exe` - plants a DLL, launches the
  game through the shell from the game directory (740 = it needs the manifest
  path), and reports liveness, then whether the module appears in any Fortnite or
  EAC process.

Measured so far: the plant lands (504050 bytes on disk), the launch starts two
Fortnite processes, and after 12 s **no process has `vulkan-1.dll` in its module
list** and the DLL's `DllMain` never ran. Both processes sit at a `Hata`
("Error") window from the missing EAC service, which is the state this box has
produced since the first experiments of the project - so the shim is not reaching
the point where it asks for the optional libraries.

Next step, in order: start the game the way the launcher does (the
`com.epicgames.launcher://...action=launch` URL, which brings up
`FortniteBootstrapper`, `EAC_EOS` and the `EasyAntiCheat_EOS` service), with the
plant in place, and check the same module list. **The plant must be removed
before any normal test** - it is a DLL named `vulkan-1.dll` in the game
directory.

### Result of that next step: the list is libpng's, not the shim's

Launching through the Epic protocol brought the **whole real chain** up:

```
FortniteBootstrapper 11288
  └ FortniteLauncher 20556
      └ FortniteClient-Win64-Shipping_EAC_EOS.exe 11496
          └ FortniteClient-Win64-Shipping.exe 16676   (window "Fortnite")
EasyAntiCheat_EOS.exe 5524
```

With `vulkan-1.dll` planted in the game directory for that launch, **no process
loaded it**: the plant is still on disk, the client has a normal window, and
nothing in the module lists of any of the five processes matches `vulkan`.

Then the string list was traced properly, and it is not a loader list at all:

* the strings sit in a single contiguous `.rdata` block that also holds
  `Too many open files in system`, `aes-128-gcm`, `camellia-128-ccm`,
  `C:\openssl-unused/cert.pem`, `glLinkProgram`, `MNG features are not allowed
  in a PNG datastream` - i.e. openssl + libpng + a GL shim;
* the only RVA reference to any of them (`0x3f14c -> libEGL.dll`) points into a
  different block; the `vulkan-1.dll` string itself has **no RVA reference and no
  LEA** to it in `.text`.

So `psapi.dll ... vulkan-1.dll` is libpng's message table ("PNG library %s is
incompatible"), not a `LoadLibrary` list. The shim does not ask for those names.
**`vulkan-1.dll` is closed as a vector, and it was closed by measurement, not by
opinion** - the proxy, the forwarders and the probe all still work, the door just
is not there.

The plant was removed from the game directory afterwards (directory back to 69
entries, the state a normal install has).

### The shim's real import table: 419 functions, and no door in it

Enumerated every import of `FortniteClient-Win64-Shipping_EAC_EOS.exe`
(15 DLLs, **419 functions**). The load-bearing ones:

| DLL | count | notable | KnownDLL? |
|---|---|---|---|
| KERNEL32 | 177 | `LoadLibraryA/W`, `LoadLibraryExW`, `GetProcAddress` | yes |
| USER32 | 112 | `SetWindowsHookExW`, `GetMessageW`, raw input, `OpenClipboard` | yes |
| WS2_32 | 25 | by ordinal | yes |
| WINMM / GDI32 / SHELL32 | 21 / 23 / 7 | | yes |
| ADVAPI32 / SETUPAPI / bcrypt | 13 / 6 / 1 | | yes |
| CRYPT32 | 16 | `CertGetCertificateChain`, `CryptQueryObject` | **no - not a KnownDLL** |
| VERSION / IMM32 / OLEAUT32 | 3 / 9 / 1 | `VerQueryValueA`, IME, `#6` | IMM32/OLEAUT32 yes, **VERSION no** |

**Thirteen of the fifteen are KnownDLLs on this machine**, read straight from
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` (37 entries:
`kernel32`, `advapi32`, `USER32`, `GDI32`, `SHELL32`, `ole32`, `OLEAUT32`,
`WS2_32`, `IMM32`, `Setupapi`, `combase` ...). Their imports are resolved from
`System32`; a same-named file in the game directory cannot take their place.

The two that are **not** in that list are `VERSION.dll` and `CRYPT32.dll`, and
that pair is exactly the set of tests this project already ran:

* `VERSION.dll` - replaced in the game directory, byte-identical or rebuilt with
  all 34 exports: the game refuses to start. The refusal is in the anti-cheat,
  not in the loader, which is why `KnownDLLs` alone does not explain it.
* `CRYPT32.dll` - never tried, and it is the one remaining shim import that is
  **not** a KnownDLL. That is the outstanding lead, not `vulkan-1.dll`.

The remaining hole *would* be a runtime name the shim builds itself, so the
lowercase name block was checked for reachability rather than assuming:

* only two 32-bit references into the block exist in the entire file, and both
  are **RIP-relative immediates of `call [rip+disp]` / `mov reg,[rip+disp]`**
  (the bytes look like `ff 15` / `48 8b 0d` around them), i.e. IAT slots, not a
  name table;
* no LEA into the block at all;
* the block's neighbours are libpng/openssl/GL message strings.

Conclusion, measured: the shim loads no library from the game directory. Its
`LoadLibraryA/W/ExW` imports exist, but no name in the binary that reaches them
comes from the game folder.

Candidates that remain, all of them *not* in `KnownDLLs` and none referenced by
this binary: `nvapi64.dll` (driver SDK, searched in the app directory before
`System32` - but only by a module that asks for it, and the shim does not),
`dbghelp.dll` (not listed in the client's loader data), `WinPixEventRuntime.dll`
(absent from this install), `vulkan-1.dll` (closed above). Each of these needs a
loader that names it; none in the game's own chain does.

### `CRYPT32.dll` tried on the real launch: the app directory is not searched at all

Built the proxy from the real export table - **295 named exports**, ordinal base
patched from 1 to the original 1012 - and deployed it together with
`crypt32_real.dll` and `payload.dll`, then launched through the Epic protocol.
All five processes came up (`Bootstrapper 18692 -> Launcher 3028 -> shim 9376 ->
client 22924`, plus `EasyAntiCheat_EOS 24268`).

Which `crypt32.dll` each process actually mapped:

```
FortniteBootstrapper   C:\WINDOWS\System32\CRYPT32.dll     (1 583 032 bytes)
FortniteLauncher       C:\WINDOWS\System32\crypt32.dll     (1 583 032 bytes)
EAC shim               C:\WINDOWS\System32\CRYPT32.dll     (1 583 032 bytes)
client                 (does not import it)
```

The planted proxy is 538 298 bytes. **Not one process mapped it** - and the
proxy's `DllMain` never ran, so it was never even opened. That is a stronger
result than a refusal: `CRYPT32.dll` is not in the 37-entry `KnownDLLs` list, so
this is the one case where the app-directory rule could have applied, and it did
not. The conclusion is that these processes do not search their own directory for
this import at all - the launcher supplies them a fixed, fully-qualified
environment (the bootstrapper and launcher are both mapped from the game folder,
so the directory is right; the import is simply resolved elsewhere).

Together with the earlier `version.dll` bisection this closes the family: **no
DLL planted in the game directory is loaded by the game's launch chain, KnownDLL
or not, referenced or not.** Deployed files removed afterwards; the game folder
is back to the state a normal install has.

## The log-file command channel: built, and where the test stands

The payload now carries a command reader (`payload/src/probe.cpp`, namespace
`ch`) that tails `C:\Users\Public\fortesp2.log` and answers on
`C:\Users\Public\fort_channel.out`, one `ACK ...` line per command:

```
PING                 ACK PING
BASE                 ACK BASE 0x<16 hex>      client base, from the module list
READ <hex> <n>       ACK READ <addr> <n*2 hex> (n <= 32)
U32  <hex>           ACK U32 <addr> 0x<8 hex>
MOD  <name>          ACK MOD <16 hex>         base, or 0
```

It is started from `entry.cpp` before anything else and runs on its own thread
with plain `CreateFileW`/`ReadFile` on a shared file object, deliberately not a
message loop.

`tools/channel_test_v2.cpp` (`out/channel_test.exe`) is the round trip: it starts
the lab mock target, maps the payload in with the project's own mapper, then
appends commands and prints the answers.

**Measured so far, and it is a real finding:** the test run stops at

```
[*] mm: remote=0x10000000 image=0x198000
[!] unresolved KERNEL32.dll!CloseHandle
```

The mapper can no longer resolve `KERNEL32.dll!CloseHandle` after the payload
gained the channel. The channel's use of the Win32 API changed the import
table the mapper walks, and the import resolver is failing on a name every
32/64-bit process has. That is a mapper bug this test exposed (the same class as
the forwarded-export gap already on the backlog), not a channel bug - the channel
code is not reached yet, because the image never finishes mapping.

Next step is small and specific: print which import it is looking at and what
`export_proc` answered for it, in `shared/src/map_host.cpp`, and fix the lookup.
The candidate causes are (a) the ordinal/name table walk in `export_proc`, (b)
the hint/name RVA arithmetic on the new `.idata`, and (c) `CloseHandle` arriving
as an ordinal import rather than a name in the rebuilt image.

## Correction, 13.11.2026 (later): the mapper bug is fixed and the channel round trip passes

The `unresolved KERNEL32.dll!CloseHandle` failure was a real mapper bug, and it
is fixed in `shared/src/map_host.cpp`:

* module hashing folded a **16-bit code unit** in the wide variant while the
  byte variant hashed **bytes**, so the module hash could never match and the
  resolver ran against no module at all. `h::fnv1a_ci_w` now hashes byte-wise,
  the way the byte variant does;
* the target's module list is incomplete for the first moments after the target
  starts, so `remote_module` now retries;
* export **forwarders** are followed (`kernel32!CloseHandle` forwards to
  `api-ms-win-core-handle-l1-1-0` in the modern layout) and **ordinal imports**
  are resolved.

Measured after the fix:

```
lab\resolver_test.exe    checked=8061 missed=0 forwarders=615   RESOLVER: OK
lab\run_all.ps1          27 passed, 0 failed
out\channel_test_v2.exe  <- ACK channel up / ACK BASE 0x00007FF6C55D0000 / ACK PING
```

So the channel was never blocked by the mapper. What is still missing is a first
entry into the real client - and that is now a complete, closed table.

## Correction, 13.11.2026: the hook vector is not refused - it is never triggered

The line above that says the hook is "refused at the loader, before the hook
runs" is wrong, and the measurement that corrects it is in section 9 of
`LIVE_TEST_RESULTS.md`:

* every hook family returns a **valid `HHOOK` with `err=0`** for the client's own
  thread, elevated and unelevated - there is no refusal;
* the same DLL, in the same run, is mapped into **26 other processes**, and into
  our own mock under the sanity control, so the mechanism works;
* the client is never among them, and the reason is its own I/O design:
  `PeekMessage` (so no `WH_GETMESSAGE`), no outgoing messages (so no
  `WH_CALLWNDPROC`), raw input (so no `WH_KEYBOARD`/`WH_MOUSE`), no
  `WM_MOVE`/`WM_SIZE`/`WM_ACTIVATE` dispatched and no foreground-idle (so no
  `WH_CBT`/`WH_FOREGROUNDIDLE`), and `WINEVENT_INCONTEXT` does not inject here
  even against a plain GUI control.

"Refused" and "never fires" are different findings, and only the second one is
true. The practical consequence is the same, but the door is the client's input
design rather than an anti-cheat gate.
