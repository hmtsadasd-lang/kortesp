# Live test results — the EAC-protected Fortnite client

Everything below was measured on this box, with the rebuilt binaries
(`out\loader.exe`, `out\payload.dll`, `out\version.dll`, `out\dbghelp.dll`).
The game directory was restored to its original state afterwards.

## 1. Handle access to the game — the hard blocker

| Caller | Target | Requested | **Granted** | NTSTATUS |
|---|---|---|---|---|
| elevated + SeDebugPrivilege | EAC | `0x1FFFFF` | `0x1FFFFF` | `0x00000000` |
| elevated + SeDebugPrivilege | EAC | `0x11F145` | `0x11F145` | `0x00000000` |
| elevated + SeDebugPrivilege | **Game** | `0x1FFFFF` | **`0x11F145`** | `0x00000000` |
| elevated + SeDebugPrivilege | **Game** | `0x3C` (VM op/read/write) | **`0x00001004`** | `0x00000000` |
| unelevated user | EAC | any | *null* | `0xC0000022` |
| unelevated user | **Game** | `0x1FFFFF` | **`0x11F145`** | `0x00000000` |

`0x11F145` = TERMINATE · SET_SESSION_INFORMATION · DUP_HANDLE · SET_QUOTA ·
QUERY_LIMITED_INFORMATION · SET_LIMITED_INFORMATION · SYNCHRONIZE.
**No `PROCESS_VM_OPERATION`, no `PROCESS_VM_WRITE`, no `PROCESS_VM_READ`, no
`PROCESS_CREATE_THREAD`, no `PROCESS_QUERY_INFORMATION`.**

`VirtualAllocEx` on the game → `NULL` / err=5 — measured *from inside EAC*
(as SYSTEM, via the injected stub) and *from outside* (as elevated admin).
The cap is applied by an EAC kernel callback: the plain unelevated user token
is capped identically, so it is not a DACL an elevated token could outrank.

## 2. Every route we tried

| # | Route | Result | Evidence |
|---|---|---|---|
| 1 | Cross-process injection into the game | **Blocked** | granted mask capped at `0x11F145`, `VirtualAllocEx` → err 5 |
| 2 | Duplicate a usable handle to the game | **Blocked** | `dupprobe`: 4375 process handles system-wide, `matched=0` — no process (the game included) holds a handle to the game with usable rights |
| 3 | Proxy `dbghelp.dll` in the game dir | **Never loaded** | the client does not load dbghelp (CrashReportClient's). The game started fine with our proxy sitting there — EAC did not care about an unloaded file |
| 4 | Proxy `EOSSDK-Win64-Shipping.dll` | **Detected** | the SDK validates its own file: *"Failed to load EOSSDK. Please verify your installation. Exiting..."* + EAC toast *"Easy Anti-Cheat … dosya sürümü (EOSSDK-Win64-Shipping.dll)"*. Client crash-looped: start → dead in 7 s, twice |
| 5 | Proxy `WinPixEventRuntime.dll` | **N/A** | the path does not exist in this install (`Engine\Binaries\ThirdParty` is absent); stock UE4 fails that load too |
| 6 | Hijack `VERSION.dll` (app-dir search order) | **Blocked by EAC** | our proxy loads fine standalone (err=0, forwarders resolve), but in the client: *"The code execution cannot proceed because VERSION.dll failed to load"* + EAC toast *"Güvenli olmayan sistem dosyası … Binaries\Win64"*. The proxy's `DllMain` never ran (no log line) — EAC refused the load |

## 3. What the client actually loads from its own directory

From the client's own log (`FortniteGame.log`):

```
LogEOSShared: Loaded ".../Binaries/Win64/EOSSDK-Win64-Shipping.dll"
```

`dbghelp.dll` never appears; `WinPixEventRuntime.dll` is attempted and fails
(path missing); `D3D12Core.dll` and `GfeSDK.dll` come from the system.
**Exactly one** library is loaded from the game directory — and it is the one
that validates itself.

## 4. EAC's actual protection model (measured)

| Surface | Result |
|---|---|
| Game process handles | masked to `0x11F145` for every caller (admin, SYSTEM, in-process) |
| Unknown DLL loaded into the client | **refused** (EAC toast: unsafe system file) |
| Game's own files (EOS SDK) | hash/self validated — replacing one aborts startup |
| Files in the game dir that are not loaded | not validated (our dbghelp proxy was tolerated) |
| EAC service process | **not** protected: elevated we get `0x1FFFFF`, can allocate in it, write to it and start threads in it |

## 5. What still works

* **Inside EAC**: full rights (`0x1FFFFF`), code execution confirmed (the
  32-bit stub ran, allocated, called `OpenProcess`/`NtQueryObject`, and
  reported back). EAC runs as SYSTEM in session 0.
* **The mapper**: verified end-to-end by `--maptest` — image relocated to a low
  base (`0x10000000`), imports resolved against the target, TLS directory
  walked, entry thread started, payload executed (`g_trace` = `A0..A3`) and
  logged.
* **The proxy**: verified standalone — 17 forwarders, forwarder target
  byte-identical to the system original, ordinals 1:1, imports limited to
  `KERNEL32`/`msvcrt`.

## 6. Bugs found and fixed during the test

| Problem | Fix |
|---|---|
| `NtCreateThreadEx` flags `1` (RUN_SYNCHRONOUS) while the context was patched right after | → `2` (SUSPENDED) in `payload/src/hide.cpp` |
| the mapper never resolved imports — the image was started with a raw IAT | import resolution added (target's modules, PEB walk + export hash) |
| a module the target does not have (the game runs D3D12, the payload wants d3d11) made the mapping fail | the mapper now loads the missing module into the target when it runs in-process |
| ld's `.def` parser rejects `#` comments | the count line goes to stderr |
| ld's `.def` parser cannot parse a path in a forwarder target | bare module name; the real copy is renamed `<name>_real.dll` next to it |
| ld does not support `name @ordinal`, and sorts exports alphabetically | `tools/patch_exports.py` copies the ordinal base (Epic's dbghelp starts at 1111) |
| `gen_def.bat` read the proxy instead of the original after a deployment | it now prefers `<name>_real.dll` |
| mkfwd.py dropped the DLL's own forwarder chain | `PE.forwarder()` follows it (the EOS SDK's `MiniDumpWriteDump` → `dbgcore.dll`) |
| the proxy logged into `Program Files`, where the game (normal user) cannot write | log moved to `C:\Users\Public\fortesp_proxy.log` |
| `loader.vcxproj` did not compile `map_host.cpp`; no proxy project | updated, plus `loader/proxy.vcxproj` and the `.sln` entry |
| a `-D` value containing dashes was split by the process spawn | the name is baked into a generated `proxy_config.h` |

## 7. What the kernel route would need on *this* machine

Measured, because it decides the whole plan:

| Property | Value | Meaning |
|---|---|---|
| OS | Windows 11 Pro, build **26200** (25H2) | — |
| Secure Boot | **enabled** | an unsigned driver cannot load at all |
| Code Integrity | enforcing (`nvspcap64.dll` rejected in the CI log) | only properly signed drivers load |
| HVCI / Memory Integrity | **off** (`Scenarios\HypervisorEnforcedCodeIntegrity\Enabled = 0`) | the kernel does not enforce the blocklist on its own |
| Microsoft vulnerable-driver blocklist | **not enforced** (`CI\Policy\VerifiedAndReputablePolicyState = 0`) | a *signed but known-vulnerable* driver would still load |
| Vulnerable drivers on the box | **none** — no `capcom.sys`, `cpuz141.sys`, `kdrvpr.sys`, `iQvw64e.sys`, `sioai64.sys`, `dbutil_2_3.sys`, `ene.sys`, `amdkmdag.sys`, `rdpc.sys` | a bring-your-own-vulnerable-driver chain has **no first link here** |

So the concept is sound — kernel access removes the need for a process handle
entirely, which is exactly what the `0x11F145` mask denies — and the *policy*
side on this box is permissive (blocklist off). What is missing is the first
link: a signed-but-vulnerable driver that is not present, and obtaining one
means pulling it from a corpus of known-vulnerable drivers, which is the
malware technique rather than the engineering technique.

## 8. Where this leaves us

Every **user-mode** way into the client is now measured and closed:

* no cross-process handle carries VM rights (and no handle anywhere does),
* no unknown DLL may be loaded into the process,
* the one library the client loads from its own directory validates itself.

What is left is not user-mode:

1. **Kernel level** — EAC's driver (`EasyAntiCheat.sys`) is inside the client;
   talking to it needs its IOCTL protocol, and the `kernemul` row of the plan
   is empty.
2. **The EAC side** — we have full control of the EAC process, but from there
   the game is still only reachable through a `0x11F145` handle, so a load
   inside EAC can observe and hook, not write into the game.
3. **A signed/manifest-approved DLL** — if EAC's manifest allowed a DLL by
   hash only, no proxy can impersonate it; if it allows by name, that would be
   the way in. That is a question about EAC's manifest, not about this code.

## 8. Reproducing the measurements

```bat
run_wowprobe.bat                 :: access probe (elevated: run_wowprobe_admin.bat)
out\loader.exe --dupprobe       :: handle survey
out\loader.exe --maptest        :: mapper self-test against a spawned cmd.exe
tools\deploy_hijack.bat          :: install a proxy (needs the game closed)
tools\restore_game_files.bat     :: put the game directory back
```

## 9. In-game delivery, 13.11.2026: every vector, measured

Second round, with the client **running** and its `UnrealWindow`
(`hwnd 0x5061C`, `tid 23232`) in the **foreground** - confirmed with
`GetForegroundWindow` at the time of the run, so the input and activation
questions below were really put to the client and not to some other window.

Each hook family is exported by one DLL (`out\FortHook.dll`) and writes a line
to `C:\Users\Public\fortesp_hook.log` from inside **whatever process the system
maps it into**, so "did the client reach our module" is a log line, not an
inference. The DLL is injected from its own path, so nothing of ours has to be
in the game directory.

### The two positive controls, because they are what make the negatives mean something

* `lab\hook_dll_sanity.exe` - `WH_GETMESSAGE` + `FortHook.dll` against
  `out\lab\mock_gui.exe` (a plain `GetMessage` loop). The DLL **is** mapped into
  the target (`DllMain in pid 3864`, then `HookProc in pid 3864`) and the worker
  starts. Only the payload read failed, because that mock has no `payload.dll`
  next to it. **The hook mechanism and the injection path work.**
* the **global sweep** below reached **26 processes** with the same DLL and the
  same `SetWindowsHookEx` calls in one run - explorer, Chrome, PowerShell,
  `ctfmon`, OneDrive, `sihost`, NVIDIA Overlay, `nvsphelper64`, the Realtek
  audio service, `GameInputRawInputProxy` (35 132 callbacks), Riot Vanguard's
  tray, the Epic launcher and the `EAC_EOS` shim - 47 654 log lines in total.

| # | vector (all using `out\FortHook.dll`) | install | DLL mapped into the **client**? | callback in the client? | what the log / the return code shows |
|---|---|---|---|---|---|
| 1 | `OpenProcess` + `VirtualAllocEx` / `WriteProcessMemory` | — | no | n/a | granted mask `0x1004` only; `VirtualAllocEx` → err 5 (also from SYSTEM inside EAC) |
| 2 | `ReadProcessMemory` through that handle | — | no | n/a | a real read is refused, err 5 |
| 3 | proxy `version.dll` in the game dir | deploys | no | no | `DllMain` never ran; the anti-cheat refuses the load |
| 4 | proxy `EOSSDK-Win64-Shipping.dll` | deploys | no | no | self-validating; the client crash-loops |
| 5 | proxy `CRYPT32.dll` (the one shim import that is not a KnownDLL) | deploys | no | no | the app directory is not searched at all |
| 6 | plant `vulkan-1.dll` | deploys | no | no | the name list is libpng's, not a loader list |
| 7 | `WH_GETMESSAGE` + DLL, client `tid` | `err=0` | no | **never** | the client's loop is `PeekMessage` |
| 8 | `WH_GETMESSAGE` + DLL, global | `err=0` | no | never in client | fired in 16 other processes |
| 9 | `WH_CALLWNDPROC` + DLL, client `tid` | `err=0` | no | **never** | the client sends no messages |
| 10 | `WH_CALLWNDPROC` + DLL, global | `err=0` | no | never in client | mapped into Discord, Chrome, Nvidia, Vanguard, the launcher, the EAC shim |
| 11 | `WH_KEYBOARD` + DLL, client `tid` | `err=0` | no | **never** | **raw input only**: no legacy `WM_KEYDOWN` is generated for it |
| 12 | `WH_MOUSE` + DLL, client `tid` | `err=0` | no | **never** | raw input only |
| 13 | `WH_CBT` + DLL, client `tid` | `err=0` | no | **never** | the client dispatches no `WM_MOVE`/`WM_SIZE`/`WM_ACTIVATE` |
| 14 | `WH_CBT` + DLL, global | `err=0` | no | never in client | fired in 11 other processes (Chrome 139, explorer 75, PowerShell, ...) |
| 15 | `WH_FOREGROUNDIDLE` + DLL, client `tid` | `err=0` | no | **never** | the client's queue never reports foreground-idle |
| 16 | `WH_HARDWARE` + DLL, global | `err=0` | no | never in client | 35 132 callbacks in `GameInputRawInputProxy`, none in the client |
| 17 | `SetWinEventHook(WINEVENT_INCONTEXT)` | handle non-null | no | never | does not inject even against our own mock target |
| 18 | `SetWinEventHook(OUTOFCONTEXT)` | handle non-null | n/a (no injection) | fires (`event=0x8002`) | a control channel only |

`WH_MSGFILTER` is `-1` (disabled) on this build; it was tried and rejected by the
OS itself.

### What the table says

The tooling is not the variable. The same DLL is injected by 26 live processes
in one run, and by our own mock under the sanity control - so when the client is
absent from the log, what is being measured is the **client's behaviour**, and
that behaviour is consistent across six hook families:

1. it never calls `GetMessage` - so `WH_GETMESSAGE` is never raised;
2. it never **sends** a message - `WH_CALLWNDPROC` fires in the *sender's*
   context, and the client is never the sender;
3. it consumes **raw input** only - `WH_KEYBOARD`/`WH_MOUSE` are never raised
   for it, so the input path never delivers the DLL either;
4. it dispatches no `WM_MOVE`/`WM_SIZE`/`WM_ACTIVATE` for `WH_CBT`, and never
   reports foreground-idle;
5. it refuses an unknown module load (`version.dll`), and
6. a handle to it carries `0x1004` - no `VM_*`, no `CREATE_THREAD` - for every
   caller, elevated admin and SYSTEM included.

Every one of (1)-(3) is a *positive* property of a shipped game rather than a
misconfiguration: raw input, a `PeekMessage` pump and no cross-thread sends are
what a game does to keep input latency low. The anti-cheat does not have to
block the hook - the client's own I/O design never gives the hook anything to
fire on, and the one family that needs no message (`WINEVENT_INCONTEXT`) does
not inject here even against our own control.

> **Correction, later the same day - see section 10.** The mock-client matrix
> disproves reasons **(1)** and the CBT half of **(4)**: a fixture with the
> client's exact `PeekMessage` + `RIDEV_NOLEGACY` design *does* drive
> `WH_GETMESSAGE`, `WH_CALLWNDPROC` and `WH_CBT`. Only the raw-input reason
> **(3)** survives. The real reading of this table is therefore not "the design
> never fires the hooks" but "`FortHook.dll` is never mapped into the client":
> the delivery is refused, and section 10 is the controlled experiment that
> separates the two.

### Reproduce

```bat
out\hook_types.exe out\FortHook.dll 120 cbt,idle,get      :: thread-local, the client's own tid
out\hook_types.exe out\FortHook.dll 120 get,hw,cbt,msg 0  :: global sweep (26 processes reached)
out\hook_input.exe out\FortHook.dll 120 both              :: WH_KEYBOARD + WH_MOUSE, client tid
tools\run_types_elevated.bat                             :: the same, elevated - the client is high-integrity
```

The hook DLL resolves `payload.dll` from **its own directory** first, so nothing
of ours needs to exist in the game directory, and it maps the payload only when
the host is `FortniteClient-Win64-Shipping.exe` - so a global sweep can never
start the overlay in an unrelated process. The game directory was verified back
to its normal 68 entries after every run.

## 10. The mock-client matrix, 13.11.2026: the client's design is not the reason

Section 9 left two explanations for six hook families that install `err=0` and
then never run, and they are not the same problem:

* **A. design** - the client's `PeekMessage` pump and raw-input path never give
  those hooks anything to fire on; or
* **B. delivery** - the injection itself (the loader mapping `FortHook.dll`
  into the client) is refused inside the client, so no callback can ever run.

They are separated by a **fixture that copies the client's I/O design** and can
be watched directly: `lab\mock_client.c`. It has three loops on its command
line, one of which (`raw`) is exactly the client's - `PeekMessage(PM_REMOVE)`
plus `RegisterRawInputDevices(RIDEV_NOLEGACY)`. `lab\hook_matrix.cpp` starts the
fixture, installs **every family** (one export per family, so the log names the
one that fired), applies its own stimuli (posted `WM_NULL`, window moves,
foreground swaps, real `SendInput`, and a `SendMessage` to drive the sender-side
`WH_CALLWNDPROC`), then parses the hook log into a table.

`lab\run_hook_matrix.ps1` builds and runs the whole thing. Counts below are one
run; the pattern is what is stable, not the exact numbers.

| target | loop | legacy input | GETMSG | CALLWND | CBT | FGIDLE | KBD | MOUSE | note |
|---|---|---|---|---|---|---|---|---|---|
| `mock_gui.exe` (control) | `GetMessage` | on | 1345 | 2777 | 1014 | 730 | 46 | 939 | everything that can fire, fires |
| `mock_client.exe get` | `GetMessage` | on | 244 | 228 | 107 | 75 | 98 | 0 | textbook loop |
| `mock_client.exe peek` | `PeekMessage` | on | 182 | 277 | 48 | 0 | 36 | 0 | `WH_GETMESSAGE` **does** fire on `PeekMessage` |
| `mock_client.exe raw` | `PeekMessage` | **`RIDEV_NOLEGACY`** | 935 | 232 | 9 | 0 | **0** | **0** | the client's design; `input=786 legacy=0` |
| `mock_client.exe raw`, global (`tid=0`) | `PeekMessage` | `RIDEV_NOLEGACY` | 1945 | 404 | 9 | 0 | 0 | 0 | reached the fixture **and 8 other processes** |

### What this settles

1. **`PeekMessage` does not suppress `WH_GETMESSAGE`.** The fixture is in `raw`
   mode, its loop never calls `GetMessage`, yet `GetMsgProc` ran **935 times**.
   `WH_GETMESSAGE` is raised by `GetMessage` **and** `PeekMessage`. So section
   9's reason (1) - "it never calls `GetMessage`, so `WH_GETMESSAGE` is never
   raised" - is **wrong**; the client's loop shape does not explain that silence.
2. **`RIDEV_NOLEGACY` *does* suppress `WH_KEYBOARD`/`WH_MOUSE`.** In `raw` mode
   the fixture saw `input=786` with `legacy=0`, and `KbdProc`/`MouseProc` never
   fired; in `peek`/`get` they did. Section 9's reason (3) **holds**: the input
   path is a design answer.
3. **`WH_CBT` fires on a `PeekMessage` + raw-input target** (9 times in `raw`),
   so section 9's reason (4) does **not** explain the client's silence either.
4. **`WH_FOREGROUNDIDLE` needs a blocking message wait.** It fired in `get`
   mode (75) and never in the `PeekMessage`+`Sleep(1)` loops (0). The client's
   loop shape is consistent with that one negative.

So of section 9's design reasons, only the raw-input one survives. The families
that a fixture with the client's *exact* design drives - **`WH_GETMESSAGE`,
`WH_CALLWNDPROC`, `WH_CBT`** - never fire in the client. The fixture also proves
the same DLL and installs reach it in a **global** sweep that the client is
absent from. Combined with the global sweep's strongest line - `DllMain` never
ran in the client's pid in 47 654 log lines - the reading is:

> **The hook families are fine; `FortHook.dll` is never mapped into the client.**
> The missing piece is delivery into the client, not the choice of hook.

The remaining candidate is the layer the client *does* have and the fixture does
not: EAC hooks `LdrpLoadDll`/`LdrRegisterDllNotification`, i.e. it can veto a
module load that a normal process would accept. That is consistent with the rest
of section 9 - the `version.dll` proxy is refused on the *file* even when
byte-identical and signed, and a handle to the client carries `0x1004` for every
caller. What the hook matrix adds is that "the client doesn't pump the right
message" is no longer an available explanation.

### Reproduce

```bat
powershell -NoProfile -ExecutionPolicy Bypass -File lab\run_hook_matrix.ps1
:: results land in out\lab\matrix_*.out
```

No elevation is needed for the fixtures (they are not elevated). The client run
is the high-integrity one and is measured with `tools\run_*_elevated.bat`.
