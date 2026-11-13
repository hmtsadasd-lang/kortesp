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
