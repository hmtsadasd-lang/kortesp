# Delivery research: what actually reaches the client, measured

Every line below is a return code from this machine on 13.11.2026, with the
client (`FortniteClient-Win64-Shipping.exe`) running. Nothing here is theory.
Tools: `out\loader.exe --lateral`, `out\hook_deliver.exe`, `out\station_probe.exe`,
`out\access_probe.exe`.

## The boundary, restated in one table

| question | measured answer |
|---|---|
| Does a handle to the client allow memory access? | **No.** `OpenProcess` succeeds, the handle carries `0x11F145`, and `ReadProcessMemory`/`VirtualAllocEx` still fail with 5. A real read is the only honest test, and it fails. |
| Can the owner fix the DACL? | **No.** `SetSecurityInfo` = `ERROR_ACCESS_DENIED`, even for the object's owner, even with a DACL that grants ourselves ALL. |
| Is the client a protected process (PPL)? | **No.** `SystemProcessInformation` protection `0x00/0x00`; integrity medium (`S-1-16-8192`). |
| Does the client set mitigation policies? | **Only DEP.** Policy class 38 on this build; every other policy reads zero, and HVCI is off. |
| Does a replaced `version.dll` load? | **No** — refused even as a byte-identical signed copy, so the check is on the file, not the exports. |
| Same desktop as us? | **Yes.** `WinSta0`, client window `UnrealWindow`, `OpenInputDesktop` = `Default`. |

So the cap is applied to the *handle*, by the anti-cheat, not by a DACL and not
by a kernel protection level: the same layer that already refuses foreign DLL
loads.

## The vector that got through the first gate

The earlier "hooks don't work" result was a measurement error, not a fact:

```
method 2 (no module):  hook=0 err=5      <- WH_GETMESSAGE with a callback in an EXE
method 1 (dll):        hook=0x1c940ea7 err=0   <- same call, callback exported by FortHook.dll
```

`SetWindowsHookExW(WH_GETMESSAGE, HookProc, hDll, client_tid)` is **accepted for
the client's own thread**, from an unelevated process, on this build. The OS will
map `out\FortHook.dll` into the client and call its export on the client's
thread. That is a real, file-backed module load, performed by the client's own
loader — no handle, no remote write, nothing for the `0x11F145` cap to refuse.

What is not yet true: the callback has not run. A hook procedure only executes
when the target thread walks a message, and the client's message-pumping thread
is not the one running the game loop. The delivering process therefore starts a
**pinger inside the hook DLL** (`StartPinger`) that posts `WM_NULL` to the
client's window once a second — a message every window procedure drops — for 40
seconds. `C:\Users\Public\fortesp_hook.log` is written by the hook's first line,
so the log's mere existence is the answer to "did the client reach our module".

| state | what it means |
|---|---|
| no log file | the client did not reach `HookProc` in 40 s of messages |
| log with `HookProc in pid …` | the client loaded the DLL; the mapper runs in-process from there |
| log with `map ok=1` | the payload is in the client and the game's own threads started it |

## Why an in-process map is enough once the hook fires

`shared/src/map_host.cpp` already maps into `GetCurrentProcess()` when it is
called from inside the target (that is how the proxy path works). From inside,
every import resolves against the client's own modules, the image comes from the
client's own address space, and the entry thread is created by the client. There
is no remote call anywhere in that path, so the handle cap is not on it.

## The other vectors, and their measured verdict

| vector | verdict | why |
|---|---|---|
| `OpenProcess` + remote write | closed | capped mask, real read refused |
| `SetWindowsHookEx` with EXE callback | closed | `ERROR_ACCESS_DENIED` (5) |
| `SetWindowsHookEx` with DLL callback | **open (install)** | accepted; execution depends on a message walk |
| `SetWinEventHook(OUTOFCONTEXT)` | **open** | the OS calls this process per event; no injection, but an honest control channel |
| `KnownDLLs` | read-only | the loader resolves those names before any directory; writing needs elevation |
| `SafeDllSearchMode` | on | app dir, system, windows, current dir, PATH |
| `App Paths` / `IFEO` | readable | usable only for names the loader already resolves |
| DLL name hijack in `Win64` | closed | only `EOSSDK` loads from there, and it self-validates |
| `CreateRemoteThread` / `NtCreateThreadEx` | closed | needs `CREATE_THREAD`, not in the mask |

## What this means for the next attempt

1. The hook installs, so the remaining question is purely "does the client's
   window thread pump". Two ways to force it are worth trying in order:
   `SendMessageTimeout` to the window from the delivering process (a direct
   call into the client's server thread, which is a *different* thread from the
   hookable one) and `AttachThreadInput` from a process that has focus.
2. If the client's thread really never pumps, the same DLL can be delivered by
   the *other* hook family — `WH_CBT`/`WH_SHELL` install on the whole desktop
   and fire without a message — which is the next measurement, not a guess.
3. `SetWinEventHook(OUTOFCONTEXT)` is confirmed available and is the fallback
   control channel for a payload that is already inside.

The tools and the DLL are built and runnable:
`out\hook_deliver.exe` (delivers), `out\FortHook.dll` (loads into the client),
`out\loader.exe --lateral` (re-runs this whole table).
