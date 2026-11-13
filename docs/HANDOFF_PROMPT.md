# Handoff prompt

Paste this into a coding model to continue the work on this repository. It is
written to be self-contained: the measured facts are in it so nothing has to
be rediscovered.

---

## Context

`C:\dev\fortesp` is a Windows user-mode research toolkit for the Fortnite
client (`FortniteClient-Win64-Shipping.exe`, shipped **packed** — no import
table, no plaintext DLL names, 508 MB encrypted payload section). It contains:

- a **manual mapper** (`shared/src/map_host.cpp`) that relocates an image,
  resolves its imports against a *target* process, walks its TLS directory and
  starts its entry point;
- a **loader/probe** (`loader/src/main.cpp`) that measures how the anti-cheat
  exposes the client (handle masks, mitigations, open paths) and prints a
  **decision table** branch;
- a **load-time proxy** (`loader/src/proxy.cpp`) that shadows a DLL and maps a
  payload into the process that loaded it;
- a **payload** (`payload/src/`) with a relay mode and a target mode;
- a **lab** (`lab/`) that reproduces the client's access behaviour locally.

## Environment (important, it is unusual)

- **No MSVC on this box.** `VsDevCmd.bat` loads but `msbuild` does not exist.
  `C:\MinGW` is a 32-bit MinGW.org GCC 9.2 whose `cc1.exe` is unusable
  (exit `0xC0000135`) — do not go back to it.
- The working toolchain is **w64devkit** (GCC 16.2, x86_64-w64-mingw32),
  unpacked at `C:\tmp\w64devkit\w64devkit`.
- Build with the repo scripts (they are PowerShell driven on purpose: `cmd`
  blocks with `if errorlevel N ( ... )` are unreliable in this shell):

```bat
build_mingw.bat                 :: out\loader.exe
build_payload_mingw.bat         :: out\payload.dll
build_proxy_mingw.bat <dll>     :: out\<dll>.dll
lab\run_lab.bat                 :: decision table lab
lab\run_payload_lab.bat         :: payload delivery lab
```

- `gcc` needs `-DWIN64`; the C mock targets need `-ladvapi32`.
- The game directory is `C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64`
  and must be restored after experiments: `tools\restore_game_files.bat`.

## What is already measured (do not redo these)

| Fact | Value |
|---|---|
| Client handle mask | every caller gets `0x11F145` — no `PROCESS_VM_OPERATION`, `VM_WRITE`, `VM_READ`, `CREATE_THREAD`, `QUERY_INFORMATION` |
| Who is capped | elevated admin with `SeDebugPrivilege`, SYSTEM inside the anti-cheat service, and the plain unelevated user — identically |
| `VirtualAllocEx` on the client | `NULL`, error 5 |
| Handles to the client anywhere on the box | none with usable rights (`--dupprobe`: 4375 surveyed, 0 matched) |
| Unknown DLL loaded into the client | refused by the anti-cheat (*"VERSION.dll failed to load"*, *"unsafe system file"*) |
| The one library the client loads from its own dir | `EOSSDK-Win64-Shipping.dll` — it validates itself, replacing it aborts startup |
| Client mitigations | anti-cheat: CFG on, ACG off. Game: all queried policies zero |
| Client DLL loads | exactly one from its own directory (`EOSSDK`), `dbghelp.dll` is CrashReportClient's, `WinPixEventRuntime.dll` does not exist in this install |
| Machine | Windows 11 Pro build 26200, Secure Boot on, HVCI off, Microsoft vulnerable-driver blocklist **not enforced**, no known-vulnerable driver present |

## Remaining work (this is the list)

1. **WOW64 fallback** — `--wowprobe`'s fallback path creates a suspended
   thread and installs a WOW64 context with `NtSetContextThread`. The kernel
   currently rejects the context with `STATUS_ACCESS_VIOLATION`. The thread
   must be created with `THREAD_CREATE_FLAGS_SUSPENDED` (0x2, **not** 1) and
   the context installed afterwards, and the selectors must be the ones a
   32-bit thread has on x64 (`CS/SS/DS/ES = 0x23`, `FS = 0x53`, `GS = 0x2B`).
   Acceptance: the fallback reports the stub's results instead of `0xC0000005`.
2. **Payload target mode** — the branch that runs when the payload is already
   inside the target (`already_in_target()` → `hide::alloc_rx` →
   `hide::launch_worker`) now runs to completion in the lab: the trace shows
   `A0..A3, A7, B0..B8, B3` and the thread exits with 0. Findings already
   folded in:
   - the payload's path buffer has to be **static** (a 520-byte stack local
     faulted);
   - the mapper's `NtCreateThreadEx` stack size must stay **0** — an explicit
     size is rejected with `STATUS_INVALID_PARAMETER`;
   - `shared/src/stubs_gas.S` had its register moves **reversed** relative to
     the MASM original (`mov rcx, r10` instead of `mov r10, rcx`), which
     clobbered the first argument of every direct syscall in the payload;
   - `hide::alloc_rx` has to page-align the protect size and must not abort
     the whole image when one section fails;
   - `NtCreateThreadEx` needs the **pseudo handle** of the current process
     (`-1`) as its ProcessHandle — `0` is invalid and the call fails;
   - `CONTEXT_` in `shared/include/nt.hpp` has to be the **real x64 layout**
     (0x430 bytes): `NtGetContextThread`/`NtSetContextThread` write and read
     the whole block, so a shortened struct corrupts the thread;
   - `hide::alloc_rx` has to leave **uninitialised data writable**
     (`SCN_UNINITIALIZED_DATA`, 0x80) the way the loader does — otherwise
     the payload's own statics in `.bss` fault the moment it writes them
     after the call.
   Next: confirm the worker actually starts (`hide::launch_worker`) and that
   `game::init()` degrades gracefully when there is no engine under it.
3. **Mapper hardening** — the mapper resolves imports against the target's
   module list; it now loads a module into the target when the target does
   not have it (the client runs D3D12, the payload wants d3d11). Consider
   resolving forwarded exports properly (`peb::export_proc` does not follow
   the `0x80000000` forwarder bit — kernel32 has 211 forwarded exports).
   Also check `shared/src/stubs_gas.S`: it is a hand translation of the MASM
   `shared/src/stubs.asm`, and a first version had the register moves
   **reversed** (`mov rcx, r10` instead of `mov r10, rcx`), which silently
   clobbered the first argument of every direct syscall in the payload
   (NtProtectVirtualMemory with a garbage handle). The MASM file is the
   reference — keep the two in sync.
4. **Lab as a regression suite** — turn `lab\run_lab.bat` and
   `lab\run_payload_lab.bat` into one script with pass/fail assertions on the
   facts (`granted=0x11F145`, `alloc=0`, `lasterr=5`, `decision=not_whitelisted`).
5. **Writeup** — `LIVE_TEST_RESULTS.md` has the raw data; it can be turned into
   a proper article about how a modern anti-cheat masks process handles
   (mask construction, which callers it applies to, DACL vs kernel callback
   semantics, DLL-load protection, self-validating libraries).

## Boundaries (please honour them)

- **Do not build a kernel-mode anti-cheat bypass.** No BYOVD chains, no
  exploiting vulnerable signed drivers, no using the anti-cheat's driver, and
  no lifting the `0x11F145` mask to obtain write access to the client. The
  measurements above show the policy side on this box is permissive, but the
  first link of such a chain is absent, and obtaining one means using a
  malware technique rather than an engineering technique.
- Everything else in this repository — the mapper, the probe, the proxy, the
  lab, the measurement writeup — is in scope.

## Working style that worked here

- Build and run things; do not theorise past the point of measurement.
- When a build or a script behaves oddly, suspect the harness quoting first
  (arguments with spaces, `-D` values with dashes, `^` continuations) — a
  PowerShell driver script per build step is more reliable than batch
  conditionals.
- Verify each step against `lab\` rather than against the live client.
