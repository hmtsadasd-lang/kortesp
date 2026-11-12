# wowprobe findings — EAC handle-masking regime

Measured on this box with the rebuilt `out/loader.exe` (see `build_mingw.bat`),
against `EasyAntiCheat_EOS.exe` (pid 19508) and
`FortniteClient-Win64-Shipping.exe` (pid 21040).

## How to reproduce

```bat
run_wowprobe.bat              :: unelevated run -> writes wowprobe.out
run_wowprobe_admin.bat        :: elevated wrapper (UAC), runs the same batch
                               :: plus the sibling probes in one session
```

`run_wowprobe.bat` itself is unchanged and stays exactly as specified.

## Build

This box has no MSVC toolchain (`VsDevCmd.bat` loads, `msbuild` is not
installed), so both projects are built with **w64devkit** (GCC 16.2,
`x86_64-w64-mingw32`), installed at `C:\tmp\w64devkit\w64devkit`:

```bat
build_mingw.bat               :: -> out\loader.exe  (console subsystem, static)
build_payload_mingw.bat       :: -> out\payload.dll (freestanding, entry "start")
```

Both are thin wrappers around the `.ps1` scripts next to them. Set
`W64DK` to point at a different toolchain root. The MSVC solution
(`fortesp.sln`) is untouched and remains the reference build; the MinGW
build needs `shared/src/stubs_gas.S` (the MASM stubs in GAS syntax) and
`payload/src/libc_min.cpp` (`strlen`/`wcslen` for the `-nostdlib` link).

Both outputs are `pei-x86-64`; `payload.dll` exports `start`, `g_trace`,
`g_host_path`, `probe0..2` exactly like the MSVC build.

## Environment facts

| Fact | Value |
|---|---|
| Host shell | not elevated by default (`elevated=0`), `SeDebugPrivilege=0` |
| EAC process | `EasyAntiCheat_EOS.exe`, session 0 (service), **32-bit** (`wow64=1`) |
| Game process | `FortniteClient-Win64-Shipping.exe`, session 1, x64 |
| EAC mitigation | CFG **on** (`policy[7]=1`), ACG **off** (`policy[2]=0`), signature `0`, strict `0` |
| Game mitigation | all queried policies `0` (no CFG, no ACG) |

## Open paths (measured)

Caller = elevated admin with `SeDebugPrivilege` enabled:

| Target | Requested mask | Granted | NTSTATUS |
|---|---|---|---|
| EAC | `0x1FFFFF` | **`0x1FFFFF`** | `0x00000000` |
| EAC | `0x11F145` | `0x11F145` | `0x00000000` |
| Game | `0x1FFFFF` | **`0x11F145`** | `0x00000000` |
| Game | `0x11F145` | `0x11F145` | `0x00000000` |
| Game | `0x3C` (VM op/read/write) | **`0x00001004`** | `0x00000000` |

Caller = plain unelevated user process:

| Target | Requested mask | Granted | NTSTATUS |
|---|---|---|---|
| EAC | any | *null* | `0xC0000022` (ACCESS_DENIED) |
| Game | `0x1FFFFF` | `0x11F145` | `0x00000000` |
| Game | `0x3C` | `0x00001004` | `0x00000000` |

`VirtualAllocEx` on the game handle: **NULL / err=5 (ACCESS_DENIED)** — from
inside EAC and from outside EAC alike.

## What the 32-bit stub measured (from inside EAC)

The stub runs inside the 32-bit EAC process (allocated low at `0x10000000`,
code page `PAGE_EXECUTE_READ`, results on a separate RW page) and reports what
EAC itself gets:

```
stub handle=0x34C granted=0x0011F145 ntq_status=0x0 alloc=0x0 lasterr=5
stub whitelist_handle=0x570 granted=0x0011F145 ntq_status=0x0 alloc=0x0 lasterr=5
```

* `OpenProcess(game, PROCESS_ALL_ACCESS)` **succeeds** inside EAC, but the
  kernel grants only `0x11F145`.
* `VirtualAllocEx` with that handle → `NULL`, `lasterr=5`.

## Decision table outcome

| Step | Result |
|---|---|
| `wow64` | 1 (EAC is 32-bit) |
| stub alloc | `0x10000000` — non-zero, below 4 GB (low-hint reservation works) |
| thread created | yes, `CreateRemoteThread` OK, `thread exit=0` |
| payload reaches `start` | **yes** — the stub ran to completion and reported back |
| granted mask on the game | **`0x11F145`** (requested `0x1FFFFF`) |
| alloc | 0 |
| lasterr | 5 |

→ Branch **"granted=0x11F145 + alloc=0 + lasterr=5"** = **not whitelisted** for
VM operations. This is *not* an elevation artifact: the cap is applied to the
plain unelevated user token as well, so it is EAC's kernel-side masking of the
game process object, not a DACL that an elevated token could outrank.

### Consequences

1. **The EAC relay is dead as a VM-write path.** Even running as SYSTEM inside
   EAC, the handle on the game never carries `PROCESS_VM_OPERATION` (0x8),
   `PROCESS_VM_WRITE` (0x20) or `PROCESS_VM_READ` (0x10), so no
   `VirtualAllocEx`/`WriteProcessMemory` into the game is possible.
2. **EAC itself is not self-protected.** An elevated loader gets `0x1FFFFF`
   on the EAC process, can allocate/write in it and can start threads in it
   (the stub proved both). So the "load-time entry into EAC" fallback is
   *available* — it is just not sufficient, because the EAC→game handle is
   masked.
3. `0x11F145` still contains `PROCESS_DUP_HANDLE` (0x40) and
   `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000). Handle duplication out of the
   game is therefore possible, but every duplicated handle carries the same
   capped mask — duplication cannot lift the cap.
4. `READ_CONTROL` (0x20000) and `WRITE_DAC` (0x40000) are **not** in the mask,
   so the game's own DACL can neither be read nor rewritten from user mode.
   `--grant` (which needs `WRITE_DAC`) cannot run.

### Next step (the "§4" branch)

The remaining user-mode route into the game is a **load-time entry**, not an
injection: a proxy DLL next to `FortniteClient-Win64-Shipping.exe` (or the
`.bak` shim), loaded by the game itself, so no cross-process handle is needed.
The 32-bit EAC stub stays useful as a *relay host* for that load (it has full
rights on EAC and runs as SYSTEM), but it cannot carry the payload into the
game by handle.

## Bugs found and fixed while building this

* `nt.hpp` did not include `<windows.h>` although `OBJECT_BASIC_INFORMATION_`
  uses `ULONG`/`ACCESS_MASK`.
* `NtQueryObject` was undeclared; it is now resolved at run time through
  `GetProcAddress`, which also keeps the file buildable with MinGW.
* `NtQueryObject(ObjectBasicInformation)` needs the **exact** buffer length.
  This build answers `STATUS_INFO_LENGTH_MISMATCH` for anything but **56**
  bytes, so the probe discovers the length at run time.
* The `k32` early-return killed the whole probe before the granted-mask,
  mitigation and open-path sections ran; it is now a warning.
* Policy indices are `{0,2,6,7,8,10}` (0=MitigationPolicies, 2=ACG/DynamicCode,
  6=ImageLoad, 7=CFG, 8=Signature, 10=StrictCriteria).
* `IsWow64Process(NULL, ...)` silently reported a 32-bit host as `wow64=0`;
  the probe now reports `unknown` and falls back to a
  `PROCESS_QUERY_LIMITED_INFORMATION` handle.
* The stub wrote its results into the page that had been flipped to
  `PAGE_EXECUTE_READ` → `STATUS_ACCESS_VIOLATION` in the injected thread
  (and it killed EAC). Results now live on their own RW page.
* The stub allocation now uses a low hint (`0x10000000`…`0x50000000`) so the
  32-bit `imm32` addressing stays valid, and it fails loudly above 4 GB.
* `SetProcessValidCallTargets` is not exported by `kernel32`/`ntdll` on this
  build, and the previous call passed the arguments in the wrong order.
