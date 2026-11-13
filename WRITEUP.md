# How a modern anti-cheat removes a process from the operating system

### Two mechanisms, measured on a live client

*Scope: this is a measurement write-up of a Windows user-mode research
toolkit (`C:\dev\fortesp`). Everything below was produced by binaries in this
repository and is reproducible from `lab\run_all.ps1`. No kernel-mode
component is involved: the kernel side is only ever *observed*.*

---

## 0. The short version

Most writing about anti-cheat protection stops at "the driver hides the
process". Two things on this box are more interesting than that, because
neither is a hook and neither is a blocklist:

1. **The access mask is rewritten, not refused.** Every caller who asks for
   `PROCESS_ALL_ACCESS` on the client gets a handle back — with the mask
   silently cut to `0x11F145`. The caller is not told. The handle is valid,
   `WaitForSingleObject` works, `QueryFullProcessImageName` works, and
   `VirtualAllocEx` fails with `ERROR_ACCESS_DENIED`. An elevated
   administrator with `SeDebugPrivilege`, a SYSTEM service, and an
   unelevated user all get the same mask: the DACL is not what is doing it.

2. **The thread handle an injection API returns is not a handle the context
   APIs accept.** `CreateRemoteThread` and `NtCreateThreadEx` return a handle
   that is good enough to wait on and to resume, but
   `NtGetContextThread`, `NtSetContextThread` and `NtQueryInformationThread`
   answer `STATUS_ACCESS_VIOLATION` (`0xC0000005`) — and `GetThreadId` answers
   `STATUS_INVALID_HANDLE`. Duplicating the very same entry with
   `DuplicateHandle` fixes it. Nothing in the documentation says this.

Both are worth having on the record because both are invisible from the
outside, both are cheap to implement on the defensive side, and both change
what an attacker has to build.

---

## 1. The setup

| Piece | What it is |
|---|---|
| `FortniteClient-Win64-Shipping.exe` | the target. Packed, no import table, 508 MB encrypted payload section |
| `EasyAntiCheat_EOS.exe` | the anti-cheat service, SYSTEM, session 0 |
| `out\loader.exe` | the probe: measures how the anti-cheat exposes the client |
| `out\payload.dll` | a manually-mapped payload with a relay mode and a target mode |
| `lab\mock_game.c` | a 64-bit mock that applies the same DACL cap, for regression runs |
| `lab\mock_host.c` | a 32-bit mock of the anti-cheat service |
| `lab\run_all.ps1` | the regression suite: 18 assertions, `PASS`/`FAIL <case> <expected> <got>` |

Machine: Windows 11 Pro build 26200, Secure Boot on, HVCI off, no vulnerable
driver on the box. Toolchain: w64devkit GCC 16.2 (no MSVC on this machine).

Every number below appears twice: once measured against the live client, and
once measured against the mock by `lab\run_all.ps1`, which is what keeps the
claims honest after a Windows update.

---

## 2. Mechanism one: the mask is rewritten

### 2.1 The numbers

`out\loader.exe --wowprobe` asks for `PROCESS_ALL_ACCESS` and then asks the
kernel what it actually got (`NtQueryObject(ObjectBasicInformation)`):

| Caller | Target | Requested | **Granted** | `VirtualAllocEx` |
|---|---|---|---|---|
| elevated + `SeDebugPrivilege` | anti-cheat service | `0x1FFFFF` | `0x1FFFFF` | works |
| elevated + `SeDebugPrivilege` | **client** | `0x1FFFFF` | **`0x11F145`** | `NULL`, err 5 |
| elevated + `SeDebugPrivilege` | **client** | `0x3C` (VM op/read/write) | **`0x00001004`** | `NULL`, err 5 |
| SYSTEM (inside the anti-cheat) | **client** | `0x1FFFFF` | **`0x11F145`** | `NULL`, err 5 |
| plain unelevated user | **client** | `0x1FFFFF` | **`0x11F145`** | `NULL`, err 5` |

`0x11F145` decomposes to:

```
0x0001 TERMINATE
0x0004 VM_READ?  no  -- it is SET_QUOTA
0x0040 DUP_HANDLE
0x0100 SET_QUOTA
0x1000 QUERY_LIMITED_INFORMATION
0x100000 SET_LIMITED_INFORMATION
0x00100000 SYNCHRONIZE
```

— that is `TERMINATE`, `SET_QUOTA`, `DUP_HANDLE`, `QUERY_LIMITED_INFORMATION`,
`SET_LIMITED_INFORMATION`, `SYNCHRONIZE`. What is missing is exactly the set
an injector needs: `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`,
`PROCESS_VM_READ`, `PROCESS_CREATE_THREAD`, `PROCESS_QUERY_INFORMATION`.

The interesting part is the *shape* of the answer, not the list:

* the request **succeeds** (`NTSTATUS 0x00000000`), so every "if
  `OpenProcess` fails, give up" code path is walked straight past;
* the cap is **identical for an elevated token**, which a DACL cannot do —
  a DACL is evaluated against the token and an admin token outranks a user
  one;
* it is identical for a **SYSTEM token inside the anti-cheat process**, which
  no DACL check can produce either.

### 2.2 What that implies about the implementation

A DACL that denies `PROCESS_VM_WRITE` produces `STATUS_ACCESS_DENIED` on
`NtOpenProcess` — the call fails and no handle comes back. A handle that comes
back with a mask the caller did not ask for is the signature of a
**`PsProcessType`-style access callback**: the object manager evaluates the
DACL, then runs the registered callback, and the callback rewrites the granted
mask before the handle is created. The kernel's own `ObpGrantAccess` allows a
callback to clear bits; that is precisely what is happening here.

Which also explains the `--dupprobe` result, which surprised me most:

```
4375 process handles surveyed system-wide, 0 carried VM rights to the client
```

If the mask were a DACL, some process on the box (a debugger, a crash
reporter, the launcher) would hold a full-rights handle opened before the
callback existed, and `DuplicateHandle` would inherit those rights. None
does. The callback is installed before the client starts and applies to every
open, so there is no "before" to inherit from.

### 2.3 Reproducing it without the game

`lab\mock_game.c` applies the same cap with a DACL that *refuses*
`PROCESS_ALL_ACCESS` outright (`0xC0000022`) and grants `0x11F145` when that
mask is asked for exactly. The suite asserts both branches:

```
PASS game ALL_ACCESS refused
PASS game 0x11F145 granted
PASS granted mask          (facts granted=0x0011F145)
PASS VirtualAllocEx        (facts alloc=0x0)
PASS last error            (facts lasterr=5)
PASS decision branch       (decision=not_whitelisted)
```

---

## 3. Mechanism two: the thread handle you get is not the thread handle you need

This one is not about the client at all. It reproduces on a plain Windows 11
box, in a process nobody protects.

### 3.1 What the probe does

`--wowprobe` starts a thread in a 32-bit host with
`NtCreateThreadEx(..., THREAD_CREATE_FLAGS_SUSPENDED)`, then tries to read
and install a `WOW64_CONTEXT` on it. The context calls came back
`0xC0000005` — "access violation", which reads like a malformed context. It is
not. The context was fine; the **handle** was wrong.

### 3.2 The measurement

`lab\probe_thread.c`, against the 32-bit mock host:

```
[host] NtCreateThreadEx st=0x00000000 thread=00000000000000d0
[host]: GetThreadId(handle)          -> works
[host]: NtGetContextThread(x86 ctx)  -> 0x00000000   accepted
[host]: Wow64GetThreadContext        -> 1
[host dup] duplicated 00000000000000d0 -> 00000000000000d4
[host dup]: NtGetContextThread(x86)  -> 0x00000000   accepted
```

The same handle answers both ways depending on *how it was obtained*, and the
failure is not an access denial on the object (that would be
`STATUS_ACCESS_DENIED`, `0xC0000022`). `0xC0000005` from
`NtGetContextThread`, and `STATUS_INVALID_HANDLE` (`0xC0000008`) from
`GetThreadId`, on a handle that `WaitForSingleObject` and `ResumeThread`
accept — that is a handle whose access bits do not include what the context
path checks for, while the wait path only needs `SYNCHRONIZE`.

The fix is one call:

```c
HANDLE dup = NULL;
DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dup,
                0, FALSE, DUPLICATE_SAME_ACCESS);
```

`DUP_HANDLE` is in the `0x11F145` mask the anti-cheat grants, by the way —
`DUP_HANDLE` is one of the few bits it leaves alone, which is consistent:
duplicating a handle cannot add rights, so it cannot add `PROCESS_VM_WRITE`.

### 3.3 Why this matters for the write-up

Three practical consequences, all measured:

1. **An injector that treats "thread handle != NULL" as success is wrong.**
   It has a handle it can wait on and a thread it can resume, and every
   context operation on it fails. The failure mode looks like a bad context
   layout, so people spend their time rebuilding the `CONTEXT` struct.
2. **`NtSetContextThread` is the wrong API for a WOW64 thread from a 64-bit
   caller.** With the duplicated handle, `NtSetContextThread` still returns
   `0xC0000005` and `Wow64SetThreadContext` accepts the identical block:

   ```
   wow64 Wow64SetThreadContext[dup]=1 err=0
   wow64 thread context: ok=1 eip=0x00100000 esp=0x000AFFF8 cs=0x23 ss=0x23
   ```

3. **Creating the thread suspended does not guarantee it stays suspended.**
   The same run, after a successful context install:

   ```
   wow64 resume suspend-count was 0        <- the kernel never held it
   wow64 wait=258 thread exit=0x00000103
   ```

   `THREAD_CREATE_FLAGS_SUSPENDED` (`0x2`) was passed, the context API
   accepted the block, and `ResumeThread` reports a suspend count of zero —
   the thread was never suspended and had already exited. A 64-bit thread
   started at the same page from the same 64-bit caller dies identically
   (`exit=0x00000103`), as does the host's own `CreateRemoteThread`. That is
   not a context problem any more: **on this build, a foreign thread start
   does not run, whatever API produces it.** The fallback now says so instead
   of reporting a context error.

---

## 4. The rest of the surface, briefly

| Surface | Result | How it was measured |
|---|---|---|
| Unknown DLL loaded into the client | **refused** | proxy `VERSION.dll` → *"failed to load"* + anti-cheat toast *"unsafe system file"*; the proxy's `DllMain` never ran |
| The one library the client loads from its own directory | `EOSSDK-Win64-Shipping.dll`, and it **validates itself** | replacing it → *"Failed to load EOSSDK. Please verify your installation."*, startup aborted |
| Files in the game directory that are *not* loaded | not validated | a `dbghelp.dll` proxy sat there through a full client start |
| Anti-cheat service process | **not** protected | elevated: `0x1FFFFF`, allocation, thread creation all work |
| Client mitigations | CFG on (anti-cheat), ACG off; game: all queried policies zero | `GetProcessMitigationPolicy`, policies 0/2/6/7/8/10 |

---

## 5. What this says about the design

The two mechanisms are complementary and neither is a hook:

* the **mask callback** makes the client's memory unreachable from outside
  without ever telling a caller "no", so it defeats code that checks for
  failure rather than for the rights it actually holds;
* the **thread-start refusal** makes the client's *execution* unreachable
  even if a handle with the right bits ever appeared.

Together they move the question from "can I open the process?" to "do I have
code inside it already?". For the client, the answer to the second question
is where the real work lives — and on this box every user-mode route to it is
measured and closed:

1. no cross-process handle carries VM rights, and no handle anywhere does;
2. no unknown DLL may be loaded into the process;
3. the one library loaded from the game directory validates itself.

What is left is not user-mode, and is deliberately out of scope here: it
needs a kernel component, and the only first links available on a
Secure-Boot machine with no signed-but-vulnerable driver installed are
malware-grade. That is the line this project does not cross.

---

## 6. Reproducing everything

```bat
lab\run_all.ps1                  :: 18 assertions, PASS/FAIL per case
lab\run_all.ps1 -Quick           :: skip the multi-minute mapper case
out\loader.exe --wowprobe MockHost.exe MockGame.exe
out\loader.exe --dupprobe
out\loader.exe --maptest out\payload.dll
```

Raw data: `LIVE_TEST_RESULTS.md`. Design notes: `DECISION_TABLE.md`,
`PROXY_ROUTE.md`, `docs\SESSION_NOTES.md`.
