# Decision table

The probe measures the facts; the branch is chosen from them. `--wowprobe`
prints both, so the decision is visible instead of implied:

```
facts wow64=1 granted=0x0011F145 alloc=0x0 lasterr=5 reached=1
decision=not_whitelisted (granted 0x11F145 carries no vm rights)
```

## The facts

| Fact | Where it comes from |
|---|---|
| `wow64` | `IsWow64Process` on the host — the anti-cheat service is 32 bit |
| `granted` | `NtQueryObject(ObjectBasicInformation).GrantedAccess` on the handle the host obtained on the game |
| `alloc` | the result of the allocation the host attempted inside itself |
| `lasterr` | `GetLastError` after that allocation |
| `reached` | the stub ran and reported back (the handle is non zero) |

## The branches

| Branch | Condition | Meaning |
|---|---|---|
| `host_unreachable` | no handle on the host | the anti-cheat service could not be opened at all |
| `re_resolve_by_name` | `wow64 = 0` | the host is not the 32 bit process we expected — resolve the image name again |
| `real_relay` | reached **and** `alloc != 0` | the host can allocate in the game — go straight to the relay |
| `not_whitelisted` | `granted = 0x11F145`, `alloc = 0`, `lasterr = 5` | the mask carries no VM rights — the whitelist regime does not allow injection |
| `thread_did_not_report` | the stub did not report back | the injected thread failed; the fallback path is tried |
| `blocked_unknown` | nothing matched | — |

The stub tries the full mask first and the whitelist mask second; the facts
are taken from whichever handle it actually obtained.

## The lab

`lab\run_lab.bat` reproduces the whole thing without the client:

```
MockGame.exe  64 bit, replaces its own DACL with one that grants exactly
              0x11F145 - no VM_OPERATION, VM_READ or VM_WRITE
MockHost.exe  32 bit, stands in for the anti-cheat service
```

The mock game is the interesting part: it reproduces the **capped grant**
with nothing but a DACL. The real anti-cheat reaches the same numbers
through a kernel callback, and the observable result is the same:

```
open_path GAME ALL_ACCESS   -> handle=null ntstatus=0xC0000022
open_path GAME 0x11F145     -> handle=0x118 granted=0x0011F145
stub whitelist_handle=0xA0  granted=0x0011F145 alloc=0x0 lasterr=5
facts wow64=1 granted=0x0011F145 alloc=0x0 lasterr=5 reached=1
decision=not_whitelisted (granted 0x11F145 carries no vm rights)
```

Same facts, same branch as the live client.

### One difference worth knowing

A DACL and a kernel callback fail differently:

* **DACL** — asking for more than the ACL allows makes the open *fail*
  outright (`0xC0000022`), asking for exactly the allowed bits succeeds.
* **Kernel callback** (what the anti-cheat does) — the requested mask is
  *stripped*, so `PROCESS_ALL_ACCESS` succeeds and returns a handle with
  `0x11F145` on it.

The lab therefore shows the DACL flavour, the live client shows the callback
flavour. The decision table reads the granted mask either way, so the branch
is the same.

### The masked process cannot even be inspected

Because the mock game only grants `0x11F145`, `taskkill` is refused — it
asks for `PROCESS_QUERY_INFORMATION` as well, which the mask does not
carry. `lab\kill_mask.c` opens it with `0x11F145` and terminates it: a
masked process can still be killed, it just cannot be looked at.

## Known limitation

The WOW64 fallback (suspended thread plus `NtSetContextThread`) is best
effort. On this build the kernel rejects the WOW64 context with
`STATUS_ACCESS_VIOLATION`; the thread has to be created suspended and the
context installed afterwards, and the segment selectors have to be the ones a
32 bit thread has on x64 (`CS/SS/DS/ES = 0x23`, `FS = 0x53`, `GS = 0x2B`).
The primary path — the stub reporting through its own result block — does
work, and that is the path the decision table is built on.

Two more things the lab pinned down:

* `NtCreateThreadEx` with an explicit `StackSize` is rejected by this kernel
  with `STATUS_INVALID_PARAMETER`; the size has to stay `0`.
* The payload's path buffer has to be **static**: a 520 byte stack local in
  the mapped payload faulted, while the same code with a file-scope buffer
  runs the whole target-mode branch cleanly (`A0..A3, A7, B0..B8, B3`,
  thread exit 0).
