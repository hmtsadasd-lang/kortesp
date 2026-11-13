
---

# 16:40 - the mapper's resolver: two independent bugs, both found by measurement

## The symptom

`[!] unresolved KERNEL32.dll!CloseHandle` - the mapper could not resolve a
name that every process on the box has. The payload had grown imports (the
log channel), and the channel code calls `CloseHandle` *through the IAT*, so
the broken IAT surfaced for the first time. The payload's own Win32 calls go
through `ntapi::k32` (a dynamic PEB lookup), which is why nothing noticed
before.

## Bug 1: the module hash could never match (pre-existing, repo original)

```c
// map_host.cpp, module list walk
if (h::fnv1a_w(name) == hash) ...      // name is WIDE
// caller
remote_proc(ph, h::fnv1a(dll), ...)  // dll is NARROW
```

`fnv1a_w` folds case but hashes the **16 bit code unit**; `fnv1a` hashes
**bytes**. The two hashes are never equal, so the module was never found and
every import failed. This has been in the repo since the original loader.

Fix: `h::fnv1a_ci_w` - folds to lowercase ASCII and hashes the *byte*, so it
matches `h::fnv1a_ci` over the narrow name exactly.

## Bug 2: the target's module list is incomplete for the first milliseconds

With the hash fixed, the walk still missed kernel32 on a freshly spawned
process:

```
[dbg] module 'FortniteClient-Win64-Shipping.exe' ...
[dbg] module 'ntdll.dll' ...            <- walk stops here, kernel32 not mapped yet
[dbg] module 'KERNEL32.DLL' hash=0xA3E6F6C3 want=0xA3E6F6C3   <- second walk, found
```

The mapper starts before the target's own loader has finished. Fix: the
module lookup retries (40 x 25 ms) instead of giving up on the first miss.

## Also fixed in the resolver

* **export forwarders** are followed (kernel32 has 211 of them). An export
  whose RVA lands inside the export directory is a forwarder string
  (`Dll.Func` / `Dll.#123`); it is resolved one more level, depth cap 2.
* **ordinal imports** are resolved through `AddressOfFunctions[ord - Base]`
  instead of being skipped (the hint/name RVA used to be left in the IAT).
* the export name compare is exact (`fnv1a`, case sensitive, linear scan).

## The harness that would have caught it

`lab/resolver_test.c` (new): loads ten modules locally, walks their export
tables the way the mapper does and compares every answer with
`GetProcAddress`.

```
checked=8061 missed=0 forwarders=615
RESOLVER: OK
```

It hashes the **wide** module name directly (not via `WideCharToMultiByte`),
because a harness that converts to ASCII first cannot see the wide/narrow
hash mismatch - that is exactly how the first version of this harness
passed while the remote path still failed.

## Suite and channel

| Item | Before | After |
|---|---|---|
| `lab\run_all.ps1` | 15 passed, 3 failed | **27 passed, 0 failed** |
| mapper case | `host spawn failed 2` | passes |
| channel round trip | never reached | `ACK PING`, `ACK BASE 0x7FF773260000` |

Two suite-side fixes: the suite now builds the mock target the mapper's
`--maptest` spawns (`out\lab\FortniteClient-Win64-Shipping.exe` - it carries
the client's name on purpose, so the payload takes the target branch), and
it pins the working directory (the spawn path is relative to it).

Two assertions expected `exit=0` where the payload legitimately returns 1
(it ran, took the target branch and `game::init()` degraded because the mock
has no engine); they now assert that the thread ran and the mapper reported
success, which is what the case is about.

Three bugs in `tools/channel_test_v2.cpp` (the test, not the mapper): it
freed the image before reading it (`keep_mapped` was false), it asked for a
non-existent export (`channel_test` instead of `channel_start`), and it read
the *target's* image in its own address space - it has to go through
`ReadProcessMemory`.

Open wart: the channel answers every command it sees in the log, so a command
that is still in the file gets answered again on the next pass (`ACK PING`
four times). The channel should track how far it has read.
