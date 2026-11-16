# Fortnite ESP — ring0 stack

User-mode physical-memory reader for the Fortnite client. No DLL is mapped into
the game, no client memory is written, and the game process is never opened
with a handle.

## Contents

| File | Purpose |
|---|---|
| `include/offsets.hpp` | Fortnite member offsets (VERIFIED / UNVERIFIED) |
| `include/r0.hpp` / `src/r0.cpp` | DBUtil_2_3 backend: physical read/write + kernel-VA write |
| `include/vmm.hpp` / `src/vmm.cpp` | ntoskrnl discovery, kernel CR3 scan, page walk, EPROCESS scan, attach |
| `include/ov.hpp` / `src/ov.cpp` | Layered-window + D3D11 quad-batcher overlay |
| `include/esp.hpp` / `src/esp.cpp` | ESP pipeline + `--probe` chain walker |
| `include/cloak.hpp` / `src/cloak.cpp` | Unlinks the driver from `PsLoadedModuleList` |
| `include/mock.hpp` / `src/mock.cpp` | Driverless self-test against a synthetic target |
| `src/main.cpp` | Entry point, flags, key toggles |
| `build_r0_mingw.bat` | g++ build script |
| `run_r0.bat` | Start driver + launch |
| `driver/` | Drop `dbutil_2_3.sys` here |

## Status

| Layer | State |
|---|---|
| Build | ✅ compiles and links with w64devkit GCC |
| IOCTL direction | ✅ disassembly + non-zero low-memory read probe in `r0::init()` |
| Page walk (PML4→PT, 2 MB + 1 GB pages) | ✅ verified by `--mock` (17 checks) |
| PEB→LDR→module walk | ✅ verified by `--mock` |
| Offset chain (GEngine→…→GameState→players) | ✅ verified by `--mock` (structure only) |
| FString decode | ✅ verified by `--mock` |
| Projection / overlay geometry | ✅ verified by `--mock` |
| `--cloak` (module unlink) | ⚠️ implemented, not yet run against a live driver |
| `--kwtest` (kernel write proof) | ✅ implemented; needs the driver to run |
| **Offsets against a real client** | ❌ **unmeasured** — no driver present on this box |

`--mock` proves the *code*. It builds the synthetic target from the same
`offsets.hpp` the live path uses, so a wrong offset is invisible there and
still wrong against a real client.

## What the review changed

An audit of the first live-capable revision found the stack could not have
worked, and one bug was actively destructive:

- **The IOCTL pair was swapped.** `0x9B0C1F44` is the physical *write*, so
  every "read" copied a zero-filled buffer into physical memory. The CR3 scan
  therefore zeroed the first 8 bytes of ~8M pages — the 0x50/0xEF bugchecks.
  `r0::init()` now reads non-zero low physical memory before trusting the
  backend (no write probe: guessing the write handler is itself a bugcheck).
- **Kernel writes went through the physical path.** `vmm::kwrite` now uses the
  driver's kernel-VA handler (cached `memmove`), not `MmMapIoSpace`.
- **`attach()` could never match.** `EPROCESS.ImageFileName` is `char[15]`, so
  the full 31-char name never compares equal; the truncated name is now
  confirmed against the target's own PEB module list.
- **The cloak wrote two bogus addresses.** `KLDR_DATA_TABLE_ENTRY` has no
  `InMemoryOrderLinks`; writing `+0x10`/`+0x18` hit `ExceptionTableSize` and
  would fault. It is exactly **two** writes now.
- **UE5 LWC.** `FVector`/`FRotator`/`FQuat` are the 3d/4d double variants;
  `POV_*` and `Xform_Translation` are 8-byte components, and
  `FTransform.Translation` is at `+0x20`.
- **Overlay was opaque.** `SetLayeredWindowAttributes(LWA_ALPHA)` over a
  layered swapchain discards the per-pixel alpha. The swapchain is now
  flip-model with `DXGI_ALPHA_MODE_PREMULTIPLIED`, alpha is premultiplied in
  the shader and blending is `ONE / INV_SRC_ALPHA`. Per-monitor DPI awareness
  is set before any window work, and the window class is no longer named after
  the tool.
- **World pointer re-resolved every frame**, `State_Team` read as a byte.
- **Runner** now tests service *state* rather than existence, refuses to launch
  unless the driver reaches RUNNING, and checks the device handle.

## ⚠ Driver safety

`DBUtil_2_3.sys` is an old driver, and two of the four bugchecks were ours: the
swapped IOCTL meant every "read" zeroed 8 bytes of physical memory, and the CR3
scan did that eight million times. With that fixed, the rules encoded in
`run_r0.bat` are:

1. **Never `sc stop` this driver.** It is `NOT_STOPPABLE` / `IGNORES_SHUTDOWN`.
   Stopping it fails, leaves the service half-deleted, and the driver stays
   loaded with no owner.
2. **Never `sc delete` it while it is running.**
3. **Never overwrite the `.sys` image while an instance is loaded.** The
   on-disk image and the mapped image diverge.
4. **Never start a second instance.** `IoCreateDevice(\Device\DBUtil_2_3)`
   fails on the second one and the driver half-initialises.

So the driver is loaded once and **left running until reboot**. `run_r0.bat`
detects an already-loaded driver and does nothing to it.

Additionally, every physical read in `vmm.cpp` is bounds-checked against
installed RAM. Note what that check is and is not: a physical address in a
reserved hole does **not** reliably fault, because `MmMapIoSpace` builds the
PTEs anyway and the copy returns garbage — it is garbage page-table entries
pointing past the physical-address width that turn into a bugcheck, and the
bound stops those.

## Build

```bat
build_r0_mingw.bat
```

```
g++ -std=c++17 -O2 -municode -Iinclude -o out\fortesp_r0.exe ^
    src\main.cpp src\vmm.cpp src\r0.cpp src\esp.cpp src\ov.cpp ^
    src\cloak.cpp src\mock.cpp ^
    -ld3d11 -ldxgi -ld3dcompiler -lgdi32 -luser32 -lole32
```

## Run

### Self-test (no driver, no game)

```bat
out\fortesp_r0.exe --mock
```

Runs 17 checks over the page walk, the kernel read, the PEB/LDR walk, the
offset chain, the FString decode, LWC doubles and the projection. Prints
PASS/FAIL per check.

### Live

```bat
run_r0.bat --probe        :: resolve the chain, print each hop (read-only)
run_r0.bat --kwtest       :: prove the kernel write path (writes back identical bytes)
run_r0.bat --cloak        :: dry run: print the two unlink writes, write nothing
run_r0.bat --cloak-commit :: actually unlink
run_r0.bat --hide-symlink :: remove \??\DBUtil_2_3 (permanent until reboot)
run_r0.bat                :: overlay + ESP
```

`run_r0.bat` looks for `dbutil_2_3.sys` in `driver\`, next to the script, in
`%SystemRoot%\System32\drivers\`, or at `%DBUTIL_SYS%`. It creates the service
`DBUtil_2_3` once and leaves it running until reboot.

State handling, in order:

| Service state | What the runner does |
|---|---|
| RUNNING / START_PENDING | touches nothing, just runs the tool |
| STOP_PENDING | **aborts** — do not delete a service mid-transition |
| STOPPED | deletes and recreates it (no live image, so nothing is mapped) |
| absent | copies the image and creates it |
| any state after `sc start` but not RUNNING | **aborts** (blocklist / Secure Boot) |

It **aborts** if HVCI (Memory Integrity) is on, because the vulnerable-driver
blocklist is enforced then and the image cannot load. `DBUTIL_FORCE=1` tries
anyway. `FORTESP_NOLOAD=1` skips all driver handling (for when the driver is
already loaded, or when testing the script itself).

**Renaming the driver** (decide before the first load):

```bat
set FORTESP_SVC=SomeSvcName
set FORTESP_IMAGE=SomeName.sys
run_r0.bat --probe
```

The runner copies the image to `drivers\%FORTESP_IMAGE%` (`.sys` is appended if
missing), creates the service from that path, and passes `--driver-name` after
`%*` so its answer always wins. The driver's hardcoded `\Device\DBUtil_2_3` and
`\??\DBUtil_2_3` survive the rename — only the file/service names change. If
the service is already running under a different image the runner refuses to
touch it: reboot first.

Renaming leaves any previous registration behind. Check it is not running, then
remove it (the runner never touches a service other than `%FORTESP_SVC%`):

```bat
sc query DBUtil_2_3
:: only if STATE says STOPPED:
sc delete DBUtil_2_3
```

## The driver

`DBUtil_2_3.sys` is **not in this repository**. It is the Dell BIOS flash
utility driver (CVE-2021-21551); it exposes `\\.\DBUtil_2_3` with two IOCTLs
that read and write arbitrary physical memory.

Fetch it with:

```bat
powershell -ExecutionPolicy Bypass -File driver\fetch_driver.ps1
```

That downloads it and verifies the SHA256 against the
VoidSec/VulnerableWindowsDrivers listing
(`0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5`) and
checks the Authenticode signature (`CN=Dell Inc.`).

### IOCTL interface (read out of the driver, not guessed)

The dispatch at the driver's IRP handler compares the control code against:

| IOCTL | Meaning | Request layout | Length |
|---|---|---|---|
| `0x9B0C1F40` | **physical read** | `{ u64 header; u64 physaddr; u8 payload[]; }` | `0x10 + n` |
| `0x9B0C1F44` | **physical write** | `{ u64 header; u64 physaddr; u8 payload[]; }` | `0x10 + n` |
| `0x9B0C1EC4` | **kernel-VA read** | `{ u64 header; u64 va; u64 offset; u8 payload[]; }` | `0x18 + n` |
| `0x9B0C1EC8` | **kernel-VA write** | `{ u64 header; u64 va; u64 offset; u8 payload[]; }` | `0x18 + n` |

The physical pair maps with `MmMapIoSpace(..., MmNonCached)`; the kernel-VA
pair `memmove`s in the caller's context through the normal cached mapping. The
cloak uses the kernel-VA write for that reason. The other IOCTLs the driver
exposes are port I/O (`0x9B0C1EC0`, `0x9B0C1F80`..`0x9B0C1F8C`) and query
handlers — none are used here.

The earlier `0xA0400C04` / `0xA0400C08` pair came from a different driver and
does not exist in this one. A later revision also had the two physical codes
transposed; `r0::init()` now proves the direction at startup.

### Blocklist and EAC

Two separate gates:

1. **Windows HVCI blocklist** — a load failure. `run_r0.bat` reads the
   `HypervisorEnforcedCodeIntegrity` key and **aborts** when it is on, because
   the blocklist is enforced then and `sc start` fails with nothing in the
   kernel. `DBUTIL_FORCE=1` overrides. Enforcement was off on this box
   (`VerifiedAndReputablePolicyState = 0x0`).
2. **Easy Anti-Cheat** — a client refusal. Since mid-2026 EAC recognises
   `dbutil_2_3.sys` and Fortnite will not start while it is loaded. This is not
   a load failure: the driver is named. The cloak removes the module-list entry
   but the device object and `\??\DBUtil_2_3` symlink survive it, and the file
   name is checkable on disk.

Test order: `--probe` (read-only), `--kwtest` (proves the write path), then
`--cloak` dry run, `--cloak-commit`, `--hide-symlink`, then launch the game.
Rename the driver (`FORTESP_SVC` / `FORTESP_IMAGE`) **before** that last step,
so one launch gives one answer instead of a bisect. `--hide-symlink` is last
because it is permanent for the boot.

## Keys

| Key | Toggle |
|---|---|
| `F1` | ESP on/off |
| `F2` | boxes |
| `F3` | names |
| `F4` | health bar |
| `F5` | distance |
| `F6` | tracer lines |
| `F7` | team colours |
| `F8` | show bots |
| `End` | quit |

Run the game **borderless**, not exclusive fullscreen — a topmost layered
window cannot composite over an exclusive swapchain.

## Flags

| Flag | Effect |
|---|---|
| `--mock` | driverless self-test; exits with the result |
| `--probe` | resolve the chain and print each hop; no window needed |
| `--kwtest` | read `PsInitialSystemProcess`, write the identical 8 bytes back, verify; exits with the result |
| `--cloak` | **dry run** — resolve the module-list entry and print every address; writes nothing |
| `--cloak-commit` | actually unlink the driver from `PsLoadedModuleList`; writes `cloak.state`; **stays** unlinked after exit |
| `--cloak-restore` | standalone: re-link from `cloak.state`, then exit |
| `--hide-symlink` | remove `\??\DBUtil_2_3` (`NtMakeTemporaryObject`); permanent until reboot, run last |
| `--driver-name <n>` | image name to match in the module list (default `dbutil_2_3.sys`, or `FORTESP_DRIVER_IMAGE`) |

`--kwtest` is the only thing that proves the kernel **write** path before the
cloak's two unlink writes — `--probe` is read-only and `--cloak` is a dry run.
Writing the same bytes back over the same address is a no-op to the kernel; a
wrong address is an 8-byte local write, not a sweep.

`--cloak-restore` cannot rediscover the entry (it is no longer in
`PsLoadedModuleList`), so the commit persists `{entry, prev, next, ntoskrnl
base, System EPROCESS}` to `<exe dir>\cloak.state`. Restore refuses a file whose
ntoskrnl base/System EPROCESS does not match the current boot, and refuses to
write unless the list is actually in the unlinked state (`prev.Flink == next`
and `next.Blink == prev`). It deletes the file on success.

`--probe` prints each hop and marks the first failure `<- rejected`:

```
chain:
  GEngine                            ok
  Engine->GameViewportClient         ok
  Viewport->World                    ok
  World->GameState                   ok
  World->OwningGameInstance          ok
  GameInstance->LocalPlayers         ok
  LocalPlayers.Count > 0             ok
  LocalPlayers[0]                    ok
  LocalPlayer->PlayerController      ok
  Controller->PlayerState            ok
  Controller->PlayerCameraManager    ok      <- first failure is marked here
```

## Ban surface

| Artifact | Present |
|---|---|
| Client memory written | no |
| Handle to the client with VM rights | no |
| Client swapchain vtable patched | no (`payload/render.cpp` does that, this does not) |
| DLL mapped into the client | no |
| Loaded kernel module `dbutil_2_3.sys` | **yes** — the one real fingerprint |
| `\GLOBAL??\DBUtil_2_3` symlink | **yes** — secondary |

The design only *reads*. `--cloak-commit` removes the module-list entry so
ordinary module enumeration stops naming the driver; the device symlink is
still visible and would need an `OBJECT_DIRECTORY` unlink to remove as well.

## Design notes

**SeDebugPrivilege is mandatory.** `NtQuerySystemInformation(SystemModuleInformation)`
redacts `SYSTEM_MODULE.ImageBase` unless the caller holds `SeDebugPrivilege`.
An elevated `cmd.exe` does **not** enable it (an elevated PowerShell does, and
the child inherits the enabled token) — so the value reads as 0 and ntoskrnl
cannot be found. `main.cpp` enables it explicitly via `AdjustTokenPrivileges`.

**The 296-byte `SYSTEM_MODULE`.** The entry layout on this build is:

```
+0x00 Section      ULONG_PTR
+0x08 MappedBase   ULONG_PTR
+0x10 ImageBase    ULONG_PTR
+0x18 ImageSize    ULONG          <- 32-bit, not 64
+0x1C Flags        ULONG
+0x20 LoadCount    USHORT
+0x22 TlsIndex     USHORT
+0x24 HashId       ULONG
+0x28 ModuleName[256]
```

The header is an 8-byte count; the stride is derived from the buffer size so
it does not have to be hardcoded. `ModuleName` holds the **full path**
(`\SystemRoot\system32\ntoskrnl.exe`), so it is matched on the suffix.

**EPROCESS offsets must be per-build.** `vmm.cpp` validates a candidate layout
by checking, for the System process, that `pid == 4`, `ImageFileName ==
"System"`, and that the `ActiveProcessLinks` node is a real circular list
(both neighbours kernel addresses, forward neighbour's `Blink` points back).
Offsets (Vergilius, x64):

| Build | UniqueProcessId | ActiveProcessLinks | ImageFileName | Peb | DirectoryTableBase |
|---|---|---|---|---|---|
| Win11 24H2 / 25H2 (26200) | 0x1D0 | 0x1D8 | 0x338 | 0x2E0 | 0x28 |
| Win11 23H2 / Win10 22H2 | 0x440 | 0x448 | 0x5A8 | 0x550 | 0x28 |

The earlier table had `links 0x98, Peb 0x38`, which are not fields in either
structure. Validation only looked at pid/name, so it passed and `attach()`
then walked garbage. The list check now rejects a wrong `links` immediately.

**Base discovery.** `NtQuerySystemInformation(SystemModuleInformation)` lists
*kernel* modules — the client is not in it, and entry field 0 is `Section`,
not `ImageBase`. The client base comes from the target's `EPROCESS` → `PEB`
→ `LDR_DATA_TABLE_ENTRY` walk. `BaseDllName` is a `UNICODE_STRING`
(length at `+0x58`, buffer at `+0x60`, UTF-16), `DllBase` is at `+0x30`,
`SizeOfImage` at `+0x40`, and `InLoadOrderLinks.Flink` at `+0x00`.

**UE5 is LWC: vectors are `double[3]`.** `FVector` is `FVector3d`,
`FRotator` is `FRotator3d`, `FQuat` is `FQuat4d` (32 bytes). `offsets.hpp` is
self-consistent only that way — `POV_Location 0x00`, `POV_Rotation 0x18`,
`POV_FOV 0x30` needs 24-byte members. Reading `float[3]` returns the low
mantissa halves of the doubles. The same applies to `FTransform`:
`Translation` is at `+0x20`, not `+0x10`.

**Page walk.** 2 MB and 1 GB large pages are handled explicitly. A 2 MB page
resolves to `(pde & 0x000FFFFFFFE00000) + (va & 0x1FFFFF)`; because the PDE
address field only carries bits 21+, the PD slot for chunk *j* of a 1 GB
region is `(pd0 + j) & 0x1FF`.

**TLB is keyed on the CR3 as well as the VA page**, because the kernel-CR3
scan walks many candidate CR3s at the same VA.

**`--cloak` without the export.** `PsLoadedModuleList` is not exported on
build 26200. The cloak falls back to scanning ntoskrnl's writable,
non-executable sections for a `LIST_ENTRY` whose first entry validates as a
real module. The driver is matched by `DllBase`, so a renamed `.sys` still
resolves. **Two** writes: `prev.Flink = next`, `next.Blink = prev`. The kernel
`KLDR_DATA_TABLE_ENTRY` has no `InMemoryOrderLinks` — that field exists only in
the user-mode `LDR_DATA_TABLE_ENTRY`, and writing to its slot would hit
`ExceptionTableSize`. `restore()` reverses the two writes from the persisted
`cloak.state`.

**The `.data` fallback is bulk-read.** Scanning for `PsLoadedModuleList` reads
4 KiB at a time and filters locally for qwords that could be the head's Flink
(kernel VA, 16-byte aligned); only those few candidates pay the ~5 dependent
reads in `valid_head()`. The old loop did one IOCTL per qword.

**The kernel CR3 is cached on disk.** `find_kernel_cr3` is ~8M IOCTLs, so a hit
is written to `<exe dir>\cr3.cache` keyed on the ntoskrnl base *and* size, and
re-validated on load by translating the base and checking for `MZ`. KASLR moves
ntoskrnl every boot, so the cache is invalidated by construction; the `MZ` check
catches a page directory that was freed and reused.

**The cloak is a dry run by default.** It is the only part of the tool that
writes to the kernel, so `--cloak` resolves every address and prints the exact
two writes it would make, and writes nothing. `--cloak-commit` is required to
actually unlink. The neighbour addresses are bounds-checked against the kernel
VA range before any write.

**The unlink is not undone on exit.** The driver cannot be stopped and stays
loaded until reboot, so its entry stays valid and re-linking would only put the
known module name back in front of the anti-cheat. `--cloak-restore` is a
standalone mode: it re-links from `cloak.state` and exits, and refuses stale
state (wrong boot, or neighbours that match neither endpoint).

Restore handles the crash-between-writes case explicitly. `prev.Flink == next`
and `next.Blink == prev` mean fully unlinked; both pointing at the entry means
nothing was written (clear the state file); exactly one means half-unlinked, and
that half is completed first (idempotent) before re-linking. Re-linking from the
half state would leave one neighbour pointing at the entry and the other not.

**`--hide-symlink` removes the name, not the device.** `IoCreateSymbolicLink`
creates `\??\DBUtil_2_3` as a permanent object; opening it with `DELETE` and
calling `NtMakeTemporaryObject` clears that flag so the directory entry goes
away when the handle closes. The already-open device handle keeps working — it
refers to the device object — but any later `CreateFile("\\.\DBUtil_2_3")`
returns `OBJECT_NAME_NOT_FOUND`, and that includes a later run of this tool.
Reboot is the only way back. `\Driver\DBUtil_2_3` and the service registry key
survive; those need object-directory surgery this tool does not do.

**Physical vs kernel writes.** Target user memory is read through the page
walk + physical path (read-only). Kernel structures are written through the
driver's kernel-VA handler. The physical handler maps non-cached, and a
non-cached write does not invalidate other cores' cache lines — the kernel
reads `PsLoadedModuleList` constantly, so that would be incoherent.

**`sc stop` after a commit.** `NtUnloadDriver` resolves the image through
`PsLoadedModuleList` via the driver object's section pointer. With the entry
unlinked there is nothing to find, so the call fails or leaves a half state.
The driver is `NOT_STOPPABLE` anyway; the runner never stops it and the only
documented unload path is a reboot.

## Offsets quick-reference

All RVAs from the client module base. `VERIFIED` = confirmed against the
6b77eceb dump, `UNVERIFIED` = needs a watch or a re-dump.

```
GEngine                          0x1C9DC1D8  VERIFIED
GObjects                         0x1C966F18  VERIFIED
Engine_GameViewportClient        0xC0        VERIFIED
Viewport_World                   0x78        VERIFIED
World_GameState                  0x1C0       VERIFIED
World_OwningGameInstance         0x238       VERIFIED
GameInstance_LocalPlayers        0x38        VERIFIED
Player_PlayerController          0x30        VERIFIED
Controller_PlayerState           0x280       VERIFIED
Controller_PlayerCameraManager   0x2C8       UNVERIFIED
Camera_CameraCachePrivate        0x15A0      VERIFIED
CacheEntry_POV                   0x10        VERIFIED
POV_Location                     0x00        VERIFIED  (3x double)
POV_Rotation                     0x18        VERIFIED  (3x double)
POV_FOV                          0x30        VERIFIED  (double, degrees)
GameState_PlayerArray            0x290       VERIFIED
State_Pawn                       0x2F0       VERIFIED
State_Name                       0x310       VERIFIED  (FString)
State_Flags                      0x2F8       UNVERIFIED
State_Team                       0xF81       UNVERIFIED
Pawn_Mesh                        0x2F8       VERIFIED
Pawn_Dying                       0x738       VERIFIED
Pawn_HealthSet                   0x1430      VERIFIED
Pawn_CapsuleHalf                 0x1E8C      VERIFIED
Comp_C2W                         0x100       VERIFIED
Xform_Translation                0x20        VERIFIED  (3x double)
Health_Current                   0x48+0x4    VERIFIED
Health_Base                      0x48        VERIFIED
Health_Max                       0x70+0x4    VERIFIED
```

## Known issues

- `State_Team` at `0xF81` is a byte (the offset is not 4-aligned). Unverified;
  if team colours look wrong, re-dump it.
- `Controller_PlayerCameraManager` at `0x2C8` is unverified and is the most
  likely first failure in `--probe`.
- `State_Flags` at `0x2F8` is unverified; if the bot filter misbehaves,
  compare with `F8` toggled.
- `Xform_Translation 0x20` follows from `FQuat4d` being 32 bytes. If a real
  target reads implausible coordinates, read both `0x10` and `0x20` once and
  keep whichever triple lands near the local pawn.
- `find_kernel_cr3()` probes physical pages one `DeviceIoControl` at a time. It
  is cached in memory and on disk (`cr3.cache`), so the ~8M-IOCTL scan is a
  one-time cost per boot. It is **not** parallelised: the driver is opened
  exclusively and its dispatch caches request state in the device extension, so
  concurrent IOCTLs on one handle are unverified — and the last thing this box
  needs is another unverified concurrency assumption. If the first scan after a
  reboot turns out to be painful, the safe shape is one worker per *disjoint
  physical range* behind a probe that has already been validated live.
- `IoCreateDevice(..., Exclusive = 1)`: a leftover handle from an earlier
  incarnation blocks the next open.
- The EPROCESS layout table is per-build. If `find_system_eprocess()` fails on
  an OS newer than 26200, add the build's offsets (Vergilius) at the top of
  `kCand`; the list-node check rejects wrong values instead of walking them.
