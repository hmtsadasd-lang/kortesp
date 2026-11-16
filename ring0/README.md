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
run_r0.bat --probe        :: resolve the chain, print each hop
run_r0.bat                :: overlay + ESP
run_r0.bat --cloak        :: unlink the driver from the module list first
```

`run_r0.bat` looks for `dbutil_2_3.sys` in `driver\`, next to the script, in
`%SystemRoot%\System32\drivers\`, or at `%DBUTIL_SYS%`. It creates the service
`DBUtil_2_3` once, leaves it running until reboot, and never stops or deletes
it. If the service exists but is stopped it retries the start; if it is already
RUNNING it does not touch the driver at all.

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

1. **Windows HVCI blocklist** — a load failure. Enforcement is currently off on
   this box (`VerifiedAndReputablePolicyState = 0x0`), so the driver loads. If
   it is turned on, `sc start` fails and nothing appears in the kernel.
2. **Easy Anti-Cheat** — a client refusal. Since mid-2026 EAC recognises
   `dbutil_2_3.sys` and Fortnite will not start while it is loaded. This is not
   a load failure: the driver is named. The cloak is the only counter here, and
   it may not be sufficient because the device object and `\??\DBUtil_2_3`
   symlink survive it.

That changes the test order: `--probe`, then `--cloak` dry run, then
`--cloak-commit`, then launch the game. If EAC still complains, running the
driver under a random service and image name is the next cheapest step (defeats
name matching, not hashing).

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
| `--cloak` | **dry run** — resolve the module-list entry and print every address; writes nothing |
| `--cloak-commit` | actually unlink the driver from `PsLoadedModuleList`; **stays** unlinked after exit |
| `--cloak-restore` | re-link on exit (debugging only) |

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
`ExceptionTableSize`. `restore()` reverses the two writes.

**The cloak is a dry run by default.** It is the only part of the tool that
writes to the kernel, so `--cloak` resolves every address and prints the exact
two writes it would make, and writes nothing. `--cloak-commit` is required to
actually unlink. The neighbour addresses are bounds-checked against the kernel
VA range before any write.

**The unlink is not undone on exit.** The driver cannot be stopped and stays
loaded until reboot, so its entry stays valid and re-linking would only put the
known module name back in front of the anti-cheat. `--cloak-restore` exists for
debugging.

**Physical vs kernel writes.** Target user memory is read through the page
walk + physical path (read-only). Kernel structures are written through the
driver's kernel-VA handler. The physical handler maps non-cached, and a
non-cached write does not invalidate other cores' cache lines — the kernel
reads `PsLoadedModuleList` constantly, so that would be incoherent.

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
- `find_kernel_cr3()` probes physical pages one `DeviceIoControl` at a time.
  It is cached after the first success, but the first run on a large-RAM box is
  slow.
- `IoCreateDevice(..., Exclusive = 1)`: a leftover handle from an earlier
  incarnation blocks the next open.
- The EPROCESS layout table is per-build. If `find_system_eprocess()` fails on
  an OS newer than 26200, add the build's offsets (Vergilius) at the top of
  `kCand`; the list-node check rejects wrong values instead of walking them.
