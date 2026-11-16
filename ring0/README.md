# Fortnite ESP — ring0 stack

User-mode physical-memory reader for the Fortnite client. No DLL is mapped into
the game, no client memory is written, and the game process is never opened
with a handle.

## Contents

| File | Purpose |
|---|---|
| `include/offsets.hpp` | Fortnite member offsets (VERIFIED / UNVERIFIED) |
| `include/r0.hpp` / `src/r0.cpp` | DBUtil_2_3 physical-memory backend (8-byte read/write) |
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
| Page walk (PML4→PT, 2 MB + 1 GB pages) | ✅ verified by `--mock` |
| PEB→LDR→module walk | ✅ verified by `--mock` |
| Offset chain (GEngine→…→GameState→players) | ✅ verified by `--mock` (structure only) |
| FString decode | ✅ verified by `--mock` |
| Projection / overlay geometry | ✅ verified by `--mock` |
| `--cloak` (module unlink) | ⚠️ implemented, not yet run against a live driver |
| **Offsets against a real client** | ❌ **unmeasured** — no driver present on this box |

`--mock` proves the *code*. It builds the synthetic target from the same
`offsets.hpp` the live path uses, so a wrong offset is invisible there and
still wrong against a real client.

## ⚠ Driver safety

`DBUtil_2_3.sys` is an old, buggy driver. It bugchecked this machine four
times before the runner was fixed. The rules now encoded in `run_r0.bat`:

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
installed RAM. The driver's read path is `MmMapIoSpace` + copy, and mapping a
physical address in a reserved hole faults in kernel mode — a bugcheck, not an
error code.

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

Runs 14 checks over the page walk, the kernel read, the PEB/LDR walk, the
offset chain, the FString decode and the projection. Prints PASS/FAIL per
check.

### Live

```bat
run_r0.bat --probe        :: resolve the chain, print each hop
run_r0.bat                :: overlay + ESP
run_r0.bat --cloak        :: unlink the driver from the module list first
```

`run_r0.bat` looks for `dbutil_2_3.sys` in `driver\`, next to the script, in
`%SystemRoot%\System32\drivers\`, or at `%DBUTIL_SYS%`. It creates the
service under a random name and deletes it on exit.

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
| `0x9B0C1F44` | read physical memory | `{ u64 header; u64 physaddr; u8 payload[]; }` | `0x10 + n` |
| `0x9B0C1EC8` | write physical memory | `{ u64 header; u64 base; u32 offset; u32 pad; u8 payload[]; }` | `0x18 + n` |

The write target address is `base + offset` (offset is 32-bit). The other
IOCTLs the driver exposes are port I/O (`0x9B0C1EC0`, `0x9B0C1EC4`,
`0x9B0C1F80`..`0x9B0C1F8C`) and query handlers — none are used here.

The earlier `0xA0400C04` / `0xA0400C08` pair came from a different driver and
does not exist in this one.

### Blocklist

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
| `--cloak-commit` | actually unlink the driver from `PsLoadedModuleList` |

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

The design only *reads*. `--cloak` removes the module-list entry so ordinary
module enumeration stops naming the driver; the device symlink is still
visible and would need an `OBJECT_DIRECTORY` unlink to remove as well.

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

**Base discovery.** `NtQuerySystemInformation(SystemModuleInformation)` lists
*kernel* modules — the client is not in it, and entry field 0 is `Section`,
not `ImageBase`. The client base comes from the target's `EPROCESS` → `PEB`
→ `LDR_DATA_TABLE_ENTRY` walk. `BaseDllName` is a `UNICODE_STRING`
(length at `+0x58`, buffer at `+0x60`, UTF-16), `DllBase` is at `+0x30`,
`SizeOfImage` at `+0x40`, and `InLoadOrderLinks.Flink` at `+0x00`.

**UE vectors are `float[3]`.** Reading them as `double[3]` pulls in 24 bytes
and leaves the upper components garbage.

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
resolves. Both `InLoadOrderLinks` and `InMemoryOrderLinks` are unlinked (four
writes), and restored in reverse before the service stops.

**The cloak is a dry run by default.** It is the only part of the tool that
writes to the kernel, so `--cloak` resolves every address and prints the
exact four writes it would make, and writes nothing. `--cloak-commit` is
required to actually unlink. The neighbour addresses are bounds-checked
against the kernel VA range before any write.

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
POV_Location                     0x00        VERIFIED  (float[3])
POV_Rotation                     0x18        VERIFIED  (float[3])
POV_FOV                          0x30        VERIFIED  (float, degrees)
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
Xform_Translation                0x10        VERIFIED  (float[3])
Health_Current                   0x48+0x4    VERIFIED
Health_Base                      0x48        VERIFIED
Health_Max                       0x70+0x4    VERIFIED
```

## Known issues

- `State_Team` at `0xF81` is not 8-aligned for an `int32`. Unverified; if
  team colours look wrong, re-dump it.
- `Controller_PlayerCameraManager` at `0x2C8` is unverified and is the most
  likely first failure in `--probe`.
- `State_Flags` at `0x2F8` is unverified; if the bot filter misbehaves,
  compare with `F8` toggled.
