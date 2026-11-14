# Fortnite ESP Ring0 Driver

Self-consistent ring0/user-mode stack for Fortnite ESP, built against w64devkit GCC.

## Contents

| File | Purpose |
|---|---|
| `include/offsets.hpp` | Fortnite member offsets (VERIFIED / UNVERIFIED) |
| `include/r0.hpp` / `src/r0.cpp` | DBUtil_2_3 8‑byte physical memory IO |
| `include/vmm.hpp` / `src/vmm.cpp` | CR3 discovery, page walks, EPROCESS scan, PEB module walk |
| `include/ov.hpp` / `src/ov.cpp` | Layered‑window + D3D11 quad batcher overlay |
| `include/esp.hpp` / `src/esp.cpp` | ESP pipeline: resolve_base, build_view, project, draw_player |
| `src/main.cpp` | `wmain` with `--probe` flag and key toggles |
| `build_r0_mingw.bat` | Full g++ build script |
| `run_r0.bat` | Start driver + launch EXE |
| `README.md` | This file |

## Build prerequisites

1. **Driver file** – place `dbutil_2_3.sys` alongside `run_r0.bat`.  
   The script creates/starts the `DBUtil_2_3` kernel service automatically.

2. **Font header** – `payload/include/font.hpp` must exist (already present).  
   Provides `font::index()` and `font::kGlyphs[]` used by `ov::text()`.

3. **w64devkit** – installed at `C:\tmp\w64devkit\w64devkit`.  
   `g++.exe` must be on `PATH`.

## Building

```bat
build_r0_mingw.bat
```

This compiles `src/*.cpp` into `out/fortesp_r0.exe` with:

```
g++ -std=c++17 -O2 -municode -Iring0\include \
    src\main.cpp src\vmm.cpp src\r0.cpp src\esp.cpp src\ov.cpp \
    -ld3d11 -ldxgi -ld3dcompiler -lgdi32 -luser32 -lole32
```

## Running

```bat
run_r0.bat --probe
```

This:

1. Ensures the `DBUtil_2_3` service is running.
2. Launches `out/fortesp_r0.exe --probe`.

### `--probe` output

Prints each hop with `<- rejected` on the first failure, then the POV location,
rotation, FOV and up to three players (name, box, health bar, distance). Example:

```
hop 1: CR3 read <- rejected   // camera chain offset mismatch
POV: location=(1123.4, 56.7, -12.3) rot=(1.2, 3.4, 0.5) fov=78.2
Players (3):
  1. JohnDoe  box=(120,200..280) health=0.73 dist=12.3m
  2. BotPlayer box=(95,180..170) health=1.00 dist=45.1m
  3. EmptyName box=(0,0..0) health=0.00 dist=999.9m
```

If the probe stops at the camera chain, the offending offset is in
`offsets.hpp` (e.g. `Controller_PlayerCameraManager 0x2C8` or
`Camera_CameraCachePrivate 0x15A0`). Fix the offset, re‑build, and rerun.

## Design notes – what changed from the last version

| Area | Change |
|---|---|
| **Base discovery** | Moved off `NtQuerySystemInformation(SystemModuleInformation)` – that list is kernel modules only. Now walks the target’s PEB `LDR_DATA_TABLE_ENTRY` list looking for `FortniteClient-Win64-Shipping.exe` by name. |
| **UE vectors** | Read as `float[3]` and promoted to `double[3]` only in the math layer; all intermediate reads use `float[3]` to match the dump. |
| **r0::init()** | Probes the device with two identical reads of page 0; only accepts if they agree. No more undefined `kDbUtil` dereference. |
| **vmm::attach()** | Finds the process by image name from the EPROCESS linked list, reads its CR3 (DTB), maps it for target‑space reads. |
| **OV overlay** | Uses `B8G8R8A8` swapchain, premultiplied clear, `ResizeBuffers` when the client rect changes, `WS_EX_NOACTIVATE`, per‑frame viewport set from client rect. |
| **Offsets** | Every entry in `offsets.hpp` is tagged `VERIFIED` or `UNVERIFIED`; none left as `INFER`. |
| **Key handling** | `main.cpp` uses a simple `was_down[]` table; no `GetAsyncKeyState` macro conflicts, no `boollast`, no `for(inti=)`. |
| **ESP math** | `project()` and `build_view()` use `float` for UE vectors, `double` for intermediate calculations – matches the dump layout exactly. |

## Offsets quick‑reference

All offsets are RVAs from the client module base (set via PEB walk). Marked
`VERIFIED` if confirmed against the 6b77eceb dump, `UNVERIFIED` if needing a
watch or re‑dump.

```
GEngine             0x1C9DC1D8   VERIFIED
GObjects            0x1C966F18   VERIFIED
Engine_GameViewportClient 0xC0   VERIFIED
Viewport_World      0x78   VERIFIED
World_GameState           0x1C0   VERIFIED
World_OwningGameInstance  0x238   VERIFIED
GameInstance_LocalPlayers 0x38   VERIFIED
Player_PlayerController   0x30   VERIFIED
Controller_PlayerCameraManager 0x2C8   UNVERIFIED (camera chain)
Camera_CameraCachePrivate 0x15A0   VERIFIED (from camera obj)
CacheEntry_POV          0x10   VERIFIED
POV_Location          0x00   VERIFIED (float[3]->double[3])
POV_Rotation          0x18   VERIFIED (float[3]->double[3])
POV_FOV               0x30   VERIFIED (float, degrees)
GameState_PlayerArray   0x290   VERIFIED
State_Pawn      0x2F0   VERIFIED
State_Name      0x310   VERIFIED (FString)
State_Flags     0x2F8   UNVERIFIED (bot/spectator/inactive bits)
State_Team      0xF81   UNVERIFIED (AFortPlayerStateAthena::TeamIndex)
Pawn_Mesh       0x2F8   VERIFIED (USkeletalMeshComponent*)
Pawn_Dying      0x738   VERIFIED (bit 5 = bIsDying)
Pawn_HealthSet      0x1430   VERIFIED
Pawn_CapsuleHalf    0x1E8C   VERIFIED (float)
Comp_C2W      0x100   VERIFIED (FTransform, gap before RelativeLocation)
Xform_Translation   0x10   VERIFIED (FTransform.Translation, 3x double)
Health_Current      0x48+0x4   VERIFIED (CurrentValue)
Health_Base       0x48   VERIFIED (BaseValue fallback)
Health_Max      0x70+0x4   VERIFIED
```