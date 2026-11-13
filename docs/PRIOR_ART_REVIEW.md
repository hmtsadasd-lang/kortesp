# Prior art review — four repositories, and what of theirs applies here

Reviewed on 13.11.2026, from the repositories' published sources:

| repository | what it actually is |
|---|---|
| `MicrosoftARMAssembler/Orelia-Injector` | a **kernel driver** plus user-mode IOCTL client. Its `module.hxx` resolves `EasyAntiCheat_EOS.sys` in kernel memory by byte pattern, then **calls EAC's own internal routines** (`allocate_memory`, `protect_memory`, `zero_memory`, `free_memory`, `attach_process`, `detach_process`) so the allocation happens inside the anti-cheat's own memory manager. |
| `MicrosoftARMAssembler/Orelia-Fortnite-Internal` | an **internal DLL** (`DllMain` → `CreateThread` entry point) that talks to a user-mode **gateway over a named pipe** (`orelia-gateway`), with a heartbeat keep-alive, `oxorany` string encryption, a `skcrypt` string cipher, VMT hooking of `DrawTransition`, and a ViGEm client for mouse input. The driver (if any) is not in this repository — only the pipe side. |
| `MicrosoftARMAssembler/Popstar-Fortnite-External` | an **external** overlay: a kernel driver device `\\.\this-isnt-a-real-device-hi-from-leproxy`, a `syscall` stub for `NtDeviceIoControlFile` (`mov r10, rcx / mov eax, 7 / syscall` — a **fixed** service number, hard-coded), DTB/linear-translate reads, and a hand-rolled ImGui overlay on DX11. |
| `MicrosoftARMAssembler/Undetected-Easy` | **not a cheat at all**: a kernel-mode **detection scanner** that reimplements EAC/BE/Vanguard integrity checks against your own driver (module integrity, execution integrity via NMI/IPI stack sampling, PTE/PFN walk, object and handle checks, device guards). |
| `MicrosoftARMAssembler/Peach-Framework` | a **rendering framework** (DX11/DX12) written as an ImGui replacement *because* ImGui needs `malloc`, `memcpy`, `new`/`delete` and leaves a font atlas in memory — costs a manual-mapped image cannot pay without a CRT. |

## Where they stand and where this project stands

Every one of the four that touches the client assumes one of two things:

* **a kernel driver** as the memory channel (Orelia-Injector, Popstar), or
* **a CRT-bearing DLL** loaded by `LoadLibrary`-like means (Orelia-Fortnite-Internal, Peach).

This project has neither, by choice, and has measured why the second one cannot be
reached on this box: the client caps every handle handed out by the kernel to
`0x11F145` (no `VM_WRITE`, `VM_READ`, `VM_OPERATION`, `CREATE_THREAD`), refuses
`SetSecurityInfo` even from the object's owner, refuses `VirtualAllocEx` with
error 5, is not PPL (`protection level 0x00`) and has no mitigation policy set
beyond DEP — and refuses any replaced `version.dll` in its own directory.
Their `Orelia-Fortnite-Internal` DLL would fail on exactly the same wall: its
`DllMain` runs `is_valid(L"FortniteClient-Win64-Shipping.exe")` and then
`_beginthreadex`, which needs nothing but *getting loaded* — and getting loaded
into this client is the unsolved half.

So the useful part of these repositories is not their delivery trick (two of them
are kernel, one is CRT, one is a checklist). It is in **how they read the SDK**
and **how they check themselves**.

## What is worth taking, concretely

### 1. Reading objects through a *call into the engine* instead of the chain
`Orelia-Fortnite-Internal/impl/sdk/sdk.hxx` locates `UObject::ProcessEvent` in the
object's **vtable by index** (`offsets::process_event = 0x22`) and then calls
engine functions through the client's own code:

```cpp
reinterpret_cast<void(__cdecl*)(u_object*, u_function*, void*)>(
    vtable[offsets::process_event])(this, fn, params);
```

and it finds objects by name via `StaticFindObject` at `base + 0x21EE808`
(`static_find_object`), calling it with the class/outer/name tuple.

**Why this matters here:** the current `payload/src/game.cpp` walks
`GEngine → GameViewportClient → World → GameState → Players` with offsets taken
from a public dump, and the hand-off lands on "GEngine address outside the client
image" because that chain is derived from a *different* build. `StaticFindObject`
by **name** (or `GObjects` by class, then compare the name) does not depend on the
intermediate field offsets at all: only the address of one exported/patterned
function and the layout of `FName` do. That is the smallest possible set of
unknowns, and it is exactly what an image that must survive a Fortnite patch
wants.

Their numbers, for reference, as offsets from the client's base (their build, not
ours — **do not paste them**):

| theirs | meaning |
|---|---|
| `0x21EE808` | `UObject::StaticFindObject` — signature: `(class*, outer*, wchar_t* name, bool exact)` |
| `0x1E83B10` / `0x1D7467C` | `malloc` / `free` inside the engine |
| `0x1512C30` / `0x151320C` | `StaticConstructObject_Internal` / `StaticAllocateObject` |
| `0x22` (index) | `UObject::ProcessEvent` vtable index |
| `115` (index) | `UGameViewportClient::DrawTransition` |

On this build the same addresses must be found by **pattern**, not by adding their
delta to our base — the two builds differ by hundreds of megabytes.

### 2. The self-check idea from `Undetected-Easy`
UDE is honest about what EAC looks for in kernel space, and three of its categories
apply to a **user-mode manual-mapped image** too, because the client's own
inspection sees the same things:

* **unnamed / non-file-backed executable regions** — a manual map is private memory
  with `PAGE_EXECUTE_READ` and no file behind it;
* **a thread whose start address is not in a module** (UDE's
  `execution::thread::scan` checks exactly that);
* **written-then-executed pages, `PAGE_EXECUTE_READWRITE` anywhere**, and code in
  a non-executable section.

This is the argument for finishing work already started in this repo: the mapper
already delivers `.bss` as one shared `CreateFileMapping` view and marks
non-executable sections `PAGE_READWRITE` / executable `PAGE_EXECUTE_READ`; a
mapped image that puts its **code and data in a file-backed section** (paging
from `\\?\...` or the payload DLL itself) removes the first two findings instead
of hiding them, without touching the anti-cheat.

### 3. No CRT, no ImGui — `Peach-Framework`
Peach exists because ImGui drags `malloc`/`new`/`sprintf` into a manual-mapped
image. `payload/src/libc_min.cpp` is this project's version of the same decision
(`strlen`/`wcslen` only, and now `___chkstk_ms` for the probe). If a UI ever goes
into the payload, Peach's drawing model (a flat draw list, glyphs rasterised from
STB) is the right shape; ImGui is not, and its font atlas is a signature of its own.

### 4. The pipe + heartbeat pattern from `Orelia-Fortnite-Internal`
Their payload is deliberately thin: the DLL only maps, hooks one vtable index,
and then answers a heartbeat over a named pipe; every decision lives outside the
process, so a crash of the internal half is survivable and every experiment costs
one restart. This project already has the "thin payload, log to a file" half;
the missing half is a control channel. `entry.cpp`'s `g_probe_mode` is the first
step of the same idea (the host bakes in what the payload should do).

## What is explicitly *not* being taken

* **`Orelia-Injector`'s method**: it calls EAC's driver routines from kernel memory.
  That is using the anti-cheat's own driver as the bypass, which is out of scope
  for this project by its own rules. Reading it was still useful: it names the
  routines (`protect/allocate/zero/free` on a control struct with a type tag of
  `5` for free, `0x8000` free type) and shows how EAC's memory manager is shaped,
  which is information about the thing being studied.
* **`Popstar`'s syscall stub**: `mov eax, 7` is a fixed syscall number for
  `NtDeviceIoControlFile`, valid on one build only. This repo's `syscall.cpp`
  resolves the number from the ntdll stub instead, which is the portable version
  of the same trick.
* **`Orelia-Injector`'s IOCTL driver** and **`Popstar`'s DTB reads**: kernel
  memory access, out of scope.
* **`Undetected-Easy`'s driver**: it is a scanner, so there is nothing to reuse
  beyond the list of what gets detected — which is the part quoted above.

## Concrete next steps this review argues for

1. **Find `StaticFindObject` (or `GObjects` + `FName::ToString`) in this client by
   pattern on its `.text`**, and replace the dump-derived chain in `game.cpp` with a
   name-based lookup. One address and one `FName` layout instead of twelve field
   offsets. The patterns can be borrowed as *structure* from the Orelia/Dumpspace
   dumps but must be re-scanned against the file at
   `C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64`.
2. **Make the mapped image file-backed** so that UDE's first two categories have
   nothing to report, rather than being evaded.
3. **Keep the payload CRT-free** (`libc_min.cpp` is the whole story) and keep the
   probe's event ring static, as it is now.
4. **Leave delivery as the open problem it is**: none of these four repositories
   solves "get a DLL into a handle-capped client without a kernel driver" — two use
   a driver, one assumes the DLL is already there, one is a rendering library. The
   `LdrpLoadDll` / `LdrRegisterDllNotification` probe in `payload/src/probe.cpp` is
   still the right instrument for that question.
