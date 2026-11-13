# Load-time route: proxy DLL + shared mapper

## What changed

| File | Change |
|---|---|
| `shared/include/nt.hpp` | `IMAGE_TLS_DIRECTORY64_`, `DIR_TLS_ = 9` |
| `shared/include/map_host.hpp` | new: `slurp_file`, `find_export`, `nt_create_thread`, `manual_map_host`, `map_log_fn`, `map_result` |
| `shared/src/map_host.cpp` | new: the mapper, moved out of `loader/src/main.cpp` |
| `loader/src/main.cpp` | mapper deleted, call sites use the shared header |
| `loader/src/proxy.cpp` | new: the load-time entry DLL |
| `loader/src/dbghelp.def` | generated forwarders (249) |
| `tools/mkfwd.py` | new: `.def` generator (`--list`, `--exports`) |
| `tools/gen_def.bat` | regenerates `dbghelp.def` |
| `tools/deploy_proxy.bat` | installs proxy + real dbghelp + payload into the game dir |
| `payload/src/entry.cpp` | target-mode detection (`already_in_target`) |

### Mapper changes (all four points from the plan)

* **Low-address allocation** – the image is reserved at `0x10000000 … 0x50000000`
  first, so a 32-bit host stays below 4 GB; the plain allocation is only the
  fallback.
* **TLS callbacks** – `run_tls_callbacks()` reads the TLS directory out of the
  mapped image and runs every callback on its own thread with
  `RCX = image base`, `RDX = DLL_PROCESS_ATTACH`, `R8 = 0`, then resumes it.
  The thread is created with `NtCreateThreadEx` flags `0x2`
  (`THREAD_CREATE_FLAGS_SUSPENDED`) – the plan's `1` is
  `THREAD_CREATE_FLAGS_RUN_SYNCHRONOUS`, which would let the callback run
  before the context is fixed up.
* **Entry-point fallback** – `start_export == nullptr` or `""` uses
  `AddressOfEntryPoint` (`_DllMainCRTStartup` for a real CRT image); a
  missing export also falls back to it.
* **`keep_mapped`** – the image and its stack are only released when the
  thread exited *and* `keep_mapped` is false.

`nt_create_thread()` was extracted as the spec asks; the mapper, the TLS
runner and the proxy all use it.

Two things the plan implied but did not spell out, and that the old code did
not do at all:

* **Imports are now resolved by `manual_map_host`.** The old mapper wrote the
  image and started the entry point with an untouched import table, so every
  imported function was a hint/name RVA instead of an address. The shared
  mapper resolves them against the *target* process (PEB walk + export hash),
  which is what makes the proxy path work.
* **The mapper works on the current process.** `manual_map_host` takes a
  handle, so `GetCurrentProcess()` is a valid target – that is how the proxy
  maps the payload into the game it was loaded into.

## The proxy

`out\dbghelp.dll` is the proxy. It is named after the DLL it shadows and
carries the forwarders from `loader/src/dbghelp.def`:

```
[ 168] Forwarder RVA -- dbghelp_real.dll.SymInitialize
[  42] Forwarder RVA -- dbghelp_real.dll.StackWalk64
```

Deployment (`tools\deploy_proxy.bat`, elevated):

```
dbghelp.dll       <- out\dbghelp.dll   (the proxy)
dbghelp_real.dll  <- Epic's original dbghelp.dll, kept under a new name
payload.dll       <- out\payload.dll
```

The real copy is preserved under a new name instead of being replaced by the
system one: Epic ships a newer dbghelp than Windows does, and the forwarders
must cover the exact API surface the game uses.

## Which DLL to shadow

> **Correction after the live test.** The client never loads `dbghelp.dll` —
> that copy belongs to CrashReportClient. The only library the client loads
> from its own directory is `EOSSDK-Win64-Shipping.dll`, and it validates
> itself. `LIVE_TEST_RESULTS.md` has the measured outcome of every anchor
> that was tried.

The Fortnite client on disk is **packed**:

```
entry point      0x0
SizeOfImage      0x200
section 0        va=0x00001000 vs=0x1E4DA000 (508 MB, RW, no CODE flag)
import directory empty
".dll" strings in the file: 0
```

There is no import table and no plaintext DLL name anywhere in the 508 MB
file, so `tools/mkfwd.py <game.exe> dbghelp.dll` (forwarders derived from the
importer's import table) cannot work on this binary – there is nothing to
derive them from.

What *is* there: `dbghelp.dll` (2.2 MB) sits next to the game executable,
which is UE4's crash-reporting copy. The game resolves that name at runtime,
and the loader's default search order puts the application directory first,
so a `dbghelp.dll` in that directory is the one that gets loaded. The
forwarders are therefore generated from the **real dbghelp's export table**
(`mkfwd.py --exports`), which is a superset of whatever the game imports.

Other files in the same directory that do have normal import tables, if a
different anchor is wanted:

| File | Imports |
|---|---|
| `FortniteClient-Win64-Shipping_EAC_EOS.exe` | ADVAPI32, bcrypt, CRYPT32, GDI32, IMM32, KERNEL32, ole32, OLEAUT32, SETUPAPI, SHELL32, USER32, VERSION, WINMM, WS2_32 |
| `FortniteBootstrapper.exe` | ADVAPI32, bcrypt, CRYPT32, imagehlp, KERNEL32, ole32, USER32, WS2_32 |
| `EOSSDK-Win64-Shipping.dll` | ADVAPI32, bcrypt, CRYPT32, GDI32, IPHLPAPI, KERNEL32, ole32, SHELL32, USER32, VERSION, WINHTTP, WINMM, WINTRUST, WS2_32 |

`imagehlp.dll` in `FortniteBootstrapper.exe` is a second candidate anchor.

### Anchors outside the game directory

`VERSION.dll`, `WINHTTP.dll`, `bcrypt.dll`, `CRYPT32.dll`, `IPHLPAPI.DLL`,
`WINMM.dll` and `WINTRUST.dll` are **not** in `KnownDLLs` and are not
app-local, so a proxy for them placed in the game directory is picked up by
the loader (application directory first). The client pulls in `VERSION.dll`
through the EOS SDK, which makes it the natural candidate — EAC refuses to
load it, though:

```
The code execution cannot proceed because VERSION.dll failed to load.
Easy Anti-Cheat: Güvenli olmayan sistem dosyası (...\Binaries\Win64)
```

So the shadowing machinery is complete and verified; what it lacks is an
anchor EAC accepts.

## Target-mode detection

`payload/src/entry.cpp` now checks whether it is already inside the game:

```c
static bool already_in_target() {
    wchar_t exe[MAX_PATH]{};
    if (!ntapi::GetModuleFileNameW_(nullptr, exe, MAX_PATH)) return false;
    ...
}
```

Without it the proxy's payload would see `g_host_path`, take the relay
branch and try to map itself into the game again – which fails, because the
game handle is capped at `0x11F145` (see `PROBE_FINDINGS.md`).

## Verify in this order

1. `proxy.log` next to the game exe has `[+] proxy thread up`
   → the proxy was loaded, so the forwarders resolved.
2. `[*] payload N bytes` → path resolution and file read work.
3. `[*] mm: tls cb N ok` → the TLS walk works. Our payload has no TLS
   directory (`no tls directory`); FortniteMCP would have callbacks.
4. `[+] map ok=1` → the mapper ran inside the game.
5. `C:\Users\Public\fortesp2.log` shows `target mode (in process)`
   → the payload took the target branch instead of relaying.
6. The payload's ESP overlay comes up (F1 toggles).

## Build

```bat
build_mingw.bat          :: out\loader.exe
build_payload_mingw.bat  :: out\payload.dll
build_proxy_mingw.bat    :: out\dbghelp.dll   (needs loader\src\dbghelp.def)
tools\gen_def.bat        :: regenerate loader\src\dbghelp.def
```

### Two gotchas found while building the proxy

* GNU `ld` parses MSVC `.def` files, but its parser rejects `#` comments –
  the count line has to go to stderr instead.
* A forwarder target may not contain a path (`C:\Windows\System32\...`):
  the parser splits on `:` and reports `cannot export C:: symbol not
  defined`. The target has to be a bare module name, which the loader then
  resolves through the normal search path (application directory first).
