# fortesp

Windows user-mode tooling for the Fortnite client: a manual mapper, a DLL
proxy, a process/handle probe, and the measurements that came out of running
them against a live EAC-protected client.

## Documents

| File | What it is |
|---|---|
| `PROBE_FINDINGS.md` | the measured EAC protection model (handle masking, mitigations, what is and is not reachable) |
| `LIVE_TEST_RESULTS.md` | the live test: every route that was tried, what happened, and the evidence |
| `PROXY_ROUTE.md` | the load-time route: proxy design, forwarder generation, anchors |
| `DECISION_TABLE.md` | the facts the probe measures, the branches it picks, and the lab that reproduces them |
| `docs/HANDOFF_PROMPT.md` | a paste-in prompt for continuing the work, with the measurements included |

## Layout

```
loader/src/main.cpp        the probe and the loader CLI (--wowprobe, --dupprobe, --maptest, ...)
loader/src/proxy.cpp       the load-time entry DLL (proxy.cpp)
loader/src/*.def           generated forwarder tables (dbghelp, version, EOSSDK)
shared/src/map_host.cpp    the manual mapper (shared by the loader and the proxy)
shared/include/map_host.hpp
shared/include/nt.hpp      PE/native types, TLS directory, OBJECT_BASIC_INFORMATION
payload/src/entry.cpp      payload entry: relay mode and target mode
payload/src/hide.cpp        thread laundering for the mapped payload
tools/mkfwd.py             .def generator (--list, --exports)
tools/patch_exports.py     copies the export ordinal base from the original
tools/gen_def.bat          regenerates a forwarder .def
tools/deploy_hijack.bat    installs a proxy into the game directory
tools/restore_game_files.bat  puts the game directory back
```

## Build

No MSVC on this machine, so the MinGW-w64 (w64devkit) path is the one that
works. `fortesp.sln` is still the reference build for a Visual Studio box.

```bat
build_mingw.bat            :: out\loader.exe
build_payload_mingw.bat    :: out\payload.dll
build_proxy_mingw.bat <dll-name>   :: out\<dll-name>.dll (proxy)
```

Set `W64DK` to the toolchain root (default `C:\tmp\w64devkit\w64devkit`).

## Run

```bat
run_wowprobe.bat           :: the probe, writes wowprobe.out
run_wowprobe_admin.bat     :: the same probe elevated (UAC), plus the sibling probes
out\loader.exe --dupprobe  :: system-wide handle survey
out\loader.exe --maptest   :: mapper self-test against a spawned cmd.exe
lab\run_lab.bat            :: decision-table lab (mock host + mock game)
lab\run_payload_lab.bat    :: payload delivery into a mock target
```

The lab reproduces the client's behaviour with nothing but a DACL: the mock
game grants exactly `0x11F145`, so the probe measures the same facts and
prints the same branch without touching the game.

## What the measurements say

* The client's process handles are masked to `0x11F145` by an EAC kernel
  callback — for every caller, including SYSTEM inside EAC and an elevated
  admin with `SeDebugPrivilege`. No `PROCESS_VM_OPERATION`, `VM_WRITE`,
  `VM_READ` or `CREATE_THREAD`.
* No process on the machine holds a handle to the client with usable rights
  (`--dupprobe`: 4375 handles surveyed, 0 matches).
* EAC refuses to load an unknown DLL into the client, and the one library the
  client loads from its own directory validates itself.
* EAC's own service is *not* protected: elevated, it hands out `0x1FFFFF`,
  and code can be started inside it.

Details, evidence and the exact error strings are in `LIVE_TEST_RESULTS.md`.
