#pragma once
// Manual mapping into a host process. Lives in shared/ so the loader EXE and
// the proxy DLL use exactly the same mapper.
#include "nt.hpp"
#include <cstddef>

using map_log_fn = void (*)(const char* fmt, ...);

struct map_result {
    bool started;      // the entry thread was created and ran
    DWORD exit_code;   // its exit code
    uintptr_t remote;  // mapped image base in the host (keep_mapped only)
};

// Read a whole file into a heap buffer (caller frees with delete[]).
bool slurp_file(const wchar_t* path, uint8_t** out, size_t* size);

// Export RVA of `name` inside a mapped image, 0 when absent.
uint64_t find_export(IMAGE_NT_HEADERS64_* nt, uint8_t* img, const char* name);

// NtCreateThreadEx wrapper. `flags` are the raw NtCreateThreadEx thread
// creation flags (0x2 = suspended).
NTSTATUS_ nt_create_thread(HANDLE proc, void* start, void* arg, uint32_t flags, HANDLE* out);

// Map `img` into `ph` and run it.
//
//   self_path     : baked into the image's g_host_path export
//   start_export  : export to call; nullptr or "" falls back to
//                   AddressOfEntryPoint (the CRT startup of a real image)
//   keep_mapped   : do not free the image when the thread exits
// Probe mode baked into the image's g_probe_mode export before the entry
// thread exists (0 = hook the loader, 1 = events only, -1 = normal payload).
void manual_map_set_probe(int mode);

bool manual_map_host(HANDLE ph, const uint8_t* img, size_t img_size,
                     const wchar_t* self_path, const char* start_export,
                     bool keep_mapped, map_result* out, DWORD wait_ms,
                     map_log_fn log);
