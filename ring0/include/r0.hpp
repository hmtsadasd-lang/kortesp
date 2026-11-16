#pragma once
#include <cstdint>
#include <cstddef>

namespace r0 {

// Physical-memory backend.
//
// The table below is the *only* place that names the device and the IOCTL
// pairs. Everything above this layer (page-table walking, EPROCESS discovery)
// is backend-agnostic, so swapping the driver is a change to this file only.
//
// The three primitives are deliberately different things:
//
//   read/write  - PHYSICAL addresses. The driver maps the range with
//                 MmMapIoSpace (uncached) and copies in or out.
//   vwrite      - KERNEL virtual addresses. The driver memmoves in the
//                 caller's context, so the write goes through the normal
//                 cached mapping and stays coherent with other cores.
//
// Do not use the physical path for kernel addresses: the cached/uncached
// mismatch leaves stale lines in cores that are reading the same structure.
struct Backend {
    const wchar_t* device;      // L"\\\\.\\DBUtil_2_3"
    bool (*open)();
    void (*close)();
    bool (*read)(uint64_t pa, void* out, size_t len);         // physical
    bool (*write)(uint64_t pa, const void* in, size_t len);   // physical
    bool (*vwrite)(uint64_t va, const void* in, size_t len);  // kernel VA
};

// Initialise the global backend. Returns false if no recognised device
// is present; caller must not use r0::pread/pwrite until init() succeeds.
bool init();
void shutdown();
bool alive();

// Install a backend directly, bypassing device discovery.
// Used by the lab mock so the whole pipeline can be exercised with no
// kernel driver present. Pass nullptr to clear.
void set_backend(const Backend* be);

// Physical read/write. Both are length-aware.
bool pread(uint64_t pa, void* buf, size_t len);
bool pwrite(uint64_t pa, const void* buf, size_t len);

// Kernel-virtual write (used by the cloak).
bool vwrite(uint64_t va, const void* buf, size_t len);

} // namespace r0