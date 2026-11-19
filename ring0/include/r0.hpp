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
// The four primitives are deliberately different things:
//
//   read/write  - PHYSICAL addresses. The driver maps the range with
//                 MmMapIoSpace (uncached) and copies in or out.
//   vread/vwrite- KERNEL virtual addresses. The driver memmoves in the
//                 caller's context, so the copy goes through the normal
//                 cached mapping and stays coherent with other cores.
//
// Do not use the physical path for kernel addresses: the cached/uncached
// mismatch leaves stale lines in cores that are reading the same structure.
// Do not use vread for an address you have not derived from a trusted source:
// a non-present kernel VA faults inside the driver's memmove and bugchecks
// (0x50). Use the page walk (vmm::kread) for unvalidated candidates.
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
bool phys_read_raw(uint64_t pa, void* buf, size_t len);

// Kernel-virtual write (used by the cloak) and read.
bool vwrite(uint64_t va, const void* buf, size_t len);
bool vread(uint64_t va, void* buf, size_t len);

extern bool g_write_ok;
bool kwtest(uint64_t sys_eproc);

// Prove which half of the kernel-VA pair 0x9B0C1EC4 really is. Sets
// vmm::g_ntos_mz_broken when it proves the pair is transposed. Until this
// returns true, vmm::kread_trusted refuses to use the handler.
bool vread_probe(uint64_t va, size_t len);
bool vread_ready();

// Remove the driver's symbolic link (e.g. L"\\DosDevices\\DBUtil_2_3") from
// the object directory, so CreateFile(L"\\\\.\\DBUtil_2_3") afterwards returns
// OBJECT_NAME_NOT_FOUND. The device object itself is unaffected: call this
// while the device handle is open, and I/O keeps working on that handle.
// Permanent until the driver is reloaded (i.e. reboot). Requires DELETE access
// on the link, so the caller must be elevated.
bool hide_symlink(const wchar_t* link);

// Live-patch the loaded DBUtil_2_3.sys so its physical path maps with
// MmCached instead of MmNonCached: on this build the kernel refuses
// MmNonCached mappings of active OS RAM, which is every page-table page
// and every game structure. Refuses outright when HVCI is running (the
// write would bugcheck), verifies every byte before writing, and needs
// the driver still listed in the kernel module list - so run it BEFORE
// --cloak, and re-run it on every boot (it lives only in memory).
bool patch_cached_map(bool dry_run = false, const char* step = nullptr);

} // namespace r0