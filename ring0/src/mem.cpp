#include "mem.hpp"
#include "vmm.hpp"
#include "r0.hpp"
#include <windows.h>
#include <cstdio>
#include <cstring>

extern vmm::Walk walk_va(uint64_t cr3, uint64_t va, uint64_t& pa);

namespace mem {

static backend g_be = backend::phys;
static HANDLE g_rpm_proc = nullptr;

void set_backend(backend b) {
    g_be = b;
}

backend active() {
    return g_be;
}

bool open_rpm(uint32_t pid) {
    g_rpm_proc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                             FALSE, pid);
    if (!g_rpm_proc) {
        DWORD err = GetLastError();
        if (err == 5) {
            printf("[rpm] err=5 - mask stripped, EAC is up. Use --backend phys.\n");
        } else {
            printf("[rpm] OpenProcess failed: err=%lu\n", err);
        }
        return false;
    }
    return true;
}

bool read(uint64_t va, void* out, size_t n) {
    if (!n || !out) return false;
    if (g_be == backend::rpm) {
        if (!g_rpm_proc) return false;
        SIZE_T got = 0;
        return ReadProcessMemory(g_rpm_proc, (LPCVOID)va, out, n, &got) && got == n;
    }
    // phys: page walk through vmm's g_gcr3, then physical read
    auto* p = static_cast<uint8_t*>(out);
    for (size_t i = 0; i < n;) {
        uint64_t pa{};
        const vmm::Walk st = walk_va(vmm::g_gcr3, va + i, pa);
        if (st != vmm::Walk::Ok) return false;
        size_t chunk = 0x1000 - ((va + i) & 0xFFF);
        if (chunk > n - i) chunk = n - i;
        if (!r0::pread(pa, p + i, chunk)) return false;
        i += chunk;
    }
    return true;
}

bool write(uint64_t va, const void* in, size_t n) {
    if (!n || !in) return false;
    if (g_be == backend::rpm) {
        if (!g_rpm_proc) return false;
        SIZE_T wrote = 0;
        return WriteProcessMemory(g_rpm_proc, (LPVOID)va, in, n, &wrote) && wrote == n;
    }
    // phys: page walk through vmm's g_gcr3, then physical write
    auto* p = static_cast<const uint8_t*>(in);
    for (size_t i = 0; i < n;) {
        uint64_t pa{};
        const vmm::Walk st = walk_va(vmm::g_gcr3, va + i, pa);
        if (st != vmm::Walk::Ok) return false;
        size_t chunk = 0x1000 - ((va + i) & 0xFFF);
        if (chunk > n - i) chunk = n - i;
        if (!r0::pwrite(pa, p + i, chunk)) return false;
        i += chunk;
    }
    return true;
}

} // namespace mem
