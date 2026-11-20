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
static unsigned g_read_fail_seen = 0;

static void log_rpm_failure(uint64_t va, size_t wanted, SIZE_T got, DWORD err) {
    if (g_read_fail_seen++ >= 8) return;
    printf("[rd] backend=rpm va=0x%llx err=%lu got=%llu/%zu\n",
           (unsigned long long)va, (unsigned long)err,
           (unsigned long long)got, wanted);
    if (!g_rpm_proc) return;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQueryEx(g_rpm_proc, reinterpret_cast<LPCVOID>(va), &mbi, sizeof(mbi))) {
        printf("[rd] VirtualQueryEx failed: err=%lu\n", (unsigned long)GetLastError());
        return;
    }
    printf("[rd] state=0x%lx type=0x%lx allocBase=0x%llx prot=0x%lx\n",
           (unsigned long)mbi.State, (unsigned long)mbi.Type,
           (unsigned long long)reinterpret_cast<uint64_t>(mbi.AllocationBase),
           (unsigned long)mbi.Protect);
}

static void log_phys_failure(const char* stage, uint64_t va, uint64_t pa,
                             size_t wanted, size_t got, DWORD err, vmm::Walk walk) {
    if (g_read_fail_seen++ >= 8) return;
    printf("[rd] backend=phys stage=%s va=0x%llx pa=0x%llx err=%lu got=%zu/%zu walk=%s\n",
           stage, (unsigned long long)va, (unsigned long long)pa,
           (unsigned long)err, got, wanted, vmm::walk_name(walk));
}

void set_backend(backend b) {
    g_be = b;
}

backend active() {
    return g_be;
}

bool open_rpm(uint32_t pid) {
    if (g_rpm_proc) {
        CloseHandle(g_rpm_proc);
        g_rpm_proc = nullptr;
    }
    g_rpm_proc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                             FALSE, pid);
    if (!g_rpm_proc) {
        const DWORD err = GetLastError();
        printf("[rpm] OpenProcess(pid=%u) failed: err=%lu\n", pid, (unsigned long)err);
        return false;
    }
    printf("[rpm] OpenProcess(pid=%u) ok\n", pid);
    return true;
}

HANDLE get_proc_handle() {
    return g_rpm_proc;
}

bool read(uint64_t va, void* out, size_t n) {
    if (!n || !out) return false;
    if (g_be == backend::rpm) {
        if (!g_rpm_proc) {
            log_rpm_failure(va, n, 0, ERROR_INVALID_HANDLE);
            return false;
        }
        SIZE_T got = 0;
        SetLastError(ERROR_SUCCESS);
        const BOOL ok = ReadProcessMemory(g_rpm_proc, reinterpret_cast<LPCVOID>(va),
                                          out, n, &got);
        const DWORD err = GetLastError();
        if (ok && got == n) return true;
        log_rpm_failure(va, n, got, ok && got != n ? ERROR_PARTIAL_COPY : err);
        return false;
    }
    // phys: page walk through vmm's g_gcr3, then physical read
    auto* p = static_cast<uint8_t*>(out);
    for (size_t i = 0; i < n;) {
        uint64_t pa{};
        const vmm::Walk st = walk_va(vmm::g_gcr3, va + i, pa);
        if (st != vmm::Walk::Ok) {
            log_phys_failure("walk", va + i, 0, n, i, 0, st);
            return false;
        }
        size_t chunk = 0x1000 - ((va + i) & 0xFFF);
        if (chunk > n - i) chunk = n - i;
        SetLastError(ERROR_SUCCESS);
        if (!r0::pread(pa, p + i, chunk)) {
            log_phys_failure("pread", va + i, pa, n, i, GetLastError(), st);
            return false;
        }
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
