#pragma once
#include "nt.hpp"

extern "C" {
    NTSTATUS_ sc1(uint64_t, uint32_t);
    NTSTATUS_ sc2(uint64_t, uint64_t, uint32_t);
    NTSTATUS_ sc3(uint64_t, uint64_t, uint64_t, uint32_t);
    NTSTATUS_ sc4(uint64_t, uint64_t, uint64_t, uint64_t, uint32_t);
    NTSTATUS_ sc5(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint32_t);
    NTSTATUS_ sc6(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint32_t);
    NTSTATUS_ sc7(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint32_t);
    NTSTATUS_ sc9(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                  uint64_t, uint64_t, uint32_t);
    NTSTATUS_ sc11(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                   uint64_t, uint64_t, uint64_t, uint64_t, uint32_t);
}

namespace sys {

bool init();
uint32_t num(const char* name);

constexpr UPTR CURRENT_PROCESS_ = static_cast<UPTR>(-1);

inline NTSTATUS_ alloc(void** base, size_t size, uint32_t prot, uint32_t type = MEM_COMMIT_ | MEM_RESERVE_) {
    uint64_t b = 0, sz = size;
    NTSTATUS_ s = sc6(CURRENT_PROCESS_, UPTR(&b), 0, UPTR(&sz), type, prot, num("NtAllocateVirtualMemory"));
    if (base) *base = reinterpret_cast<void*>(b);
    return s;
}

inline NTSTATUS_ protect(void* addr, size_t size, uint32_t prot) {
    uint64_t a = UPTR(addr), sz = size;
    uint32_t old = 0;
    return sc5(CURRENT_PROCESS_, UPTR(&a), UPTR(&sz), prot, UPTR(&old), num("NtProtectVirtualMemory"));
}

inline NTSTATUS_ release(void* addr) {
    uint64_t a = UPTR(addr), sz = 0;
    return sc4(CURRENT_PROCESS_, UPTR(&a), UPTR(&sz), MEM_RELEASE_, num("NtFreeVirtualMemory"));
}

inline NTSTATUS_ close(void* h) { return sc1(UPTR(h), num("NtClose")); }

inline NTSTATUS_ sleep(uint64_t ticks) {
    int64_t t = -static_cast<int64_t>(ticks);
    return sc2(0, UPTR(&t), num("NtDelayExecution"));
}

inline NTSTATUS_ ctx_get(void* t, CONTEXT_* c) { return sc2(UPTR(t), UPTR(c), num("NtGetContextThread")); }
inline NTSTATUS_ ctx_set(void* t, CONTEXT_* c) { return sc2(UPTR(t), UPTR(c), num("NtSetContextThread")); }
inline NTSTATUS_ resume(void* t, uint32_t* prev) { return sc2(UPTR(t), UPTR(prev), num("NtResumeThread")); }

} // namespace sys