#include "hide.hpp"
#include "log.hpp"
#include "../../shared/include/syscall.hpp"
#include "../../shared/include/peb.hpp"

namespace {

void* g_thread{};
void* g_stack{};

uintptr_t ret_gadget() {
    auto* dos = static_cast<IMAGE_DOS_HEADER_*>(peb::self()->ImageBaseAddress);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(reinterpret_cast<uint8_t*>(dos) + dos->e_lfanew);

    auto* sec = IMAGE_FIRST_SECTION_(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & SCN_EXECUTE_)) continue;
        auto* p = reinterpret_cast<uint8_t*>(dos) + sec->VirtualAddress;
        uint32_t n = sec->VirtualSize ? sec->VirtualSize : sec->SizeOfRawData;
        for (uint32_t b = 0; b < n; ++b)
            if (p[b] == 0xC3) return reinterpret_cast<uintptr_t>(p + b);
    }
    return 0;
}

} // namespace

bool hide::alloc_rx(void* base, size_t image_size) {
    auto* b   = static_cast<uint8_t*>(base);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER_*>(b);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(b + dos->e_lfanew);

    auto* sec = IMAGE_FIRST_SECTION_(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->VirtualSize) continue;
        uint32_t prot = PAGE_R_;
        if (sec->Characteristics & SCN_EXECUTE_) prot = PAGE_RX_;
        else if (sec->Characteristics & SCN_WRITE_) prot = PAGE_RW_;
        if (!NT_SUCCESS(sys::protect(b + sec->VirtualAddress, sec->VirtualSize, prot))) return false;
    }

    sys::protect(b, nt->OptionalHeader.SizeOfHeaders, PAGE_R_);
    return true;
}

bool hide::launch_worker(void* worker) {
    uintptr_t gadget = ret_gadget();
    if (!gadget) { log::w(L"no ret gadget"); return false; }

    if (!NT_SUCCESS(sys::alloc(&g_stack, 0x8000, PAGE_RW_))) { log::w(L"stack alloc failed"); return false; }

    auto* top = reinterpret_cast<uint8_t*>(
        (reinterpret_cast<uintptr_t>(g_stack) + 0x7F00) & ~static_cast<uintptr_t>(0xF));
    top -= 8;                                  // RSP % 16 == 8 at function entry
    *reinterpret_cast<uintptr_t*>(top) = gadget;
    *reinterpret_cast<uintptr_t*>(top + 8) = 0;

    uint64_t handle = 0;
    NTSTATUS_ s = sc11(UPTR(&handle), 0x1FFFFF, 0, 0,
                       UPTR(worker), UPTR(top), 1 /* CREATE_SUSPENDED */, 0, 0, 0, 0,
                       sys::num("NtCreateThreadEx"));
    if (!NT_SUCCESS(s)) { log::w(L"create thread failed"); return false; }

    CONTEXT_ ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL_;
    if (!NT_SUCCESS(sys::ctx_get(reinterpret_cast<void*>(handle), &ctx))) return false;

    ctx.Rip = UPTR(worker);
    ctx.Rsp = UPTR(top);
    ctx.Rbp = 0;

    if (!NT_SUCCESS(sys::ctx_set(reinterpret_cast<void*>(handle), &ctx))) return false;

    uint32_t prev = 0;
    sys::resume(reinterpret_cast<void*>(handle), &prev);
    g_thread = reinterpret_cast<void*>(handle);
    log::w(L"worker laundered");
    return true;
}

void hide::stop_worker() {
    if (g_thread) { sys::close(g_thread); g_thread = nullptr; }
    if (g_stack) { sys::release(g_stack); g_stack = nullptr; }
}