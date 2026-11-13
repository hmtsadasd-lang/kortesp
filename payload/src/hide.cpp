#include "../../shared/include/ntapi.hpp"
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

// NtCreateThreadEx hands back a handle the context calls do not accept: the
// entry is valid in this process, but NtGet/NtSetContextThread convert it
// again and answer STATUS_ACCESS_VIOLATION, so the launch fails after the
// image is already in place. Duplicating the same entry with DUP_HANDLE gives
// a handle all of them accept. This walks the process handle table to find it.
uint64_t dup_handle(uint64_t h) {
    using NtQSI = NTSTATUS_(__stdcall*)(ULONG, void*, ULONG, ULONG*);
    void* ntdll = peb::module_base(HHW(L"ntdll.dll"));
    auto qsi = reinterpret_cast<NtQSI>(peb::export_proc(ntdll, HH("NtQuerySystemInformation")));
    if (!qsi) { log::w(L"dup: no NtQuerySystemInformation"); return 0; }

    struct E { uintptr_t object, pid, handle; uint32_t access; uint16_t bt, type; uint32_t attrs, res; };
    constexpr uint32_t kLen = 1u << 20;

    void* buf = nullptr;
    if (!NT_SUCCESS(sys::alloc(&buf, kLen, PAGE_RW_))) { log::w(L"dup: buffer alloc failed"); return 0; }

    ULONG ret = 0;
    NTSTATUS_ st = static_cast<NTSTATUS_>(-1);
    for (int i = 0; i < 6; ++i) {
        st = qsi(0x40, buf, kLen, &ret);
        if (st >= 0) break;
    }
    if (st < 0) { log::w(L"dup: NtQuerySystemInformation failed"); sys::release(buf); return 0; }

    auto* ent = reinterpret_cast<E*>(static_cast<uint8_t*>(buf) + 0x10);
    uintptr_t count = *static_cast<uintptr_t*>(buf);
    // PEB->UniqueProcessId: the process id the handle table belongs to.
    uintptr_t me = *reinterpret_cast<uintptr_t*>(reinterpret_cast<uint8_t*>(peb::self()) + 0x440);

    using F = int(__stdcall*)(void*, void*, void*, void**, uint32_t, int, uint32_t);
    void* k32 = peb::module_base(HHW(L"kernel32.dll"));
    auto dh = reinterpret_cast<F>(peb::export_proc(k32, HH("DuplicateHandle")));

    uint64_t out = 0;
    log::w(dh ? L"dup: kernel32 DuplicateHandle ok" : L"dup: no DuplicateHandle");
    if (dh) {
        for (uintptr_t i = 0; i < count; ++i) {
            if (ent[i].pid != me || ent[i].handle != h) continue;
            void* dup = nullptr;
            if (dh(reinterpret_cast<void*>(-1), reinterpret_cast<void*>(h),
                   reinterpret_cast<void*>(-1), &dup, 0, 0, 0x2 /* DUPLICATE_SAME_ACCESS */))
                out = reinterpret_cast<uint64_t>(dup);
            break;
        }
    }
    sys::release(buf);
    return out;
}

} // namespace

bool hide::alloc_rx(void* base, size_t image_size) {
    auto* b   = static_cast<uint8_t*>(base);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER_*>(b);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(b + dos->e_lfanew);

    const size_t page = 0x1000;
    bool ok = true;

    auto* sec = IMAGE_FIRST_SECTION_(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        size_t size = sec->VirtualSize ? sec->VirtualSize : sec->SizeOfRawData;
        if (!size) continue;
        // NtProtectVirtualMemory wants a page aligned region.
        size = (size + page - 1) & ~(page - 1);

        // PAGE_READONLY is the fault-in-progress page: once the payload's own
        // code runs in this image, a read-only section that get_module_base
        // and every other static walk touches turns into an access violation
        // the moment anything writes to it. Read-write costs nothing here and
        // keeps the sections usable; code pages stay read+execute.
        uint32_t prot = PAGE_RW_;
        if (sec->Characteristics & SCN_EXECUTE_) prot = PAGE_RX_;
        // Uninitialised data stays writable: the loader keeps .bss writable,
        // and the payload writes its own statics after this call.
        else if ((sec->Characteristics & SCN_WRITE_) ||
                 (sec->Characteristics & SCN_UNINITIALIZED_DATA_)) prot = PAGE_RW_;
        if (!NT_SUCCESS(sys::protect(b + sec->VirtualAddress, size, prot))) {
            log::w(L"protect sec failed");
            ok = false;
        }
    }

    sys::protect(b, (nt->OptionalHeader.SizeOfHeaders + page - 1) & ~(page - 1), PAGE_R_);
    return ok;
}

// Launch marks go to the one channel measured to work in a mapped image: a
// rewritten 8-byte record in C:\Users\Public\fortesp_w.log. The log calls in
// here are the suspects, so they cannot be the instrument too.
bool hide::launch_worker(void* worker) {
    uintptr_t gadget = ret_gadget();
    if (!gadget) { log::w(L"no ret gadget"); return false; }
    log::w(L"worker: gadget ok");

    if (!NT_SUCCESS(sys::alloc(&g_stack, 0x8000, PAGE_RW_))) { log::w(L"stack alloc failed"); return false; }
    log::w(L"worker: stack ok");

    auto* top = reinterpret_cast<uint8_t*>(
        (reinterpret_cast<uintptr_t>(g_stack) + 0x7F00) & ~static_cast<uintptr_t>(0xF));
    top -= 8;                                  // RSP % 16 == 8 at function entry
    *reinterpret_cast<uintptr_t*>(top) = gadget;
    *reinterpret_cast<uintptr_t*>(top + 8) = 0;

    uint64_t handle = 0;
    // NtCreateThreadEx flags: 0x2 = THREAD_CREATE_FLAGS_SUSPENDED.
    // 0x1 is RUN_SYNCHRONOUS, which would let the thread run before the
    // context below is patched.
    // ProcessHandle is the pseudo handle of the current process (-1); 0 is
    // not a valid process handle and the call fails with it.
    NTSTATUS_ s = sc11(UPTR(&handle), 0x1FFFFF, 0, static_cast<uint64_t>(-1),
                       UPTR(worker), UPTR(top), 2 /* CREATE_SUSPENDED */, 0, 0, 0, 0,
                       sys::num("NtCreateThreadEx"));
    if (!NT_SUCCESS(s)) { log::w(L"create thread failed"); return false; }
    log::w(L"worker: created");

    // No handle laundering and no context patching: the thread was created
    // suspended with its start routine and argument already installed, so the
    // only thing left is to let it run. The previous version walked the process
    // handle table and re-wrote Rip/Rsp through a duplicate - and the thread
    // then died inside that window, before "handle dup done" was ever logged.
    // NtCreateThreadEx's own start context is what the loader does for the
    // entry thread as well.
    uint32_t prev = 0;
    NTSTATUS_ r = sys::resume(reinterpret_cast<void*>(handle), &prev);
    if (!NT_SUCCESS(r)) {
        log::w(L"worker: resume failed");
        sys::close(reinterpret_cast<void*>(handle));
        return false;
    }
    g_thread = reinterpret_cast<void*>(handle);
    log::w(L"worker laundered");
    return true;
}

void hide::stop_worker() {
    if (g_thread) { sys::close(g_thread); g_thread = nullptr; }
    if (g_stack) { sys::release(g_stack); g_stack = nullptr; }
}