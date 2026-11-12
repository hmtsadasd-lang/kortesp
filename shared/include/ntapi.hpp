#pragma once
#include "nt.hpp"
#include "peb.hpp"
#include "hash.hpp"
#include "mem.hpp"
#include "syscall.hpp"

namespace ntapi {

inline void* k32(const char* fn) {
    void* k = peb::module_base(HHW(L"kernel32.dll"));
    return peb::export_proc(k, HH(fn));
}

inline void* u32(const char* fn) {
    void* u = peb::module_base(HHW(L"user32.dll"));
    return peb::export_proc(u, HH(fn));
}

inline void* LoadLibraryW_(const wchar_t* p) {
    using F = void*(__stdcall*)(const wchar_t*);
    return reinterpret_cast<F>(k32("LoadLibraryW"))(p);
}

inline void* GetProcAddress_(void* m, const char* n) {
    using F = void*(__stdcall*)(void*, const char*);
    return reinterpret_cast<F>(k32("GetProcAddress"))(m, n);
}

inline short GetAsyncKeyState_(int vk) {
    using F = short(__stdcall*)(int);
    return reinterpret_cast<F>(u32("GetAsyncKeyState"))(vk);
}

inline void* CreateWindowExW_(uint32_t ex, const wchar_t* cls, const wchar_t* name,
                              uint32_t style, int x, int y, int w, int h,
                              void* parent, void* menu, void* inst, void* param) {
    using F = void*(__stdcall*)(uint32_t, const wchar_t*, const wchar_t*, uint32_t,
                                int, int, int, int, void*, void*, void*, void*);
    return reinterpret_cast<F>(u32("CreateWindowExW"))(ex, cls, name, style, x, y, w, h,
                                                       parent, menu, inst, param);
}

inline uint16_t RegisterClassExW_(const void* wc) {
    using F = uint16_t(__stdcall*)(const void*);
    return reinterpret_cast<F>(u32("RegisterClassExW"))(wc);
}

inline int DestroyWindow_(void* w) {
    using F = int(__stdcall*)(void*);
    return reinterpret_cast<F>(u32("DestroyWindow"))(w);
}

inline int64_t DefWindowProcW_(void* w, uint32_t m, uint64_t a, int64_t b) {
    using F = int64_t(__stdcall*)(void*, uint32_t, uint64_t, int64_t);
    return reinterpret_cast<F>(u32("DefWindowProcW"))(w, m, a, b);
}

inline void* CreateFileW_(const wchar_t* p, uint32_t acc, uint32_t share, void* sa,
                          uint32_t disp, uint32_t flags, void* tpl) {
    using F = void*(__stdcall*)(const wchar_t*, uint32_t, uint32_t, void*, uint32_t, uint32_t, void*);
    return reinterpret_cast<F>(k32("CreateFileW"))(p, acc, share, sa, disp, flags, tpl);
}
inline uint32_t GetFileSize_(void* f) {
    using F = uint32_t(__stdcall*)(void*, uint32_t*);
    return reinterpret_cast<F>(k32("GetFileSize"))(f, nullptr);
}
inline int ReadFile_(void* f, void* b, uint32_t n, uint32_t* got, void* ov) {
    using F = int(__stdcall*)(void*, void*, uint32_t, uint32_t*, void*);
    return reinterpret_cast<F>(k32("ReadFile"))(f, b, n, got, ov);
}
inline int WriteFile_(void* f, const void* b, uint32_t n, uint32_t* put, void* ov) {
    using F = int(__stdcall*)(void*, const void*, uint32_t, uint32_t*, void*);
    return reinterpret_cast<F>(k32("WriteFile"))(f, b, n, put, ov);
}
inline int CloseHandle_(void* h) {
    using F = int(__stdcall*)(void*);
    return reinterpret_cast<F>(k32("CloseHandle"))(h);
}
inline uint32_t GetModuleFileNameW_(void* m, wchar_t* b, uint32_t n) {
    using F = uint32_t(__stdcall*)(void*, wchar_t*, uint32_t);
    return reinterpret_cast<F>(k32("GetModuleFileNameW"))(m, b, n);
}
inline uint32_t GetTempPathW_(uint32_t n, wchar_t* b) {
    using F = uint32_t(__stdcall*)(uint32_t, wchar_t*);
    return reinterpret_cast<F>(k32("GetTempPathW"))(n, b);
}
inline uint32_t pid_by_name_(const wchar_t* exe) {
    // host icinde toolhelp yok; SystemProcessInformation ile ara
    using QSI = NTSTATUS_(__stdcall*)(uint32_t, void*, uint32_t, uint32_t*);
    static auto q = reinterpret_cast<QSI>(peb::export_proc(peb::module_base(HHW(L"ntdll.dll")),
                                                          HH("NtQuerySystemInformation")));
    if (!q) return 0;

    uint32_t len = 1 << 20, ret = 0;
    void* buf = nullptr;
    if (!NT_SUCCESS(sys::alloc(&buf, len, PAGE_RW_))) return 0;

    // SYSTEM_PROCESS_INFORMATION (x64) up to UniqueProcessId
    struct SPI {
        uint32_t next;
        uint32_t threads;
        uint64_t working_set;
        uint32_t hardfault;
        uint32_t highwater;
        uint64_t cycle_time;
        int64_t  create_time, user_time, kernel_time;
        uint16_t len_name, max_name;
        uint32_t pad0;
        wchar_t* name;
        uint32_t base_priority;
        uint32_t pad1;
        void*    pid;
        void*    ppid;
    };
    uint32_t found = 0;

    for (int i = 0; i < 8; ++i) {
        if (NT_SUCCESS(q(5, buf, len, &ret))) {
            auto* e = static_cast<SPI*>(buf);
            for (int g = 0; g < 65536; ++g) {
                if (e->name && e->len_name) {
                    wchar_t nm[64]{};
                    uint32_t n = e->len_name < 126 ? e->len_name : 126;
                    auto* src = static_cast<const uint8_t*>(static_cast<const void*>(e->name));
                    for (uint32_t k = 0; k < n; ++k) reinterpret_cast<uint8_t*>(nm)[k] = src[k];

                    if (h::fnv1a_w(nm) == h::fnv1a_w(exe)) { found = static_cast<uint32_t>(UPTR(e->pid)); break; }
                }
                if (!e->next) break;
                e = reinterpret_cast<SPI*>(reinterpret_cast<uint8_t*>(e) + e->next);
            }
            break;
        }
        sys::release(buf);
        len *= 2;
        if (!NT_SUCCESS(sys::alloc(&buf, len, PAGE_RW_))) return 0;
    }
    sys::release(buf);
    return found;
}

} // namespace ntapi