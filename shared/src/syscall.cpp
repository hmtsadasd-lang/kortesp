#include "syscall.hpp"
#include "peb.hpp"
#include "hash.hpp"

namespace { uint8_t* g_nt{}; }

namespace sys {

uint32_t num(const char* name) {
    if (!g_nt) return 0;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER_*>(g_nt);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(g_nt + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[DIR_EXPORT_];
    if (!dir.VirtualAddress) return 0;

    auto* exp   = reinterpret_cast<IMAGE_EXPORT_DIRECTORY_*>(g_nt + dir.VirtualAddress);
    auto* names = reinterpret_cast<uint32_t*>(g_nt + exp->AddressOfNames);
    auto* funcs = reinterpret_cast<uint32_t*>(g_nt + exp->AddressOfFunctions);
    auto* ords  = reinterpret_cast<uint16_t*>(g_nt + exp->AddressOfNameOrdinals);

    uint32_t want = HH(name);
    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        if (h::fnv1a(reinterpret_cast<const char*>(g_nt + names[i])) != want) continue;
        uint8_t* stub = g_nt + funcs[ords[i]];
        for (int b = 0; b < 24; ++b)
            if (stub[b] == 0xB8) return *reinterpret_cast<uint32_t*>(stub + b + 1);
        return 0;
    }
    return 0;
}

bool init() {
    g_nt = static_cast<uint8_t*>(peb::module_base(HHW(L"ntdll.dll")));
    return g_nt && num("NtClose") != 0;
}

} // namespace sys