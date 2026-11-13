#pragma once
#include <intrin.h>
#include "nt.hpp"
#include "hash.hpp"

namespace peb {

inline PEB_* self() {
    return reinterpret_cast<PEB_*>(__readgsqword(0x60));
}

// FLAG ON FAILURE: the module walk used to fail silently (return nullptr),
// and a caller cannot tell "ntdll is not loaded" from "the PEB was read at the
// wrong offset". In a manually mapped image this walk is the only way to reach
// an API, so a silent nullptr hides the bug that kills the payload. The host
// reads this counter out of the mapped data section and the payload reports it
// itself; see docs/SESSION_NOTES.md.
inline volatile uint32_t g_module_walk_miss = 0;

// Loader-list iteration, for callers that need to inspect every module (a
// hash cannot answer "which module is the client", only "is this name here").
inline LDR_DATA_TABLE_ENTRY_* first_module() {
    PEB_* p = self();
    if (!p || !p->Ldr) return nullptr;
    auto* head = reinterpret_cast<uint8_t*>(p->Ldr) + 0x10;
    auto* cur  = *reinterpret_cast<uint8_t**>(head);
    return (cur && cur != head) ? reinterpret_cast<LDR_DATA_TABLE_ENTRY_*>(cur) : nullptr;
}

inline LDR_DATA_TABLE_ENTRY_* next_module(LDR_DATA_TABLE_ENTRY_* e) {
    if (!e) return nullptr;
    PEB_* p = self();
    if (!p || !p->Ldr) return nullptr;
    auto* head = reinterpret_cast<uint8_t*>(p->Ldr) + 0x10;
    auto* cur  = *reinterpret_cast<uint8_t**>(reinterpret_cast<uint8_t*>(e));
    return (cur && cur != head) ? reinterpret_cast<LDR_DATA_TABLE_ENTRY_*>(cur) : nullptr;
}

inline void* module_base(uint32_t name_hash) {
    PEB_* p = self();
    if (!p || !p->Ldr) { ++g_module_walk_miss; return nullptr; }

    auto* head = reinterpret_cast<uint8_t*>(p->Ldr) + 0x10;
    auto* cur  = *reinterpret_cast<uint8_t**>(head);

    for (int guard = 0; cur && cur != head && guard < 512; ++guard) {
        auto* e = reinterpret_cast<LDR_DATA_TABLE_ENTRY_*>(cur);
        if (e->BaseDllName.Buffer && h::fnv1a_w(e->BaseDllName.Buffer) == name_hash) return e->DllBase;
        cur = *reinterpret_cast<uint8_t**>(cur);
    }
    ++g_module_walk_miss;
    return nullptr;
}

inline void* export_proc(void* mod, uint32_t fn_hash) {
    auto* base = static_cast<uint8_t*>(mod);
    if (!base) return nullptr;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER_*>(base);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(base + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[DIR_EXPORT_];
    if (!dir.VirtualAddress) return nullptr;

    auto* exp   = reinterpret_cast<IMAGE_EXPORT_DIRECTORY_*>(base + dir.VirtualAddress);
    auto* names = reinterpret_cast<uint32_t*>(base + exp->AddressOfNames);
    auto* funcs = reinterpret_cast<uint32_t*>(base + exp->AddressOfFunctions);
    auto* ords  = reinterpret_cast<uint16_t*>(base + exp->AddressOfNameOrdinals);

    for (uint32_t i = 0; i < exp->NumberOfNames; ++i)
        if (h::fnv1a(reinterpret_cast<const char*>(base + names[i])) == fn_hash)
            return base + funcs[ords[i]];
    return nullptr;
}

} // namespace peb