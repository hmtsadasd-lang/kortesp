#include "cloak.hpp"
#include "vmm.hpp"
#include <windows.h>
#include <cstring>
#include <cstdio>

namespace {

constexpr uint64_t kKvaLo = 0xFFFF800000000000ull;
constexpr uint64_t kLde_DllBase  = 0x30;
constexpr uint64_t kLde_BaseName = 0x58;

uint64_t g_head{};
uint64_t g_entry{};
uint64_t g_p1{}, g_n1{};   // InLoadOrderLinks  .Blink / .Flink
uint64_t g_p2{}, g_n2{};   // InMemoryOrderLinks.Blink / .Flink
uint64_t g_our_base{};
bool     g_on{};

// ---- the module's own base, straight from the kernel module list ----------
// Name-suffix match, so a renamed image still resolves. Returns 0 if the
// driver is not loaded, which is the only case where cloak can legitimately
// do nothing.
uint64_t our_base() {
    HMODULE n = GetModuleHandleW(L"ntdll.dll");
    if (!n) return 0;
    using Q = LONG(__stdcall*)(ULONG, void*, ULONG, ULONG*);
    auto q = reinterpret_cast<Q>(GetProcAddress(n, "NtQuerySystemInformation"));
    if (!q) return 0;

    ULONG need = 0;
    q(11, nullptr, 0, &need);
    if (!need) return 0;

    void* buf = VirtualAlloc(nullptr, need, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 0;

    uint64_t base = 0;
    if (q(11, buf, need, &need) == 0) {
        struct E {
            uint64_t section, mapped, image_base, image_size;
            uint32_t flags;
            uint16_t a, b, c, d;
            uint8_t path[256];
        };
        struct L { uint32_t count; uint32_t pad; E e[1]; };

        auto* l = static_cast<L*>(buf);
        for (uint32_t i = 0; i < l->count && i < 512; ++i) {
            const char* p = reinterpret_cast<const char*>(l->e[i].path);
            const size_t len = strlen(p);
            const char* want = "dbutil_2_3.sys";
            const size_t wl = strlen(want);
            if (len < wl) continue;

            bool same = true;
            for (size_t k = 0; k < wl; ++k) {
                char a = p[len - wl + k], b = want[k];
                if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + 32);
                if (a != b) { same = false; break; }
            }
            if (same) { base = l->e[i].image_base; break; }
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    return base;
}

// ---- locating PsLoadedModuleList -----------------------------------------
// It is not exported on 26200 any more, so the export is only a fast path.
// The fallback scans ntoskrnl's writable, non-executable sections for a
// LIST_ENTRY whose first entry validates as a real module.
bool export_rva(const char* want, uint64_t& rva) {
    IMAGE_DOS_HEADER dos{};
    if (!vmm::kread(vmm::g_ntos, &dos, sizeof(dos)) || dos.e_magic != 0x5A4D) return false;

    IMAGE_NT_HEADERS64 nt{};
    if (!vmm::kread(vmm::g_ntos + dos.e_lfanew, &nt, sizeof(nt))) return false;
    if (nt.Signature != 0x4550) return false;

    const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return false;

    IMAGE_EXPORT_DIRECTORY ed{};
    if (!vmm::kread(vmm::g_ntos + dir.VirtualAddress, &ed, sizeof(ed))) return false;

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

bool valid_head(uint64_t h) {
    uint64_t f{};
    if (!vmm::kread(h, &f, 8)) return false;
    if (f < kKvaLo || (f & 0xF) || f == h) return false;

    uint64_t b{};
    if (!vmm::kread(f + 8, &b, 8) || b != h) return false;

    uint64_t base{};
    if (!vmm::kread(f + kLde_DllBase, &base, 8) || base < 0x10000) return false;
    uint16_t mz{};
    if (!vmm::kread(base, &mz, 2) || mz != 0x5A4D) return false;

    uint64_t nb{};
    uint16_t nl{};
    if (!vmm::kread(f + kLde_BaseName + 8, &nb, 8) || nb < kKvaLo) return false;
    if (!vmm::kread(f + kLde_BaseName, &nl, 2) || nl < 4 || nl > 256) return false;

    return true;
}

bool find_head(uint64_t& head) {
    uint64_t rva{};
    if (export_rva("PsLoadedModuleList", rva)) {
        head = vmm::g_ntos + rva;
        if (valid_head(head)) return true;
    }

    IMAGE_DOS_HEADER dos{};
    if (!vmm::kread(vmm::g_ntos, &dos, sizeof(dos))) return false;
    IMAGE_NT_HEADERS64 nt{};
    if (!vmm::kread(vmm::g_ntos + dos.e_lfanew, &nt, sizeof(nt))) return false;

    auto* sec = IMAGE_FIRST_SECTION(&nt);
    for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i, ++sec) {
        const DWORD ch = sec->Characteristics;
        if (!(ch & IMAGE_SCN_MEM_WRITE) || (ch & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (!sec->Misc.VirtualSize) continue;

        const uint64_t lo = vmm::g_ntos + sec->VirtualAddress;
        const uint64_t hi = lo + sec->Misc.VirtualSize;
        for (uint64_t a = (lo + 7) & ~7ull; a + 8 < hi; a += 8) {
            if (!valid_head(a)) continue;
            head = a;
            return true;
        }
    }
    return false;
}

} // namespace

namespace cloak {

Plan g_plan{};

const Plan& plan() { return g_plan; }
bool active() { return g_on; }

bool apply(bool commit) {
    if (g_on) return true;

    g_plan = Plan{};

    g_our_base = our_base();
    if (!g_our_base) return false;

    if (!find_head(g_head)) return false;

    uint64_t cur{};
    if (!vmm::kread(g_head, &cur, 8) || !cur) return false;

    for (int guard = 0; guard < 512 && cur != g_head; ++guard) {
        const uint64_t entry = cur;

        uint64_t base{};
        if (vmm::kread(entry + kLde_DllBase, &base, 8) && base == g_our_base) {
            uint64_t ln{}, lp{}, mn{}, mp{};
            if (!vmm::kread(entry + 0x00, &ln, 8)) return false;   // load .Flink
            if (!vmm::kread(entry + 0x08, &lp, 8)) return false;   // load .Blink
            if (!vmm::kread(entry + 0x10, &mn, 8)) return false;   // mem  .Flink
            if (!vmm::kread(entry + 0x18, &mp, 8)) return false;   // mem  .Blink

            // Sanity: the neighbours must be kernel addresses. A wrong list
            // head would otherwise have us write the entry pointer into an
            // arbitrary kernel address.
            if (lp < kKvaLo || ln < kKvaLo || mp < kKvaLo || mn < kKvaLo) return false;

            g_entry = entry;
            g_p1 = lp; g_n1 = ln;
            g_p2 = mp; g_n2 = mn;

            g_plan.head      = g_head;
            g_plan.entry     = entry;
            g_plan.load_prev = lp;
            g_plan.load_next = ln;
            g_plan.mem_prev  = mp;
            g_plan.mem_next  = mn;
            g_plan.dll_base  = base;
            g_plan.found     = true;

            if (!commit) {
                printf("[cloak] DRY RUN - nothing written.\n");
                printf("[cloak]   PsLoadedModuleList head : 0x%llx\n", (unsigned long long)g_head);
                printf("[cloak]   our KLDR entry          : 0x%llx\n", (unsigned long long)entry);
                printf("[cloak]   DllBase                 : 0x%llx\n", (unsigned long long)base);
                printf("[cloak]   InLoadOrder  prev/next  : 0x%llx / 0x%llx\n",
                       (unsigned long long)lp, (unsigned long long)ln);
                printf("[cloak]   InMemoryOrder prev/next  : 0x%llx / 0x%llx\n",
                       (unsigned long long)mp, (unsigned long long)mn);
                printf("[cloak]   write 0x%llx <- 0x%llx   (load prev.Flink)\n",
                       (unsigned long long)lp, (unsigned long long)ln);
                printf("[cloak]   write 0x%llx <- 0x%llx   (load next.Blink)\n",
                       (unsigned long long)ln + 8, (unsigned long long)lp);
                printf("[cloak]   write 0x%llx <- 0x%llx   (mem prev.Flink)\n",
                       (unsigned long long)mp, (unsigned long long)mn);
                printf("[cloak]   write 0x%llx <- 0x%llx   (mem next.Blink)\n",
                       (unsigned long long)mn + 8, (unsigned long long)mp);
                printf("[cloak] re-run with --cloak-commit to actually unlink.\n");
                return true;
            }

            // ---- the only kernel writes in the whole tool ----
            // Unlink from BOTH lists: SystemModuleInformation walks
            // InLoadOrderLinks, but an anti-cheat that walks
            // InMemoryOrderLinks would otherwise still see the driver.
            if (!vmm::kwrite(lp,     &ln, 8)) return false;   // load prev.Flink = next
            if (!vmm::kwrite(ln + 8, &lp, 8)) return false;   // load next.Blink = prev
            if (!vmm::kwrite(mp,     &mn, 8)) return false;   // mem  prev.Flink = next
            if (!vmm::kwrite(mn + 8, &mp, 8)) return false;   // mem  next.Blink = prev

            g_on = true;
            return true;
        }

        if (!vmm::kread(cur, &cur, 8) || !cur) return false;
    }
    return false;
}

void restore() {
    if (!g_on) return;
    vmm::kwrite(g_p1, &g_entry, 8);      // load prev.Flink = entry
    vmm::kwrite(g_n1 + 8, &g_entry, 8);   // load next.Blink = entry
    vmm::kwrite(g_p2, &g_entry, 8);       // mem  prev.Flink = entry
    vmm::kwrite(g_n2 + 8, &g_entry, 8);   // mem  next.Blink = entry
    g_on = false;
}

} // namespace cloak