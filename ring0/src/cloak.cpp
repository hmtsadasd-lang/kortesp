#include "cloak.hpp"
#include "vmm.hpp"
#include <windows.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>

namespace {

constexpr uint64_t kKvaLo = 0xFFFF800000000000ull;
constexpr uint64_t kLde_DllBase  = 0x30;
constexpr uint64_t kLde_BaseName = 0x58;

uint64_t g_head{};
uint64_t g_entry{};
uint64_t g_prev{};
uint64_t g_next{};
uint64_t g_our_base{};
bool     g_on{};

// The image the driver was loaded under. Defaults to the stock name; the
// runner overrides it when it installs the driver under a random name.
const char* driver_image() {
    const char* e = getenv("FORTESP_DRIVER_IMAGE");
    if (e && *e) return e;
    return "dbutil_2_3.sys";
}

// ---- the module's own base, straight from the kernel module list ----------
// Name-suffix match, so a renamed image still resolves as long as the caller
// tells us what it was renamed to. Returns 0 if the driver is not loaded,
// which is the only case where cloak can legitimately do nothing.
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

        const char* want = driver_image();
        const size_t wl = strlen(want);

        auto* l = static_cast<L*>(buf);
        for (uint32_t i = 0; i < l->count && i < 512; ++i) {
            const char* p = reinterpret_cast<const char*>(l->e[i].path);
            const size_t len = strlen(p);
            if (len < wl) continue;

            bool same = true;
            for (size_t k = 0; k < wl; ++k) {
                char a = p[len - wl + k], b = want[k];
                if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + 32);
                if (b >= 'A' && b <= 'Z') b = static_cast<char>(b + 32);
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
    if (vmm::export_rva("PsLoadedModuleList", rva)) {
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
    if (!g_our_base) {
        printf("[cloak] driver module \"%s\" not found in the kernel module list\n",
               driver_image());
        return false;
    }

    if (!find_head(g_head)) return false;

    uint64_t cur{};
    if (!vmm::kread(g_head, &cur, 8) || !cur) return false;

    for (int guard = 0; guard < 512 && cur != g_head; ++guard) {
        const uint64_t entry = cur;

        uint64_t base{};
        if (vmm::kread(entry + kLde_DllBase, &base, 8) && base == g_our_base) {
            // KLDR_DATA_TABLE_ENTRY has exactly ONE list: InLoadOrderLinks at
            // +0x00. There is no InMemoryOrderLinks - that belongs to the
            // USER-MODE LDR_DATA_TABLE_ENTRY. Unlinking a "memory order"
            // link here would write into ExceptionTable/ExceptionTableSize
            // (+0x10/+0x18) and bugcheck the machine.
            uint64_t next{}, prev{};
            if (!vmm::kread(entry + 0x00, &next, 8)) return false;
            if (!vmm::kread(entry + 0x08, &prev, 8)) return false;

            // The neighbours must be kernel addresses. A wrong list head
            // would otherwise have us write the entry pointer into an
            // arbitrary kernel address.
            if (prev < kKvaLo || next < kKvaLo) return false;

            g_entry = entry;
            g_prev = prev;
            g_next = next;

            g_plan.head      = g_head;
            g_plan.entry     = entry;
            g_plan.load_prev = prev;
            g_plan.load_next = next;
            g_plan.dll_base  = base;
            g_plan.found     = true;

            if (!commit) {
                printf("[cloak] DRY RUN - nothing written.\n");
                printf("[cloak]   PsLoadedModuleList head : 0x%llx\n", (unsigned long long)g_head);
                printf("[cloak]   our KLDR entry          : 0x%llx\n", (unsigned long long)entry);
                printf("[cloak]   DllBase                 : 0x%llx\n", (unsigned long long)base);
                printf("[cloak]   prev / next             : 0x%llx / 0x%llx\n",
                       (unsigned long long)prev, (unsigned long long)next);
                printf("[cloak]   would write 0x%llx <- 0x%llx   (prev.Flink = next)\n",
                       (unsigned long long)prev, (unsigned long long)next);
                printf("[cloak]   would write 0x%llx <- 0x%llx   (next.Blink = prev)\n",
                       (unsigned long long)next + 8, (unsigned long long)prev);
                printf("[cloak] re-run with --cloak-commit to actually unlink.\n");
                return true;
            }

            // ---- the only kernel writes in the whole tool ----
            // Two writes. The kernel-VA path (memmove on the cached mapping),
            // not the physical one - MmMapIoSpace(MmNonCached) would leave
            // stale lines in the cores that are reading this list.
            if (!vmm::kwrite(prev, &next, 8)) return false;   // prev.Flink = next
            if (!vmm::kwrite(next + 8, &prev, 8)) return false; // next.Blink = prev

            g_on = true;
            return true;
        }

        if (!vmm::kread(cur, &cur, 8) || !cur) return false;
    }
    return false;
}

void restore() {
    if (!g_on) return;
    vmm::kwrite(g_prev, &g_entry, 8);       // prev.Flink = entry
    vmm::kwrite(g_next + 8, &g_entry, 8);   // next.Blink = entry
    g_on = false;
}

} // namespace cloak