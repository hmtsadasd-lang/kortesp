#include "vmm.hpp"
#include "r0.hpp"
#include <windows.h>
#include <cstring>

// --- TLB definitions matching the header ---
std::array<vmm::TlbEntry, vmm::kTlbSize> vmm::g_tlb{};
uint32_t                                    vmm::g_stamp = 1;

// --- Global state definitions (must match header exactly) ---
uint64_t  vmm::g_kcr3 = 0;
uint64_t  vmm::g_gcr3 = 0;
uint64_t  vmm::g_base = 0;
uint64_t  vmm::g_size = 0;
uint64_t  vmm::g_eprocess = 0;
uint32_t  vmm::g_pid = 0;
bool      vmm::g_ready = false;
bool      vmm::g_attached = false;

// Layout triples for EPROCESS field walks
vmm::Layout   vmm::g_lay{ 0x1D0, 0x1D8, 0x338, 0x28 };

// --- Helper: physical-page read via r0 backend ---
bool phys_read(uint64_t pa, void* buf) {
    return r0::pread(pa, buf, 8);
}

// --- CR3 translation: PML4 → PDPT → PDE → PT ---
bool translate_cr3(uint64_t cr3, uint64_t va, uint64_t& pa) {
    uint64_t page = va & ~0xFFFull;
    auto& e = vmm::g_tlb[(page >> 12) & (vmm::kTlbSize - 1)];
    if (e.page == page && e.stamp == vmm::g_stamp) {
        pa = e.phys + (va & 0xFFF);
        return true;
    }

    cr3 &= vmm::kPteMask;

    // PML4e
    uint64_t pml4e{};
    if (!phys_read(cr3 + 8 * ((va >> 39) & 0x1FF), &pml4e)) return false;
    if (!(pml4e & static_cast<uint64_t>(vmm::PteFlags::Present))) return false;
    uint64_t pdpt = pml4e & vmm::kPteMask;

    // PDPTE
    uint64_t pdpte{};
    if (!phys_read(pdpt + 8 * ((va >> 30) & 0x1FF), &pdpte)) return false;
    if (!(pdpte & static_cast<uint64_t>(vmm::PteFlags::Present))) return false;

    // 1 GB large page?
    {
        uint64_t large_page_phys = (pdpte & 0x000FFFFFC0000000ull) + (va & 0x3FFFFFFFull);
        e.page = page; e.phys = large_page_phys & ~0xFFFull; e.stamp = vmm::g_stamp;
        pa = large_page_phys;
        return true;
    }

    // PDE
    uint64_t pd = pdpte & vmm::kPteMask;
    uint64_t pde{};
    if (!phys_read(pd + 8 * ((va >> 21) & 0x1FF), &pde)) return false;
    if (!(pde & static_cast<uint64_t>(vmm::PteFlags::Present))) return false;

    // PT
    uint64_t pt = pd & vmm::kPteMask;
    uint64_t pte{};
    if (!phys_read(pt + 8 * ((va >> 12) & 0x1FF), &pte)) return false;
    if (!(pte & static_cast<uint64_t>(vmm::PteFlags::Present))) return false;

    pa = (pte & vmm::kPteMask) + (va & 0xFFF);
    e.page = page; e.phys = pa & ~0xFFFull; e.stamp = vmm::g_stamp;
    return true;
}

// --- ntoskrnl reachability probe ---
bool ntoskrnl_from_user() {
    ULONG need = 0;
    auto q = reinterpret_cast<LONG(__stdcall*)(ULONG, void*, ULONG, ULONG*)>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!q) return false;
    q(11, nullptr, 0, &need);
    return need != 0;
}

// --- init: just probe that the kernel information class is reachable ---
bool vmm::init() {
    if (!ntoskrnl_from_user()) return false;
    g_ready = false;
    return true;
}

void vmm::shutdown() {
    g_ready = false; g_gcr3 = 0; g_eprocess = 0; g_pid = 0;
    g_base = 0; g_size = 0;
    ++g_stamp;
    r0::shutdown();
}

// --- attach: find process by image name, map its CR3 ---
bool vmm::attach(const wchar_t* image_name) {
    if (!g_eprocess) return false;

    char want[256]{};
    for (int i = 0; i < 255 && image_name[i]; ++i)
        want[i] = static_cast<char>(image_name[i] > 0x7F ? '?' : image_name[i]);

    uint64_t cur = g_eprocess;
    for (int guard = 0; guard < 4096; ++guard) {
        uint64_t flink{};
        if (!kread(cur + g_lay.links, &flink, 8) || !flink) break;
        cur = flink - g_lay.links;

        uint64_t pid{}; char name[256]{};
        if (!kread(cur + g_lay.pid, &pid, 8)) break;
        if (!kread(cur + g_lay.name, name, sizeof(name))) break;

        if (::_stricmp(name, want) != 0) continue;

        uint64_t dtb{};
        if (!kread(cur + g_lay.dtb, &dtb, 8)) return false;

        g_gcr3 = dtb & kPteMask;
        g_eprocess = cur;
        g_pid  = static_cast<uint32_t>(pid);
        g_ready = true;
        ++g_stamp;
        return true;
    }
    return false;
}

void vmm::detach() {
    g_ready = false; g_gcr3 = 0; ++g_stamp;
}

bool vmm::attached() { return g_ready; }
uint32_t  vmm::pid()      { return g_pid; }
uint64_t  vmm::base()     { return g_base; }
uint64_t  vmm::size()     { return g_size; }
void      vmm::set_base(uint64_t b, uint64_t s) { g_base = b; g_size = s; }

// kread / kwrite – kernel‑space reads (System CR3).
bool vmm::kread(uint64_t va, void* buf, size_t len) {
    auto* p = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        if (!translate_cr3(g_kcr3, va + i, pa)) return false;
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        if (!phys_read(pa, p + i)) return false;
        i += n;
    }
    return true;
}

bool vmm::kwrite(uint64_t va, const void* buf, size_t len) {
    auto* p = static_cast<const uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        if (!translate_cr3(g_kcr3, va + i, pa)) return false;
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        // phys_read expects void*, so cast away const
        if (!phys_read(pa, const_cast<void*>(reinterpret_cast<const void*>(p + i)))) return false;
        i += n;
    }
    return true;
}

// read / write – target‑space reads (target CR3).
bool vmm::read(uint64_t va, void* buf, size_t len) {
    if (!g_ready || va < kUserLo || va > kUserHi) return false;
    auto* p = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        if (!translate_cr3(g_gcr3, va + i, pa)) return false;
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        if (!phys_read(pa, p + i)) return false;
        i += n;
    }
    return true;
}

bool vmm::write(uint64_t va, const void* buf, size_t len) {
    if (!g_ready || va < kUserLo || va > kUserHi) return false;
    auto* p = static_cast<const uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        if (!translate_cr3(g_gcr3, va + i, pa)) return false;
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        if (!phys_read(pa, const_cast<void*>(reinterpret_cast<const void*>(p + i)))) return false;
        i += n;
    }
    return true;
}

bool vmm::present(uint64_t va) {
    uint64_t pa{};
    return g_ready && translate_cr3(g_gcr3, va, pa);
}