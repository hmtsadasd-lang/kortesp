#include "vmm.hpp"
#include "r0.hpp"
#include <windows.h>
#include <cstring>
#include <cstdio>
#include <vector>

// --- TLB definitions matching the header ---
std::array<vmm::TlbEntry, vmm::kTlbSize> vmm::g_tlb{};
uint32_t                                    vmm::g_stamp = 1;

// --- Global state definitions (must match header exactly) ---
uint64_t  vmm::g_kcr3 = 0;
uint64_t  vmm::g_gcr3 = 0;
uint64_t  vmm::g_base = 0;
uint64_t  vmm::g_size = 0;
uint64_t  vmm::g_eprocess = 0;
uint64_t  vmm::g_ntos = 0;
uint64_t  vmm::g_ntos_size = 0;
uint32_t  vmm::g_pid = 0;
bool      vmm::g_ready = false;
bool      vmm::g_attached = false;

// EPROCESS layout candidates, most likely first.
// { pid, links, name, dtb, peb }
vmm::Layout   vmm::g_lay{ 0x1D0, 0x98, 0x338, 0x28, 0x38 };

// --- Helper: physical read via r0 backend (length-aware) ---
//
// Every physical read goes through the driver's MmMapIoSpace path. Reading a
// physical address that is not backed by RAM (a reserved hole, or anything
// above installed RAM) faults in kernel mode and bugchecks the machine, so
// every read is bounds-checked against the physical RAM size first.
uint64_t phys_ram_end() {
    static uint64_t end = 0;
    if (!end) {
        MEMORYSTATUSEX ms{ sizeof(ms) };
        if (!GlobalMemoryStatusEx(&ms)) end = 0x100000000ull;  // 4 GB fallback
        else end = static_cast<uint64_t>(ms.ullTotalPhys);
    }
    return end;
}

bool phys_read(uint64_t pa, void* buf, size_t len) {
    if (!len) return false;
    if (pa + len > phys_ram_end()) return false;
    if (pa + len < pa) return false;          // overflow
    return r0::pread(pa, buf, len);
}

// --- CR3 translation: PML4 -> PDPT -> PDE -> PT ---
bool translate_cr3(uint64_t cr3, uint64_t va, uint64_t& pa) {
    uint64_t page = va & ~0xFFFull;
    auto& e = vmm::g_tlb[(page >> 12) & (vmm::kTlbSize - 1)];
    if (e.page == page && e.cr3 == cr3 && e.stamp == vmm::g_stamp) {
        pa = e.phys + (va & 0xFFF);
        return true;
    }

    cr3 &= vmm::kPteMask;

    // PML4e
    uint64_t pml4e{};
    if (!phys_read(cr3 + 8 * ((va >> 39) & 0x1FF), &pml4e, 8)) return false;
    if (!(pml4e & static_cast<uint64_t>(vmm::PteFlags::Present))) return false;
    uint64_t pdpt = pml4e & vmm::kPteMask;

    // PDPTE
    uint64_t pdpte{};
    if (!phys_read(pdpt + 8 * ((va >> 30) & 0x1FF), &pdpte, 8)) return false;
    if (!(pdpte & static_cast<uint64_t>(vmm::PteFlags::Present))) return false;

    // 1 GB large page? (bit 7 set in the PDPTE)
    if (pdpte & 0x80) {
        uint64_t lp = (pdpte & 0x000FFFFFC0000000ull) + (va & 0x3FFFFFFFull);
        e.page = page; e.cr3 = cr3; e.phys = lp & ~0xFFFull; e.stamp = vmm::g_stamp;
        pa = lp;
        return true;
    }

    // PDE
    uint64_t pd = pdpte & vmm::kPteMask;
    uint64_t pde{};
    if (!phys_read(pd + 8 * ((va >> 21) & 0x1FF), &pde, 8)) return false;
    if (!(pde & static_cast<uint64_t>(vmm::PteFlags::Present))) return false;

    // 2 MB large page? (bit 7 set in the PDE)
    if (pde & 0x80) {
        uint64_t lp = (pde & 0x000FFFFFFFE00000ull) + (va & 0x1FFFFFull);
        e.page = page; e.cr3 = cr3; e.phys = lp & ~0xFFFull; e.stamp = vmm::g_stamp;
        pa = lp;
        return true;
    }

    // PT
    uint64_t pt = pd & vmm::kPteMask;
    uint64_t pte{};
    if (!phys_read(pt + 8 * ((va >> 12) & 0x1FF), &pte, 8)) return false;
    if (!(pte & static_cast<uint64_t>(vmm::PteFlags::Present))) return false;

    uint64_t leaf = (pte & vmm::kPteMask) + (va & 0xFFF);
    e.page = page; e.cr3 = cr3; e.phys = leaf & ~0xFFFull; e.stamp = vmm::g_stamp;
    pa = leaf;
    return true;
}

// ---------------------------------------------------------------------------
// ntoskrnl base
//
// NtQuerySystemInformation(SystemModuleInformation) is a *kernel* module
// list, so ntoskrnl is in it (the game client is not - that comes from the
// target's PEB instead).
//
// The entry layout on this build is the 296-byte SYSTEM_MODULE:
//
//   +0x00 Section      ULONG_PTR
//   +0x08 MappedBase   ULONG_PTR
//   +0x10 ImageBase    ULONG_PTR
//   +0x18 ImageSize    ULONG        <- 32-bit, not 64
//   +0x1C Flags        ULONG
//   +0x20 LoadCount    USHORT
//   +0x22 TlsIndex     USHORT
//   +0x24 HashId       ULONG
//   +0x28 ModuleName[256]
//
// The header is an 8-byte count. The stride is derived from the buffer size
// so it does not have to be hardcoded.
//
// NOTE: ImageBase is only populated for elevated callers. Unelevated, the
// kernel redacts it and the value reads as 0 - so this must run elevated.
// ---------------------------------------------------------------------------
bool find_ntoskrnl(uint64_t& base, uint64_t& size) {
    auto q = reinterpret_cast<LONG(__stdcall*)(ULONG, void*, ULONG, ULONG*)>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!q) return false;

    ULONG need = 0;
    q(11, nullptr, 0, &need);
    if (!need) return false;

    std::vector<uint8_t> buf(need);
    ULONG got = need;
    if (q(11, buf.data(), need, &got) != 0) return false;

    const uint32_t count = *(uint32_t*)buf.data();
    if (!count || count > 4096) return false;

    const size_t header = 8;
    if (buf.size() <= header) return false;

    size_t stride = (buf.size() - header) / count;
    if (!stride || stride < 0x28) { stride = 296; }

    for (uint32_t i = 0; i < count; ++i) {
        const size_t off = header + (size_t)i * stride;
        if (off + 0x30 > buf.size()) break;

        const char* name = reinterpret_cast<const char*>(&buf[off + 0x28]);
        // The field holds the full path, e.g. "\SystemRoot\system32\ntoskrnl.exe".
        // Match on the suffix so the directory prefix does not matter.
        static const char want[] = "ntoskrnl.exe";
        const size_t wl = sizeof(want) - 1;
        size_t nl = 0;
        while (nl < 256 && name[nl]) ++nl;
        if (nl < wl) continue;
        if (_strnicmp(name + nl - wl, want, wl) != 0) continue;

        uint64_t ib{}, isz{};
        memcpy(&ib,  &buf[off + 0x10], 8);
        memcpy(&isz, &buf[off + 0x18], 4);   // 32-bit ImageSize

        if (ib < 0xFFFF000000000000ull) continue;
        if (isz == 0 || isz > 0x10000000ull) continue;

        base = ib;
        size = isz;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Kernel CR3: scan physical memory for a CR3 whose kernel half maps ntoskrnl.
// ---------------------------------------------------------------------------
bool find_kernel_cr3(uint64_t& out) {
    // The CR3 and all of its page tables live in installed RAM. Do not scan
    // past it - above RAM is the PCI hole and mapping it would fault.
    const uint64_t top = phys_ram_end();

    for (uint64_t pa = 0x1000; pa < top; pa += 0x1000) {
        uint64_t e{};
        if (!phys_read(pa, &e, 8)) continue;
        if (!(e & static_cast<uint64_t>(vmm::PteFlags::Present))) continue;

        const uint64_t target = e & vmm::kPteMask;
        if (target < 0x1000 || target >= top) continue;

        uint64_t probe{};
        if (!translate_cr3(pa, vmm::g_ntos, probe)) continue;
        if (probe >= top) continue;

        uint16_t mz{};
        if (!phys_read(probe & ~0xFFFull, &mz, 2)) continue;
        if (mz == 0x5A4D) { out = pa; return true; }
    }
    return false;
}

// ---------------------------------------------------------------------------
// System EPROCESS: scan ntoskrnl's writable sections for a pointer that
// validates as the System process (pid 4, name "System").
// ---------------------------------------------------------------------------
bool looks_eprocess(uint64_t p, const vmm::Layout& l) {
    if (p < 0xFFFF800000000000ull || (p & 7)) return false;
    uint64_t pid{};
    char name[16]{};
    if (!vmm::kread(p + l.pid, &pid, 8)) return false;
    if (pid != 4) return false;
    if (!vmm::kread(p + l.name, name, sizeof(name))) return false;
    return memcmp(name, "System", 7) == 0;
}

bool find_system_eprocess() {
    static const vmm::Layout kCand[] = {
        { 0x1D0, 0x98, 0x338, 0x28, 0x38 },   // Win11 24H2 / 25H2 (build 26200)
        { 0x440, 0x98, 0x5A8, 0x28, 0x38 },   // Win10 22H2 / 11 23H2
        { 0x440, 0x98, 0x5A8, 0x20, 0x38 },
        { 0x2E8, 0x98, 0x450, 0x28, 0x38 },   // Win10 1903 - 21H2
    };

    // Read the PE headers so we only scan writable data sections.
    IMAGE_DOS_HEADER dos{};
    if (!vmm::kread(vmm::g_ntos, &dos, sizeof(dos)) || dos.e_magic != 0x5A4D) return false;
    IMAGE_NT_HEADERS64 nt{};
    if (!vmm::kread(vmm::g_ntos + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != 0x4550) return false;

    auto* sec = IMAGE_FIRST_SECTION(&nt);
    for (unsigned s = 0; s < nt.FileHeader.NumberOfSections; ++s, ++sec) {
        const DWORD ch = sec->Characteristics;
        if (!(ch & IMAGE_SCN_MEM_WRITE)) continue;
        if (!sec->Misc.VirtualSize) continue;

        const uint64_t lo = vmm::g_ntos + sec->VirtualAddress;
        const uint64_t hi = lo + sec->Misc.VirtualSize;

        for (uint64_t a = (lo + 7) & ~7ull; a + 8 < hi; a += 8) {
            uint64_t cand{};
            if (!vmm::kread(a, &cand, 8)) continue;
            for (const auto& l : kCand) {
                if (!looks_eprocess(cand, l)) continue;
                vmm::g_lay = l;
                vmm::g_eprocess = cand;
                return true;
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// vmm API
// ---------------------------------------------------------------------------
bool vmm::init() {
    if (g_ready) return true;

    if (!find_ntoskrnl(g_ntos, g_ntos_size)) {
        printf("[!] ntoskrnl base not found in SystemModuleInformation\n");
        return false;
    }
    printf("[+] ntoskrnl base 0x%llx size 0x%llx\n",
           (unsigned long long)g_ntos, (unsigned long long)g_ntos_size);

    if (!find_kernel_cr3(g_kcr3)) {
        printf("[!] no CR3 maps ntoskrnl (kernel CR3 scan failed)\n");
        return false;
    }
    printf("[+] kernel CR3 0x%llx\n", (unsigned long long)g_kcr3);

    if (!find_system_eprocess()) {
        printf("[!] System EPROCESS not found\n");
        return false;
    }
    printf("[+] System EPROCESS 0x%llx\n", (unsigned long long)g_eprocess);

    return true;
}

void vmm::shutdown() {
    g_ready = false; g_gcr3 = 0; g_eprocess = 0; g_pid = 0;
    g_base = 0; g_size = 0;
    ++g_stamp;
    r0::shutdown();
}

// attach: find the process by image name and map its CR3
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

// kread / kwrite - kernel-space reads (System CR3).
bool vmm::kread(uint64_t va, void* buf, size_t len) {
    auto* p = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        if (!translate_cr3(g_kcr3, va + i, pa)) return false;
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        if (!phys_read(pa, p + i, n)) return false;
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
        if (!r0::pwrite(pa, p + i, n)) return false;
        i += n;
    }
    return true;
}

// read / write - target-space reads (target CR3).
bool vmm::read(uint64_t va, void* buf, size_t len) {
    if (!g_ready || va < kUserLo || va > kUserHi) return false;
    auto* p = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        if (!translate_cr3(g_gcr3, va + i, pa)) return false;
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        if (!phys_read(pa, p + i, n)) return false;
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
        if (!r0::pwrite(pa, p + i, n)) return false;
        i += n;
    }
    return true;
}

bool vmm::present(uint64_t va) {
    uint64_t pa{};
    return g_ready && translate_cr3(g_gcr3, va, pa);
}