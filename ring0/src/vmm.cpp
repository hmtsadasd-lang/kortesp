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
// { pid, links, name, dtb, peb } - Win11 24H2/25H2.
vmm::Layout   vmm::g_lay{ 0x1D0, 0x1D8, 0x338, 0x28, 0x2E0 };

// --- Helper: physical read via r0 backend (length-aware) ---
//
// Every physical read goes through the driver's MmMapIoSpace path. A garbage
// page-table entry can name a physical address that is not RAM; the driver
// maps it anyway and the copy returns garbage, so the read cannot fault on
// its own - but the *contents* of a page table we are about to trust would be
// garbage. Refusing anything above installed RAM keeps the page walk honest.
uint64_t vmm::phys_ram_end() {
    static uint64_t end = 0;
    if (!end) {
        MEMORYSTATUSEX ms{ sizeof(ms) };
        if (!GlobalMemoryStatusEx(&ms)) end = 0x100000000ull;  // 4 GB fallback
        else end = static_cast<uint64_t>(ms.ullTotalPhys);
    }
    return end;
}

static bool phys_read(uint64_t pa, void* buf, size_t len) {
    if (!len) return false;
    if (pa + len > vmm::phys_ram_end()) return false;
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
namespace {

// The scan is ~8M IOCTLs, so cache the hit on disk. KASLR moves ntoskrnl on
// every boot, so the cache is keyed on its base and size and re-validated by
// translating that base and checking for MZ before it is trusted. A Windows
// update that moves ntoskrnl invalidates it by construction.
constexpr uint32_t kCr3Magic = 0x33435246;   // 'FRC3'
constexpr uint32_t kCr3Ver   = 1;
struct Cr3Cache {
    uint32_t magic;
    uint32_t ver;
    uint64_t ntos;
    uint64_t ntos_size;
    uint64_t cr3;
};

bool cr3_cache_path(wchar_t* out, size_t cch) {
    wchar_t exe[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (!n || n >= MAX_PATH) return false;
    wchar_t* slash = wcsrchr(exe, L'\\');
    if (!slash) return false;
    *(slash + 1) = 0;
    return swprintf(out, cch, L"%scr3.cache", exe) > 0;
}

bool load_cr3_cache(uint64_t& cr3) {
    wchar_t path[MAX_PATH]{};
    if (!cr3_cache_path(path, MAX_PATH)) return false;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    Cr3Cache c{};
    DWORD r = 0;
    const bool ok = ReadFile(h, &c, sizeof(c), &r, nullptr) && r == sizeof(c);
    CloseHandle(h);
    if (!ok || c.magic != kCr3Magic || c.ver != kCr3Ver) return false;
    if (c.ntos != vmm::g_ntos || c.ntos_size != vmm::g_ntos_size) return false;
    if (c.cr3 < 0x1000 || (c.cr3 & 0xFFF)) return false;

    // Re-validate: the entry must still translate ntoskrnl's base to a page
    // that starts with "MZ". This rejects a stale cr3 whose page tables were
    // freed and reused, which is the failure mode a boot id would miss.
    uint64_t probe{};
    if (!translate_cr3(c.cr3, vmm::g_ntos, probe)) return false;
    if (probe >= vmm::phys_ram_end()) return false;
    uint16_t mz{};
    if (!phys_read(probe & ~0xFFFull, &mz, 2) || mz != 0x5A4D) return false;

    cr3 = c.cr3;
    return true;
}

void save_cr3_cache(uint64_t cr3) {
    wchar_t path[MAX_PATH]{};
    if (!cr3_cache_path(path, MAX_PATH)) return;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    const Cr3Cache c{ kCr3Magic, kCr3Ver, vmm::g_ntos, vmm::g_ntos_size, cr3 };
    DWORD w = 0;
    WriteFile(h, &c, sizeof(c), &w, nullptr);
    CloseHandle(h);
}

} // namespace

bool find_kernel_cr3(uint64_t& out) {
    // One scan per process is enough; remember the hit so a later call (or a
    // re-init after a detach) does not pay for 8M round-trips again.
    if (vmm::g_kcr3) { out = vmm::g_kcr3; return true; }

    uint64_t cached{};
    if (load_cr3_cache(cached)) {
        printf("[+] kernel CR3 0x%llx (from cr3.cache)\n", (unsigned long long)cached);
        vmm::g_kcr3 = cached;
        out = cached;
        return true;
    }

    // The CR3 and all of its page tables live in installed RAM. Do not scan
    // past it - above RAM is the PCI hole and mapping it would fault.
    const uint64_t top = vmm::phys_ram_end();

    uint64_t visited = 0;
    for (uint64_t pa = 0x1000; pa < top; pa += 0x1000) {
        if (!(++visited & 0xFFFFF)) {
            // Every ~4 GB. Without this the scan just looks hung.
            printf("[*] CR3 scan: 0x%llx / 0x%llx\n",
                   (unsigned long long)pa, (unsigned long long)top);
        }
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
        if (mz == 0x5A4D) {
            vmm::g_kcr3 = pa;
            save_cr3_cache(pa);
            out = pa;
            return true;
        }
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
    if (memcmp(name, "System", 7) != 0) return false;

    // Validate the LIST_ENTRY offset for real: both neighbours must be
    // kernel addresses, and the forward neighbour's Blink must point back at
    // this node. A wrong `links` offset (the old table had 0x98) reads two
    // arbitrary EPROCESS fields and fails here instead of at attach().
    uint64_t flink{}, blink{};
    if (!vmm::kread(p + l.links, &flink, 8)) return false;
    if (!vmm::kread(p + l.links + 8, &blink, 8)) return false;
    if (flink < 0xFFFF800000000000ull || blink < 0xFFFF800000000000ull) return false;
    uint64_t back{};
    if (!vmm::kread(flink + 8, &back, 8)) return false;
    if (back != p + l.links) return false;

    return true;
}

// ---------------------------------------------------------------------------
// ntoskrnl export lookup.
//
// Resolves a *data* export (a variable, not a function): the export RVA is
// the address of the variable itself. PsInitialSystemProcess is one; the
// PsLoadedModuleList head is not - that one is not exported on 26200, so the
// cloak has to find it by scanning instead.
// ---------------------------------------------------------------------------
bool vmm::export_rva(const char* want, uint64_t& rva) {
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

// ---------------------------------------------------------------------------
// System EPROCESS.
//
// PsInitialSystemProcess is exported by ntoskrnl on every modern Windows -
// it is a pointer to the System process EPROCESS. One read, no scan.
// ---------------------------------------------------------------------------
bool find_system_eprocess() {
    uint64_t rva{};
    if (vmm::export_rva("PsInitialSystemProcess", rva)) {
        uint64_t ep{};
        if (vmm::kread(vmm::g_ntos + rva, &ep, sizeof(ep)) && ep &&
            ep >= 0xFFFF800000000000ull && !(ep & 7)) {
            // Confirm it really is the System process (pid 4, name "System").
            // Offsets from Vergilius (_EPROCESS):
            //   24H2/25H2 (26100/26200): pid 0x1D0, links 0x1D8, name 0x338,
            //                            Peb 0x2E0
            //   23H2 / Win10 22H2:      pid 0x440, links 0x448, name 0x5A8,
            //                            Peb 0x550
            // DirectoryTableBase is KPROCESS+0x28 on every x64 build.
            //
            // The previous table had links 0x98 and Peb 0x38, which are not
            // fields in either structure; validation (pid/name) still passed,
            // so attach() would have failed at the first list walk.
            static const vmm::Layout kCand[] = {
                { 0x1D0, 0x1D8, 0x338, 0x28, 0x2E0 },
                { 0x440, 0x448, 0x5A8, 0x28, 0x550 },
            };
            for (const auto& l : kCand) {
                if (!looks_eprocess(ep, l)) continue;
                vmm::g_lay = l;
                vmm::g_eprocess = ep;
                return true;
            }
        }
    }

    // Fallback: scan ntoskrnl's writable sections for a pointer that
    // validates as the System process (pid 4, name "System").
    static const vmm::Layout kCand[] = {
        { 0x1D0, 0x1D8, 0x338, 0x28, 0x2E0 },   // Win11 24H2 / 25H2 (26200)
        { 0x440, 0x448, 0x5A8, 0x28, 0x550 },   // Win11 23H2 / Win10 22H2
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

// Read through an arbitrary CR3 - used before we have attached to anything.
static bool read_cr3(uint64_t cr3, uint64_t va, void* buf, size_t len) {
    auto* p = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        if (!translate_cr3(cr3, va + i, pa)) return false;
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        if (!phys_read(pa, p + i, n)) return false;
        i += n;
    }
    return true;
}

// Confirm the candidate process really has the wanted module in its own PEB.
//
// EPROCESS.ImageFileName is only char[15], so the game truncates to
// "FortniteClient-". "FortniteClient-Win64-Shipping.exe" and
// "FortniteClient-Win64-Shipping_BE.exe" truncate identically, so the
// truncated name alone is ambiguous - the module list settles it.
//
// x64 PEB:  Ldr at +0x18.  PEB_LDR_DATA: InLoadOrderModuleList at +0x10.
// LDR_DATA_TABLE_ENTRY: BaseDllName (UNICODE_STRING) length +0x58, buffer +0x60.
static bool peb_has_module(uint64_t eprocess, uint64_t cr3, const char* want) {
    uint64_t peb{}, ldr{}, head{}, cur{};
    if (!read_cr3(cr3, eprocess + vmm::g_lay.peb, &peb, 8)) return false;
    if (peb < vmm::kUserLo || peb > vmm::kUserHi) return false;
    if (!read_cr3(cr3, peb + 0x18, &ldr, 8)) return false;      // PEB->Ldr
    if (ldr < vmm::kUserLo || ldr > vmm::kUserHi) return false;
    if (!read_cr3(cr3, ldr + 0x10, &head, 8)) return false;     // InLoadOrderModuleList
    if (head < vmm::kUserLo || head > vmm::kUserHi) return false;
    if (!read_cr3(cr3, head, &cur, 8)) return false;

    for (int g = 0; g < 512 && cur && cur != head; ++g) {
        uint64_t nbuf{};
        uint16_t nlen{};
        if (!read_cr3(cr3, cur + 0x58, &nlen, 2)) return false;
        if (!read_cr3(cr3, cur + 0x60, &nbuf, 8)) return false;
        if (nlen > 3 && nlen < 512) {
            wchar_t w[264]{};
            const int c = nlen / 2;
            if (c < 263 && read_cr3(cr3, nbuf, w, nlen)) {
                char a[64]{};
                for (int i = 0; i < c && i < 63; ++i)
                    a[i] = w[i] < 128 ? static_cast<char>(w[i]) : '?';
                if (_stricmp(a, want) == 0) return true;
            }
        }
        if (!read_cr3(cr3, cur, &cur, 8)) return false;
    }
    return false;
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

        // ImageFileName is char[15] - the field truncates. Compare only as
        // many characters as the field can hold.
        constexpr size_t kEprocNameMax = 15;
        size_t wl = strlen(want);
        if (wl > kEprocNameMax) wl = kEprocNameMax;
        if (_strnicmp(name, want, wl) != 0) continue;
        if (pid == 0 || pid == 4) continue;

        uint64_t dtb{};
        if (!kread(cur + g_lay.dtb, &dtb, 8)) continue;
        dtb &= kPteMask;
        if (!dtb || dtb >= vmm::phys_ram_end()) continue;

        // The truncated name is ambiguous - confirm against the target's own
        // module list before committing to this process.
        if (!peb_has_module(cur, dtb, want)) continue;

        g_gcr3 = dtb;
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
        // Walk first: it validates that every page is present, so the
        // memmove cannot fault halfway through.
        if (!translate_cr3(g_kcr3, va + i, pa)) return false;
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        // The driver's KERNEL-VIRTUAL path, not the physical one: it memmoves
        // on the normal cached mapping, so other cores see the change. The
        // physical path uses MmMapIoSpace(MmNonCached) and would leave stale
        // lines in any core reading the same structure.
        if (!r0::vwrite(va + i, p + i, n)) return false;
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