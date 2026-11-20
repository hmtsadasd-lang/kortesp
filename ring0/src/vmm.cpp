#include "vmm.hpp"
#include "offsets.hpp"
#include "r0.hpp"
#include "pm.hpp"
#include "mem.hpp"
#include <windows.h>
#include <cstring>
#include <cstdio>
#include <vector>
#include <algorithm>

std::array<vmm::TlbEntry, vmm::kTlbSize> vmm::g_tlb{};
uint32_t                                 vmm::g_stamp = 1;

uint64_t  vmm::g_kcr3 = 0;
uint64_t  vmm::g_gcr3 = 0;
uint64_t  vmm::g_pte_base = 0;
uint64_t  vmm::g_base = 0;
uint64_t  vmm::g_size = 0;
uint64_t  vmm::g_eprocess = 0;
uint64_t  vmm::g_ntos = 0;
uint64_t  vmm::g_ntos_size = 0;
uint32_t  vmm::g_pid = 0;
bool      vmm::g_ready = false;
bool      vmm::g_dtb_ok = false;
bool      vmm::g_ntos_mz_broken = false;

vmm::Layout vmm::g_lay{ off::Eproc_Pid, off::Eproc_Links, off::Eproc_Name,
                        off::Eproc_Dtb, off::Eproc_Peb };

vmm::ProcOffsets vmm::g_off{};
bool           vmm::g_off_ready = false;
vmm::Target    vmm::g_target{};

namespace {

using Range = std::pair<uint64_t, uint64_t>;

std::vector<Range> g_ram;
std::vector<Range> g_mmio;
bool g_map_built = false;
bool g_map_exact = false;

bool reg_read_blob(HKEY root, const wchar_t* sub, const wchar_t* name,
                   std::vector<uint8_t>& out) {
    HKEY k{};
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) return false;
    DWORD type = 0, sz = 0;
    LONG r = RegQueryValueExW(k, name, nullptr, &type, nullptr, &sz);
    if (r != ERROR_SUCCESS || sz < 8 || sz > 0x40000) { RegCloseKey(k); return false; }
    out.assign(sz, 0);
    r = RegQueryValueExW(k, name, nullptr, &type, out.data(), &sz);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS) return false;
    out.resize(sz);
    return true;
}

void parse_resource_list(const std::vector<uint8_t>& b, std::vector<Range>& out) {
    auto rd16 = [&](size_t o, uint16_t& v) {
        if (o + 2 > b.size()) return false;
        memcpy(&v, b.data() + o, 2); return true;
    };
    auto rd32 = [&](size_t o, uint32_t& v) {
        if (o + 4 > b.size()) return false;
        memcpy(&v, b.data() + o, 4); return true;
    };
    auto rd64 = [&](size_t o, uint64_t& v) {
        if (o + 8 > b.size()) return false;
        memcpy(&v, b.data() + o, 8); return true;
    };

    uint32_t lists = 0;
    if (!rd32(0, lists) || !lists || lists > 32) return;

    size_t p = 4;
    for (uint32_t li = 0; li < lists; ++li) {
        const size_t prl = p + 8;
        uint32_t cnt = 0;
        if (!rd32(prl + 4, cnt) || cnt > 512) return;
        size_t d = prl + 8;
        for (uint32_t di = 0; di < cnt; ++di, d += 20) {
            if (d + 20 > b.size()) return;
            const uint8_t t = b[d];
            if (t != 3 && t != 7) continue;
            uint64_t start = 0, len = 0;
            uint32_t raw = 0;
            if (!rd64(d + 4, start) || !rd32(d + 12, raw)) continue;
            if (!start || !raw) continue;
            len = raw;
            if (t == 7) {
                uint16_t fl = 0;
                if (!rd16(d + 2, fl)) continue;
                switch (fl & 0x0E00) {
                case 0x0200: len = static_cast<uint64_t>(len) << 8;  break;
                case 0x0400: len = static_cast<uint64_t>(len) << 16; break;
                case 0x0800: len = static_cast<uint64_t>(len) << 32; break;
                default: continue;
                }
            }
            out.emplace_back(start, start + len);
        }
        p = d;
    }
}

void normalise(std::vector<Range>& v, uint64_t cap) {
    if (v.empty()) return;
    std::sort(v.begin(), v.end());
    std::vector<Range> m;
    for (const auto& r : v) {
        if (r.first >= cap) continue;
        const uint64_t hi = r.second > cap ? cap : r.second;
        if (!m.empty() && r.first <= m.back().second)
            m.back().second = std::max(m.back().second, hi);
        else
            m.emplace_back(r.first, hi);
    }
    v.swap(m);
}

} // namespace

void vmm::phys_map_reset() {
    g_ram.clear(); g_mmio.clear(); g_map_built = true; g_map_exact = false;
}
bool vmm::phys_map_exact() { return g_map_exact; }

void vmm::phys_map_init() {
    if (g_map_built) return;
    g_map_built = true;

    ULONGLONG installed_kb = 0;
    if (!GetPhysicallyInstalledSystemMemory(&installed_kb) || !installed_kb) {
        printf("[!] GetPhysicallyInstalledSystemMemory failed - physical reads are unbounded\n");
        return;
    }
    const uint64_t cap = static_cast<uint64_t>(installed_kb) * 1024ull * 2ull;

    std::vector<uint8_t> blob;
    if (reg_read_blob(HKEY_LOCAL_MACHINE,
                      L"HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
                      L".Translated", blob)) {
        parse_resource_list(blob, g_ram);
        normalise(g_ram, cap);
        g_map_exact = !g_ram.empty();
    }

    if (!g_map_exact) {
        printf("[!] usable-RAM resource list unavailable - falling back to "
               "installed size minus HAL MMIO ranges\n");
        std::vector<uint8_t> hal;
        if (reg_read_blob(HKEY_LOCAL_MACHINE,
                          L"HARDWARE\\RESOURCEMAP\\Hardware Abstraction Layer",
                          L".Translated", hal))
            parse_resource_list(hal, g_mmio);
        normalise(g_mmio, cap);

        const uint64_t top = static_cast<uint64_t>(installed_kb) * 1024ull;
        uint64_t cur = 0x1000;
        for (const auto& r : g_mmio) {
            if (r.second <= cur) continue;
            if (r.first >= top) break;
            if (r.first > cur) g_ram.emplace_back(cur, r.first);
            cur = std::max(cur, r.second);
        }
        if (cur < top) g_ram.emplace_back(cur, top);
    }

    uint64_t sum = 0;
    for (const auto& r : g_ram) sum += r.second - r.first;
    printf("[+] physical map: %zu range(s), 0x%llx usable bytes (%s)\n",
           g_ram.size(), (unsigned long long)sum,
           g_map_exact ? "loader list" : "derived");
}

bool vmm::phys_is_ram(uint64_t pa, size_t len) {
    if (!g_map_built) phys_map_init();
    if (g_ram.empty()) return true;
    if (!len) len = 1;
    if (pa + len < pa) return false;

    size_t lo = 0, hi = g_ram.size();
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2;
        if (g_ram[mid].second <= pa) lo = mid + 1;
        else hi = mid;
    }
    if (lo >= g_ram.size()) return false;
    const auto& r = g_ram[lo];
    return pa >= r.first && pa + len <= r.second;
}

uint64_t vmm::phys_ram_end() {
    if (!g_map_built) phys_map_init();
    return g_ram.empty() ? 0x100000000ull : g_ram.back().second;
}

static bool phys_read(uint64_t pa, void* buf, size_t len) {
    if (!len || !buf) return false;
    auto* p = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        const uint64_t cur = pa + i;
        size_t chunk = 0x1000 - (cur & 0xFFF);
        if (chunk > len - i) chunk = len - i;
        // pm::read uses the PTE self-map remap: no MmMapIoSpace, no
        // MmNonCached conflict, works on page-table pages too.
        if (pm::g_pm_ok && !pm::read(cur, p + i, chunk)) return false;
        else if (!pm::g_pm_ok && !r0::pread(cur, p + i, chunk)) return false;
        i += chunk;
    }
    return true;
}

uint32_t g_fail_seen = 0;

bool page_mz(uint64_t pa) {
    uint8_t p[16]{};
    if (!phys_read(pa & ~0xFFFull, p, sizeof(p))) return false;
    uint16_t mz{};
    memcpy(&mz, p, 2);
    if (mz == 0x5A4D) return true;
    if (mz == 0 && vmm::g_ntos_mz_broken) {
        for (uint8_t b : p) if (b) return true;
    }
    return false;
}

void reset_fail_count() { g_fail_seen = 0; }

void report_fail(const char* who, uint64_t cr3, uint64_t va, vmm::Walk st) {
    if (st == vmm::Walk::Ok) return;
    if (g_fail_seen >= 8) { ++g_fail_seen; return; }
    ++g_fail_seen;
    printf("[!] %s: walk stopped at %s cr3=0x%llx va=0x%llx%s\n", who,
           vmm::walk_name(st), (unsigned long long)cr3, (unsigned long long)va,
           st == vmm::Walk::PhysFail
               ? "  <- PT PFN: MmMapIoSpace does not support this read; section view required" : "");
}

bool va_canonical(uint64_t va) {
    const uint64_t sign = (va >> 47) & 1;
    return sign ? (va >> 48) == 0xFFFFull : (va >> 48) == 0;
}

bool vmm::safe_translate(uint64_t va, uint64_t& pa);   // forward declaration

vmm::Walk walk_va(uint64_t cr3, uint64_t va, uint64_t& pa) {
    cr3 &= vmm::kPteMask;
    if (!cr3 || !va_canonical(va)) return vmm::Walk::BadArgs;

    // Kernel VAs are globally mapped (same PTEs in every process).
    // safe_translate() reads through the current process's PTE self-map
    // via the kernel-VA IOCTL, which works on Win11 26200 where physical
    // PT-page reads are refused (487). This avoids the dangerous PTE
    // remap (pm.cpp) that caused BSODs.
    if (va >= 0xFFFF800000000000ull) {
        if (vmm::safe_translate(va, pa)) return vmm::Walk::Ok;
    }

    const uint64_t page = va & ~0xFFFull;
    auto& e = vmm::g_tlb[(page >> 12) & (vmm::kTlbSize - 1)];
    if (e.page == page && e.cr3 == cr3 && e.stamp == vmm::g_stamp) {
        pa = e.phys + (va & 0xFFF);
        return vmm::Walk::Ok;
    }

    auto store = [&](uint64_t phys, vmm::Walk r) {
        e.page = page; e.cr3 = cr3; e.phys = phys & ~0xFFFull;
        e.stamp = vmm::g_stamp;
        return r;
    };

    uint64_t pml4e{};
    if (!phys_read(cr3 + 8 * ((va >> 39) & 0x1FF), &pml4e, 8)) return vmm::Walk::PhysFail;
    if (!(pml4e & 1)) return vmm::Walk::Pml4;
    const uint64_t pdpt = pml4e & vmm::kPteMask;

    uint64_t pdpte{};
    if (!phys_read(pdpt + 8 * ((va >> 30) & 0x1FF), &pdpte, 8)) return vmm::Walk::PhysFail;
    if (!(pdpte & 1)) return vmm::Walk::Pdpt;

    if (pdpte & 0x80) {
        pa = (pdpte & 0x000FFFFFC0000000ull) + (va & 0x3FFFFFFFull);
        return store(pa, vmm::Walk::Ok);
    }

    const uint64_t pd = pdpte & vmm::kPteMask;
    uint64_t pde{};
    if (!phys_read(pd + 8 * ((va >> 21) & 0x1FF), &pde, 8)) return vmm::Walk::PhysFail;
    if (!(pde & 1)) return vmm::Walk::Pde;

    if (pde & 0x80) {
        pa = (pde & 0x000FFFFFFFE00000ull) + (va & 0x1FFFFFull);
        return store(pa, vmm::Walk::Ok);
    }

    const uint64_t pt = pde & vmm::kPteMask;
    uint64_t pte{};
    if (!phys_read(pt + 8 * ((va >> 12) & 0x1FF), &pte, 8)) return vmm::Walk::PhysFail;
    if (!(pte & 1)) return vmm::Walk::Pte;

    pa = (pte & vmm::kPteMask) + (va & 0xFFF);
    return store(pa, vmm::Walk::Ok);
}

const char* vmm::walk_name(vmm::Walk s) {
    switch (s) {
    case vmm::Walk::Ok:         return "ok";
    case vmm::Walk::PhysFail:   return "physical read refused";
    case vmm::Walk::Pml4:       return "PML4E not present (wrong CR3)";
    case vmm::Walk::Pdpt:       return "PDPTE not present";
    case vmm::Walk::Pde:        return "PDE not present";
    case vmm::Walk::Pte:        return "PTE not present (wrong VA)";
    case vmm::Walk::NotPresent: return "not present";
    case vmm::Walk::BadArgs:    return "bad arguments";
    }
    return "?";
}

static bool translate_cr3(uint64_t cr3, uint64_t va, uint64_t& pa) {
    return walk_va(cr3, va, pa) == vmm::Walk::Ok;
}

static bool find_ntoskrnl(uint64_t& base, uint64_t& size) {
    auto q = reinterpret_cast<LONG(__stdcall*)(ULONG, void*, ULONG, ULONG*)>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                               "NtQuerySystemInformation")));
    if (!q) return false;

    std::vector<uint8_t> buf;
    ULONG got = 0;
    bool have = false;
    for (int attempt = 0; attempt < 3; ++attempt) {
        ULONG need = 0;
        q(11, nullptr, 0, &need);
        if (!need) return false;
        need += 0x1000 * static_cast<ULONG>(attempt + 1);
        buf.assign(need, 0);
        got = need;
        const LONG st = q(11, buf.data(), need, &got);
        if (st == 0) { have = true; break; }
        if (static_cast<ULONG>(st) != 0xC0000004ul) return false;
    }
    if (!have || buf.size() < 8) return false;

    const uint32_t count = *reinterpret_cast<uint32_t*>(buf.data());
    if (!count || count > 4096) return false;
    size_t stride = (got - 8) / count;
    if (stride < 0x128) stride = 0x128;

    for (uint32_t i = 0; i < count; ++i) {
        const size_t off = 8 + static_cast<size_t>(i) * stride;
        if (off + 0x128 > buf.size()) break;
        const char* name = reinterpret_cast<const char*>(&buf[off + 0x28]);
        size_t nl = strnlen(name, 256);
        static const char want[] = "ntoskrnl.exe";
        const size_t wl = sizeof(want) - 1;
        if (nl < wl) continue;
        if (_strnicmp(name + nl - wl, want, wl) != 0) continue;

        uint64_t ib{}; uint32_t isz{};
        memcpy(&ib, &buf[off + 0x10], 8);
        memcpy(&isz, &buf[off + 0x18], 4);
        if (ib < 0xFFFF000000000000ull) continue;
        if (!isz || isz > 0x10000000ull) continue;
        base = ib; size = isz;
        return true;
    }
    return false;
}

bool vmm::module_base(const char* image_name, uint64_t& base, uint64_t& size) {
    auto q = reinterpret_cast<LONG(__stdcall*)(ULONG, void*, ULONG, ULONG*)>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                               "NtQuerySystemInformation")));
    if (!q) return false;

    std::vector<uint8_t> buf;
    ULONG got = 0;
    bool have = false;
    for (int attempt = 0; attempt < 3; ++attempt) {
        ULONG need = 0;
        q(11, nullptr, 0, &need);
        if (!need) return false;
        need += 0x1000 * static_cast<ULONG>(attempt + 1);
        buf.assign(need, 0);
        got = need;
        const LONG st = q(11, buf.data(), need, &got);
        if (st == 0) { have = true; break; }
        if (static_cast<ULONG>(st) != 0xC0000004ul) return false;
    }
    if (!have || buf.size() < 8) return false;

    const uint32_t count = *reinterpret_cast<uint32_t*>(buf.data());
    if (!count || count > 4096) return false;
    size_t stride = (got - 8) / count;
    if (stride < 0x128) stride = 0x128;

    const size_t wl = strlen(image_name);
    if (!wl || wl >= 0x100) return false;

    for (uint32_t i = 0; i < count; ++i) {
        const size_t off = 8 + static_cast<size_t>(i) * stride;
        if (off + 0x128 > buf.size()) break;
        const char* name = reinterpret_cast<const char*>(&buf[off + 0x28]);
        size_t nl = strnlen(name, 256);
        if (nl < wl) continue;
        const char* tail = name + nl - wl;
        if (tail > name && tail[-1] != '\\' && tail[-1] != '/') continue;
        if (_strnicmp(tail, image_name, wl) != 0) continue;

        uint64_t ib{}; uint32_t isz{};
        memcpy(&ib, &buf[off + 0x10], 8);
        memcpy(&isz, &buf[off + 0x18], 4);
        if (ib < 0xFFFF000000000000ull || !isz) continue;
        base = ib; size = isz;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// CR3 cache
// ---------------------------------------------------------------------------
namespace {

constexpr uint32_t kCr3Magic = 0x33435246;
constexpr uint32_t kCr3Ver   = 1;
struct Cr3Cache { uint32_t magic; uint32_t ver; uint64_t ntos; uint64_t ntos_size; uint64_t cr3; };

bool cr3_cache_path(wchar_t* out, size_t cch) {
    wchar_t exe[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (!n || n >= MAX_PATH) return false;
    wchar_t* slash = wcsrchr(exe, L'\\');
    if (!slash) return false;
    *(slash + 1) = 0;
    return swprintf(out, cch, L"%scr3.cache", exe) > 0;
}

bool cache_valid(const Cr3Cache& c) {
    if (c.magic != kCr3Magic || c.ver != kCr3Ver) return false;
    if (c.ntos != vmm::g_ntos || c.ntos_size != vmm::g_ntos_size) return false;
    if (c.cr3 < 0x1000 || (c.cr3 & 0xFFF)) return false;
    uint64_t probe{};
    if (!translate_cr3(c.cr3, vmm::g_ntos, probe)) return false;
    return page_mz(probe);
}

bool try_cached_cr3(uint64_t& cr3) {
    wchar_t path[MAX_PATH]{};
    if (!cr3_cache_path(path, MAX_PATH)) return false;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    Cr3Cache c{};
    DWORD r = 0;
    const bool ok = ReadFile(h, &c, sizeof(c), &r, nullptr) && r == sizeof(c);
    CloseHandle(h);
    if (!ok || !cache_valid(c)) return false;
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

bool vmm::init_kcr3_cached() {
    if (g_kcr3) return true;
    if (!g_ntos || !g_ntos_size) return false;
    uint64_t c{};
    if (!try_cached_cr3(c)) return false;
    g_kcr3 = c;
    printf("[+] kernel CR3 0x%llx (from cr3.cache)\n", (unsigned long long)c);
    return true;
}

bool vmm::page_table_read_ok() {
    if (!g_eprocess) return false;
    uint64_t dtb{};
    if (!kread_trusted(g_eprocess + g_lay.dtb, &dtb, 8)) return false;
    dtb &= kPteMask;
    if (!dtb) return false;
    uint8_t b[16]{};
    if (!phys_read(dtb, b, sizeof(b))) return false;
    for (uint8_t v : b) if (v) return true;
    return false;
}

bool vmm::safe_translate(uint64_t va, uint64_t& pa) {
    if ((va >> 48) != 0xFFFFull) return false;
    if (!g_pte_base) return false;   // caller must call init_pte_base() first
    constexpr uint64_t kMask48 = 0x0000FFFFFFFFFFFFull;
    const uint64_t kPteBase = g_pte_base;
    const uint64_t m = va & kMask48;
    const uint64_t pde_base = kPteBase + ((kPteBase & kMask48) >> 9);
    const uint64_t ppe_base = kPteBase + ((pde_base & kMask48) >> 9);
    const uint64_t pxe_base = kPteBase + ((ppe_base & kMask48) >> 9);

    uint64_t e{};
    if (!r0::vread(pxe_base + (m >> 39) * 8, &e, 8) || !(e & 1)) return false;
    if (e & 0x80) { pa = (e & kPteMask) | (m & 0x3FFFFFFFull); return true; }
    if (!r0::vread(ppe_base + (m >> 30) * 8, &e, 8) || !(e & 1)) return false;
    if (e & 0x80) { pa = (e & kPteMask) | (m & 0x1FFFFFFFull); return true; }
    if (!r0::vread(pde_base + (m >> 21) * 8, &e, 8) || !(e & 1)) return false;
    if (e & 0x80) { pa = (e & kPteMask) | (m & 0x1FFFFFull); return true; }
    if (!r0::vread(kPteBase + (m >> 12) * 8, &e, 8) || !(e & 1)) return false;
    pa = (e & kPteMask) | (m & 0xFFF);
    return true;
}

bool vmm::init_kcr3() {
    if (g_kcr3) return true;
    if (!g_ntos || !g_eprocess) return false;

    auto try_off = [&](uint64_t o, bool accept) -> bool {
        uint64_t dtb{};
        if (!kread_trusted(g_eprocess + o, &dtb, 8)) return false;
        const uint64_t c = dtb & kPteMask;
        if (!c) return false;
        uint64_t kpa{};
        if (walk_va(c, g_ntos, kpa) != Walk::Ok || !page_mz(kpa)) return false;
        if (!accept) return true;
        g_kcr3 = c;
        g_lay.dtb = o;
        g_dtb_ok = true;
        printf("[+] kernel CR3 0x%llx (EPROCESS +0x%llx, stored 0x%016llx)\n",
               (unsigned long long)c, (unsigned long long)o, (unsigned long long)dtb);
        return true;
    };

    if (try_off(g_lay.dtb, true)) return true;

    printf("[!] EPROCESS +0x%llx is not a DTB - offset table:\n",
           (unsigned long long)g_lay.dtb);
    for (uint64_t o = 0x20; o <= 0xF8; o += 8) {
        uint64_t dtb{};
        if (!kread_trusted(g_eprocess + o, &dtb, 8)) {
            printf("  +0x%02llx = <kread failed>\n", (unsigned long long)o);
            continue;
        }
        const uint64_t c = dtb & kPteMask;
        if (!c) { printf("  +0x%02llx = 0\n", (unsigned long long)o); continue; }
        uint64_t kpa{};
        const Walk st = walk_va(c, g_ntos, kpa);
        const bool mz = st == Walk::Ok && page_mz(kpa);
        printf("  +0x%02llx = 0x%016llx  phys 0x%010llx  walk=%s mz=%s%s\n",
               (unsigned long long)o, (unsigned long long)dtb,
               (unsigned long long)c, walk_name(st), mz ? "yes" : "no",
               mz ? "   <== DTB" : "");
        if (mz) {
            g_kcr3 = c; g_lay.dtb = o; g_dtb_ok = true;
            printf("[+] DirectoryTableBase is +0x%llx\n", (unsigned long long)o);
            return true;
        }
    }
    if (init_kcr3_cached()) return true;
    printf("[!] no DTB in 0x20..0xF8 mapped ntoskrnl to MZ\n");
    return false;
}

namespace {
bool pml4e_plausible(uint64_t cr3, uint64_t va);
}

bool vmm::scan_kernel_cr3() {
    if (g_kcr3) {
        printf("[*] kernel CR3 already 0x%llx\n", (unsigned long long)g_kcr3);
        return true;
    }
    if (!g_ntos) return false;
    if (init_kcr3_cached()) return true;

    phys_map_init();
    constexpr size_t kChunk = 0x10000;
    std::vector<uint8_t> buf(kChunk);
    const uint64_t top = phys_ram_end();

    for (uint64_t base = 0x1000; base < top; base += kChunk) {
        size_t n = kChunk;
        if (base + n > top) n = static_cast<size_t>(top - base);
        if (!phys_is_ram(base, n)) {
            size_t m = 0;
            while (m + 0x1000 <= n && phys_is_ram(base + m, 0x1000)) m += 0x1000;
            n = m;
        }
        if (n < 0x1000) continue;
        if (!r0::pread(base, buf.data(), n)) continue;

        for (size_t off = 0; off + 8 <= n; off += 0x1000) {
            uint64_t e{};
            memcpy(&e, buf.data() + off, 8);
            if (!(e & 1)) continue;
            const uint64_t pa = base + off;
            if (!pml4e_plausible(pa, g_ntos)) continue;
            uint64_t probe{};
            if (!translate_cr3(pa, g_ntos, probe)) continue;
            if (!page_mz(probe)) continue;
            g_kcr3 = pa;
            save_cr3_cache(pa);
            printf("[+] kernel CR3 0x%llx (scan)\n", (unsigned long long)pa);
            return true;
        }
    }
    printf("[!] CR3 scan exhausted 0x%llx without a hit\n", (unsigned long long)top);
    return false;
}

bool vmm::sections(std::vector<Section>& out) {
    out.clear();
    if (!g_ntos || !g_ntos_size) return false;

    IMAGE_DOS_HEADER dos{};
    if (!kread_trusted(g_ntos, &dos, sizeof(dos)) || !vmm::mz_ok(dos.e_magic)) return false;
    if (dos.e_lfanew >= g_ntos_size) return false;

    IMAGE_NT_HEADERS64 nt{};
    if (!kread_trusted(g_ntos + dos.e_lfanew, &nt, sizeof(nt))) return false;
    if (nt.Signature != 0x4550) return false;

    const unsigned n = nt.FileHeader.NumberOfSections;
    if (!n || n > 96) return false;

    const uint64_t off = g_ntos + dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER)
                       + nt.FileHeader.SizeOfOptionalHeader;
    std::vector<IMAGE_SECTION_HEADER> raw(n);
    if (!kread_trusted(off, raw.data(), raw.size() * sizeof(IMAGE_SECTION_HEADER)))
        return false;

    for (const auto& s : raw) {
        if (!s.Misc.VirtualSize) continue;
        if (s.VirtualAddress >= g_ntos_size) continue;
        if (s.Misc.VirtualSize > g_ntos_size) continue;
        out.push_back(Section{ s.VirtualAddress, s.Misc.VirtualSize,
                               s.Characteristics });
    }
    return !out.empty();
}

bool vmm::export_rva(const char* want, uint64_t& rva) {
    if (!g_ntos || !g_ntos_size) return false;

    IMAGE_DOS_HEADER dos{};
    if (!kread_trusted(g_ntos, &dos, sizeof(dos)) || !vmm::mz_ok(dos.e_magic)) return false;
    if (dos.e_lfanew >= g_ntos_size) return false;

    IMAGE_NT_HEADERS64 nt{};
    if (!kread_trusted(g_ntos + dos.e_lfanew, &nt, sizeof(nt))) return false;
    if (nt.Signature != 0x4550) return false;

    const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size || dir.VirtualAddress >= g_ntos_size) return false;

    IMAGE_EXPORT_DIRECTORY ed{};
    if (!kread_trusted(g_ntos + dir.VirtualAddress, &ed, sizeof(ed))) return false;
    if (ed.NumberOfNames > 0x10000) return false;

    for (uint32_t i = 0; i < ed.NumberOfNames; ++i) {
        uint32_t name_rva{};
        if (!kread_trusted(g_ntos + ed.AddressOfNames + 4ull * i, &name_rva, 4)) return false;
        if (!name_rva || name_rva >= g_ntos_size) continue;
        char name[64]{};
        if (!kread_trusted(g_ntos + name_rva, name, sizeof(name) - 1)) continue;
        if (strcmp(name, want) != 0) continue;

        uint16_t ord{};
        if (!kread_trusted(g_ntos + ed.AddressOfNameOrdinals + 2ull * i, &ord, 2)) return false;
        uint32_t fn{};
        if (!kread_trusted(g_ntos + ed.AddressOfFunctions + 4ull * ord, &fn, 4)) return false;
        rva = fn;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Runtime PTE self-map base (nt!MiPteBase).
//
// Win10 1607+ randomizes the base that used to be the constant
// 0xFFFFF68000000000. MiGetPteAddress in this build is
//
//   48 C1 E9 09                    shr  rcx, 9
//   48 23 C8                       and  rcx, rax        ; rax = 7FFFFFFFF8h
//   48 B8 <imm64 = MiPteBase>      mov  rax, MiPteBase
//   48 03 C8                       add  rcx, rax
//
// The image stores the link-time 0xFFFFF68000000000 in many inlined copies;
// the loader relocates each one to the randomized runtime base. Reading the
// instruction stream therefore yields the live value directly - no .data
// pointer scan and no blind candidate dereference. The sites must agree, and
// the winner is proven against ntoskrnl's own self-map PTE (present, PFN page
// starts with a PE image header).
// ---------------------------------------------------------------------------
bool vmm::init_pte_base() {
    if (g_pte_base) return true;
    if (!g_ntos || !g_ntos_size) return false;

    std::vector<Section> secs;
    if (!sections(secs)) {
        printf("[!] pte base: ntoskrnl section table unavailable\n");
        return false;
    }

    // shr rcx,9 ; and rcx,rax ; mov rax, imm64  (exactly 9 bytes before imm64)
    static const uint8_t kSig[9] = {
        0x48, 0xC1, 0xE9, 0x09, 0x48, 0x23, 0xC8, 0x48, 0xB8
    };

    uint64_t votes[8]{};
    size_t  counts[8]{};
    int nvotes = 0;
    size_t total = 0;
    auto vote = [&](uint64_t v) {
        ++total;
        for (int i = 0; i < nvotes; ++i) if (votes[i] == v) { ++counts[i]; return; }
        if (nvotes < 8) { votes[nvotes] = v; counts[nvotes] = 1; ++nvotes; }
    };

    constexpr size_t kChunk = 0x10000;
    constexpr size_t kTail = sizeof(kSig) + 8;
    std::vector<uint8_t> buf(kChunk + kTail);
    for (const auto& s : secs) {
        if (!(s.chars & IMAGE_SCN_MEM_EXECUTE) || !s.size) continue;
        if (s.chars & IMAGE_SCN_MEM_DISCARDABLE) continue;
        if (!(s.chars & IMAGE_SCN_MEM_NOT_PAGED)) continue;
        const uint64_t lo = g_ntos + s.va;
        const uint64_t hi = lo + s.size;
        for (uint64_t page = lo; page < hi; page += kChunk) {
            size_t rn = kChunk;
            if (page + rn > hi) rn = static_cast<size_t>(hi - page);
            if (page + rn + kTail <= hi) rn += kTail;   // overlap for split matches
            if (!r0::vread(page, buf.data(), rn)) continue;
            for (size_t i = 0; i + kTail <= rn; ++i) {
                if (memcmp(buf.data() + i, kSig, sizeof(kSig)) != 0) continue;
                uint64_t v{};
                memcpy(&v, buf.data() + i + sizeof(kSig), 8);
                vote(v);
            }
        }
    }

    if (!nvotes) {
        printf("[!] pte base: MiGetPteAddress pattern not found in ntoskrnl\n");
        return false;
    }
    int best = 0;
    for (int i = 1; i < nvotes; ++i) if (counts[i] > counts[best]) best = i;
    const uint64_t cand = votes[best];
    printf("[*] pte base candidate 0x%llx (%zu of %zu site(s))\n",
           (unsigned long long)cand, counts[best], total);

    // The self-map occupies one 512 GB PML4 slot, so the base is naturally
    // 512 GB aligned. Refuse anything else before dereferencing it.
    if ((cand >> 48) != 0xFFFFull || cand < 0xFFFF800000000000ull ||
        (cand & 0x7FFFFFFFFFull) != 0) {
        printf("[!] pte base: 0x%llx is not a canonical 512 GB-aligned base\n",
               (unsigned long long)cand);
        return false;
    }

    // Prove the candidate on a page that is guaranteed 4 KB-mapped: allocate
    // a private page in this process, write a nonce, translate it through the
    // candidate self-map, then read the decoded PFN physically and require the
    // nonce. ntoskrnl is 2 MB mapped here, so its "PTE slot" aliases the image
    // page itself (an MZ header) instead of a PTE - that is not a valid proof.
    void* probe = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                               PAGE_READWRITE);
    if (!probe) {
        printf("[!] pte base: private probe page allocation failed\n");
        return false;
    }
    const uint64_t nonce = 0x9E3779B97F4A7C15ull;
    volatile uint64_t* words = static_cast<volatile uint64_t*>(probe);
    words[0] = nonce;
    words[1] = ~nonce;

    const uint64_t probe_va = reinterpret_cast<uint64_t>(probe);
    const uint64_t probe_pte = cand + ((probe_va & 0x0000FFFFFFFFFFFFull) >> 12) * 8;
    uint64_t e{};
    const bool present = r0::vread(probe_pte, &e, sizeof e) && (e & 1);
    const uint64_t pfn = present ? (e & kPteMask) >> 12 : 0;
    uint8_t got[16]{};
    const bool match = pfn && r0::pread(pfn << 12, got, sizeof got) &&
                       memcmp(got, &nonce, 8) == 0;
    VirtualFree(probe, 0, MEM_RELEASE);
    if (!match) {
        printf("[!] pte base 0x%llx failed the private-page self-map proof "
               "(pte 0x%llx, present=%d, pfn 0x%llx)\n",
               (unsigned long long)cand, (unsigned long long)e,
               present ? 1 : 0, (unsigned long long)pfn);
        return false;
    }
    printf("[+] pte base self-map proof: private VA 0x%llx -> pte 0x%llx -> pa 0x%llx\n",
           (unsigned long long)probe_va, (unsigned long long)e,
           (unsigned long long)(pfn << 12));

    g_pte_base = cand;
    printf("[+] PTE self-map base 0x%llx (validated)\n", (unsigned long long)cand);
    return true;
}

namespace {

constexpr uint64_t kKernelLo = 0xFFFF800000000000ull;
constexpr uint64_t kKernelHi = 0xFFFFFFFFFFFFFFFFull;

bool in_kernel_va(uint64_t a) { return a >= kKernelLo && a <= kKernelHi; }

bool kq(uint64_t a, uint64_t& out) { return vmm::kread_trusted(a, &out, sizeof out); }

bool has_bytes(const uint8_t* hay, size_t n, const char* needle) {
    size_t m = strlen(needle);
    if (m > n) return false;
    for (size_t i = 0; i + m <= n; ++i)
        if (!memcmp(hay + i, needle, m)) return true;
    return false;
}

bool validate_system_eprocess(uint64_t p, bool page_gate) {
    if (!in_kernel_va(p) || (p & 7)) return false;
    // A .data decoy can point at a paged-out page; gate every header page
    // through the PTE self-map before touching it with the trusted read.
    // The PsInitialSystemProcess export is already authoritative, so it may
    // bypass the gate (and keep --eproc usable if PTE-base discovery fails).
    if (page_gate) {
        for (size_t i = 0; i < 0x600; i += 0x1000) {
            uint64_t pa{};
            if (!vmm::safe_translate(p + i, pa)) return false;
        }
    }
    uint8_t buf[0x600];
    if (!vmm::kread_trusted(p, buf, sizeof buf)) return false;
    if (!has_bytes(buf, sizeof buf, "System")) return false;
    bool pid4 = false;
    for (size_t i = 0; i + 8 <= sizeof buf; i += 8)
        if (*(uint64_t*)(buf + i) == 4) { pid4 = true; break; }
    return pid4;
}

bool pml4e_plausible(uint64_t cr3_pa, uint64_t va) {
    if (!cr3_pa || (cr3_pa & 0xFFF)) return false;
    uint64_t e = 0;
    if (!r0::pread(cr3_pa + 8 * ((va >> 39) & 0x1FF), &e, 8)) return false;
    if (!(e & 1)) return false;
    const uint64_t pfn = (e >> 12) & 0xFFFFFFFFFFull;
    if (!pfn) return false;
    if (!vmm::phys_is_ram(pfn << 12, 0x1000)) return false;
    return true;
}

// Image alaninda: onceki byte null, printable ASCII, 15 byte icinde null ile biten
bool plausible_image_field(const uint8_t* buf, size_t off) {
    if (off == 0 || buf[off - 1] != 0) return false;
    size_t i = off;
    while (i < off + 15 && buf[i]) {
        if (buf[i] < 0x20 || buf[i] > 0x7E) return false;
        ++i;
    }
    return i < off + 15;   // null ile kapandi
}

} // namespace

static bool find_system_eprocess(uint64_t& out) {
    uint64_t sym = 0;
    if (vmm::export_rva("PsInitialSystemProcess", sym)) {
        uint64_t p = 0;
        if (kq(vmm::g_ntos + sym, p) && validate_system_eprocess(p, /*page_gate=*/false)) { out = p; return true; }
    }

    std::vector<vmm::Section> secs;
    if (!vmm::sections(secs)) return false;
    constexpr size_t kChunk = 0x1000;
    std::vector<uint8_t> buf(kChunk);

    for (const auto& s : secs) {
        if (!(s.chars & IMAGE_SCN_MEM_WRITE) || (s.chars & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (!s.size) continue;
        const uint64_t lo = vmm::g_ntos + s.va;
        const uint64_t hi = lo + s.size;
        for (uint64_t page = lo & ~0xFFFull; page < hi; page += kChunk) {
            size_t n = kChunk;
            if (page + n > hi) n = static_cast<size_t>(hi - page);
            if (!vmm::kread_trusted(page, buf.data(), n)) continue;
            for (size_t off = 0; off + 8 <= n; off += 8) {
                const uint64_t cand_addr = page + off;
                if (cand_addr < lo || cand_addr + 8 > hi) continue;
                uint64_t cand{};
                memcpy(&cand, buf.data() + off, 8);
                if (!in_kernel_va(cand) || (cand & 7)) continue;
                if (validate_system_eprocess(cand, /*page_gate=*/true)) { out = cand; return true; }
            }
        }
    }
    return false;
}

bool vmm::discover_offsets(uint64_t p) {
    uint8_t buf[0x600];
    if (!vmm::kread_trusted(p, buf, sizeof buf)) return false;
    vmm::ProcOffsets o{};

    // image: "System\0" + plausible_image_field capraz dogrulama
    for (size_t i = 0x100; i + 7 <= sizeof buf; ++i) {
        if (!memcmp(buf + i, "System\0", 7) && plausible_image_field(buf, i)) {
            o.image = (uint32_t)i;
            break;
        }
    }
    if (!o.image) return false;

    // pid + links: System'in kendi PID'i 4'tur. Adayi yalnizca degeriyle kabul
    // etmiyoruz. ActiveProcessLinks her NT build'inde UniqueProcessId'yi hemen
    // izler ve zincirdeki her dugum gecerli bir PID ile gorunur bir
    // ImageFileName tasir. Bu kosullar, ayni EPROCESS icindeki
    // SessionProcessLinks gibi baska dairesel listelerin yanlislikla
    // secilmesini engeller (o liste yalnizca System'in oturumunu dolasir ve
    // Fortnite'i asla bulamaz).
    auto image_ok = [&](uint64_t e) {
        char img[16]{};
        if (!vmm::kread_trusted(e + o.image, img, sizeof img - 1)) return false;
        for (char c : img) {
            if (c == 0) return true;
            if (c < 0x20 || c > 0x7E) return false;
        }
        return false;
    };
    auto walk = [&](uint64_t e, size_t links, size_t pid, int max) {
        uint64_t cur = e;
        for (int n = 0; n < max; ++n) {
            uint64_t fl = 0, back = 0;
            if (!kq(cur + links, fl)) return false;
            if (!in_kernel_va(fl) || (fl & 7)) return false;
            const uint64_t next = fl - links;
            if (next == e) return n > 0;
            if (!in_kernel_va(next) || (next & 7)) return false;
            uint64_t np = 0;
            if (!kq(next + pid, np)) return false;
            if (!np || np > 0x100000 || (np & 3)) return false;
            if (!image_ok(next)) return false;
            if (!kq(next + links + 8, back) || back != cur + links) return false;
            cur = next;
        }
        return true;   // max dugum boyunca tutarli zincir
    };

    for (size_t i = 0x100; i + 16 <= sizeof buf; i += 8) {
        if (*(uint64_t*)(buf + i) != 4) continue;
        const size_t l = i + 8;          // ActiveProcessLinks, PID'yi izler
        uint64_t fl = *(uint64_t*)(buf + l);
        if (!in_kernel_va(fl) || (fl & 7)) continue;
        uint64_t back = 0;
        if (!kq(fl + 8, back) || back != p + l) continue;
        if (!walk(p, l, i, 8)) continue;
        o.pid = (uint32_t)i;
        o.links = (uint32_t)l;
        break;
    }
    if (!o.pid || !o.links) return false;

    vmm::g_off = o;
    vmm::g_off_ready = true;
    printf("[vmm] offsets pid=0x%X links=0x%X image=0x%X\n", o.pid, o.links, o.image);
    return true;
}

bool vmm::init_system() {

    if (g_eprocess) return true;
    if (!g_ntos) return false;

    uint64_t ep{};
    if (!find_system_eprocess(ep)) return false;
    g_eprocess = ep;

    if (!discover_offsets(ep)) return false;
    return true;
}

bool vmm::init_ntos() {
    if (g_ntos) return true;
    phys_map_init();
    if (!find_ntoskrnl(g_ntos, g_ntos_size)) {
        printf("[!] ntoskrnl base not found in SystemModuleInformation\n"
               "    (SeDebugPrivilege must be enabled or ImageBase reads as 0)\n");
        return false;
    }
    uint16_t hdr{};
    if (!kread_trusted(g_ntos, &hdr, sizeof hdr) || hdr != 0x5A4D) {
        printf("[!] ntoskrnl base 0x%llx is not MZ (hdr=0x%04X)\n",
               (unsigned long long)g_ntos, hdr);
        return false;
    }
    printf("[+] ntoskrnl base 0x%llx size 0x%llx\n",
           (unsigned long long)g_ntos, (unsigned long long)g_ntos_size);
    return true;
}

bool vmm::init() {
    if (!init_ntos()) return false;
    init_kcr3_cached();
    if (!init_system()) return false;
    return init_kcr3();
}

void vmm::shutdown() {
    g_ready = false; g_gcr3 = 0; g_eprocess = 0; g_pid = 0;
    g_base = 0; g_size = 0;
    ++g_stamp;
    r0::shutdown();
}

static bool read_cr3(uint64_t cr3, uint64_t va, void* buf, size_t len) {
    auto* p = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        const vmm::Walk st = walk_va(cr3, va + i, pa);
        if (st != vmm::Walk::Ok) { report_fail("read_cr3", cr3, va + i, st); return false; }
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        if (!phys_read(pa, p + i, n)) {
            report_fail("read_cr3(phys)", cr3, va + i, vmm::Walk::PhysFail);
            return false;
        }
        i += n;
    }
    return true;
}

// ImageFileName is char[15], so every Fortnite sibling truncates identically;
// the PEB module list settles which one it is.
static bool peb_has_module(uint64_t eprocess, uint64_t cr3, const char* want) {
    uint64_t peb{}, ldr{}, head{}, cur{};
    if (!vmm::kread_trusted(eprocess + vmm::g_lay.peb, &peb, 8)) return false;
    if (peb < vmm::kUserLo || peb > vmm::kUserHi) return false;
    if (!read_cr3(cr3, peb + 0x18, &ldr, 8)) return false;
    if (ldr < vmm::kUserLo || ldr > vmm::kUserHi) return false;
    if (!read_cr3(cr3, ldr + 0x10, &head, 8)) return false;
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

static bool read_user_va(uint64_t cr3, uint64_t va, void* buf, size_t len);

static bool find_module_in_ldr(uint64_t cr3, uint64_t ldr, const char* want,
                               uint64_t& base, uint64_t& size) {
    uint64_t head{}, cur{};
    if (!read_user_va(cr3, ldr + off::Ldr_InLoadOrder, &head, 8)) return false;
    if (head < vmm::kUserLo || head > vmm::kUserHi) return false;
    if (!read_user_va(cr3, head, &cur, 8)) return false;

    for (int g = 0; g < 512 && cur && cur != head; ++g) {
        uint16_t nlen{};
        uint64_t nbuf{}, dllbase{};
        if (!read_user_va(cr3, cur + off::Ldr_BaseDllNameLen, &nlen, 2)) return false;
        if (!read_user_va(cr3, cur + off::Ldr_BaseDllNameBuf, &nbuf, 8)) return false;
        if (!read_user_va(cr3, cur + off::Ldr_DllBase, &dllbase, 8)) return false;
        uint32_t imgsz32{};
        if (!read_user_va(cr3, cur + off::Ldr_SizeOfImage, &imgsz32, 4)) return false;

        if (nlen > 3 && nlen < 512 && nbuf >= vmm::kUserLo && nbuf <= vmm::kUserHi) {
            wchar_t w[264]{};
            const int c = static_cast<int>(nlen / 2);
            if (c < 263 && read_user_va(cr3, nbuf, w, static_cast<size_t>(nlen))) {
                char a[64]{};
                for (int i = 0; i < c && i < 63; ++i)
                    a[i] = w[i] < 128 ? static_cast<char>(w[i]) : '?';
                if (_stricmp(a, want) == 0) {
                    base = dllbase;
                    size = static_cast<uint64_t>(imgsz32);
                    return true;
                }
            }
        }
        if (!read_user_va(cr3, cur, &cur, 8)) return false;
    }
    return false;
}

// User-space VA reader: uses RPM (ReadProcessMemory) when the rpm backend is
// active, otherwise falls back to the physical page-table walk (read_cr3).
// On Win11 26200 the driver refuses PT-page physical reads, so rpm is the
// only working path for user VAs there.
static bool read_user_va(uint64_t cr3, uint64_t va, void* buf, size_t len) {
    if (mem::active() == mem::backend::rpm) {
        return mem::read(va, buf, len);
    }
    return read_cr3(cr3, va, buf, len);
}

static bool fill_target(uint64_t eproc, uint32_t pid, vmm::Target& t) {
    uint64_t dtb = 0;
    if (!vmm::kread_trusted(eproc + vmm::g_lay.dtb, &dtb, 8)) return false;
    if (dtb & 0xFFF) return false;
    if (mem::active() != mem::backend::rpm && !pml4e_plausible(dtb, vmm::g_ntos)) return false;

    // PEB adayi: +0x200..+0x600, user VA, translate edilebilir, LDR null degil.
    // Bir adayda modul bulunamazsa bir sonraki adayi dene (decoy alanlara karsi).
    uint64_t peb = 0;
    uint64_t base = 0, size = 0;
    bool peb_ok = false;
    for (uint32_t o = 0x200; o + 8 <= 0x600 && !peb_ok; o += 8) {
        uint64_t cand = 0;
        if (!vmm::kread_trusted(eproc + o, &cand, 8)) continue;
        if (cand < vmm::kUserLo || cand > vmm::kUserHi || (cand & 7)) continue;
        uint64_t ldr = 0;
        if (!read_user_va(dtb, cand + off::Peb_Ldr, &ldr, 8)) continue;
        if (!ldr) continue;

        uint64_t ldr2 = 0;
        if (!read_user_va(dtb, cand + off::Peb_Ldr, &ldr2, 8)) continue;
        base = 0; size = 0;
        if (!find_module_in_ldr(dtb, ldr2, "FortniteClient-Win64-Shipping.exe", base, size))
            continue;   // bu aday degil, bir sonraki
        if (size < 0x04000000) continue;          // launcher'lari ele

        // Capa 1: PEB->ImageBaseAddress == modul base
        uint64_t peb_base = 0;
        if (!read_user_va(dtb, cand + off::Peb_ImageBaseAddress, &peb_base, 8)) continue;
        if (peb_base != base) continue;

        peb = cand;
        vmm::g_off.peb = o;
        vmm::g_lay.peb = o;
        peb_ok = true;
    }

    t.eproc = eproc;
    t.pid = pid;
    t.cr3 = dtb;
    t.base = base;
    t.size = size;
    t.peb_ok = peb_ok;
    return true;
}

bool vmm::find_process_by_prefix(const char* prefix, vmm::Target& t) {
    if (!vmm::g_off_ready) return false;
    uint64_t head = vmm::g_eprocess + vmm::g_off.links;
    uint64_t cur = 0;
    if (!vmm::kread_trusted(head, &cur, 8)) return false;
    int n = 0, matches = 0;
    while (cur && cur != head && n < 4096) {
        uint64_t e = cur - vmm::g_off.links;
        ++n;
        char name[15] = {};
        if (vmm::kread_trusted(e + vmm::g_off.image, name, 14) &&
            !strncmp(name, prefix, 14)) {
            uint64_t pid = 0;
            if (kq(e + vmm::g_off.pid, pid) && pid >= 0x64 && pid < 0x100000) {
                ++matches;
                t.eproc = e;
                t.pid = static_cast<uint32_t>(pid);
                // DTB comes from fill_target() after RPM is opened
                return true;   // first name match, defer PEB/LDR to fill_target()
            }
        }
        if (!vmm::kread_trusted(cur, &cur, 8)) break;
    }
    printf("[vmm] walked %d processes, %d name matches\n", n, matches);
    if (n < 50) printf("[vmm] WARN: short walk - links offset wrong\n");
    if (n >= 50 && !matches) printf("[vmm] WARN: no match - process may be unlinked\n");
    return false;
}

bool vmm::attach() {
    reset_fail_count();
    Target t{};
    if (!find_process_by_prefix("FortniteClient-", t)) return false;

    // Open RPM for user-space VA reads before PEB/LDR discovery.
    // read_user_va() dispatches to mem::read() when rpm backend is active.
    if (mem::active() == mem::backend::rpm && !mem::open_rpm(t.pid)) return false;

    // PEB/LDR discovery via mem::read() (rpm) or read_cr3() (phys walk).
    if (!fill_target(t.eproc, t.pid, t)) return false;

    // Capa 2: ntoskrnl base'i hedef CR3 altinda MZ ile karsilanmali.
    // read_cr3() fisik sayfa tablosu yaylasar. pm::read (PTE self-map remap)
    // etkinse her sayfa okunur, y compris PT sayfaları; bu durumda strict
    // dogrulama gerekir. pm yoksa degradation: DTB guvenilmez olarak isaretlenir.
    uint16_t mz = 0;
    bool cr3_ok = read_cr3(t.cr3, vmm::g_ntos, &mz, 2) && mz == 0x5A4D;

    if (pm::g_pm_ok) {
        // pm etkin: CR3 probe basarili olmali. Basarisizsa EPROCESS veya Peb
        // offseti yanlidir — degradation ile örtmez, düzelt.
        if (!cr3_ok) {
            printf("[!] CR3 MZ probe failed with pm active - EPROCESS/Peb "
                   "offsets may be wrong. Aborting attach.\n");
            return false;
        }
    } else if (!cr3_ok) {
        printf("[!] CR3 MZ probe failed (PT-page physical reads refused) - "
               "DTB UNVERIFIED (pm not available)\n");
    }

    vmm::g_target = t;
    vmm::g_gcr3 = t.cr3;
    vmm::g_eprocess = t.eproc;
    vmm::g_pid = t.pid;
    vmm::g_base = t.base;
    vmm::g_size = t.size;
    vmm::g_dtb_ok = cr3_ok;
    if (!vmm::g_kcr3) vmm::g_kcr3 = t.cr3;
    ++vmm::g_stamp;

    vmm::g_ready = true;

    printf("[vmm] attached pid=%u base=0x%llX size=0x%llX peb_ok=%s\n",
           t.pid, (unsigned long long)t.base, (unsigned long long)t.size,
           t.peb_ok ? "yes" : "no");
    return true;
}

void vmm::detach() { g_ready = false; g_gcr3 = 0; g_dtb_ok = false; ++g_stamp; }

bool vmm::attached() { return g_ready; }
uint32_t  vmm::pid()  { return g_pid; }
uint64_t  vmm::base() { return g_base; }
uint64_t  vmm::size() { return g_size; }
void      vmm::set_base(uint64_t b, uint64_t s) { g_base = b; g_size = s; }
bool      vmm::dtb_proven() { return g_dtb_ok; }


bool vmm::kread(uint64_t va, void* buf, size_t len) {
    if (!g_kcr3) return false;
    auto* p = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        const Walk st = walk_va(g_kcr3, va + i, pa);
        if (st != Walk::Ok) { report_fail("kread", g_kcr3, va + i, st); return false; }
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        if (!phys_read(pa, p + i, n)) {
            report_fail("kread(phys)", g_kcr3, va + i, Walk::PhysFail);
            return false;
        }
        i += n;
    }
    return true;
}

bool vmm::kread_trusted(uint64_t va, void* buf, size_t len) {
    if (!len) return false;
    if (va < 0xFFFF800000000000ull) return false;

    static bool probe_done = false;
    static bool probe_ok = false;
    if (!probe_done) {
        probe_done = true;
        probe_ok = g_ntos && r0::vread_probe(g_ntos, 2);
        if (probe_ok) printf("[+] kernel-VA read path proven\n");
        else printf("[!] kernel-VA read path NOT proven\n");
    }

    if (probe_ok) return r0::vread(va, buf, len);
    if (g_kcr3) return kread(va, buf, len);
    return false;
}

bool vmm::kwrite_trusted(uint64_t va, const void* buf, size_t len) {
    if (!len) return false;
    if (va < 0xFFFF800000000000ull) return false;

    if (r0::vread_ready() && r0::vwrite(va, buf, len)) return true;
    if (g_kcr3) return kwrite(va, buf, len);
    return false;
}



bool vmm::kwrite(uint64_t va, const void* buf, size_t len) {
    if (!g_kcr3) return false;
    auto* p = static_cast<const uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        const Walk st = walk_va(g_kcr3, va + i, pa);
        if (st != Walk::Ok) { report_fail("kwrite", g_kcr3, va + i, st); return false; }
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        if (!r0::vwrite(va + i, p + i, n)) return false;
        i += n;
    }
    return true;
}

bool vmm::read(uint64_t va, void* buf, size_t len) {
    if (!g_ready || va < kUserLo || va > kUserHi) return false;
    return mem::read(va, buf, len);
}

bool vmm::write(uint64_t va, const void* buf, size_t len) {
    if (!g_ready || va < kUserLo || va > kUserHi) return false;
    return mem::write(va, buf, len);
}

bool vmm::rd(uint64_t va, void* buf, size_t len) {
    if (!g_ready || !len || !buf) return false;
    if (va >= 0xFFFF800000000000ull) return kread_trusted(va, buf, len);
    if (va < kUserLo) return false;
    return read(va, buf, len);
}

bool vmm::present(uint64_t va) {
    uint64_t pa{};
    const Walk st = walk_va(g_gcr3, va, pa);
    if (st != Walk::Ok) report_fail("present", g_gcr3, va, st);
    return st == Walk::Ok;
}

bool vmm::prove_target_cr3() {
    if (!g_gcr3 || !g_ntos) return false;
    // ntoskrnl is a kernel VA mapped identically in every process.
    // safe_translate() reads through the current process's PTE self-map
    // (kernel-VA IOCTL), which works on Win11 26200 where physical PT reads
    // are refused. The physical address of ntoskrnl is CR3-independent.
    uint64_t pa{};
    if (!safe_translate(g_ntos, pa)) {
        printf("[!] target CR3 0x%llx cannot translate ntoskrnl via self-map\n",
               (unsigned long long)g_gcr3);
        return false;
    }
    if (!page_mz(pa & ~0xFFFull)) {
        printf("[!] target CR3 0x%llx maps ntoskrnl to 0x%llx but not MZ\n",
               (unsigned long long)g_gcr3, (unsigned long long)(pa & ~0xFFFull));
        return false;
    }
    g_dtb_ok = true;
    if (!g_kcr3) g_kcr3 = g_gcr3;
    return true;
}

static void raw_walk(const char* tag, uint64_t cr3, uint64_t va) {
    printf("[*] raw walk %s va=0x%llx cr3=0x%llx\n", tag,
           (unsigned long long)va, (unsigned long long)cr3);
    constexpr uint64_t kMask48 = 0x0000FFFFFFFFFFFFull;
    const uint64_t kPteBase = vmm::g_pte_base;
    const uint64_t m = va & kMask48;
    const uint64_t pde_base = kPteBase + ((kPteBase & kMask48) >> 9);
    const uint64_t ppe_base = kPteBase + ((pde_base & kMask48) >> 9);
    const uint64_t pxe_base = kPteBase + ((ppe_base & kMask48) >> 9);
    static const char* kName[4] = { "PML4E", "PDPTE", "PDE", "PTE" };
    const uint64_t kBases[4] = { pxe_base, ppe_base, pde_base, kPteBase };
    const uint64_t kShifts[4] = { 39, 30, 21, 12 };

    for (int i = 0; i < 4; ++i) {
        const uint64_t idx = (va >> kShifts[i]) & 0x1FF;
        const uint64_t entry_va = kBases[i] + idx * 8;
        uint64_t e{};
        if (!r0::vread(entry_va, &e, 8)) {
            printf("    %s[%llu] @0x%llx  READ FAILED\n",
                   kName[i], (unsigned long long)idx, (unsigned long long)entry_va);
            return;
        }
        printf("    %s[%llu] @0x%llx = 0x%016llx  present=%d ps=%d\n",
               kName[i], (unsigned long long)idx, (unsigned long long)entry_va,
               (unsigned long long)e, (e & 1) ? 1 : 0, (e & 0x80) ? 1 : 0);
        if (!(e & 1)) { printf("    -> chain stops here\n"); return; }
        if (e & 0x80) { printf("    -> large page, chain ends\n"); return; }
    }
    printf("    -> 4-level chain complete\n");
}

bool vmm::dump_cr3() {
    if (!g_eprocess || !g_ntos) return false;

    uint64_t dtb{};
    if (!kread_trusted(g_eprocess + g_lay.dtb, &dtb, 8)) {
        printf("[!] +0x%llx read failed\n", (unsigned long long)g_lay.dtb);
        return false;
    }
    printf("[*] EPROCESS 0x%llx pid %u\n", (unsigned long long)g_eprocess, g_pid);
    printf("[*] +0x%llx = 0x%016llx  page_aligned=%s  in_ram=%s\n",
           (unsigned long long)g_lay.dtb, (unsigned long long)dtb,
           (dtb & 0xFFF) ? "no" : "yes",
           phys_is_ram(dtb & kPteMask, 0x1000) ? "yes" : "no");

    const uint64_t c = dtb & kPteMask;
    if (!c) return false;
    raw_walk("ntoskrnl", c, g_ntos);

    uint64_t peb{};
    if (!read_cr3(c, g_eprocess + g_lay.peb, &peb, 8)) {
        printf("[!] PEB read through 0x%llx failed\n", (unsigned long long)c);
        return false;
    }
    printf("[*] PEB 0x%llx\n", (unsigned long long)peb);
    raw_walk("PEB+0x18", c, peb + 0x18);
    return true;
}

bool vmm::dtb_scan() {
    if (!g_eprocess || !g_ntos) return false;
    printf("[*] DTB offset scan, EPROCESS 0x%llx (pid %u), peb +0x%llx\n",
           (unsigned long long)g_eprocess, g_pid, (unsigned long long)g_lay.peb);

    for (uint64_t o = 0x20; o <= 0xF8; o += 8) {
        uint64_t v{};
        if (!kread_trusted(g_eprocess + o, &v, 8)) continue;
        const uint64_t c = v & kPteMask;
        if (!c || !phys_is_ram(c, 0x1000)) {
            printf("  +0x%02llx = 0x%016llx  (not a CR3)\n",
                   (unsigned long long)o, (unsigned long long)v);
            continue;
        }
        uint64_t kpa{};
        const bool ntos = walk_va(c, g_ntos, kpa) == Walk::Ok && page_mz(kpa);

        uint64_t peb{}, ldr{};
        const bool peb_read = read_cr3(c, g_eprocess + g_lay.peb, &peb, 8) &&
                              peb >= kUserLo && peb <= kUserHi;
        const bool peb_ok = peb_read && read_cr3(c, peb + 0x18, &ldr, 8) &&
                            ldr >= kUserLo && ldr <= kUserHi;

        printf("  +0x%02llx = 0x%016llx  ntoskrnl=%s peb=%s%s\n",
               (unsigned long long)o, (unsigned long long)v,
               ntos ? "ok" : "FAIL", peb_ok ? "ok" : "FAIL",
               (ntos && peb_ok) ? "   <== DTB" : "");

        if (ntos && (peb_ok || !peb_read)) {
            g_lay.dtb = o;
            g_gcr3 = c;
            g_dtb_ok = true;
            if (!g_kcr3) g_kcr3 = c;
            return true;
        }
    }
    printf("[!] no offset in 0x20..0xF8 produced a working CR3\n");
    return false;
}


