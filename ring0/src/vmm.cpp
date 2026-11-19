#include "vmm.hpp"
#include "offsets.hpp"
#include "r0.hpp"
#include <windows.h>
#include <cstring>
#include <cstdio>
#include <vector>
#include <algorithm>

std::array<vmm::TlbEntry, vmm::kTlbSize> vmm::g_tlb{};
uint32_t                                 vmm::g_stamp = 1;

uint64_t  vmm::g_kcr3 = 0;
uint64_t  vmm::g_gcr3 = 0;
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
        if (!r0::pread(cur, p + i, chunk)) return false;
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
               ? "  <- driver/map problem (did --dpatch run?)" : "");
}

bool va_canonical(uint64_t va) {
    const uint64_t sign = (va >> 47) & 1;
    return sign ? (va >> 48) == 0xFFFFull : (va >> 48) == 0;
}

vmm::Walk walk_va(uint64_t cr3, uint64_t va, uint64_t& pa) {
    cr3 &= vmm::kPteMask;
    if (!cr3 || !va_canonical(va)) return vmm::Walk::BadArgs;

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
    constexpr uint64_t kMask48 = 0x0000FFFFFFFFFFFFull;
    constexpr uint64_t kPteBase = 0xFFFFF68000000000ull;
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

namespace {

bool looks_eprocess(uint64_t p, const vmm::Layout& l) {
    if (p < 0xFFFF800000000000ull || (p & 7)) return false;

    uint64_t pid{};
    char name[16]{};
    if (!vmm::kread_trusted(p + l.pid, &pid, 8)) return false;
    if (pid != 4) return false;
    if (!vmm::kread_trusted(p + l.name, name, sizeof(name))) return false;
    if (memcmp(name, "System", 7) != 0) return false;

    uint64_t flink{}, blink{};
    if (!vmm::kread_trusted(p + l.links, &flink, 8)) return false;
    if (!vmm::kread_trusted(p + l.links + 8, &blink, 8)) return false;
    if (flink < 0xFFFF800000000000ull || blink < 0xFFFF800000000000ull) return false;
    uint64_t back{};
    if (!vmm::kread_trusted(flink + 8, &back, 8)) return false;
    if (back != p + l.links) return false;
    return true;
}

const vmm::Layout kCand[] = {
    { 0x1D0, 0x1D8, 0x338, 0x28, 0x2E0 },
    { 0x440, 0x448, 0x5A8, 0x28, 0x550 },
};

} // namespace

bool vmm::init_system() {

    if (g_eprocess) return true;
    if (!g_ntos) return false;

    uint64_t rva{};
    if (export_rva("PsInitialSystemProcess", rva) && rva + 8 <= g_ntos_size) {
        uint64_t ep{};
        if (kread_trusted(g_ntos + rva, &ep, sizeof(ep)) && ep) {
            for (const auto& l : kCand) {
                if (!looks_eprocess(ep, l)) continue;
                g_lay = l;
                g_eprocess = ep;
                printf("[+] System EPROCESS 0x%llx (layout pid 0x%llx links 0x%llx "
                       "name 0x%llx dtb 0x%llx peb 0x%llx)\n",
                       (unsigned long long)ep, (unsigned long long)l.pid,
                       (unsigned long long)l.links, (unsigned long long)l.name,
                       (unsigned long long)l.dtb, (unsigned long long)l.peb);
                return true;
            }
            printf("[!] PsInitialSystemProcess points at 0x%llx but no known layout "
                   "validates\n", (unsigned long long)ep);
        }
    }

    printf("[*] falling back to an ntoskrnl data-section scan for System\n");
    std::vector<Section> secs;
    if (!sections(secs)) return false;
    constexpr size_t kChunk = 0x1000;
    std::vector<uint8_t> buf(kChunk);

    for (const auto& s : secs) {
        if (!(s.chars & IMAGE_SCN_MEM_WRITE) || (s.chars & IMAGE_SCN_MEM_EXECUTE)) continue;
        const uint64_t lo = g_ntos + s.va;
        const uint64_t hi = lo + s.size;
        for (uint64_t page = lo & ~0xFFFull; page < hi; page += kChunk) {
            size_t n = kChunk;
            if (page + n > hi) n = static_cast<size_t>(hi - page);
            if (!kread_trusted(page, buf.data(), n)) continue;
            for (size_t off = 0; off + 8 <= n; off += 8) {
                const uint64_t cand_addr = page + off;
                if (cand_addr < lo || cand_addr + 8 > hi) continue;
                uint64_t cand{};
                memcpy(&cand, buf.data() + off, 8);
                if (cand < 0xFFFF800000000000ull || (cand & 7)) continue;
                for (const auto& l : kCand) {
                    if (!looks_eprocess(cand, l)) continue;
                    g_lay = l;
                    g_eprocess = cand;
                    printf("[+] System EPROCESS 0x%llx (scan)\n", (unsigned long long)cand);
                    return true;
                }
            }
        }
    }
    return false;
}

bool vmm::init_ntos() {
    if (g_ntos) return true;
    phys_map_init();
    if (!find_ntoskrnl(g_ntos, g_ntos_size)) {
        printf("[!] ntoskrnl base not found in SystemModuleInformation\n"
               "    (SeDebugPrivilege must be enabled or ImageBase reads as 0)\n");
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

static void accept_candidate(uint64_t c, uint64_t o, uint64_t pid,
                             uint64_t eproc, const char* how) {
    vmm::g_gcr3 = c;
    vmm::g_eprocess = eproc;
    vmm::g_pid = static_cast<uint32_t>(pid);
    vmm::g_ready = true;
    vmm::g_dtb_ok = true;
    vmm::g_lay.dtb = o;
    if (!vmm::g_kcr3) vmm::g_kcr3 = c;
    ++vmm::g_stamp;
    printf("[+] attached pid %u eprocess 0x%llx dtb 0x%llx (+0x%llx) (%s)\n",
           vmm::g_pid, (unsigned long long)eproc, (unsigned long long)c,
           (unsigned long long)o, how);
}

bool vmm::attach(const wchar_t* image_name) {
    if (!g_eprocess) return false;
    reset_fail_count();

    char want_full[256]{};
    for (int i = 0; i < 255 && image_name[i]; ++i)
        want_full[i] = static_cast<char>(image_name[i] > 0x7F ? '?' : image_name[i]);

    char want15[256]{};
    memcpy(want15, want_full, 14);
    want15[14] = 0;

    int names = 0, rejected = 0;
    uint64_t cur = g_eprocess;
    for (int guard = 0; guard < 4096; ++guard) {
        uint64_t flink{};
        if (!kread_trusted(cur + g_lay.links, &flink, 8) || !flink) break;
        cur = flink - g_lay.links;

        uint64_t pid{}; char name[256]{};
        if (!kread_trusted(cur + g_lay.pid, &pid, 8)) break;
        if (!kread_trusted(cur + g_lay.name, name, sizeof(name))) break;
        if (_strnicmp(name, want15, strlen(want15)) != 0) continue;
        if (pid == 0 || pid == 4) continue;
        ++names;

        bool matched = false;
        for (uint64_t o = 0x20; o <= 0xF8; o += 8) {
            uint64_t dtb{};
            if (!kread_trusted(cur + o, &dtb, 8)) continue;
            const uint64_t c = dtb & kPteMask;
            if (!c) continue;

            bool ntos_ok = false;
            if (g_ntos) {
                uint64_t kpa{};
                ntos_ok = walk_va(c, g_ntos, kpa) == Walk::Ok && page_mz(kpa);
            }
            const bool peb_ok = peb_has_module(cur, c, want_full);
            if (!ntos_ok && !peb_ok) continue;

            accept_candidate(c, o, pid, cur,
                ntos_ok && peb_ok ? "ntoskrnl + PEB module proven"
                                  : peb_ok ? "PEB module proven" : "ntoskrnl proven only");
            matched = true;
            break;
        }
        if (matched) return true;
        ++rejected;
    }

    printf("[!] attach: %d name match(es), %d rejected, none usable\n", names, rejected);
    return false;
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
    auto* p = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        const Walk st = walk_va(g_gcr3, va + i, pa);
        if (st != Walk::Ok) { report_fail("read", g_gcr3, va + i, st); return false; }
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        if (!phys_read(pa, p + i, n)) {
            report_fail("read(phys)", g_gcr3, va + i, Walk::PhysFail);
            return false;
        }
        i += n;
    }
    return true;
}

bool vmm::write(uint64_t va, const void* buf, size_t len) {
    if (!g_ready || va < kUserLo || va > kUserHi) return false;
    auto* p = static_cast<const uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        const Walk st = walk_va(g_gcr3, va + i, pa);
        if (st != Walk::Ok) { report_fail("write", g_gcr3, va + i, st); return false; }
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        if (!r0::pwrite(pa, p + i, n)) return false;
        i += n;
    }
    return true;
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
    uint64_t pa{};
    const Walk st = walk_va(g_gcr3, g_ntos, pa);
    if (st != Walk::Ok) {
        printf("[!] target CR3 0x%llx does not map ntoskrnl: %s\n",
               (unsigned long long)g_gcr3, walk_name(st));
        return false;
    }
    if (!page_mz(pa)) {
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
    static const int kShift[4] = { 39, 30, 21, 12 };
    static const char* kName[4] = { "PML4E", "PDPTE", "PDE", "PTE" };

    uint64_t tbl = cr3 & vmm::kPteMask;
    for (int i = 0; i < 4; ++i) {
        const uint64_t idx = (va >> kShift[i]) & 0x1FF;
        const uint64_t at = tbl + 8 * idx;
        uint64_t e{};
        if (!phys_read(at, &e, 8)) {
            printf("    %s[%llu] @0x%llx  READ FAILED\n", kName[i],
                   (unsigned long long)idx, (unsigned long long)at);
            return;
        }
        printf("    %s[%llu] @0x%llx = 0x%016llx  present=%d ps=%d\n", kName[i],
               (unsigned long long)idx, (unsigned long long)at,
               (unsigned long long)e, !!(e & 1), !!(e & 0x80));
        if (!(e & 1)) { printf("    -> chain stops here\n"); return; }
        if (e & 0x80) { printf("    -> large page, chain ends\n"); return; }
        tbl = e & vmm::kPteMask;
    }
    printf("    -> leaf 0x%llx\n", (unsigned long long)(tbl + (va & 0xFFF)));
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


