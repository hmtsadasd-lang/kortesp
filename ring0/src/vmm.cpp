#include "vmm.hpp"
#include "r0.hpp"
#include <windows.h>
#include <cstring>

namespace { constexpr uint64_t kUserLo=0x10000,kUserHi=0x7FFFFFFFFFFF,kPteMask=0x000FFFFFFFFFF000ull; }

bool translate_cr3(uint64_t cr3, uint64_t va, uint64_t& pa) {
    uint64_t page = va & ~0xFFFull;
    auto& e = g_tlb[(page >> 12) & (kTlb - 1)];
    if (e.page == page && e.stamp == g_stamp) { pa = e.phys + (va & 0xFFF); return true; }

    cr3 &= kPteMask;
    uint64_t t{}, next{}, phys{};
    bool big = false;

    if (!r0::pread(cr3 + 8 * ((va >> 39) & 0x1FF), &t, 8) || !(t & 1)) return false;
    next = t & kPteMask;

    if (!r0::pread(next + 8 * ((va >> 30) & 0x1FF), &t, 8) || !(t & 1)) return false;
    if (t & 0x80) { phys = (t & 0x000FFFFFC0000000ull) + (va & 0x3FFFFFFFull); big = true; }

    if (!big) {
        next = t & kPteMask;
        if (!r0::pread(next + 8 * ((va >> 21) & 0x1FF), &t, 8) || !(t & 1)) return false;
        if (t & 0x80) { phys = (t & 0x000FFFFFFFE00000ull) + (va & 0x1FFFFFull); big = true; }
    }
    if (!big) {
        next = t & kPteMask;
        if (!r0::pread(next + 8 * ((va >> 12) & 0x1FF), &t, 8) || !(t & 1)) return false;
        phys = (t & kPteMask) + (va & 0xFFF);
    }

    pa = phys;
    e.page = page; e.phys = phys & ~0xFFFull; e.stamp = g_stamp;
    return true;
}

bool ntoskrnl_from_user() {
    if (!resolve_query()) return false;
    ULONG need = 0;
    g_query(11, nullptr, 0, &need);
    if (!need) return false;

    void* buf = VirtualAlloc(nullptr, need, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return false;

    bool ok = g_query(11, buf, need, &need) == 0;
    if (ok) {
        auto* l = static_cast<ModuleList*>(buf);
        for (uint32_t i = 0; i < l->count && i < 512; ++i) {
            const char* p = reinterpret_cast<const char*>(l->mods[i].path);
            const char* n = strrchr(p, '\\');
            n = n ? n + 1 : p;
            if (_stricmp(n, "ntoskrnl.exe") == 0) {
                g_ntos = l->mods[i].base;
                g_ntos_size = l->mods[i].size;
                break;
            }
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    return g_ntos != 0;
}

bool find_kernel_cr3(uint64_t& out) {
    MEMORYSTATUSEX ms{ sizeof(ms) };
    if (!GlobalMemoryStatusEx(&ms)) return false;
    const uint64_t top = ms.ullTotalPhys + 0x10000000ull;

    for (uint64_t pa = 0x100000; pa < top; pa += 0x1000) {
        uint64_t e{};
        if (!r0::pread(pa + 8 * 256, &e, 8) || !(e & 1)) continue;
        if (e & 0x80) continue;

        uint64_t probe{};
        if (!translate_cr3(pa, g_ntos, probe)) continue;
        uint16_t mz{};
        if (!r0::pread(probe & ~0xFFFull, &mz, 2)) continue;
        if (mz == 0x5A4D) { out = pa; return true; }
    }
    return false;
}

bool looks_eprocess(uint64_t p, const vmm::Layout& l) {
    if (p < 0xFFFF800000000000ull || (p & 7)) return false;
    uint64_t pid{}, links{};
    char name[16]{};
    if (!vmm::kread(p + l.pid, &pid, 8) || pid != 4) return false;
    if (!vmm::kread(p + l.links, &links, 8) || !links) return false;
    if (!vmm::kread(p + l.name, name, sizeof(name))) return false;
    return memcmp(name, "System", 7) == 0;
}

bool find_system_eprocess() {
    static const vmm::Layout kCand[] = {
        { 0x1D0, 0x1D8, 0x338, 0x28 },
        { 0x440, 0x448, 0x5A8, 0x28 },
        { 0x440, 0x448, 0x5A8, 0x20 },
        { 0x2E8, 0x2F0, 0x450, 0x28 },
    };
    for (const auto& l : kCand) {
        for (uint64_t o = g_ntos_size / 2; o + 8 < g_ntos_size; o += 8) {
            uint64_t c{};
            if (!vmm::kread(g_ntos + o, &c, 8)) continue;
            if (!looks_eprocess(c, l)) continue;
            g_lay = l; g_eprocess = c;
            return true;
        }
    }
    return false;
}

namespace vmm {

bool kread(uint64_t va, void* buf, size_t len) {
    auto* p = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        if (!translate_cr3(g_kcr3, va + i, pa)) return false;
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        if (!r0::pread(pa, p + i, n)) return false;
        i += n;
    }
    return true;
}

bool kwrite(uint64_t va, const void* buf, size_t len) {
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

bool read(uint64_t va, void* buf, size_t len) {
    if (!g_ready || va < kUserLo || va > kUserHi) return false;
    auto* p = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        if (!translate_cr3(g_gcr3, va + i, pa)) return false;
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        if (!r0::pread(pa, p + i, n)) return false;
        i += n;
    }
    return true;
}

bool write(uint64_t va, const void* buf, size_t len) {
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

bool present(uint64_t va) { uint64_t pa{}; return g_ready && translate_cr3(g_gcr3, va, pa); }

bool init() {
    if (g_ready) return true;
    if (!r0::init()) return false;
    if (!ntoskrnl_from_user()) return false;
    if (!find_kernel_cr3(g_kcr3)) return false;
    if (!find_system_eprocess()) return false;
    return true;
}

void shutdown() { g_ready = false; g_gcr3 = 0; g_eprocess = 0; g_pid = 0; r0::shutdown(); }

bool attach(const wchar_t* image_name) {
    if (!g_eprocess) return false;
    char want[16]{};
    for (int i = 0; i < 15 && image_name[i]; ++i) want[i] = static_cast<char>(image_name[i]);

    uint64_t cur = g_eprocess;
    for (int guard = 0; guard < 4096; ++guard) {
        uint64_t fl{};
        if (!kread(cur + g_lay.links, &fl, 8) || !fl) break;
        cur = fl - g_lay.links;

        uint64_t pid{}; char name[16]{};
        if (!kread(cur + g_lay.pid, &pid, 8)) break;
        if (!kread(cur + g_lay.name, name, sizeof(name))) break;
        if (memcmp(name, want, 15) != 0) continue;

        uint64_t dtb{};
        if (!kread(cur + g_lay.dtb, &dtb, 8)) return false;
        g_gcr3 = dtb & kPteMask;
        g_eprocess = cur;
        g_pid = static_cast<uint32_t>(pid);
        g_ready = true;
        ++g_stamp;
        return true;
    }
    return false;
}

void detach() { g_ready = false; g_gcr3 = 0; ++g_stamp; }
bool attached() { return g_ready; }
uint32_t pid() { return g_pid; }
uint64_t base() { return g_base; }
uint64_t size() { return g_size; }
void set_base(uint64_t b, uint64_t s) { g_base = b; g_size = s; }

} // namespace vmm