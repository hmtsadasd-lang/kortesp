#include "cloak.hpp"
#include "vmm.hpp"
#include "r0.hpp"
#include <windows.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>

namespace cloak {

namespace {

uint64_t g_head{};
uint64_t g_our_base{};
bool     g_on{};
std::string g_driver_name;

constexpr uint32_t kStateMagic = 0x4B4C4F43;
constexpr uint32_t kStateVer   = 1;
struct State {
    uint32_t magic, ver;
    uint64_t entry, prev, next, ntos, eprocess;
};

bool state_path(wchar_t* out, size_t cch) {
    wchar_t exe[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (!n || n >= MAX_PATH) return false;
    wchar_t* slash = wcsrchr(exe, L'\\');
    if (!slash) return false;
    *(slash + 1) = 0;
    return swprintf(out, cch, L"%scloak.state", exe) > 0;
}

bool save_state(const State& s) {
    wchar_t p[MAX_PATH]{};
    if (!state_path(p, MAX_PATH)) return false;
    HANDLE h = CreateFileW(p, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD w = 0;
    WriteFile(h, &s, sizeof(s), &w, nullptr);
    CloseHandle(h);
    return w == sizeof(s);
}

bool load_state(State& s) {
    wchar_t p[MAX_PATH]{};
    if (!state_path(p, MAX_PATH)) return false;
    HANDLE h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD r = 0;
    const bool ok = ReadFile(h, &s, sizeof(s), &r, nullptr) && r == sizeof(s);
    CloseHandle(h);
    return ok && s.magic == kStateMagic && s.ver == kStateVer;
}

void drop_state() {
    wchar_t p[MAX_PATH]{};
    if (state_path(p, MAX_PATH)) DeleteFileW(p);
}

const char* driver_image_name() {
    if (!g_driver_name.empty()) return g_driver_name.c_str();
    const char* e = getenv("FORTESP_DRIVER_IMAGE");
    if (e && *e) return e;
    e = getenv("FORTESP_IMAGE");
    if (e && *e) return e;
    return "dbutil_2_3.sys";
}

// A trusted (kernel-VA) read is only safe for an address whose page is
// provably present. safe_translate() walks the PTE self-map and fails closed,
// so a decoy qword in ntoskrnl .data can no longer fault the driver's memmove
// (the 0x50 path).
bool safe_read(uint64_t va, void* buf, size_t len) {
    if (!len) return false;
    for (size_t i = 0; i < len; i += 0x1000) {
        uint64_t pa{};
        if (!vmm::safe_translate(va + i, pa)) return false;
    }
    return vmm::kread_trusted(va, buf, len);
}

bool valid_head(uint64_t h) {
    if (h < 0xFFFF800000000000ull || (h & 0xF)) return false;
    uint64_t flink{}, blink{};
    if (!safe_read(h, &flink, 8)) return false;
    if (!safe_read(h + 8, &blink, 8)) return false;
    if (flink < 0xFFFF800000000000ull || blink < 0xFFFF800000000000ull) return false;
    return true;
}

bool find_head(uint64_t& head) {
    uint64_t rva{};
    if (vmm::export_rva("PsLoadedModuleList", rva)) {
        head = vmm::g_ntos + rva;
        if (valid_head(head)) return true;
    }
    std::vector<vmm::Section> secs;
    if (!vmm::sections(secs)) return false;
    for (const auto& s : secs) {
        if (!(s.chars & IMAGE_SCN_MEM_WRITE) || (s.chars & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (!s.size) continue;
        const uint64_t lo = vmm::g_ntos + s.va;
        const uint64_t hi = lo + s.size;
        constexpr size_t kChunk = 0x1000;
        std::vector<uint8_t> buf(kChunk);
        for (uint64_t page = lo & ~0xFFFull; page < hi; page += kChunk) {
            size_t n = kChunk;
            if (page + n > hi) n = static_cast<size_t>(hi - page);
            if (!safe_read(page, buf.data(), n)) continue;
            for (size_t off = 0; off + 8 <= n; off += 8) {
                const uint64_t cand_addr = page + off;
                if (cand_addr < lo || cand_addr + 8 > hi) continue;
                uint64_t cand{};
                memcpy(&cand, buf.data() + off, 8);
                if (!valid_head(cand)) continue;
                head = cand;
                return true;
            }
        }
    }
    return false;
}

bool find_our_driver() {
    if (!g_head && !find_head(g_head)) return false;

    const char* want = driver_image();
    if (!want || !*want) return false;

    char lwant[128]{};
    for (size_t i = 0; want[i] && i < sizeof(lwant) - 1; ++i)
        lwant[i] = (want[i] >= 'A' && want[i] <= 'Z') ? static_cast<char>(want[i] + 32) : want[i];
    const size_t wl = strlen(lwant);

    uint64_t flink{};
    if (!safe_read(g_head, &flink, 8)) return false;
    uint64_t cur = flink;
    int seen = 0;
    for (int guard = 0; cur && cur != g_head && guard < 4096; ++guard) {
        ++seen;
        uint64_t dll_base{}, cur_flink{}, name_buf{};
        uint16_t nlen{};
        if (!safe_read(cur + 0x30, &dll_base, 8)) break;
        if (!safe_read(cur, &cur_flink, 8)) break;
        if (!safe_read(cur + 0x58, &nlen, 2)) break;
        if (!safe_read(cur + 0x60, &name_buf, 8)) break;

        if (name_buf >= 0xFFFF800000000000ull && nlen > 3 && nlen < 512) {
            wchar_t wname[256]{};
            const int chars = nlen / 2;
            if (chars < 255 && safe_read(name_buf, wname, nlen)) {
                char aname[256]{};
                for (int i = 0; i < chars; ++i)
                    aname[i] = wname[i] < 128 ? static_cast<char>(wname[i]) : '?';
                const char* tail = aname;
                for (const char* p = aname; *p; ++p)
                    if (*p == '\\' || *p == '/') tail = p + 1;
                char ltail[128]{};
                for (size_t i = 0; tail[i] && i < sizeof(ltail) - 1; ++i)
                    ltail[i] = (tail[i] >= 'A' && tail[i] <= 'Z')
                             ? static_cast<char>(tail[i] + 32) : tail[i];
                printf("[cloak] entry 0x%llx base=0x%llx name='%s'\n",
                       (unsigned long long)cur, (unsigned long long)dll_base, ltail);
                if (strlen(ltail) == wl && memcmp(ltail, lwant, wl) == 0) {
                    g_our_base = dll_base;
                    return true;
                }
            }
        }
        cur = cur_flink;
    }
    if (cur == g_head)
        printf("[cloak] walked %d modules - end of PsLoadedModuleList\n", seen);
    else
        printf("[cloak] walk stopped early at 0x%llx after %d modules (head=0x%llx)\n",
               (unsigned long long)cur, seen, (unsigned long long)g_head);
    return false;
}

} // namespace

const char* driver_image() { return driver_image_name(); }

bool module_base(uint64_t& base, uint32_t& size) {
    if (g_our_base == 0 && !find_our_driver()) return false;
    uint16_t mz{};
    if (!safe_read(g_our_base, &mz, 2) || mz != 0x5A4D) return false;
    uint32_t lfanew{};
    if (!safe_read(g_our_base + 0x3C, &lfanew, 4)) return false;
    if (lfanew < 0x40 || lfanew > 0x1000) return false;
    uint32_t img{};
    if (!safe_read(g_our_base + lfanew + 0x50, &img, 4)) return false;
    if (img < 0x1000 || img > (1u << 26)) return false;
    base = g_our_base;
    size = img;
    return true;
}

bool apply(bool commit) {
    if (!g_on) {
        printf("[!] cloak not initialised\n");
        return false;
    }
    if (commit && !r0::g_write_ok) {
        printf("[!] kernel write path not proven - refusing cloak\n");
        return false;
    }
    if (!r0::vread_ready()) {
        printf("[!] kernel-VA read not proven - refusing cloak\n");
        return false;
    }
    if (!vmm::g_ntos) {
        printf("[!] ntoskrnl base unknown - refusing cloak\n");
        return false;
    }
    if (!vmm::g_pte_base) {
        printf("[!] PTE self-map base not proven - refusing cloak\n");
        return false;
    }
    if (!g_head && !find_head(g_head)) {
        printf("[!] PsLoadedModuleList head not found\n");
        return false;
    }
    if (g_our_base == 0 && !find_our_driver()) {
        printf("[!] our driver's KLDR_DATA_TABLE_ENTRY not found (image '%s')\n",
               driver_image());
        return false;
    }

    uint64_t flink{};
    if (!safe_read(g_head, &flink, 8)) return false;
    uint64_t cur = flink;
    for (int guard = 0; cur && cur != g_head && guard < 4096; ++guard) {
        uint64_t dll_base{}, cur_flink{};
        if (!safe_read(cur + 0x30, &dll_base, 8)) break;
        if (!safe_read(cur, &cur_flink, 8)) break;
        if (dll_base != g_our_base) { cur = cur_flink; continue; }

        uint64_t cur_blink{};
        if (!safe_read(cur + 8, &cur_blink, 8)) return false;

        printf("[*] entry 0x%llx DllBase 0x%llx prev 0x%llx next 0x%llx\n",
               (unsigned long long)cur, (unsigned long long)dll_base,
               (unsigned long long)cur_blink, (unsigned long long)cur_flink);

        if (!commit) {
            printf("[*] dry run - nothing written\n");
            return true;
        }
        if (cur_blink < 0xFFFF800000000000ull || cur_flink < 0xFFFF800000000000ull) {
            printf("[!] neighbour is not a kernel VA\n");
            return false;
        }

        if (!vmm::kwrite_trusted(cur_blink, &cur_flink, 8)) {
            printf("[!] write prev->Flink failed\n");
            return false;
        }
        if (!vmm::kwrite_trusted(cur_flink + 8, &cur_blink, 8)) {
            printf("[!] write next->Blink failed\n");
            return false;
        }

        uint64_t a{}, b{};
        if (!safe_read(cur_blink, &a, 8) || !safe_read(cur_flink + 8, &b, 8) ||
            a != cur_flink || b != cur_blink) {
            printf("[!] read-back does not show an unlinked list\n");
            return false;
        }

        const State s{ kStateMagic, kStateVer, cur, cur_blink, cur_flink,
                       vmm::g_ntos, vmm::g_eprocess };
        save_state(s);
        g_on = false;
        printf("[+] driver unlinked from PsLoadedModuleList (state saved)\n");
        return true;
    }
    printf("[!] our driver's entry not found in PsLoadedModuleList\n");
    return false;
}

bool restore() {
    State s{};
    if (!load_state(s)) {
        printf("[!] no cloak.state next to the exe\n");
        return false;
    }
    if (s.ntos != vmm::g_ntos || s.eprocess != vmm::g_eprocess) {
        printf("[!] cloak.state belongs to another boot (ntos 0x%llx vs 0x%llx)\n",
               (unsigned long long)s.ntos, (unsigned long long)vmm::g_ntos);
        return false;
    }
    if (s.entry < 0xFFFF800000000000ull || s.prev < 0xFFFF800000000000ull ||
        s.next < 0xFFFF800000000000ull) {
        printf("[!] state holds a non-kernel address\n");
        return false;
    }

    uint64_t pf{}, nb{};
    if (!safe_read(s.prev, &pf, 8) || !safe_read(s.next + 8, &nb, 8)) return false;

    if (pf == s.entry && nb == s.entry) {
        printf("[*] list already re-linked - clearing state\n");
        drop_state();
        return true;
    }

    if (pf == s.next) {
        if (!vmm::kwrite_trusted(s.next + 8, &s.prev, 8)) return false;
    } else if (nb == s.prev) {
        if (!vmm::kwrite_trusted(s.prev, &s.next, 8)) return false;
    }

    if (!vmm::kwrite_trusted(s.prev, &s.entry, 8)) return false;
    if (!vmm::kwrite_trusted(s.next + 8, &s.entry, 8)) return false;

    uint64_t a{}, b{};
    if (!safe_read(s.prev, &a, 8) || !safe_read(s.next + 8, &b, 8) ||
        a != s.entry || b != s.entry) {
        printf("[!] read-back does not show a re-linked list\n");
        return false;
    }
    drop_state();
    printf("[+] driver re-linked\n");
    return true;
}

bool active() { return g_on; }

void set_driver_image(const char* name) {
    if (name && *name) g_driver_name = name;
}

bool cloak_init(const char* driver_image_name) {
    if (driver_image_name && *driver_image_name) g_driver_name = driver_image_name;
    g_our_base = 0;
    g_on = true;
    return true;
}

} // namespace cloak
