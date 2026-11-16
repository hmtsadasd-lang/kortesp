#include "cloak.hpp"
#include "vmm.hpp"
#include <windows.h>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

namespace cloak {

namespace {

uint64_t g_head{};
uint64_t g_our_base{};
bool     g_on{};

std::string g_driver_name;

const char* driver_image() {
    if (!g_driver_name.empty()) return g_driver_name.c_str();
    const char* e = getenv("FORTESP_DRIVER_IMAGE");
    if (e && *e) return e;
    e = getenv("FORTESP_IMAGE");
    if (e && *e) return e;
    return "dbutil_2_3.sys";
}

bool valid_head(uint64_t h) {
    if (h < 0xFFFF800000000000ull || (h & 0xF)) return false;
    uint64_t flink{}, blink{};
    if (!vmm::kread_trusted(h, &flink, 8)) return false;
    if (!vmm::kread_trusted(h + 8, &blink, 8)) return false;
    if (flink < 0xFFFF800000000000ull || blink < 0xFFFF800000000000ull)
        return false;
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
            if (!vmm::kread_trusted(page, buf.data(), n)) continue;
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
    if (!g_head) {
        if (!find_head(g_head)) return false;
    }
    const char* our_name = driver_image();
    if (!our_name || !*our_name) return false;

    printf("[DEBUG] find_our_driver: our_name=%s\n", our_name);

    // Build wide-char version of our driver name (just the filename part)
    wchar_t our_name_w[128]{};
    size_t len = strlen(our_name);
    for (size_t i = 0; i < len && i < 127; i++) {
        our_name_w[i] = static_cast<wchar_t>(our_name[i]);
    }
    size_t our_len = strlen(our_name);

    uint64_t flink{};
    if (!vmm::kread_trusted(g_head, &flink, 8)) return false;

    uint64_t cur = flink;
    int guard = 0;
    while (cur != g_head && cur != 0 && guard++ < 4096) {
        uint64_t dll_base{};
        uint64_t cur_flink{};
        if (!vmm::kread_trusted(cur + 0x30, &dll_base, 8)) break;
        if (!vmm::kread_trusted(cur, &cur_flink, 8)) break;

        uint64_t base_dll_name_buffer{};
        if (!vmm::kread_trusted(cur + 0x58, &base_dll_name_buffer, 8)) break;
        if (!base_dll_name_buffer || base_dll_name_buffer < 0xFFFF800000000000ull) break;

        wchar_t base_name[128]{};
        if (!vmm::kread_trusted(base_dll_name_buffer, base_name, sizeof(base_name) - 2)) break;

        printf("[DEBUG] walk: cur=0x%llx dll_base=0x%llx name=",
               (unsigned long long)cur, (unsigned long long)dll_base);
        for (size_t i = 0; i < 127 && base_name[i]; i++) printf("%lc", base_name[i]);
        printf("\n");

        // Case-insensitive suffix match: BaseDllName may be full path like
        // \SystemRoot\System32\drivers\dbx64.sys
        size_t blen = 0;
        while (blen < 127 && base_name[blen]) blen++;

        size_t start = blen;
        while (start > 0 && base_name[start - 1] != L'\\' && base_name[start - 1] != L'/') start--;

        bool match = true;
        size_t j = 0;
        for (size_t i = start; i < blen && our_name_w[j]; i++, j++) {
            wchar_t c1 = base_name[i];
            wchar_t c2 = our_name_w[j];
            if (c1 >= L'A' && c1 <= L'Z') c1 = c1 - L'A' + L'a';
            if (c2 >= L'A' && c2 <= L'Z') c2 = c2 - L'A' + L'a';
            if (c1 != c2) { match = false; break; }
        }
        if (match && our_name_w[j] == 0) {
            g_our_base = dll_base;
            return true;
        }

        cur = cur_flink;
    }
    return false;
}

} // namespace

bool apply(bool commit) {
    if (!g_on) return false;
    if (!g_head) {
        if (!find_head(g_head)) return false;
    }
    if (g_our_base == 0) {
        if (!find_our_driver()) {
            printf("[!] our driver's KLDR_DATA_TABLE_ENTRY not found\n");
            return false;
        }
    }
    uint64_t flink{};
    if (!vmm::kread_trusted(g_head, &flink, 8)) return false;
    uint64_t cur = flink;
    while (cur != g_head && cur != 0) {
        uint64_t dll_base{};
        uint64_t cur_flink{};
        if (!vmm::kread_trusted(cur + 0x30, &dll_base, 8)) break;
        if (!vmm::kread_trusted(cur, &cur_flink, 8)) break;
        if (dll_base == g_our_base) {
            uint64_t cur_blink{};
            if (!vmm::kread_trusted(cur + 8, &cur_blink, 8)) return false;
            if (!commit) {
                printf("[*] dry run: would unlink driver entry at 0x%llx (DllBase=0x%llx)\n",
                       (unsigned long long)cur, (unsigned long long)dll_base);
                return true;
            }
            if (!vmm::kwrite_trusted(cur_blink, &cur_flink, 8)) return false;
            if (!vmm::kwrite_trusted(cur_flink + 8, &cur_blink, 8)) return false;
            g_on = false;
            return true;
        }
        cur = cur_flink;
    }
    printf("[!] our driver's entry not found in PsLoadedModuleList\n");
    return false;
}

bool restore() {
    g_on = false;
    return true;
}

bool active() {
    return g_on;
}

void set_driver_image(const char* name) {
    if (name && *name) g_driver_name = name;
}

bool cloak_init(const char* driver_image_name) {
    if (driver_image_name && *driver_image_name) {
        g_driver_name = driver_image_name;
    }
    g_our_base = 0;
    g_on = true;
    return true;
}

bool hide_symlink(const wchar_t* link) {
    return false;
}

} // namespace cloak