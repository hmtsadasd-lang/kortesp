#include "cloak.hpp"
#include "vmm.hpp"
#include <windows.h>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

uint64_t g_head{};
uint64_t g_entry{};
uint64_t g_prev{};
uint64_t g_next{};
uint64_t g_our_base{};
bool     g_on{};

} // namespace

// Set by --driver-name. Overrides FORTESP_DRIVER_IMAGE / the stock name, so a
// renamed .sys still resolves. Must be decided before the service is created;
// see run_r0.bat. Held by value: the caller's string is often a temporary.
std::string g_driver_name;

// The image the driver was loaded under. Defaults to the stock name; the
// runner overrides it when it installs the driver under a different name.
const char* driver_image() {
    if (!g_driver_name.empty()) return g_driver_name.c_str();
    const char* e = getenv("FORTESP_DRIVER_IMAGE");
    if (e && *e) return e;
    return "dbutil_2_3.sys";
}

// ---- the module's list entry, found by scanning ntoskrnl's section table ----

bool valid_head(uint64_t h) {
    if (h < 0xFFFF800000000000ull || (h & 0xF) || h == g_head) return false;

    uint64_t b{};
    if (!vmm::kread(h + 8, &b, 8) || b != h) return false;

    uint64_t base{};
    if (!vmm::kread(h + 0x30, &base, 8) || base < 0x10000) return false;

    uint16_t mz{};
    if (!vmm::kread(base, &mz, 2) || !vmm::mz_ok(mz)) return false;

    uint64_t nb{};
    uint16_t nl{};
    if (!vmm::kread(h + 0x58, &nb, 8) || nb < 0x1000) return false;
    if (!vmm::kread(h + 0x60, &nl, 2) || nl < 4 || nl > 256) return false;

    return true;
}

bool find_head(uint64_t& head) {
    uint64_t rva{};
    if (vmm::export_rva("PsLoadedModuleList", rva)) {
        head = vmm::g_ntos + rva;
        if (valid_head(head)) return true;
    }

    // Section table read properly - IMAGE_FIRST_SECTION(&nt) on a stack-local
    // IMAGE_NT_HEADERS64 points past the struct, because the section table
    // follows OptionalHeader in the image and is not part of it. That bug made
    // this scan walk stack garbage as if it were section headers.
    std::vector<vmm::Section> secs;
    if (!vmm::sections(secs)) return false;

    for (const auto& s : secs) {
        if (!(s.chars & IMAGE_SCN_MEM_WRITE) || (s.chars & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (!s.size) continue;

        const uint64_t lo = vmm::g_ntos + s.va;
        const uint64_t hi = lo + s.size;

        // Bulk read: one IOCTL per 4 KiB page instead of one per qword (the
        // old code did 8 bytes per IOCTL *plus* ~5 more in valid_head for
        // every slot in .data - tens of thousands of round trips).
        //
        // Only qwords that could possibly be the list head's Flink are worth
        // validating: a kernel VA, 16-byte aligned (valid_head requires
        // h & 0xF == 0). That filter runs on the local buffer, so the ~5
        // dependent reads in valid_head happen for a handful of candidates.
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

// ---- our own driver's KLDR data table entry ----

bool cloak_init(uint64_t our_base) {
    g_our_base = our_base;
    g_on = true;
    return true;
}

void cloak_cleanup() {
    g_on = false;
}

// ---- the two writes that unlink the driver from PsLoadedModuleList ----

bool cloak_apply(bool commit) {
    // If the driver is already unlinked, just re-link and return.
    if (!g_on) return false;

    // neigh_1 = entry + FLINK offset, neigh_2 = entry + BLINK offset
    uint64_t neigh_1{};
    uint64_t neigh_2{};

    if (!vmm::kread(g_head + 0x10, &neigh_1, 8) || !vmm::kread(g_head + 0x18, &neigh_2, 8))
        return false;

    // If both neighbours already point at the entry, it is already unlinked.
    if (neigh_1 == g_head && neigh_2 == g_head) {
        // Clear the state file and return.
        g_on = false;
        return true;
    }

    // If exactly one neighbour points at the entry, complete the unlink.
    if (neigh_1 == g_head || neigh_2 == g_head) {
        // Complete the half-unlink by fixing the other neighbour.
        if (neigh_1 == g_head) {
            if (!vmm::kwrite(g_head + 0x18, &g_head, 8)) return false;
        } else {
            if (!vmm::kwrite(g_head + 0x10, &g_head, 8)) return false;
        }
        g_on = false;
        return true;
    }

    // Neither neighbour points at the entry: perform the full unlink.
    // Write: entry.Flink = next, entry.Blink = prev
    if (!vmm::kwrite(g_head + 0x10, &neigh_2, 8) || !vmm::kwrite(g_head + 0x18, &neigh_1, 8))
        return false;

    if (commit) {
        // Persist the state so --cloak-restore can re-link later.
        // ... (state persistence would go here)
    }

    g_on = false;
    return true;
}

// ---- remove the \??\DBUtil_2_3 symlink ----

// This is the name EAC is expected to name, and the only part of the
// surface removable without touching the driver. It is permanent for the
// boot, so it runs last: a later process cannot open the device by path
// (this one still can - its handle refers to the device object).
bool hide_symlink(const wchar_t* link) {
    // ... implementation would use NtMakeTemporaryObject etc.
    // For now, placeholder.
    return false;
}