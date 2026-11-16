#include "cloak.hpp"
#include "vmm.hpp"
#include <windows.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

constexpr uint64_t kKvaLo = 0xFFFF800000000000ull;
constexpr uint64_t kLde_DllBase  = 0x30;
constexpr uint64_t kLde_BaseName = 0x58;

uint64_t g_head{};
uint64_t g_entry{};
uint64_t g_prev{};
uint64_t g_next{};
uint64_t g_our_base{};
bool     g_on{};

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

// ---- the module's own base, straight from the kernel module list ----------
// Name-suffix match, so a renamed image still resolves as long as the caller
// tells us what it was renamed to. Returns 0 if the driver is not loaded,
// which is the only case where cloak can legitimately do nothing.
uint64_t our_base() {
    HMODULE n = GetModuleHandleW(L"ntdll.dll");
    if (!n) return 0;
    using Q = LONG(__stdcall*)(ULONG, void*, ULONG, ULONG*);
    auto q = reinterpret_cast<Q>(GetProcAddress(n, "NtQuerySystemInformation"));
    if (!q) return 0;

    ULONG need = 0;
    q(11, nullptr, 0, &need);
    if (!need) return 0;

    void* buf = VirtualAlloc(nullptr, need, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 0;

    uint64_t base = 0;
    if (q(11, buf, need, &need) == 0) {
        struct E {
            uint64_t section, mapped, image_base, image_size;
            uint32_t flags;
            uint16_t a, b, c, d;
            uint8_t path[256];
        };
        struct L { uint32_t count; uint32_t pad; E e[1]; };

        const char* want = driver_image();
        const size_t wl = strlen(want);

        auto* l = static_cast<L*>(buf);
        for (uint32_t i = 0; i < l->count && i < 512; ++i) {
            const char* p = reinterpret_cast<const char*>(l->e[i].path);
            const size_t len = strlen(p);
            if (len < wl) continue;

            bool same = true;
            for (size_t k = 0; k < wl; ++k) {
                char a = p[len - wl + k], b = want[k];
                if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + 32);
                if (b >= 'A' && b <= 'Z') b = static_cast<char>(b + 32);
                if (a != b) { same = false; break; }
            }
            if (same) { base = l->e[i].image_base; break; }
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    return base;
}

// ---- locating PsLoadedModuleList -----------------------------------------
// It is not exported on 26200 any more, so the export is only a fast path.
// The fallback scans ntoskrnl's writable, non-executable sections for a
// LIST_ENTRY whose first entry validates as a real module.
bool valid_head(uint64_t h) {
    uint64_t f{};
    if (!vmm::kread(h, &f, 8)) return false;
    if (f < kKvaLo || (f & 0xF) || f == h) return false;

    uint64_t b{};
    if (!vmm::kread(f + 8, &b, 8) || b != h) return false;

    uint64_t base{};
    if (!vmm::kread(f + kLde_DllBase, &base, 8) || base < 0x10000) return false;
    uint16_t mz{};
    if (!vmm::kread(base, &mz, 2) || mz != 0x5A4D) return false;

    uint64_t nb{};
    uint16_t nl{};
    if (!vmm::kread(f + kLde_BaseName + 8, &nb, 8) || nb < kKvaLo) return false;
    if (!vmm::kread(f + kLde_BaseName, &nl, 2) || nl < 4 || nl > 256) return false;

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
        // f & 0xF == 0). That filter runs on the local buffer, so the ~5
        // dependent reads in valid_head happen for a handful of candidates.
        constexpr size_t kChunk = 0x1000;
        std::vector<uint8_t> buf(kChunk);
        for (uint64_t page = lo & ~0xFFFull; page < hi; page += kChunk) {
            size_t n = kChunk;
            if (page + n > hi) n = static_cast<size_t>(hi - page);
            if (!vmm::kread(page, buf.data(), n)) continue;   // hole - skip

            for (size_t off = 0; off + 8 <= n; off += 8) {
                const uint64_t cand = page + off;
                if (cand < lo || cand + 8 > hi) continue;
                uint64_t v{};
                memcpy(&v, buf.data() + off, 8);
                if (v < kKvaLo || (v & 0xF)) continue;
                if (!valid_head(cand)) continue;
                head = cand;
                return true;
            }
        }
    }
    return false;
}

} // namespace

namespace cloak {

Plan g_plan{};

const Plan& plan() { return g_plan; }
bool active() { return g_on; }

void set_driver_image(const char* name) {
    if (name && *name) g_driver_name = name;
    else g_driver_name.clear();
}

// ---------------------------------------------------------------------------
// Persisted unlink state.
//
// After the commit, the entry is no longer reachable from PsLoadedModuleList,
// so a *separate* process cannot find it again by walking the list. Without a
// record, --cloak-restore would resolve nothing and silently do nothing.
// Write the five addresses the unlink touched, plus the ntoskrnl base so a
// stale file from before a Windows update is rejected.
// ---------------------------------------------------------------------------
namespace {

constexpr uint32_t kStateMagic = 0x434B4C52;   // 'RLCK'
constexpr uint32_t kStateVer   = 1;

struct State {
    uint32_t magic;
    uint32_t ver;
    uint64_t entry;
    uint64_t prev;
    uint64_t next;
    uint64_t ntos;
    uint64_t system_eprocess;   // changes every boot; rejects a stale file
};

// <exe dir>\cloak.state - next to the binary, not in the cwd, so the runner
// and a manual invocation see the same file.
bool state_path(wchar_t* out, size_t cch) {
    wchar_t exe[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (!n || n >= MAX_PATH) return false;
    wchar_t* slash = wcsrchr(exe, L'\\');
    if (!slash) return false;
    *(slash + 1) = 0;
    return swprintf(out, cch, L"%scloak.state", exe) > 0;
}

bool save_state() {
    wchar_t path[MAX_PATH]{};
    if (!state_path(path, MAX_PATH)) return false;
    const State s{ kStateMagic, kStateVer, g_entry, g_prev, g_next,
                   vmm::g_ntos, vmm::g_eprocess };
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD w = 0;
    const bool ok = WriteFile(h, &s, sizeof(s), &w, nullptr) && w == sizeof(s);
    CloseHandle(h);
    return ok;
}

bool load_state(State& s) {
    wchar_t path[MAX_PATH]{};
    if (!state_path(path, MAX_PATH)) return false;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD r = 0;
    const bool ok = ReadFile(h, &s, sizeof(s), &r, nullptr) && r == sizeof(s);
    CloseHandle(h);
    return ok && s.magic == kStateMagic && s.ver == kStateVer &&
           s.ntos == vmm::g_ntos && s.system_eprocess == vmm::g_eprocess;
}

void delete_state() {
    wchar_t path[MAX_PATH]{};
    if (state_path(path, MAX_PATH)) DeleteFileW(path);
}

} // namespace

bool apply(bool commit) {
    if (g_on) return true;

    g_plan = Plan{};

    g_our_base = our_base();
    if (!g_our_base) {
        printf("[cloak] driver module \"%s\" not found in the kernel module list\n",
               driver_image());
        return false;
    }

    if (!find_head(g_head)) return false;

    uint64_t cur{};
    if (!vmm::kread(g_head, &cur, 8) || !cur) return false;

    for (int guard = 0; guard < 512 && cur != g_head; ++guard) {
        const uint64_t entry = cur;

        uint64_t base{};
        if (vmm::kread(entry + kLde_DllBase, &base, 8) && base == g_our_base) {
            // KLDR_DATA_TABLE_ENTRY has exactly ONE list: InLoadOrderLinks at
            // +0x00. There is no InMemoryOrderLinks - that belongs to the
            // USER-MODE LDR_DATA_TABLE_ENTRY. Unlinking a "memory order"
            // link here would write into ExceptionTable/ExceptionTableSize
            // (+0x10/+0x18) and bugcheck the machine.
            uint64_t next{}, prev{};
            if (!vmm::kread(entry + 0x00, &next, 8)) return false;
            if (!vmm::kread(entry + 0x08, &prev, 8)) return false;

            // The neighbours must be kernel addresses. A wrong list head
            // would otherwise have us write the entry pointer into an
            // arbitrary kernel address.
            if (prev < kKvaLo || next < kKvaLo) return false;

            g_entry = entry;
            g_prev = prev;
            g_next = next;

            g_plan.head      = g_head;
            g_plan.entry     = entry;
            g_plan.load_prev = prev;
            g_plan.load_next = next;
            g_plan.dll_base  = base;
            g_plan.found     = true;

            if (!commit) {
                printf("[cloak] DRY RUN - nothing written.\n");
                printf("[cloak]   PsLoadedModuleList head : 0x%llx\n", (unsigned long long)g_head);
                printf("[cloak]   our KLDR entry          : 0x%llx\n", (unsigned long long)entry);
                printf("[cloak]   DllBase                 : 0x%llx\n", (unsigned long long)base);
                printf("[cloak]   prev / next             : 0x%llx / 0x%llx\n",
                       (unsigned long long)prev, (unsigned long long)next);
                printf("[cloak]   would write 0x%llx <- 0x%llx   (prev.Flink = next)\n",
                       (unsigned long long)prev, (unsigned long long)next);
                printf("[cloak]   would write 0x%llx <- 0x%llx   (next.Blink = prev)\n",
                       (unsigned long long)next + 8, (unsigned long long)prev);
                printf("[cloak] re-run with --cloak-commit to actually unlink.\n");
                return true;
            }

            // ---- the only kernel writes in the whole tool ----
            // Two writes. The kernel-VA path (memmove on the cached mapping),
            // not the physical one - MmMapIoSpace(MmNonCached) would leave
            // stale lines in the cores that are reading this list.
            if (!vmm::kwrite(prev, &next, 8)) {              // prev.Flink = next
                printf("[cloak] FATAL: first unlink write failed - nothing changed. Reboot.\n");
                return false;
            }
            if (!vmm::kwrite(next + 8, &prev, 8)) {          // next.Blink = prev
                // The list is now half-unlinked: prev skips us, we still point
                // at next, and next still points back at us. Put prev back so
                // a walk from the head does not dead-end.
                printf("[cloak] FATAL: second unlink write failed - list is half-unlinked.\n");
                if (vmm::kwrite(prev, &entry, 8))
                    printf("[cloak] rolled prev.Flink back to the entry; reboot before retrying.\n");
                else
                    printf("[cloak] rollback failed too. REBOOT NOW.\n");
                return false;
            }

            // Read it back rather than trusting the write. Both writes are 8
            // bytes into pool that is mapped and readable by construction, so
            // a mismatch here means the kernel-VA path is wrong.
            uint64_t pf{}, nb{};
            if (!vmm::kread(prev, &pf, 8) || pf != next ||
                !vmm::kread(next + 8, &nb, 8) || nb != prev) {
                printf("[cloak] FATAL: unlink read-back mismatch (prev=0x%llx next=0x%llx)\n",
                       (unsigned long long)pf, (unsigned long long)nb);
                if (vmm::kwrite(prev, &entry, 8) && vmm::kwrite(next + 8, &entry, 8))
                    printf("[cloak] re-linked both sides; treat the write path as broken.\n");
                else
                    printf("[cloak] could not re-link. REBOOT NOW.\n");
                return false;
            }

            // Record what was unlinked. A later process cannot rediscover the
            // entry, so without this file --cloak-restore has nothing to use.
            // Failure to write it is not fatal to the unlink itself.
            if (!save_state())
                printf("[cloak] warning: could not write cloak.state - restore will not be possible\n");

            g_on = true;
            return true;
        }

        if (!vmm::kread(cur, &cur, 8) || !cur) return false;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Re-link the entry. Works both in the process that unlinked it (globals set)
// and in a fresh process (state file), because after the unlink the entry is
// unreachable from PsLoadedModuleList and cannot be rediscovered by walking.
//
// Before writing, classify the list from its two links. Fully unlinked and
// "nothing was written" are both safe endpoints (the latter just needs the
// stale state file cleared). The half-unlinked state - a crash between the two
// commit writes - is completed first, because re-linking from it would leave
// one neighbour pointing at the entry and the other not. Anything else means
// the state file is stale or the kernel moved things, and is refused.
// ---------------------------------------------------------------------------
bool restore() {
    uint64_t entry{}, prev{}, next{};

    if (g_on && g_entry && g_prev && g_next) {
        entry = g_entry;
        prev  = g_prev;
        next  = g_next;
    } else {
        State s{};
        if (!load_state(s)) {
            printf("[cloak] no usable cloak.state - nothing to restore "
                   "(wrong session, or the image was never cloaked here)\n");
            return false;
        }
        entry = s.entry;
        prev  = s.prev;
        next  = s.next;
    }

    if (entry < kKvaLo || prev < kKvaLo || next < kKvaLo) {
        printf("[cloak] state rejected: addresses are not kernel VAs\n");
        return false;
    }

    uint64_t pf{}, nb{};
    if (!vmm::kread(prev, &pf, 8) || !vmm::kread(next + 8, &nb, 8)) {
        printf("[cloak] state rejected: cannot read the neighbours\n");
        return false;
    }

    // Three states are possible, because the commit is two writes and a
    // process can die between them:
    //
    //   a && b      fully unlinked      (both neighbours skip the entry)
    //   !a && !b    nothing was written (both still point at the entry)
    //   a != b      half-unlinked       (exactly one write landed)
    //
    // Re-linking from the half state would leave one neighbour pointing at the
    // entry and the other not, i.e. a broken list. Finish the unlink first
    // (idempotent from either half), then re-link from a coherent state.
    const bool a = (pf == next);
    const bool b = (nb == prev);

    if (!a && !b) {
        if (pf != entry || nb != entry) {
            printf("[cloak] state rejected: neighbours point at neither the entry "
                   "nor each other - cloak.state is stale\n");
            printf("[cloak]   prev.Flink = 0x%llx (expected 0x%llx)\n",
                   (unsigned long long)pf, (unsigned long long)entry);
            printf("[cloak]   next.Blink = 0x%llx (expected 0x%llx)\n",
                   (unsigned long long)nb, (unsigned long long)entry);
            return false;
        }
        printf("[cloak] list is already linked - clearing the stale state file\n");
        g_on = false;
        delete_state();
        return true;
    }

    if (a != b) {
        printf("[cloak] half-unlinked list (prev.Flink %s entry, next.Blink %s entry)\n",
               a ? "skips" : "points at", b ? "skips" : "points at");
        printf("[cloak] completing the unlink before re-linking\n");
        if (!a && !vmm::kwrite(prev, &next, 8)) {        // prev.Flink = next
            printf("[cloak] could not finish the unlink at prev.Flink. REBOOT NOW.\n");
            return false;
        }
        if (!b && !vmm::kwrite(next + 8, &prev, 8)) {    // next.Blink = prev
            printf("[cloak] could not finish the unlink at next.Blink. REBOOT NOW.\n");
            return false;
        }
        if (!vmm::kread(prev, &pf, 8) || !vmm::kread(next + 8, &nb, 8) ||
            pf != next || nb != prev) {
            printf("[cloak] FATAL: list is still half-unlinked after the completion "
                   "writes. REBOOT NOW.\n");
            return false;
        }
    }

    // Fully unlinked: re-link with the same kernel-VA write path the unlink used.
    if (!vmm::kwrite(prev, &entry, 8)) {                    // prev.Flink = entry
        printf("[cloak] re-link write failed at prev.Flink. REBOOT NOW.\n");
        return false;
    }
    if (!vmm::kwrite(next + 8, &entry, 8)) {                // next.Blink = entry
        printf("[cloak] re-link write failed at next.Blink. REBOOT NOW.\n");
        return false;
    }

    // Confirm both sides took, rather than assuming.
    if (!vmm::kread(prev, &pf, 8) || pf != entry ||
        !vmm::kread(next + 8, &nb, 8) || nb != entry) {
        printf("[cloak] re-link read-back mismatch (prev=0x%llx next=0x%llx). REBOOT NOW.\n",
               (unsigned long long)pf, (unsigned long long)nb);
        return false;
    }

    g_on = false;
    delete_state();
    printf("[cloak] re-linked entry 0x%llx between 0x%llx and 0x%llx\n",
           (unsigned long long)entry, (unsigned long long)prev,
           (unsigned long long)next);
    return true;
}

} // namespace cloak