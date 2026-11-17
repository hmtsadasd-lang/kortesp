#pragma once
#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>

namespace vmm {

// ---- simple 3D vector -----------------------------------------------------
struct Vec3 { double x, y, z; };

enum class PteFlags : uint64_t {
    Present   = 1,
    Write     = 2,
    User      = 4,
    WriteThrough = 8,
    CacheDisable = 16,
    Accessed   = 0x20,
    Dirty      = 0x40,
    LargePage = 0x80,
    Gigantic  = 0x8000000000000000ull
};

inline constexpr uint64_t kUserLo = 0x10000;
inline constexpr uint64_t kUserHi = 0x7FFFFFFFFFFF;
inline constexpr uint64_t kPteMask  = 0x000FFFFFFFFFF000ull;
inline constexpr size_t kTlbSize    = 16;

struct TlbEntry {
    uint64_t page;   // VA page base
    uint64_t phys;   // PA page base
    uint64_t cr3;    // owning CR3 - a scan walks many CR3s at the same VA
    uint32_t stamp;  // bumped on attach/detach
};
extern std::array<TlbEntry, kTlbSize> g_tlb;
extern uint32_t g_stamp;

// Global state
extern uint64_t  g_kcr3;
extern uint64_t  g_gcr3;
extern uint64_t  g_base;
extern uint64_t  g_size;
extern uint64_t  g_eprocess;
extern uint64_t  g_ntos;      // ntoskrnl base
extern uint64_t  g_ntos_size; // ntoskrnl image size
extern uint32_t  g_pid;
extern bool      g_ready;
extern bool      g_attached;
extern bool      g_dtb_ok;      // target CR3 proven: ntoskrnl + PEB translate

// Layout for EPROCESS field walks
struct Layout {
    uint64_t pid;
    uint64_t links;   // offset of the LIST_ENTRY inside the EPROCESS
    uint64_t name;    // ImageFileName
    uint64_t dtb;     // DirectoryTableBase
    uint64_t peb;     // PEB
};
extern Layout g_lay;

// A PE section of ntoskrnl, resolved by vmm::sections(). Windows headers are
// deliberately kept out of this header; `chars` carries the raw
// IMAGE_SCN_* Characteristics dword.
struct Section {
    uint64_t va;      // RVA from the image base
    uint64_t size;
    uint32_t chars;
};

// ---------------------------------------------------------------------------
// Staged initialisation.
//
// vmm::init() does every stage, but each one is also callable on its own so a
// failing driver or a hanging box can be bisected instead of guessed at:
//
//   init_ntos()          SystemModuleInformation only. No IOCTL.
//   init_kcr3_cached()   cr3.cache from a previous --cr3scan in this boot.
//   init_system()        PsInitialSystemProcess + EPROCESS validation.
//   init_kcr3()          DirectoryTableBase of System (one IOCTL).
//   scan_kernel_cr3()    explicit fallback: the 64 KB-per-IOCTL RAM scan.
//
// Only init_ntos() is a prerequisite for the others. The scan is never called
// implicitly: it is the heaviest and riskiest operation in the tool, so it
// lives behind its own --cr3scan mode.

// ---------------------------------------------------------------------------
// Why a walk stopped. Returned by the internals so a failure is falsifiable
// instead of just "false".
enum class Walk : int {
    Ok = 0,
    PhysFail,       // the driver refused the page-table read itself
    Pml4,           // PML4E absent      -> wrong CR3
    Pdpt,           // PDPTE absent
    Pde,            // PDE absent
    Pte,            // PTE absent        -> wrong VA inside a mapped region
    NotPresent,     // reserved
    BadArgs         // null CR3 / non-canonical VA
};
const char* walk_name(Walk s);

// Walk one VA through a given CR3, reporting the first failing stage.
// Used by attach/dump/dtbscan before g_kcr3 is trusted.

// Reject a zero page unless the header was proven zeroed by a transposed pair.

// Report where a walk stopped (capped at 8 prints per attach).

// Prove the ATTACHED process's CR3 by translating ntoskrnl's own base through
// it and requiring MZ. Independent of g_kcr3. On success it also fills g_kcr3,
// because the kernel half of a user CR3 is the same mapping.
bool prove_target_cr3();
bool dtb_proven();

// Diagnostics. Both operate on the attached EPROCESS and need no g_ready.
bool dump_cr3();     // raw +0x28 and the four unmasked entries for PEB+0x18
bool dtb_scan();     // sweep DTB offsets 0x20..0x80, accept the one that works

bool init();                  // every stage
bool init_ntos();
bool init_kcr3_cached();
bool init_system();
bool init_kcr3();
bool scan_kernel_cr3();
void shutdown();

bool attach(const wchar_t* image_name);
void detach();
bool attached();
uint32_t  pid();
uint64_t  base();
uint64_t  size();
void      set_base(uint64_t base, uint64_t size);

// Kernel read through the page walk. Safe for an UNVALIDATED address: a
// missing page is a false return, not a fault.
bool kread(uint64_t va, void* buf, size_t len);

// Kernel read through the driver's kernel-VA handler. One IOCTL, no walk.
// Only for addresses derived from ntoskrnl's headers or a validated EPROCESS.
// The handler's direction is proven once with a zero-payload probe first; if
// that cannot be proven the page walk is used instead (when a CR3 is known).
bool kread_trusted(uint64_t va, void* buf, size_t len);
bool kwrite_trusted(uint64_t va, const void* buf, size_t len);

bool kwrite(uint64_t va, const void* buf, size_t len);
bool read (uint64_t va, void* buf, size_t len);
// Kernel-VA -> kread_trusted, user VA -> read (page walk).
bool rd   (uint64_t va, void* buf, size_t len);

// Walk one VA through a given CR3, reporting the first failing stage.
// Used by attach/dump/dtbscan before g_kcr3 is trusted.

// MZ check that survives a transposed kernel-VA pair (which zeroes the header).
// Rejects a zero page unless the header was proven zeroed by a transposed pair,

// Report where a walk stopped (capped at 8 prints per attach).
// void report_fail(const char* who, uint64_t cr3, uint64_t va, Walk st);

// MZ check that survives a transposed kernel-VA pair (which zeroes the header).

bool write(uint64_t va, const void* buf, size_t len);
bool present(uint64_t va);

// Resolve a data export out of ntoskrnl's export directory. The export RVA
// is the address of the variable itself. Used for PsInitialSystemProcess;
// PsLoadedModuleList is NOT exported on 26200, so the cloak scans for it.
bool export_rva(const char* name, uint64_t& rva);

// Find a kernel module by name via SystemModuleInformation. Used by cloak.cpp
// to avoid pool-scanning ntoskrnl for its own base.
bool module_base(const char* name, uint64_t& base, uint64_t& size);

// ntoskrnl's section table, read properly. IMAGE_FIRST_SECTION(&nt) on a
// stack-local IMAGE_NT_HEADERS64 points one-past-the-end of that struct,
// because the section table follows OptionalHeader in the file and is not
// part of it. That bug made the writable-section scan read stack garbage.
bool sections(std::vector<Section>& out);

// ---------------------------------------------------------------------------
// Physical address space map.
//
// `ullTotalPhys` is an amount, not a top, and the space below it contains
// PCIe MMIO holes. MmMapIoSpace builds PTEs for a hole anyway and the copy
// returns garbage - and reading a powered-down device BAR can lock the root
// complex. So physical reads are gated on a real range map built from the
// loader's own resource list.
// ---------------------------------------------------------------------------
void      phys_map_init();
void      phys_map_reset();          // permissive: for the driverless mock
bool      phys_map_exact();          // true when built from the registry
bool      phys_is_ram(uint64_t pa, size_t len);
uint64_t  phys_ram_end();

// MZ check that survives a transposed kernel-VA pair (which zeroes the header).
// Used by vmm::sections(), export_rva(), init_kcr3(), cache_valid(), and
// scan_kernel_cr3() to accept both 0x5A4D and 0x0000 when the kernel-VA
// pair is transposed.
// State is defined in vmm.cpp as `bool vmm::g_ntos_mz_broken = false;`
extern bool g_ntos_mz_broken;

// Inline MZ check that survives a transposed kernel-VA pair.
// Definition in header → every TU gets its own copy, no linker involvement.
inline bool mz_ok(uint16_t m) {
    return m == 0x5A4D || (m == 0 && g_ntos_mz_broken);
}

} // namespace vmm

// MZ check that survives a transposed kernel-VA pair (which zeroes the header).



