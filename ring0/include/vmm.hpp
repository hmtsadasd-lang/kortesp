#pragma once
#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>

namespace vmm {

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

bool kwrite(uint64_t va, const void* buf, size_t len);
bool read (uint64_t va, void* buf, size_t len);
bool write(uint64_t va, const void* buf, size_t len);
bool present(uint64_t va);

// Resolve a data export out of ntoskrnl's export directory. The export RVA
// is the address of the variable itself. Used for PsInitialSystemProcess;
// PsLoadedModuleList is NOT exported on 26200, so the cloak scans for it.
bool export_rva(const char* name, uint64_t& rva);

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

} // namespace vmm