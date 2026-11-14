#pragma once
#include <cstdint>
#include <cstddef>
#include <array>

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
    uint64_t page;
    uint64_t phys;
    uint32_t stamp;
};
extern std::array<TlbEntry, kTlbSize> g_tlb;
extern uint32_t g_stamp;

// Global state
extern uint64_t  g_kcr3;
extern uint64_t  g_gcr3;
extern uint64_t  g_base;
extern uint64_t  g_size;
extern uint64_t  g_eprocess;
extern uint64_t  g_ntos;      // ntoskrnl base, for export resolution
extern uint32_t  g_pid;
extern bool      g_ready;
extern bool      g_attached;

// Layout for EPROCESS field walks
struct Layout {
    uint64_t pid;
    uint64_t links;
    uint64_t name;
    uint64_t dtb;
};
extern Layout g_lay;

// Public API
bool init();
void shutdown();

bool attach(const wchar_t* image_name);
void detach();
bool attached();
uint32_t  pid();
uint64_t  base();
uint64_t  size();
void      set_base(uint64_t base, uint64_t size);

bool kread(uint64_t va, void* buf, size_t len);
bool kwrite(uint64_t va, const void* buf, size_t len);
bool read (uint64_t va, void* buf, size_t len);
bool write(uint64_t va, const void* buf, size_t len);
bool present(uint64_t va);

} // namespace vmm