#pragma once
#include <cstdint>
#include <cstddef>

namespace pm {

// PTE self-map remap physical reader.
//
// Allocates one private page (the "slot"), walks the PTE self-map to find
// the slot's own PTE, then remaps that PTE to any target physical address.
// Reads/writes go through the slot VA directly (user-mode memory access,
// no IOCTL, no MmMapIoSpace, no MmNonCached conflict). The PTE itself is
// rewritten via the driver's kernel-VA write IOCTL (self-map PTEs are
// writable kernel VA), then a VirtualProtect flushes the TLB for the slot.
//
// Slot lifetime: allocated once on init, freed on shutdown. Never
// MEM_DECOMMIT the slot mid-boot (T1: refcount hazard).
//
// Requires vmm::g_pte_base (validated by init_pte_base()).
bool init(uint64_t pte_base);

// Read up to a full page through the remapped slot. Multi-page reads are
// chunked internally; each chunk remaps the slot to its own PA.
bool read(uint64_t pa, void* out, size_t len);

void shutdown();
extern bool g_pm_ok;

} // namespace pm
