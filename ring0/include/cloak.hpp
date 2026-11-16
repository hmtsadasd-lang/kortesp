#pragma once
#include <cstdint>

// Removes the backend driver's KLDR_DATA_TABLE_ENTRY from PsLoadedModuleList so
// module enumeration stops naming it. `restore` puts it back - call it before
// the service is stopped, or the entry is written into freed pool.
//
// SAFETY: this writes to kernel memory. A mistake corrupts the kernel and
// bugchecks the machine. So the default is a DRY RUN - every address is
// computed and printed, nothing is written. Call apply(true) to actually
// unlink.
namespace cloak {

// Dry run by default. commit=false computes and reports, writes nothing.
bool apply(bool commit = false);

void restore();
bool active();

// Diagnostics for the dry run.
struct Plan {
    uint64_t head{};        // &PsLoadedModuleList
    uint64_t entry{};       // our KLDR_DATA_TABLE_ENTRY
    uint64_t load_prev{};   // InLoadOrderLinks.Blink
    uint64_t load_next{};   // InLoadOrderLinks.Flink
    uint64_t mem_prev{};    // InMemoryOrderLinks.Blink
    uint64_t mem_next{};    // InMemoryOrderLinks.Flink
    uint64_t dll_base{};    // DllBase of the matched entry
    bool     found{};
};

const Plan& plan();

} // namespace cloak