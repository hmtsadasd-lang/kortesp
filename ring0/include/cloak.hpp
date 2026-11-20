#pragma once
#include <cstdint>

// Removes the backend driver's KLDR_DATA_TABLE_ENTRY from PsLoadedModuleList so
// module enumeration stops naming it. `restore` puts it back.
//
// SAFETY: this writes to kernel memory. A mistake corrupts the kernel and
// bugchecks the machine. So the default is a DRY RUN - every address is
// computed and printed, nothing is written. Call apply(true) to actually
// unlink.
namespace cloak {

// Dry run by default. commit=false computes and reports, writes nothing.
bool apply(bool commit = false);

// Initialize cloak with our driver's image name. Must be called before apply().
bool cloak_init(const char* driver_image_name);

// Re-link the entry and delete the persisted state file.
//
// Works in the process that unlinked it, and in a fresh process: the commit
// writes {entry, prev, next, ntoskrnl base, System EPROCESS} to
// <exe dir>\cloak.state, because once unlinked the entry is no longer
// reachable from PsLoadedModuleList and cannot be found by walking it.
//
// Refuses (returns false) if the state file is absent/stale or if the list is
// not currently in the unlinked state - writing then would corrupt the list.
// Returns true only after a read-back confirms the re-link.
bool restore();

bool active();

// Locate our driver's DllBase and SizeOfImage while the KLDR entry is still
// linked in PsLoadedModuleList (i.e. before --cloak unlinks it). Returns
// false once the driver is cloaked - so run --dpatch BEFORE --cloak.
bool module_base(uint64_t& base, uint32_t& size);

// The image name the driver was loaded under, e.g. "dbutil_2_3.sys" or the
// random name run_r0.bat installed it as. Must match what the service was
// created from, or our_base() cannot find the KLDR entry. Precedence:
// --driver-name > FORTESP_DRIVER_IMAGE > "dbutil_2_3.sys".
void set_driver_image(const char* name);
const char* driver_image();

} // namespace cloak