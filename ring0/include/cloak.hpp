#pragma once

// Removes the backend driver's KLDR_DATA_TABLE_ENTRY from PsLoadedModuleList so
// module enumeration stops naming it. `restore` puts it back - call it before
// the service is stopped, or the entry is written into freed pool.
namespace cloak {

bool apply();
void restore();
bool active();

} // namespace cloak