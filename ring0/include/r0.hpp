#pragma once
#include <cstdint>
#include <cstddef>

namespace r0 {

// Physical-memory backend. One backend is built at init time; the table
// below is the *only* place that names the device and the IOCTL pair.
//
// The read/write entry points are length-aware: the DBUtil request layout
// puts the payload behind a fixed-size header, so the backend has to build
// the whole request itself.
struct Backend {
    const wchar_t* device;   // L"\\\\.\\DBUtil_2_3"
    bool (*open)();
    void (*close)();
    bool (*read)(uint64_t pa, void* out, size_t len);
    bool (*write)(uint64_t pa, const void* in, size_t len);
};

// Initialise the global backend. Returns false if no recognised device
// is present; caller must not use r0::pread/pwrite until init() succeeds.
bool init();
void shutdown();
bool alive();

// Install a backend directly, bypassing device discovery.
// Used by the lab mock so the whole pipeline can be exercised with no
// kernel driver present. Pass nullptr to clear.
void set_backend(const Backend* be);

// Physical read/write. Both are length-aware.
bool pread(uint64_t pa, void* buf, size_t len);
bool pwrite(uint64_t pa, const void* buf, size_t len);

} // namespace r0