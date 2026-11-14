#pragma once
#include <cstdint>
#include <cstddef>

namespace r0 {

// Physical-memory backend. One backend is built at init time; the table
// below is the *only* place that names the device and the IOCTL pair.
struct Backend {
    const wchar_t* device;   // L"\\\\.\\DBUtil_2_3"
    bool (*open)();
    void (*close)();
    bool (*read8)(uint64_t pa, void* out);
    bool (*write8)(uint64_t pa, const void* in);
};

// Initialise the global backend. Returns false if no recognised device
// is present; caller must not use r0::pread/pwrite until init() succeeds.
bool init();
void shutdown();
bool alive();

// Physical, 8-byte granular. Both loop internally over len.
bool pread(uint64_t pa, void* buf, size_t len);
bool pwrite(uint64_t pa, const void* buf, size_t len);

} // namespace r0