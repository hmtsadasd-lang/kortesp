#include "log.hpp"
#include "../../shared/include/ntapi.hpp"
#include "../../shared/include/mem.hpp"

namespace {

void* g_file{};

} // namespace

void log::open() {
    if (g_file) return;

    // fixed path: SYSTEM/session-0 hosts have a different %TEMP%
    void* f = ntapi::CreateFileW_(L"C:\\Users\\Public\\fortesp2.log", 0x00100004, 7, nullptr, 4, 0x80, nullptr);
    g_file = (f == reinterpret_cast<void*>(static_cast<intptr_t>(-1))) ? nullptr : f;
}

void log::close() {
    if (!g_file) return;
    ntapi::CloseHandle_(g_file);
    g_file = nullptr;
}

void log::w(const wchar_t* s) {
    if (!g_file) return;
    uint32_t put = 0;
    ntapi::WriteFile_(g_file, s, static_cast<uint32_t>(wcslen_(s) * 2), &put, nullptr);
    ntapi::WriteFile_(g_file, L"\r\n", 4, &put, nullptr);
}

void log::a(const char* s) {
    if (!g_file) return;
    uint32_t put = 0;
    ntapi::WriteFile_(g_file, s, static_cast<uint32_t>(strlen_(s)), &put, nullptr);
    ntapi::WriteFile_(g_file, "\r\n", 2, &put, nullptr);
}

void log::hex(uint64_t v) {
    if (!g_file) return;
    wchar_t b[19];
    b[0] = L'0'; b[1] = L'x';
    for (int i = 0; i < 16; ++i) {
        static const wchar_t d[] = L"0123456789ABCDEF";
        b[2 + i] = d[(v >> (60 - i * 4)) & 0xF];
    }
    b[18] = 0;
    uint32_t put = 0;
    ntapi::WriteFile_(g_file, b, 36, &put, nullptr);
    ntapi::WriteFile_(g_file, L"\r\n", 4, &put, nullptr);
}