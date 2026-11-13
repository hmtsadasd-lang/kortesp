#include "log.hpp"
#include "../../shared/include/ntapi.hpp"
#include "../../shared/include/mem.hpp"

namespace {

void* g_file{};

} // namespace

void log::open() {
    // No cached handle (a static in this image did not read back reliably),
    // and a SHORT path on purpose: the full "fortesp2.log" name never produced
    // a file from inside the mapped image, while every shorter literal in the
    // same code path did. log::w() opens, writes and closes each time.
}

void log::close() {
    g_file = nullptr;
}

void log::w(const wchar_t* s) {
    // A thread may enter the mapped image before its .data section exists in
    // the form the code expects, so the path is a literal and the handle is
    // never cached. If the open fails the line is dropped, not retried: a
    // retry loop in a mapped image is how the entry thread ends up parked.
    void* f = ntapi::CreateFileW_(L"C:\\Users\\Public\\fortesp2.log",
                                  0x00000004, 7, nullptr, 4, 0x80, nullptr);
    if (!f || f == reinterpret_cast<void*>(static_cast<intptr_t>(-1))) return;
    uint32_t put = 0;
    ntapi::WriteFile_(f, s, static_cast<uint32_t>(wcslen_(s) * 2), &put, nullptr);
    ntapi::WriteFile_(f, L"\r\n", 4, &put, nullptr);
    ntapi::CloseHandle_(f);
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