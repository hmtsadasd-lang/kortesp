#pragma once
#include <cstdint>
namespace log {
    void open();
    void close();
    void w(const wchar_t* s);
    void a(const char* s);
    void hex(uint64_t v);
}