#pragma once
#include <cstdint>

namespace h {

constexpr uint32_t fnv1a(const char* s, uint32_t v = 0x811C9DC5u) {
    return (*s == 0) ? v : fnv1a(s + 1, (v ^ static_cast<uint8_t>(*s)) * 0x01000193u);
}

constexpr uint32_t fnv1a_w(const wchar_t* s, uint32_t v = 0x811C9DC5u) {
    if (*s == 0) return v;
    uint32_t c = static_cast<uint32_t>(static_cast<uint16_t>(*s));
    if (c >= L'A' && c <= L'Z') c += 32;   // LDR module names vary in case
    return fnv1a_w(s + 1, (v ^ c) * 0x01000193u);
}

} // namespace h

#define HH(s)  ::h::fnv1a(s)
#define HHW(s) ::h::fnv1a_w(s)