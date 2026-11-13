#pragma once
#include <cstdint>

namespace h {

constexpr uint32_t fnv1a(const char* s, uint32_t v = 0x811C9DC5u) {
    return (*s == 0) ? v : fnv1a(s + 1, (v ^ static_cast<uint8_t>(*s)) * 0x01000193u);
}

// Case-insensitive ASCII hash. An import table writes "KERNEL32.dll" while
// the loader's module list says "kernel32.dll"; the two have to hash the
// same for the module to be found.
constexpr uint32_t fnv1a_ci(const char* s, uint32_t v = 0x811C9DC5u) {
    return (*s == 0) ? v
                     : fnv1a_ci(s + 1, (v ^ static_cast<uint8_t>(
                           (*s >= 'A' && *s <= 'Z') ? (*s + 32) : *s)) * 0x01000193u);
}

// Iterative, not recursive. As a recursive constexpr function GCC unrolled it
// into one giant inlined chain (every list entry's name went through a
// generated 0x200-deep ladder), which is where the payload's time and its
// stack went. Same values, one small loop.
inline uint32_t fnv1a_w(const wchar_t* s, uint32_t v = 0x811C9DC5u) {
    while (*s) {
        uint32_t c = static_cast<uint32_t>(static_cast<uint16_t>(*s));
        if (c >= L'A' && c <= L'Z') c += 32;   // LDR module names vary in case
        v = (v ^ c) * 0x01000193u;
        ++s;
    }
    return v;
}

// ASCII-folded hash of a wide string.
//
// fnv1a_w folds case but hashes the 16 bit code unit, while fnv1a hashes
// bytes - so a module name walked out of the LDR list (wide) can never match
// the same name read from an import table (narrow). This one folds to
// lowercase ASCII and hashes the byte, so it matches fnv1a_ci exactly.
inline uint32_t fnv1a_ci_w(const wchar_t* s, uint32_t v = 0x811C9DC5u) {
    while (*s) {
        uint32_t c = static_cast<uint32_t>(static_cast<uint16_t>(*s));
        if (c >= L'A' && c <= L'Z') c += 32;
        if (c > 0x7F) c = '?';
        v = (v ^ static_cast<uint8_t>(c)) * 0x01000193u;
        ++s;
    }
    return v;
}

} // namespace h

#define HH(s)  ::h::fnv1a(s)
#define HHW(s) ::h::fnv1a_w(s)