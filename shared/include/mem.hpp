#pragma once
#include <cstddef>
#include <cstdint>

template <class T> constexpr T min_(T a, T b) { return a < b ? a : b; }
template <class T> constexpr T max_(T a, T b) { return a > b ? a : b; }

inline size_t strlen_(const char* s) { size_t n = 0; while (s[n]) ++n; return n; }
inline size_t wcslen_(const wchar_t* s) { size_t n = 0; while (s[n]) ++n; return n; }

inline float sqrtf_(float v) {
    float x = v;
    for (int i = 0; i < 24; ++i) x = 0.5f * (x + v / x);
    return x;
}