#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" int _fltused = 0;

// Disable compiler intrinsics so our manual versions link cleanly
#pragma function(memset)
#pragma function(memcpy)
#pragma function(memcmp)

extern "C" void* memset(void* d, int c, size_t n) {
    auto* p = static_cast<uint8_t*>(d);
    while (n--) *p++ = static_cast<uint8_t>(c);
    return d;
}

extern "C" void* memcpy(void* d, const void* s, size_t n) {
    auto* a = static_cast<uint8_t*>(d);
    auto* b = static_cast<const uint8_t*>(s);
    while (n--) *a++ = *b++;
    return d;
}

extern "C" int memcmp(const void* a, const void* b, size_t n) {
    auto* x = static_cast<const uint8_t*>(a);
    auto* y = static_cast<const uint8_t*>(b);
    for (size_t i = 0; i < n; ++i) if (x[i] != y[i]) return int(x[i] - y[i]);
    return 0;
}

template <class T> constexpr T min_(T a, T b) { return a < b ? a : b; }
template <class T> constexpr T max_(T a, T b) { return a > b ? a : b; }

inline size_t strlen_(const char* s) { size_t n = 0; while (s[n]) ++n; return n; }
inline size_t wcslen_(const wchar_t* s) { size_t n = 0; while (s[n]) ++n; return n; }

inline float sqrtf_(float v) {
    float x = v;
    for (int i = 0; i < 24; ++i) x = 0.5f * (x + v / x);
    return x;
}