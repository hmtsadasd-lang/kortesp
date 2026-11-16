#pragma once
#include <cstdint>

// 5x7 bitmap font for ASCII 32-126.
// Each glyph is 5 columns x 7 rows, stored as 7 rows of 5 bits (LSB = left).
// Packed as 7 bytes per glyph, one byte per row.
extern const uint8_t kGlyphs[95][7];

inline int index(wchar_t c) {
    if (c < 32 || c > 126) return 0;
    return static_cast<int>(c) - 32;
}