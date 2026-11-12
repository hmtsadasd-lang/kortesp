#pragma once
#include <cstdint>
#include <cstddef>

namespace map {
    bool into(uint32_t pid, const uint8_t* img, size_t size, void** out);
}