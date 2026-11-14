#pragma once
#include <cstdint>
#include <cstddef>

namespace r0 {
struct Backend { const wchar_t* device; bool (*open)(); void (*close)(); bool (*read8)(uint64_t pa, void* out); bool (*write8)(uint64_t pa, const void* in); };
bool init(); void shutdown(); bool alive();
bool pread(uint64_t pa, void* buf, size_t len); bool pwrite(uint64_t pa, const void* buf, size_t len);
} // namespace r0