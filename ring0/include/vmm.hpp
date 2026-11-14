#pragma once
#include <cstdint>
#include <cstddef>

namespace vmm {
struct Layout { uint32_t pid, links, name, dtb; };
bool init(); void shutdown();
bool attach(const wchar_t* image_name); void detach(); bool attached(); uint32_t pid(); uint64_t base(); uint64_t size(); void set_base(uint64_t base, uint64_t size);
bool kread(uint64_t va, void* buf, size_t len); bool kwrite(uint64_t va, const void* buf, size_t len); bool read(uint64_t va, void* buf, size_t len); bool write(uint64_t va, const void* buf, size_t len); bool present(uint64_t va);
} // namespace vmm