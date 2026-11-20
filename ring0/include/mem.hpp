#pragma once
#include <cstdint>
#include <cstddef>
#include <windows.h>

namespace mem {

enum class backend { phys, rpm };

void set_backend(backend b);
backend active();
bool open_rpm(uint32_t pid);   // sadece backend::rpm icin
HANDLE get_proc_handle();    // sadece backend::rpm icin, VirtualQueryEx icin
bool read(uint64_t va, void* out, size_t n);
bool write(uint64_t va, const void* in, size_t n);
}
