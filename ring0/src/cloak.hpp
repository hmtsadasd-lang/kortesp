#pragma once
#include <cstdint>

namespace cloak {

bool apply(bool commit = false);
bool cloak_init(const char* driver_image_name);
bool restore();
bool active();
bool module_base(uint64_t& base, uint32_t& size);
void set_driver_image(const char* name);
const char* driver_image();

} // namespace cloak
