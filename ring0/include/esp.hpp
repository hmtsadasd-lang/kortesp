#pragma once
#include <cstdint>

namespace esp {
struct Config { bool on{ true }, boxes{ true }, names{ true }, health{ true }, dist{ true };
    lines{ true }, team_colors{ true }, bots{ false }, teammates{ true }; float max_dist{ 400.f }; };
extern Config cfg;
bool init(); void shutdown(); bool ready(); void draw();
} // namespace esp