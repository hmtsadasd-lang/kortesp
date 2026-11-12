#pragma once
#include "render.hpp"
#include <cstdint>
#include <cstddef>

namespace game {

struct Vec { float x, y, z; };

struct Player {
    uintptr_t pawn{};
    Vec  head{}, origin{};
    int  hp{}, hp_max{};
    int  team{};
    float dist{};
    bool visible{}, local{};
    wchar_t name[32]{};
};

bool init();
void draw();
bool ready();
void shutdown();

} // namespace game