#pragma once
#include <cstdint>

namespace esp {

struct Config {
    bool on{ true }, boxes{ true }, names{ true }, health{ true }, dist{ true };
    bool lines{ true }, team_colors{ true }, bots{ false }, teammates{ true };
    bool skeleton{ false };
    float max_dist{ 400.f };
};

extern Config cfg;
extern bool use_actors;      // --actors: PersistentLevel/Actors instead of PlayerArray

bool init();
void shutdown();
bool ready();
void draw();
bool probe();
int decode_fstring(const wchar_t* src, int src_chars, wchar_t* dst, int dst_cap);

} // namespace esp
