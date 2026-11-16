#pragma once
#include <cstdint>

namespace esp {

struct Config {
    bool on{ true }, boxes{ true }, names{ true }, health{ true }, dist{ true };
    bool lines{ true }, team_colors{ true }, bots{ false }, teammates{ true };
    float max_dist{ 400.f };
};

extern Config cfg;

bool init();
void shutdown();
bool ready();
void draw();

// Resolve the whole chain and print each hop. The first hop that fails is
// marked "<- rejected"; on success the POV and the first few players are
// printed. Returns true if the camera chain fully resolved.
bool probe();

// Decode an obfuscated UE FString buffer into plaintext.
// `src_chars` is the number of wchar_t present (FString.Length - 1; Length
// counts the null terminator). Pure function - no target needed.
int decode_fstring(const wchar_t* src, int src_chars, wchar_t* dst, int dst_cap);

} // namespace esp