#include "esp.hpp"
#include "offsets.hpp"
#include "vmm.hpp"
#include "ov.hpp"
#include <windows.h>
#include <cmath>
#include <cstring>
#include <cstdio>

namespace esp {

Config cfg{};

// Decode an obfuscated UE FString buffer into plaintext.
// `src_chars` is the number of wchar_t actually present (FString.Length-1;
// Length counts the null terminator). Returns characters written.
int decode_fstring(const wchar_t* src, int src_chars, wchar_t* dst, int dst_cap) {
    if (!src || !dst || dst_cap <= 0) return 0;
    dst[0] = 0;
    int key = (src_chars) & 3, out = 0;
    for (int i = 0; i < src_chars && out < dst_cap - 1; ++i) {
        wchar_t c = static_cast<wchar_t>(src[i] - (key & 7));
        if (c >= 0x20 && c < 0x7F) dst[out++] = c;
        key += 3;
    }
    dst[out] = 0;
    return out;
}

namespace {

    struct Vec3{float x,y,z;};  // UE vectors are float[3]
    struct Pov{Vec3 loc{},fwd{},right{},up{};float focal{};int w{},h{};};
    uint64_t g_world{},g_pc{},g_my_state{}; bool g_ready{};
    constexpr double kPi=3.14159265358979323846;
    inline bool ok(uint64_t p){return p>0x10000&&p<0x7FFFFFFFFFFF&&!(p&3);}

    // Case-insensitive compare of a UTF-16 string against an ASCII literal.
    bool iequals_ascii(const wchar_t* w, const wchar_t* a) {
        for (int i = 0;; ++i) {
            wchar_t x = w[i], y = a[i];
            if (x >= L'A' && x <= L'Z') x = static_cast<wchar_t>(x + 32);
            if (y >= L'A' && y <= L'Z') y = static_cast<wchar_t>(y + 32);
            if (x != y) return false;
            if (!y) return true;
        }
    }

    // PEB-based module discovery.
    // The PEB we want is the TARGET's, reached through the target's EPROCESS.
    // Reading our own GS-segment PEB pointer and then dereferencing it in the
    // target's address space would read the wrong address entirely.
    //
    // LDR_DATA_TABLE_ENTRY (x64):
    //   0x00 InLoadOrderLinks.Flink
    //   0x30 DllBase
    //   0x40 SizeOfImage
    //   0x58 BaseDllName.Length (USHORT)
    //   0x60 BaseDllName.Buffer (PWSTR) - UTF-16
    bool resolve_base() {
        uint64_t peb{}, ldr{}, head{}, cur{};
        if (!vmm::kread(vmm::g_eprocess + vmm::g_lay.peb, &peb, sizeof(peb))) return false;
        if (!ok(peb)) return false;
        if (!vmm::read(peb + 0x30, &ldr, sizeof(ldr))) return false;          // PEB->Ldr
        if (!vmm::read(ldr + 0x20, &head, sizeof(head))) return false;         // &InLoadOrderModuleList
        if (!vmm::read(head, &cur, sizeof(cur))) return false;                 // head.Flink

        for (int g = 0; g < 512 && cur && cur != head; ++g) {
            uint64_t base{}, size{}, nbuf{};
            uint16_t nlen{};

            if (!vmm::read(cur + 0x30, &base, sizeof(base))) break;   // DllBase
            if (!vmm::read(cur + 0x40, &size, sizeof(size))) break;   // SizeOfImage
            if (!vmm::read(cur + 0x58, &nlen, sizeof(nlen))) break;   // BaseDllName.Length
            if (!vmm::read(cur + 0x60, &nbuf, sizeof(nbuf))) break;   // BaseDllName.Buffer
            if (nlen == 0 || nlen > 1024) break;

            wchar_t wname[264]{};
            const int chars = static_cast<int>(nlen / 2);
            if (chars > 263) break;
            if (!vmm::read(nbuf, wname, static_cast<size_t>(nlen))) break;

            if (iequals_ascii(wname, L"FortniteClient-Win64-Shipping.exe")) {
                vmm::g_base = base;
                vmm::g_size = size;
                return true;
            }

            if (!vmm::read(cur + 0x00, &cur, sizeof(cur))) break;     // InLoadOrderLinks.Flink
        }
        return false;
    }

    bool build_view(Pov& v) {
        uint64_t gi{}, arr{}; int count{};

        if (!vmm::read(g_world + off::World_OwningGameInstance, &gi, sizeof(gi)) || !ok(gi)) return false;
        if (!vmm::read(gi + off::GameInstance_LocalPlayers, &arr, sizeof(arr)) || !ok(arr)) return false;
        vmm::read(gi + off::GameInstance_LocalPlayers + 8, &count, sizeof(count)); if (count <= 0) return false;

        uint64_t local{}; if (!vmm::read(arr, &local, sizeof(local)) || !ok(local)) return false;
        if (!vmm::read(local + off::Player_PlayerController, &g_pc, sizeof(g_pc)) || !ok(g_pc)) return false;

        vmm::read(g_pc + off::Controller_PlayerState, &g_my_state, sizeof(g_my_state));

        uint64_t cam{}; if (!vmm::read(g_pc + off::Controller_PlayerCameraManager, &cam, sizeof(cam)) || !ok(cam)) return false;

        const uint64_t pov = cam + off::Camera_CameraCachePrivate + off::CacheEntry_POV;
        Vec3 rot{}; float fov{};

        float loc_buf[3]{};
        if (!vmm::read(pov + off::POV_Location, loc_buf, sizeof(loc_buf))) return false;
        vmm::read(pov + off::POV_Rotation, &rot, sizeof(rot));
        if (!vmm::read(pov + off::POV_FOV, &fov, sizeof(fov)) || fov < 1.f || fov > 179.f) return false;
        if (!loc_buf[0] && !loc_buf[1] && !loc_buf[2]) return false;

        const double p = rot.x * kPi / 180.0, y = rot.y * kPi / 180.0;
        v.fwd   = { float(cos(p)*cos(y)), float(cos(p)*sin(y)), float(sin(p)) };
        v.right = { float(-sin(y)), float(cos(y)), 0.0f };
        v.up    = { float(v.fwd.y*v.right.z - v.fwd.z*v.right.y),
                    float(v.fwd.z*v.right.x - v.fwd.x*v.right.z),
                    float(v.fwd.x*v.right.y - v.fwd.y*v.right.x) };

        v.w = ov::width(); v.h = ov::height(); if (v.w < 8 || v.h < 8) return false;
        v.focal = static_cast<float>((v.w * 0.5f) / tan(fov * 0.5f * kPi / 180.0f));
        return true;
    }

    bool project(const Pov& v, const Vec3& p, float& sx, float& sy) {
        Vec3 d{ p.x - v.loc.x, p.y - v.loc.y, p.z - v.loc.z };
        const double vz = d.x * v.fwd.x + d.y * v.fwd.y + d.z * v.fwd.z;
        if (vz < 10.0) return false;
        sx = static_cast<float>(v.w * 0.5f + (d.x * v.right.x + d.y * v.right.y + d.z * v.right.z) * v.focal / vz);
        sy = static_cast<float>(v.h * 0.5f - (d.x * v.up.x   + d.y * v.up.y   + d.z * v.up.z)   * v.focal / vz);
        return sx > -200.f && sy > -200.f && sx < v.w + 200.f && sy < v.h + 200.f;
    }

    void read_name(uint64_t state, wchar_t* dst, size_t cap) {
        dst[0] = 0; uint64_t data{}; int len{};
        vmm::read(state + off::State_Name, &data, sizeof(data)); if (!ok(data)) return;
        vmm::read(state + off::State_Name + 8, &len, sizeof(len)); if (len <= 1 || len > 31) return;
        wchar_t tmp[32]{};
        vmm::read(data, tmp, sizeof(wchar_t) * static_cast<size_t>(len - 1)); if (!tmp[0]) return;
        decode_fstring(tmp, len - 1, dst, static_cast<int>(cap));
    }

    ov::Color team_color(int team, int mine) {
        if (!cfg.team_colors) return { 0.95f, 0.95f, 0.95f, 1.f };
        if (team == mine) return { 0.30f, 0.90f, 0.40f, 1.f };
        switch (team & 7) {
        case 0: return { 1.00f, 0.35f, 0.35f, 1.f };
        case 1: return { 0.40f, 0.65f, 1.00f, 1.f };
        case 2: return { 1.00f, 0.85f, 0.30f, 1.f };
        case 3: return { 0.80f, 0.45f, 1.00f, 1.f };
        case 4: return { 0.35f, 1.00f, 0.90f, 1.f };
        default: return { 1.00f, 0.55f, 0.85f, 1.f };
        }
    }

    void draw_player(const Pov& v, uint64_t state, int my_team) {
        uint64_t pawn{}; vmm::read(state + off::State_Pawn, &pawn, sizeof(pawn)); if (!ok(pawn)) return;

        uint8_t dying{}; vmm::read(pawn + off::Pawn_Dying, &dying, sizeof(dying)); if (dying & 0x20) return;
        uint64_t mesh{}; vmm::read(pawn + off::Pawn_Mesh, &mesh, sizeof(mesh)); if (!ok(mesh)) return;

        // ComponentToWorld translation (FTransform + 0x10). UE vectors are float[3].
        float feet[3]{};
        vmm::read(mesh + off::Comp_C2W + off::Xform_Translation, feet, sizeof(feet));
        if (feet[0] != feet[0] || feet[2] != feet[2]) return; // NaN guard
        const Vec3 base{ feet[0], feet[1], feet[2] };
        Vec3 d{ base.x - v.loc.x, base.y - v.loc.y, base.z - v.loc.z };
        const float metres = static_cast<float>(sqrtf(d.x * d.x + d.y * d.y + d.z * d.z) / 100.0f);
        if (metres > cfg.max_dist) return;

        float half{}; vmm::read(pawn + off::Pawn_CapsuleHalf, &half, sizeof(half)); if (half < 10.f || half > 200.f) half = 88.f;
        const Vec3 top{ base.x, base.y, base.z + half * 2.0f };

        float bx{}, by{}, tx{}, ty{}; if (!project(v, base, bx, by) || !project(v, top, tx, ty)) return;
        const float h = by - ty; if (h < 6.f || h > 1600.f) return;
        const float w = h * 0.42f;

        int team{}; vmm::read(state + off::State_Team, &team, sizeof(team));
        if (!cfg.teammates && team == my_team) return;
        const ov::Color col = team_color(team, my_team);

        const float l = tx - w * 0.5f, r = tx + w * 0.5f;

        if (cfg.boxes) ov::box(l, ty, r, by, col, 1.4f);

        if (cfg.health) {
            uint64_t hs{}; float cur{}, max{};
            vmm::read(pawn + off::Pawn_HealthSet, &hs, sizeof(hs)); if (ok(hs)) {
                float cur_f{}, max_f{};
                vmm::read(hs + off::Health_Current, &cur_f, sizeof(cur_f));
                vmm::read(hs + off::Health_Max,     &max_f,     sizeof(max_f));
                cur = cur_f; max = max_f;
            }
            if (max <= 0.f) max = 100.f;
            float frac = cur / max; if (frac < 0.f) frac = 0.f; if (frac > 1.f) frac = 1.f;
            ov::fill(l - 6.f, ty, l - 3.f, by, { 0.f, 0.f, 0.f, 0.65f });
            ov::fill(l - 6.f, by - h * frac, l - 3.f, by,
                frac > 0.6f ? ov::Color{ 0.30f, 0.90f, 0.30f, 1.f }
                : frac > 0.3f ? ov::Color{ 1.00f, 0.80f, 0.20f, 1.f }
                : ov::Color{ 1.00f, 0.25f, 0.25f, 1.f });
        }

        if (cfg.names) {
            wchar_t nm[32]{}; read_name(state, nm, 32);
            if (nm[0]) ov::text(tx - ov::textw(nm, 1.f) * 0.5f, ty - 11.f, nm, col);
        }

        if (cfg.dist) {
            wchar_t buf[16]{}; int n = 0, t = static_cast<int>(metres);
            wchar_t tmp[8]; int k = 0;
            if (!t) buf[n++] = L'0';
            while (t) { tmp[k++] = static_cast<wchar_t>(L'0' + t % 10); t /= 10; }
            while (k) buf[n++] = tmp[--k];
            buf[n++] = L'M'; buf[n] = 0;
            ov::text(tx - 7.f, by + 2.f, buf, { 0.85f, 0.85f, 0.85f, 1.f }, 0.8f);
        }

        if (cfg.lines) ov::line(static_cast<float>(v.w) * 0.5f, static_cast<float>(v.h), tx, by, 1.2f, col);
    }
} // namespace

bool init() {
    if (!vmm::base() && !resolve_base()) return false;
    uint64_t engine{}; vmm::read(vmm::base() + off::GEngine, &engine, sizeof(engine)); if (!ok(engine)) return false;
    uint64_t vp{};          vmm::read(engine + off::Engine_GameViewportClient, &vp,        sizeof(vp));        if (!ok(vp)) return false;
    vmm::read(vp + off::Viewport_World, &g_world, sizeof(g_world)); if (!ok(g_world)) return false;
    g_ready = true;
    return true;
}

void shutdown() { g_ready = false; g_world = 0; g_pc = 0; }
bool ready() { return g_ready; }

// ---------------------------------------------------------------------------
// probe: walk the chain step by step and report the first rejection.
// ---------------------------------------------------------------------------
bool probe() {
    auto step = [](const char* what, bool ok) {
        printf("  %-34s %s\n", what, ok ? "ok" : "<- rejected");
        return ok;
    };

    printf("chain:\n");

    uint64_t engine{};
    if (!step("GEngine", vmm::read(vmm::base() + off::GEngine, &engine, sizeof(engine)) && ok(engine))) return false;

    uint64_t viewport{};
    if (!step("Engine->GameViewportClient", vmm::read(engine + off::Engine_GameViewportClient, &viewport, sizeof(viewport)) && ok(viewport))) return false;

    uint64_t world{};
    if (!step("Viewport->World", vmm::read(viewport + off::Viewport_World, &world, sizeof(world)) && ok(world))) return false;

    uint64_t gs{};
    if (!step("World->GameState", vmm::read(world + off::World_GameState, &gs, sizeof(gs)) && ok(gs))) return false;

    uint64_t gi{};
    if (!step("World->OwningGameInstance", vmm::read(world + off::World_OwningGameInstance, &gi, sizeof(gi)) && ok(gi))) return false;

    uint64_t lp_array{}; int lp_count{};
    if (!step("GameInstance->LocalPlayers", vmm::read(gi + off::GameInstance_LocalPlayers, &lp_array, sizeof(lp_array)) && ok(lp_array))) return false;
    vmm::read(gi + off::GameInstance_LocalPlayers + 8, &lp_count, sizeof(lp_count));
    if (!step("LocalPlayers.Count > 0", lp_count > 0)) return false;

    uint64_t local{};
    if (!step("LocalPlayers[0]", vmm::read(lp_array, &local, sizeof(local)) && ok(local))) return false;

    uint64_t ctrl{};
    if (!step("LocalPlayer->PlayerController", vmm::read(local + off::Player_PlayerController, &ctrl, sizeof(ctrl)) && ok(ctrl))) return false;

    uint64_t mystate{};
    vmm::read(ctrl + off::Controller_PlayerState, &mystate, sizeof(mystate));
    if (!step("Controller->PlayerState", ok(mystate))) return false;

    uint64_t cam{};
    if (!step("Controller->PlayerCameraManager", vmm::read(ctrl + off::Controller_PlayerCameraManager, &cam, sizeof(cam)) && ok(cam))) return false;

    uint64_t cache{};
    if (!step("CameraManager->CameraCachePrivate", vmm::read(cam + off::Camera_CameraCachePrivate, &cache, sizeof(cache)) && ok(cache))) return false;

    const uint64_t pov = cam + off::Camera_CameraCachePrivate + off::CacheEntry_POV;
    float loc3[3]{}, rot3[3]{}, fov{};
    if (!step("POV.Location", vmm::read(pov + off::POV_Location, loc3, sizeof(loc3)))) return false;
    if (!step("POV.Rotation", vmm::read(pov + off::POV_Rotation, rot3, sizeof(rot3)))) return false;
    if (!step("POV.FOV", vmm::read(pov + off::POV_FOV, &fov, sizeof(fov)) && fov >= 1.f && fov <= 179.f)) return false;

    printf("\nPOV: location=(%.1f, %.1f, %.1f) rotation=(%.1f, %.1f, %.1f) fov=%.1f\n",
           loc3[0], loc3[1], loc3[2], rot3[0], rot3[1], rot3[2], fov);

    // Player array
    uint64_t arr{}; int count{};
    if (!step("GameState->PlayerArray", vmm::read(gs + off::GameState_PlayerArray, &arr, sizeof(arr)) && ok(arr))) return false;
    vmm::read(gs + off::GameState_PlayerArray + 8, &count, sizeof(count));
    if (!step("PlayerArray.Count > 0", count > 0)) return false;
    if (count > off::kMaxPlayers) count = off::kMaxPlayers;

    printf("\nplayers (%d):\n", count);
    int shown = 0;
    for (int i = 0; i < count && shown < 3; ++i) {
        uint64_t state{};
        if (!vmm::read(arr + i * 8, &state, sizeof(state)) || !ok(state)) continue;
        if (state == mystate) continue;

        wchar_t nm[32]{}; read_name(state, nm, 32);
        uint64_t pawn{}; vmm::read(state + off::State_Pawn, &pawn, sizeof(pawn));
        uint64_t mesh{}; if (ok(pawn)) vmm::read(pawn + off::Pawn_Mesh, &mesh, sizeof(mesh));

        float feet[3]{};
        if (ok(mesh)) vmm::read(mesh + off::Comp_C2W + off::Xform_Translation, feet, sizeof(feet));

        int team{}; vmm::read(state + off::State_Team, &team, sizeof(team));
        uint8_t flags{}; vmm::read(state + off::State_Flags, &flags, sizeof(flags));

        printf("  %d. %-18ls team=%d flags=0x%02x pawn=%s mesh=%s pos=(%.0f, %.0f, %.0f)\n",
               shown + 1, nm[0] ? nm : L"(no name)", team, flags,
               ok(pawn) ? "yes" : "no", ok(mesh) ? "yes" : "no",
               feet[0], feet[1], feet[2]);
        ++shown;
    }
    if (!shown) printf("  (none readable)\n");

    return true;
}
void draw() {
    if (!g_ready || !cfg.on || !vmm::attached()) return;
    Pov v{}; if (!build_view(v)) return;
    uint64_t gs{}, arr{}; int count{};
    vmm::read(g_world + off::World_GameState, &gs, sizeof(gs)); if (!ok(gs)) return;
    vmm::read(gs + off::GameState_PlayerArray, &arr, sizeof(arr)); if (!ok(arr)) return;
    vmm::read(gs + off::GameState_PlayerArray + 8, &count, sizeof(count)); if (count <= 0) return;
    if (count > off::kMaxPlayers) count = off::kMaxPlayers;

    int my_team{-1};
    if (ok(g_my_state)) vmm::read(g_my_state + off::State_Team, &my_team, sizeof(my_team));

    for (int i = 0; i < count; ++i) {
        uint64_t state{}; vmm::read(arr + i * 8, &state, sizeof(state)); if (!ok(state)) continue;
        if (state == g_my_state) continue;
        uint8_t flags{}; vmm::read(state + off::State_Flags, &flags, sizeof(flags));
        if (!cfg.bots && (flags & 0x08)) continue;
        if (flags & 0x02) continue;
        if (flags & 0x20) continue;
        draw_player(v, state, my_team);
    }
}
} // namespace esp