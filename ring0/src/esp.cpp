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
bool use_actors = false;

int decode_fstring(const wchar_t* src, int src_chars, wchar_t* dst, int dst_cap) {
    if (!src || !dst || dst_cap <= 0) return 0;
    dst[0] = 0;
    int key = src_chars & 3, out = 0;
    for (int i = 0; i < src_chars && out < dst_cap - 1; ++i) {
        const wchar_t c = static_cast<wchar_t>(src[i] - (key & 7));
        if (c >= 0x20 && c < 0x7F) dst[out++] = c;
        key += 3;
    }
    dst[out] = 0;
    return out;
}

namespace {

struct Vec3d { double x, y, z; };
struct Pov { Vec3d loc{}, fwd{}, right{}, up{}; double focal{}; int w{}, h{}; };
struct Entity { uint64_t pawn{}, state{}; };

uint64_t g_world{}, g_pc{}, g_my_state{}, g_my_pawn{};
bool g_ready{};
constexpr double kPi = 3.14159265358979323846;

// Accept BOTH halves of the address space. Game objects are kernel pool
// pointers; the PEB chain is user memory. A user-only bound rejects every
// UObject.
inline bool ok(uint64_t p) {
    if (p < 0x10000 || (p & 3)) return false;
    if (p <= vmm::kUserHi) return true;
    return p >= 0xFFFF800000000000ull;
}

bool iequals_ascii(const wchar_t* w, const wchar_t* a) {
    for (int i = 0;; ++i) {
        wchar_t x = w[i], y = a[i];
        if (x >= L'A' && x <= L'Z') x = static_cast<wchar_t>(x + 32);
        if (y >= L'A' && y <= L'Z') y = static_cast<wchar_t>(y + 32);
        if (x != y) return false;
        if (!y) return true;
    }
}

bool resolve_base() {
    // EPROCESS.SectionBaseAddress: plain kernel-VA read, no page walk needed.
    // (The old PEB/LDR fallback lived here; it needs user page-walk reads,
    // which the unpatched physical path cannot serve.)
    uint64_t section_base{};
    if (vmm::rd(vmm::g_eprocess + off::Eproc_SectionBase, &section_base, sizeof(section_base)) &&
        section_base > 0x10000 && section_base <= vmm::kUserHi) {
        vmm::set_base(section_base, 0);
        printf("[+] found FortniteClient base 0x%llx (via EPROCESS.SectionBaseAddress)\n",
               (unsigned long long)section_base);
        return true;
    }
    printf("[!] resolve_base: SectionBaseAddress read failed (eprocess 0x%llx)\n",
           (unsigned long long)vmm::g_eprocess + off::Eproc_SectionBase);
    return false;
}

bool build_view(Pov& v) {
    uint64_t gi{}, arr{}; int count{};

    if (!vmm::rd(g_world + off::World_OwningGameInstance, &gi, sizeof(gi)) || !ok(gi)) return false;
    if (!vmm::rd(gi + off::GameInstance_LocalPlayers, &arr, sizeof(arr)) || !ok(arr)) return false;
    if (!vmm::rd(gi + off::GameInstance_LocalPlayers + 8, &count, sizeof(count))) return false;
    if (count <= 0) return false;

    uint64_t local{};
    if (!vmm::rd(arr, &local, sizeof(local)) || !ok(local)) return false;
    if (!vmm::rd(local + off::Player_PlayerController, &g_pc, sizeof(g_pc)) || !ok(g_pc)) return false;

    vmm::rd(g_pc + off::Controller_PlayerState, &g_my_state, sizeof(g_my_state));
    if (ok(g_my_state)) vmm::rd(g_my_state + off::State_Pawn, &g_my_pawn, sizeof(g_my_pawn));

    uint64_t cam{};
    if (!vmm::rd(g_pc + off::Controller_PlayerCameraManager, &cam, sizeof(cam)) || !ok(cam)) return false;

    const uint64_t pov = cam + off::Camera_CameraCachePrivate + off::CacheEntry_POV;
    Vec3d rot{}; double fov{};
    if (!vmm::rd(pov + off::POV_Location, &v.loc, sizeof(v.loc))) return false;
    if (!vmm::rd(pov + off::POV_Rotation, &rot, sizeof(rot))) return false;
    if (!vmm::rd(pov + off::POV_FOV, &fov, sizeof(fov)) || fov < 1.0 || fov > 179.0) return false;
    if (!v.loc.x && !v.loc.y && !v.loc.z) return false;

    const double p = rot.x * kPi / 180.0, y = rot.y * kPi / 180.0;
    v.fwd   = { cos(p) * cos(y), cos(p) * sin(y), sin(p) };
    v.right = { -sin(y), cos(y), 0.0 };
    v.up    = { v.fwd.y * v.right.z - v.fwd.z * v.right.y,
                v.fwd.z * v.right.x - v.fwd.x * v.right.z,
                v.fwd.x * v.right.y - v.fwd.y * v.right.x };

    v.w = ov::width(); v.h = ov::height();
    if (v.w < 8 || v.h < 8) return false;
    v.focal = (v.w * 0.5) / tan(fov * 0.5 * kPi / 180.0);
    return true;
}

bool project(const Pov& v, const Vec3d& p, float& sx, float& sy) {
    const Vec3d d{ p.x - v.loc.x, p.y - v.loc.y, p.z - v.loc.z };
    const double vz = d.x * v.fwd.x + d.y * v.fwd.y + d.z * v.fwd.z;
    if (vz < 10.0) return false;
    sx = static_cast<float>(v.w * 0.5 + (d.x * v.right.x + d.y * v.right.y + d.z * v.right.z) * v.focal / vz);
    sy = static_cast<float>(v.h * 0.5 - (d.x * v.up.x + d.y * v.up.y + d.z * v.up.z) * v.focal / vz);
    return sx > -200.f && sy > -200.f && sx < v.w + 200.f && sy < v.h + 200.f;
}

void read_name(uint64_t state, wchar_t* dst, size_t cap) {
    dst[0] = 0;
    uint64_t data{}; int len{};
    if (!vmm::rd(state + off::State_Name, &data, sizeof(data)) || !ok(data)) return;
    if (!vmm::rd(state + off::State_Name + 8, &len, sizeof(len))) return;
    if (len <= 1 || len > 32) return;
    wchar_t tmp[33]{};
    if (!vmm::rd(data, tmp, sizeof(wchar_t) * static_cast<size_t>(len - 1))) return;
    if (!tmp[0]) return;
    decode_fstring(tmp, len - 1, dst, static_cast<int>(cap));
}

bool bone_pos(uint64_t mesh, int idx, Vec3d& out) {
    uint64_t arr{};
    if (!vmm::rd(mesh + off::Mesh_BoneArray, &arr, sizeof(arr)) || !ok(arr)) return false;
    const uint64_t at = arr + static_cast<uint64_t>(idx) * off::Xform_Stride + off::Xform_Translation;
    if (!vmm::rd(at, &out, sizeof(out))) return false;
    return out.x == out.x && out.z == out.z;
}

bool bone_pos(uint64_t mesh, uint64_t arr, int idx, Vec3d& out) {
    const uint64_t at = arr + static_cast<uint64_t>(idx) * off::Xform_Stride + off::Xform_Translation;
    if (!vmm::rd(at, &out, sizeof(out))) return false;
    return out.x == out.x && out.z == out.z;
}

constexpr int kPairs[][2] = {
    { off::Bone_Head, off::Bone_Neck },       { off::Bone_Neck, off::Bone_Chest },
    { off::Bone_Chest, off::Bone_Pelvis },
    { off::Bone_Chest, off::Bone_LShoulder }, { off::Bone_LShoulder, off::Bone_LElbow },
    { off::Bone_LElbow, off::Bone_LHand },
    { off::Bone_Chest, off::Bone_RShoulder }, { off::Bone_RShoulder, off::Bone_RElbow },
    { off::Bone_RElbow, off::Bone_RHand },
    { off::Bone_Pelvis, off::Bone_LThigh },   { off::Bone_LThigh, off::Bone_LKnee },
    { off::Bone_LKnee, off::Bone_LFoot },
    { off::Bone_Pelvis, off::Bone_RThigh },   { off::Bone_RThigh, off::Bone_RKnee },
    { off::Bone_RKnee, off::Bone_RFoot },
};

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

void draw_entity(const Pov& v, const Entity& e, int my_team) {
    const uint64_t pawn = e.pawn;
    if (!ok(pawn) || pawn == g_my_pawn) return;

    uint8_t dying{};
    if (!vmm::rd(pawn + off::Pawn_Dying, &dying, sizeof(dying))) return;
    if (dying & 0x20) return;

    uint64_t mesh{};
    if (!vmm::rd(pawn + off::Pawn_Mesh, &mesh, sizeof(mesh)) || !ok(mesh)) return;

    // Hoist the bone array read once per entity instead of per bone pair.
    uint64_t bone_arr{};
    if (!vmm::rd(mesh + off::Mesh_BoneArray, &bone_arr, sizeof(bone_arr)) || !ok(bone_arr)) {
        bone_arr = 0;
    }

    Vec3d feet{};
    if (!vmm::rd(mesh + off::Comp_C2W + off::Xform_Translation, &feet, sizeof(feet))) return;
    if (feet.x != feet.x || feet.z != feet.z) return;

    const Vec3d d{ feet.x - v.loc.x, feet.y - v.loc.y, feet.z - v.loc.z };
    const float metres = static_cast<float>(sqrt(d.x * d.x + d.y * d.y + d.z * d.z) / 100.0);
    if (metres > cfg.max_dist) return;

    float half{};
    vmm::rd(pawn + off::Pawn_CapsuleHalf, &half, sizeof(half));
    if (half < 10.f || half > 200.f) half = 88.f;
    const Vec3d top{ feet.x, feet.y, feet.z + half * 2.f + 34.f };

    float bx{}, by{}, tx{}, ty{};
    if (!project(v, feet, bx, by) || !project(v, top, tx, ty)) return;
    const float h = static_cast<float>(by - ty);
    if (h < 6.f || h > 1600.f) return;
    const float w = static_cast<float>(h * 0.42);

    uint8_t team{};
    if (ok(e.state)) vmm::rd(e.state + off::State_Team, &team, sizeof(team));
    if (!cfg.teammates && team == static_cast<uint8_t>(my_team)) return;
    const ov::Color col = team_color(team, my_team);

    const float l = static_cast<float>(tx - w * 0.5), r = static_cast<float>(tx + w * 0.5);

    if (cfg.boxes) ov::box(l, ty, r, by, col, 1.4f);

    if (cfg.skeleton && bone_arr != 0) {
        for (const auto& pr : kPairs) {
            Vec3d a{}, c{};
            if (!bone_pos(mesh, bone_arr, pr[0], a) || !bone_pos(mesh, bone_arr, pr[1], c)) continue;
            float ax, ay, cx, cy;
            if (!project(v, a, ax, ay) || !project(v, c, cx, cy)) continue;
            ov::line(ax, ay, cx, cy, 1.3f, col);
        }
    }

    if (cfg.health) {
        uint64_t hs{}; float cur{}, max{};
        bool hs_ok = vmm::rd(pawn + off::Pawn_HealthSet, &hs, sizeof(hs)) && ok(hs);
        if (hs_ok) {
            hs_ok = vmm::rd(hs + off::Health_Current, &cur, sizeof(cur));
            hs_ok = hs_ok && vmm::rd(hs + off::Health_Max, &max, sizeof(max));
        }
        if (!hs_ok) { /* skip bar on failed read */ }
        else {
            if (max <= 0.f) max = 100.f;
            float frac = cur / max;
            if (frac < 0.f) frac = 0.f;
            if (frac > 1.f) frac = 1.f;
            ov::fill(l - 6.f, ty, l - 3.f, by, { 0.f, 0.f, 0.f, 0.65f });
            ov::fill(l - 6.f, by - h * frac, l - 3.f, by,
                frac > 0.6f ? ov::Color{ 0.30f, 0.90f, 0.30f, 1.f }
                : frac > 0.3f ? ov::Color{ 1.00f, 0.80f, 0.20f, 1.f }
                : ov::Color{ 1.00f, 0.25f, 0.25f, 1.f });
        }
    }

    if (cfg.names && ok(e.state)) {
        wchar_t nm[32]{};
        read_name(e.state, nm, 32);
        if (nm[0]) ov::text(tx - ov::textw(nm, 1.f) * 0.5f, ty - 11.f, nm, col);
    }

    if (cfg.dist) {
        wchar_t buf[16]{}; wchar_t tmp[8];
        int n = 0, k = 0, t = static_cast<int>(metres);
        if (!t) buf[n++] = L'0';
        while (t) { tmp[k++] = static_cast<wchar_t>(L'0' + t % 10); t /= 10; }
        while (k) buf[n++] = tmp[--k];
        buf[n++] = L'M'; buf[n] = 0;
        ov::text(tx - ov::textw(buf, 0.8f) * 0.5f, by + 2.f, buf, { 0.85f, 0.85f, 0.85f, 1.f }, 0.8f);
    }

    if (cfg.lines) ov::line(static_cast<float>(v.w) * 0.5f, static_cast<float>(v.h), tx, by, 1.2f, col);
}

bool refresh_world() {
    uint64_t engine{}, vp{}, world{};
    if (!vmm::rd(vmm::base() + off::GEngine, &engine, sizeof(engine)) || !ok(engine)) return false;
    if (!vmm::rd(engine + off::Engine_GameViewportClient, &vp, sizeof(vp)) || !ok(vp)) return false;
    if (!vmm::rd(vp + off::Viewport_World, &world, sizeof(world)) || !ok(world)) return false;
    g_world = world;
    return true;
}

// ACharacter validation without a full IsA: a live character has a mesh, a
// sane capsule and a finite location. Cheaper than UObject::Class -> UClass
// -> FName and it rejects the vast majority of non-character actors.
bool looks_character(uint64_t actor, Vec3d& feet) {
    if (!ok(actor)) return false;
    uint64_t mesh{};
    if (!vmm::rd(actor + off::Pawn_Mesh, &mesh, sizeof(mesh)) || !ok(mesh)) return false;
    if (!vmm::rd(mesh + off::Comp_C2W + off::Xform_Translation, &feet, sizeof(feet))) return false;
    if (feet.x != feet.x || feet.y != feet.y || feet.z != feet.z) return false;
    if (!feet.x && !feet.y && !feet.z) return false;
    return true;
}

} // namespace

bool init() {
    if (!vmm::base() && !resolve_base()) {
        printf("[!] resolve_base failed\n");
        return false;
    }
    printf("[+] client base 0x%llx size 0x%llx\n", (unsigned long long)vmm::base(), (unsigned long long)vmm::size());
    if (!refresh_world()) {
        printf("[!] refresh_world failed\n");
        return false;
    }
    printf("[+] world 0x%llx\n", (unsigned long long)g_world);
    if (!use_actors) {
        uint64_t gs{};
        if (!vmm::rd(g_world + off::World_GameState, &gs, sizeof(gs)) || !ok(gs)) {
            printf("[!] World->GameState failed\n");
            return false;
        }
        printf("[+] gamestate 0x%llx\n", (unsigned long long)gs);
    }
    g_ready = true;
    return true;
}

void shutdown() { g_ready = false; g_world = g_pc = g_my_state = g_my_pawn = 0; }
bool ready() { return g_ready; }

void draw() {
    if (!g_ready || !cfg.on || !vmm::attached()) return;
    if (!refresh_world()) return;

    Pov v{};
    if (!build_view(v)) return;

    int my_team = -1;
    if (ok(g_my_state)) {
        uint8_t t{};
        vmm::rd(g_my_state + off::State_Team, &t, sizeof(t));
        my_team = t;
    }

    if (use_actors) {
        uint64_t level{}, arr{};
        int count{};
        if (!vmm::rd(g_world + off::World_PersistentLevel, &level, sizeof(level)) || !ok(level)) return;
        if (!vmm::rd(level + off::Level_Actors, &arr, sizeof(arr)) || !ok(arr)) return;
        if (!vmm::rd(level + off::Level_Actors + 8, &count, sizeof(count))) return;
        if (count <= 0) return;
        if (count > off::kMaxActors) count = off::kMaxActors;

        for (int i = 0; i < count; ++i) {
            uint64_t actor{};
            if (!vmm::rd(arr + static_cast<uint64_t>(i) * 8, &actor, sizeof(actor)) || !ok(actor)) continue;
            Vec3d feet{};
            if (!looks_character(actor, feet)) continue;
            Entity e{ actor, 0 };
            if (!vmm::rd(actor + off::Pawn_PlayerState, &e.state, sizeof(e.state))) e.state = 0;
            if (ok(e.state)) {
                uint8_t flags{};
                vmm::rd(e.state + off::State_Flags, &flags, sizeof(flags));
                if (!cfg.bots && (flags & 0x08)) continue;
                if (flags & 0x02) continue;
                if (flags & 0x20) continue;
            }
            draw_entity(v, e, my_team);
        }
        return;
    }

    uint64_t gs{}, arr{};
    int count{};
    if (!vmm::rd(g_world + off::World_GameState, &gs, sizeof(gs)) || !ok(gs)) return;
    if (!vmm::rd(gs + off::GameState_PlayerArray, &arr, sizeof(arr)) || !ok(arr)) return;
    if (!vmm::rd(gs + off::GameState_PlayerArray + 8, &count, sizeof(count))) return;
    if (count <= 0) return;
    if (count > off::kMaxPlayers) count = off::kMaxPlayers;

    for (int i = 0; i < count; ++i) {
        uint64_t state{};
        if (!vmm::rd(arr + static_cast<uint64_t>(i) * 8, &state, sizeof(state)) || !ok(state)) continue;
        if (state == g_my_state) continue;
        uint8_t flags{};
        vmm::rd(state + off::State_Flags, &flags, sizeof(flags));
        if (!cfg.bots && (flags & 0x08)) continue;
        if (flags & 0x02) continue;
        if (flags & 0x20) continue;
        Entity e{ 0, state };
        if (!vmm::rd(state + off::State_Pawn, &e.pawn, sizeof(e.pawn))) continue;
        draw_entity(v, e, my_team);
    }
}

bool probe() {
    auto step = [](const char* what, bool good) {
        printf("  %-34s %s\n", what, good ? "ok" : "<- rejected");
        return good;
    };

    printf("chain:\n");
    uint64_t engine{};
    if (!step("GEngine", vmm::rd(vmm::base() + off::GEngine, &engine, sizeof(engine)) && ok(engine))) return false;

    uint64_t viewport{};
    if (!step("Engine->GameViewportClient", vmm::rd(engine + off::Engine_GameViewportClient, &viewport, sizeof(viewport)) && ok(viewport))) return false;

    uint64_t world{};
    if (!step("Viewport->World", vmm::rd(viewport + off::Viewport_World, &world, sizeof(world)) && ok(world))) return false;

    if (use_actors) {
        uint64_t level{};
        if (!step("World->PersistentLevel", vmm::rd(world + off::World_PersistentLevel, &level, sizeof(level)) && ok(level))) return false;

        uint64_t arr{};
        if (!step("Level->Actors", vmm::rd(level + off::Level_Actors, &arr, sizeof(arr)) && ok(arr))) return false;

        int count{};
        if (!vmm::rd(level + off::Level_Actors + 8, &count, sizeof(count))) count = 0;
        if (!step("Level->Actors.Count > 0", count > 0)) return false;
        if (count > off::kMaxActors) count = off::kMaxActors;

        printf("\nactors (%d):\n", count);
        int shown = 0;
        for (int i = 0; i < count && shown < 3; ++i) {
            uint64_t actor{};
            if (!vmm::rd(arr + static_cast<uint64_t>(i) * 8, &actor, sizeof(actor)) || !ok(actor)) continue;
            Vec3d feet{};
            if (!looks_character(actor, feet)) continue;
            printf("  %d. actor=%s mesh=yes pos=(%.0f, %.0f, %.0f)\n",
                   shown + 1, ok(actor) ? "yes" : "no", feet.x, feet.y, feet.z);
            ++shown;
        }
        if (!shown) printf("  (none readable)\n");
    } else {
        uint64_t gs{};
        if (!step("World->GameState", vmm::rd(world + off::World_GameState, &gs, sizeof(gs)) && ok(gs))) return false;

        uint64_t gi{};
        if (!step("World->OwningGameInstance", vmm::rd(world + off::World_OwningGameInstance, &gi, sizeof(gi)) && ok(gi))) return false;

        uint64_t lp{}; int lpc{};
        if (!step("GameInstance->LocalPlayers", vmm::rd(gi + off::GameInstance_LocalPlayers, &lp, sizeof(lp)) && ok(lp))) return false;
        vmm::rd(gi + off::GameInstance_LocalPlayers + 8, &lpc, sizeof(lpc));
        if (!step("LocalPlayers.Count > 0", lpc > 0)) return false;

        uint64_t local{};
        if (!step("LocalPlayers[0]", vmm::rd(lp, &local, sizeof(local)) && ok(local))) return false;

        uint64_t ctrl{};
        if (!step("LocalPlayer->PlayerController", vmm::rd(local + off::Player_PlayerController, &ctrl, sizeof(ctrl)) && ok(ctrl))) return false;

        uint64_t mystate{};
        vmm::rd(ctrl + off::Controller_PlayerState, &mystate, sizeof(mystate));
        if (!step("Controller->PlayerState", ok(mystate))) return false;

        uint64_t cam{};
        if (!step("Controller->PlayerCameraManager", vmm::rd(ctrl + off::Controller_PlayerCameraManager, &cam, sizeof(cam)) && ok(cam))) return false;

        const uint64_t pov = cam + off::Camera_CameraCachePrivate + off::CacheEntry_POV;
        Vec3d loc{}, rot{}; double fov{};
        if (!step("POV.Location", vmm::rd(pov + off::POV_Location, &loc, sizeof(loc)))) return false;
        if (!step("POV.Rotation", vmm::rd(pov + off::POV_Rotation, &rot, sizeof(rot)))) return false;
        if (!step("POV.FOV", vmm::rd(pov + off::POV_FOV, &fov, sizeof(fov)) && fov >= 1.0 && fov <= 179.0)) return false;

        printf("\nPOV: location=(%.1f, %.1f, %.1f) rotation=(%.1f, %.1f, %.1f) fov=%.1f\n",
               loc.x, loc.y, loc.z, rot.x, rot.y, rot.z, fov);

        uint64_t arr{}; int count{};
        if (!step("GameState->PlayerArray", vmm::rd(gs + off::GameState_PlayerArray, &arr, sizeof(arr)) && ok(arr))) return false;
        vmm::rd(gs + off::GameState_PlayerArray + 8, &count, sizeof(count));
        if (!step("PlayerArray.Count > 0", count > 0)) return false;
        if (count > off::kMaxPlayers) count = off::kMaxPlayers;

        printf("\nplayers (%d):\n", count);
        int shown = 0;
        for (int i = 0; i < count && shown < 3; ++i) {
            uint64_t state{};
            if (!vmm::rd(arr + static_cast<uint64_t>(i) * 8, &state, sizeof(state)) || !ok(state)) continue;
            if (state == mystate) continue;

            wchar_t nm[32]{}; read_name(state, nm, 32);
            uint64_t pawn{}; vmm::rd(state + off::State_Pawn, &pawn, sizeof(pawn));
            uint64_t mesh{}; if (ok(pawn)) vmm::rd(pawn + off::Pawn_Mesh, &mesh, sizeof(mesh));
            Vec3d feet{};
            if (ok(mesh)) vmm::rd(mesh + off::Comp_C2W + off::Xform_Translation, &feet, sizeof(feet));
            uint8_t team{}; vmm::rd(state + off::State_Team, &team, sizeof(team));
            uint8_t flags{}; vmm::rd(state + off::State_Flags, &flags, sizeof(flags));

            printf("  %d. %-18ls team=%u flags=0x%02x pawn=%s mesh=%s pos=(%.0f, %.0f, %.0f)\n",
                   shown + 1, nm[0] ? nm : L"(no name)", (unsigned)team, flags,
                   ok(pawn) ? "yes" : "no", ok(mesh) ? "yes" : "no", feet.x, feet.y, feet.z);
            ++shown;
        }
        if (!shown) printf("  (none readable)\n");
    }
    return true;
}

} // namespace esp
