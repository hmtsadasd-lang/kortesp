#include "game.hpp"
#include "log.hpp"
#include "../../shared/include/peb.hpp"
#include "../../shared/include/ntapi.hpp"
#include "../../shared/include/mem.hpp"

namespace {

using game::Vec;

// 43.00 (CL-59596594) offsets - baked from Underscores dump
namespace off {
    constexpr uintptr_t GEngine             = 0x1C8E2F48;
    constexpr uintptr_t Engine_GameViewport = 0xB70;
    constexpr uintptr_t Viewport_World      = 0x78;

    constexpr uintptr_t World_Location      = 0x178;
    constexpr uintptr_t World_Rotation      = 0x188;
    constexpr uintptr_t World_GameState     = 0x160;
    constexpr uintptr_t World_Seconds       = 0x198;

    constexpr uintptr_t GameState_Players   = 0x290;

    constexpr uintptr_t State_Pawn          = 0x2F0;
    constexpr uintptr_t State_Team          = 0xF81;
    constexpr uintptr_t State_Name          = 0x9F0;
    constexpr uintptr_t Text_String         = 0x28;

    constexpr uintptr_t Pawn_Mesh           = 0x318;
    constexpr uintptr_t Pawn_Dying          = 0x738;
    constexpr uintptr_t Pawn_HealthSet      = 0x1430;

    constexpr uintptr_t Health_Value        = 0x48;
    constexpr uintptr_t Health_Max          = 0x70;

    constexpr uintptr_t Mesh_C2W            = 0x1C0;
    constexpr uintptr_t Mesh_Bones          = 0x6F0;
    constexpr uintptr_t Mesh_RenderTime     = 0x2E8;
    constexpr uintptr_t Xform_Trans         = 0x10;
    constexpr uintptr_t Xform_Stride        = 0x60;

    constexpr int HeadBone = 8;
    constexpr int RootBone = 0;
    constexpr int MaxActors = 200;
}

uintptr_t g_world{};
uintptr_t g_base{};
bool g_ready{};
int g_w{}, g_h{};

inline bool okp(uintptr_t p) { return p > 0x10000 && p < 0x7FFFFFFFFFFF && !(p & 3); }
template <class T> inline T rd(uintptr_t a) { return okp(a) ? *reinterpret_cast<T*>(a) : T{}; }

struct Mat { float m[4][4]; };

bool bone_world(uintptr_t mesh, int idx, Vec& out) {
    Mat c2w = rd<Mat>(mesh + off::Mesh_C2W);
    uintptr_t arr = rd<uintptr_t>(mesh + off::Mesh_Bones);
    int count = rd<int>(mesh + off::Mesh_Bones + 8);
    if (!okp(arr) || count <= idx) return false;

    float* t = reinterpret_cast<float*>(arr + idx * off::Xform_Stride + off::Xform_Trans);
    out.x = t[0] * c2w.m[0][0] + t[1] * c2w.m[1][0] + t[2] * c2w.m[2][0] + c2w.m[3][0];
    out.y = t[0] * c2w.m[0][1] + t[1] * c2w.m[1][1] + t[2] * c2w.m[2][1] + c2w.m[3][1];
    out.z = t[0] * c2w.m[0][2] + t[1] * c2w.m[1][2] + t[2] * c2w.m[2][2] + c2w.m[3][2];
    return out.x > -1e7f && out.x < 1e7f;
}

void read_name(uintptr_t state, wchar_t* dst, size_t cap) {
    uintptr_t td = rd<uintptr_t>(state + off::State_Name);
    if (!okp(td)) return;

    uintptr_t str = td + off::Text_String;
    wchar_t* chars = rd<wchar_t*>(str);
    int len = rd<int>(str + 8);
    if (!okp(reinterpret_cast<uintptr_t>(chars)) || len <= 1 || len > 31) return;

    int i = (len - 1) & 3;
    for (int k = 0; k < len - 1 && k < static_cast<int>(cap) - 1; ++k) {
        dst[k] = static_cast<wchar_t>(chars[k] - (i & 7));
        i += 3;
    }
}

struct View {
    Vec loc, fwd, right, up;
    float focal{};
    int w{}, h{};

    bool project(const Vec& p, float& sx, float& sy) const {
        Vec d{ p.x - loc.x, p.y - loc.y, p.z - loc.z };
        float vz = d.x * fwd.x + d.y * fwd.y + d.z * fwd.z;
        if (vz < 1.f) return false;
        sx = w * 0.5f + (d.x * right.x + d.y * right.y + d.z * right.z) * focal / vz;
        sy = h * 0.5f - (d.x * up.x + d.y * up.y + d.z * up.z) * focal / vz;
        return sx > -80 && sy > -80 && sx < w + 80 && sy < h + 80;
    }
};

bool build_view(View& v) {
    v.loc = rd<Vec>(g_world + off::World_Location);
    Vec rot = rd<Vec>(g_world + off::World_Rotation);
    if (v.loc.x == 0.f && v.loc.y == 0.f && v.loc.z == 0.f) return false;

    Vec f{ rot.y, -rot.x, rot.z };
    float fl = sqrtf_(f.x * f.x + f.y * f.y + f.z * f.z);
    if (fl < 0.1f) return false;
    f = { f.x / fl, f.y / fl, f.z / fl };

    Vec r{ -f.y, f.x, 0.f };
    float rl = sqrtf_(r.x * r.x + r.y * r.y);
    if (rl < 0.01f) r = { 1, 0, 0 }; else r = { r.x / rl, r.y / rl, 0.f };

    Vec u{ r.y * f.z - r.z * f.y, r.z * f.x - r.x * f.z, r.x * f.y - r.y * f.x };

    v.fwd = f; v.right = r; v.up = u;
    g_w = render::width();
    g_h = render::height();
    v.w = g_w; v.h = g_h;
    v.focal = (g_w * 0.5f) / 1.0f;   // 90 deg horizontal
    return true;
}

render::Color team_color(int team, int my_team) {
    if (team == my_team) return { 0.30f, 0.85f, 0.40f, 1.f };
    switch (team % 6) {
        case 0:  return { 1.00f, 0.35f, 0.35f, 1.f };
        case 1:  return { 0.40f, 0.65f, 1.00f, 1.f };
        case 2:  return { 1.00f, 0.85f, 0.30f, 1.f };
        case 3:  return { 0.80f, 0.45f, 1.00f, 1.f };
        case 4:  return { 0.35f, 1.00f, 0.90f, 1.f };
        default: return { 1.00f, 0.55f, 0.85f, 1.f };
    }
}

} // namespace

namespace game {

bool init() {
    g_base = reinterpret_cast<uintptr_t>(peb::self()->ImageBaseAddress);
    if (!g_base) { log::w(L"no base"); return false; }

    uintptr_t engine = rd<uintptr_t>(g_base + off::GEngine);
    if (!engine) { log::w(L"gEngine null"); return false; }

    uintptr_t vp = rd<uintptr_t>(engine + off::Engine_GameViewport);
    if (!vp) { log::w(L"viewport null"); return false; }

    g_world = rd<uintptr_t>(vp + off::Viewport_World);
    if (!g_world) { log::w(L"world null"); return false; }

    if (!rd<uintptr_t>(g_world + off::World_GameState)) { log::w(L"gamestate null"); return false; }

    g_ready = true;
    log::w(L"chain resolved");
    return true;
}

bool ready() { return g_ready; }
void shutdown() { g_ready = false; }

void draw() {
    if (!g_ready) return;

    uintptr_t gs = rd<uintptr_t>(g_world + off::World_GameState);
    if (!gs) return;

    uintptr_t states = rd<uintptr_t>(gs + off::GameState_Players);
    int count = rd<int>(gs + off::GameState_Players + 8);
    if (!okp(states) || count <= 0) return;
    if (count > off::MaxActors) count = off::MaxActors;

    View view{};
    if (!build_view(view)) return;

    double now = rd<double>(g_world + off::World_Seconds);

    int my_team = -1;

    // First pass: determine my team
    for (int i = 0; i < count; ++i) {
        uintptr_t st = rd<uintptr_t>(states + i * 8);
        if (!okp(st)) continue;
        uintptr_t pawn = rd<uintptr_t>(st + off::State_Pawn);
        if (!okp(pawn)) continue;
        int team = rd<uint8_t>(st + off::State_Team);
        if (my_team < 0) my_team = team;
    }

    // Second pass: draw ESP for all valid players
    for (int i = 0; i < count; ++i) {
        uintptr_t st = rd<uintptr_t>(states + i * 8);
        if (!okp(st)) continue;

        uintptr_t pawn = rd<uintptr_t>(st + off::State_Pawn);
        if (!okp(pawn)) continue;

        if (rd<uint8_t>(pawn + off::Pawn_Dying) & 0x20) continue;

        uintptr_t mesh = rd<uintptr_t>(pawn + off::Pawn_Mesh);
        if (!okp(mesh)) continue;

        Vec head{}, origin{};
        if (!bone_world(mesh, off::HeadBone, head)) continue;
        if (!bone_world(mesh, off::RootBone, origin)) continue;

        int team = rd<uint8_t>(st + off::State_Team);
        if (my_team < 0) my_team = team;

        float hx, hy, ox, oy;
        if (!view.project(head, hx, hy)) continue;
        if (!view.project(origin, ox, oy)) continue;

        float hgt = oy - hy;
        if (hgt < 6.f || hgt > 1200.f) continue;
        float wid = hgt * 0.55f;
        float left = hx - wid * 0.5f;

        double last = rd<double>(mesh + off::Mesh_RenderTime);
        bool vis = last > 0.0 && (now - last) < 0.12;

        render::Color col = team_color(team, my_team);
        if (!vis) col.a = 0.45f;

        render::rect(left, hy, left + wid, oy, col);

        // Health bar
        if (true) {  // show_hp always in this build
            uintptr_t hs = rd<uintptr_t>(pawn + off::Pawn_HealthSet);
            float hp = okp(hs) ? rd<float>(hs + off::Health_Value) : 0.f;
            float mx = okp(hs) ? rd<float>(hs + off::Health_Max) : 0.f;
            if (mx <= 0.f) mx = 100.f;
            float frac = hp / mx;
            render::rect(left - 5.f, hy, left - 2.f, oy, { 0, 0, 0, 0.65f });
            render::rect(left - 5.f, oy - hgt * frac, left - 2.f, oy,
                frac > 0.6f ? render::Color{ 0.3f, 0.9f, 0.3f, 1.f }
                : frac > 0.3f ? render::Color{ 1.f, 0.8f, 0.2f, 1.f }
                              : render::Color{ 1.f, 0.25f, 0.25f, 1.f });
        }

        // Player name
        wchar_t nm[32]{};
        read_name(st, nm, 32);
        if (nm[0]) {
            float tw = render::text_width(nm, 1.f);
            render::text(hx - tw * 0.5f, hy - 10.f, nm, col);
        }

        // Distance
        Vec d{ origin.x - view.loc.x, origin.y - view.loc.y, origin.z - view.loc.z };
        float dist = sqrtf_(d.x * d.x + d.y * d.y + d.z * d.z) / 100.f;
        int whole = static_cast<int>(dist);
        wchar_t buf[16]{};
        int n = 0, t = whole;
        if (!t) buf[n++] = L'0';
        wchar_t tmp[8]; int k = 0;
        while (t) { tmp[k++] = L'0' + (t % 10); t /= 10; }
        while (k) buf[n++] = tmp[--k];
        buf[n++] = L'M';
        render::text(hx - 8.f, oy + 2.f, buf, { 0.85f, 0.85f, 0.85f, 1.f }, 0.8f);
    }
}

} // namespace game

// Bridge called by render.cpp's present hook
void esp_draw() {
    game::draw();
}