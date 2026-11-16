import sys

with open('C:\\dev\\fortesp\\ring0\\src\\esp.cpp', 'r') as f:
    c = f.read()

old = '''    printf("  PlayerArray count: %d\n", count);

    return true;
}

} // namespace esp'''

new = '''    printf("  PlayerArray count: %d\\n", count);

    return true;
}

bool read_name(uint64_t state, wchar_t* out, int cap) {
    uint64_t nb{};
    if (!vmm::rd(state + off::State_Name, &nb, sizeof(nb)) || !ok(nb)) return 0;
    if (nb == 0 || nb > cap * 2) return 0;
    uint64_t buf{}; uint16_t len{};
    if (!vmm::rd(state + off::State_Name, &len, sizeof(len))) return 0;
    if (!vmm::rd(state + off::State_Name + 8, &buf_addr, sizeof(buf_addr))) return 0;
    if (!buf_addr || !len || len > cap * 2) return 0;
    wchar_t buf_tmp[256]{};
    if (!vmm::rd(buf_addr, buf_tmp, len)) return 0;
    int n = len / 2;
    for (int i = 0; i < n && i < cap - 1; ++i) out[i] = buf_tmp[i];
    out[n] = 0;
    return n;
}

bool bone_pos(uint64_t mesh, int idx, Vec3d& out) {
    uint64_t arr{};
    if (!vmm::rd(mesh + off::Mesh_BoneArray, &arr, sizeof(arr)) || !ok(arr)) return false;
    const uint64_t at = arr + static_cast<uint64_t>(idx) * off::Xform_Stride + off::Xform_Translation;
    return vmm::rd(at, &out, sizeof(out));
}

bool project(const Pov& v, const Vec3d& p, float& sx, float& sy) {
    const Vec3d d{ p.x - v.loc.x, p.y - v.loc.y, p.z - v.loc.z };
    const double fwd = d.x * v.fwd.x + d.y * v.fwd.y + d.z * v.fwd.z;
    if (fwd <= 0.0) return false;
    const double rgt = d.x * v.right.x + d.y * v.right.y + d.z * v.fwd.z;
    const double up  = d.x * v.up.x   + d.y * v.up.y   + d.z * v.up.z;
    sx = static_cast<float>(v.w * 0.5 + (rgt * v.focal / fwd));
    sy = static_cast<float>(v.h * 0.5 - (up  * v.focal / fwd));
    return sx >= 0.f && sx < static_cast<float>(v.w) && sy >= 0.f && sy < static_cast<float>(v.h);
}

ov::Color team_color(uint8_t team, int my_team) {
    if (!cfg.team_colors) return { 0.9f, 0.9f, 0.9f, 1.f };
    if (team == static_cast<uint8_t>(my_team)) return { 0.3f, 0.9f, 0.3f, 1.f };
    switch (team & 7) {
        case 0: return { 1.0f, 0.3f, 0.3f, 1.f };
        case 1: return { 0.4f, 0.6f, 1.0f, 1.f };
        case 2: return { 1.0f, 0.8f, 0.3f, 1.f };
        case 3: return { 0.8f, 0.4f, 1.0f, 1.f };
        case 4: return { 0.3f, 1.0f, 0.9f, 1.f };
        default: return { 1.0f, 0.6f, 0.9f, 1.f };
    }
}

} // namespace esp'''

if old in c:
    c = c.replace(old, new, 1)
    with open('C:\\dev\\fortesp\\ring0\\src\\esp.cpp', 'w') as f:
        f.write(c)
    print('SUCCESS')
else:
    print('NOT FOUND')
    # Debug
    idx = c.find('    printf("  PlayerArray count: %d\\n", count);')
    if idx >= 0:
        print(f'Found at {idx}')
        print(repr(c[idx:idx+200]))