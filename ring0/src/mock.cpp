#include "mock.hpp"
#include "r0.hpp"
#include "vmm.hpp"
#include "esp.hpp"
#include "ov.hpp"
#include "offsets.hpp"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace mock {
namespace {

// ---------------------------------------------------------------------------
// Synthetic machine layout
//
//   user   VA  0x00007FF600000000  -> 2 MB pages
//   kernel VA  0xFFFF800000000000  -> 2 MB pages
//
// A 2 MB large page resolves to  PA = (pde & 0x000FFFFFFFE00000) + (va & 0x1FFFFF).
// The PDE address field only carries bits 21+, so consecutive 2 MB chunks
// advance the physical base by 2 MB but the VA must sit in the *same* 1 GB
// region - hence the PD slot for chunk j is (pd0 + j) & 0x1FF.
//
// The physical side is sparse (page-granular map), so a 512 MB user VA range
// costs only the pages actually touched.
// ---------------------------------------------------------------------------
constexpr uint64_t kVaBase   = 0x00007FF600000000ull;
constexpr uint64_t kKvaBase  = 0xFFFF800000000000ull;
constexpr uint64_t kDataPa   = 0x0000000010000000ull;
constexpr uint64_t kKernPa   = 0x0000000020000000ull;
constexpr uint64_t kPageSz   = 0x1000;

// Page-table physical pages.
constexpr uint64_t kPml4Pa   = 0x1000;
constexpr uint64_t kPdptPa   = 0x2000;
constexpr uint64_t kPdPa     = 0x3000;
constexpr uint64_t kPdptkPa  = 0x5000;
constexpr uint64_t kPdkPa    = 0x6000;

// Object offsets inside the user data region (== VA offset from kVaBase).
constexpr uint64_t O_CLIENT       = 0x00000000;
constexpr uint64_t O_ENGINE      = 0x00100000;
constexpr uint64_t O_VIEWPORT    = 0x00101000;
constexpr uint64_t O_WORLD       = 0x00102000;
constexpr uint64_t O_GAMEINST    = 0x00103000;
constexpr uint64_t O_LOCALARR    = 0x00104000;
constexpr uint64_t O_LOCALPLAYER = 0x00104100;
constexpr uint64_t O_CONTROLLER  = 0x00105000;
constexpr uint64_t O_CAMERAMGR   = 0x00106000;
constexpr uint64_t O_CAMERACACHE = 0x00107000;
constexpr uint64_t O_GAMESTATE   = 0x00108000;
constexpr uint64_t O_PLAYERARRAY = 0x00109000;
constexpr uint64_t O_STATE0      = 0x0010A000;
constexpr uint64_t O_STATE1      = 0x0010B000;
constexpr uint64_t O_PAWN0       = 0x0010C000;
constexpr uint64_t O_PAWN1       = 0x0010D000;
constexpr uint64_t O_MESH0       = 0x0010E000;
constexpr uint64_t O_MESH1       = 0x0010F000;
constexpr uint64_t O_HEALTH0     = 0x00110000;
constexpr uint64_t O_HEALTH1     = 0x00111000;
constexpr uint64_t O_NAMEBUF0    = 0x00112000;
constexpr uint64_t O_NAMEBUF1    = 0x00113000;
constexpr uint64_t O_PEB         = 0x00120000;
constexpr uint64_t O_LDR         = 0x00121000;
constexpr uint64_t O_MODLIST     = 0x00122000;
constexpr uint64_t O_MODENTRY    = 0x00123000;
constexpr uint64_t O_MODNAME     = 0x00124000;

// Kernel-side offsets.
constexpr uint64_t K_EPROCESS    = 0x1000;

// Sparse physical memory.
std::unordered_map<uint64_t, std::vector<uint8_t>> g_pages;

uint8_t* page_for_write(uint64_t pa) {
    const uint64_t key = pa / kPageSz;
    auto it = g_pages.find(key);
    if (it == g_pages.end())
        it = g_pages.emplace(key, std::vector<uint8_t>(kPageSz, 0)).first;
    return it->second.data();
}

const uint8_t* page_for_read(uint64_t pa) {
    auto it = g_pages.find(pa / kPageSz);
    return it == g_pages.end() ? nullptr : it->second.data();
}

// ---- mock backend --------------------------------------------------------
bool mock_open()  { return true; }
void mock_close() {}

bool mock_read(uint64_t pa, void* out, size_t len) {
    auto* dst = static_cast<uint8_t*>(out);
    for (size_t i = 0; i < len; ++i) {
        const uint64_t a = pa + i;
        const uint8_t* p = page_for_read(a);
        if (!p) return false;
        dst[i] = p[a % kPageSz];
    }
    return true;
}

bool mock_write(uint64_t pa, const void* in, size_t len) {
    const auto* src = static_cast<const uint8_t*>(in);
    for (size_t i = 0; i < len; ++i) {
        const uint64_t a = pa + i;
        uint8_t* p = page_for_write(a);
        p[a % kPageSz] = src[i];
    }
    return true;
}

// The mock's "kernel VA" space is the kernel data region.
bool mock_vwrite(uint64_t va, const void* in, size_t len) {
    const uint64_t off = va - kKvaBase;
    if (va < kKvaBase) return false;
    return mock_write(kKernPa + off, in, len);
}

bool mock_vread(uint64_t va, void* out, size_t len) {
    if (va < kKvaBase) return false;
    return mock_read(kKernPa + (va - kKvaBase), out, len);
}

const r0::Backend kMockBackend{L"mock", mock_open, mock_close,
                               mock_read, mock_write, mock_vwrite, mock_vread};

// ---- writers into the user data region -----------------------------------
uint64_t uva(uint64_t off) { return kVaBase + off; }
uint64_t kva(uint64_t off) { return kKvaBase + off; }
uint64_t upa(uint64_t off) { return kDataPa + off; }
uint64_t kpa(uint64_t off) { return kKernPa + off; }

void w8 (uint64_t off, uint8_t v)   { uint8_t* p = page_for_write(upa(off)); p[off % kPageSz] = v; }
void w16(uint64_t off, uint16_t v)  { uint8_t* p = page_for_write(upa(off)); memcpy(p + off % kPageSz, &v, 2); }
void w32(uint64_t off, uint32_t v)  { uint8_t* p = page_for_write(upa(off)); memcpy(p + off % kPageSz, &v, 4); }
void w64(uint64_t off, uint64_t v)  { uint8_t* p = page_for_write(upa(off)); memcpy(p + off % kPageSz, &v, 8); }
void wf32(uint64_t off, float v)    { uint8_t* p = page_for_write(upa(off)); memcpy(p + off % kPageSz, &v, 4); }
void wf64(uint64_t off, double v)   { uint8_t* p = page_for_write(upa(off)); memcpy(p + off % kPageSz, &v, 8); }
void wbytes(uint64_t off, const void* src, size_t n) {
    uint8_t* p = page_for_write(upa(off));
    memcpy(p + off % kPageSz, src, n);
}
void kw64(uint64_t off, uint64_t v) {
    uint8_t* p = page_for_write(kpa(off));
    memcpy(p + off % kPageSz, &v, 8);
}

// ---- page-table construction ---------------------------------------------
void put_pde(uint64_t pd_pa, uint64_t slot, uint64_t phys) {
    uint8_t* p = page_for_write(pd_pa);
    const uint64_t v = (phys & 0x000FFFFFFFE00000ull) | 0x83ull;  // Present|Write|User|Large
    memcpy(p + (slot * 8) % kPageSz, &v, 8);
}

void build_page_tables() {
    // --- user half ---
    const uint64_t u_pml4 = (kVaBase >> 39) & 0x1FF;
    const uint64_t u_pdpt = (kVaBase >> 30) & 0x1FF;
    const uint64_t u_pd0  = (kVaBase >> 21) & 0x1FF;

    {
        uint8_t* p = page_for_write(kPml4Pa);
        const uint64_t v = kPdptPa | 0x03ull;
        memcpy(p + (u_pml4 * 8) % kPageSz, &v, 8);
    }
    {
        uint8_t* p = page_for_write(kPdptPa);
        const uint64_t v = kPdPa | 0x03ull;
        memcpy(p + (u_pdpt * 8) % kPageSz, &v, 8);
    }
    for (uint64_t j = 0; j < 512; ++j)
        put_pde(kPdPa, (u_pd0 + j) & 0x1FF, kDataPa + j * 0x200000ull);

    // --- kernel half (one 2 MB chunk is enough) ---
    const uint64_t k_pml4 = (kKvaBase >> 39) & 0x1FF;
    const uint64_t k_pdpt = (kKvaBase >> 30) & 0x1FF;
    const uint64_t k_pd0  = (kKvaBase >> 21) & 0x1FF;

    {
        uint8_t* p = page_for_write(kPml4Pa);
        const uint64_t v = kPdptkPa | 0x03ull;
        memcpy(p + (k_pml4 * 8) % kPageSz, &v, 8);
    }
    {
        uint8_t* p = page_for_write(kPdptkPa);
        const uint64_t v = kPdkPa | 0x03ull;
        memcpy(p + (k_pdpt * 8) % kPageSz, &v, 8);
    }
    put_pde(kPdkPa, k_pd0, kKernPa);
}

// ---- FString encoding (inverse of esp::decode_fstring) -------------------
int encode_fstring(const wchar_t* plain, wchar_t* out, int cap) {
    const int n = static_cast<int>(wcslen(plain));
    int key = ((n + 1) - 1) & 3;                 // same seed the decoder uses
    for (int i = 0; i < n && i < cap; ++i) {
        out[i] = static_cast<wchar_t>(plain[i] + (key & 7));
        key += 3;
    }
    return n;
}

void write_name(uint64_t state_off, const wchar_t* plain, uint64_t buf_off) {
    const int n = static_cast<int>(wcslen(plain));
    const int len = n + 1;                              // FString.Length counts the null
    wchar_t tmp[64]{};
    encode_fstring(plain, tmp, 64);
    wbytes(buf_off, tmp, static_cast<size_t>(n) * sizeof(wchar_t));
    w64(state_off + off::State_Name, uva(buf_off));      // FString.Data
    w32(state_off + off::State_Name + 8, len);            // FString.Length
    w32(state_off + off::State_Name + 12, len);           // FString.Max
}

// ---- build the synthetic Fortnite graph ----------------------------------
void build_graph() {
    w16(O_CLIENT, 0x5A4D);                                   // module MZ

    w64(O_CLIENT + off::GEngine, uva(O_ENGINE));            // GEngine -> UEngine
    w64(O_ENGINE + off::Engine_GameViewportClient, uva(O_VIEWPORT));
    w64(O_VIEWPORT + off::Viewport_World, uva(O_WORLD));

    w64(O_WORLD + off::World_GameState, uva(O_GAMESTATE));
    w64(O_WORLD + off::World_OwningGameInstance, uva(O_GAMEINST));

    w64(O_GAMEINST + off::GameInstance_LocalPlayers, uva(O_LOCALARR));
    w32(O_GAMEINST + off::GameInstance_LocalPlayers + 8, 1);
    w32(O_GAMEINST + off::GameInstance_LocalPlayers + 12, 1);
    w64(O_LOCALARR, uva(O_LOCALPLAYER));

    w64(O_LOCALPLAYER + off::Player_PlayerController, uva(O_CONTROLLER));

    w64(O_CONTROLLER + off::Controller_PlayerState, uva(O_STATE0));
    w64(O_CONTROLLER + off::Controller_PlayerCameraManager, uva(O_CAMERAMGR));

    w64(O_CAMERAMGR + off::Camera_CameraCachePrivate, uva(O_CAMERACACHE));

    // POV: { FVector3d Location; FRotator3d Rotation; double FOV }
    const uint64_t po = O_CAMERAMGR + off::Camera_CameraCachePrivate + off::CacheEntry_POV;
    wf64(po + off::POV_Location + 0,  1000.0);
    wf64(po + off::POV_Location + 8,  2000.0);
    wf64(po + off::POV_Location + 16,  100.0);
    wf64(po + off::POV_Rotation + 0,     0.0);   // pitch
    wf64(po + off::POV_Rotation + 8,    90.0);   // yaw -> facing +Y
    wf64(po + off::POV_Rotation + 16,    0.0);   // roll
    wf64(po + off::POV_FOV,             90.0);

    w64(O_GAMESTATE + off::GameState_PlayerArray, uva(O_PLAYERARRAY));
    w32(O_GAMESTATE + off::GameState_PlayerArray + 8, 2);
    w32(O_GAMESTATE + off::GameState_PlayerArray + 12, 2);
    w64(O_PLAYERARRAY + 0, uva(O_STATE0));
    w64(O_PLAYERARRAY + 8, uva(O_STATE1));

    // local player
    w64(O_STATE0 + off::State_Pawn, uva(O_PAWN0));
    w8 (O_STATE0 + off::State_Team, 3);            // byte, not int32
    w8 (O_STATE0 + off::State_Flags, 0x00);
    write_name(O_STATE0, L"LocalPlayer", O_NAMEBUF0);

    // enemy
    w64(O_STATE1 + off::State_Pawn, uva(O_PAWN1));
    w8 (O_STATE1 + off::State_Team, 7);
    w8 (O_STATE1 + off::State_Flags, 0x00);
    write_name(O_STATE1, L"TestEnemy123", O_NAMEBUF1);

    w64(O_PAWN0 + off::Pawn_Mesh, uva(O_MESH0));
    w64(O_PAWN0 + off::Pawn_HealthSet, uva(O_HEALTH0));
    wf32(O_PAWN0 + off::Pawn_CapsuleHalf, 88.0f);
    w8 (O_PAWN0 + off::Pawn_Dying, 0x00);

    // enemy pawn: 3000 units ahead (+Y), same height as the camera
    w64(O_PAWN1 + off::Pawn_Mesh, uva(O_MESH1));
    w64(O_PAWN1 + off::Pawn_HealthSet, uva(O_HEALTH1));
    wf32(O_PAWN1 + off::Pawn_CapsuleHalf, 88.0f);
    w8 (O_PAWN1 + off::Pawn_Dying, 0x00);

    // ComponentToWorld translation: FTransform { FQuat4d; FVector3d; FVector3d }
    // FQuat4d is 32 bytes, so Translation is at +0x20 and is 3x double.
    wf64(O_MESH0 + off::Comp_C2W + off::Xform_Translation + 0,  1000.0);
    wf64(O_MESH0 + off::Comp_C2W + off::Xform_Translation + 8,  2000.0);
    wf64(O_MESH0 + off::Comp_C2W + off::Xform_Translation + 16,  100.0);

    wf64(O_MESH1 + off::Comp_C2W + off::Xform_Translation + 0,  1000.0);
    wf64(O_MESH1 + off::Comp_C2W + off::Xform_Translation + 8,  5000.0);
    wf64(O_MESH1 + off::Comp_C2W + off::Xform_Translation + 16,  100.0);

    wf32(O_HEALTH0 + off::Health_Current, 100.0f);
    wf32(O_HEALTH0 + off::Health_Max,     100.0f);
    wf32(O_HEALTH1 + off::Health_Current,  40.0f);
    wf32(O_HEALTH1 + off::Health_Max,     100.0f);

    // PEB / LDR / module list.
    //   x64 PEB:  Ldr at +0x18
    //   PEB_LDR_DATA: InLoadOrderModuleList at +0x10
    w64(O_PEB + 0x18, uva(O_LDR));
    w64(O_LDR + 0x10, uva(O_MODLIST));

    w64(O_MODLIST + 0x00, uva(O_MODENTRY));
    w64(O_MODLIST + 0x08, uva(O_MODENTRY));
    w64(O_MODENTRY + 0x00, uva(O_MODLIST));
    w64(O_MODENTRY + 0x08, uva(O_MODLIST));
    w64(O_MODENTRY + 0x30, uva(O_CLIENT));          // DllBase
    w32(O_MODENTRY + 0x40, 0x01000000);             // SizeOfImage

    const wchar_t* modname = L"FortniteClient-Win64-Shipping.exe";
    const size_t nlen = (wcslen(modname) + 1) * sizeof(wchar_t);
    wbytes(O_MODNAME, modname, nlen);
    w16(O_MODENTRY + 0x58, static_cast<uint16_t>(nlen));
    w16(O_MODENTRY + 0x5A, static_cast<uint16_t>(nlen));
    w64(O_MODENTRY + 0x60, uva(O_MODNAME));

    // mock EPROCESS: PEB pointer at +g_lay.peb
    kw64(K_EPROCESS + vmm::g_lay.peb, uva(O_PEB));
}

// ---- assertion plumbing --------------------------------------------------
int g_pass = 0, g_fail = 0;

void check(bool cond, const char* what) {
    if (cond) { ++g_pass; printf("  [PASS] %s\n", what); }
    else      { ++g_fail; printf("  [FAIL] %s\n", what); }
}

} // namespace

bool run() {
    // The mock's physical addresses are synthetic; a real RAM map would reject
    // every one of them. Permissive mode keeps phys_read() out of the way.
    vmm::phys_map_reset();
    g_pages.clear();
    g_pass = g_fail = 0;

    printf("ring0 mock self-test (no kernel driver required)\n\n");

    build_page_tables();
    build_graph();

    r0::set_backend(&kMockBackend);
    vmm::g_kcr3 = kPml4Pa;
    vmm::g_gcr3 = kPml4Pa;
    vmm::g_eprocess = kva(K_EPROCESS);
    vmm::g_base = 0;
    vmm::g_size = 0;
    vmm::g_ready = true;
    vmm::g_pid = 4242;
    ++vmm::g_stamp;

    printf("1. page walk\n");
    {
        uint64_t probe = 0x0123456789ABCDEFull;
        const uint64_t va = uva(0x0010A500);
        w64(0x0010A500, probe);

        uint64_t got = 0;
        check(vmm::read(va, &got, sizeof(got)) && got == probe,
              "8-byte read through a 2MB large-page mapping");

        uint8_t one = 0xFF;
        check(vmm::read(va, &one, 1) && one == static_cast<uint8_t>(probe),
              "1-byte read does not overflow the destination");

        const uint64_t va2 = uva(0x0030A500);
        uint64_t probe2 = 0x00FFEEDDCCBBAA00ull;
        w64(0x0030A500, probe2);
        uint64_t got2 = 0;
        check(vmm::read(va2, &got2, sizeof(got2)) && got2 == probe2,
              "read from a second 2MB chunk lands on the right physical page");

        constexpr uint64_t kScratch = 0x1F000000;
        const uint64_t va3 = uva(kScratch);
        uint64_t probe3 = 0x0BADF00DDEADBEEFull;
        w64(kScratch, probe3);
        uint64_t got3 = 0;
        check(vmm::read(va3, &got3, sizeof(got3)) && got3 == probe3,
              "read at base+0x1F000000 (far past the first chunk) resolves");
    }

    printf("\n2. kernel-space read (mock EPROCESS)\n");
    {
        uint64_t peb = 0;
        check(vmm::kread(vmm::g_eprocess + vmm::g_lay.peb, &peb, sizeof(peb))
              && peb == uva(O_PEB),
              "EPROCESS->Peb resolves to the target PEB");
    }

    printf("\n3. PEB / LDR module walk\n");
    {
        esp::shutdown();
        vmm::g_base = 0;
        check(esp::init(), "resolve_base() finds the client through PEB->Ldr");
        check(vmm::base() == uva(O_CLIENT), "module base is the client image");
    }

    printf("\n4. offset chain\n");
    {
        check(esp::ready(), "esp::init() resolved GEngine->Viewport->World->GameState");
    }

    printf("\n5. FString decode\n");
    {
        wchar_t cipher[64]{};
        const int n = encode_fstring(L"TestEnemy123", cipher, 64);
        wchar_t out[64]{};
        const int d = esp::decode_fstring(cipher, n, out, 64);
        check(d == n && wcscmp(out, L"TestEnemy123") == 0,
              "encode/decode round-trips a name");

        uint64_t data = 0; int len = 0;
        vmm::read(uva(O_STATE1 + off::State_Name), &data, sizeof(data));
        vmm::read(uva(O_STATE1 + off::State_Name + 8), &len, sizeof(len));
        wchar_t raw[32]{};
        vmm::read(data, raw, sizeof(wchar_t) * static_cast<size_t>(len - 1));
        wchar_t dec[64]{};
        esp::decode_fstring(raw, len - 1, dec, 64);
        check(wcscmp(dec, L"TestEnemy123") == 0,
              "the name read out of the FString decodes correctly");
    }

    printf("\n6. LWC doubles\n");
    {
        // The POV Location is 3x double at +0x00. Read it back and check the
        // value is a real coordinate, not the low mantissa half of one.
        double loc[3]{};
        const uint64_t po = uva(O_CAMERAMGR + off::Camera_CameraCachePrivate + off::CacheEntry_POV);
        vmm::read(po + off::POV_Location, loc, sizeof(loc));
        check(loc[0] == 1000.0 && loc[1] == 2000.0 && loc[2] == 100.0,
              "POV.Location reads back as 3x double");

        double feet[3]{};
        vmm::read(uva(O_MESH1 + off::Comp_C2W + off::Xform_Translation), feet, sizeof(feet));
        check(feet[1] == 5000.0, "FTransform.Translation reads back as 3x double");

        uint8_t team = 0;
        vmm::read(uva(O_STATE1 + off::State_Team), &team, sizeof(team));
        check(team == 7, "State_Team reads back as a byte");
    }

    printf("\n7. projection and drawing\n");
    {
        const esp::Config saved = esp::cfg;
        esp::cfg.boxes = true;
        esp::cfg.health = true;
        esp::cfg.names = false;
        esp::cfg.dist = false;
        esp::cfg.lines = false;

        ov::set_surface(1920, 1080);
        ov::begin();
        esp::draw();
        const int verts = ov::pending();

        // one box (4 quads = 24 verts) + health bar (2 fills = 12 verts)
        check(verts == 36, "exactly one player drew a box and a health bar");
        check(verts != 72, "the local player was excluded");

        esp::cfg = saved;
    }

    printf("\n8. cleanup\n");
    {
        esp::shutdown();
        r0::set_backend(nullptr);
        vmm::g_ready = false;
        check(!esp::ready(), "esp::shutdown() clears readiness");
        check(!r0::alive(), "backend detached");
    }

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0;
}

} // namespace mock