#include "map.hpp"
#include "game.hpp"
#include "render.hpp"
#include "hide.hpp"
#include "log.hpp"
#include "../../shared/include/syscall.hpp"
#include "../../shared/include/ntapi.hpp"
#include "../../shared/include/peb.hpp"
#include "../../shared/include/mem.hpp"

namespace {

void* g_stack{};
volatile bool g_run{ true };

constexpr int K_ESP = VK_F1;

bool pressed(int vk, bool& last) {
    bool cur = (ntapi::GetAsyncKeyState_(vk) & 0x8000) != 0;
    bool hit = cur && !last;
    last = cur;
    return hit;
}

DWORD __stdcall worker(void*) {
    log::w(L"worker up");

    bool l1{};  // ESP toggle

    while (!game::init()) { sys::sleep(5000000); }   // 500ms

    if (!render::init()) { log::w(L"render failed"); return 1; }

    while (g_run) {
        if (pressed(K_ESP, l1)) {
            render::enabled = !render::enabled;
            log::w(render::enabled ? L"esp on" : L"esp off");
        }

        sys::sleep(160000);   // ~16ms
    }

    render::shutdown();
    game::shutdown();
    log::w(L"worker exit");
    return 0;
}

bool in_ldr(void* base) {
    auto* p = peb::self();
    if (!p || !p->Ldr) return false;

    auto* head = reinterpret_cast<uint8_t*>(p->Ldr) + 0x10;
    auto* cur = *reinterpret_cast<uint8_t**>(head);
    for (int g = 0; cur && cur != head && g < 512; ++g) {
        auto* e = reinterpret_cast<LDR_DATA_TABLE_ENTRY_*>(cur);
        if (e->DllBase == base) return true;
        cur = *reinterpret_cast<uint8_t**>(cur);
    }
    return false;
}

// host mode: read ourselves from disk, then map into the game
bool relay(const wchar_t* self_path) {
    log::w(L"relay: open self");
    void* f = ntapi::CreateFileW_(self_path, 0x80000000, 1, nullptr, 3, 0, nullptr);
    if (!f || f == reinterpret_cast<void*>(-1)) { log::w(L"self read failed"); return false; }

    uint32_t size = static_cast<uint32_t>(ntapi::GetFileSize_(f));
    log::w(size ? L"relay: size ok" : L"relay: size zero");

    void* buf = nullptr;
    if (!NT_SUCCESS(sys::alloc(&buf, size, PAGE_RW_))) { log::w(L"relay: alloc failed"); return false; }

    uint32_t got = 0;
    ntapi::ReadFile_(f, buf, size, &got, nullptr);
    ntapi::CloseHandle_(f);
    log::w(got ? L"relay: read ok" : L"relay: read empty");

    auto* dos = static_cast<IMAGE_DOS_HEADER_*>(buf);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(static_cast<uint8_t*>(buf) + dos->e_lfanew);

    log::w(L"relay: find game");
    DWORD pid = ntapi::pid_by_name_(L"FortniteClient-Win64-Shipping.exe");
    if (!pid) { log::w(L"game not running"); sys::release(buf); return false; }

    log::w(L"relay: map into game");
    bool ok = map::into(pid, static_cast<uint8_t*>(buf), got, nullptr);
    sys::release(buf);
    return ok;
}

} // namespace

// filled by the loader when the payload is manually mapped into a host process
extern "C" __declspec(dllexport) wchar_t g_host_path[260] = { 0 };

// progress markers for the manual-map host (loader reads these after exit)
extern "C" __declspec(dllexport) volatile uint32_t g_trace[16] = { 0 };

// return target for manually mapped threads: the loader cannot use its own
// module addresses (ASLR differs per process), so terminate from inside the
// mapped image with a direct syscall.
extern "C" __declspec(dllexport) void __stdcall exit_thunk() {
    sys::init();
    sc2(static_cast<uint64_t>(-2), 0, sys::num("NtTerminateThread"));
    for (;;) {}
}

extern "C" __declspec(dllexport) uint32_t __stdcall probe0() {
    g_trace[0] = 0x1234;
    return 0x1234;
}

extern "C" __declspec(dllexport) uint32_t __stdcall probe1() {
    g_trace[0] = 0x11;
    log::open();
    g_trace[1] = 0x12;
    log::w(L"probe1");
    g_trace[2] = 0x13;
    log::close();
    g_trace[3] = 0x14;
    return 0x1235;
}

extern "C" __declspec(dllexport) uint32_t __stdcall probe2() {
    g_trace[0] = 0x21;
    bool ok = sys::init();
    g_trace[1] = ok ? 0x22 : 0x2F;
    g_trace[2] = sys::num("NtClose");
    return 0x1236;
}

extern "C" __declspec(dllexport) bool __stdcall start(void* arg1, uint32_t reason, void* arg3) {
    (void)reason; (void)arg3;
    g_trace[0] = 0xA0;

    // DllMain can be invoked more than once (failed attach/detach); only run once
    static int state = 0;
    static bool result = false;
    if (state == 2) return result;
    if (state == 1) return false;
    state = 1;

    log::open();
    g_trace[1] = 0xA1;
    log::w(L"entered");
    g_trace[2] = 0xA2;

    if (!sys::init()) { log::w(L"sys init failed"); log::close(); state = 2; result = false; return false; }
    g_trace[3] = 0xA3;

    if (in_ldr(arg1)) {
        g_trace[4] = 0xA4;
        log::w(L"host mode");
        wchar_t path[260]{};
        ntapi::GetModuleFileNameW_(static_cast<void*>(arg1), path, 260);
        bool ok = relay(path);
        log::w(ok ? L"relay ok" : L"relay failed");
        log::close();
        state = 2; result = ok;
        return ok;
    }

    if (g_host_path[0]) {
        g_trace[4] = 0xA5;
        log::w(L"manual host mode");
        bool ok = relay(g_host_path);
        log::w(ok ? L"relay ok" : L"relay failed");
        log::close();
        state = 2; result = ok;
        return ok;
    }
    g_trace[4] = 0xA6;

    log::w(L"target mode");
    auto* dos = static_cast<IMAGE_DOS_HEADER_*>(arg1);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(static_cast<uint8_t*>(arg1) + dos->e_lfanew);

    if (!hide::alloc_rx(arg1, nt->OptionalHeader.SizeOfImage)) { log::w(L"rx failed"); log::close(); state = 2; result = false; return false; }
    result = hide::launch_worker(reinterpret_cast<void*>(&worker));
    log::close();
    state = 2;
    return result;
}