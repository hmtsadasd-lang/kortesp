#include "vmm.hpp"
#include "esp.hpp"
#include "ov.hpp"
#include "r0.hpp"
#include "cloak.hpp"
#include "mock.hpp"
#include "mem.hpp"
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <io.h>
#include <string>
#include <vector>

namespace { constexpr wchar_t kImage[] = L"FortniteClient-Win64-Shipping.exe"; }
namespace { constexpr DWORD kWindowWaitMs = 120000; }
namespace { constexpr double kTargetFps = 120.0; }

struct CmdFlags {
    bool probe{ false }, esp_mode{ false }, cloak{ false };
    bool cloak_restore{ false }, cloak_dry{ false }, hide_symlink{ false }, kwtest{ false };
    bool only_ntos{ false }, only_eproc{ false }, dump_cr3{ false }, dtbscan{ false };
    bool dpatch{ false }, dpatch_dry{ false }, actors{ false }, raw{ false }, mock{ false };
    bool kvread{ false };
    std::string backend;
    std::string dpatch_step;
    uint64_t raw_pa{ 0 };
    uint64_t kvread_va{ 0 };
    size_t   raw_len{ 16 };
    size_t   kvread_len{ 16 };
    std::wstring driver_name;
};

static void boot_output() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
}

static std::string narrow(const std::wstring& s);

static CmdFlags parse_cmd() {
    CmdFlags f;
    int argc;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return f;
    for (int i = 1; i < argc; ++i) {
        const wchar_t* a = argv[i];
        if (!wcscmp(a, L"--probe")) f.probe = true;
        else if (!wcscmp(a, L"--esp")) f.esp_mode = true;
        else if (!wcscmp(a, L"--cloak")) f.cloak = true;
        else if (!wcscmp(a, L"--cloak-restore")) f.cloak_restore = true;
        else if (!wcscmp(a, L"--hide-symlink")) f.hide_symlink = true;
        else if (!wcscmp(a, L"--kwtest")) f.kwtest = true;
        else if (!wcscmp(a, L"--ntos")) f.only_ntos = true;
        else if (!wcscmp(a, L"--eproc")) f.only_eproc = true;
        else if (!wcscmp(a, L"--dump-cr3")) f.dump_cr3 = true;
        else if (!wcscmp(a, L"--dtbscan")) f.dtbscan = true;
        else if (!wcscmp(a, L"--actors")) f.actors = true;
        else if (!wcscmp(a, L"--driver-name") && i + 1 < argc) f.driver_name = argv[++i];
        else if (!wcscmp(a, L"--raw")) {
            f.raw = true;
            if (i + 1 < argc) f.raw_pa = wcstoull(argv[++i], nullptr, 0);
            if (i + 1 < argc && argv[i + 1][0] != L'-') {
                const unsigned long long l = wcstoull(argv[++i], nullptr, 0);
                if (l && l <= 0x1000) f.raw_len = static_cast<size_t>(l);
            }
        }
        else if (!wcscmp(a, L"--mock")) f.mock = true;
        else if (!wcscmp(a, L"--backend") && i + 1 < argc) {
            f.backend = narrow(argv[++i]);
        }
        else if (!wcscmp(a, L"--dpatch")) f.dpatch = true;
        else if (!wcscmp(a, L"--dpatch-dry")) { f.dpatch = true; f.dpatch_dry = true; }
        else if (!wcscmp(a, L"--dpatch-step") && i + 1 < argc) {
            f.dpatch = true;
            f.dpatch_step = narrow(argv[++i]);
        }
        else if (!wcscmp(a, L"--kvread")) {
            f.kvread = true;
            if (i + 1 < argc) f.kvread_va = wcstoull(argv[++i], nullptr, 0);
            if (i + 1 < argc && argv[i + 1][0] != L'-') {
                const unsigned long long l = wcstoull(argv[++i], nullptr, 0);
                if (l && l <= 0x1000) f.kvread_len = static_cast<size_t>(l);
            }
        }
        else if (!wcscmp(a, L"--cloak-dry")) f.cloak_dry = true;
    }
    LocalFree(argv);
    return f;
}

static std::string narrow(const std::wstring& s) {
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), n, nullptr, nullptr);
    out.resize(static_cast<size_t>(n - 1));
    return out;
}

static bool enable_debug_privilege() {
    HANDLE hToken{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return false; }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
    const DWORD err = GetLastError();
    CloseHandle(hToken);
    // AdjustTokenPrivileges returns TRUE even when the privilege is not held;
    // the documented failure signal is ERROR_NOT_ALL_ASSIGNED.
    if (!ok) return false;
    return err != ERROR_NOT_ALL_ASSIGNED;
}

static HWND wait_window(DWORD ms) {
    HWND h = FindWindowW(nullptr, L"Fortnite");
    if (!h) h = FindWindowW(L"UnrealWindow", nullptr);
    const DWORD start = GetTickCount();
    while (!h && GetTickCount() - start < ms) {
        Sleep(250);
        h = FindWindowW(nullptr, L"Fortnite");
        if (!h) h = FindWindowW(L"UnrealWindow", nullptr);
    }
    return h;
}

static void frame_wait(double target_fps, LARGE_INTEGER& freq, LARGE_INTEGER& last) {
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    const double target_ms = 1000.0 / target_fps;
    const double elapsed_ms = (double)(now.QuadPart - last.QuadPart) * 1000.0 / (double)freq.QuadPart;
    if (elapsed_ms < target_ms) Sleep((DWORD)(target_ms - elapsed_ms));
    QueryPerformanceCounter(&last);
}

static bool key_pressed_once(int vk) {
    static bool state[256]{};
    const bool pressed = (GetAsyncKeyState(vk) & 0x8000) != 0;
    if (pressed && !state[vk]) { state[vk] = true; return true; }
    if (!pressed) state[vk] = false;
    return false;
}

static bool raw_read(uint64_t pa, size_t len) {
    if (!len) return false;
    const bool in_ram = vmm::phys_is_ram(pa, len);
    printf("[*] physical read 0x%llx, %zu bytes\n", (unsigned long long)pa, len);
    printf("[*] in RAM map: %s%s\n", in_ram ? "yes" : "NO",
           in_ram ? "" : " - reading anyway, that is what --raw is for");
    std::vector<uint8_t> b(len, 0xCC);
    if (!r0::phys_read_raw(pa, b.data(), len)) {
        const DWORD err = GetLastError();
        printf("[!] IOCTL failed (GetLastError=%lu / 0x%lx)\n",
               (unsigned long)err, (unsigned long)err);
        return false;
    }
    bool any = false;
    for (uint8_t v : b) any |= (v != 0);
    for (size_t i = 0; i < len; i += 16) {
        printf("  %08llx  ", (unsigned long long)(pa + i));
        for (size_t j = 0; j < 16 && i + j < len; ++j) printf("%02x ", b[i + j]);
        printf("\n");
    }
    // The IOCTL succeeded, so the read direction is proven by construction.
    // Zero bytes are data: an untouched free page above 4 GB is normally
    // zero-filled, and treating that as a failure would make the documented
    // --raw 0x100000000 test unpassable on a healthy machine.
    if (!any) printf("[+] read returned zeros (IOCTL succeeded; page is zero-filled)\n");
    else printf("[+] read returned data\n");
    return true;
}

// --kvread: one kernel-VA read through the proven handler. Writes nothing.
static bool kvread(uint64_t va, size_t len) {
    if (!len || va < 0xFFFF800000000000ull) {
        printf("[!] --kvread needs a kernel VA and len 1..4096\n");
        return false;
    }
    if (!r0::vread_ready()) {
        printf("[!] kernel-VA read direction not proven - refusing to touch 0x%llx\n",
               (unsigned long long)va);
        return false;
    }
    printf("[*] kernel-VA read 0x%llx, %zu bytes (no writes)\n",
           (unsigned long long)va, len);
    std::vector<uint8_t> b(len, 0xCC);
    if (!r0::vread(va, b.data(), len)) { printf("[!] vread failed\n"); return false; }
    for (size_t i = 0; i < len; i += 16) {
        printf("  %016llx  ", (unsigned long long)(va + i));
        for (size_t j = 0; j < 16 && i + j < len; ++j) printf("%02x ", b[i + j]);
        printf("\n");
    }
    return true;
}

static bool kwtest() {
    uint64_t rva{};
    if (!vmm::export_rva("PsInitialSystemProcess", rva)) {
        printf("[!] PsInitialSystemProcess not found\n");
        return false;
    }
    if (!vmm::g_ntos || vmm::g_ntos_size < 8 || rva > vmm::g_ntos_size - 8) return false;
    const uint64_t va = vmm::g_ntos + rva;
    printf("[*] PsInitialSystemProcess at 0x%llx\n", (unsigned long long)va);

    uint64_t val{};
    if (!vmm::kread_trusted(va, &val, sizeof(val))) return false;
    printf("[*] value 0x%llx\n", (unsigned long long)val);
    if (val < 0xFFFF800000000000ull) { printf("[!] not a kernel VA\n"); return false; }

    if (!vmm::kwrite_trusted(va, &val, sizeof(val))) { printf("[!] write failed\n"); return false; }
    uint64_t back{};
    if (!vmm::kread_trusted(va, &back, sizeof(back))) return false;
    if (back != val) { printf("[!] read-back mismatch\n"); return false; }
    printf("[+] write-back read-back matches\n");
    r0::g_write_ok = true;
    return true;
}

static bool bring_up_kernel() {
    if (!vmm::init_ntos()) return false;
    if (!vmm::init_system()) return false;
    if (!vmm::init_kcr3()) {
        printf("[!] kernel CR3 not proven\n");
        return false;
    }
    return true;
}

int wmain() {
    CmdFlags f = parse_cmd();
    boot_output();
    cloak::cloak_init(narrow(f.driver_name).c_str());

    if (!SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2))
        printf("[!] per-monitor DPI awareness failed\n");

    if (!enable_debug_privilege())
        printf("[!] enable_debug_privilege failed (module ImageBase will read 0)\n");

    printf("fortesp ring0\n");

    if (f.mock) { const bool ok = mock::run(); return ok ? 0 : 1; }

    if (!r0::init()) { printf("[!] driver not present\n"); return 1; }
    printf("[+] driver ok\n");

    if (f.backend == "rpm") {
        mem::set_backend(mem::backend::rpm);
    } else {
        mem::set_backend(mem::backend::phys);
    }

    if (f.raw) { const bool ok = raw_read(f.raw_pa, f.raw_len); vmm::shutdown(); return ok ? 0 : 1; }

    if (!vmm::init_ntos()) { vmm::shutdown(); return 1; }
    if (f.only_ntos) { vmm::shutdown(); return 0; }

    if (f.kvread) { const bool ok = kvread(f.kvread_va, f.kvread_len); vmm::shutdown(); return ok ? 0 : 1; }

    if (f.dpatch) {
        vmm::init_pte_base();
        const bool ok = r0::patch_cached_map(
            f.dpatch_dry, f.dpatch_step.empty() ? nullptr : f.dpatch_step.c_str());
        vmm::shutdown();
        return ok ? 0 : 1;
    }

    if (!vmm::init_system()) { vmm::shutdown(); return 1; }
    if (f.only_eproc) { vmm::shutdown(); return 0; }
    if (f.dump_cr3) { const bool ok = vmm::dump_cr3(); vmm::shutdown(); return ok ? 0 : 1; }
    if (f.dtbscan)  { const bool ok = vmm::dtb_scan(); vmm::shutdown(); return ok ? 0 : 1; }

    if (!vmm::init_kcr3()) {
        printf("[!] CR3 not proven\n");
        vmm::shutdown();
        return 1;
    }

    if (f.cloak_restore) { const bool ok = cloak::restore(); vmm::shutdown(); return ok ? 0 : 1; }
    if (f.cloak_dry) { const bool ok = cloak::apply(false); vmm::shutdown(); return ok ? 0 : 1; }
    if (f.kwtest) { const bool ok = kwtest(); vmm::shutdown(); return ok ? 0 : 1; }

    if (f.cloak) {
        const bool ok = cloak::apply(true);
        vmm::shutdown();
        return ok ? 0 : 1;
    }

    if (f.hide_symlink) {
        if (r0::hide_symlink(L"\\DosDevices\\DBUtil_2_3")) printf("[+] symlink removed\n");
        else { printf("[!] symlink still present\n"); vmm::shutdown(); return 1; }
    }

    if (f.actors) esp::use_actors = true;

    if (f.probe || f.esp_mode) {
        if (!bring_up_kernel()) { vmm::shutdown(); return 1; }

        if (!vmm::attach()) { printf("[!] Fortnite not found\n"); vmm::shutdown(); return 1; }
        printf("[+] attached pid %u\n", vmm::pid());
        if (!vmm::prove_target_cr3()) { vmm::shutdown(); return 1; }

        if (!esp::init()) { printf("[!] esp init failed\n"); vmm::shutdown(); return 1; }

        printf("[*] chain probe:\n");
        const bool chain = esp::probe();
        if (f.probe || !f.esp_mode) {
            esp::shutdown();
            vmm::shutdown();
            return chain ? 0 : 1;
        }
        if (!chain) printf("[!] chain probe failed - launching the overlay anyway\n");
    } else {
        HWND game = wait_window(kWindowWaitMs);
        if (!game) { printf("[!] no Fortnite window\n"); vmm::shutdown(); return 1; }
        if (!bring_up_kernel()) { vmm::shutdown(); return 1; }
        if (!vmm::attach()) { printf("[!] Fortnite not found\n"); vmm::shutdown(); return 1; }
        if (!vmm::prove_target_cr3()) { vmm::shutdown(); return 1; }
        if (!esp::init()) { vmm::shutdown(); return 1; }
        if (!ov::init(game)) { printf("[!] overlay failed\n"); vmm::shutdown(); return 1; }

        struct Toggle { int vk; bool* flag; };
        Toggle t[] = {
            { VK_F1, &esp::cfg.on },        { VK_F2, &esp::cfg.boxes },
            { VK_F3, &esp::cfg.names },     { VK_F4, &esp::cfg.health },
            { VK_F5, &esp::cfg.dist },      { VK_F6, &esp::cfg.lines },
            { VK_F7, &esp::cfg.team_colors }, { VK_F8, &esp::cfg.bots },
            { VK_F9, &esp::cfg.skeleton }
        };
        LARGE_INTEGER freq{}, last{};
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&last);

        for (;;) {
            if (!ov::pump()) break;
            if (key_pressed_once(VK_END)) break;
            for (auto& x : t) if (key_pressed_once(x.vk)) *x.flag = !*x.flag;
            ov::tick();
            ov::begin();
            esp::draw();
            ov::end();
            frame_wait(kTargetFps, freq, last);
        }
        ov::shutdown();
        esp::shutdown();
        vmm::shutdown();
        return 0;
    }

    HWND game = wait_window(kWindowWaitMs);
    if (!game) { printf("[!] no Fortnite window\n"); return 1; }
    if (!ov::init(game)) { printf("[!] overlay failed\n"); return 1; }

    struct Toggle { int vk; bool* flag; };
    Toggle t[] = {
        { VK_F1, &esp::cfg.on },        { VK_F2, &esp::cfg.boxes },
        { VK_F3, &esp::cfg.names },     { VK_F4, &esp::cfg.health },
        { VK_F5, &esp::cfg.dist },      { VK_F6, &esp::cfg.lines },
        { VK_F7, &esp::cfg.team_colors }, { VK_F8, &esp::cfg.bots },
        { VK_F9, &esp::cfg.skeleton }
    };
    LARGE_INTEGER freq{}, last{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&last);

    for (;;) {
        if (!ov::pump()) break;
        if (key_pressed_once(VK_END)) break;
        for (auto& x : t) if (key_pressed_once(x.vk)) *x.flag = !*x.flag;
        ov::tick();
        ov::begin();
        esp::draw();
        ov::end();
        frame_wait(kTargetFps, freq, last);
    }

    ov::shutdown();
    esp::shutdown();
    vmm::shutdown();
    return 0;
}
