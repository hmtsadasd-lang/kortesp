#include "vmm.hpp"
#include "esp.hpp"
#include "ov.hpp"
#include "r0.hpp"
#include "cloak.hpp"
#include "mock.hpp"
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <io.h>
#include <string>
#include <vector>
#include <shlwapi.h>

namespace { constexpr wchar_t kImage[] = L"FortniteClient-Win64-Shipping.exe"; }
namespace { constexpr DWORD kWindowWaitMs = 120000; }

namespace { constexpr double kTargetFps = 120.0; }

// Forward declaration.
bool key_pressed_once(int vk);

// Simple toggle state.
struct Toggle { int vk; bool* flag; };

// Wide-string command-line parser.
struct CmdFlags {
    bool probe{ false };
    bool kwtest{ false };
    bool cloak{ false };
    bool cloak_commit{ false };
    bool cloak_restore{ false };
    bool hide_symlink{ false };
    bool mock_flag{ false };
    bool raw{ false };
    bool only_ntos{ false };
    bool only_cr3{ false };
    bool only_eproc{ false };
    bool esp_mode{ false };
    bool preflight{ false };
    bool actors{ false };
    uint64_t raw_pa{ 0 };
    size_t   raw_len{ 16 };
    std::wstring driver_name;
};

// ---------------------------------------------------------------------------
// Console bootstrap. -mwindows allocates no console, so attach to the parent
// cmd window if there is one (no new window appears); otherwise log to a file
// next to the exe. Never AllocConsole - an elevated console window freezes
// this box.
// ---------------------------------------------------------------------------
static void boot_output() {
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        _wfreopen(L"CONOUT$", L"w", stdout);
        _dup2(_fileno(stdout), _fileno(stderr));
        return;
    }
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return;
    wchar_t* s = wcsrchr(path, L'\\');
    if (!s) return;
    *(s + 1) = 0;
    if (wcslen(path) + 12 < MAX_PATH) wcscat(path, L"fortesp.log");
    _wfreopen(path, L"w", stdout);
    _dup2(_fileno(stdout), _fileno(stderr));
}

bool raw_read(uint64_t pa, size_t len);

bool run_preflight() {
    printf("preflight:\n");
    if (!raw_read(0x400, 16))  { printf("[!] step 1/5 physical read 0x400 failed\n"); return false; }
    if (!raw_read(0x1000, 16)) { printf("[!] step 2/5 physical read 0x1000 failed\n"); return false; }
    if (!vmm::init_ntos())     { printf("[!] step 3/5 ntoskrnl not found\n"); return false; }
    if (!vmm::init_system())   { printf("[!] step 4/5 System EPROCESS not found\n"); return false; }
    if (!vmm::init_kcr3())     printf("[*] no CR3 - kernel-VA path only\n");
    if (!vmm::attach(kImage))  { printf("[!] step 5/5 client not found\n"); return false; }
    if (!esp::init())          { printf("[!] client base unresolved\n"); return false; }
    printf("[+] esp init ok\n");
    return true;
}

CmdFlags parse_cmd() {
    CmdFlags f;
    int argc;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            if (wcscmp(argv[i], L"--probe") == 0) f.probe = true;
            if (wcscmp(argv[i], L"--kwtest") == 0) f.kwtest = true;
            if (wcscmp(argv[i], L"--cloak") == 0) f.cloak = true;
            if (wcscmp(argv[i], L"--cloak-commit") == 0) { f.cloak = true; f.cloak_commit = true; }
            if (wcscmp(argv[i], L"--cloak-restore") == 0) f.cloak_restore = true;
            if (wcscmp(argv[i], L"--hide-symlink") == 0) f.hide_symlink = true;
            if (wcscmp(argv[i], L"--mock")  == 0) f.mock_flag  = true;
            if (wcscmp(argv[i], L"--esp")    == 0) f.esp_mode = true;
            if (wcscmp(argv[i], L"--actors") == 0) f.actors  = true;
            if (wcscmp(argv[i], L"--preflight") == 0) f.preflight = true;
            if (wcscmp(argv[i], L"--ntos")  == 0) f.only_ntos = true;
            if (wcscmp(argv[i], L"--cr3scan") == 0) f.only_cr3 = true;
            if (wcscmp(argv[i], L"--eproc") == 0) f.only_eproc = true;
            if (wcscmp(argv[i], L"--driver-name") == 0 && i + 1 < argc)
                f.driver_name = argv[++i];
            if (wcscmp(argv[i], L"--raw") == 0) {
                f.raw_pa = wcstoull(argv[++i], nullptr, 0);
                if (i + 1 < argc && argv[i + 1][0] != L'-') {
                    const unsigned long long l = wcstoull(argv[++i], nullptr, 0);
                    if (l && l <= 0x1000) f.raw_len = static_cast<size_t>(l);
                    else if (l) printf("[!] len %llu capped to 4096\n", l);
                }
            }
        }
        LocalFree(argv);
    }
    return f;
}

std::string narrow(const std::wstring& s) {
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), n, nullptr, nullptr);
    out.resize(static_cast<size_t>(n - 1));
    return out;
}

// ---------------------------------------------------------------------------
// Minimal stubs for functions referenced by wmain() but not yet implemented.
// ---------------------------------------------------------------------------
bool enable_debug_privilege() {
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
    CloseHandle(hToken);
    return ok != FALSE;
}

HWND wait_window(DWORD ms) {
    HWND h = FindWindowW(nullptr, L"Fortnite");
    if (!h) h = FindWindowW(L"UnrealWindow", nullptr);
    DWORD start = GetTickCount();
    while (!h && GetTickCount() - start < ms) {
        Sleep(250);
        h = FindWindowW(nullptr, L"Fortnite");
        if (!h) h = FindWindowW(L"UnrealWindow", nullptr);
    }
    return h;
}

void frame_wait(double target_fps, LARGE_INTEGER& freq, LARGE_INTEGER& last) {
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    const double target_ms = 1000.0 / target_fps;
    const double elapsed_ms = (double)(now.QuadPart - last.QuadPart) * 1000.0 / (double)freq.QuadPart;
    if (elapsed_ms < target_ms)
        Sleep((DWORD)(target_ms - elapsed_ms));
    QueryPerformanceCounter(&last);
}

bool key_pressed_once(int vk) {
    static bool state[256]{};
    bool pressed = (GetAsyncKeyState(vk) & 0x8000) != 0;
    if (pressed && !state[vk]) { state[vk] = true; return true; }
    if (!pressed) state[vk] = false;
    return false;
}

bool raw_read(uint64_t pa, size_t len) {
    if (!len) { printf("[!] zero length\n"); return false; }
    const bool in_ram = vmm::phys_is_ram(pa, len);
    printf("[*] physical read 0x%llx, %zu bytes\n", (unsigned long long)pa, len);
    printf("[*] in RAM map: %s%s\n", in_ram ? "yes" : "NO", in_ram ? "" : " - reading anyway, that is what --raw is for");
    std::vector<uint8_t> b(len, 0xCC);
    if (!r0::pread(pa, b.data(), len)) {
        printf("[!] IOCTL failed\n");
        return false;
    }
    bool any = false;
    for (uint8_t v : b) any |= (v != 0);
    for (size_t i = 0; i < len; i += 16) {
        printf("  %08llx  ", (unsigned long long)(pa + i));
        for (size_t j = 0; j < 16 && i + j < len; ++j)
            printf("%02x ", b[i + j]);
        printf("\n");
    }
    if (!any) {
        printf("[!] all zeros.\n");
        return false;
    }
    printf("[+] read returned data\n");
    return true;
}

bool kwtest() {
    uint64_t rva{};
    if (!vmm::export_rva("PsInitialSystemProcess", rva)) {
        printf("[!] PsInitialSystemProcess not found\n");
        return false;
    }
    if (!vmm::g_ntos || vmm::g_ntos_size < 8 || rva > vmm::g_ntos_size - 8) {
        printf("[!] RVA out of range\n");
        return false;
    }
    const uint64_t va = vmm::g_ntos + rva;
    printf("[*] PsInitialSystemProcess at 0x%llx\n", (unsigned long long)va);

    uint64_t val{};
    if (!vmm::kread_trusted(va, &val, sizeof(val))) return false;
    printf("[*] value 0x%llx\n", (unsigned long long)val);
    if (val < 0xFFFF800000000000ull) {
        printf("[!] value is not a kernel VA\n");
        return false;
    }

    if (!vmm::kwrite_trusted(va, &val, sizeof(val))) {
        printf("[!] kernel write failed\n");
        return false;
    }

    uint64_t back{};
    if (!vmm::kread_trusted(va, &back, sizeof(back))) {
        printf("[!] read-back failed\n");
        return false;
    }
    if (back != val) {
        printf("[!] write-back mismatch\n");
        return false;
    }
    printf("[+] write-back read-back matches\n");
    return true;
}

int wmain() {
    CmdFlags flags = parse_cmd();
    boot_output();

    if (flags.mock_flag) {
        const bool ok = mock::run();
        return ok ? 0 : 1;
    }

    cloak::cloak_init(narrow(flags.driver_name).c_str());

    if (SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {
        printf("[+] DPI awareness: per-monitor v2\n");
    } else {
        printf("[!] could not set per-monitor DPI awareness\n");
    }

    if (!enable_debug_privilege())
        printf("[!] enable_debug_privilege failed\n");

    printf("fortesp ring0\n");

    if (!r0::init()) {
        printf("[!] driver not present\n");
        return 1;
    }
    printf("[+] driver ok\n");

    if (flags.raw) {
        const bool ok = raw_read(flags.raw_pa, flags.raw_len);
        vmm::shutdown();
        return ok ? 0 : 1;
    }

    if (flags.actors) esp::use_actors = true;

    if (flags.preflight || flags.esp_mode) {
        if (!run_preflight()) { vmm::shutdown(); return 1; }
        if (flags.preflight && !flags.esp_mode) {
            const bool ok = esp::probe();
            vmm::shutdown();
            return ok ? 0 : 1;
        }
        // --esp: probe is advisory output, not a gate. esp::init() succeeded,
        // which is sufficient to launch the overlay.
        printf("[*] running probe (advisory):\n");
        esp::probe();
    }

    if (!vmm::init_ntos()) { vmm::shutdown(); return 1; }
    if (flags.only_ntos) { vmm::shutdown(); return 0; }

    if (flags.only_cr3) {
        const bool ok = vmm::scan_kernel_cr3();
        vmm::shutdown();
        return ok ? 0 : 1;
    }

    if (!vmm::init_kcr3_cached())
        printf("[*] no cr3.cache\n");

    if (!vmm::init_system()) {
        printf("[!] system EPROCESS not found\n");
        vmm::shutdown();
        return 1;
    }

    if (flags.only_eproc) { vmm::shutdown(); return 0; }

    if (!vmm::init_kcr3()) {
        printf("[!] CR3 not proven\n");
    }

    if (flags.cloak_restore) {
        const bool ok = cloak::restore();
        vmm::shutdown();
        return ok ? 0 : 1;
    }

    if (flags.kwtest) {
        const bool ok = kwtest();
        vmm::shutdown();
        return ok ? 0 : 1;
    }

    if (flags.cloak) {
        cloak::cloak_init(narrow(flags.driver_name).c_str());
        const bool ok = cloak::apply(flags.cloak_commit);
        if (ok && flags.cloak_commit)
            printf("[+] driver unlinked\n");
        else if (ok)
            printf("[*] cloak dry run ok\n");
        else
            printf("[!] cloak failed\n");
    }

    if (flags.hide_symlink) {
        const bool ok = r0::hide_symlink(L"\\DosDevices\\DBUtil_2_3");
        if (ok)
            printf("[+] symlink removed\n");
        else
            printf("[!] symlink still present\n");
    }

    HWND game = nullptr;
    if (!flags.probe) {
        game = wait_window(kWindowWaitMs);
        if (!game) {
            printf("[!] no Fortnite window found\n");
            return 1;
        }
        printf("[*] window 0x%p\n", static_cast<void*>(game));
    }

    if (!vmm::attach(kImage)) {
        printf("[!] Fortnite not found\n");
        return 1;
    }
    printf("[+] attached pid %u\n", vmm::pid());

    if (!esp::init()) {
        printf("[!] esp init failed\n");
        return 1;
    }
    printf("[+] esp init ok\n");

    if (flags.probe) {
        const bool ok = esp::probe();
        esp::shutdown();
        vmm::shutdown();
        return ok ? 0 : 1;
    }

    if (!ov::init(game)) {
        printf("[!] overlay failed\n");
        return 1;
    }

    Toggle t[] = {
        { VK_F1, &esp::cfg.on },
        { VK_F2, &esp::cfg.boxes },
        { VK_F3, &esp::cfg.names },
        { VK_F4, &esp::cfg.health },
        { VK_F5, &esp::cfg.dist },
        { VK_F6, &esp::cfg.lines },
        { VK_F7, &esp::cfg.team_colors },
        { VK_F8, &esp::cfg.bots },
        { VK_F9, &esp::cfg.skeleton }
    };

    LARGE_INTEGER freq{}, last{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&last);

    for (;;) {
        if (!ov::pump()) break;
        if (key_pressed_once(VK_END)) break;
        for (auto& x : t) {
            if (key_pressed_once(x.vk)) *x.flag = !*x.flag;
        }
        ov::tick();
        ov::begin();
        esp::draw();
        ov::end();
        frame_wait(kTargetFps, freq, last);
    }

    esp::shutdown();
    vmm::shutdown();
    return 0;
}