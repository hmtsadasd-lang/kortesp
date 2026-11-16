#include "vmm.hpp"
#include "esp.hpp"
#include "ov.hpp"
#include "r0.hpp"
#include "cloak.hpp"
#include "mock.hpp"
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include <shlwapi.h>

namespace { constexpr wchar_t kImage[] = L"FortniteClient-Win64-Shipping.exe"; }
namespace { constexpr DWORD kWindowWaitMs = 120000; }

// Forward declaration.
bool key_pressed_once(int vk);

// Simple toggle state – no boollast / staticULONGLAST_try cruft.
struct Toggle { int vk; bool* flag; };

// Wide-string command-line parser.
struct CmdFlags {
    bool probe{ false };
    bool cloak{ false };        // dry run - compute and report, write nothing
    bool cloak_commit{ false }; // actually unlink from PsLoadedModuleList
    bool mock{ false };
};

CmdFlags parse_cmd() {
    CmdFlags f;
    int argc;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            if (wcscmp(argv[i], L"--probe") == 0) f.probe = true;
            if (wcscmp(argv[i], L"--cloak") == 0) f.cloak = true;
            if (wcscmp(argv[i], L"--cloak-commit") == 0) { f.cloak = true; f.cloak_commit = true; }
            if (wcscmp(argv[i], L"--mock")  == 0) f.mock  = true;
        }
        LocalFree(argv);
    }
    return f;
}

// Wait for the game's top-level window.
HWND wait_window(DWORD ms) {
    const DWORD step = 500;
    for (DWORD waited = 0; waited < ms; waited += step) {
        if (HWND h = FindWindowW(L"UnrealWindow", nullptr)) return h;
        Sleep(step);
    }
    return nullptr;
}

// Check if a key was pressed this frame (edge-detect).
bool key_pressed_once(int vk) {
    static bool was_down[256]{};
    bool cur = (GetAsyncKeyState(vk) & 0x8000) != 0;
    bool ret = cur && !was_down[vk];
    was_down[vk] = cur;
    return ret;
}

// Enable SeDebugPrivilege on our own token.
//
// This is not optional: NtQuerySystemInformation(SystemModuleInformation)
// redacts SYSTEM_MODULE.ImageBase unless the caller holds SeDebugPrivilege.
// An elevated cmd.exe does not enable it (PowerShell does), so the value
// reads as 0 and ntoskrnl cannot be located.
bool enable_debug_privilege() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) { CloseHandle(tok); return false; }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    const BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    const DWORD err = GetLastError();
    CloseHandle(tok);
    return ok && err != ERROR_NOT_ALL_ASSIGNED;
}

int wmain() {
    CmdFlags flags = parse_cmd();

    // --mock: driverless self-test against a synthetic target.
    if (flags.mock) {
        const bool ok = mock::run();
        return ok ? 0 : 1;
    }

    if (!enable_debug_privilege())
        printf("[!] SeDebugPrivilege could not be enabled - module discovery will fail\n");

    printf("fortesp ring0 - DBUtil_2_3 physical reader\n");

    if (!r0::init()) {
        printf("[!] driver missing - run run_r0.bat as admin\n");
        return 1;
    }
    printf("[+] driver ok\n");

    if (!vmm::init()) {
        printf("[!] kernel discovery failed\n");
        return 1;
    }
    printf("[+] ntoskrnl base 0x%llx\n", static_cast<unsigned long long>(vmm::g_ntos));

    // --- Cloak: unlink from PsLoadedModuleList so module enumeration skips it ---
    // --cloak is a DRY RUN: it resolves every address and prints them but
    // writes nothing to the kernel. --cloak-commit actually unlinks.
    if (flags.cloak) {
        const bool ok = cloak::apply(flags.cloak_commit);
        if (ok && flags.cloak_commit)
            printf("[*] driver unlinked from PsLoadedModuleList\n");
        else if (ok)
            printf("[*] cloak dry run complete - nothing was written\n");
        else
            printf("[!] cloak failed - module stays visible (not fatal)\n");
    }
    // -----------------------------------------------------------------------

    // The window is only needed for the overlay. --probe needs no window,
    // so it attaches straight away instead of burning the whole wait.
    HWND game = nullptr;
    if (!flags.probe) {
        game = wait_window(kWindowWaitMs);
        if (!game) {
            printf("[!] no UnrealWindow after %lu ms\n", kWindowWaitMs);
            return 1;
        }
        printf("[*] window 0x%p\n", static_cast<void*>(game));
    }

    if (!vmm::attach(kImage)) {
        printf("[!] %ls not found in the process list\n", kImage);
        if (cloak::active()) cloak::restore();
        return 1;
    }
    printf("[+] attached pid %u\n", vmm::pid());

    // Resolve the client base through the target's PEB.
    if (!esp::init()) {
        printf("[!] could not resolve the client module base\n");
        if (cloak::active()) cloak::restore();
        return 1;
    }
    printf("[+] client base 0x%llx\n", static_cast<unsigned long long>(vmm::base()));

    if (flags.probe) {
        const bool ok = esp::probe();
        if (cloak::active()) cloak::restore();
        esp::shutdown();
        vmm::shutdown();
        return ok ? 0 : 1;
    }

    if (!ov::init(game)) {
        printf("[!] overlay failed\n");
        if (cloak::active()) cloak::restore();
        return 1;
    }

    // Toggle table – one entry per config flag.
    Toggle t[] = {
        { VK_F1, &esp::cfg.on },
        { VK_F2, &esp::cfg.boxes },
        { VK_F3, &esp::cfg.names },
        { VK_F4, &esp::cfg.health },
        { VK_F5, &esp::cfg.dist },
        { VK_F6, &esp::cfg.lines },
        { VK_F7, &esp::cfg.team_colors },
        { VK_F8, &esp::cfg.bots }
    };

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
        Sleep(1);
    }

    // Restore the KLDR_DATA_TABLE_ENTRY before the driver stops, or the
    // relink writes into freed pool.
    if (cloak::active()) cloak::restore();

    esp::shutdown();
    ov::shutdown();
    vmm::shutdown();
    return 0;
}