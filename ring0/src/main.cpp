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
    bool kwtest{ false };       // kernel-VA write/read-back test, changes nothing
    bool cloak{ false };        // dry run - compute and report, write nothing
    bool cloak_commit{ false }; // actually unlink from PsLoadedModuleList
    bool cloak_restore{ false };// standalone: re-link from cloak.state, then exit
    bool hide_symlink{ false }; // remove \??\DBUtil_2_3, permanent until reboot
    bool mock{ false };
    std::wstring driver_name;   // --driver-name <name.sys>
};

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
            if (wcscmp(argv[i], L"--mock")  == 0) f.mock  = true;
            if (wcscmp(argv[i], L"--driver-name") == 0 && i + 1 < argc)
                f.driver_name = argv[++i];
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
// --kwtest: exercise the kernel-VA write path without changing anything.
//
// Read PsInitialSystemProcess (a data export), write the *identical* 8 bytes
// back over it, then read it again. Right address + right value means no
// observable change to the kernel; a wrong address is still a small, local
// 8-byte write of the value that was just read from that same address, not the
// 8-million-page sweep a transposed IOCTL produced.
//
// This exists because --probe is read-only and --cloak is a dry run, so
// without it the first kernel writes ever performed are the cloak's two unlink
// writes - and a bug there is a bugcheck with no prior signal.
// ---------------------------------------------------------------------------
bool kwtest() {
    uint64_t rva{};
    if (!vmm::export_rva("PsInitialSystemProcess", rva)) {
        printf("[!] PsInitialSystemProcess not found in ntoskrnl's exports\n");
        return false;
    }
    // Bound the address against the image before writing anything. export_rva
    // returning garbage would otherwise put ntos+rva in an arbitrary kernel
    // page, and the memmove would fault (0x50/0xEF) before any value check
    // could help.
    if (!vmm::g_ntos || vmm::g_ntos_size < 8 || rva > vmm::g_ntos_size - 8) {
        printf("[!] RVA 0x%llx is outside the image (size 0x%llx) - refusing to write\n",
               static_cast<unsigned long long>(rva),
               static_cast<unsigned long long>(vmm::g_ntos_size));
        return false;
    }
    const uint64_t va = vmm::g_ntos + rva;
    printf("[*] PsInitialSystemProcess at 0x%llx (ntos+0x%llx)\n",
           static_cast<unsigned long long>(va), static_cast<unsigned long long>(rva));

    uint64_t v{};
    if (!vmm::kread(va, &v, 8)) {
        printf("[!] kernel read failed\n");
        return false;
    }
    printf("[*] value 0x%llx\n", static_cast<unsigned long long>(v));
    if (v < 0xFFFF800000000000ull) {
        // PsInitialSystemProcess must point at the System EPROCESS. A
        // non-kernel value means the export RVA or the read is wrong. The
        // write below is still safe (same address, same bytes), but report it.
        printf("[!] value is not a kernel VA - export RVA or read path is wrong\n");
    }

    if (!vmm::kwrite(va, &v, 8)) {
        printf("[!] kernel write failed (device VA write path)\n");
        return false;
    }

    uint64_t back{};
    if (!vmm::kread(va, &back, 8)) {
        printf("[!] read-back failed\n");
        return false;
    }
    if (back != v) {
        // The write returned success, so it landed SOMEWHERE - just not where
        // we expected to read it back from (or the read path is wrong). Either
        // way the kernel now holds 8 bytes we did not intend to place. Do not
        // retry: reboot and start from a known state.
        printf("[!] write reported success but read-back returned 0x%llx (wrote 0x%llx)\n",
               static_cast<unsigned long long>(back), static_cast<unsigned long long>(v));
        printf("[!] the write landed somewhere unknown. REBOOT before doing anything else.\n");
        return false;
    }
    printf("[+] write-back read-back matches - kernel write path works\n");
    return true;
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

    // Chosen before the service is created and passed down as --driver-name;
    // the runner never exports a second copy. Accept "name" or "name.sys".
    if (!flags.driver_name.empty()) {
        std::wstring n = flags.driver_name;
        if (n.size() < 4 || _wcsicmp(n.c_str() + n.size() - 4, L".sys") != 0) n += L".sys";
        const std::string a = narrow(n);
        cloak::set_driver_image(a.c_str());
        printf("[*] driver image: %s\n", a.c_str());
    }

    // Per-monitor DPI awareness must be set before any window work, or the
    // overlay is the wrong size and offset at 125%/150% scaling.
    if (SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {
        printf("[+] DPI awareness: per-monitor v2\n");
    } else {
        printf("[!] could not set per-monitor DPI awareness\n");
    }

    if (!enable_debug_privilege())
        printf("[!] SeDebugPrivilege could not be enabled - module discovery will fail\n");

    printf("fortesp ring0 - kernel read-only backend\n");

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

    // --cloak-restore is a standalone mode: it uses cloak.state written by the
    // commit, because a fresh process cannot rediscover an unlinked entry.
    if (flags.cloak_restore) {
        const bool ok = cloak::restore();
        vmm::shutdown();
        return ok ? 0 : 1;
    }

    // --kwtest proves the kernel-VA write path before the cloak uses it.
    if (flags.kwtest) {
        const bool ok = kwtest();
        vmm::shutdown();
        return ok ? 0 : 1;
    }

    // --- Cloak: unlink from PsLoadedModuleList so module enumeration skips it ---
    // --cloak is a DRY RUN: it resolves every address and prints them but
    // writes nothing to the kernel. --cloak-commit actually unlinks.
    if (flags.cloak) {
        const bool ok = cloak::apply(flags.cloak_commit);
        if (ok && flags.cloak_commit)
            printf("[*] driver unlinked from PsLoadedModuleList (stays unlinked until reboot)\n");
        else if (ok)
            printf("[*] cloak dry run complete - nothing was written\n");
        else
            printf("[!] cloak failed - module stays visible (not fatal)\n");
    }
    // -----------------------------------------------------------------------

    // --- Remove the \??\DBUtil_2_3 symlink ---
    // This is the name EAC is expected to name, and the only part of the
    // surface removable without touching the driver. It is permanent for the
    // boot, so it runs last: a later process cannot open the device by path
    // (this one still can - its handle refers to the device object itself).
    if (flags.hide_symlink) {
        const bool ok = r0::hide_symlink(L"\\DosDevices\\DBUtil_2_3");
        if (ok)
            printf("[+] \\??\\DBUtil_2_3 removed - opens by path fail until reboot\n");
        else
            printf("[!] symlink still present - device name stays visible\n");

        // Standalone unless --probe asked for the read check as well.
        if (!flags.probe) {
            vmm::shutdown();
            return ok ? 0 : 1;
        }
    }

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

    // The cloak is deliberately NOT undone on exit. The driver stays loaded
    // until reboot (it is NOT_STOPPABLE), so its KLDR entry stays valid;
    // re-linking it would just put the known module name back in front of EAC
    // for no benefit. Use --cloak-restore (standalone) if you ever need it.

    if (!vmm::attach(kImage)) {
        printf("[!] %ls not found in the process list\n", kImage);
        return 1;
    }
    printf("[+] attached pid %u\n", vmm::pid());

    // Resolve the client base through the target's PEB.
    if (!esp::init()) {
        printf("[!] could not resolve the client module base\n");
        return 1;
    }
    printf("[+] client base 0x%llx\n", static_cast<unsigned long long>(vmm::base()));

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

    // Driver stays loaded until reboot; the entry is left unlinked so module
    // enumeration keeps skipping it.

    esp::shutdown();
    ov::shutdown();
    vmm::shutdown();
    return 0;
}