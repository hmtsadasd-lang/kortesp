/* hook_matrix - self-contained hook-injection matrix against a chosen target.
 *
 * Why this exists
 * ---------------
 * On the live client, six hook families installed with err=0 and then never
 * fired. The project could not tell whether the client's I/O design simply
 * never drives them, or whether the injection itself is refused inside the
 * client. This harness removes the ambiguity: it drives a *fixture* whose I/O
 * design we control (lab\mock_client.exe) through the same family set, and
 * prints which families fired. Compare the fixture's table with the client's
 * table:
 *
 *   fixture fires, client does not   -> the client's design/message handling
 *                                       is the reason, not the loader.
 *   fixture also stays silent        -> the expected hooks do not fire even
 *                                       where nothing obstructs them, so the
 *                                       family itself is not usable.
 *
 * It is deliberately independent of the human: it starts the target, finds its
 * window, installs every family, applies its own stimuli (posted WM_NULL,
 * window moves, foreground swaps, real SendInput, a SendMessage to drive the
 * sender-side CALLWNDPROC hook), then parses the hook log into a table.
 *
 *   usage: hook_matrix.exe <target.exe> <class> [mode] [seconds] [tl|global]
 *
 *   class   window class to watch: MockClientWindow | MockGuiTarget | UnrealWindow
 *   mode    passed to the target as an argument (mock_client: raw|peek|get)
 *   seconds how long to stimulate (default 20)
 *   tl|global  thread-local to the target's window thread, or a global sweep
 *
 * The hook DLL is injected from its own file path, so no copy of ours has to
 * live next to the target.
 */
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <map>

static wchar_t g_log[MAX_PATH] = L"C:\\Users\\Public\\fortesp_hook.log";
static wchar_t g_dll[MAX_PATH] = L"C:\\dev\\fortesp\\out\\FortHook.dll";

struct spec {
    const char*  name;   /* short label for the table            */
    int          type;   /* WH_* value                           */
    const char*  exp;    /* export in FortHook.dll               */
};

static const spec kSpecs[] = {
    { "get",   WH_GETMESSAGE,     "GetMsgProc"  },
    { "cwp",   WH_CALLWNDPROC,    "CallWndProc" },
    { "cbt",   WH_CBT,            "CbtProc"     },
    { "idle",  WH_FOREGROUNDIDLE, "IdleProc"    },
    { "kbd",   WH_KEYBOARD,       "KbdProc"     },
    { "mouse", WH_MOUSE,          "MouseProc"   },
    { "hw",    WH_HARDWARE,       "HwProc"      },
};

static const char* kFamilies[] = {
    "GetMsgProc", "CallWndProc", "CbtProc", "IdleProc",
    "KbdProc", "MouseProc", "HwProc", "HookProc", "WinEventProc",
};

struct found { HWND hwnd; DWORD pid; DWORD tid; wchar_t cls[128]; };

static BOOL CALLBACK find_win(HWND h, LPARAM l) {
    found* f = (found*)l;
    DWORD pid = 0;
    DWORD tid = GetWindowThreadProcessId(h, &pid);
    if (pid != f->pid) return TRUE;
    wchar_t cls[128] = { 0 };
    GetClassNameW(h, cls, 128);
    if (wcscmp(cls, f->cls) == 0) {
        f->hwnd = h; f->tid = tid;
        return FALSE;
    }
    return TRUE;
}

static std::string slurp(const wchar_t* path) {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER sz{};
    GetFileSizeEx(f, &sz);
    std::string s;
    s.resize((size_t)sz.QuadPart);
    DWORD got = 0;
    if (!s.empty()) ReadFile(f, s.data(), (DWORD)s.size(), &got, nullptr);
    s.resize(got);
    CloseHandle(f);
    return s;
}

int wmain(int argc, wchar_t** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);

    if (argc < 3) {
        printf("usage: hook_matrix.exe <target.exe> <class> [mode] [seconds] [tl|global]\n");
        return 2;
    }
    const wchar_t* target = argv[1];
    wchar_t want_cls[128] = L"MockClientWindow";
    lstrcpynW(want_cls, argv[2], 128);
    const wchar_t* mode = (argc > 3) ? argv[3] : L"";
    int seconds = (argc > 4) ? _wtoi(argv[4]) : 20;
    bool global = (argc > 5) && (wcscmp(argv[5], L"global") == 0);
    if (seconds <= 0) seconds = 20;

    /* Fresh log: without this the table would count the previous run's lines. */
    DeleteFileW(g_log);

    /* Start the target. The mode, when given, is appended to its command line -
     * mock_client reads it from GetCommandLine. */
    std::wstring cmd = L"\"";
    cmd += target;
    cmd += L"\"";
    if (mode[0]) { cmd += L" "; cmd += mode; }
    std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
    cmdline.push_back(0);

    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, FALSE, 0,
                        nullptr, nullptr, &si, &pi)) {
        printf("[!] target start failed %lu\n", GetLastError());
        return 1;
    }
    printf("[*] target pid %lu\n", (unsigned long)pi.dwProcessId);
    Sleep(1500);

    found f{}; f.pid = pi.dwProcessId;
    lstrcpynW(f.cls, want_cls, 128);
    for (int i = 0; i < 20 && !f.hwnd; ++i) {
        EnumWindows(find_win, (LPARAM)&f);
        if (!f.hwnd) Sleep(300);
    }
    if (!f.hwnd) {
        printf("[!] no window of class %ls in pid %lu\n", want_cls, (unsigned long)pi.dwProcessId);
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }
    printf("[*] window %p tid %lu class %ls\n", (void*)f.hwnd, (unsigned long)f.tid, f.cls);

    DWORD hook_tid = global ? 0 : f.tid;

    HMODULE d = LoadLibraryW(g_dll);
    printf("[*] dll %p err=%lu\n", (void*)d, GetLastError());
    if (!d) { TerminateProcess(pi.hProcess, 0); return 1; }

    HHOOK hooks[8] = { 0 };
    int n = 0;
    printf("--- install ---\n");
    for (const spec& s : kSpecs) {
        FARPROC fp = GetProcAddress(d, s.exp);
        if (!fp) { printf("%-6s export %-11s MISSING\n", s.name, s.exp); continue; }
        SetLastError(0);
        HHOOK h = SetWindowsHookExW(s.type, (HOOKPROC)fp, d, hook_tid);
        DWORD e = GetLastError();
        printf("%-6s type=%2d export=%-11s hook=%p err=%lu\n", s.name, s.type, s.exp, (void*)h, e);
        if (h) hooks[n++] = h;
    }
    if (!n) { printf("[!] nothing installed\n"); TerminateProcess(pi.hProcess, 0); return 1; }

    /* The pinger lives in the hook DLL: PostMessage(WM_NULL) + SetWindowPos once
     * a second. That is the stimulus WH_GETMESSAGE and WH_CBT need even when
     * nobody is touching the machine. */
    typedef void (__stdcall *pinger_fn)(HWND);
    pinger_fn pinger = (pinger_fn)(uintptr_t)GetProcAddress(d, "StartPinger");
    if (pinger) { pinger(f.hwnd); printf("[*] pinger started\n"); }

    printf("--- stimulate %d s ---\n", seconds);
    SetForegroundWindow(f.hwnd);
    ULONGLONG t0 = GetTickCount64();
    int it = 0;
    while ((int)((GetTickCount64() - t0) / 1000) < seconds) {
        PostMessageW(f.hwnd, WM_NULL, 0, 0);

        if (it % 10 == 0) {
            /* Move/size: HCBT_MOVESIZE for the window's own thread. */
            int dx = (it / 10) % 2 ? 4 : -4;
            SetWindowPos(f.hwnd, nullptr, dx, dx, 640 + dx, 400 + dx,
                         SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOSENDCHANGING);
            SetForegroundWindow(f.hwnd);
        }
        if (it % 5 == 0) {
            /* Real input through the input stack: this is what the game sees
             * when the user presses a key. With RIDEV_NOLEGACY on the target it
             * becomes WM_INPUT and no legacy keyboard/mouse message is queued. */
            INPUT in[2];
            ZeroMemory(in, sizeof(in));
            in[0].type = INPUT_KEYBOARD; in[0].ki.wVk = VK_F13;
            in[1] = in[0]; in[1].ki.dwFlags = KEYEVENTF_KEYUP;
            SendInput(2, in, sizeof(INPUT));
        }
        if (it % 20 == 0) {
            /* A message *sent* (not posted) to the target window. WH_CALLWNDPROC
             * runs in the sender's context, so its log line carries *this*
             * process's pid - that is the observable, and the table shows it. */
            SendMessageW(f.hwnd, WM_NULL, 0, 0);
        }
        Sleep(100);
        ++it;
    }

    for (int i = 0; i < n; ++i) UnhookWindowsHookEx(hooks[i]);
    Sleep(500);

    /* ---- parse the hook log ------------------------------------------- */
    std::string log = slurp(g_log);
    printf("--- log (%zu bytes) ---\n", log.size());

    /* per family: total count, and a per-pid breakdown */
    std::map<std::string, int> fired;
    std::map<std::string, std::map<unsigned, int>> by_pid;
    int dllmain_target = 0, dllmain_other = 0;

    size_t pos = 0;
    std::vector<std::string> lines;
    while (pos <= log.size()) {
        size_t nl = log.find('\n', pos);
        std::string ln = log.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        if (!ln.empty() && ln.back() == '\r') ln.pop_back();
        if (nl == std::string::npos) { if (!ln.empty()) lines.push_back(ln); break; }
        lines.push_back(ln);
        pos = nl + 1;
    }

    for (const std::string& ln : lines) {
        unsigned pid = 0;
        size_t p = ln.find(" pid ");
        if (p != std::string::npos) pid = (unsigned)strtoul(ln.c_str() + p + 5, nullptr, 10);

        if (ln.find("DllMain") != std::string::npos) {
            if (pid == pi.dwProcessId) dllmain_target++;
            else dllmain_other++;
        }
        for (const char* fam : kFamilies) {
            std::string needle = std::string(fam) + " fired";
            if (ln.find(needle) != std::string::npos) {
                fired[fam]++;
                by_pid[fam][pid]++;
            }
        }
    }

    printf("--- result: target pid %lu (%ls) ---\n", (unsigned long)pi.dwProcessId, target);
    printf("DllMain in target=%d other=%d\n", dllmain_target, dllmain_other);
    printf("%-13s %8s %s\n", "family", "fired", "pids");
    for (const char* fam : kFamilies) {
        int c = fired[fam];
        std::string pids;
        char b[64];
        for (auto& kv : by_pid[fam]) { sprintf(b, "%u:%d ", kv.first, kv.second); pids += b; }
        printf("%-13s %8d %s\n", fam, c, pids.c_str());
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
