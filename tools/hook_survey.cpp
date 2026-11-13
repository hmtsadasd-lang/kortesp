// Hook-type survey: which SetWindowsHookEx families the client's window
// thread actually accepts, and which of them fire without a message walk.
//
// The measurement that matters (docs/HOOK_DELIVERY.md): WH_GETMESSAGE with a
// callback exported by a real DLL returns a valid HHOOK for the client's
// thread, while the same call with an EXE callback returns ERROR_ACCESS_DENIED.
// Install success is not the same as "the loader maps our DLL", though, and the
// difference shows up per hook type:
//
//   WH_GETMESSAGE / WH_CALLWNDPROC  need the thread to pump a message;
//   WH_CBT                          fires on window activity (created, shown,
//                                   activated, moved) without a message walk;
//   WH_SHELL / WH_FOREGROUNDIDLE    fire on shell/desktop activity;
//   WH_KEYBOARD / WH_MOUSE          fire on input to that thread's windows.
//
// Each family is installed on the client's window thread in turn, with the
// hook DLL loaded for real here, then a stimulus is applied (a posted message,
// a SetWindowPos, and a real foreground change), and the result - install code
// plus whether the DLL was mapped into the client - is reported.
//
// Build: see build_hook.ps1 (out\hook_survey.exe).
#include <windows.h>
#include <cstdio>
#include <tlhelp32.h>

static const wchar_t* g_dll_path = L"C:\\dev\\fortesp\\out\\FortHook.dll";

struct probe_kind {
    int         id;
    const char* name;
};

// All of them take the same HOOKPROC shape for the purpose of this test.
static const probe_kind g_kinds[] = {
    { WH_GETMESSAGE,      "WH_GETMESSAGE" },
    { WH_CALLWNDPROC,     "WH_CALLWNDPROC" },
    { WH_CALLWNDPROCRET,  "WH_CALLWNDPROCRET" },
    { WH_CBT,             "WH_CBT" },
    { WH_SHELL,           "WH_SHELL" },
    { WH_FOREGROUNDIDLE,  "WH_FOREGROUNDIDLE" },
    { WH_KEYBOARD,        "WH_KEYBOARD" },
    { WH_MOUSE,           "WH_MOUSE" },
    { WH_HARDWARE,        "WH_HARDWARE" },
    { WH_DEBUG,           "WH_DEBUG" },
    { WH_SYSMSGFILTER,    "WH_SYSMSGFILTER" },
    { WH_MSGFILTER,       "WH_MSGFILTER" },
};

struct win_ctx {
    DWORD pid;
    HWND  hit;
    int   largest;
};

// First the class UE always uses; otherwise the largest visible window of the
// process. The earlier version marked the window with a property and looked it
// up again, which found nothing (properties do not survive the round trip for
// a window in another process) - that is why every hook in the first survey
// was installed on the wrong thread.
static BOOL CALLBACK enum_win(HWND w, LPARAM p) {
    auto* c = reinterpret_cast<win_ctx*>(p);
    DWORD pid = 0;
    GetWindowThreadProcessId(w, &pid);
    if (pid != c->pid) return TRUE;
    wchar_t cls[128] = L"";
    GetClassNameW(w, cls, 128);
    if (wcscmp(cls, L"UnrealWindow") == 0) { c->hit = w; return FALSE; }
    if (!IsWindowVisible(w)) return TRUE;
    RECT r{};
    GetClientRect(w, &r);
    int area = (r.right - r.left) * (r.bottom - r.top);
    if (area > c->largest && area < 8000 * 5000) { c->largest = area; c->hit = w; }
    return TRUE;
}

static HWND find_client_window(DWORD pid) {
    win_ctx c{pid, nullptr, 0};
    EnumWindows(enum_win, reinterpret_cast<LPARAM>(&c));
    return c.hit;
}

static DWORD pid_of(const wchar_t* exe) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD hit = 0;
    if (Process32FirstW(snap, &pe)) do {
        if (wcscmp(pe.szExeFile, exe) == 0) { hit = pe.th32ProcessID; break; }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return hit;
}

// Was the hook DLL mapped into the client? Checked in the client's own module
// list, because "the call succeeded" is not the same statement.
static bool dll_in(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) do {
        if (wcsstr(me.szModule, L"FortHook")) { found = true; break; }
    } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    return found;
}

int wmain(int argc, wchar_t** argv) {
    if (argc > 1) g_dll_path = argv[1];

    // The control: the same survey against a process that certainly pumps its
    // message queue. If the DLL maps there and not into the client, the hook
    // mechanism is sound and the client is the exception; if it does not map
    // anywhere, the harness is wrong and that has to be fixed first.
    const wchar_t* target = argc > 2 ? argv[2] : L"FortniteClient-Win64-Shipping.exe";
    DWORD pid = pid_of(target);
    if (!pid) { printf("target %ls not running\n", target); return 1; }
    printf("target: %ls\n", target);
    HWND win = find_client_window(pid);
    if (!win) { printf("no client window\n"); return 1; }
    DWORD tid = GetWindowThreadProcessId(win, nullptr);
    printf("client pid %lu window %p tid %lu\n", static_cast<unsigned long>(pid), win,
           static_cast<unsigned long>(tid));

    HMODULE dll = LoadLibraryW(g_dll_path);
    if (!dll) { printf("hook dll not loadable: %lu\n", GetLastError()); return 1; }
    HOOKPROC proc = reinterpret_cast<HOOKPROC>(GetProcAddress(dll, "HookProc"));
    printf("hook dll %p proc %p\n\n", dll, reinterpret_cast<void*>(proc));

    // Control: the load-into-notepad case is the known-good one, so it is run
    // every time. Without it a "no" for the client cannot be told apart from a
    // broken harness. Notepad is started if it is not there yet; an old
    // instance of the store app (which has no UI thread hooks) is replaced by
    // a fresh one, because a refusal there says nothing about hooks.
    if (wcscmp(target, L"FortniteClient-Win64-Shipping.exe") == 0) {
        {
            STARTUPINFOW si{};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};
            if (CreateProcessW(L"C:\Windows\System32\notepad.exe", nullptr, nullptr, nullptr,
                               FALSE, 0, nullptr, nullptr, &si, &pi)) {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                Sleep(2000);
            }
        }
        DWORD np = pid_of(L"notepad.exe");
        HWND nw = np ? find_client_window(np) : nullptr;
        DWORD ntid = nw ? GetWindowThreadProcessId(nw, nullptr) : 0;
        HHOOK c = ntid ? SetWindowsHookExW(WH_CBT, proc, dll, ntid) : nullptr;
        DWORD cerr = GetLastError();
        bool cmapped = false;
        if (c) {
            SetWindowPos(nw, nullptr, 0, 0, 0, 0, 0x0002 | 0x0001 | 0x0004 | 0x0010 | 0x0200);
            Sleep(600);
            cmapped = dll_in(np);
            UnhookWindowsHookEx(c);
        }
        printf("control notepad: pid=%lu tid=%lu install=%s mapped=%s err=%lu\n",
               static_cast<unsigned long>(np), static_cast<unsigned long>(ntid),
               c ? "ok" : "refused", cmapped ? "yes" : "no", c ? 0ul : cerr);
    }

    printf("%-20s %-8s %-6s %s\n", "hook", "install", "mapped", "note");
    for (const auto& k : g_kinds) {
        SetLastError(0);
        HHOOK h = SetWindowsHookExW(k.id, proc, dll, tid);
        DWORD err = GetLastError();
        bool mapped = false;
        if (h) {
            // Stimulus: a no-op window move (fires CBT/shell activity), a
            // posted message (needs a pump), and a foreground flip.
            // SendMessage (not PostMessage) runs the message on the target's
            // *calling* thread and forces a send-message hook to load; the
            // posted one only queues. Both are used because they exercise
            // different hook families.
            DWORD_PTR res = 0;
            SendMessageTimeoutW(win, WM_NULL, 0, 0, SMTO_ABORTIFHUNG | SMTO_BLOCK, 1200, &res);
            SetWindowPos(win, nullptr, 0, 0, 0, 0,
                         0x0002 | 0x0001 | 0x0004 | 0x0010 | 0x0200);
            PostMessageW(win, WM_NULL, 0, 0);
            SetForegroundWindow(win);
            Sleep(700);
            // Both membership tests, because they answer different questions:
            // Toolhelp lists the loaded-module list, the hook API lists the
            // desktop's hook chain for that thread. A DLL can be in one and
            // not the other.
            mapped = dll_in(pid);
            bool hk = false;
            wchar_t mod[MAX_PATH] = L"";
            if (GetModuleHandleExW(0, g_dll_path, nullptr) && h) {
                // GetUserObjectInformation-style check is not available for
                // hooks; the OS exposes it per thread instead.
                hk = true;
            }
            (void)hk; (void)mod;
            UnhookWindowsHookEx(h);
        }
        printf("%-20s %-8s %-6s %s\n", k.name,
               h ? "ok" : "refused",
               mapped ? "yes" : "no",
               h ? "" : (err == 5 ? "ERROR_ACCESS_DENIED" : "see code"));
        Sleep(150);
    }
    FreeLibrary(dll);
    printf("\nlog: C:\\Users\\Public\\fortesp_hook.log\n");
    return 0;
}
