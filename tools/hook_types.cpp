// Hook-type delivery against the client's own window thread.
//
// Measured so far (docs/SESSION_NOTES.md):
//   WH_GETMESSAGE  -> the client's loop is PeekMessage, so it never fires.
//   WH_CALLWNDPROC -> fires in the *sender's* context, and the client does
//                      not send messages.
//   WH_KEYBOARD    -> the client consumes raw input only, so no legacy
//                      keyboard message is ever generated for it.
//   WINEVENT_INCONTEXT -> installs, does not inject.
//
// What is left are the thread-local hooks whose *target* is the receiving or
// owning thread:
//
//   WH_CBT (5)            fires in the thread that created the window, on
//                         WM_MOVE / WM_SIZE / WM_ACTIVATE / WM_SETFOCUS.
//   WH_FOREGROUNDIDLE (11) fires in the foreground thread when its queue runs
//                         dry - which a game does between every frame.
//
// Both need the client to *dispatch* a message, not to call GetMessage, so
// the PeekMessage loop does not get in the way.
//
//   usage: hook_types.exe <dll> <seconds> [cbt,idle,get]
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>

static wchar_t g_log[MAX_PATH] = L"C:\\Users\\Public\\fortesp_hook.log";

static void hlog(const char* fmt, ...) {
    char buf[512]{};
    va_list a;
    va_start(a, fmt);
    wvsprintfA(buf, fmt, a);
    va_end(a);
    lstrcatA(buf, "\r\n");
    HANDLE f = CreateFileW(g_log, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    SetFilePointer(f, 0, nullptr, FILE_END);
    WriteFile(f, buf, static_cast<DWORD>(lstrlenA(buf)), &w, nullptr);
    CloseHandle(f);
}

static BOOL CALLBACK find_win(HWND h, LPARAM l) {
    DWORD* p = (DWORD*)l;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid != p[0]) return TRUE;
    wchar_t cls[128] = { 0 };
    GetClassNameW(h, cls, 128);
    if (wcscmp(cls, L"UnrealWindow") == 0) { *(HWND*)(p + 1) = h; return FALSE; }
    if (IsWindowVisible(h) && !*(HWND*)(p + 1)) *(HWND*)(p + 1) = h;
    return TRUE;
}

static DWORD pid_of(const wchar_t* exe) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD hit = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (wcscmp(pe.szExeFile, exe) == 0) { hit = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return hit;
}

struct spec {
    const wchar_t* name;
    int type;
    const char* export_name;
};

int wmain(int argc, wchar_t** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);

    wchar_t dll[MAX_PATH] = L"C:\\dev\\fortesp\\out\\FortHook.dll";
    if (argc > 1) lstrcpynW(dll, argv[1], MAX_PATH);
    int seconds = (argc > 2) ? _wtoi(argv[2]) : 120;
    wchar_t want[64] = L"cbt,idle,get";
    if (argc > 3) lstrcpynW(want, argv[3], 64);
    // tid override: 0 = global (every thread of every process on the desktop).
    DWORD tid_override = (argc > 4) ? (DWORD)_wtoi(argv[4]) : 0xFFFFFFFF;

    DWORD pid = pid_of(L"FortniteClient-Win64-Shipping.exe");
    printf("client pid %lu\n", (unsigned long)pid);
    if (!pid) { printf("[!] client not running\n"); return 1; }

    DWORD ctx[2] = { pid, 0 };
    EnumWindows(find_win, (LPARAM)ctx);
    HWND w = (HWND)ctx[1];
    if (!w) { printf("[!] no client window\n"); return 1; }
    DWORD tid = GetWindowThreadProcessId(w, NULL);
    printf("window %p tid %lu\n", (void*)w, (unsigned long)tid);
    if (tid_override != 0xFFFFFFFF) {
        printf("tid overridden to %lu (0 = global)\n", (unsigned long)tid_override);
        tid = tid_override;
    }

    HMODULE d = LoadLibraryW(dll);
    if (!d) { printf("[!] dll %ls err=%lu\n", dll, GetLastError()); return 1; }
    printf("dll %p\n", d);

    spec specs[] = {
        { L"cbt",  WH_CBT,             "CbtProc"  },
        { L"idle", WH_FOREGROUNDIDLE,  "IdleProc" },
        { L"get",  WH_GETMESSAGE,      "HookProc" },
        { L"hw",   WH_HARDWARE,        "HookProc" },
        { L"msg",  WH_MSGFILTER,       "HookProc" },
    };

    HHOOK hooks[8] = { 0 };
    int n = 0;
    for (auto& s : specs) {
        if (!wcsstr(want, s.name)) continue;
        FARPROC fp = GetProcAddress(d, s.export_name);
        if (!fp) { printf("[!] no export %s\n", s.export_name); continue; }
        HHOOK h = SetWindowsHookExW(s.type, (HOOKPROC)fp, d, tid);
        DWORD e = GetLastError();
        printf("%-6s type=%2d export=%-9s hook=%p err=%lu tid=%lu\n",
               s.name, s.type, s.export_name, h, e, (unsigned long)tid);
        if (!h) printf("[!] %s refused err=%lu\n", s.name, e);
        else hooks[n++] = h;
    }
    if (!n) { printf("[!] nothing installed\n"); return 1; }

    printf("[+] installed - waiting %d s\n", seconds);
    hlog("[*] hook_types deliver: n=%d tid=%lu dll=%ls", n, (unsigned long)tid, dll);

    for (int i = 0; i < seconds; ++i) {
        Sleep(1000);
        if ((i + 1) % 15 == 0) printf("  ... %d s left\n", seconds - i - 1);
    }

    for (int i = 0; i < n; ++i) UnhookWindowsHookEx(hooks[i]);
    printf("[*] hooks removed\n");
    return 0;
}
