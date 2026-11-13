// Input-hook delivery: the vector that does not need a message *loop*.
//
// What has been measured so far (docs/SESSION_NOTES.md, LIVE_TEST_RESULTS.md):
//   * WH_GETMESSAGE + DLL  -> the DLL is injected into the target and the
//     callback runs there (proved against lab\mock_gui.exe, which calls
//     GetMessage). The client never fires it because its loop is PeekMessage.
//   * WH_CALLWNDPROC + DLL -> the hook runs in the *sender's* context, so it
//     lands in Discord/Chrome/Nvidia/Vanguard/the launcher, never in the
//     client: the client does not send messages.
//   * WINEVENT_INCONTEXT   -> installs, but does not inject.
//
// What is left is the input path. A keyboard or mouse hook is dispatched by
// the *input stack* to the thread that owns the focused window - not by the
// target's message loop. The client's window thread (class UnrealWindow) gets
// keyboard focus the moment the game is focused, so a thread hook on that
// thread puts our DLL inside the client as soon as the user touches the
// keyboard or the mouse.
//
// The DLL is injected from *this* process's copy of the file, so nothing has
// to exist in the game directory.
//
//   usage: hook_input.exe <dll> [seconds] [kbd|mouse|both] [tid]
//          tid 0 = global (every process), otherwise the client's window thread
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

int wmain(int argc, wchar_t** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);

    wchar_t dll[MAX_PATH] = L"C:\\dev\\fortesp\\out\\FortHook.dll";
    if (argc > 1) lstrcpynW(dll, argv[1], MAX_PATH);
    int seconds = (argc > 2) ? _wtoi(argv[2]) : 120;
    wchar_t mode[16] = L"kbd";
    if (argc > 3) lstrcpynW(mode, argv[3], 16);
    DWORD forced_tid = (argc > 4) ? (DWORD)_wtoi(argv[4]) : 0xFFFFFFFF;

    DWORD pid = pid_of(L"FortniteClient-Win64-Shipping.exe");
    printf("client pid %lu\n", (unsigned long)pid);
    if (!pid) { printf("[!] client not running\n"); return 1; }

    DWORD ctx[2] = { pid, 0 };
    EnumWindows(find_win, (LPARAM)ctx);
    HWND w = (HWND)ctx[1];
    if (!w) { printf("[!] no client window\n"); return 1; }
    DWORD tid = GetWindowThreadProcessId(w, NULL);
    printf("window %p tid %lu\n", (void*)w, (unsigned long)tid);

    DWORD hook_tid = (forced_tid == 0xFFFFFFFF) ? tid : forced_tid;

    HMODULE d = LoadLibraryW(dll);
    if (!d) { printf("[!] dll %ls err=%lu\n", dll, GetLastError()); return 1; }
    HOOKPROC proc = (HOOKPROC)(uintptr_t)GetProcAddress(d, "HookProc");
    printf("dll %p HookProc %p\n", d, (void*)proc);
    if (!proc) return 1;

    bool want_kbd = (wcscmp(mode, L"mouse") != 0);
    bool want_mouse = (wcscmp(mode, L"kbd") != 0);

    HHOOK hk = nullptr, hm = nullptr;
    if (want_kbd) {
        hk = SetWindowsHookExW(WH_KEYBOARD, proc, d, hook_tid);
        DWORD e = GetLastError();
        printf("WH_KEYBOARD   hook=%p err=%lu tid=%lu\n", hk, e, (unsigned long)hook_tid);
        if (!hk) printf("[!] keyboard hook refused err=%lu\n", e);
    }
    if (want_mouse) {
        hm = SetWindowsHookExW(WH_MOUSE, proc, d, hook_tid);
        DWORD e = GetLastError();
        printf("WH_MOUSE      hook=%p err=%lu tid=%lu\n", hm, e, (unsigned long)hook_tid);
        if (!hm) printf("[!] mouse hook refused err=%lu\n", e);
    }
    if (!hk && !hm) { printf("[!] nothing installed\n"); return 1; }

    printf("[+] installed - now click the game window and press a key\n");
    hlog("[*] input deliver: kbd=%p mouse=%p tid=%lu dll=%ls",
         hk, hm, (unsigned long)hook_tid, dll);

    for (int i = 0; i < seconds; ++i) {
        Sleep(1000);
        if ((i + 1) % 15 == 0) printf("  ... %d s left\n", seconds - i - 1);
    }

    if (hk) UnhookWindowsHookEx(hk);
    if (hm) UnhookWindowsHookEx(hm);
    printf("[*] hooks removed\n");
    return 0;
}
