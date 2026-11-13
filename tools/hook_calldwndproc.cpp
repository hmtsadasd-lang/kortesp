// WH_CALLWNDPROC delivery.
//
// The control (lab\hook_dll_sanity.c) proved that a WH_GETMESSAGE hook with
// a real DLL does inject that DLL into the target and run the callback
// there. It did not fire for the client because the client's message loop
// uses PeekMessage, which never raises a WH_GETMESSAGE hook.
//
// WH_CALLWNDPROC fires in the context of the thread that *sent* a message -
// so it is the client that has to send one, and the client's own SendMessage
// traffic does that continuously. The DLL is injected into the client, the
// callback runs on the client's thread, and from there the payload is mapped
// out of the client's own address space.
//
//   usage: hook_calldwndproc.exe <dll> [seconds]
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
    DWORD *p = (DWORD *)l;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid != p[0]) return TRUE;
    wchar_t cls[128] = { 0 };
    GetClassNameW(h, cls, 128);
    if (wcscmp(cls, L"UnrealWindow") == 0) { *(HWND *)(p + 1) = h; return FALSE; }
    if (IsWindowVisible(h) && !*(HWND *)(p + 1)) { *(HWND *)(p + 1) = h; }
    return TRUE;
}

static DWORD pid_of(const wchar_t* exe) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD hit = 0;
    if (Process32FirstW(snap, &pe)) do {
        if (wcscmp(pe.szExeFile, exe) == 0) { hit = pe.th32ProcessID; break; }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return hit;
}

int wmain(int argc, wchar_t** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    wchar_t dll[MAX_PATH] = L"C:\\dev\\fortesp\\out\\FortHook.dll";
    if (argc > 1) lstrcpynW(dll, argv[1], MAX_PATH);
    int seconds = (argc > 2) ? _wtoi(argv[2]) : 120;

    DWORD pid = pid_of(L"FortniteClient-Win64-Shipping.exe");
    printf("client pid %lu\n", (unsigned long)pid);
    if (!pid) { printf("[!] client not running\n"); return 1; }

    DWORD ctx[2] = { pid, 0 };
    EnumWindows(find_win, (LPARAM)ctx);
    HWND w = (HWND)ctx[1];
    if (!w) { printf("[!] no client window\n"); return 1; }
    DWORD tid = GetWindowThreadProcessId(w, NULL);
    printf("window %p tid %lu\n", (void *)w, (unsigned long)tid);

    HMODULE d = LoadLibraryW(dll);
    if (!d) { printf("[!] dll %ls err=%lu\n", dll, GetLastError()); return 1; }
    HOOKPROC proc = (HOOKPROC)(uintptr_t)GetProcAddress(d, "HookProc");
    printf("dll %p HookProc %p\n", d, (void *)proc);
    if (!proc) return 1;

    // tid = 0 installs the hook for *every* thread in the process. The
    // client does not send messages from its window thread, but some thread
    // of it does - and WH_CALLWNDPROC fires in the context of the thread
    // that sent the message, so a global hook is what puts our DLL inside
    // the client.
    DWORD hook_tid = (argc > 3) ? (DWORD)_wtoi(argv[3]) : 0;
    HHOOK h = SetWindowsHookExW(WH_CALLWNDPROC, proc, d, hook_tid);
    DWORD err = GetLastError();
    printf("WH_CALLWNDPROC hook=%p err=%lu tid=%lu\n", h, err, (unsigned long)hook_tid);
    if (!h) { printf("[!] refused err=%lu\n", err); return 1; }

    printf("[+] installed - the client's own SendMessage traffic should fire it\n");
    hlog("[*] calldwndproc deliver: hook=%p tid=%lu dll=%ls", h, (unsigned long)tid, dll);

    for (int i = 0; i < seconds; ++i) {
        Sleep(1000);
        if ((i + 1) % 15 == 0) printf("  ... %d s left\n", seconds - i - 1);
    }
    UnhookWindowsHookEx(h);
    printf("[*] hook removed\n");
    return 0;
}
