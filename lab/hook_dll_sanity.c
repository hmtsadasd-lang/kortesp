/* Does a WH_GETMESSAGE hook with a real DLL inject it into the target?
 *
 * The target here is a plain Win32 GUI app whose message loop calls
 * GetMessage, so a thread hook has to be invoked. If the callback in the DLL
 * runs, the injection works and the client's silence is its own message
 * loop (PeekMessage) - not the loader.
 *
 * Build: gcc -m64 -O2 -o hook_dll_sanity.exe hook_dll_sanity.c
 */
#include <windows.h>
#include <stdio.h>

static wchar_t g_dll[MAX_PATH] = L"C:\\dev\\fortesp\\out\\FortHook.dll";

static BOOL CALLBACK find_win(HWND h, LPARAM l) {
    DWORD *p = (DWORD *)l;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid == p[0]) {
        wchar_t cls[64] = { 0 };
        GetClassNameW(h, cls, 64);
        if (wcscmp(cls, L"MockGuiTarget") == 0) { *(HWND *)(p + 1) = h; return FALSE; }
    }
    return TRUE;
}

int wmain(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    wchar_t target[] = L"C:\\dev\\fortesp\\out\\lab\\mock_gui.exe";
    if (!CreateProcessW(NULL, target, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[!] target start failed %lu\n", GetLastError());
        return 1;
    }
    printf("[*] target pid %lu\n", (unsigned long)pi.dwProcessId);
    Sleep(1200);

    DWORD ctx[2] = { pi.dwProcessId, 0 };
    EnumWindows(find_win, (LPARAM)ctx);
    HWND w = (HWND)ctx[1];
    if (!w) { printf("[!] no target window\n"); return 1; }
    DWORD tid = GetWindowThreadProcessId(w, NULL);

    // The module has to be loaded for real here: the loader maps *that file*
    // into the target and calls the address inside that copy.
    HMODULE d = LoadLibraryW(g_dll);
    printf("dll %p err=%lu\n", d, GetLastError());
    if (!d) return 1;
    HOOKPROC proc = (HOOKPROC)(uintptr_t)GetProcAddress(d, "HookProc");
    printf("HookProc %p\n", (void *)proc);

    HHOOK h = proc ? SetWindowsHookExW(WH_GETMESSAGE, proc, d, tid) : NULL;
    printf("hook=%p err=%lu\n", h, GetLastError());
    if (!h) return 1;

    for (int i = 0; i < 12; ++i) {
        PostMessageW(w, WM_NULL, 0, 0);
        Sleep(400);
    }
    UnhookWindowsHookEx(h);
    TerminateProcess(pi.hProcess, 0);
    printf("[*] done - the hook log tells whether the DLL ran in the target\n");
    return 0;
}
