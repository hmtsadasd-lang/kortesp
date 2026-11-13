/* Sanity check: does a WH_GETMESSAGE thread hook fire at all on this box?
 *
 * The target is a plain Win32 GUI app whose message loop calls GetMessage,
 * so a thread hook has to be invoked. If this prints nothing, hooks are not
 * working here and the winevent result says nothing about the client.
 *
 * Build: gcc -m64 -O2 -o hook_sanity.exe hook_sanity.c
 */
#include <windows.h>
#include <stdio.h>

static volatile LONG g_calls;

static LRESULT CALLBACK proc(int code, WPARAM wp, LPARAM lp) {
    InterlockedIncrement(&g_calls);
    printf("[*] hook callback code=%d in pid %lu\n", code, GetCurrentProcessId());
    fflush(stdout);
    return CallNextHookEx(NULL, code, wp, lp);
}

static BOOL CALLBACK find_win(HWND h, LPARAM l) {
    DWORD *p = (DWORD *)l;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid == p[0]) {
        wchar_t cls[64] = { 0 };
        GetClassNameW(h, cls, 64);
        if (wcscmp(cls, L"MockGuiTarget") == 0) {
            *(HWND *)(p + 1) = h;
            return FALSE;
        }
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

    HWND w = NULL;
    DWORD ctx[2] = { pi.dwProcessId, 0 };
    EnumWindows(find_win, (LPARAM)ctx);
    w = (HWND)ctx[1];

    if (!w) { printf("[!] no target window\n"); return 1; }
    DWORD tid = GetWindowThreadProcessId(w, NULL);
    printf("[*] window %p tid %lu\n", (void *)w, (unsigned long)tid);

    HHOOK h = SetWindowsHookExW(WH_GETMESSAGE, proc, NULL, tid);
    printf("hook=%p err=%lu\n", h, GetLastError());
    if (!h) return 1;

    for (int i = 0; i < 10; ++i) {
        PostMessageW(w, WM_NULL, 0, 0);
        Sleep(400);
    }
    printf("[*] callbacks=%ld\n", InterlockedCompareExchange(&g_calls, 0, 0));
    UnhookWindowsHookEx(h);
    TerminateProcess(pi.hProcess, 0);
    return InterlockedCompareExchange(&g_calls, 0, 0) ? 0 : 2;
}
