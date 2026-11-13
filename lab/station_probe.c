// Is this process on the same desktop as the client, and can it enumerate it?
//
// "I can see the game on my screen, so we share a desktop" is an assumption: a
// process can sit on WinSta0\Default and still be denied the *input* desktop's
// objects, and a hook has to land on the exact desktop of the target thread.
// This prints names, not conclusions.
#include <windows.h>
#include <stdio.h>

static void dump(const char* label, HANDLE obj) {
    if (!obj) { printf("%-10s <no handle> err=%lu\n", label, GetLastError()); return; }
    wchar_t n[128] = L"";
    DWORD need = 0;
    BOOL ok = GetUserObjectInformationW(obj, UOI_NAME, n, sizeof(n), &need);
    DWORD len = 0;
    // UOI_FLAGS carries the desktop's window-station flags (write access,
    // switch desktop, global hooks, visibility) - USEROBJECTFLAGS.
    USEROBJECTFLAGS fl;
    ZeroMemory(&fl, sizeof(fl));
    DWORD got = 0;
    BOOL ok2 = GetUserObjectInformationW(obj, UOI_FLAGS, &fl, sizeof(fl), &got);
    printf("%-10s name='%ls' read=%d flags=0x%08lX\n", label, n, ok, ok2 ? fl.dwFlags : 0);
}

struct C { DWORD pid; HWND h; };

static BOOL CALLBACK find_client_win(HWND w, LPARAM p) {
    DWORD pid = 0;
    GetWindowThreadProcessId(w, &pid);
    wchar_t exe[MAX_PATH] = L"";
    DWORD sz = MAX_PATH;
    HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (ph) {
        QueryFullProcessImageNameW(ph, 0, exe, &sz);
        CloseHandle(ph);
        if (wcsstr(exe, L"FortniteClient-Win64-Shipping.exe")) {
            ((struct C*)p)->pid = pid;
            ((struct C*)p)->h = w;
            return FALSE;
        }
    }
    return TRUE;
}

int wmain(void) {
    dump("winsta", GetProcessWindowStation());
    dump("desktop", GetThreadDesktop(GetCurrentThreadId()));

    // The client's own thread desktop, found through its window.
    HWND h = FindWindowW(L"UnrealWindow", nullptr);
    if (!h) {
        // Fall back to any window of the process.
        struct C ctx;
        ctx.pid = 0; ctx.h = 0;
        EnumWindows(find_client_win, (LPARAM)&ctx);
        h = ctx.h;
    }
    printf("client window: %p\n", h);
    if (h) {
        DWORD pid = 0;
        DWORD tid = GetWindowThreadProcessId(h, &pid);
        wchar_t cls[128] = L"";
        GetClassNameW(h, cls, 128);
        printf("client tid=%lu pid=%lu class='%ls'\n", (unsigned long)tid, (unsigned long)pid, cls);

        HANDLE hd = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS | DESKTOP_HOOKCONTROL);
        printf("OpenInputDesktop=%p err=%lu\n", hd, GetLastError());
        if (hd) dump("input", hd);
    }

    // What a subsetting probe would need: can this process open the input
    // desktop for hook control at all?
    return 0;
}
