// Which half of the win-event mechanism works?
//
//   mode 1  WINEVENT_OUTOFCONTEXT, callback in this EXE
//           -> the event has to arrive here. If it does not, the event is
//              never raised (or never reaches us) and the in-context variant
//              is hopeless too.
//   mode 2  WINEVENT_INCONTEXT, callback in FortHook.dll
//           -> the target's own loader maps the DLL and calls it there.
//
// usage: winevent_probe.exe <mode> [dll]
#include <windows.h>
#include <cstdio>

static void CALLBACK exe_proc(HWINEVENTHOOK h, DWORD ev, HWND wnd,
                              LONG idObj, LONG idChild, DWORD tid, DWORD time) {
    printf("[*] EXE callback: event=0x%lX hwnd=%p pid=%lu\n",
           static_cast<unsigned long>(ev), (void*)wnd, GetCurrentProcessId());
    fflush(stdout);
}

int wmain(int argc, wchar_t** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    int mode = (argc > 1) ? _wtoi(argv[1]) : 1;

    if (mode == 1) {
        HWINEVENTHOOK h = SetWinEventHook(
            EVENT_OBJECT_SHOW, EVENT_OBJECT_SHOW,
            nullptr, exe_proc, 0, 0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
        printf("outofcontext hook=%p err=%lu\n", h, GetLastError());
        if (!h) return 1;
        printf("[+] installed - start a target now\n");
        // An out-of-context callback is dispatched through the *installing*
        // process's message queue: without a pump here the callback is never
        // delivered and the probe measures nothing.
        MSG msg;
        DWORD end = GetTickCount() + 30000;
        while (GetTickCount() < end) {
            while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageA(&msg);
            }
            Sleep(20);
        }
        UnhookWinEvent(h);
        return 0;
    }

    if (mode == 3) {
        // The widest possible range: if *any* event arrives, the hook works
        // and the problem is the event choice; if none arrives, the hook
        // itself is not wired up.
        HWINEVENTHOOK h = SetWinEventHook(
            0x00000001, 0x7FFFFFFF,
            nullptr, exe_proc, 0, 0,
            WINEVENT_OUTOFCONTEXT);
        printf("all-events hook=%p err=%lu\n", h, GetLastError());
        if (!h) return 1;
        printf("[+] installed - start a target now\n");
        Sleep(30000);
        UnhookWinEvent(h);
        return 0;
    }

    wchar_t dll[MAX_PATH] = L"C:\\dev\\fortesp\\out\\FortHook.dll";
    if (argc > 2) lstrcpynW(dll, argv[2], MAX_PATH);
    HMODULE d = LoadLibraryW(dll);
    if (!d) { printf("[!] dll %ls err=%lu\n", dll, GetLastError()); return 1; }
    auto proc = reinterpret_cast<WINEVENTPROC>(GetProcAddress(d, "WinEventProc"));
    printf("dll %p WinEventProc %p\n", d, reinterpret_cast<void*>(proc));
    if (!proc) return 1;

    HWINEVENTHOOK h = SetWinEventHook(
        EVENT_OBJECT_SHOW, EVENT_OBJECT_SHOW,
        d, proc, 0, 0, 0);
    printf("incontext hook=%p err=%lu\n", h, GetLastError());
    if (!h) return 1;
    printf("[+] installed - start a target now\n");
    Sleep(30000);
    UnhookWinEvent(h);
    return 0;
}
