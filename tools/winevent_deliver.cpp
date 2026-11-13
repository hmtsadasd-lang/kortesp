// Win-event delivery: the door that does not need a message queue.
//
// SetWinEventHook with WINEVENT_INCONTEXT delivers the callback *inside the
// process that raised the event*. The client's own loader maps the callback
// DLL into the client and calls it on the client's thread - so no handle to
// the client is ever opened, and the 0x11F145 mask is not in the path.
//
// The event that fires is EVENT_OBJECT_SHOW: the client raises it when its
// window is created. That means the hook has to be installed *before* the
// client starts, which is why this tool stays alive and waits.
//
//   usage: winevent_deliver.exe [dll] [seconds]
#include <windows.h>
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

int wmain(int argc, wchar_t** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);

    wchar_t dll[MAX_PATH] = L"";
    if (argc > 1) lstrcpynW(dll, argv[1], MAX_PATH);
    else {
        GetModuleFileNameW(nullptr, dll, MAX_PATH);
        wchar_t* s = wcsrchr(dll, L'\\');
        if (s) { *s = 0; lstrcatW(dll, L"\\FortHook.dll"); }
    }
    int seconds = (argc > 2) ? _wtoi(argv[2]) : 120;

    HMODULE d = LoadLibraryW(dll);
    if (!d) {
        printf("[!] hook dll not loadable: %ls err=%lu\n", dll, GetLastError());
        return 1;
    }
    auto proc = reinterpret_cast<WINEVENTPROC>(GetProcAddress(d, "WinEventProc"));
    printf("dll %p WinEventProc %p\n", d, reinterpret_cast<void*>(proc));
    if (!proc) { printf("[!] no WinEventProc export\n"); return 1; }

    // The callback module has to be the DLL itself: the loader maps *that*
    // file into the target and calls the address inside that copy.
    //   SetWinEventHook(eventMin, eventMax, hmod, proc, idProcess, idThread, flags)
    HWINEVENTHOOK h = SetWinEventHook(
        EVENT_OBJECT_SHOW, EVENT_OBJECT_SHOW,   // event range
        d,                                       // the callback module
        proc,
        0,                                       // every process
        0,                                       // every thread
        0);                                      // no flags: INCONTEXT
    DWORD err = GetLastError();
    printf("winevent hook=%p err=%lu (incontext, EVENT_OBJECT_SHOW)\n", h, err);
    if (!h) {
        printf("[!] refused err=%lu\n", err);
        return 1;
    }

    printf("[+] installed - start the client now, this tool waits %d s\n", seconds);
    hlog("[*] winevent deliver: hook=%p dll=%ls", h, dll);

    for (int i = 0; i < seconds; ++i) {
        Sleep(1000);
        if ((i + 1) % 10 == 0) printf("  ... %d s left\n", seconds - i - 1);
    }

    UnhookWinEvent(h);
    printf("[*] hook removed\n");
    return 0;
}
