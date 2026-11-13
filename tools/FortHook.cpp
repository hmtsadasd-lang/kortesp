// FortHook.dll - the module a desktop hook makes the client load.
//
// This file exists because a hook procedure has to live in a *file* the target
// can map. When the client's message loop walks a message, the loader maps
// this DLL into the client process and calls HookProc on the client's own
// thread. Everything after that happens with the client's own rights: the
// mapper in shared/map_host.cpp runs in-process (GetCurrentProcess()), reads
// payload.dll from the game directory and maps it - no handle to the client is
// ever opened, so the 0x11F145 mask is not in the path at all.
//
// DllMain stays empty on purpose: it runs under the loader lock, and anything
// that touches the filesystem or starts a thread there is what made the
// VERSION.dll experiment fail to load ("failed to load" is the loader's report
// of a DllMain that did not finish, not of a bad export table).
#include <windows.h>
#include <cstdarg>
#include "../../shared/include/map_host.hpp"

static wchar_t g_log[MAX_PATH] = L"C:\\Users\\Public\\fortesp_hook.log";

// Where this DLL last wrote, so a caller can find the file even after the code
// changed its mind about the name.
static void hlog(const char* fmt, ...);

static void hlog(const char* fmt, ...) {
    char buf[512]{};
    va_list a;
    va_start(a, fmt);
    wvsprintfA(buf, fmt, a);
    va_end(a);
    lstrcatA(buf, "\r\n");
    HANDLE f = CreateFileW(g_log, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        // Public is the writable place for a service-like context; when it is
        // not (a restricted token, a redirected profile) the temp directory is
        // the second choice, and the name is the same so the reader does not
        // have to know which one was used.
        wchar_t tmp[MAX_PATH] = L"";
        DWORD n = GetTempPathW(MAX_PATH, tmp);
        if (n && n < MAX_PATH) {
            lstrcpynW(g_log, tmp, MAX_PATH);
            lstrcatW(g_log, L"fortesp_hook.log");
            f = CreateFileW(g_log, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        }
        if (f == INVALID_HANDLE_VALUE) return;
    }
    DWORD w = 0;
    SetFilePointer(f, 0, nullptr, FILE_END);
    WriteFile(f, buf, static_cast<DWORD>(lstrlenA(buf)), &w, nullptr);
    CloseHandle(f);
}

// The work, done once. The hook can be called on every message, so the guard
// matters; it is a word in this DLL's .data and needs no lock because the hook
// chain runs on one thread at a time per message queue.
static volatile long g_mapped = 0;
static wchar_t g_dir[MAX_PATH];

// The pinger: while the hook is installed, this thread posts WM_NULL to the
// client's window once a second. A hook procedure only runs when the target
// thread walks a message, and a client sitting idle walks none - so the
// message has to be supplied. WM_NULL is dropped by every window procedure and
// exists for exactly this purpose.
static HWND g_client_win = nullptr;

// Counts every entry to the hook, whether or not the mapping has started: this
// is the number that says the client's thread reached our module at all.
static volatile long g_calls = 0;

static DWORD WINAPI pinger(LPVOID) {
    hlog("[*] pinger up, target window %p", g_client_win);
    for (int i = 0; i < 40; ++i) {
        // SWP_NOSIZE|SWP_NOMOVE|SWP_NOZORDER|SWP_NOACTIVATE|SWP_NOOWNERZORDER
        SetWindowPos(g_client_win, nullptr, 0, 0, 0, 0,
                     0x0002 | 0x0001 | 0x0004 | 0x0010 | 0x0200);
        PostMessageW(g_client_win, WM_NULL, 0, 0);
        Sleep(1000);
    }
    hlog("[*] pinger done, callbacks=%ld", InterlockedCompareExchange(&g_calls, 0, 0));
    return 0;
}

static DWORD WINAPI map_payload(LPVOID) {
    hlog("[+] FortHook: worker in the client, tid=%lu", GetCurrentThreadId());

    wchar_t path[MAX_PATH] = L"";
    lstrcpynW(path, g_dir, MAX_PATH);
    lstrcatW(path, L"\\payload.dll");
    hlog("[*] payload path: %ls", path);

    size_t size = 0;
    uint8_t* img = nullptr;
    if (!slurp_file(path, &img, &size)) {
        hlog("[!] payload read failed err=%lu", GetLastError());
        return 1;
    }
    hlog("[*] payload %lu bytes", static_cast<unsigned long>(size));

    // In-process map: the mapper treats GetCurrentProcess() as the target, so
    // every import resolves against this process, memory comes from this
    // process's own address space and the entry thread is created by the
    // client itself. No OpenProcess, no WriteProcessMemory, no CreateRemoteThread.
    map_result r{};
    bool ok = manual_map_host(GetCurrentProcess(), img, size, path, "start",
                              /*keep_mapped*/true, &r, 30000, hlog);
    hlog("[%c] map ok=%d exit=0x%08lX", ok ? '+' : '!', ok ? 1 : 0,
         static_cast<unsigned long>(r.exit_code));
    delete[] img;
    return 0;
}

// The exported hook. WH_GETMESSAGE only: the client's loop asks for the next
// message, this runs before it gets one, and the mapping is handed to a thread
// so the hook returns immediately (an inline map would block the message loop
// for the whole mapping, and the client would look hung).
extern "C" __declspec(dllexport) LRESULT CALLBACK HookProc(int code, WPARAM wp, LPARAM lp) {
    InterlockedIncrement(&g_calls);
    if (code >= 0 && InterlockedCompareExchange(&g_mapped, 1, 0) == 0) {
        GetModuleFileNameW(nullptr, g_dir, MAX_PATH);
        wchar_t* s = wcsrchr(g_dir, L'\\');
        if (s) *s = 0;
        hlog("[*] HookProc in pid %lu dir %ls", GetCurrentProcessId(), g_dir);
        CreateThread(nullptr, 0, map_payload, nullptr, 0, nullptr);
    }
    return CallNextHookEx(nullptr, code, wp, lp);
}

// Called from DllMain only. The stand-in driver in EAC's kernel DPC is a DPC
// *timer* and nothing else: nobody has to be inside the process for it to fire.
// `SetWaitableTimerEx` with a null callback class queues an APC to this thread,
// but the timer itself is what has to exist here; a message-loop-free process
// (the client's main thread) can still be reached by it because the entry
// point is the DPC, not a message.
static HANDLE g_timer = nullptr;

static void CALLBACK driver_timer_trampoline(void*, unsigned long, unsigned long) {
    hlog("[*] timer fired in pid %lu tid %lu", GetCurrentProcessId(), GetCurrentThreadId());
}

static bool install_stand_in_driver(HINSTANCE h) {
    // CreateTimerQueueTimer is safe here: it is an ntdll path and allocates no
    // message, so it cannot recurse into the loader.
    g_timer = CreateWaitableTimerExW(nullptr, nullptr, 0, TIMER_ALL_ACCESS);
    if (!g_timer) { hlog("[!] timer create failed %lu", GetLastError()); return false; }
    LARGE_INTEGER due;
    due.QuadPart = -10000000;   // 1 s
    if (!SetWaitableTimerEx(g_timer, &due, 1000, driver_timer_trampoline, nullptr,
                            nullptr, 0)) {
        hlog("[!] timer arm failed %lu", GetLastError());
        return false;
    }
    hlog("[*] timer armed in pid %lu", GetCurrentProcessId());
    return true;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        // One deferred-driver-shaped thing per process: it proves this module
        // runs in a process that never calls a message loop.
        install_stand_in_driver(h);
        // One line per process the module lands in. This is the *only* work in
        // DllMain and it is a file append (no thread, no other module), because
        // the question "did the client load this at all" has to be answerable
        // even when the hook is never called. Without it, "no log" was
        // indistinguishable from "loaded but never called".
        hlog("[*] FortHook DllMain in pid %lu tid %lu", GetCurrentProcessId(), GetCurrentThreadId());
    }
    return TRUE;
}

// Called from the delivering process once the hook is installed. Lives here
// because the thread has to outlive the caller: a thread in the EXE dies with
// the EXE and the client would then walk messages with no hook to run.
extern "C" __declspec(dllexport) void __stdcall StartPinger(HWND target) {
    g_client_win = target;
    CreateThread(nullptr, 0, pinger, nullptr, 0, nullptr);
}
