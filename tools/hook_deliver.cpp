// Desktop-hook delivery: the one file-loaded vector left in user mode.
//
// Facts this file is built on (all measured, docs/SESSION_NOTES.md):
//   * this process and the client share WinSta0\Default (station_probe.exe);
//   * the client's window answers SendMessageTimeout (loader --lateral);
//   * a cross-thread SetWindowsHookEx from this process is refused, and the
//     reason has to be found - not assumed - before the method is declared
//     dead: an empty HOOKPROC inside a *DLL file* is what a working hook needs,
//     and the earlier test used a callback in an EXE, which cannot be mapped
//     into the target at all.
//
// Method 1 (hook with a real DLL):
//   FortHook.dll exports HookProc; SetWindowsHookExW(WH_GETMESSAGE, ..., hDll,
//   client_tid) makes the client's loader map FortHook.dll *by file* - a real,
//   file-backed module - and call HookProc on its own thread. HookProc then
//   maps the payload from the client's own address space with the mapper the
//   rest of this project already uses (no handle, no remote call).
//
// Method 2 (hook without a DLL of ours):
//   The same call with hMod == nullptr is refused by the OS by design; it is
//   measured once so the difference between "the OS refuses this at all" and
//   "the OS refuses this without a module" is on record.
//
// Method 3 (thread-level fallback):
//   SetWindowsHookEx(WH_CALLWNDPROC) on the *process-wide* desktop, installed
//   before the client's own thread exists, is the shape a launcher uses. It
//   cannot be tested from a process that starts after the client, and this
//   file says so instead of pretending otherwise.
#include <windows.h>
#include <cstdio>
#include <tlhelp32.h>
#include "../../shared/include/map_host.hpp"

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

struct ctx {
    DWORD pid;
    HWND  win;
};

static BOOL CALLBACK find_win(HWND w, LPARAM p) {
    auto* c = reinterpret_cast<ctx*>(p);
    DWORD pid = 0;
    GetWindowThreadProcessId(w, &pid);
    if (pid != c->pid) return TRUE;
    wchar_t cls[128]{};
    GetClassNameW(w, cls, 128);
    if (wcscmp(cls, L"UnrealWindow") == 0) { c->win = w; return FALSE; }
    if (IsWindowVisible(w) && !c->win) c->win = w;
    return TRUE;
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

// A callback in this EXE, used only for the "no module" control case: the OS
// refuses it, which is the point of measuring it.
static LRESULT CALLBACK exe_hook_proc(int, WPARAM, LPARAM) { return 0; }

int wmain(int argc, wchar_t** argv) {
    // The DLL is this same file's sibling; the caller may name another.
    wchar_t dll[MAX_PATH] = L"";
    if (argc > 1) lstrcpynW(dll, argv[1], MAX_PATH);
    else {
        GetModuleFileNameW(nullptr, dll, MAX_PATH);
        wchar_t* s = wcsrchr(dll, L'\\');
        if (s) { *s = 0; lstrcatW(dll, L"\\FortHook.dll"); }
    }

    DWORD pid = pid_of(L"FortniteClient-Win64-Shipping.exe");
    printf("client pid %lu\n", static_cast<unsigned long>(pid));
    printf("hook dll  %ls\n", dll);
    if (!pid) return 1;

    ctx c{pid, nullptr};
    EnumWindows(find_win, reinterpret_cast<LPARAM>(&c));
    if (!c.win) { printf("no client window\n"); return 1; }
    DWORD tid = GetWindowThreadProcessId(c.win, nullptr);
    printf("window %p tid %lu\n", c.win, static_cast<unsigned long>(tid));

    // ---- 2. control: no module at all -------------------------------------
    HHOOK k0 = SetWindowsHookExW(WH_GETMESSAGE, exe_hook_proc, nullptr, tid);
    DWORD e0 = GetLastError();
    printf("method 2 (no module):       hook=%p err=%lu\n", k0, e0);
    if (k0) UnhookWindowsHookEx(k0);

    // ---- 1. a real DLL ----------------------------------------------------
    // The module handle has to be the DLL itself (the loader maps it into the
    // target and calls *the address inside that file*), and the callback has
    // to be the address in that same loaded copy - so the DLL is loaded for
    // real in this process, and the address is taken from it.
    HMODULE d = LoadLibraryW(dll);
    if (!d) {
        printf("[!] hook dll not loadable: err=%lu\n", GetLastError());
        return 1;
    }
    HOOKPROC proc = reinterpret_cast<HOOKPROC>(GetProcAddress(d, "HookProc"));
    printf("dll %p HookProc %p\n", d, reinterpret_cast<void*>(proc));
    HHOOK k1 = proc ? SetWindowsHookExW(WH_GETMESSAGE, proc, d, tid) : nullptr;
    DWORD e1 = GetLastError();
    printf("method 1 (dll):             hook=%p err=%lu\n", k1, e1);

    if (k1) {
        printf("[+] hook installed - posting a message to the client's window\n");
        // The pinger lives in the hook DLL and is started *before* the
        // delivering process exits: a thread here would die with the EXE,
        // leaving the client walking messages with nothing to run.
        {
            using Ping = void(__stdcall*)(HWND);
            auto ping = reinterpret_cast<Ping>(GetProcAddress(d, "StartPinger"));
            printf("pinger export %p\n", reinterpret_cast<void*>(ping));
            if (ping) ping(c.win);
        }

        // A hook only runs when the target thread walks a message. The client
        // has been up for minutes and may be idle, so the message is supplied
        // here: WM_NULL is dropped by every window procedure and exists for
        // exactly this purpose. Without this the hook installs and nobody
        // ever calls it.
        for (int i = 0; i < 12; ++i) {
            // SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE|SWP_NOOWNERZORDER
            // on a 1x1 rect: a no-op in geometry, but it makes the window
            // manager send messages to the window, which is what walks a
            // queue that is otherwise idle.
            SetWindowPos(c.win, nullptr, 0, 0, 0, 0,
                         0x0002 | 0x0001 | 0x0004 | 0x0010 | 0x0200);
            PostMessageW(c.win, WM_NULL, 0, 0);
            Sleep(600);
        }
        Sleep(6000);
        UnhookWindowsHookEx(k1);
        FreeLibrary(d);
        printf("[*] hook removed\n");
    } else {
        printf("[!] refused: err=%lu - see docs/HOOK_DELIVERY.md for the cause list\n", e1);
    }
    printf("log: %ls\n", g_log);
    return 0;
}
