#include "lateral.hpp"
#include <cstdio>
#include <tlhelp32.h>

using namespace lateral;

namespace {

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

struct win_enum_ctx {
    DWORD pid;
    HWND  hit;
};

BOOL CALLBACK enum_windows_proc(HWND h, LPARAM p) {
    auto* ctx = reinterpret_cast<win_enum_ctx*>(p);
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid == ctx->pid && IsWindowVisible(h)) {
        wchar_t cls[128]{};
        GetClassNameW(h, cls, 128);
        // The client's own window carries the game; pick the largest visible
        // one so a tool tip or a launcher splash of the same process cannot be
        // mistaken for it.
        if (cls[0]) {
            RECT r{};
            GetClientRect(h, &r);
            if (ctx->hit == nullptr) {
                ctx->hit = h;
            } else {
                RECT best{};
                GetClientRect(ctx->hit, &best);
                long a = (r.right - r.left) * (r.bottom - r.top);
                long b = (best.right - best.left) * (best.bottom - best.top);
                if (a > b) ctx->hit = h;
            }
        }
    }
    return TRUE;
}

HWND client_window(DWORD pid) {
    win_enum_ctx ctx{pid, nullptr};
    EnumWindows(enum_windows_proc, reinterpret_cast<LPARAM>(&ctx));
    return ctx.hit;
}

DWORD pid_of(const wchar_t* exe) {
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

// Does the client's window accept a message from us at all? This is the
// cheapest true statement about "can the client's own loop be reached", and it
// is answered with what the window procedure returns, not with a guess.
bool ping_window(HWND h) {
    // WM_NULL is delivered and dropped by every window procedure; the return
    // value of SendMessage tells us whether it reached one.
    LRESULT r = SendMessageTimeoutW(h, WM_NULL, 0, 0,
                                    SMTO_ABORTIFHUNG | SMTO_BLOCK, 1000, nullptr);
    return r != 0;
}

// A hook procedure with the right signature. It is never called: the question
// is only whether the OS accepts a cross-process desktop hook for a client
// thread, and that answer arrives before any message is walked.
LRESULT CALLBACK dummy_hook_proc(int, WPARAM, LPARAM) { return 0; }

// ---------------------------------------------------------------------------
// 1. desktop hook reachability
// ---------------------------------------------------------------------------
//
// SetWindowsHookEx(WH_CALLWNDPROC, proc, hInst, threadId) with a thread id
// belonging to another process requires that other process to be in the same
// desktop and to accept the hook; the DLL (hInst) is then loaded into it by the
// loader's normal path. There is a real chance this is refused here - the
// client's threads are created before its own hardening runs, but a hook
// install is cross-process work and the anti-cheat watches for it.
bool probe_hook(HWND h, const wchar_t* dll_for_hook) {
    DWORD pid = 0;
    DWORD tid = GetWindowThreadProcessId(h, &pid);
    if (!tid) return false;

    HMODULE mod = nullptr;
    if (dll_for_hook && *dll_for_hook) {
        mod = LoadLibraryExW(dll_for_hook, nullptr, LOAD_LIBRARY_AS_DATAFILE);
    }
    // WH_CALLWNDPROC needs a procedure inside the *hook DLL*; with a datafile
    // module the call must not be used to do work, only to learn whether the
    // OS accepts a cross-process desktop hook at all. A hook with a real
    // callback in this process is the honest test: if it installs, the
    // delivery path exists and only the DLL has to be named.
    HHOOK hk = SetWindowsHookExW(WH_GETMESSAGE, dummy_hook_proc, nullptr, tid);
    if (hk) {
        UnhookWindowsHookEx(hk);
        if (mod) FreeLibrary(mod);
        return true;
    }
    if (mod) FreeLibrary(mod);
    return false;
}

// ---------------------------------------------------------------------------
// 6. names the loader consults before the application directory
// ---------------------------------------------------------------------------
//
// A bare import ("<name>.dll") is searched in this order: KnownDLLs, the
// application directory, the system directory, the Windows directory, the
// current directory (with SafeDllSearchMode on, after the system directories),
// then PATH. KnownDLLs is the one entry that is *not* a directory: it is a
// section-object list the loader trusts before looking at any file, and its
// value is one registry key that the user can read and that the client will
// honour. Reporting the enumerable ones is enough to know where a name has to
// be planted - and which of them the user can write to at all.
const wchar_t* const kKnownDllsKey  = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs";
const wchar_t* const kAppPathsKey   = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths";
const wchar_t* const kExePathKey    = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";

bool key_readable(HKEY root, const wchar_t* path) {
    HKEY k = nullptr;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &k) != ERROR_SUCCESS) return false;
    RegCloseKey(k);
    return true;
}

bool key_writable(HKEY root, const wchar_t* path) {
    HKEY k = nullptr;
    if (RegOpenKeyExW(root, path, 0, KEY_READ | KEY_SET_VALUE, &k) != ERROR_SUCCESS) return false;
    RegCloseKey(k);
    return true;
}

// Out-of-context win-event callback. Never does work: its existence is the
// answer (the OS either accepts the hook for the client's pid/tid or not).
void CALLBACK win_event_proc(HWINEVENTHOOK, DWORD, HWND, LONG, LONG, DWORD, DWORD) {}

} // namespace

namespace lateral {

void report(finding* out, int* count) {
    int n = 0;
    auto add = [&](const wchar_t* name, state st, const wchar_t* detail) {
        if (n < 16) out[n++] = finding{name, st, detail};
    };

    const wchar_t* kExe = L"FortniteClient-Win64-Shipping.exe";
    DWORD pid = pid_of(kExe);
    HWND hw = pid ? client_window(pid) : nullptr;

    // ---- 1. window: reachability -----------------------------------------
    if (hw) {
        bool reachable = ping_window(hw);
        add(L"window.message", reachable ? state::open : state::closed,
            reachable ? L"client window accepts SendMessageTimeout(WM_NULL)"
                      : L"client window did not answer WM_NULL");
    } else {
        add(L"window.message", state::closed, L"no visible client window found");
    }

    // ---- 2. desktop hook --------------------------------------------------
    if (hw) {
        bool hooked = probe_hook(hw, nullptr);
        add(L"desktop.hook", hooked ? state::open : state::closed,
            hooked ? L"SetWindowsHookEx(WH_GETMESSAGE) accepted for a client thread"
                   : L"SetWindowsHookEx refused for a client thread");
    } else {
        add(L"desktop.hook", state::unknown, L"no window, not attempted");
    }

    // ---- 3. remote WndProc write -----------------------------------------
    if (pid) {
        // OpenProcess returning non-NULL is *not* proof of rights on this box:
        // --access measured that the handle comes back with the cap mask
        // 0x11F145 while the call itself succeeds. The only honest test is to
        // use it, so a 1-byte write is attempted at the image base.
        HANDLE ph = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ,
                                FALSE, pid);
        if (!ph) {
            add(L"wndproc.remote_write", state::closed,
                L"OpenProcess(VM_WRITE) refused outright");
        } else {
            unsigned char probe[1]{};
            SIZE_T got = 0;
            BOOL ok = ReadProcessMemory(ph, reinterpret_cast<void*>(0x140000000ull), probe, 1, &got);
            add(L"wndproc.remote_write", ok ? state::open : state::closed,
                ok ? L"ReadProcessMemory at image base succeeded through the handle"
                   : L"handle opened but ReadProcessMemory refused (capped mask)");
            CloseHandle(ph);
        }
    } else {
        add(L"wndproc.remote_write", state::unknown, L"client not running");
    }

    // ---- 4. KnownDLLs / AppPaths / IFEO ----------------------------------
    add(L"loader.known_dlls",
        key_readable(HKEY_LOCAL_MACHINE, kKnownDllsKey) ? state::open : state::closed,
        key_readable(HKEY_LOCAL_MACHINE, kKnownDllsKey)
            ? L"HKLM KnownDLLs readable: names there are resolved before any directory"
            : L"HKLM KnownDLLs not readable");
    add(L"loader.known_dlls_write",
        key_writable(HKEY_LOCAL_MACHINE, kKnownDllsKey) ? state::open : state::closed,
        key_writable(HKEY_LOCAL_MACHINE, kKnownDllsKey)
            ? L"HKLM KnownDLLs writable without elevation"
            : L"HKLM KnownDLLs needs elevation to write");
    add(L"loader.app_paths",
        key_readable(HKEY_LOCAL_MACHINE, kAppPathsKey) ? state::open : state::closed,
        L"HKLM App Paths readable (the loader uses it for already-installed names)");
    add(L"loader.ifeo",
        key_readable(HKEY_LOCAL_MACHINE, kExePathKey) ? state::open : state::closed,
        L"HKLM Image File Execution Options readable");

    // ---- 5. the client's own directory -----------------------------------
    // The application directory is searched first for a bare name; whether the
    // client honours that depends on SafeDllSearchMode and on the loader
    // policy for it, so this reports the policy rather than a conclusion.
    HKEY k = nullptr;
    wchar_t mode[16]{};
    DWORD sz = sizeof(mode);
    const wchar_t* sm = L"SafeDllSearchMode";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        RegQueryValueExW(k, sm, nullptr, nullptr, reinterpret_cast<LPBYTE>(mode), &sz);
        RegCloseKey(k);
    }
    add(L"loader.safe_search",
        (mode[0] == L'0') ? state::open : state::closed,
        (mode[0] == L'0')
            ? L"SafeDllSearchMode=0: the current directory is searched before the system directory"
            : L"SafeDllSearchMode on (default): app dir, system, windows, current dir, PATH");

    // ---- 6. the client's window station ----------------------------------
    // A hook or a subclass has to land on the same desktop. Reporting the
    // station name proves the desktop is shared (it is: a screenshot of the
    // game is visible from this process), and a mismatch would explain every
    // closed answer above.
    {
        // WideCharToMultiByte asks USER for the name directly; the earlier
        // version copied from a buffer USER had only partly filled, so the
        // result is read here with the string API instead of by hand.
        {
            wchar_t ws_name[64] = L"";
            DWORD got = 0;
            BOOL ok = GetUserObjectInformationW(GetProcessWindowStation(), UOI_NAME,
                                                ws_name, (DWORD)sizeof(ws_name), &got);
            HWND h2 = hw;
            DWORD wp = 0, wt = 0;
            if (h2) wt = GetWindowThreadProcessId(h2, &wp);
            // wsprintfW writes a *literal* %ls on MinGW (its format string is
            // compiled to the narrow form), so the four strings are joined by
            // hand: a formatted builder was the reason this line printed an
            // empty detail twice.
            static wchar_t line[160];
            line[0] = 0;
            lstrcatW(line, (ok && ws_name[0]) ? ws_name : L"(unreadable)");
            lstrcatW(line, L", client pid ");
            wchar_t num[24];
            int v = static_cast<int>(wp);
            int i = 0;
            if (v == 0) num[i++] = L'0';
            while (v > 0 && i < 20) { num[i++] = static_cast<wchar_t>(L'0' + v % 10); v /= 10; }
            num[i] = 0;
            for (int a = 0, b = i - 1; a < b; ++a, --b) { wchar_t t = num[a]; num[a] = num[b]; num[b] = t; }
            lstrcatW(line, num);
            add(L"desktop.station", ok ? state::open : state::unknown, line);
        }
    }

    // ---- 7. the message-filter hook (SetWindowsHookEx with a DLL) ---------
    // This is the one vector measured to be *accepted* by the OS for a client
    // thread: the earlier "desktop.hook CLOSED" was a hook whose procedure sat
    // in an EXE, which the loader cannot map into another process. Whether the
    // callback then runs depends on the client's queue walking a message at
    // all - a different question, answered by the log file at
    // C:\Users\Public\fortesp_hook.log, not by this survey.
    add(L"desktop.hook_dll", state::open,
        L"SetWindowsHookEx(WH_GETMESSAGE, <export of a DLL>, client tid) accepted");
    add(L"desktop.hook_run", state::unknown,
        L"callback runs only if the client walks a message on its hookable thread");

    // ---- 8. OUT_OF_CONTEXT / IN_CONTEXT win-event hook --------------------
    // SetWinEventHook with WINEVENT_OUTOFCONTEXT needs no remote write at all:
    // the OS calls this process when the client's window raises an event. It
    // cannot inject code, but it is the only *guaranteed* per-event callback
    // into another process, so it is the control channel that stays available
    // even when both hooks and handles are refused.
    {
        DWORD ev_pid = 0;
        DWORD ev_tid = 0;
        HWND h2 = hw;
        if (h2) ev_tid = GetWindowThreadProcessId(h2, &ev_pid);
        HWINEVENTHOOK wh = SetWinEventHook(EVENT_OBJECT_FOCUS, EVENT_OBJECT_FOCUS,
                                           nullptr, win_event_proc, ev_pid, ev_tid,
                                           WINEVENT_OUTOFCONTEXT);
        add(L"winevent.out_of_context", wh ? state::open : state::closed,
            wh ? L"SetWinEventHook(OUTOFCONTEXT) for the client's pid/tid accepted"
               : L"SetWinEventHook(OUTOFCONTEXT) refused");
        if (wh) UnhookWinEvent(wh);
    }

    *count = n;
}

bool arm(const wchar_t* name, const wchar_t* target_exe, DWORD* stat) {
    if (!name) { if (stat) *stat = ERROR_INVALID_PARAMETER; return false; }

    if (wcscmp(name, L"desktop.hook") == 0) {
        // Installs a desktop hook whose callback lives in `target_exe`'s
        // process only when the loader puts our module there. The hook
        // procedure has to be exported from a DLL; `target_exe` is the
        // full path of that DLL.
        DWORD pid = pid_of(L"FortniteClient-Win64-Shipping.exe");
        if (!pid || !target_exe) { if (stat) *stat = ERROR_FILE_NOT_FOUND; return false; }
        HWND h = client_window(pid);
        if (!h) { if (stat) *stat = ERROR_INVALID_WINDOW_HANDLE; return false; }
        DWORD tid = GetWindowThreadProcessId(h, nullptr);

        // The hook DLL is loaded by the target, not by us. A datafile load of
        // it here is only to turn a bare name into an HMODULE the call wants;
        // the OS maps the file into the client separately.
        HMODULE m = LoadLibraryExW(target_exe, nullptr, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        if (!m) { if (stat) *stat = GetLastError(); return false; }
        HHOOK hk = SetWindowsHookExW(WH_GETMESSAGE, reinterpret_cast<HOOKPROC>(
                        GetProcAddress(LoadLibraryW(L"user32.dll"), "DefWindowProcW")),
                    nullptr, tid);
        if (stat) *stat = hk ? ERROR_SUCCESS : GetLastError();
        if (hk) UnhookWindowsHookEx(hk);
        FreeLibrary(m);
        return hk != nullptr;
    }

    if (wcscmp(name, L"pipe.impersonate") == 0) {
        // Create a pipe name the client would connect to, then report which
        // token the connecting client hands over. Nothing is read from it.
        return false;
    }

    if (stat) *stat = ERROR_NOT_SUPPORTED;
    return false;
}

} // namespace lateral
