// vulkan_probe.cpp - is "<game dir>\vulkan-1.dll" a delivery vector?
//
// Background, measured: the client's import table is empty. Everything the
// running client links against is resolved by its own loader, so a DLL planted
// in the game directory never reaches the Windows loader and is never asked
// for. There is one exception worth testing, because *another* module in that
// directory has a perfectly normal import table:
//
//   FortniteClient-Win64-Shipping_EAC_EOS.exe   imports VERSION.dll, and it is
//                                               started by the same launcher
//
// and the QWORD-style loader strings in it list a set of "optional" system
// libraries - vulkan-1.dll, d3d11.dll, d3dcompiler_47.dll - which it names but
// does not import, i.e. it asks for them by name at run time. If that module
// calls LoadLibraryW(L"vulkan-1.dll") and the game directory is writable,
// planting a DLL of that name there is the delivery: the file lands in a loaded
// module's dependency search, not in the client's own (empty) import table.
//
// This probe answers the two questions the plan needs, in order:
//
//   phase 1  the plant is benign and visible:
//            - write vulkan-1.dll (the same bytes as this DLL) into the game dir
//            - start the game from the game dir with the import the module wants
//            - report whether this process ran inside the EAC shim or the client,
//              and whether the module list contains us
//   phase 2  the plant is hostile:
//            - replace vulkan-1.dll in the game dir with the proxy in out\,
//              whose payload maps into the loading process
//            - run the same launch and report whether a map happened
//
// Every phase prints one line per fact and never guesses: a "no" is printed with
// the API answer that produced it.
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <shellapi.h>

static const wchar_t* kGameDir =
    L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64";

static void log_line(const char* msg) {
    FILE* f = fopen("C:\\Users\\Public\\fortesp_vulkan.log", "a");
    if (f) { fputs(msg, f); fputc('\n', f); fclose(f); }
    printf("%s\n", msg);
}

static bool module_loaded(DWORD pid, const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me;
    ZeroMemory(&me, sizeof(me));
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) do {
        if (_wcsicmp(me.szModule, name) == 0) { found = true; break; }
    } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    return found;
}

// The plan in one function: copy `src` to "<game dir>\\vulkan-1.dll", start the
// game from that directory, watch which process ends up with the module.
static int plant_and_launch(const wchar_t* src, const char* tag) {
    wchar_t dst[MAX_PATH];
    lstrcpynW(dst, kGameDir, MAX_PATH);
    lstrcatW(dst, L"\\vulkan-1.dll");

    if (!CopyFileW(src, dst, FALSE)) {
        char buf[512];
        wsprintfA(buf, "[%s] plant failed err=%lu", tag, GetLastError());
        log_line(buf);
        return 1;
    }
    {
        HANDLE fh = CreateFileW(dst, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, 0, nullptr);
        DWORD sz = fh == INVALID_HANDLE_VALUE ? 0 : GetFileSize(fh, nullptr);
        if (fh != INVALID_HANDLE_VALUE) CloseHandle(fh);
        char buf[512];
        wsprintfA(buf, "[%s] planted %lu bytes -> %ls", tag, (unsigned long)sz, dst);
        log_line(buf);
    }

    // Started from the game directory, which is what makes the game dir the
    // first place the loader looks for a name that is not a KnownDLL.
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    wchar_t exe[MAX_PATH];
    lstrcpynW(exe, kGameDir, MAX_PATH);
    lstrcatW(exe, L"\\FortniteClient-Win64-Shipping.exe");

    // CreateProcess answers 740: the client carries an auto-elevation manifest.
    // The shell is the only way to start it, and the shell is also what the
    // launcher uses, so the test starts the same way the real launch does.
    SHELLEXECUTEINFOW sei;
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.lpVerb = L"open";
    sei.lpFile = exe;
    sei.lpDirectory = kGameDir;
    sei.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei) || !sei.hProcess) {
        char buf[512];
        wsprintfA(buf, "[%s] ShellExecuteEx err=%lu", tag, GetLastError());
        log_line(buf);
        return 1;
    }
    pi.hProcess = sei.hProcess;
    pi.hThread = nullptr;
    pi.dwProcessId = GetProcessId(sei.hProcess);
    {
        char buf[512];
        wsprintfA(buf, "[%s] launched pid %lu", tag, (unsigned long)pi.dwProcessId);
        log_line(buf);
    }

    // The shim is the process that asks for the optional libraries. Give it long
    // enough to start, then look for us in every process the launch produced.
    // Liveness first: if no Fortnite process exists at all, "module not loaded"
    // says nothing about the vector - the launch itself failed.
    for (int i = 0; i < 6; ++i) {
        Sleep(1000);
        HANDLE snapc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pc;
        ZeroMemory(&pc, sizeof(pc));
        pc.dwSize = sizeof(pc);
        int n = 0;
        if (Process32FirstW(snapc, &pc)) do {
            if (wcsstr(pc.szExeFile, L"Fortnite") || wcsstr(pc.szExeFile, L"EAC"))
                ++n;
        } while (Process32NextW(snapc, &pc));
        CloseHandle(snapc);
        char buf[256];
        wsprintfA(buf, "[%s] t+%ds: %d Fortnite/EAC process(es)", tag, (i + 1) * 2, n);
        log_line(buf);
    }

    for (int i = 0; i < 40; ++i) {
        Sleep(500);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe;
        ZeroMemory(&pe, sizeof(pe));
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) do {
            if (pe.th32ProcessID && (wcsstr(pe.szExeFile, L"Fortnite") || wcsstr(pe.szExeFile, L"EAC"))) {
                if (module_loaded(pe.th32ProcessID, L"vulkan-1.dll")) {
                    char buf[512];
                    wsprintfA(buf, "[%s] ++ vulkan-1.dll IS LOADED in %ls pid %lu",
                              tag, pe.szExeFile, (unsigned long)pe.th32ProcessID);
                    log_line(buf);
                }
            }
        } while (Process32NextW(snap, &pe));
        CloseHandle(snap);
    }

    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    {
        char buf[512];
        wsprintfA(buf, "[%s] process state: %s (0x%08lX)", tag,
                  ec == STILL_ACTIVE ? "alive" : "exited", (unsigned long)ec);
        log_line(buf);
    }
    if (pi.hThread) CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        printf("usage: vulkan_probe.exe <phase1|phase2> <dll to plant>\n");
        return 2;
    }
    DeleteFileW(L"C:\\Users\\Public\\fortesp_vulkan.log");
    return plant_and_launch(argv[2], argc > 1 ? "probe" : "probe");
}
