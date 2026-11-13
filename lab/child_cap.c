// Is a *child* process we created ourselves also handle-capped?
//
// Measured anomaly (docs/DELIVERY_STATUS.md): launching
// FortniteClient-Win64-Shipping.exe with ShellExecuteEx gives a handle we own,
// and `VirtualAllocEx` through it still fails with STATUS_ACCESS_DENIED - the
// same answer the anti-cheat gives to a foreign process. Either the handle is
// carved by the anti-cheat's process-creation callback (which runs for every
// new process, including our children), or something else about this process
// refuses the operation.
//
// This tool separates the two with a control that has the identical code path:
// the same calls, in the same session, against
//   (a) notepad.exe,                 started by us  -> expected: works
//   (b) FortniteClient-...exe,       started by us  -> the question
//   (c) the already-running client   (if any)       -> expected: refused
//
// The launch is the one that matters for the plan of getting in before the
// anti-cheat exists: if (b) works when the launch is fast enough, the window is
// real and only has to be hit earlier; if (b) is refused with a full-rights
// handle, the cap is applied by a callback that knows every process on the box
// and no launch timing will help.
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

static const wchar_t* kClient =
    L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe";

static void try_dir(DWORD pid, const char* tag) {
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    printf("%-10s pid %-6lu OpenProcess(ALL)=%p err=%lu\n", tag, (unsigned long)pid, h, GetLastError());
    if (!h) return;

    // NtQueryObject(ObjectBasicInformation).GrantedAccess is the mask the kernel
    // actually attached, independent of what was asked for.
    struct { ULONG a, b; } basic;
    basic.a = basic.b = 0;
    ULONG ret = 0;
    typedef LONG(NTAPI* QO)(HANDLE, ULONG, void*, ULONG, ULONG*);
    QO qo = (QO)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    if (qo && qo(h, 0, &basic, sizeof(basic), &ret) >= 0)
        printf("%-10s granted mask 0x%08lX\n", tag, basic.b);

    void* p = VirtualAllocEx(h, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD e = GetLastError();
    printf("%-10s VirtualAllocEx=%p err=%lu\n", tag, p, e);
    if (p) VirtualFreeEx(h, p, 0, MEM_RELEASE);

    SIZE_T got = 0;
    unsigned char b = 0;
    BOOL r = ReadProcessMemory(h, (void*)0x400000, &b, 1, &got);
    printf("%-10s ReadProcessMemory=%d err=%lu\n", tag, r, GetLastError());
    CloseHandle(h);
}

int wmain(int argc, wchar_t** argv) {
    int fast = argc > 1 ? _wtoi(argv[1]) : 50;   // ms between launch and OpenProcess

    // (a) control: notepad
    {
        STARTUPINFOW si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(pi));
        if (CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", nullptr, nullptr, nullptr,
                           FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
            CloseHandle(pi.hThread);
            Sleep(200);
            try_dir(pi.dwProcessId, "notepad");
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
        }
    }

    // (b) the client, launched by us through the shell (CreateProcess returns 740)
    SHELLEXECUTEINFOW sei;
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.lpVerb = L"open";
    sei.lpFile = kClient;
    sei.nShow = SW_SHOWNORMAL;
    if (ShellExecuteExW(&sei) && sei.hProcess) {
        DWORD pid = GetProcessId(sei.hProcess);
        printf("client launched, pid %lu, sleeping %d ms before the first call\n",
               (unsigned long)pid, fast);
        Sleep((DWORD)fast);
        try_dir(pid, "child");
        DWORD ec = 0;
        GetExitCodeProcess(sei.hProcess, &ec);
        printf("child state: %s (0x%08lX)\n", ec == STILL_ACTIVE ? "alive" : "exited",
               (unsigned long)ec);
        CloseHandle(sei.hProcess);
    } else {
        printf("ShellExecuteEx failed %lu\n", GetLastError());
    }

    // (c) the already-running client, if the launcher started one
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe;
        ZeroMemory(&pe, sizeof(pe));
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) do {
            if (wcscmp(pe.szExeFile, L"FortniteClient-Win64-Shipping.exe") == 0) {
                if (pe.th32ProcessID != 0) try_dir(pe.th32ProcessID, "existing");
                break;
            }
        } while (Process32NextW(snap, &pe));
        CloseHandle(snap);
    }
    return 0;
}
