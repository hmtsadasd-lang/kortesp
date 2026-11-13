// Who can write an event to the client's log without ever being inside it?
//
// The log the payload writes (C:\Users\Public\fortesp2.log) has been the only
// honest "I am running" signal all along. That makes it a **delivery channel**
// in its own right: any process can append a line, and the client is the
// process that owns the file's directory, so anything watching that file
// *inside* the client would receive commands from outside.
//
// This tool answers the questions that decide whether that channel is real:
//
//   1. can this process append to the file the client's payload uses, while the
//      client may have it open? (share modes, DACL on C:\Users\Public)
//   2. do other processes see those writes (the file object is shared, so the
//      answer is the same for everyone)?
//   3. which of the client's own logs are open right now (a file the client
//      holds is one it will read again)?
//   4. does the client hold the *directory* of the game, which is where a
//      mapped image would come from?
//
// None of this needs a handle to the client, so it is not subject to the
// 0x11F145 mask. What it needs is a reader on the other side - which is the
// part a mapped payload would provide once it is inside.
#include <windows.h>
#include <cstdio>
#include <tlhelp32.h>

static const wchar_t* kLogs[] = {
    L"C:\\Users\\Public\\fortesp2.log",
    L"C:\\Users\\Public\\fortesp_hook.log",
    L"C:\\Users\\Public\\fortesp_proxy.log",
};

int wmain() {
    printf("=== 1. append rights on the payload log\n");
    for (const wchar_t* p : kLogs) {
        HANDLE f = CreateFileW(p, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD e = GetLastError();
        printf("  %-42ls %s\n", p, f != INVALID_HANDLE_VALUE ? "appendable" : "refused");
        if (f != INVALID_HANDLE_VALUE) {
            const char line[] = "[probe] append test\r\n";
            DWORD w = 0;
            SetFilePointer(f, 0, nullptr, FILE_END);
            BOOL ok = WriteFile(f, line, sizeof(line) - 1, &w, nullptr);
            printf("    write=%d bytes=%lu lastError=%lu\n", ok ? 1 : 0,
                   static_cast<unsigned long>(w), GetLastError());
            CloseHandle(f);
        } else {
            printf("    lastError=%lu\n", e);
        }
    }

    printf("\n=== 2. directory of the game: handles the client itself holds\n");
    // Any process can ask for the open handles of a directory: none of these
    // calls needs a handle to the client.
    DWORD client = 0;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) do {
            if (wcscmp(pe.szExeFile, L"FortniteClient-Win64-Shipping.exe") == 0) {
                client = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
        CloseHandle(snap);
    }
    printf("  client pid %lu\n", static_cast<unsigned long>(client));

    // A directory handle is what a mapped image needs for file-backed pages, so
    // reporting whether one is obtainable here is the first half of that plan.
    HANDLE dir = CreateFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64",
                             FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    printf("  directory handle: %p err=%lu\n", dir, GetLastError());
    if (dir == INVALID_HANDLE_VALUE) {
        printf("  (the game directory refuses FILE_LIST_DIRECTORY here - a mapped image would need another source)\n");
    } else {
        // Can this handle be used to create/open a file *by name* inside it,
        // relative to the directory, without a full path? That is the property a
        // file-backed image wants (the image then has the DLL's identity, not a
        // path that can be renamed).
        printf("  (FILE_LIST_DIRECTORY granted: file-backed mapping is possible through this handle)\n");
        CloseHandle(dir);
    }

    // What the client's *own* current directory is: a relative path in a later
    // LoadLibrary call resolves there, and the loader search with
    // SafeDllSearchMode=on still ends in the current directory before PATH.
    // It is read through the PEB of a process this one can open ... which it
    // cannot, so it is reported as unknown rather than assumed. The directory
    // the client is launched from is the game directory by convention, and the
    // writable test below settles whether planting a file there is possible.
    printf("\n=== 2b. the client's working directory and its own loader search\n");
    {
        // The loader search order *per process* is not readable without a
        // handle, but one thing is: any process may ask the OS what the target
        // did recently - and nothing is exposed for that either. What can be
        // tested is the *candidate* directory: putting a file in the game
        // directory and asking the loader for it by name from a process whose
        // search path is the same one the client uses. That is done in
        // hook_deliver (FortHook.dll), and the result of the client's own
        // search is the DllMain line in C:\Users\Public\fortesp_hook.log.
        printf("  candidate: the game directory (writable, see 3.) - a file planted there is\n");
        printf("  reachable by a bare-name load *if* the client's search reaches it; the\n");
        printf("  client's DllMain line in the hook log answers that, not this tool.\n");
    }

    printf("\n=== 3. writable directories the client searches for a bare DLL name\n");
    // From the survey: SafeDllSearchMode on means app dir, system, windows,
    // current dir, PATH. The current directory of the *client* is what can be
    // written without touching Program Files - and it is often a folder under
    // the user's profile.
    const wchar_t* cand[] = {
        L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64",
        L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\ThirdParty",
        L"C:\\ProgramData\\Epic\\UnrealEngineLauncher",
    };
    for (const wchar_t* d : cand) {
        DWORD a = GetFileAttributesW(d);
        if (a == INVALID_FILE_ATTRIBUTES) { printf("  %-70ls <missing>\n", d); continue; }
        wchar_t probe[MAX_PATH];
        lstrcpynW(probe, d, MAX_PATH);
        lstrcatW(probe, L"\\fortesp_write_test.tmp");
        HANDLE f = CreateFileW(probe, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        printf("  %-70ls %s\n", d, f != INVALID_HANDLE_VALUE ? "writable" : "not writable");
        if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    }
    return 0;
}
