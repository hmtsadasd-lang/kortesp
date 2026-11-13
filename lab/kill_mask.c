/* Terminates a process through a handle that only carries the masked mask.
 *
 * The mock game replaces its own DACL with one that grants exactly
 * 0x11F145, so taskkill (which asks for PROCESS_QUERY_INFORMATION as well)
 * is refused - "access denied". PROCESS_TERMINATE is still allowed, which
 * is exactly the point: a masked process can be killed, it just cannot be
 * inspected.
 *
 * Build:  gcc -O2 -o kill_mask.exe kill_mask.c
 * Usage:  kill_mask.exe <image-name>
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#define ALLOWED_MASK 0x11F145

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("usage: kill_mask <image-name>\n");
        return 2;
    }

    wchar_t name[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, name, MAX_PATH);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 1;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    int killed = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) != 0) continue;

            HANDLE h = OpenProcess(ALLOWED_MASK, FALSE, pe.th32ProcessID);
            if (!h) {
                printf("open failed err=%lu\n", GetLastError());
                continue;
            }
            printf("opened pid %lu with 0x%08lX, terminating\n",
                   pe.th32ProcessID, (unsigned long)ALLOWED_MASK);
            if (TerminateProcess(h, 0)) killed++;
            CloseHandle(h);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    printf("killed=%d\n", killed);
    return killed ? 0 : 1;
}
