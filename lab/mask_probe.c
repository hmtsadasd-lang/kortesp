// Who is capping the client's handle, and with what?
//
// The same mask (0x11F145) comes back to an unelevated user, an administrator
// with SeDebugPrivilege and SYSTEM, and SetSecurityInfo on the process object
// fails with ERROR_ACCESS_DENIED even from the owner - so the deny is not in the
// DACL this process can read. This tool asks the kernel instead:
//
//   1. NtQueryInformationProcess(ProcessMitigationPolicy) for every policy,
//      including the strict-handle-check / redirection-trust bits that a
//      protected process light (PPL) sets and that nobody else can clear;
//   2. the same through NtQuerySystemInformation(SystemProcessInformation) at
//      the protection level field, which is readable for any process;
//   3. whether a second handle to the same object reports the same mask (a
//      DACL deny would be stable, a callback-per-call filter would not).
//
// Build: gcc -DWIN64 -O2 lab/mask_probe.c -o out/mask_probe.exe
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* NtQIP)(HANDLE, ULONG, void*, ULONG, ULONG*);

static NtQIP g_qip;
static NTSTATUS(NTAPI* g_qsi)(ULONG, void*, ULONG, ULONG*);

static void policy(HANDLE h, int idx, const char* name) {
    // PROCESS_MITIGATION_POLICY_INFORMATION { int Policy; union { DWORD Flags; struct; } }
    struct { int Policy; unsigned char Flags[12]; } pm;
    ZeroMemory(&pm, sizeof(pm));
    pm.Policy = idx;
    ULONG ret = 0;
    // 0x34 = 52 is ProcessMitigationPolicy on current builds; older ones use 0x34
    // and the struct is (Policy, Union) with an 8-byte union, so ask for 16 bytes.
    NTSTATUS st = g_qip(h, 38, &pm, sizeof(pm), &ret);   // 38 = ProcessMitigationPolicy here
    if (st < 0) { printf("  %-34s query failed 0x%08lX\n", name, (unsigned)st); return; }
    printf("  %-34s %02X | %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
           name, pm.Flags[0], pm.Flags[1], pm.Flags[2], pm.Flags[3], pm.Flags[4],
           pm.Flags[5], pm.Flags[6], pm.Flags[7], pm.Flags[8], pm.Flags[9],
           pm.Flags[10], pm.Flags[11]);
}

int main(void) {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    g_qip = (NtQIP)GetProcAddress(nt, "NtQueryInformationProcess");
    g_qsi = (NTSTATUS(NTAPI*)(ULONG, void*, ULONG, ULONG*))GetProcAddress(nt, "NtQuerySystemInformation");

    DWORD me = GetCurrentProcessId();
    printf("pid %lu (self) protection:\n", (unsigned long)me);

    // SystemProcessInformation walk: Protection.Level at 0x6A, Type at 0x6B in
    // the 64-bit SYSTEM_PROCESS_INFORMATION.
    ULONG len = 1 << 20, ret = 0;
    void* buf = malloc(len);
    NTSTATUS st = g_qsi(5, buf, len, &ret);
    if (st == 0xC0000004) { len = ret + 0x10000; buf = realloc(buf, len); st = g_qsi(5, buf, len, &ret); }
    if (st < 0) { printf("  qsi failed 0x%08lX\n", (unsigned)st); return 1; }

    unsigned char* p = (unsigned char*)buf;
    for (DWORD i = 0; i < 200000; ++i) {
        DWORD pid = *(DWORD*)(p + 0x50);
        DWORD next = *(DWORD*)(p + 0x58);
        unsigned char level = p[0x6A], type = p[0x6B];
        if (level || type) {
            wchar_t* name = NULL;
            // image name is a UNICODE_STRING in the next process structure; the
            // name for this entry sits at the end of the variable block, so it
            // is only used when it is obviously a pointer.
            printf("  pid %-6lu level=0x%02X type=0x%02X\n", (unsigned long)pid, level, type);
        }
        if (!next) break;
        p += next;
    }
    free(buf);

    DWORD game = 0;
    {
        // find the client by name through Toolhelp
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) do {
            if (wcsstr(pe.szExeFile, L"FortniteClient-Win64-Shipping.exe")) game = pe.th32ProcessID;
        } while (Process32NextW(snap, &pe));
        CloseHandle(snap);
    }
    if (!game) { printf("client not running\n"); return 2; }

    HANDLE h = OpenProcess(0x1FFFFF, FALSE, game);
    printf("\nclient pid %lu handle %p err=%lu\n", (unsigned long)game, h, GetLastError());
    if (!h) return 3;

    printf("mitigation policies (Flags per policy):\n");
    static const char* names[] = {
        "DEP", "ATL_THUNK", "SEHOP", "HEAP_TERMINATE", "BOTTOM_UP_ASLR",
        "HIGH_ENTROPY_ASLR", "STRICT_HANDLE_CHECKS", "WIN32K_SYSTEM_CALL_DISABLE",
        "EXTENSION_POINT_DISABLE", "PROHIBIT_DYNAMIC_CODE", "CONTROL_FLOW_GUARD",
        "BLOCK_NON_MICROSOFT_BINARIES", "FONT_DISABLE", "IMAGE_LOAD_CONFIG",
        "SIGNATURE", "MITIGATION_16", "MITIGATION_17", "MITIGATION_18",
    };
    for (int i = 0; i < 18; ++i) policy(h, i, names[i]);

    // Two handles, same object: a DACL deny is stable, a per-call filter is not.
    unsigned char obi[0x38] = {0};
    ULONG r2 = 0;
    for (int k = 0; k < 3; ++k) {
        HANDLE hk = OpenProcess(0x1FFFFF, FALSE, game);
        unsigned int ga = 0;
        if (hk && g_qip(hk, 0, obi, sizeof(obi), &r2) >= 0) ga = *(DWORD*)(obi + 4);
        printf("handle %d: %p granted 0x%08lX\n", k, hk, ga);
        if (hk) CloseHandle(hk);
    }
    return 0;
}
