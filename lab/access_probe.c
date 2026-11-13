// Read the client's protection level - the field that explains the mask.
//
// The mask (0x11F145), the refusal of SetSecurityInfo (ERROR_ACCESS_DENIED) from
// the object's own owner, and the identical treatment of SYSTEM and an elevated
// admin all point at one thing: the process is a protected process light (PPL)
// and the anti-cheat's certificate is the only signer the kernel accepts. That
// is a field, not a guess, and this tool prints it.
//
// Build: gcc -DWIN64 -O2 lab/access_probe.c -o out/access_probe.exe
#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <stdio.h>

typedef LONG NTSTATUS;
typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } UNI_STRING;
typedef NTSTATUS(NTAPI* NtQSI)(ULONG, void*, ULONG, ULONG*);

static DWORD find(const wchar_t* want) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    DWORD hit = 0;
    if (Process32FirstW(snap, &pe)) do {
        if (wcsstr(pe.szExeFile, want)) hit = pe.th32ProcessID;
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return hit;
}

// SYSTEM_PROCESS_INFORMATION on x64: NextEntryOffset +0, NumberOfThreads +4,
// WorkingSetPrivateSize +8, ... ImageName (UNICODE_STRING) +0x38, ..., and the
// protection fields sit at +0x6A/+0x6B right before InheritedFromUniqueProcessId.
static void dump_protection(const wchar_t* want) {
    auto qsi = (NtQSI)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    ULONG len = 1 << 20, ret = 0;
    void* buf = malloc(len);
    NTSTATUS st = qsi(5, buf, len, &ret);
    if (st == (NTSTATUS)0xC0000004) { len = ret + 0x20000; buf = realloc(buf, len); st = qsi(5, buf, len, &ret); }
    if (st < 0) { printf("qsi failed 0x%08lX\n", (unsigned)st); free(buf); return; }

    const unsigned char* p = (const unsigned char*)buf;
    for (int guard = 0; guard < 200000; ++guard) {
        DWORD next = *(const DWORD*)(p + 0);
        DWORD pid  = *(const DWORD*)(p + 0x50);
        const UNI_STRING* nm = (const UNI_STRING*)(p + 0x38);
        unsigned char level = p[0x6A], type = p[0x6B];
        if (nm->Buffer && nm->Length && wcsstr(nm->Buffer, want)) {
            DWORD ppid = *(const DWORD*)(p + 0x60);
            printf("%-46ls pid=%-6lu ppid=%-6lu protection level=0x%02X type=0x%02X\n",
                   nm->Buffer, (unsigned long)pid, (unsigned long)ppid, level, type);
        }
        if (!next) break;
        p += next;
    }
    free(buf);
}

int main(void) {
    dump_protection(L"Fortnite");
    dump_protection(L"EasyAntiCheat");
    dump_protection(L"FortniteClient-Win64-Shipping_EAC_EOS");
    printf("\nlegend: level 0x00 none, 0x01 light, 0x21 light (signer=windows),\n"
           "        0x31 light (signer=win-tcb), 0x32 light (signer=antimalware),\n"
           "        0x41/0x51 protection 0x61/0x71 PPL (signer=antimalware/unknown)\n");

    DWORD pid = find(L"FortniteClient-Win64-Shipping.exe");
    if (!pid) { printf("client not running\n"); return 0; }
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    printf("\nOpenProcess(QUERY_LIMITED_INFORMATION) = %p err=%lu\n", h, GetLastError());
    if (h) {
        HANDLE tok = NULL;
        if (OpenProcessToken(h, TOKEN_QUERY, &tok)) {
            DWORD sz = 0;
            if (GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &sz)) {}
            TOKEN_MANDATORY_LABEL* tl = (TOKEN_MANDATORY_LABEL*)malloc(sz + 0x100);
            if (GetTokenInformation(tok, TokenIntegrityLevel, tl, sz + 0x100, &sz)) {
                LPWSTR s = NULL;
                ConvertSidToStringSidW(tl->Label.Sid, &s);
                printf("client integrity sid %ls\n", s);
                LocalFree(s);
            }
            free(tl);
            CloseHandle(tok);
        }
        CloseHandle(h);
    }
    return 0;
}
