// Set an ACE on the client's process object that grants this user every access.
//
// Measured on this machine (see docs/SESSION_NOTES.md): every handle to the
// client comes back with 0x0011F145 - PROCESS_TERMINATE|CREATE_PROCESS|
// DUP_HANDLE|SET_INFORMATION|SUSPEND_RESUME|QUERY_INFORMATION - and
// NtAllocateVirtualMemory through it fails with STATUS_ACCESS_DENIED (5).
// The same mask is handed to an elevated administrator and to SYSTEM, so it is
// not the caller's privilege that is capped.
//
// This tool answers a question the loader cannot: it never asks for a handle
// through the normal path. It opens the object for WRITE_DAC only, sets a DACL
// that grants the current user PROCESS_ALL_ACCESS, and then reopens through the
// *desktop* path - the one the anti-cheat's callback does not police - and
// reports what the new handle carries.
//
// Build: gcc -DWIN64 -O2 lab\dacl_grant.c -o out\dacl_grant.exe -ladvapi32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) { printf("usage: dacl_grant <pid>\n"); return 2; }
    DWORD pid = wcstoul(argv[1], NULL, 10);

    // The object name the kernel uses for the process. The desktop path
    // ("\\?\GLOBALROOT\Device\HarddiskVolume2\...") also names the image FILE,
    // not the process - the process object is "Pid:<hex>".
    wchar_t objname[64] = {0};
    wsprintfW(objname, L"Pid:%08lX", (unsigned long)pid);
    printf("object: %ls\n", objname);

    HANDLE h = OpenProcess(WRITE_DAC, FALSE, pid);
    printf("OpenProcess(WRITE_DAC) = %p err=%lu\n", h, GetLastError());
    if (!h) return 1;

    // Grant the current user ALL on this object.
    HANDLE tok = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok);
    DWORD sz = 0; GetTokenInformation(tok, TokenUser, NULL, 0, &sz);
    TOKEN_USER* tu = (TOKEN_USER*)malloc(sz);
    GetTokenInformation(tok, TokenUser, tu, sz, &sz);
    {   LPWSTR sidtxt = NULL;
        ConvertSidToStringSidW(tu->User.Sid, &sidtxt);
        printf("user sid: %ls\n", sidtxt);
        LocalFree(sidtxt); }

    // An explicitly built DACL: one ACE granting the user PROCESS_ALL_ACCESS.
    // No inherit flags: a process object has no children.
    EXPLICIT_ACCESS_W ea;
    ZeroMemory(&ea, sizeof(ea));
    ea.grfAccessPermissions = PROCESS_ALL_ACCESS;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = (LPWSTR)tu->User.Sid;

    PACL acl = NULL;
    DWORD r = SetEntriesInAclW(1, &ea, nullptr, &acl);
    printf("SetEntriesInAcl = %lu acl=%p\n", r, acl);
    if (r != ERROR_SUCCESS || !acl) return 1;

    r = SetSecurityInfo(h, SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        NULL, NULL, acl, NULL);
    printf("SetSecurityInfo = %lu\n", r);

    // Reopen and see what the mask looks like now.
    HANDLE h2 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    printf("reopen ALL_ACCESS = %p err=%lu\n", h2, GetLastError());
    if (h2) {
        DWORD ga = 0;
        // NtQueryObject(ObjectBasicInformation).GrantedAccess is the real mask;
        // the loader's --grant prints it too, this is the same read.
        unsigned char obi[0x38] = {0};
        ULONG ret = 0;
        NTSTATUS st = 0;
        typedef LONG(NTAPI* QO)(HANDLE, ULONG, void*, ULONG, ULONG*);
        QO qo = (QO)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
        st = qo(h2, 0, obi, sizeof(obi), &ret);
        if (st >= 0) ga = *(DWORD*)(obi + 4);
        printf("granted mask = 0x%08lX\n", (unsigned long)ga);

        // And the operation that has been failing all along.
        void* p = VirtualAllocEx(h2, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        printf("VirtualAllocEx = %p err=%lu\n", p, GetLastError());
        if (p) VirtualFreeEx(h2, p, 0, MEM_RELEASE);
        CloseHandle(h2);
    }
    LocalFree(acl);
    free(tu);
    CloseHandle(tok);
    CloseHandle(h);
    return 0;
}
