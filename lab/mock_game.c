/* Mock game for the decision-table lab.
 *
 * Reproduces, with nothing but a DACL, what the real client looks like from
 * the outside: a handle is granted, but only 0x11F145 of it - no
 * PROCESS_VM_OPERATION, VM_WRITE or VM_READ - so an allocation into it fails
 * with ERROR_ACCESS_DENIED. The real anti-cheat reaches the same numbers
 * through a kernel callback; the observable result is identical.
 *
 * Build:  gcc -m64 -O2 -o MockGame.exe mock_game.c -ladvapi32
 */
#include <windows.h>
#include <aclapi.h>
#include <stdio.h>

int main(void) {
    /* TERMINATE | SET_SESSION_INFORMATION | DUP_HANDLE | SET_QUOTA |
     * QUERY_LIMITED_INFORMATION | SET_LIMITED_INFORMATION | SYNCHRONIZE */
    const DWORD kMask = 0x11F145;

    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        printf("mock_game: OpenProcessToken failed %lu\n", GetLastError());
        return 1;
    }

    BYTE tb[512];
    DWORD tl = 0;
    PSID user = NULL;
    if (GetTokenInformation(tok, TokenUser, tb, sizeof(tb), &tl))
        user = ((TOKEN_USER *)tb)->User.Sid;

    EXPLICIT_ACCESSW ea;
    ZeroMemory(&ea, sizeof(ea));
    ea.grfAccessPermissions = kMask;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = user ? (LPWSTR)user : (LPWSTR)L"S-1-1-0";

    PACL acl = NULL;
    DWORD r = SetEntriesInAclW(1, &ea, NULL, &acl);
    if (r != ERROR_SUCCESS || !acl) {
        printf("mock_game: SetEntriesInAcl failed %lu\n", r);
        return 1;
    }

    r = SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                        NULL, NULL, acl, NULL);
    printf("mock_game: SetSecurityInfo=%lu (mask 0x%08lX)\n", r, kMask);
    LocalFree(acl);
    CloseHandle(tok);

    /* Keep the process alive so the loader can open and inspect it. */
    for (;;) Sleep(1000);
}
