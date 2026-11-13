/* Thread probes for the WOW64 fallback lab.
 *
 * The loader's --wowprobe creates a thread in the 32 bit host and installs a
 * WOW64 context on it. The kernel answers every context call with
 * STATUS_ACCESS_VIOLATION, which says nothing about why. This helper asks the
 * same questions on the same thread and prints the raw answers, so the
 * rejection can be attributed:
 *
 *   - the handle that NtCreateThreadEx returned, as a 32 bit thread id
 *     (GetThreadId) and as a kernel object (NtQueryObject);
 *   - a local thread created the same way, with the same calls, so a kernel
 *     behaviour can be told apart from a broken handle;
 *   - Wow64GetThreadContext / NtGetContextThread with both context layouts;
 *   - NtQueryInformationThread(ThreadBasicInformation) on both.
 *
 * Build: gcc -m64 -O2 -static -o probe_thread.exe probe_thread.c
 * Usage: probe_thread.exe <pid>
 */
#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;
typedef struct { USHORT Length, MaxLength; PWSTR Buffer; } USTR;

static NTSTATUS (NTAPI *pNtCreateThreadEx)(HANDLE *, ACCESS_MASK, PVOID, HANDLE,
                                           PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
static NTSTATUS (NTAPI *pNtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NTSTATUS (NTAPI *pNtGetContextThread)(HANDLE, PVOID);
static NTSTATUS (NTAPI *pNtSetContextThread)(HANDLE, PVOID);
static NTSTATUS (NTAPI *pNtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static void load(void) {
    HMODULE n = GetModuleHandleW(L"ntdll.dll");
    pNtCreateThreadEx = (void *)GetProcAddress(n, "NtCreateThreadEx");
    pNtQueryInformationThread = (void *)GetProcAddress(n, "NtQueryInformationThread");
    pNtGetContextThread = (void *)GetProcAddress(n, "NtGetContextThread");
    pNtSetContextThread = (void *)GetProcAddress(n, "NtSetContextThread");
    pNtQueryObject = (void *)GetProcAddress(n, "NtQueryObject");
}

/* x86 CONTEXT as the WOW64 APIs take it */
typedef struct {
    DWORD ContextFlags;
    DWORD Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    BYTE  FloatSave[112];
    DWORD SegGs, SegFs, SegEs, SegDs;
    DWORD Edi, Esi, Ebx, Edx, Ecx, Eax;
    DWORD Ebp, Eip, SegCs, EFlags, Esp, SegSs;
    BYTE  ExtendedRegisters[512];
} X86_CONTEXT;

static DWORD __stdcall local_start(void *arg) {
    (void)arg;
    return 0;
}

static void describe(const char *tag, HANDLE th) {
    if (!th) { printf("%s: no thread\n", tag); return; }

    printf("%s: handle=%p GetThreadId=%lu GetThreadId-of-handle-err=%lu\n",
           tag, th, GetThreadId(th), GetLastError());

    /* the kernel object behind the handle: type name and handle count */
    {
        UCHAR buf[1024] = { 0 };
        ULONG need = 0;
        NTSTATUS st = pNtQueryObject(th, 1 /* ObjectTypeInformation */, buf, sizeof(buf), &need);
        if (st >= 0) {
            USTR *u = (USTR *)(buf + 0x60);   /* TypeName inside OBJECT_TYPE_INFORMATION */
            printf("%s: type=%.*ls\n", tag, u->Length / 2, u->Buffer);
        } else {
            printf("%s: NtQueryObject(type) st=0x%08lX\n", tag, (unsigned)st);
        }
        ULONG granted = 0;
        UCHAR bi[64] = { 0 };
        st = pNtQueryObject(th, 0, bi, sizeof(bi), &need);
        if (st >= 0) {
            granted = *(ULONG *)(bi + 4);
            printf("%s: granted=0x%08lX handles=%lu\n", tag, granted, *(ULONG *)(bi + 8));
        } else {
            printf("%s: NtQueryObject(basic) st=0x%08lX\n", tag, (unsigned)st);
        }
    }

    /* ThreadBasicInformation: pid/tid of the thread the handle points at */
    {
        UCHAR tbi[64] = { 0 };
        ULONG need = 0;
        NTSTATUS st = pNtQueryInformationThread(th, 9, tbi, sizeof(tbi), &need);
        if (st >= 0) {
            printf("%s: ThreadBasicInformation exit=0x%08lX prio=%ld pid=%lu tid=%lu teb=%p\n",
                   tag, *(ULONG *)tbi, (long)*(LONG *)(tbi + 4),
                   *(ULONG *)(tbi + 0x20), *(ULONG *)(tbi + 0x24), *(PVOID *)(tbi + 0x28));
        } else {
            printf("%s: ThreadBasicInformation st=0x%08lX\n", tag, (unsigned)st);
        }
    }

    /* both context layouts */
    {
        X86_CONTEXT c32 = { 0 };
        c32.ContextFlags = 0x00010001;
        NTSTATUS st = pNtGetContextThread(th, &c32);
        printf("%s: NtGetContextThread(x86) st=0x%08lX eip=0x%08lX\n",
               tag, (unsigned)st, (unsigned)c32.Eip);
        BOOL ok = Wow64GetThreadContext(th, (WOW64_CONTEXT *)&c32);
        printf("%s: Wow64GetThreadContext=%d err=%lu\n", tag, ok ? 1 : 0, GetLastError());

        UCHAR c64[0x4D0] = { 0 };
        *(DWORD *)c64 = 0x00100001;
        st = pNtGetContextThread(th, c64);
        printf("%s: NtGetContextThread(x64) st=0x%08lX\n", tag, (unsigned)st);

        st = pNtQueryInformationThread(th, 26 /* ThreadWow64Context */, c64, sizeof(c64), NULL);
        printf("%s: ThreadWow64Context st=0x%08lX\n", tag, (unsigned)st);
    }
}

int main(int argc, char **argv) {
    load();
    if (!pNtCreateThreadEx) { printf("no NtCreateThreadEx\n"); return 1; }

    DWORD pid = argc > 1 ? (DWORD)strtoul(argv[1], NULL, 0) : 0;
    if (!pid) { printf("usage: probe_thread <pid>\n"); return 2; }

    /* 1. a local thread: does the same sequence work in this process? */
    {
        HANDLE th = NULL;
        NTSTATUS st = pNtCreateThreadEx(&th, 0x1FFFFF, NULL, GetCurrentProcess(),
                                        (PVOID)local_start, NULL, 2, 0, 0, 0, NULL);
        printf("[local] NtCreateThreadEx st=0x%08lX thread=%p\n", (unsigned)st, th);
        describe("[local]", th);
        if (th) {
            ResumeThread(th);
            WaitForSingleObject(th, 5000);
            CloseHandle(th);
        }
    }

    /* 2. a thread in the 32 bit host, started at its own kernel32!Sleep */
    HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    printf("[host] pid=%lu OpenProcess=%p err=%lu\n", pid, ph, GetLastError());
    if (!ph) return 3;

    /* kernel32 (32 bit) base through the WOW64 PEB is not needed: any low
     * address with an int3 is enough, the thread never has to run. */
    PVOID start = VirtualAllocEx(ph, (PVOID)0x00100000, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
    printf("[host] start=%p err=%lu\n", start, GetLastError());
    if (start) {
        BYTE cc = 0xCC;
        WriteProcessMemory(ph, start, &cc, 1, NULL);

        HANDLE th = NULL;
        NTSTATUS st = pNtCreateThreadEx(&th, 0x1FFFFF, NULL, ph, start, NULL, 2, 0, 0, 0, NULL);
        printf("[host] NtCreateThreadEx st=0x%08lX thread=%p\n", (unsigned)st, th);
        describe("[host]", th);

        /* The same entry, duplicated with DUP_HANDLE: the context APIs accept
         * this one. That difference is the whole finding. */
        if (th) {
            HANDLE dup = NULL;
            if (DuplicateHandle(GetCurrentProcess(), th, GetCurrentProcess(), &dup,
                                0, FALSE, DUPLICATE_SAME_ACCESS)) {
                printf("[host dup] duplicated %p -> %p\n", th, dup);
                describe("[host dup]", dup);
                CloseHandle(dup);
            } else {
                printf("[host dup] DuplicateHandle failed %lu\n", GetLastError());
            }
        }

        if (th) {
            X86_CONTEXT c = { 0 };
            c.ContextFlags = 0x00010001;
            c.SegCs = 0x23; c.SegSs = 0x23; c.SegDs = 0x23; c.SegEs = 0x23;
            c.SegFs = 0x53; c.SegGs = 0x2B;
            c.EFlags = 0x246;
            c.Eip = (DWORD)(ULONG_PTR)start;
            c.Esp = 0x00040000;
            NTSTATUS s2 = pNtSetContextThread(th, &c);
            printf("[host] NtSetContextThread(x86) st=0x%08lX\n", (unsigned)s2);
            CloseHandle(th);
        }
        VirtualFreeEx(ph, start, 0, MEM_RELEASE);
    }

    /* 3. the same thing through the documented Win32 API */
    {
        HANDLE th = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(
                                       GetModuleHandleW(L"kernel32.dll"), "Sleep"),
                                       (PVOID)100000, CREATE_SUSPENDED, NULL);
        printf("[host] CreateRemoteThread=%p err=%lu\n", th, GetLastError());
        describe("[host crt]", th);
        if (th) { TerminateThread(th, 0); CloseHandle(th); }
    }

    CloseHandle(ph);
    return 0;
}
