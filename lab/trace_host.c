/* Tracer for the loader's WOW64 fallback.
 *
 * The loader's fallback starts a 32 bit thread in a 32 bit host at a stub of
 * its own. When the thread dies with an NTSTATUS that says nothing (0x103,
 * 0xC0000005), this attaches to the host before the fallback runs and prints
 * the exception record and the 32 bit stack of the faulting thread, so the
 * fault can be placed instead of guessed.
 *
 * Build: gcc -m64 -O2 -static -o trace_host.exe trace_host.c
 * Usage: trace_host.exe <pid> [seconds]
 */
#include <windows.h>
#include <stdio.h>

static void dump32(HANDLE ph, DWORD tid) {
    printf("  [32] enter dump32 tid=%lu\n", tid); fflush(stdout);
    /* WOW64_CONTEXT through the documented API needs an open thread */
    /* A 64 bit debugger's CreateThread event hands out a thread handle, and
     * OpenThread hands out another - both are of the kind the context APIs do
     * not accept, so the WOW64 view has to be reached through a DUP_HANDLE
     * duplicate of the same entry (the same trick the loader needs). */
    HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (th) {
        HANDLE dup = NULL;
        if (DuplicateHandle(GetCurrentProcess(), th, GetCurrentProcess(), &dup,
                            0, FALSE, DUPLICATE_SAME_ACCESS)) {
            CloseHandle(th);
            th = dup;
        }
    } else {
        printf("  [32] OpenThread(tid=%lu) failed err=%lu\n", tid, GetLastError());
        return;
    }
    printf("  [32] context query on tid=%lu via duplicate %p\n", tid, th);
    fflush(stdout);

    WOW64_CONTEXT c;
    ZeroMemory(&c, sizeof(c));
    c.ContextFlags = WOW64_CONTEXT_ALL;
    SetLastError(0);
    if (Wow64GetThreadContext(th, &c)) {
        printf("  [32] eip=0x%08lX esp=0x%08lX ebp=0x%08lX eax=0x%08lX ebx=0x%08lX "
               "ecx=0x%08lX edx=0x%08lX esi=0x%08lX edi=0x%08lX\n",
               (unsigned)c.Eip, (unsigned)c.Esp, (unsigned)c.Ebp, (unsigned)c.Eax,
               (unsigned)c.Ebx, (unsigned)c.Ecx, (unsigned)c.Edx, (unsigned)c.Esi,
               (unsigned)c.Edi);
        printf("  [32] cs=0x%X ss=0x%X ds=0x%X es=0x%X fs=0x%X gs=0x%X eflags=0x%08lX\n",
               c.SegCs, c.SegSs, c.SegDs, c.SegEs, c.SegFs, c.SegGs, (unsigned)c.EFlags);

        DWORD stack[24] = { 0 };
        SIZE_T got = 0;
        if (ReadProcessMemory(ph, (LPCVOID)(ULONG_PTR)(c.Esp & ~3u), stack, sizeof(stack), &got)) {
            for (int i = 0; i < 12; ++i) {
                printf("  [32] stk[%02d] esp+0x%02X = 0x%08lX\n", i, i * 4, (unsigned)stack[i]);
            }
        } else {
            printf("  [32] stack read failed %lu (esp=0x%08lX)\n", GetLastError(), (unsigned)c.Esp);
        }

        printf("  [32] context read ok (dr7=0x%08lX)\n", (unsigned)c.Dr7);

        /* the code around eip, so an int 3 / ud2 / bad call shows */
        BYTE code[16] = { 0 };
        SIZE_T cg = 0;
        if (ReadProcessMemory(ph, (LPCVOID)(ULONG_PTR)c.Eip, code, sizeof(code), &cg)) {
            printf("  [32] code @eip:");
            for (size_t i = 0; i < cg; ++i) printf(" %02X", code[i]);
            printf("\n");
        }
    } else {
        printf("  [32] Wow64GetThreadContext failed %lu\n", GetLastError());
    }
    printf("  [32] leaving dump32\n");
    fflush(stdout);
    CloseHandle(th);
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: trace_host <pid> [seconds]\n"); return 2; }
    DWORD pid = (DWORD)strtoul(argv[1], NULL, 0);
    int secs = argc > 2 ? atoi(argv[2]) : 20;

    HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!ph) ph = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION |
                              PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!ph) { printf("OpenProcess %lu failed %lu\n", pid, GetLastError()); return 3; }
    printf("[trace] process handle %p\n", ph); fflush(stdout);

    /* 0x2 = DEBUG_ONLY_THIS_PROCESS: the loader's descendants (it starts
     * none) and its own new threads stay out of the way, but every thread of
     * the host is reported. */
    if (!DebugActiveProcess(pid)) {
        printf("DebugActiveProcess failed %lu\n", GetLastError());
        CloseHandle(ph);
        return 4;
    }
    DebugSetProcessKillOnExit(FALSE);
    printf("[trace] attached to %lu\n", pid);
    fflush(stdout);

    DWORD deadline = GetTickCount() + (DWORD)secs * 1000;
    DEBUG_EVENT de;
    int printed = 0;
    while (GetTickCount() < deadline && WaitForDebugEvent(&de, 500)) {
        DWORD cont = DBG_CONTINUE;
        printf("[trace] event %lu tid=%lu\n", de.dwDebugEventCode, de.dwThreadId); fflush(stdout);
        switch (de.dwDebugEventCode) {
        case CREATE_THREAD_DEBUG_EVENT:
            printf("[trace] thread create tid=%lu handle=%p start=0x%p\n", de.dwThreadId,
                   de.u.CreateThread.hThread,
                   de.u.CreateThread.lpStartAddress);
            /* let the thread run until it is suspended, then read it. The
             * CreateThread event arrives before the kernel has finished the
             * thread's own setup, so the context there is not the one it will
             * execute. */
            if (de.u.CreateThread.lpStartAddress &&
                (ULONG_PTR)de.u.CreateThread.lpStartAddress < 0x10000000ULL) {
                printf("[trace] low thread: continuing, then dumping\n"); fflush(stdout);
                ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
                printf("[trace] create continued, err=%lu\n", GetLastError()); fflush(stdout);
                /* ReadProcessMemory on a 32 bit target's pages is the same
                 * call as on a 64 bit one, but a thread the debugger has just
                 * continued cannot be opened for reading without the process
                 * handle it already holds - retry once through that handle. */
                HANDLE vt = OpenThread(THREAD_SUSPEND_RESUME, FALSE, de.dwThreadId);
                if (vt) {
                    SuspendThread(vt);
                    Sleep(100);
                    dump32(ph, de.dwThreadId);
                    ResumeThread(vt);
                    CloseHandle(vt);
                } else {
                    printf("[trace] low thread: OpenThread failed %lu\n", GetLastError());
                    dump32(ph, de.dwThreadId);
                }
                continue;
            }
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            printf("[trace] thread exit  tid=%lu code=0x%08lX\n", de.dwThreadId,
                   de.u.ExitThread.dwExitCode);
            break;
        case LOAD_DLL_DEBUG_EVENT: {
            char name[MAX_PATH] = "?";
            SIZE_T n = 0;
            SIZE_T rg = 0;
            if (de.u.LoadDll.lpImageName && de.u.LoadDll.lpBaseOfDll) {
                char *p = NULL;
                if (ReadProcessMemory(ph, de.u.LoadDll.lpImageName, &p, sizeof(p), &rg) && p) {
                    if (de.u.LoadDll.fUnicode)
                        WideCharToMultiByte(CP_ACP, 0, (wchar_t *)p, -1, name, MAX_PATH, NULL, NULL);
                    else
                        ReadProcessMemory(ph, p, name, MAX_PATH - 1, &n);
                }
            }
            printf("[trace] dll load     base=0x%p %s (read=%llu ptr=%p)\n",
                   de.u.LoadDll.lpBaseOfDll, name, (unsigned long long)rg, de.u.LoadDll.lpImageName);
            fflush(stdout);
            break;
        }
        case EXCEPTION_DEBUG_EVENT: {
            EXCEPTION_DEBUG_INFO *ei = &de.u.Exception;
            DWORD code = ei->ExceptionRecord.ExceptionCode;
            /* the debugger's own attach breakpoint on the main thread */
            if (code == 0x80000003L && printed == 0) {
                printf("[trace] initial breakpoint (expected)\n");
                printed = 1;
                break;
            }
            printf("[trace] EXCEPTION code=0x%08lX addr=0x%p first=%lu tid=%lu params=%lu\n",
                   code, ei->ExceptionRecord.ExceptionAddress, ei->dwFirstChance,
                   de.dwThreadId, ei->ExceptionRecord.NumberParameters);
            for (DWORD i = 0; i < ei->ExceptionRecord.NumberParameters && i < 15; ++i)
                printf("[trace]   param[%lu]=0x%llX\n", i,
                       (unsigned long long)ei->ExceptionRecord.ExceptionInformation[i]);
            fflush(stdout);
            dump32(ph, de.dwThreadId);
            /* let the process die the way it would without us */
            cont = DBG_EXCEPTION_NOT_HANDLED;
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            printf("[trace] process exit code=0x%08lX\n", de.u.ExitProcess.dwExitCode);
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
            DebugActiveProcessStop(pid);
            CloseHandle(ph);
            return 0;
        default:
            break;
        }
        printf("[trace] continue tid=%lu cont=0x%lX\n", de.dwThreadId, cont); fflush(stdout);
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont);
        printf("[trace] continued tid=%lu\n", de.dwThreadId); fflush(stdout);
    }
    printf("[trace] loop end tick=%lu deadline=%lu\n", GetTickCount(), deadline);

    DebugActiveProcessStop(pid);
    CloseHandle(ph);
    printf("[trace] done\n");
    return 0;
}
