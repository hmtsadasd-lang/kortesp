#include "../../shared/include/nt.hpp"
#include "../../shared/include/hash.hpp"
#include "../../shared/include/mem.hpp"
#include "../../shared/include/peb.hpp"
#include "../../shared/include/map_host.hpp"
#include "../../shared/include/lateral.hpp"
#include "handle.hpp"
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <accctrl.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <vector>

namespace {

// NtQueryObject is resolved at run time so the probe builds unchanged with
// MSVC and MinGW toolchains (winternl.h does not declare it everywhere).
using NtQueryObjectFn = NTSTATUS_(NTAPI*)(HANDLE, int, void*, ULONG, ULONG*);

NtQueryObjectFn nt_query_object() {
    static NtQueryObjectFn fn = reinterpret_cast<NtQueryObjectFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
    return fn;
}

// NtQueryObject(ObjectBasicInformation) is strict about the buffer length:
// a mismatch is answered with STATUS_INFO_LENGTH_MISMATCH and the call
// carries no length hint back. The accepted size differs between Windows
// builds, so it is discovered by probing.
ULONG query_granted_access(HANDLE h, NtQueryObjectFn nqobj, const char* tag) {
    if (!h || !nqobj) return 0;
    UCHAR buf[0x40]{};
    for (ULONG len = 8; len <= sizeof(buf); len += 4) {
        ULONG need = 0;
        NTSTATUS_ st = nqobj(h, 0, buf, len, &need);
        if (st >= 0) {
            printf("  NtQueryObject[%s] ok len=%lu need=%lu\n", tag, len, need);
            return reinterpret_cast<OBJECT_BASIC_INFORMATION_*>(buf)->GrantedAccess;
        }
        if (need && need <= sizeof(buf) && need != len) {
            ULONG need2 = 0;
            NTSTATUS_ st2 = nqobj(h, 0, buf, need, &need2);
            if (st2 >= 0) {
                printf("  NtQueryObject[%s] ok len=%lu need=%lu\n", tag, need, need2);
                return reinterpret_cast<OBJECT_BASIC_INFORMATION_*>(buf)->GrantedAccess;
            }
        }
    }
    printf("  NtQueryObject[%s] no accepted length in 8..%lu\n", tag, sizeof(buf));
    return 0;
}

// SYSTEM_EXTENDED_HANDLE_INFORMATION as SystemExtendedHandleInformation
// (0x40) returns it. The entry array starts at 0x10, each entry is 0x28.
struct SYS_HANDLE_ENTRY_ {
    ULONG_PTR Object;
    ULONG_PTR Pid;
    ULONG_PTR Handle;
    ULONG     Access;
    USHORT    CreatorBackTraceIndex;
    USHORT    TypeIndex;
    ULONG     Attributes;
    ULONG     Reserved;
};

// CreateRemoteThread / NtCreateThreadEx hand back a handle that is valid for
// NtCreateThreadEx and then dead for everything else: GetThreadId and
// NtQueryInformationThread answer STATUS_INVALID_HANDLE and NtGetContextThread
// answers STATUS_ACCESS_VIOLATION. A DUP_HANDLE duplicate of the same entry is
// accepted by all of them. This walks this process's handle table, finds the
// entry with that numeric value and duplicates it.
HANDLE dup_local_thread_handle(HANDLE h) {
    using NtQSI = NTSTATUS_(__stdcall*)(ULONG, void*, ULONG, ULONG*);
    static auto qsi = reinterpret_cast<NtQSI>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!qsi) return nullptr;

    std::vector<uint8_t> buf(1 << 20);
    ULONG ret = 0;
    NTSTATUS_ st = static_cast<NTSTATUS_>(-1);
    for (int i = 0; i < 8; ++i) {
        st = qsi(0x40, buf.data(), static_cast<ULONG>(buf.size()), &ret);
        if (st >= 0) break;
        if (st != static_cast<NTSTATUS_>(0xC0000004)) return nullptr;   // not length
        buf.resize(buf.size() * 2);
    }
    if (st < 0) return nullptr;

    ULONG_PTR count = *reinterpret_cast<ULONG_PTR*>(buf.data());
    auto* ent = reinterpret_cast<SYS_HANDLE_ENTRY_*>(buf.data() + 0x10);
    ULONG_PTR me = GetCurrentProcessId();

    for (ULONG_PTR i = 0; i < count; ++i) {
        auto& e = ent[i];
        if (e.Pid != me) continue;
        if (reinterpret_cast<HANDLE>(e.Handle) != h) continue;

        HANDLE dup = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dup,
                             0, FALSE, DUPLICATE_SAME_ACCESS))
            return nullptr;
        return dup;
    }
    return nullptr;
}

// A one word reading of the NTSTATUS the context calls return. The kernel
// uses STATUS_INVALID_HANDLE for a handle that is not valid in this process
// and STATUS_ACCESS_VIOLATION for a handle it can see but not use, so the
// two must not be read as the same failure.
const char* rst_to_text(unsigned st) {
    switch (st) {
        case 0x00000000u: return "ok";
        case 0xC0000008u: return "STATUS_INVALID_HANDLE: not an entry in this process";
        case 0xC0000005u: return "STATUS_ACCESS_VIOLATION: handle not usable, or bad buffer";
        case 0xC000000Du: return "STATUS_INVALID_PARAMETER";
        case 0xC0000004u: return "STATUS_INFO_LENGTH_MISMATCH";
        case 0xC0000002u: return "STATUS_NOT_IMPLEMENTED";
        case 0xC00000BBu: return "STATUS_NOT_SUPPORTED";
        default: return "ntstatus";
    }
}

DWORD find_pid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (lstrcmpiW(pe.szExeFile, L"FortniteClient-Win64-Shipping.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

HANDLE   g_proc{};
uint8_t* g_local{};

// printf-compatible logging for the shared mapper
static void mlog(const char* fmt, ...) {
    va_list a;
    va_start(a, fmt);
    vprintf(fmt, a);
    va_end(a);
    printf("\n");
}

struct ModRange { uint64_t base, end; wchar_t name[64]; };

void collect_modules(DWORD pid, std::vector<ModRange>& mods) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me{ sizeof(me) };
    for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me)) {
        ModRange r{};
        r.base = reinterpret_cast<uint64_t>(me.modBaseAddr);
        r.end  = r.base + me.modBaseSize;
        lstrcpynW(r.name, me.szModule, 64);
        mods.push_back(r);
    }
    CloseHandle(snap);
}

void print_addr(const std::vector<ModRange>& mods, uint64_t a) {
    for (auto& m : mods) {
        if (a >= m.base && a < m.end) {
            printf("%ls+0x%llX", m.name, static_cast<unsigned long long>(a - m.base));
            return;
        }
    }
    printf("0x%llX", static_cast<unsigned long long>(a));
}

// One loop, not two. A second WaitForDebugEvent loop after this one never gets
// an event: when the first loop's timeout expires the debug event is left
// pending, and the next WaitForDebugEvent call returns FALSE for good. So the
// dump happens inline, in the same loop that keeps the process running.
DWORD g_dump_pid = 0;
HANDLE g_dump_ph = nullptr;
int g_dump_quiet = 60;

void report_exception(DEBUG_EVENT& de, EXCEPTION_DEBUG_INFO& ei);

void drain_debug_events(DWORD pid, int quiet_ms) {
    // Nothing else prints from this thread, so every line can be flushed here:
    // a debugger loop that dies before its buffer is flushed reports nothing,
    // which is indistinguishable from "no exceptions".
    printf("[dbg] drain start pid=%lu quiet=%d debugger_present=%d\n",
           static_cast<unsigned long>(pid), quiet_ms, IsDebuggerPresent() ? 1 : 0);
    fflush(stdout);
    DEBUG_EVENT de{};
    int quiet = quiet_ms;
    for (;;) {
        if (!WaitForDebugEvent(&de, quiet)) {
            printf("[dbg] drain wait failed/timeout err=%lu after %d ms\n",
                   GetLastError(), quiet);
            fflush(stdout);
            break;
        }
        printf("[dbg] event code=%lu tid=%lu\n", de.dwDebugEventCode, de.dwThreadId);
        fflush(stdout);
        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && g_dump_ph) {
            auto& er = de.u.Exception.ExceptionRecord;
            if (er.ExceptionCode != 0x80000003L)
                report_exception(de, de.u.Exception);
        } else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
            break;
        }
        quiet = g_dump_ph ? g_dump_quiet : quiet_ms;
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }
}

void report_exception(DEBUG_EVENT& de, EXCEPTION_DEBUG_INFO& ei) {
    auto& er = ei.ExceptionRecord;
    fflush(stdout);
    printf("[dbg] exception code=0x%08lX addr=0x%llX first=%d params=%lu\n",
           static_cast<unsigned>(er.ExceptionCode),
           static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(er.ExceptionAddress)),
           ei.dwFirstChance,
           static_cast<unsigned long>(er.NumberParameters));
    for (DWORD i = 0; i < er.NumberParameters && i < 15; ++i)
        printf("[dbg]   param[%lu]=0x%llX\n", static_cast<unsigned long>(i),
               static_cast<unsigned long long>(er.ExceptionInformation[i]));

    HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, de.dwThreadId);
    if (!th) return;
    CONTEXT c{};
    c.ContextFlags = CONTEXT_ALL;
    if (GetThreadContext(th, &c)) {
        printf("[dbg]   rip=0x%llX rsp=0x%llX rbp=0x%llX rcx=0x%llX rdx=0x%llX r8=0x%llX\n",
               static_cast<unsigned long long>(c.Rip), static_cast<unsigned long long>(c.Rsp),
               static_cast<unsigned long long>(c.Rbp), static_cast<unsigned long long>(c.Rcx),
               static_cast<unsigned long long>(c.Rdx), static_cast<unsigned long long>(c.R8));
        uint64_t stack[96]{};
        SIZE_T got = 0;
        if (ReadProcessMemory(g_dump_ph, reinterpret_cast<void*>(c.Rsp), stack, sizeof(stack), &got)) {
            for (size_t i = 0; i < got / sizeof(uint64_t); ++i) {
                if (!stack[i]) continue;
                printf("[dbg]   stk[%02u] 0x%llX\n", static_cast<unsigned>(i),
                       static_cast<unsigned long long>(stack[i]));
            }
        }
    }
    CloseHandle(th);
}

uint32_t wow_export32(HANDLE ph, uint32_t base, const char* want) {
    IMAGE_DOS_HEADER dos{};
    if (!ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(base)), &dos, sizeof(dos), nullptr))
        return 0;
    IMAGE_NT_HEADERS32 nt{};
    if (!ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(base) + dos.e_lfanew),
                           &nt, sizeof(nt), nullptr))
        return 0;

    auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return 0;

    IMAGE_EXPORT_DIRECTORY ed{};
    if (!ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(base) + dir.VirtualAddress),
                           &ed, sizeof(ed), nullptr))
        return 0;

    for (uint32_t i = 0; i < ed.NumberOfNames; ++i) {
        uint32_t nr = 0;
        if (!ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(base) + ed.AddressOfNames + i * 4),
                               &nr, 4, nullptr)) break;

        char name[128]{};
        if (!ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(base) + nr),
                               name, sizeof(name) - 1, nullptr)) continue;
        if (strcmp(name, want) != 0) continue;

        uint16_t ord = 0;
        if (!ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(base) + ed.AddressOfNameOrdinals + i * 2),
                               &ord, 2, nullptr)) return 0;
        uint32_t frva = 0;
        if (!ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(base) + ed.AddressOfFunctions + ord * 4),
                               &frva, 4, nullptr)) return 0;
        return base + frva;
    }
    return 0;
}

uint32_t wow_module32(HANDLE ph, uint64_t peb32, const wchar_t* want) {
    uint32_t ldr = 0;
    if (!ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(peb32) + 0x0C),
                           &ldr, 4, nullptr) || !ldr) return 0;

    uint32_t head = ldr + 0x14, cur = 0;
    if (!ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(head)), &cur, 4, nullptr))
        return 0;

    for (int g = 0; cur && cur != head && g < 512; ++g) {
        uint32_t entry = cur - 0x08;
        uint32_t base = 0, buf = 0;
        uint16_t len = 0;
        ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(entry) + 0x18), &base, 4, nullptr);
        ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(entry) + 0x2C), &len, 2, nullptr);
        ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(entry) + 0x30), &buf, 4, nullptr);

        if (buf && len) {
            wchar_t name[64]{};
            uint32_t n = len > sizeof(name) - 2 ? static_cast<uint32_t>(sizeof(name) - 2) : len;
            if (ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(buf)), name, n, nullptr) &&
                h::fnv1a_w(name) == h::fnv1a_w(want))
                return base;
        }
        ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(cur)), &cur, 4, nullptr);
    }
    return 0;
}

bool enable_debug_privilege() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        SetLastError(0);
        if (AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr))
            ok = (GetLastError() == ERROR_SUCCESS);
    }
    CloseHandle(tok);
    return ok;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    bool maptest_dbg = argc > 1 && lstrcmpW(argv[1], L"--maptestdbg") == 0;
    if (argc > 1 && (lstrcmpW(argv[1], L"--maptest") == 0 || maptest_dbg)) {
        const wchar_t* dll = argc > 2 ? argv[2] : L"C:\\dev\\fortesp\\out\\payload.dll";
        char exp[64] = "start";
        if (argc > 3)
            WideCharToMultiByte(CP_ACP, 0, argv[3], -1, exp, sizeof(exp), nullptr, nullptr);

        size_t size = 0;
        uint8_t* img = nullptr;
        if (!slurp_file(dll, &img, &size) || size < 0x100) {
            printf("[!] cannot read %ls\n", dll);
            return 1;
        }

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER_*>(img);
        auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(img + dos->e_lfanew);
        if (dos->e_magic != 0x5A4D || nt->Signature != 0x4550 || nt->FileHeader.Machine != 0x8664) {
            printf("[!] bad image\n");
            delete[] img;
            return 1;
        }

        wchar_t full[MAX_PATH]{};
        GetFullPathNameW(dll, MAX_PATH, full, nullptr);

        STARTUPINFOW si{ sizeof(si) };
        PROCESS_INFORMATION pi{};
        // The host has to be a process the payload recognises as its target:
        // otherwise the payload takes its relay branch and never reaches
        // launch_worker, and the mapper test proves only half of itself.
        // lab\mock_target64.c is a sleep loop that carries the client's real
        // name; it sits in out\lab next to the other mocks.
        // The loader itself must not be called ...Shipping.exe: the payload
        // picks its branch from the name of the process it runs in, and the
        // loader runs in a process with the same name as its own image, so
        // g_host_path is still baked in and the relay branch is taken first.
        // Passing g_host_path empty makes the payload fall through to target
        // mode, which is the branch this test is for.
        wchar_t cmdline[] = L"out\\lab\\FortniteClient-Win64-Shipping.exe";
        DWORD host_flags = CREATE_NEW_CONSOLE;
        if (!CreateProcessW(nullptr, cmdline, nullptr, nullptr, FALSE,
                            host_flags, nullptr, nullptr, &si, &pi)) {
            printf("[!] host spawn failed %lu\n", GetLastError());
            delete[] img;
            return 1;
        }
        setvbuf(stdout, nullptr, _IONBF, 0);   // the host can take this process down
        printf("[*] test host %ls pid %lu\n", cmdline, static_cast<unsigned long>(pi.dwProcessId));

        HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
        if (!ph) {
            printf("[!] open host failed %lu\n", GetLastError());
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            delete[] img;
            return 1;
        }

        if (maptest_dbg) Sleep(200);

        // Relocated copy of the image, used only to find one export after the
        // fact: the mapped copy is freed when the entry thread exits, and the
        // trace read below needs the RVA before that happens.
        uint64_t trace_rva = 0;
        {
            uint8_t* cp = new uint8_t[size];
            memcpy(cp, img, size);
            auto* cdos = reinterpret_cast<IMAGE_DOS_HEADER_*>(cp);
            auto* cnt = reinterpret_cast<IMAGE_NT_HEADERS64_*>(cp + cdos->e_lfanew);
            // (find_export is the mapper's own; its cached state is not the
            // loader's, so it is inlined here as a plain name walk)
            // Map the export directory by hand: exports live at Section RVA +
            // (RVA - VirtualAddress), not at RVA - which is what a mapped
            // image has and a file on disk does not.
            auto rva_to_off = [&](uint32_t rva) -> const uint8_t* {
                auto* sec = IMAGE_FIRST_SECTION_(cnt);
                for (uint16_t i = 0; i < cnt->FileHeader.NumberOfSections; ++i, ++sec) {
                    const uint32_t vsize = sec->VirtualSize ? sec->VirtualSize : sec->SizeOfRawData;
                    if (rva < sec->VirtualAddress || rva >= sec->VirtualAddress + vsize) continue;
                    const uint32_t delta = rva - sec->VirtualAddress;
                    if (delta >= sec->SizeOfRawData) return nullptr;   // .bss tail
                    return cp + sec->PointerToRawData + delta;
                }
                return nullptr;
            };
            auto& edir = cnt->OptionalHeader.DataDirectory[0];
            if (edir.VirtualAddress) {
                auto* ed = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY_*>(rva_to_off(edir.VirtualAddress));
                if (ed) {
                    auto* names = reinterpret_cast<const uint32_t*>(rva_to_off(ed->AddressOfNames));
                    auto* ords  = reinterpret_cast<const uint16_t*>(rva_to_off(ed->AddressOfNameOrdinals));
                    auto* funcs = reinterpret_cast<const uint32_t*>(rva_to_off(ed->AddressOfFunctions));
                    if (names && ords && funcs) {
                        for (uint32_t i = 0; i < ed->NumberOfNames; ++i) {
                            auto* nm = reinterpret_cast<const char*>(rva_to_off(names[i]));
                            if (nm && strcmp(nm, "g_trace") == 0) {
                                // An exported *object* is not an export function:
                                // the address table entry for g_trace is its RVA,
                                // and the payload's .data section is where it
                                // lives. Reading 0xD000 (the value of the export
                                // address entry for the function-style exports)
                                // read .bss and reported an all-zero trace.
                                // .data's RVA is where the payload's statics
                                // live; g_trace is the first of them.
                                auto* ds = IMAGE_FIRST_SECTION_(cnt);
                                for (uint16_t k = 0; k < cnt->FileHeader.NumberOfSections; ++k, ++ds)
                                    if (memcmp(ds->Name, ".data", 5) == 0) { trace_rva = ds->VirtualAddress; break; }
                                printf("[*] mm: g_trace export at rva 0x%llX (reading 0x%llX)\n",
                                       static_cast<unsigned long long>(funcs[ords[i]]),
                                       static_cast<unsigned long long>(trace_rva));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // NtDebugActiveProcess is the call that actually attaches: the
        // Win32 wrapper DebugActiveProcess returned TRUE here while
        // WaitForDebugEvent then failed with ERROR_INVALID_HANDLE, i.e. the
        // "debugger" was never in the loop and every exception was missed.
        // Debugging this process from here does not work, and both APIs say why:
        // DebugActiveProcess returns TRUE while WaitForDebugEvent then fails
        // with ERROR_INVALID_HANDLE, and NtDebugActiveProcess answers
        // STATUS_INVALID_HANDLE for the same process handle that
        // ReadProcessMemory/WriteProcessMemory accept. A debugger loop that is
        // not really attached reports nothing, and "no exceptions" from a loop
        // that never ran is not evidence. Fall back to what works: catch the
        // fault by keeping the process alive and reading its memory.
        bool dbg = false;
        if (maptest_dbg) {
            using NtDAP = NTSTATUS_(__stdcall*)(HANDLE, HANDLE);
            auto dap = reinterpret_cast<NtDAP>(
                GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDebugActiveProcess"));
            NTSTATUS_ st = dap ? dap(ph, nullptr) : static_cast<NTSTATUS_>(-1);
            dbg = st >= 0;
            printf("[*] debugger attach=0x%08lX dbg=%d (0 = no exception stream available)\n",
                   static_cast<unsigned>(st), dbg ? 1 : 0);
            if (!dbg) {
                printf("[*] --maptestdbg: exception stream unavailable, "
                       "using the post-mortem dump instead\n");
            }
        }
        // A background drainer keeps the process alive from the first second;
        // exceptions are printed as they arrive, by the same loop.
        HANDLE drain_th = nullptr;
        if (dbg) {
            // Exactly one drainer. Two WaitForDebugEvent loops on the same
            // debuggee split the event stream between them, so half the
            // exceptions are consumed by the loop that does not print, and the
            // other half are reported from a thread whose printf can interleave
            // with the main one. One thread, one stream.
            g_dump_ph = ph;
            g_dump_quiet = 300;
            drain_th = CreateThread(nullptr, 0, [](void* p) -> DWORD {
                drain_debug_events(static_cast<DWORD>(reinterpret_cast<uintptr_t>(p)), 300);
                return 0;
            }, reinterpret_cast<void*>(static_cast<uintptr_t>(pi.dwProcessId)), 0, nullptr);
            printf("[*] debug drainer started=%d\n", drain_th ? 1 : 0);
        }

        DWORD mexit = 0;
        map_result mr{};
        // self_path = nullptr: the payload is not told where its own file is,
        // so it cannot take the relay branch. The branch under test is target
        // mode, and with a host whose name already says "the client" the
        // payload would otherwise prefer the relay.
        // keep_mapped: the worker thread the payload starts keeps using the
        // mapped image (it was started from inside it), so the image must not
        // be freed under it. The host is terminated at the end of the test.
        // The debugger is attached, so every process creation, thread creation
        // and exit is a debug event the loader has to acknowledge. A mapper
        // that waits for the entry thread blocks the loader from doing that,
        // and the whole host stops at its next event - which is what a
        // STATUS_PENDING entry thread with no exception looks like from
        // outside. Run the mapper on its own thread and keep draining here.
        struct map_job { HANDLE ph; const uint8_t* img; size_t size; bool* done; map_result* mr; const char* exp; };
        map_job job{ ph, img, size, nullptr, &mr, exp };
        volatile bool job_done = false;
        bool ran = false;
        if (dbg) {
            job.done = const_cast<bool*>(&job_done);
            HANDLE jt = CreateThread(nullptr, 0, [](void* p) -> DWORD {
                auto* j = static_cast<map_job*>(p);
                bool ok = manual_map_host(j->ph, j->img, j->size, nullptr, j->exp,
                                          /*keep_mapped*/true, j->mr, 15000, mlog);
                *const_cast<bool*>(j->done) = ok;
                return 0;
            }, &job, 0, nullptr);
            // drain until the job reports done (the drainer thread keeps the
            // process alive meanwhile)
            for (int i = 0; i < 3000 && !job_done; ++i) Sleep(10);
            if (jt) { WaitForSingleObject(jt, 5000); CloseHandle(jt); }
            ran = job_done;
        } else {
            ran = manual_map_host(ph, img, size, nullptr, exp, /*keep_mapped*/true,
                                  &mr, 15000, mlog);
        }
        // The mapped image is kept, so the trace can be read after the entry
        // thread has returned; before, the read happened after the free.
        uintptr_t remote_base = mr.remote;
        if (!remote_base) {
            // opened by handle, so this is the address the mapper used
            remote_base = 0x10000000;
        }
        // trace_rva is resolved from g_trace's *export address* when the image
        // is loaded; for a manually mapped image that value is the RVA the
        // mapper reported, and the export table of a mapped image cannot be
        // read with `cp + rva`. Report both so a wrong offset is visible.
        printf("[*] mm: trace read at 0x%llX (rva 0x%llX base 0x%llX)\n",
               static_cast<unsigned long long>(remote_base + trace_rva),
               static_cast<unsigned long long>(trace_rva),
               static_cast<unsigned long long>(remote_base));
        // Dump the first bytes of .data from the mapping and compare them with
        // the file: if they differ, the payload's static initialisers never ran
        // in the mapping the loader is reading.
        {
            // .data is only 0x50 bytes; past it lies .rdata, so read the
            // section exactly and nothing more.
            uint8_t got[0x50]{};
            if (ReadProcessMemory(ph, reinterpret_cast<void*>(remote_base + 0x8000),
                                  got, sizeof(got), nullptr)) {
                printf("[*] mm: .data =");
                for (int i = 0; i < 0x50; ++i) {
                    if (i && !(i % 16)) printf("\n[*] mm:        ");
                    printf(" %02X", got[i]);
                }
                printf("\n");
            }
            uint8_t raw[16]{};
            memcpy(raw, img + 0x6C00, sizeof(raw));
            printf("[*] mm: file .data[0..15] =");
            for (int i = 0; i < 16; ++i) printf(" %02X", raw[i]);
            printf("\n");
        }
        if (ran && trace_rva) {
            uint32_t tr[16]{};
            if (ReadProcessMemory(ph, reinterpret_cast<void*>(remote_base + trace_rva),
                                  tr, sizeof(tr), nullptr)) {
                printf("[*] mm: trace");
                for (int i = 0; i < 16; ++i)
                    printf(" %d=%08X", i, tr[i]);
                printf("\n");
            } else {
                printf("[!] mm: trace read failed %lu\n", GetLastError());
            }
            // Sanity check the trace base against the mapped image itself: the
            // first qword of the mapping must be 'MZ' + a valid PE header, and
            // the trace base has to sit inside a mapped section. A trace that
            // reads as all zeros is a wrong address, not a silent payload.
            uint16_t mz = 0;
            if (ReadProcessMemory(ph, reinterpret_cast<void*>(remote_base), &mz, 2, nullptr))
                printf("[*] mm: mapped MZ=%04X at base\n", mz);
            uint32_t nt_sig = 0;
            uint32_t lfanew = 0;
            ReadProcessMemory(ph, reinterpret_cast<void*>(remote_base + 0x3C), &lfanew, 4, nullptr);
            if (lfanew && lfanew < 0x400 &&
                ReadProcessMemory(ph, reinterpret_cast<void*>(remote_base + lfanew), &nt_sig, 4, nullptr))
                printf("[*] mm: mapped NT sig=%08X\n", nt_sig);
        }
        DWORD host_alive = 0;
        if (!ran || mr.exit_code) {
            // A payload that dies in its own startup takes the host with it
            // only if the host died; a live host with a dead thread is a
            // crash inside the mapped image, which is what to look at next.
            host_alive = WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT ? 1 : 0;
            printf("[*] host alive=%lu\n", static_cast<unsigned long>(host_alive));
        }
        mexit = mr.exit_code;
        printf("[*] maptest ran=%d exit=%lu (0x%08lX)\n",
               ran ? 1 : 0, static_cast<unsigned long>(mexit),
               static_cast<unsigned>(mexit));
        fflush(stdout);   // the host can take this process down below

        if (dbg) {
            // Let the drainer keep running while the host is still alive: it is
            // the only thread acknowledging this process's debug events, so
            // stopping it parks the host at its next event - and a parked
            // process reports a pending entry thread with no exception, which
            // is exactly the symptom this run is trying to explain.
            Sleep(1500);
            if (drain_th) { CloseHandle(drain_th); drain_th = nullptr; }
            g_dump_ph = nullptr;
            DebugActiveProcessStop(pi.dwProcessId);
        }

        // Do NOT close the process handle while a thread could still be
        // running in there: closing the last handle is what killed the
        // *loader* (exit 5) once the host had already gone.
        DWORD host_wait = WaitForSingleObject(pi.hProcess, 3000);
        DWORD host_exit = 0;
        GetExitCodeProcess(pi.hProcess, &host_exit);
        printf("[*] host wait=%lu state=%lu exit=0x%08lX\n",
               static_cast<unsigned long>(host_wait), static_cast<unsigned long>(host_alive),
               static_cast<unsigned long>(host_exit));
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(ph);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        delete[] img;
        return ran ? 0 : 1;
    }

    if (argc > 1 && lstrcmpW(argv[1], L"--hosttest") == 0) {
        const wchar_t* host = argc > 2 ? argv[2] : L"FortniteClient-Win64-Shipping_EAC_EOS.exe";
        const wchar_t* dll  = argc > 3 ? argv[3] : L"C:\\dev\\fortesp\\out\\payload.dll";
        char exp[64] = "start";
        if (argc > 4)
            WideCharToMultiByte(CP_ACP, 0, argv[4], -1, exp, sizeof(exp), nullptr, nullptr);

        size_t size = 0;
        uint8_t* img = nullptr;
        if (!slurp_file(dll, &img, &size) || size < 0x100) {
            printf("[!] cannot read %ls\n", dll);
            return 1;
        }

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER_*>(img);
        auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(img + dos->e_lfanew);
        if (dos->e_magic != 0x5A4D || nt->Signature != 0x4550 || nt->FileHeader.Machine != 0x8664) {
            printf("[!] bad image\n");
            delete[] img;
            return 1;
        }

        wchar_t full[MAX_PATH]{};
        GetFullPathNameW(dll, MAX_PATH, full, nullptr);

        DWORD hp = pid_by_name(host);
        printf("[*] host %ls pid %lu\n", host, static_cast<unsigned long>(hp));
        if (!hp) { delete[] img; return 1; }

        printf("[*] SeDebugPrivilege=%d\n", enable_debug_privilege() ? 1 : 0);

        HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hp);
        if (!ph) {
            printf("[!] open host failed %lu\n", GetLastError());
            delete[] img;
            return 1;
        }

        DWORD mexit = 0;
        map_result mr{};
        bool ran = manual_map_host(ph, img, size, full, exp, /*keep_mapped*/false,
                                   &mr, 15000, mlog);
        mexit = mr.exit_code;
        printf("[*] hosttest ran=%d exit=%lu (0x%08lX)\n",
               ran ? 1 : 0, static_cast<unsigned long>(mexit),
               static_cast<unsigned>(mexit));

        CloseHandle(ph);
        delete[] img;
        return ran ? 0 : 1;
    }

    // --probe <host-exe> [dll] [mode]: map the delivery probe into an already
    // running process. The probe reports which module names the target asks the
    // loader for, and is how a late-load hijack name is chosen by measurement
    // instead of by guesswork.
    if (argc > 1 && lstrcmpW(argv[1], L"--probe") == 0) {
        const wchar_t* host = argc > 2 ? argv[2] : L"FortniteClient-Win64-Shipping.exe";
        const wchar_t* dll  = argc > 3 ? argv[3] : L"C:\\dev\\fortesp\\out\\payload.dll";
        int mode = argc > 4 ? _wtoi(argv[4]) : 0;

        size_t size = 0;
        uint8_t* img = nullptr;
        if (!slurp_file(dll, &img, &size) || size < 0x100) {
            printf("[!] cannot read %ls\n", dll);
            return 1;
        }

        DWORD hp = pid_by_name(host);
        printf("[*] host %ls pid %lu\n", host, static_cast<unsigned long>(hp));
        if (!hp) { delete[] img; return 1; }

        HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hp);
        if (!ph) {
            printf("[!] open host failed %lu\n", GetLastError());
            delete[] img;
            return 1;
        }

        manual_map_set_probe(mode);
        map_result mr{};
        bool ran = manual_map_host(ph, img, size, dll, "start", /*keep_mapped*/false,
                                   &mr, 15000, mlog);
        manual_map_set_probe(-1);
        printf("[*] probe mapped ran=%d exit=%lu (0x%08lX)\n", ran ? 1 : 0,
               static_cast<unsigned long>(mr.exit_code),
               static_cast<unsigned>(mr.exit_code));

        CloseHandle(ph);
        delete[] img;
        return ran ? 0 : 1;
    }

    // --lateral: survey the user-mode boundary between this process and the
    // client - the points where the client's own threads ask the OS to run
    // something on its behalf. Each answer is an OS return code, not a theory.
    if (argc > 1 && lstrcmpW(argv[1], L"--lateral") == 0) {
        lateral::finding f[16]{};
        int n = 0;
        lateral::report(f, &n);
        static const wchar_t* st[] = { L"CLOSED", L"OPEN", L"UNKNOWN" };
        for (int i = 0; i < n; ++i) {
            printf("%-28ls %-8ls %ls\n",
                   f[i].name, st[static_cast<int>(f[i].st)], f[i].detail);
        }
        return 0;
    }

    // --launch: start the game the way a launcher does and act before the
    // anti-cheat exists.
    //
    // This is the Minecraft-launcher idea, on Windows: the client is started as
    // a *child* of this process, so (a) it is ours - every handle is full
    // PROCESS_ALL_ACCESS without asking the anti-cheat's callback for anything
    // but the first one, and (b) we can be attached as its debugger from the
    // first instruction, which is a window that closes the moment the anti-cheat
    // starts inside it.
    //
    // Modes:
    //   --launch map    map the payload as soon as the "map now" gate is open
    //                   (default: as soon as the process exists, before its own
    //                   start-up has run)
    //   --launch wait <ms>   same, after a delay (for a gate inside the client)
    //   --launch gated  wait for the payload's gate file to appear, then map
    // --launchvia <exe> <dll> [delay]: same as --launch, but the exe is the
    // registered one and CreateProcess is refused (error 740) because the
    // launcher path runs with an auto-elevation manifest. Two ways round that
    // are used here, in order:
    //   1. ShellExecuteEx with SEE_MASK_NOCLOSEPROCESS gives a process handle;
    //   2. a child created through the launcher's own protocol (not used here:
    //      the client needs its arguments, which only the launcher knows).
    // The important property is the same: the handle is one *we* own.
    if (argc > 1 && lstrcmpW(argv[1], L"--launchvia") == 0) {
        const wchar_t* exe = argc > 2 ? argv[2] : L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe";
        const wchar_t* dll = argc > 3 ? argv[3] : L"C:\\dev\\fortesp\\out\\payload.dll";
        int delay = argc > 4 ? _wtoi(argv[4]) : 5000;

        size_t size = 0;
        uint8_t* img = nullptr;
        if (!slurp_file(dll, &img, &size) || size < 0x100) {
            printf("[!] cannot read %ls\n", dll);
            return 1;
        }

        wchar_t dir[MAX_PATH]{};
        lstrcpynW(dir, exe, MAX_PATH);
        wchar_t* slash = wcsrchr(dir, L'\\');
        if (slash) *slash = 0;

        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        sei.lpVerb = L"open";
        sei.lpFile = exe;
        sei.lpDirectory = dir;
        sei.nShow = SW_SHOWNORMAL;
        if (!ShellExecuteExW(&sei) || !sei.hProcess) {
            printf("[!] ShellExecuteEx failed %lu\n", GetLastError());
            delete[] img;
            return 1;
        }
        DWORD cpid = GetProcessId(sei.hProcess);
        printf("[*] launched pid %lu (handle owned by us)\n", static_cast<unsigned long>(cpid));

        Sleep(static_cast<DWORD>(delay));

        DWORD ec = 0;
        if (!GetExitCodeProcess(sei.hProcess, &ec) || ec != STILL_ACTIVE) {
            printf("[!] child already gone (0x%08lX) before the map\n", static_cast<unsigned long>(ec));
            CloseHandle(sei.hProcess);
            delete[] img;
            return 1;
        }

        map_result mr{};
        bool ran = manual_map_host(sei.hProcess, img, size, dll, "start", true, &mr, 20000, mlog);
        printf("[*] map ran=%d exit=0x%08lX remote=0x%llX\n", ran ? 1 : 0,
               static_cast<unsigned>(mr.exit_code),
               static_cast<unsigned long long>(mr.remote));
        Sleep(15000);
        GetExitCodeProcess(sei.hProcess, &ec);
        printf("[*] child state after 15 s: %s\n", ec == STILL_ACTIVE ? "alive" : "exited");
        CloseHandle(sei.hProcess);
        delete[] img;
        return 0;
    }

    if (argc > 1 && lstrcmpW(argv[1], L"--launch") == 0) {
        const wchar_t* mode = argc > 2 ? argv[2] : L"map";
        const wchar_t* dll  = argc > 3 ? argv[3] : L"C:\\dev\\fortesp\\out\\payload.dll";
        int delay = (lstrcmpW(mode, L"wait") == 0 && argc > 4) ? _wtoi(argv[4]) : 0;

        size_t size = 0;
        uint8_t* img = nullptr;
        if (!slurp_file(dll, &img, &size) || size < 0x100) {
            printf("[!] cannot read %ls\n", dll);
            return 1;
        }

        // The launcher URL is what the Epic launcher itself accepts; the client
        // is started by it, not by us, so this path is only for the direct
        // case. Both are kept because the direct path is the one that gives a
        // handle we own.
        wchar_t cmdline[MAX_PATH * 2]{};
        lstrcpynW(cmdline, L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe", MAX_PATH);
        if (GetFileAttributesW(cmdline) == INVALID_FILE_ATTRIBUTES) {
            printf("[!] client executable not found at %ls\n", cmdline);
            delete[] img;
            return 1;
        }

        STARTUPINFOW si{ sizeof(si) };
        PROCESS_INFORMATION pi{};
        printf("[*] launching %ls\n", cmdline);
        if (!CreateProcessW(cmdline, nullptr, nullptr, nullptr, FALSE,
                            CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            printf("[!] launch failed %lu\n", GetLastError());
            delete[] img;
            return 1;
        }
        printf("[*] child pid %lu (suspended)\n", static_cast<unsigned long>(pi.dwProcessId));

        HANDLE ph = pi.hProcess;
        printf("[*] handle owned by us (no anti-cheat query happened)\n");

        if (delay > 0) {
            printf("[*] waiting %d ms before mapping\n", delay);
            Sleep(static_cast<DWORD>(delay));
        }

        map_result mr{};
        bool ran = manual_map_host(ph, img, size, dll, "start", /*keep_mapped*/true,
                                   &mr, 20000, mlog);
        printf("[*] map ran=%d exit=0x%08lX remote=0x%llX\n", ran ? 1 : 0,
               static_cast<unsigned>(mr.exit_code),
               static_cast<unsigned long long>(mr.remote));

        // The payload's own gate has to exist before its code runs, otherwise
        // "mapped" and "the game is up" cannot be told apart.
        ResumeThread(pi.hThread);
        printf("[*] child resumed; leaving it alone for 30 s\n");
        Sleep(30000);
        DWORD ec = 0;
        if (GetExitCodeProcess(ph, &ec) && ec == STILL_ACTIVE)
            printf("[*] child still alive after 30 s\n");
        else
            printf("[!] child exited 0x%08lX during the window\n", static_cast<unsigned long>(ec));

        CloseHandle(pi.hThread);
        CloseHandle(ph);
        delete[] img;
        return 0;
    }

    if (argc > 1 && lstrcmpW(argv[1], L"--stubtest") == 0) {
        uint8_t* code = static_cast<uint8_t*>(
            VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!code) { printf("code alloc failed\n"); return 1; }
        // mov ecx,0x7777 ; ret  (the ret chain below lands on the trailing C3)
        uint8_t sc[] = { 0xB9, 0x77, 0x77, 0x00, 0x00, 0xC3 };
        memcpy(code, sc, sizeof(sc));

        uint64_t exit_thread = reinterpret_cast<uint64_t>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ExitThread"));
        uint8_t* stack = static_cast<uint8_t*>(
            VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!stack) { printf("stack alloc failed\n"); return 1; }

        uint64_t top = reinterpret_cast<uint64_t>(stack) + 0x8000;
        top &= ~0xFull;
        top -= 8;
        uint64_t frame[2] = { reinterpret_cast<uint64_t>(code) + 5, exit_thread };
        memcpy(reinterpret_cast<void*>(top), frame, sizeof(frame));

        using NtCTE = NTSTATUS_(__stdcall*)(HANDLE*, uint32_t, void*, HANDLE, void*,
                                            void*, uint32_t, uintptr_t, uintptr_t,
                                            uintptr_t, void*);
        auto cte = reinterpret_cast<NtCTE>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"));
        HANDLE th = nullptr;
        NTSTATUS_ st = cte(&th, 0x1FFFFF, nullptr, GetCurrentProcess(),
                           reinterpret_cast<void*>(exit_thread), nullptr,
                           1, 0, 0, 0, nullptr);
        printf("create st=0x%08lX th=%p code=%p top=0x%llX\n",
               static_cast<unsigned>(st), th, code,
               static_cast<unsigned long long>(top));
        if (st < 0 || !th) return 1;

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        GetThreadContext(th, &ctx);
        ctx.Rip = reinterpret_cast<DWORD64>(code);
        ctx.Rsp = top;
        ctx.Rcx = 0x7777;
        printf("set=%d\n", SetThreadContext(th, &ctx) ? 1 : 0);

        ResumeThread(th);
        WaitForSingleObject(th, 5000);
        DWORD ec = 0;
        GetExitCodeThread(th, &ec);
        printf("exit=0x%08lX\n", static_cast<unsigned>(ec));
        return 0;
    }

    if (argc > 1 && lstrcmpW(argv[1], L"--dupprobe") == 0) {
        printf("SeDebugPrivilege=%d\n", enable_debug_privilege() ? 1 : 0);
        DWORD gp = pid_by_name(L"FortniteClient-Win64-Shipping.exe");
        printf("game pid=%lu\n", static_cast<unsigned long>(gp));
        if (gp) dump_game_handles(gp);
        return 0;
    }

    if (argc > 1 && lstrcmpW(argv[1], L"--eacprobe") == 0) {
        DWORD hp = pid_by_name(L"EasyAntiCheat_EOS.exe");
        printf("eac pid=%lu\n", static_cast<unsigned long>(hp));
        if (!hp) return 0;

        // enable SeDebugPrivilege: OpenProcess does not use it while disabled
        bool debug_on = enable_debug_privilege();
        printf("SeDebugPrivilege enabled=%d\n", debug_on ? 1 : 0);

        struct Probe { DWORD mask; const char* name; } probes[] = {
            { 0x1FFFFF, "ALL_ACCESS" },
            { 0x0043A,  "CREATE_THREAD|VM_OP|VM_WRITE|VM_READ|QUERY_INFO" },
            { 0x0103A,  "CREATE_THREAD|VM_OP|VM_WRITE|VM_READ|QUERY_LIMITED" },
            { 0x0042A,  "CREATE_THREAD|VM_OP|VM_WRITE|QUERY_INFO" },
            { 0x00008,  "VM_OPERATION" },
            { 0x00020,  "VM_WRITE" },
            { 0x00400,  "QUERY_INFORMATION" },
            { 0x01000,  "QUERY_LIMITED" },
        };

        auto try_masks = [&](DWORD pid, const char* label) {
            printf("--- %s (pid %lu) ---\n", label, static_cast<unsigned long>(pid));
            for (auto& p : probes) {
                SetLastError(0);
                HANDLE h = OpenProcess(p.mask, FALSE, pid);
                DWORD err = GetLastError();
                if (!h) {
                    printf("mask 0x%08lX (%-55s) -> FAIL err=%lu\n",
                           static_cast<unsigned long>(p.mask), p.name, err);
                    continue;
                }
                ULONG g = granted_access(GetCurrentProcessId(), h);
                printf("mask 0x%08lX (%-55s) -> OK granted=0x%08lX\n",
                       static_cast<unsigned long>(p.mask), p.name, g);
                CloseHandle(h);
            }
        };

        try_masks(hp, "EAC");
        DWORD gp = pid_by_name(L"FortniteClient-Win64-Shipping.exe");
        if (gp) try_masks(gp, "GAME");

        // PS_PROTECTION (PROCESSINFOCLASS 61): level/type/audit/signer
        using QIP = NTSTATUS_(__stdcall*)(HANDLE, uint32_t, void*, uint32_t, uint32_t*);
        auto qip = reinterpret_cast<QIP>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                       "NtQueryInformationProcess"));
        auto protection = [&](DWORD pid, const char* label) {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!h) { printf("%s: query open failed %lu\n", label, GetLastError()); return; }
            uint8_t prot[4]{};
            uint32_t ret = 0;
            NTSTATUS_ st = qip(h, 61, prot, sizeof(prot), &ret);
            printf("%s: status=0x%08lX level=%u type=%u audit=%u signer=%u\n",
                   label, static_cast<unsigned>(st), prot[0], prot[1], prot[2], prot[3]);
            CloseHandle(h);
        };
        protection(hp, "EAC");
        if (gp) protection(gp, "GAME");

        // Process mitigation policies (signature, dynamic code, CFG, image load)
        using GPM = BOOL(WINAPI*)(HANDLE, int, void*, SIZE_T);
        auto gpm = reinterpret_cast<GPM>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                                        "GetProcessMitigationPolicy"));
        auto policies = [&](DWORD pid, const char* label) {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!h) { printf("%s: mitigation open failed %lu\n", label, GetLastError()); return; }
            printf("--- %s mitigations ---\n", label);
            const int ps[] = { 0, 2, 6, 7, 8, 10 };
            for (int i = 0; i < 6; ++i) {
                int p = ps[i];
                DWORD v = 0;
                BOOL ok = gpm ? gpm(h, p, &v, sizeof(v)) : FALSE;
                printf("policy[%2d] = 0x%08lX%s\n", p, static_cast<unsigned long>(v),
                       ok ? "" : " (query failed)");
            }
            CloseHandle(h);
        };
        if (gpm) { policies(hp, "EAC"); if (gp) policies(gp, "GAME"); }
        else printf("GetProcessMitigationPolicy unavailable\n");
        return 0;
    }

    if (argc > 2 && lstrcmpW(argv[2], L"--selftest") == 0) {
        auto* ldr = peb::self()->Ldr;
        printf("ldr=%p want_kernel32=%08lX\n", ldr, (unsigned long)HHW(L"kernel32.dll"));
        if (ldr) {
            auto* head = reinterpret_cast<uint8_t*>(ldr) + 0x10;
            auto* cur = *reinterpret_cast<uint8_t**>(head);
            int n = 0;
            for (; cur && cur != head && n < 12; cur = *reinterpret_cast<uint8_t**>(cur), ++n) {
                auto* e = reinterpret_cast<LDR_DATA_TABLE_ENTRY_*>(cur);
                wchar_t nm[64]{};
                if (e->BaseDllName.Buffer) {
                    for (int i = 0; i < 63 && e->BaseDllName.Buffer[i]; ++i) nm[i] = e->BaseDllName.Buffer[i];
                }
                printf("mod[%d] base=%p len=%u hash=%08lX name=%ls\n", n, e->DllBase,
                       static_cast<unsigned>(e->BaseDllName.Length),
                       static_cast<unsigned long>(h::fnv1a_w(nm)), nm);
            }
        }
        void* mb = peb::module_base(HHW(L"kernel32.dll"));
        printf("kernel32 base=%p\n", mb);
        if (mb) {
            auto* b = static_cast<uint8_t*>(mb);
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER_*>(b);
            printf("MZ=%04X lfanew=%ld\n", dos->e_magic, static_cast<long>(dos->e_lfanew));
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64_*>(b + dos->e_lfanew);
            printf("PE=%08lX magic=%04X\n", static_cast<unsigned long>(nt->Signature),
                   static_cast<unsigned>(nt->OptionalHeader.Magic));
            auto& dir = nt->OptionalHeader.DataDirectory[DIR_EXPORT_];
            printf("expdir rva=%08lX size=%08lX\n",
                   static_cast<unsigned long>(dir.VirtualAddress),
                   static_cast<unsigned long>(dir.Size));
            if (dir.VirtualAddress) {
                auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY_*>(b + dir.VirtualAddress);
                printf("nfunc=%lu nnames=%lu names_rva=%08lX ords_rva=%08lX funcs_rva=%08lX\n",
                       static_cast<unsigned long>(exp->NumberOfFunctions),
                       static_cast<unsigned long>(exp->NumberOfNames),
                       static_cast<unsigned long>(exp->AddressOfNames),
                       static_cast<unsigned long>(exp->AddressOfNameOrdinals),
                       static_cast<unsigned long>(exp->AddressOfFunctions));
                auto* names = reinterpret_cast<uint32_t*>(b + exp->AddressOfNames);
                for (uint32_t i = 0; i < exp->NumberOfNames && i < 5; ++i)
                    printf("  name[%lu]=%s hash=%08lX\n", static_cast<unsigned long>(i),
                           reinterpret_cast<const char*>(b + names[i]),
                           static_cast<unsigned long>(h::fnv1a(reinterpret_cast<const char*>(b + names[i]))));
            }
        }
        void* gtp = peb::export_proc(mb, HH("GetTempPathW"));
        void* cfw = peb::export_proc(mb, HH("CreateFileW"));
        void* wf = peb::export_proc(mb, HH("WriteFile"));
        printf("GetTempPathW=%p CreateFileW=%p WriteFile=%p\n", gtp, cfw, wf);
        if (gtp) {
            wchar_t dir[260]{};
            uint32_t n = reinterpret_cast<uint32_t(__stdcall*)(uint32_t, wchar_t*)>(gtp)(260, dir);
            printf("temp n=%u path=%ls\n", n, dir);
        }
        return 0;
    }

    if (argc > 1 && lstrcmpW(argv[1], L"--access") == 0) {
        FILE* f = nullptr;
        fopen_s(&f, "C:\\dev\\fortesp\\access_probe.out", "w");
        auto out = [&](const char* fmt, ...) {
            va_list a1, a2;
            va_start(a1, fmt);
            vprintf(fmt, a1);
            va_end(a1);
            if (f) {
                va_start(a2, fmt);
                vfprintf(f, fmt, a2);
                va_end(a2);
                fflush(f);
            }
        };

        DWORD pid = pid_by_name(L"FortniteClient-Win64-Shipping.exe");
        out("self pid=%lu game pid=%lu\n",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(pid));

        HANDLE tok = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
            BYTE tb[512]{};
            DWORD tl = 0;
            if (GetTokenInformation(tok, TokenUser, tb, sizeof(tb), &tl)) {
                auto* tu = reinterpret_cast<TOKEN_USER*>(tb);
                LPWSTR sid = nullptr;
                if (ConvertSidToStringSidW(tu->User.Sid, &sid)) {
                    out("user=%ls\n", sid);
                    LocalFree(sid);
                }
            }

            BYTE gb[1024]{};
            DWORD gl = 0;
            if (GetTokenInformation(tok, TokenGroups, gb, sizeof(gb), &gl)) {
                auto* tg = reinterpret_cast<TOKEN_GROUPS*>(gb);
                for (DWORD i = 0; i < tg->GroupCount; ++i) {
                    LPWSTR sid = nullptr;
                    if (ConvertSidToStringSidW(tg->Groups[i].Sid, &sid)) {
                        out("group=%ls\n", sid);
                        LocalFree(sid);
                    }
                }
            }
            CloseHandle(tok);
        }

        if (!pid) { out("game not running\n"); if (f) fclose(f); return 1; }

        HANDLE h = OpenProcess(0x1FFFFF, FALSE, pid);
        out("OpenProcess=%p err=%lu\n", h, GetLastError());
        if (h) {
            out("granted=0x%08lX\n", granted_access(GetCurrentProcessId(), h));
            void* p = VirtualAllocEx(h, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            out("alloc=%p err=%lu\n", p, GetLastError());
            if (p) VirtualFreeEx(h, p, 0, MEM_RELEASE);
            CloseHandle(h);
        }
        if (f) fclose(f);
        return 0;
    }

    if (argc > 1 && lstrcmpW(argv[1], L"--wowprobe") == 0) {
        const wchar_t* host = argc > 2 ? argv[2] : L"EasyAntiCheat_EOS.exe";
        DWORD hp = pid_by_name(host);
        printf("host=%ls pid=%lu\n", host, static_cast<unsigned long>(hp));
        if (!hp) return 1;

        printf("SeDebugPrivilege=%d\n", enable_debug_privilege() ? 1 : 0);

        // --- Elevation check: err=5 is only interpretable once we know
        // whether this process is elevated (unelevated vs protected). ---
        {
            HANDLE tok = nullptr;
            DWORD elevated = 0;
            BOOL have_tok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok);
            if (have_tok) {
                TOKEN_ELEVATION te{};
                DWORD tl = sizeof(te);
                if (GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &tl)) {
                    elevated = te.TokenIsElevated;
                }
                CloseHandle(tok);
            }
            printf("elevated=%d tok=%d\n", elevated ? 1 : 0, have_tok ? 1 : 0);
        }

        HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hp);
        printf("open host=%p err=%lu\n", ph, GetLastError());
        // Continue even if PROCESS_ALL_ACCESS fails — the probe gathers
        // granted-mask and open-path data even without full rights.
        if (!ph) ph = nullptr;

        // Read-only fallback: PROCESS_QUERY_LIMITED_INFORMATION is enough for
        // IsWow64Process and GetProcessMitigationPolicy, so the probe still
        // reports the host architecture and mitigations when the full mask
        // is denied (unelevated run).
        HANDLE h_lim = nullptr;
        if (!ph) {
            h_lim = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, hp);
            printf("open_limited host=%p err=%lu\n", h_lim, GetLastError());
        }

        BOOL wow = FALSE;
        HANDLE wow_handle = ph ? ph : h_lim;
        if (!wow_handle) {
            // IsWow64Process(NULL, ...) silently fails and reports a
            // perfectly good 32-bit host as wow64=0.
            printf("wow64=unknown (no handle to host)\n");
        } else {
            if (!IsWow64Process(wow_handle, &wow)) {
                printf("wow64=query_failed err=%lu\n", GetLastError());
            } else {
                printf("wow64=%d\n", wow ? 1 : 0);
            }
        }

        uint64_t peb32 = 0;
        uint32_t ret = 0;
        using QIP = NTSTATUS_(__stdcall*)(HANDLE, uint32_t, void*, uint32_t, uint32_t*);
        auto qip = reinterpret_cast<QIP>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
        NTSTATUS_ st = qip(ph, 26, &peb32, sizeof(peb32), &ret);
        printf("peb32=0x%llX st=0x%08lX\n",
               static_cast<unsigned long long>(peb32), static_cast<unsigned>(st));

        uint32_t k32 = wow_module32(ph, peb32, L"kernel32.dll");
        printf("kernel32_32=0x%X\n", k32);
        if (!k32) printf("warning: kernel32 32-bit module not found\n");

        uint32_t p_open = wow_export32(ph, k32, "OpenProcess");
        uint32_t p_alloc = wow_export32(ph, k32, "VirtualAllocEx");
        uint32_t p_gle = wow_export32(ph, k32, "GetLastError");
        printf("OpenProcess=0x%X VirtualAllocEx=0x%X GetLastError=0x%X\n", p_open, p_alloc, p_gle);

        // --- Granted mask via NtQueryObject on the game process ---
        DWORD game = pid_by_name(argc > 3 ? argv[3] : L"FortniteClient-Win64-Shipping.exe");
        printf("game pid=%lu\n", static_cast<unsigned long>(game));

        NtQueryObjectFn nqobj = nt_query_object();
        if (!nqobj) printf("warning: NtQueryObject not exported by ntdll\n");

        HANDLE gh = nullptr;
        ULONG granted_mask = 0;
        if (game) {
            gh = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, game);
            if (gh) {
                // NtQueryObject with ObjectBasicInformation (info class 0).
                // The kernel is strict about the length, so the accepted size
                // is discovered at run time.
                granted_mask = query_granted_access(gh, nqobj, "game");
                if (granted_mask) {
                    printf("granted_mask=0x%08lX (via NtQueryObject ObjectBasicInformation)\n",
                           static_cast<unsigned long>(granted_mask));
                }
                CloseHandle(gh);
            } else {
                printf("open game failed %lu\n", GetLastError());
            }
        }

        if (!game) { printf("granted_mask=0 err=game_not_found\n"); }

        // --- Mitigation policies for EAC and game ---
        using GPM = BOOL(WINAPI*)(HANDLE, int, void*, SIZE_T);
        auto gpm = reinterpret_cast<GPM>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                                         "GetProcessMitigationPolicy"));
        auto query_policies = [&](HANDLE h, const char* label) {
            if (!gpm) { printf("%s: GetProcessMitigationPolicy unavailable\n", label); return; }
            if (!h) { printf("--- %s mitigations ---\nno handle\n", label); return; }
            printf("--- %s mitigations ---\n", label);
            // Policy indices: 0=MitigationPolicies, 2=ACG/DynamicCode, 6=ImageLoad, 7=CFG, 8=Signature, 10=StrictCriteria,
            const int ps[] = { 0, 2, 6, 7, 8, 10 };
            for (int i = 0; i < 6; ++i) {
                DWORD v = 0;
                BOOL ok = gpm(h, ps[i], &v, sizeof(v));
                printf("policy[%2d] = 0x%08lX%s\n", ps[i], static_cast<unsigned long>(v),
                       ok ? "" : " (query failed)");
            }
        };
        query_policies(ph ? ph : h_lim, "EAC");
        if (game) {
            HANDLE gh2 = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, game);
            if (gh2) { query_policies(gh2, "GAME"); CloseHandle(gh2); }
        }

        // --- Both open paths: full mask and the EAC whitelist mask ---
        // NtOpenProcess is used so the real NTSTATUS is reported instead of a
        // Win32 error code; each path also prints the mask the kernel granted.
        using NtOpenProcessFn = NTSTATUS_(NTAPI*)(HANDLE*, ACCESS_MASK,
                                                   OBJECT_ATTRIBUTES_*, CLIENT_ID_*);
        auto nop = reinterpret_cast<NtOpenProcessFn>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess"));

        auto probe_open = [&](DWORD target_pid, ACCESS_MASK mask, const char* label) {
            HANDLE h = nullptr;
            NTSTATUS_ sts = static_cast<NTSTATUS_>(-1);
            if (nop) {
                OBJECT_ATTRIBUTES_ oa{};
                CLIENT_ID_ cid{};
                cid.UniqueProcess = target_pid;
                cid.UniqueThread = 0;
                oa.Length = sizeof(oa);
                sts = nop(&h, mask, &oa, &cid);
            } else {
                h = OpenProcess(mask, FALSE, target_pid);
                sts = h ? STATUS_SUCCESS : static_cast<NTSTATUS_>(GetLastError());
            }
            ULONG granted = 0;
            if (h) {
                granted = query_granted_access(h, nqobj, label);
                printf("open_path %s pid=%lu mask=0x%08lX handle=%p ntstatus=0x%08lX granted=0x%08lX\n",
                       label, static_cast<unsigned long>(target_pid),
                       static_cast<unsigned long>(mask), h,
                       static_cast<unsigned long>(sts), static_cast<unsigned long>(granted));
            } else {
                printf("open_path %s pid=%lu mask=0x%08lX handle=null ntstatus=0x%08lX\n",
                       label, static_cast<unsigned long>(target_pid),
                       static_cast<unsigned long>(mask), static_cast<unsigned long>(sts));
            }
            return h;
        };

        probe_open(hp, PROCESS_ALL_ACCESS, "EAC ALL_ACCESS");
        probe_open(hp, 0x11F145, "EAC 0x11F145");

        if (game) {
            probe_open(game, PROCESS_ALL_ACCESS, "GAME ALL_ACCESS");
            probe_open(game, 0x11F145, "GAME 0x11F145");
            // Minimum rights a classic injector needs: VM op/write/read plus
            // thread creation.
            probe_open(game, 0x0008 | 0x0010 | 0x0020 | 0x0004, "GAME vm+thread");

            // Does the mask we hold actually allow VM operations on the game?
            HANDLE hg = OpenProcess(PROCESS_ALL_ACCESS, FALSE, game);
            if (hg) {
                void* mem = VirtualAllocEx(hg, nullptr, 0x1000,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                printf("game vm alloc=%p err=%lu\n", mem, GetLastError());
                if (mem) VirtualFreeEx(hg, mem, 0, MEM_RELEASE);
                CloseHandle(hg);
            } else {
                printf("game vm alloc skipped: no full handle (err=%lu)\n", GetLastError());
            }
        }

        // --- Build and run the stub (existing logic continues below) ---
        // The stub is 32-bit code and addresses everything with absolute
        // imm32, so the allocation must land below 4 GB. Reserve with a low
        // hint instead of letting the allocator choose.
        uint8_t* code = nullptr;
        if (ph) {
            static const ULONG_PTR kHints[] = { 0x10000000, 0x18000000, 0x20000000,
                                                0x28000000, 0x30000000, 0x40000000,
                                                0x50000000 };
            for (size_t i = 0; i < _countof(kHints); ++i) {
                code = static_cast<uint8_t*>(
                    VirtualAllocEx(ph, reinterpret_cast<LPVOID>(kHints[i]), 0x2000,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
                if (code) break;
            }
            printf("stub alloc=%p err=%lu\n", code, GetLastError());
            if (code && (reinterpret_cast<uintptr_t>(code) + 0x2000ull) > 0xFFFFFFFFull) {
                printf("stub alloc too high for 32-bit imm32 addressing: %p\n", code);
                VirtualFreeEx(ph, code, 0, MEM_RELEASE);
                code = nullptr;
            }
        } else {
            printf("stub alloc skipped: no host handle\n");
        }
        if (!code) { if (ph) CloseHandle(ph); return 1; }

        // The stub writes its results back, so the results live on their own
        // read-write page; only the code page is flipped to execute-read.
        uint32_t buf = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(code)) + 0x1000;
        std::vector<uint8_t> b;
        auto imm32 = [&](uint32_t v) {
            b.push_back(v & 0xFF);
            b.push_back((v >> 8) & 0xFF);
            b.push_back((v >> 16) & 0xFF);
            b.push_back((v >> 24) & 0xFF);
        };

        // 32-bit ntdll gives the stub NtQueryObject so it can report the
        // access mask the kernel actually granted EAC on the game.
        uint32_t n32 = wow_module32(ph, peb32, L"ntdll.dll");
        uint32_t p_ntq = wow_export32(ph, n32, "NtQueryObject");
        printf("ntdll_32=0x%X NtQueryObject=0x%X\n", n32, p_ntq);

        // Result block (32-bit, in the data page):
        //   [0x00] handle  = OpenProcess(game, PROCESS_ALL_ACCESS)
        //   [0x04] status  = NtQueryObject status for that handle
        //   [0x08] granted = access mask the kernel granted on that handle
        //   [0x0C] alloc   = VirtualAllocEx result with that handle
        //   [0x10] lasterr = GetLastError after that VirtualAllocEx
        //   [0x14] handle_w = OpenProcess(game, 0x11F145)
        //   [0x18] granted_w = access mask granted on the 0x11F145 handle
        //   [0x1C] status_w  = NtQueryObject status for that handle
        //   [0x20] alloc_w   = VirtualAllocEx result with the 0x11F145 handle
        //   [0x24] lasterr_w = GetLastError after that VirtualAllocEx
        //   [0x40] OBJECT_BASIC_INFORMATION buffer (56 bytes)
        //   [0x60] second OBJECT_BASIC_INFORMATION buffer (56 bytes)

        b.push_back(0x68); imm32(game);        // push game pid
        b.push_back(0x6A); b.push_back(0x00);  // push 0 (bInheritHandle)
        b.push_back(0x68); imm32(0x1FFFFF);    // push PROCESS_ALL_ACCESS
        b.push_back(0xB8); imm32(p_open);      // mov eax, OpenProcess
        b.push_back(0xFF); b.push_back(0xD0);  // call eax
        b.push_back(0xA3); imm32(buf + 0x00);  // mov [buf+0x00], eax

        if (p_ntq) {
            // NtQueryObject(handle, 0, buf+0x40, 56, &need)
            b.push_back(0x68); imm32(buf + 0x58);  // push &need
            b.push_back(0x68); imm32(56);          // push length
            b.push_back(0x68); imm32(buf + 0x40);  // push ObjectInformation
            b.push_back(0x6A); b.push_back(0x00);  // push class 0
            b.push_back(0xFF); b.push_back(0x35); imm32(buf + 0x00);  // push [buf]
            b.push_back(0xB8); imm32(p_ntq);        // mov eax, NtQueryObject
            b.push_back(0xFF); b.push_back(0xD0);    // call eax
            b.push_back(0xA3); imm32(buf + 0x04);    // mov [buf+0x04], eax
            b.push_back(0xA1); imm32(buf + 0x44);    // mov eax, [buf+0x44] (granted)
            b.push_back(0xA3); imm32(buf + 0x08);    // mov [buf+0x08], eax
        }

        b.push_back(0x6A); b.push_back(0x04);  // PAGE_READWRITE
        b.push_back(0x68); imm32(0x3000);      // MEM_COMMIT|MEM_RESERVE
        b.push_back(0x68); imm32(0x1000);      // 4 KB
        b.push_back(0x6A); b.push_back(0x00);  // lpAddress = 0
        b.push_back(0xFF); b.push_back(0x35); imm32(buf + 0x00);  // push [buf]
        b.push_back(0xB8); imm32(p_alloc);     // mov eax, VirtualAllocEx
        b.push_back(0xFF); b.push_back(0xD0);  // call eax
        b.push_back(0xA3); imm32(buf + 0x0C);  // mov [buf+0x0C], eax

        b.push_back(0xB8); imm32(p_gle);       // mov eax, GetLastError
        b.push_back(0xFF); b.push_back(0xD0);  // call eax
        b.push_back(0xA3); imm32(buf + 0x10);  // mov [buf+0x10], eax

        // --- same again with the whitelist mask 0x11F145 ---
        b.push_back(0x68); imm32(game);        // push game pid
        b.push_back(0x6A); b.push_back(0x00);  // push 0
        b.push_back(0x68); imm32(0x11F145);    // push 0x11F145
        b.push_back(0xB8); imm32(p_open);      // mov eax, OpenProcess
        b.push_back(0xFF); b.push_back(0xD0);  // call eax
        b.push_back(0xA3); imm32(buf + 0x14);  // mov [buf+0x14], eax

        if (p_ntq) {
            b.push_back(0x68); imm32(buf + 0x5C);  // push &need
            b.push_back(0x68); imm32(56);          // push length
            b.push_back(0x68); imm32(buf + 0x60);  // push ObjectInformation
            b.push_back(0x6A); b.push_back(0x00);  // push class 0
            b.push_back(0xFF); b.push_back(0x35); imm32(buf + 0x14);  // push [buf+0x14]
            b.push_back(0xB8); imm32(p_ntq);        // mov eax, NtQueryObject
            b.push_back(0xFF); b.push_back(0xD0);    // call eax
            b.push_back(0xA3); imm32(buf + 0x1C);    // mov [buf+0x1C], eax
            b.push_back(0xA1); imm32(buf + 0x64);    // mov eax, [buf+0x64] (granted)
            b.push_back(0xA3); imm32(buf + 0x18);    // mov [buf+0x18], eax
        }

        b.push_back(0x6A); b.push_back(0x04);  // PAGE_READWRITE
        b.push_back(0x68); imm32(0x3000);      // MEM_COMMIT|MEM_RESERVE
        b.push_back(0x68); imm32(0x1000);      // 4 KB
        b.push_back(0x6A); b.push_back(0x00);  // lpAddress = 0
        b.push_back(0xFF); b.push_back(0x35); imm32(buf + 0x14);  // push [buf+0x14]
        b.push_back(0xB8); imm32(p_alloc);     // mov eax, VirtualAllocEx
        b.push_back(0xFF); b.push_back(0xD0);  // call eax
        b.push_back(0xA3); imm32(buf + 0x20);  // mov [buf+0x20], eax

        b.push_back(0xB8); imm32(p_gle);       // mov eax, GetLastError
        b.push_back(0xFF); b.push_back(0xD0);  // call eax
        b.push_back(0xA3); imm32(buf + 0x24);  // mov [buf+0x24], eax

        b.push_back(0x33); b.push_back(0xC0);  // xor eax, eax
        b.push_back(0xC3);                     // ret

        printf("stub len=%u\n", static_cast<unsigned>(b.size()));
        WriteProcessMemory(ph, code, b.data(), b.size(), nullptr);

        // Flip to execute-only-read: a writable+executable page trips ACG
        // and is rejected by hardened processes.
        {
            DWORD old_prot = 0;
            BOOL pok = VirtualProtectEx(ph, code, 0x1000, PAGE_EXECUTE_READ, &old_prot);
            printf("stub protect RX=%d err=%lu\n", pok ? 1 : 0, GetLastError());
        }

        using SPVCT = BOOL(__stdcall*)(HANDLE, void*, SIZE_T, ULONG, void*);
        auto spv = reinterpret_cast<SPVCT>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetProcessValidCallTargets"));
        if (!spv) {
            spv = reinterpret_cast<SPVCT>(
                GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "SetProcessValidCallTargets"));
            if (spv) printf("cfg api from ntdll\n");
        }
        if (spv) {
            // Register the stub entry as a valid CFG call target: EAC runs
            // with Control Flow Guard enabled (policy[7] = 1), so an
            // unregistered indirect call target kills the thread.
            struct CFG_CTI {
                ULONG  Flags;
                ULONG  Target;
                ULONG  FunctionCount;
                PVOID  Targets;
                ULONG  Metadata;
                ULONG  ProcessTag;
            } info{};
            ULONG target = static_cast<ULONG>(reinterpret_cast<uintptr_t>(code));
            info.Flags = 0;
            info.Target = target;
            info.FunctionCount = 1;
            info.Targets = &target;
            info.Metadata = 0;
            info.ProcessTag = 0;
            BOOL ok = spv(ph, nullptr, 0, 0, &info);
            printf("cfg mark=%d err=%lu\n", ok ? 1 : 0, GetLastError());
        } else {
            printf("no SetProcessValidCallTargets\n");
        }

        HANDLE th = CreateRemoteThread(ph, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(code),
                                       nullptr, 0, nullptr);
        printf("thread=%p err=%lu\n", th, GetLastError());
        uint32_t res[10]{};
        bool stub_ok = false;
        auto print_stub_results = [&](const char* tag, const uint32_t* r) {
            printf("%s handle=0x%X granted=0x%08lX ntq_status=0x%08lX alloc=0x%X lasterr=%lu\n",
                   tag, r[0], static_cast<unsigned long>(r[2]),
                   static_cast<unsigned long>(r[1]), r[3], static_cast<unsigned long>(r[4]));
            printf("%s whitelist_handle=0x%X whitelist_granted=0x%08lX whitelist_ntq=0x%08lX "
                   "whitelist_alloc=0x%X whitelist_lasterr=%lu\n",
                   tag, r[5], static_cast<unsigned long>(r[6]),
                   static_cast<unsigned long>(r[7]), r[8], static_cast<unsigned long>(r[9]));
        };
        if (th) {
            WaitForSingleObject(th, 10000);
            DWORD ec = 0;
            GetExitCodeThread(th, &ec);

            ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(buf)), res, sizeof(res), nullptr);
            printf("thread exit=0x%08lX\n", static_cast<unsigned>(ec));
            print_stub_results("stub", res);
            stub_ok = (res[0] != 0);
            CloseHandle(th);
        }

        // --- Fallback: WOW64 thread start ---
        // A 64 bit caller that starts a thread in a 32 bit process can end up
        // with a startup context NtContinue cannot restore. The reliable route
        // is a thread created suspended (THREAD_CREATE_FLAGS_SUSPENDED = 0x2,
        // not 0x1), a real 32 bit stack, a WOW64 context installed with
        // Wow64SetThreadContext, and only then a resume.
        //
        // Three things had to be fixed before any of it worked, and each one
        // is measured in docs/SESSION_NOTES.md:
        //   * a hint below 0x10000000 can already be mapped in the host -
        //     the allocation is slid forward until it is accepted;
        //   * the handle CreateRemoteThread/NtCreateThreadEx return is not a
        //     usable handle for the context APIs (STATUS_ACCESS_VIOLATION);
        //     a DUP_HANDLE duplicate of the same entry is;
        //   * NtSetContextThread is the wrong API for a WOW64 thread from a
        //     64 bit caller - Wow64SetThreadContext accepts the same block.
        if (!stub_ok && wow) {
            printf("--- wow64 fallback: suspended thread + Wow64SetThreadContext ---\n");

            using NtCTE = NTSTATUS_(NTAPI*)(HANDLE*, ACCESS_MASK, void*, HANDLE, void*,
                                            void*, ULONG, SIZE_T, SIZE_T, SIZE_T, void*);
            HMODULE nt_dll = GetModuleHandleW(L"ntdll.dll");
            auto cte = reinterpret_cast<NtCTE>(GetProcAddress(nt_dll, "NtCreateThreadEx"));

            // Low, page aligned pages in the host for the 32 bit stack, the
            // stub's code and its result block. A hint the host already has
            // mapped is refused with STATUS_CONFLICTING_ADDRESSES, so each
            // block slides past the hints until the allocation sticks.
            auto alloc_low = [&](ULONG_PTR first, SIZE_T size, const char* what) -> void* {
                for (ULONG_PTR at = first; at < first + 0x2000000; at += 0x10000) {
                    void* p = VirtualAllocEx(ph, reinterpret_cast<LPVOID>(at), size,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (p) return p;
                }
                printf("wow64 %s alloc failed err=%lu\n", what, GetLastError());
                return nullptr;
            };

            // The thread's own stack: 0x80000 below a fresh top. A garbage
            // thread has no stack to borrow - pointing Esp into the host's
            // existing stack area (0x00030000) is answered with
            // STATUS_BAD_STACK when the thread is resumed.
            constexpr uint32_t kStackSize = 0x80000;
            void* stack32 = alloc_low(0x00030000, kStackSize, "stack");

            // A 32 bit thread needs a TEB of its own: the kernel start context
            // carries one, an arbitrary entry point does not. Without it the
            // thread is started with a stack whose TEB fields are whatever the
            // page happened to hold, and dies before the first instruction
            // (measured: exit 0x103, or 0xC0000028 for a stack the kernel will
            // not accept). The TEB is 0x1000 bytes, its ExceptionList and
            // StackBase/StackLimit are the only fields that matter here.
            void* teb32 = alloc_low(0x00200000, 0x1000, "teb");

            // The 32 bit stub needs a page below 4 GB for its imm32 calls;
            // data lives on the second page so the code page stays RX.
            uint8_t* code32 = static_cast<uint8_t*>(alloc_low(0x00100000, 0x2000, "stub"));
            printf("wow64 stack=%p (%u bytes) teb=%p stub=%p\n", stack32, kStackSize, teb32, code32);

            if (stack32 && teb32 && code32) {
                // TEB_32: ExceptionList at 0x00, StackBase at 0x04,
                // StackLimit at 0x08, Self at 0x18, TlsSlots after 0xE0.
                uint8_t teb_bytes[0x1000]{};
                uint32_t teb_addr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(teb32));
                uint32_t stk_base = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(stack32)) + kStackSize;
                uint32_t stk_limit = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(stack32));
                auto put32 = [&](uint32_t off, uint32_t v) {
                    teb_bytes[off + 0] = v & 0xFF;
                    teb_bytes[off + 1] = (v >> 8) & 0xFF;
                    teb_bytes[off + 2] = (v >> 16) & 0xFF;
                    teb_bytes[off + 3] = (v >> 24) & 0xFF;
                };
                put32(0x00, 0xFFFFFFFFu);        // ExceptionList: end of chain
                put32(0x04, stk_base);
                put32(0x08, stk_limit);
                put32(0x0C, 0);                  // SubSystemTib
                put32(0x10, 0xFFFFFFFFu);        // FiberData
                put32(0x14, 0xFFFFFFFFu);        // ArbitraryUserPointer
                put32(0x18, teb_addr);           // Self
                put32(0x20, 0);                  // EnvironmentPointer
                put32(0x24, static_cast<uint32_t>(hp));  // ClientId.UniqueProcess
                WriteProcessMemory(ph, teb32, teb_bytes, sizeof(teb_bytes), nullptr);
                printf("wow64 teb: self=0x%08lX stack base=0x%08lX limit=0x%08lX\n",
                       teb_addr, stk_base, stk_limit);

                uint32_t stub_addr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(code32));
                uint32_t buf = stub_addr + 0x1000;

                // The same stub, rebuilt for this page, so the fallback does
                // not depend on the page the first attempt happened to get.
                std::vector<uint8_t> body;
                auto imm = [&](uint32_t v) {
                    body.push_back(v & 0xFF); body.push_back((v >> 8) & 0xFF);
                    body.push_back((v >> 16) & 0xFF); body.push_back((v >> 24) & 0xFF);
                };
                auto call_into = [&](uint32_t fn) {
                    body.push_back(0xB8); imm(fn);              // mov eax, fn
                    body.push_back(0xFF); body.push_back(0xD0); // call eax
                };
                // OpenProcess(game, ALL_ACCESS)
                body.push_back(0x68); imm(game);
                body.push_back(0x6A); body.push_back(0x00);
                body.push_back(0x68); imm(0x1FFFFF);
                call_into(p_open);
                body.push_back(0xA3); imm(buf + 0x00);
                // NtQueryObject(handle, 0, buf+0x40, 56, &need) -> status, granted
                if (p_ntq) {
                    body.push_back(0x68); imm(buf + 0x58);
                    body.push_back(0x68); imm(56);
                    body.push_back(0x68); imm(buf + 0x40);
                    body.push_back(0x6A); body.push_back(0x00);
                    body.push_back(0xFF); body.push_back(0x35); imm(buf + 0x00);
                    call_into(p_ntq);
                    body.push_back(0xA3); imm(buf + 0x04);
                    body.push_back(0xA1); imm(buf + 0x44);
                    body.push_back(0xA3); imm(buf + 0x08);
                }
                // VirtualAllocEx(handle, 0, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
                body.push_back(0x6A); body.push_back(0x04);
                body.push_back(0x68); imm(0x3000);
                body.push_back(0x68); imm(0x1000);
                body.push_back(0x6A); body.push_back(0x00);
                body.push_back(0xFF); body.push_back(0x35); imm(buf + 0x00);
                call_into(p_alloc);
                body.push_back(0xA3); imm(buf + 0x0C);
                call_into(p_gle);
                body.push_back(0xA3); imm(buf + 0x10);
                // ... and the same two calls on a 0x11F145 handle
                body.push_back(0x68); imm(game);
                body.push_back(0x6A); body.push_back(0x00);
                body.push_back(0x68); imm(0x11F145);
                call_into(p_open);
                body.push_back(0xA3); imm(buf + 0x14);
                if (p_ntq) {
                    body.push_back(0x68); imm(buf + 0x5C);
                    body.push_back(0x68); imm(56);
                    body.push_back(0x68); imm(buf + 0x60);
                    body.push_back(0x6A); body.push_back(0x00);
                    body.push_back(0xFF); body.push_back(0x35); imm(buf + 0x14);
                    call_into(p_ntq);
                    body.push_back(0xA3); imm(buf + 0x1C);
                    body.push_back(0xA1); imm(buf + 0x64);
                    body.push_back(0xA3); imm(buf + 0x18);
                }
                body.push_back(0x6A); body.push_back(0x04);
                body.push_back(0x68); imm(0x3000);
                body.push_back(0x68); imm(0x1000);
                body.push_back(0x6A); body.push_back(0x00);
                body.push_back(0xFF); body.push_back(0x35); imm(buf + 0x14);
                call_into(p_alloc);
                body.push_back(0xA3); imm(buf + 0x20);
                call_into(p_gle);
                body.push_back(0xA3); imm(buf + 0x24);
                body.push_back(0x33); body.push_back(0xC0); // xor eax, eax
                body.push_back(0xC3);                        // ret

                WriteProcessMemory(ph, code32, body.data(), body.size(), nullptr);

                // The stub returns into the host's own ExitThread, at the top
                // of the new stack.
                uint32_t exit_thunk = wow_export32(ph, k32, "ExitThread");
                uint32_t stack_top = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(stack32)) + kStackSize;
                stack_top &= ~0xFu;
                uint32_t frame[2] = { exit_thunk, 0 };
                WriteProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(stack_top - 8)),
                                   frame, sizeof(frame), nullptr);

                // The context a 32 bit thread has on x64: CS/SS/DS/ES = 0x23,
                // FS = 0x53, GS = 0x2B. Anything else makes the kernel fault
                // while it applies the context.
                WOW64_CONTEXT_ c{};
                c.ContextFlags = WOW64_CONTEXT_CONTROL_;
                c.SegCs = c.SegSs = c.SegDs = c.SegEs = 0x23;
                c.SegFs = 0x53;
                c.SegGs = 0x2B;
                c.EFlags = 0x246;                 // IF set
                // Ebx is left at 0 on purpose: WOW64SetupException / the
                // WOW64 thunk reads the TEB from the thread's own kernel
                // structure and a TEB that is not the kernel's is worse than
                // none. The block is still mapped and printed so the values
                // the stub would see are on the record.
                c.Eip = stub_addr;
                c.Esp = stack_top - 8;
                c.Ebp = 0;

                // ProcessHandle is the host's real handle: 0 and (HANDLE)-1 are
                // both rejected with STATUS_INVALID_PARAMETER, ph is not.
                HANDLE th2 = nullptr;
                NTSTATUS_ st2 = cte(&th2, 0x1FFFFF, nullptr, ph,
                                    reinterpret_cast<void*>(static_cast<uintptr_t>(stub_addr)),
                                    nullptr, 2 /* THREAD_CREATE_FLAGS_SUSPENDED */,
                                    0, 0, 0, nullptr);
                if (st2 == static_cast<NTSTATUS_>(0xC000000D)) {
                    // A stale process handle is the usual cause at this point.
                    CloseHandle(ph);
                    ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hp);
                    printf("wow64 diag: host reopened=%p err=%lu\n", ph, GetLastError());
                    if (ph)
                        st2 = cte(&th2, 0x1FFFFF, nullptr, ph,
                                  reinterpret_cast<void*>(static_cast<uintptr_t>(stub_addr)),
                                  nullptr, 2, 0, 0, 0, nullptr);
                }
                printf("wow64 NtCreateThreadEx status=0x%08lX thread=%p (%s)\n",
                       static_cast<unsigned>(st2), th2, rst_to_text(static_cast<unsigned>(st2)));

                if (th2) {
                    // Both handles are tried, because which one the context
                    // calls accept is exactly the question:
                    //   raw   what NtCreateThreadEx returned
                    //   dup   the same entry duplicated with DUP_HANDLE
                    // Only "dup" has been seen accepted (docs/SESSION_NOTES.md);
                    // the raw one is kept as the second attempt so a build
                    // where the raw handle works does not regress.
                    HANDLE dup = dup_local_thread_handle(th2);
                    HANDLE tries[2] = { dup, th2 };
                    BOOL applied = FALSE;
                    bool used_dup = true;
                    for (int i = 0; i < 2 && !applied; ++i) {
                        HANDLE h = tries[i];
                        if (!h) continue;
                        SetLastError(0);
                        applied = Wow64SetThreadContext(h, reinterpret_cast<WOW64_CONTEXT*>(&c));
                        DWORD err = GetLastError();
                        printf("wow64 Wow64SetThreadContext[%s]=%d err=%lu\n",
                               i == 0 ? "dup" : "raw", applied ? 1 : 0, err);
                        if (applied) { used_dup = (i == 0); }
                    }
                    if (applied) {
                        if (used_dup) th2 = dup;
                        else if (dup) CloseHandle(dup);
                    }
                    printf("wow64 thread handle=%p (%s)\n", th2, used_dup ? "duplicate" : "raw");
                    BOOL wok = applied;

                    // Read the context back and print what the thread is about
                    // to execute: a stack fault is visible here first.
                    {
                        WOW64_CONTEXT_ got{};
                        got.ContextFlags = WOW64_CONTEXT_CONTROL_;
                        SetLastError(0);
                        BOOL gok = Wow64GetThreadContext(th2, reinterpret_cast<WOW64_CONTEXT*>(&got));
                        printf("wow64 thread context: ok=%d err=%lu eip=0x%08lX esp=0x%08lX "
                               "cs=0x%X ss=0x%X fs=0x%X eflags=0x%08lX\n",
                               gok ? 1 : 0, GetLastError(),
                               static_cast<unsigned>(got.Eip), static_cast<unsigned>(got.Esp),
                               got.SegCs, got.SegSs, got.SegFs, static_cast<unsigned>(got.EFlags));
                        if (gok && got.Eip != stub_addr) {
                            printf("wow64 warning: eip is not the stub (0x%08lX != 0x%08lX)\n",
                                   static_cast<unsigned>(got.Eip), stub_addr);
                        }
                    }

                    if (!wok) {
                        printf("wow64 fallback refused: the thread context could not be installed\n");
                    }
                    // Read the entry's code before anything runs: a WOW64
                    // entry must be 32 bit code the CPU can execute from 64
                    // bit mode as well, and the byte at 0x00100000 is the
                    // first thing to look at when a thread dies silently.
                    {
                        uint8_t head[16]{};
                        SIZE_T hg = 0;
                        ReadProcessMemory(ph, code32, head, sizeof(head), &hg);
                        printf("wow64 stub bytes:");
                        for (SIZE_T i = 0; i < hg; ++i) printf(" %02X", head[i]);
                        printf("\n");
                        MEMORY_BASIC_INFORMATION mbi{};
                        SIZE_T qn = VirtualQueryEx(ph, code32, &mbi, sizeof(mbi));
                        printf("wow64 stub region: query=%llu state=0x%lX protect=0x%lX type=0x%lX\n",
                               static_cast<unsigned long long>(qn),
                               static_cast<unsigned long>(mbi.State),
                               static_cast<unsigned long>(mbi.Protect),
                               static_cast<unsigned long>(mbi.Type));

                        // Leave the entry as 64 bit code: a 64 bit thread that
                        // starts at the same page and runs the same two calls
                        // is what tells a WOW64 problem from a stub problem.
                        {
                            std::vector<uint8_t> x64;
                            auto i64 = [&](uint64_t v) {
                                for (int k = 0; k < 8; ++k) x64.push_back((v >> (8 * k)) & 0xFF);
                            };
                            auto call64 = [&](uint64_t fn) {
                                x64.push_back(0x48); x64.push_back(0xB8); i64(fn);  // mov rax, fn
                                x64.push_back(0xFF); x64.push_back(0xD0);          // call rax
                            };
                            x64.push_back(0x48); x64.push_back(0x83); x64.push_back(0xEC); x64.push_back(0x28);
                            x64.push_back(0x48); x64.push_back(0xB9); i64(game);  // mov rcx, pid
                            x64.push_back(0x48); x64.push_back(0xBA); i64(0x1FFFFF); // mov rdx, mask
                            x64.push_back(0x45); x64.push_back(0x33); x64.push_back(0xC0); // xor r8d,r8d
                            call64(reinterpret_cast<uint64_t>(GetProcAddress(
                                GetModuleHandleW(L"kernel32.dll"), "OpenProcess")));
                            x64.push_back(0x48); x64.push_back(0xBB); i64(buf + 0x00); // mov rbx, buf
                            x64.push_back(0x48); x64.push_back(0x89); x64.push_back(0x03); // mov [rbx], rax
                            // VirtualAllocEx(handle, 0, 0x1000, 0x3000, 4)
                            x64.push_back(0x48); x64.push_back(0x89); x64.push_back(0xC1); // mov rcx, rax
                            x64.push_back(0x48); x64.push_back(0x31); x64.push_back(0xD2); // xor rdx, rdx
                            x64.push_back(0x49); x64.push_back(0xC7); x64.push_back(0xC0); i64(0x1000);
                            x64.push_back(0x49); x64.push_back(0xC7); x64.push_back(0xC1); i64(0x3000);
                            x64.push_back(0x48); x64.push_back(0xC7); x64.push_back(0xC0); i64(4);
                            x64.push_back(0x48); x64.push_back(0x89); x64.push_back(0x44); x64.push_back(0x24); x64.push_back(0x20);
                            call64(reinterpret_cast<uint64_t>(GetProcAddress(
                                GetModuleHandleW(L"kernel32.dll"), "VirtualAllocEx")));
                            x64.push_back(0x48); x64.push_back(0x89); x64.push_back(0x43); x64.push_back(0x0C); // mov [rbx+0x0C], rax
                            x64.push_back(0x31); x64.push_back(0xC0);  // xor eax, eax
                            x64.push_back(0x48); x64.push_back(0x83); x64.push_back(0xC4); x64.push_back(0x28);
                            x64.push_back(0xC3);                       // ret

                            // The 64 bit stub lives on its own page, below 4 GB,
                            // so both attempts share the same buffer.
                            uint8_t* code64 = nullptr;
                            for (ULONG_PTR at = 0x01000000; at < 0x02000000 && !code64; at += 0x10000) {
                                code64 = static_cast<uint8_t*>(VirtualAllocEx(
                                    ph, reinterpret_cast<LPVOID>(at), 0x2000,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
                            }
                            if (code64) {
                                uint32_t b64 = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(code64)) + 0x1000;
                                printf("wow64 x64 control stub=%p buffer=0x%08lX len=%u\n",
                                       code64, b64, static_cast<unsigned>(x64.size()));
                                WriteProcessMemory(ph, code64, x64.data(), x64.size(), nullptr);
                                DWORD op = 0;
                                VirtualProtectEx(ph, code64, 0x1000, PAGE_EXECUTE_READ, &op);
                                // buf is baked as the 32 bit address above; the
                                // 64 bit stub writes there, which is inside the
                                // same low region.
                                // A control, so the stub's own start has to
                                // come from the kernel: ntdll's RtlExitUserThread
                                // takes the exit status as its only argument and
                                // is the start a CreateRemoteThread is meant to
                                // use. Running *our* bytes there is a second
                                // question and is tried only if this one runs.
                                FARPROC rtl_exit = nullptr;
                                // ntdll's RtlExitUserThread is exported from
                                // the 64 bit ntdll; a 32 bit process needs the
                                // same routine out of its own kernel32.
                                uint32_t k32_ = wow_module32(ph, peb32, L"kernel32.dll");
                                uint32_t exit32 = wow_export32(ph, k32_, "ExitThread");
                                printf("wow64 x64 control: ExitThread(32)=0x%08X\n", exit32);
                                HANDLE thc = CreateRemoteThread(
                                    ph, nullptr, 0,
                                    reinterpret_cast<LPTHREAD_START_ROUTINE>(
                                        static_cast<uintptr_t>(exit32)),
                                    reinterpret_cast<void*>(static_cast<uintptr_t>(7)),
                                    0, nullptr);
                                if (thc) {
                                    DWORD wc0 = WaitForSingleObject(thc, 10000);
                                    DWORD ecc0 = 0;
                                    GetExitCodeThread(thc, &ecc0);
                                    printf("wow64 x64 control (kernel start): wait=%lu exit=0x%08lX\n",
                                           static_cast<unsigned long>(wc0), static_cast<unsigned>(ecc0));
                                    CloseHandle(thc);
                                }
                                thc = CreateRemoteThread(
                                    ph, nullptr, 0,
                                    reinterpret_cast<LPTHREAD_START_ROUTINE>(code64), nullptr, 0, nullptr);
                                if (thc) {
                                    DWORD wc = WaitForSingleObject(thc, 10000);
                                    DWORD ecc = 0;
                                    GetExitCodeThread(thc, &ecc);
                                    uint32_t resc[10]{};
                                    ReadProcessMemory(ph, reinterpret_cast<void*>(
                                                          static_cast<uintptr_t>(buf)),
                                                      resc, sizeof(resc), nullptr);
                                    printf("wow64 x64 control: wait=%lu exit=0x%08lX handle=0x%X alloc=0x%X\n",
                                           static_cast<unsigned long>(wc), static_cast<unsigned>(ecc),
                                           resc[0], resc[3]);
                                    CloseHandle(thc);
                                } else {
                                    printf("wow64 x64 control: CreateRemoteThread failed %lu\n",
                                           GetLastError());
                                }
                                VirtualFreeEx(ph, code64, 0, MEM_RELEASE);
                            } else {
                                printf("wow64 x64 control: alloc failed %lu\n", GetLastError());
                            }
                        }
                    }

                    if (wok) {
                        // Wait until the thread is not suspended before reading
                        // it: a context read on a never-resumed thread returns
                        // the values the kernel still holds, not the ones the
                        // thread will execute, and a 0 suspend count means the
                        // stub is already running (or already gone).
                        DWORD before = ResumeThread(th2);
                        printf("wow64 resume suspend-count was %lu\n", before);
                        DWORD after = SuspendThread(th2);
                        printf("wow64 suspend after resume=%lu\n", after);
                        if (after != 0xFFFFFFFF) ResumeThread(th2);
                        DWORD w2 = WaitForSingleObject(th2, 10000);
                        DWORD ec2 = 0;
                        GetExitCodeThread(th2, &ec2);
                        uint32_t res2[10]{};
                        ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(buf)),
                                          res2, sizeof(res2), nullptr);
                        printf("wow64 wait=%lu thread exit=0x%08lX (%s)\n",
                               static_cast<unsigned long>(w2), static_cast<unsigned>(ec2),
                               rst_to_text(static_cast<unsigned>(ec2)));
                        print_stub_results("wow64", res2);
                        stub_ok = (res2[0] != 0);
                    }
                    CloseHandle(th2);
                }
            }
            if (code32) VirtualFreeEx(ph, code32, 0, MEM_RELEASE);
            if (teb32) VirtualFreeEx(ph, teb32, 0, MEM_RELEASE);
            if (stack32) VirtualFreeEx(ph, stack32, 0, MEM_RELEASE);
        }

        // --- Decision table ---
        // The facts the branch is chosen from:
        //   wow64       the host is a 32 bit process
        //   granted     the access mask the host actually gets on the game
        //   alloc       the result of the allocation inside the host
        //   lasterr     the error of that allocation
        //   reached     the payload ran and reported back
        {
            const uint32_t* r = res;
            // The stub tries the full mask first and the whitelist mask
            // second. Whichever handle it actually got carries the facts
            // the branch is decided from.
            bool full = (r[0] != 0);
            uint32_t granted = full ? r[2] : r[6];
            uint32_t alloc    = full ? r[3] : r[8];
            uint32_t lasterr  = full ? r[4] : r[9];
            bool reached = (r[0] != 0) || (r[5] != 0);

            const char* branch = "unknown";
            const char* why = "";
            if (!ph) {
                branch = "host_unreachable";
                why = "no handle on the host";
            } else if (!wow) {
                branch = "re_resolve_by_name";
                why = "host is not wow64";
            } else if (reached && alloc != 0) {
                branch = "real_relay";
                why = "the host can allocate in the game";
            } else if (granted == 0x11F145 && alloc == 0 && lasterr == 5) {
                branch = "not_whitelisted";
                why = "granted 0x11F145 carries no vm rights";
            } else if (!reached) {
                branch = "thread_did_not_report";
                why = "the stub did not report back";
            } else {
                branch = "blocked_unknown";
                why = "no rule matched";
            }

            printf("facts wow64=%d granted=0x%08lX alloc=0x%X lasterr=%lu reached=%d\n",
                   wow ? 1 : 0, static_cast<unsigned long>(granted), alloc,
                   static_cast<unsigned long>(lasterr), reached ? 1 : 0);
            printf("decision=%s (%s)\n", branch, why);
        }

        VirtualFreeEx(ph, code, 0, MEM_RELEASE);
        CloseHandle(ph);
        if (h_lim) CloseHandle(h_lim);
        return 0;
    }

    if (argc > 1 && lstrcmpW(argv[1], L"--grant") == 0) {
        DWORD pid = pid_by_name(L"FortniteClient-Win64-Shipping.exe");
        printf("game pid=%lu\n", static_cast<unsigned long>(pid));
        if (!pid) return 1;

        HANDLE tok = nullptr;
        PSID user_sid = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
            BYTE tb[256]{};
            DWORD tl = 0;
            if (GetTokenInformation(tok, TokenUser, tb, sizeof(tb), &tl)) {
                PSID src = reinterpret_cast<TOKEN_USER*>(tb)->User.Sid;
                DWORD sl = GetLengthSid(src);
                user_sid = LocalAlloc(LPTR, sl);
                CopySid(sl, user_sid, src);
            }
            CloseHandle(tok);
        }
        printf("user sid=%p\n", user_sid);

        PSID sys_sid = nullptr, adm_sid = nullptr, world_sid = nullptr;
        ConvertStringSidToSidW(L"S-1-5-18", &sys_sid);
        ConvertStringSidToSidW(L"S-1-5-32-544", &adm_sid);
        ConvertStringSidToSidW(L"S-1-5-1", &world_sid);

        EXPLICIT_ACCESSW ea[4]{};
        PSID sids[4] = { user_sid, sys_sid, adm_sid, world_sid };
        DWORD masks[4] = { 0x1FFFFF, 0x1FFFFF, 0x1FFFFF, 0x11F145 };
        for (int i = 0; i < 4; ++i) {
            ea[i].grfAccessPermissions = masks[i];
            ea[i].grfAccessMode = GRANT_ACCESS;
            ea[i].grfInheritance = NO_INHERITANCE;
            ea[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[i].Trustee.TrusteeType = TRUSTEE_IS_USER;
            ea[i].Trustee.ptstrName = static_cast<LPWSTR>(sids[i]);
        }

        PACL acl = nullptr;
        DWORD r = SetEntriesInAclW(4, ea, nullptr, &acl);
        printf("SetEntriesInAcl=%lu acl=%p\n", r, acl);

        HANDLE h = OpenProcess(WRITE_DAC, FALSE, pid);
        printf("open WRITE_DAC=%p err=%lu\n", h, GetLastError());
        if (h) {
            r = SetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                                nullptr, nullptr, acl, nullptr);
            printf("SetSecurityInfo=%lu\n", r);
            CloseHandle(h);
        }

        HANDLE h2 = OpenProcess(0x1FFFFF, FALSE, pid);
        printf("reopen=%p err=%lu granted=0x%08lX\n", h2, GetLastError(),
               granted_access(GetCurrentProcessId(), h2));
        if (h2) {
            void* p = VirtualAllocEx(h2, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            printf("alloc=%p err=%lu\n", p, GetLastError());
            if (p) VirtualFreeEx(h2, p, 0, MEM_RELEASE);
            CloseHandle(h2);
        }

        if (acl) LocalFree(acl);
        LocalFree(user_sid);
        LocalFree(sys_sid);
        LocalFree(adm_sid);
        LocalFree(world_sid);
        return 0;
    }

    const wchar_t* path = argc > 1 ? argv[1] : L"payload.dll";

    size_t size = 0;
    if (!slurp_file(path, &g_local, &size)) { printf("[!] cannot read %ls\n", path); return 1; }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER_*>(g_local);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(g_local + dos->e_lfanew);
    if (dos->e_magic != 0x5A4D || nt->Signature != 0x4550 || nt->FileHeader.Machine != 0x8664) {
        printf("[!] bad image\n");
        return 1;
    }

    DWORD pid = pid_by_name(argc > 2 ? argv[2] : L"FortniteClient-Win64-Shipping.exe");
    if (!pid) { printf("[!] game not running\n"); return 1; }
    printf("[*] target pid %lu\n", pid);

    printf("[*] SeDebugPrivilege=%d\n", enable_debug_privilege() ? 1 : 0);

    constexpr DWORD kNeed = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
                            PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION;

    g_proc = open_game(pid, kNeed);
    if (!g_proc) {
        printf("[!] no writable handle, run the bootstrap path\n");

        // host: EAC first, overlay second, launcher last
        const wchar_t* hosts[] = {
            L"EasyAntiCheat_EOS.exe",
            L"EOSOVH-Win64-Shipping.exe",
            L"FortniteClient-Win64-Shipping_EAC_EOS.exe",
            L"FortniteLauncher.exe",
            L"EpicGamesLauncher.exe",
        };

        for (const wchar_t* h : hosts) {
            DWORD hp = pid_by_name(h);
            if (!hp) continue;

            HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hp);
            if (!ph) {
                printf("[!] cannot open %ls (pid %lu): %lu\n", h, hp, GetLastError());
                continue;
            }
            printf("[*] trying host %ls (pid %lu)\n", h, hp);

            wchar_t full[MAX_PATH]{};
            GetFullPathNameW(path, MAX_PATH, full, nullptr);

            // manual map first: EAC blocks LoadLibraryW and its self-protection
            // never runs DllMain for unsigned images loaded the normal way.
            DWORD mexit = 0;
            map_result mr{};
            bool ran = manual_map_host(ph, g_local, size, full, "start", /*keep_mapped*/false,
                                       &mr, 30000, mlog);
            mexit = mr.exit_code;
            if (ran) {
                printf("[+] payload manual-mapped via %ls (pid %lu) exit=%lu relay=%d\n",
                       h, hp, mexit, mexit ? 1 : 0);
                if (mexit) { CloseHandle(ph); return 0; }
            } else {
                printf("[!] manual map into %ls failed\n", h);
            }

            // LoadLibraryW(full) in the host (fallback)
            size_t bytes = (wcslen(full) + 1) * sizeof(wchar_t);
            void* remote = VirtualAllocEx(ph, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!remote) { printf("[!] alloc in %ls failed %lu\n", h, GetLastError()); CloseHandle(ph); continue; }

            if (!WriteProcessMemory(ph, remote, full, bytes, nullptr)) {
                printf("[!] write to %ls failed %lu\n", h, GetLastError());
                VirtualFreeEx(ph, remote, 0, MEM_RELEASE);
                CloseHandle(ph);
                continue;
            }

            HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
            HANDLE t = CreateRemoteThread(ph, nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(k32, "LoadLibraryW")),
                remote, 0, nullptr);

            bool loaded = false;
            if (t) {
                WaitForSingleObject(t, 10000);
                DWORD ec = 0;
                GetExitCodeThread(t, &ec);

                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, hp);
                if (snap != INVALID_HANDLE_VALUE) {
                    MODULEENTRY32W me{ sizeof(me) };
                    for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me))
                        if (lstrcmpiW(me.szModule, L"payload.dll") == 0) { loaded = true; break; }
                    CloseHandle(snap);
                }
                printf("[+] payload relayed via %ls (pid %lu) exit=%lu loaded=%d\n",
                       h, hp, ec, loaded ? 1 : 0);
                CloseHandle(t);
            } else {
                printf("[!] thread in %ls failed %lu\n", h, GetLastError());
            }
            VirtualFreeEx(ph, remote, 0, MEM_RELEASE);
            CloseHandle(ph);
            if (loaded) break;
        }

        return 2;
    }

    // Direct map into the game: the shared mapper handles relocations,
    // import resolution, TLS callbacks and the entry thread.
    {
        wchar_t full[MAX_PATH]{};
        GetFullPathNameW(path, MAX_PATH, full, nullptr);
        map_result mr{};
        bool ran = manual_map_host(g_proc, g_local, size, full, "start", /*keep_mapped*/true,
                                   &mr, 15000, mlog);
        printf("[+] mapped into game pid %lu ran=%d exit=%lu (0x%08lX)\n",
               pid, ran ? 1 : 0, static_cast<unsigned long>(mr.exit_code),
               static_cast<unsigned>(mr.exit_code));
        return ran ? 0 : 1;
    }
}
