#include "handle.hpp"
#include "../../shared/include/nt.hpp"
#include <tlhelp32.h>
#include <cstdio>
#include <vector>

namespace {

struct HENTRY {
    ULONG_PTR Object;
    ULONG_PTR Pid;
    ULONG_PTR Handle;
    ULONG     Access;
    USHORT    BtIndex;
    USHORT    TypeIndex;
    ULONG     Attributes;
    ULONG     Reserved;
};

struct HEX {
    ULONG_PTR Count;
    ULONG_PTR Reserved;
    HENTRY    Entries[1];
};

using NtQSI = NTSTATUS_(__stdcall*)(ULONG, void*, ULONG, ULONG*);

bool query_handles(std::vector<uint8_t>& buf) {
    static auto q = reinterpret_cast<NtQSI>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!q) return false;

    ULONG len = 1 << 20, ret = 0;
    for (int i = 0; i < 10; ++i) {
        buf.resize(len);
        NTSTATUS_ st = q(0x40, buf.data(), len, &ret);   // SystemExtendedHandleInformation
        if (st >= 0) return true;
        if (st != static_cast<NTSTATUS_>(0xC0000004)) return false;
        len *= 2;
    }
    return false;
}

USHORT process_type_index() {
    HANDLE self = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (!self) return 0;

    std::vector<uint8_t> buf;
    USHORT idx = 0;
    if (query_handles(buf)) {
        auto* ex = reinterpret_cast<HEX*>(buf.data());
        for (ULONG_PTR i = 0; i < ex->Count; ++i) {
            auto& e = ex->Entries[i];
            if (e.Pid == GetCurrentProcessId() && e.Handle == reinterpret_cast<ULONG_PTR>(self)) {
                idx = e.TypeIndex;
                break;
            }
        }
    }
    CloseHandle(self);
    return idx;
}

} // namespace

DWORD pid_by_name(const wchar_t* exe) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{ sizeof(pe) };
    DWORD pid = 0;
    for (BOOL ok = Process32FirstW(s, &pe); ok; ok = Process32NextW(s, &pe))
        if (lstrcmpiW(pe.szExeFile, exe) == 0) { pid = pe.th32ProcessID; break; }

    CloseHandle(s);
    return pid;
}

ULONG granted_access(DWORD pid, HANDLE h) {
    std::vector<uint8_t> buf;
    if (!query_handles(buf)) return 0;

    auto* ex = reinterpret_cast<HEX*>(buf.data());
    for (ULONG_PTR i = 0; i < ex->Count; ++i) {
        auto& e = ex->Entries[i];
        if (e.Pid == pid && e.Handle == reinterpret_cast<ULONG_PTR>(h)) return e.Access;
    }
    return 0;
}

HANDLE open_game(DWORD pid, DWORD need) {
    HANDLE h = OpenProcess(need, FALSE, pid);
    if (h) {
        ULONG g = granted_access(GetCurrentProcessId(), h);
        printf("[*] direct open: need=0x%08lX granted=0x%08lX\n", need, g);

        if ((g & need) == need) {
            printf("[+] handle is complete\n");
            return h;
        }
        printf("[!] bits stripped: 0x%08lX\n", need & ~g);
        CloseHandle(h);
    } else {
        printf("[!] direct open failed %lu\n", GetLastError());
    }

    // second pass: a handle that already carries the bits may exist in another process.
    // Object pointers are zeroed for non-elevated callers on recent builds, so identify
    // the game by duplicating candidates and checking the target pid.
    USHORT ptype = process_type_index();
    if (!ptype) { printf("[!] process type index unknown\n"); return nullptr; }

    std::vector<uint8_t> buf;
    if (!query_handles(buf)) { printf("[!] handle query failed\n"); return nullptr; }

    auto* ex = reinterpret_cast<HEX*>(buf.data());
    for (ULONG_PTR i = 0; i < ex->Count; ++i) {
        auto& e = ex->Entries[i];
        if (e.TypeIndex != ptype) continue;
        if ((e.Access & need) != need) continue;
        if (e.Pid == GetCurrentProcessId() || e.Pid == pid) continue;

        DWORD owner = static_cast<DWORD>(e.Pid);
        HANDLE src = OpenProcess(PROCESS_DUP_HANDLE, FALSE, owner);
        if (!src) continue;

        HANDLE dup = nullptr;
        BOOL ok = DuplicateHandle(src, reinterpret_cast<HANDLE>(e.Handle),
                                  GetCurrentProcess(), &dup, need, FALSE, 0);
        CloseHandle(src);
        if (!ok || !dup) continue;

        if (GetProcessId(dup) != pid) { CloseHandle(dup); continue; }

        // probe: only an actual allocation proves the bits survived duplication
        void* probe = VirtualAllocEx(dup, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!probe) { CloseHandle(dup); continue; }
        VirtualFreeEx(dup, probe, 0, MEM_RELEASE);

        ULONG g = granted_access(GetCurrentProcessId(), dup);
        printf("[+] duplicated from pid %lu, granted=0x%08lX\n", owner, g);
        return dup;
    }

    printf("[!] no usable handle found\n");
    return nullptr;
}

void dump_game_handles(DWORD game_pid) {
    USHORT ptype = process_type_index();
    printf("[*] process type index=%u\n", static_cast<unsigned>(ptype));
    if (!ptype) return;

    std::vector<uint8_t> buf;
    if (!query_handles(buf)) { printf("[!] handle query failed\n"); return; }

    auto* ex = reinterpret_cast<HEX*>(buf.data());
    struct Cached { ULONG_PTR pid; HANDLE h; };
    std::vector<Cached> cache;

    int total = 0, matched = 0, open_fail = 0, dup_fail = 0;
    for (ULONG_PTR i = 0; i < ex->Count; ++i) {
        auto& e = ex->Entries[i];
        if (e.TypeIndex != ptype) continue;
        ++total;

        DWORD owner = static_cast<DWORD>(e.Pid);
        HANDLE src = nullptr;
        for (auto& c : cache) if (c.pid == e.Pid) { src = c.h; break; }
        if (!src) {
            src = OpenProcess(PROCESS_DUP_HANDLE, FALSE, owner);
            if (!src) { ++open_fail; continue; }
            cache.push_back({ e.Pid, src });
        }

        HANDLE dup = nullptr;
        // desired access 0 = keep the source handle's access
        if (!DuplicateHandle(src, reinterpret_cast<HANDLE>(e.Handle),
                             GetCurrentProcess(), &dup, 0, FALSE, 0)) {
            ++dup_fail;
            continue;
        }

        if (GetProcessId(dup) == game_pid) {
            ++matched;
            ULONG dg = granted_access(GetCurrentProcessId(), dup);
            void* probe = VirtualAllocEx(dup, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            printf("[game] owner=%lu handle=%llX access=0x%08lX dup_granted=0x%08lX alloc=%s\n",
                   static_cast<unsigned long>(owner),
                   static_cast<unsigned long long>(e.Handle),
                   static_cast<unsigned long>(e.Access),
                   static_cast<unsigned long>(dg),
                   probe ? "OK" : "FAIL");
            if (probe) VirtualFreeEx(dup, probe, 0, MEM_RELEASE);
        }
        CloseHandle(dup);
    }

    for (auto& c : cache) CloseHandle(c.h);
    printf("[*] process handles=%d matched=%d open_fail=%d dup_fail=%d\n",
           total, matched, open_fail, dup_fail);
}