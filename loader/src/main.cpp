#include "../../shared/include/nt.hpp"
#include "../../shared/include/hash.hpp"
#include "../../shared/include/mem.hpp"
#include "../../shared/include/peb.hpp"
#include "handle.hpp"
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <accctrl.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <vector>

namespace {

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
uint8_t* g_remote{};
uint64_t g_delta{};

bool slurp(const wchar_t* path, uint8_t** out, size_t* size) {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER li{};
    GetFileSizeEx(f, &li);
    *size = static_cast<size_t>(li.QuadPart);
    *out = new uint8_t[*size];

    DWORD got = 0;
    bool ok = ReadFile(f, *out, static_cast<DWORD>(*size), &got, nullptr) && got == *size;
    CloseHandle(f);
    return ok;
}

uint8_t* remote_module(uint32_t hash) {
    using QIP = NTSTATUS_(__stdcall*)(HANDLE, uint32_t, void*, uint32_t, uint32_t*);
    auto qip = reinterpret_cast<QIP>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

    PROCESS_BASIC_INFORMATION_ pbi{};
    if (qip(g_proc, 0, &pbi, sizeof(pbi), nullptr) < 0 || !pbi.PebBaseAddress) return nullptr;

    uint64_t ldr = 0;
    ReadProcessMemory(g_proc, reinterpret_cast<uint8_t*>(pbi.PebBaseAddress) + 0x18, &ldr, 8, nullptr);
    if (!ldr) return nullptr;

    uint64_t head = ldr + 0x10, cur = 0;
    ReadProcessMemory(g_proc, reinterpret_cast<void*>(head), &cur, 8, nullptr);

    for (int guard = 0; cur && cur != head && guard < 512; ++guard) {
        LDR_DATA_TABLE_ENTRY_ e{};
        if (!ReadProcessMemory(g_proc, reinterpret_cast<void*>(cur), &e, sizeof(e), nullptr)) break;

        if (e.BaseDllName.Buffer) {
            wchar_t name[64]{};
            ReadProcessMemory(g_proc, e.BaseDllName.Buffer, name, sizeof(name) - 2, nullptr);
            if (h::fnv1a_w(name) == hash) return static_cast<uint8_t*>(e.DllBase);
        }
        ReadProcessMemory(g_proc, reinterpret_cast<void*>(cur), &cur, 8, nullptr);
    }
    return nullptr;
}

uint64_t remote_proc(uint32_t mod_hash, uint32_t fn_hash) {
    auto* base = remote_module(mod_hash);
    if (!base) return 0;

    IMAGE_DOS_HEADER_ dos{};
    ReadProcessMemory(g_proc, base, &dos, sizeof(dos), nullptr);

    IMAGE_NT_HEADERS64_ nt{};
    ReadProcessMemory(g_proc, base + dos.e_lfanew, &nt, sizeof(nt), nullptr);

    auto& dir = nt.OptionalHeader.DataDirectory[DIR_EXPORT_];
    if (!dir.VirtualAddress) return 0;

    IMAGE_EXPORT_DIRECTORY_ ed{};
    ReadProcessMemory(g_proc, base + dir.VirtualAddress, &ed, sizeof(ed), nullptr);

    for (uint32_t i = 0; i < ed.NumberOfNames; ++i) {
        uint32_t rva = 0;
        ReadProcessMemory(g_proc, base + ed.AddressOfNames + i * 4, &rva, 4, nullptr);

        char name[128]{};
        ReadProcessMemory(g_proc, base + rva, name, sizeof(name) - 1, nullptr);
        if (h::fnv1a(name) != fn_hash) continue;

        uint16_t ord = 0;
        ReadProcessMemory(g_proc, base + ed.AddressOfNameOrdinals + i * 2, &ord, 2, nullptr);

        uint32_t fn = 0;
        ReadProcessMemory(g_proc, base + ed.AddressOfFunctions + ord * 4, &fn, 4, nullptr);
        return reinterpret_cast<uint64_t>(base + fn);
    }
    return 0;
}

void do_relocs(IMAGE_NT_HEADERS64_* nt, uint8_t* img) {
    auto& dir = nt->OptionalHeader.DataDirectory[DIR_BASERELOC_];
    if (!dir.VirtualAddress) return;

    auto* blk = reinterpret_cast<IMAGE_BASE_RELOCATION_*>(img + dir.VirtualAddress);
    uint32_t left = dir.Size;

    while (left > sizeof(IMAGE_BASE_RELOCATION_)) {
        uint32_t n = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION_)) / 2;
        auto* ent = reinterpret_cast<uint16_t*>(blk + 1);

        for (uint32_t i = 0; i < n; ++i) {
            if ((ent[i] >> 12) != REL_DIR64_) continue;
            auto* p = reinterpret_cast<uint64_t*>(img + blk->VirtualAddress + (ent[i] & 0xFFF));
            *p += g_delta;
        }
        left -= blk->SizeOfBlock;
        blk = reinterpret_cast<IMAGE_BASE_RELOCATION_*>(reinterpret_cast<uint8_t*>(blk) + blk->SizeOfBlock);
    }
}

bool do_imports(IMAGE_NT_HEADERS64_* nt, uint8_t* img) {
    auto& dir = nt->OptionalHeader.DataDirectory[DIR_IMPORT_];
    if (!dir.VirtualAddress) return true;

    auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR_*>(img + dir.VirtualAddress);
    for (; imp->Name; ++imp) {
        char dll[128]{};
        memcpy(dll, img + imp->Name, sizeof(dll) - 1);

        for (auto* thunk = reinterpret_cast<uint64_t*>(img + imp->FirstThunk); *thunk; ++thunk) {
            if (*thunk & 0x8000000000000000ull) continue;

            char fn[128]{};
            memcpy(fn, img + *thunk + 2, sizeof(fn) - 1);

            uint64_t addr = remote_proc(h::fnv1a(dll), h::fnv1a(fn));
            if (!addr) { printf("[!] unresolved %s!%s\n", dll, fn); return false; }
            *thunk = addr;
        }
    }
    return true;
}

uint64_t find_export(IMAGE_NT_HEADERS64_* nt, uint8_t* img, const char* name) {
    auto& dir = nt->OptionalHeader.DataDirectory[DIR_EXPORT_];
    if (!dir.VirtualAddress) return 0;

    auto* ed = reinterpret_cast<IMAGE_EXPORT_DIRECTORY_*>(img + dir.VirtualAddress);
    auto* names = reinterpret_cast<uint32_t*>(img + ed->AddressOfNames);
    auto* ords  = reinterpret_cast<uint16_t*>(img + ed->AddressOfNameOrdinals);
    auto* funcs = reinterpret_cast<uint32_t*>(img + ed->AddressOfFunctions);

    for (uint32_t i = 0; i < ed->NumberOfNames; ++i)
        if (h::fnv1a(reinterpret_cast<const char*>(img + names[i])) == h::fnv1a(name))
            return funcs[ords[i]];
    return 0;
}

void flush(IMAGE_NT_HEADERS64_* nt, uint8_t* img) {
    WriteProcessMemory(g_proc, g_remote, img, nt->OptionalHeader.SizeOfHeaders, nullptr);

    auto* sec = IMAGE_FIRST_SECTION_(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
        if (sec->SizeOfRawData)
            WriteProcessMemory(g_proc, g_remote + sec->VirtualAddress,
                               img + sec->PointerToRawData, sec->SizeOfRawData, nullptr);
}

// Map the payload into a host without LoadLibrary: build a relocated private
// copy, bake g_host_path into .data, then start a suspended thread and point
// its context straight at `start`. The context route skips RtlUserThreadStart,
// whose indirect call would trip CFG in the EAC process.
bool manual_map_host(HANDLE ph, const uint8_t* img, size_t img_size,
                     const wchar_t* self_path, const char* start_export,
                     DWORD* out_exit, DWORD wait_ms) {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER_*>(const_cast<uint8_t*>(img));
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(const_cast<uint8_t*>(img) + dos->e_lfanew);

    SIZE_T image_size = nt->OptionalHeader.SizeOfImage;
    uint8_t* remote = static_cast<uint8_t*>(
        VirtualAllocEx(ph, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!remote) {
        printf("[!] host image alloc failed %lu\n", GetLastError());
        return false;
    }

    auto cleanup = [&](bool free_stack, uint8_t* stack) {
        if (free_stack && stack) VirtualFreeEx(ph, stack, 0, MEM_RELEASE);
        VirtualFreeEx(ph, remote, 0, MEM_RELEASE);
    };

    std::vector<uint8_t> local(image_size, 0);
    size_t hdr = nt->OptionalHeader.SizeOfHeaders;
    if (hdr > img_size) hdr = img_size;
    memcpy(local.data(), img, hdr);

    auto* sec = IMAGE_FIRST_SECTION_(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData) continue;
        if (static_cast<uint64_t>(sec->PointerToRawData) + sec->SizeOfRawData > img_size) {
            printf("[!] bad section %u\n", static_cast<unsigned>(i));
            cleanup(false, nullptr);
            return false;
        }
        memcpy(local.data() + sec->VirtualAddress, img + sec->PointerToRawData, sec->SizeOfRawData);
    }

    uint64_t delta = reinterpret_cast<uint64_t>(remote) - nt->OptionalHeader.ImageBase;
    auto& rel = nt->OptionalHeader.DataDirectory[DIR_BASERELOC_];
    if (rel.VirtualAddress && rel.Size && delta) {
        auto* blk = reinterpret_cast<IMAGE_BASE_RELOCATION_*>(local.data() + rel.VirtualAddress);
        uint32_t left = rel.Size;
        while (left > sizeof(IMAGE_BASE_RELOCATION_)) {
            if (!blk->SizeOfBlock) break;
            uint32_t n = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION_)) / 2;
            auto* ent = reinterpret_cast<uint16_t*>(blk + 1);
            for (uint32_t i = 0; i < n; ++i) {
                if ((ent[i] >> 12) != REL_DIR64_) continue;
                auto* p = reinterpret_cast<uint64_t*>(
                    local.data() + blk->VirtualAddress + (ent[i] & 0xFFF));
                *p += delta;
            }
            left -= blk->SizeOfBlock;
            blk = reinterpret_cast<IMAGE_BASE_RELOCATION_*>(
                reinterpret_cast<uint8_t*>(blk) + blk->SizeOfBlock);
        }
    }

    uint64_t path_rva = find_export(nt, local.data(), "g_host_path");
    if (!path_rva) { printf("[!] g_host_path export missing\n"); cleanup(false, nullptr); return false; }
    lstrcpynW(reinterpret_cast<wchar_t*>(local.data() + path_rva), self_path, 260);

    uint64_t start_rva = find_export(nt, local.data(), start_export);
    if (!start_rva) start_rva = nt->OptionalHeader.AddressOfEntryPoint;

    uint64_t exit_rva = find_export(nt, local.data(), "exit_thunk");
    if (!exit_rva) { printf("[!] exit_thunk export missing\n"); cleanup(false, nullptr); return false; }

    printf("[*] mm: remote=%p image=0x%llX pref=0x%llX export=%s rva=0x%llX path_rva=0x%llX exit_rva=0x%llX\n",
           remote, static_cast<unsigned long long>(image_size),
           static_cast<unsigned long long>(nt->OptionalHeader.ImageBase),
           start_export, static_cast<unsigned long long>(start_rva),
           static_cast<unsigned long long>(path_rva),
           static_cast<unsigned long long>(exit_rva));

    if (!WriteProcessMemory(ph, remote, local.data(), image_size, nullptr)) {
        printf("[!] host image write failed %lu\n", GetLastError());
        cleanup(false, nullptr);
        return false;
    }

    DWORD old = 0;
    VirtualProtectEx(ph, remote, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old);
    sec = IMAGE_FIRST_SECTION_(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData) continue;
        DWORD prot = PAGE_READONLY;
        if (sec->Characteristics & SCN_EXECUTE_) prot = PAGE_EXECUTE_READ;
        else if (sec->Characteristics & SCN_WRITE_) prot = PAGE_READWRITE;
        if (!VirtualProtectEx(ph, remote + sec->VirtualAddress, sec->SizeOfRawData, prot, &old))
            printf("[!] protect sec %u (0x%lX) failed %lu\n",
                   static_cast<unsigned>(i), prot, GetLastError());
    }

    // return chain: start -> ret gadget -> ExitThread, keeping the ABI
    // alignment correct for the ExitThread call.
    uint64_t gadget = 0;
    sec = IMAGE_FIRST_SECTION_(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections && !gadget; ++i, ++sec) {
        if (!(sec->Characteristics & SCN_EXECUTE_)) continue;
        auto* p = local.data() + sec->VirtualAddress;
        uint32_t n = sec->VirtualSize ? sec->VirtualSize : sec->SizeOfRawData;
        for (uint32_t b = 0; b < n; ++b)
            if (p[b] == 0xC3) {
                gadget = reinterpret_cast<uint64_t>(remote) + sec->VirtualAddress + b;
                break;
            }
    }
    if (!gadget) { printf("[!] no ret gadget\n"); cleanup(false, nullptr); return false; }

    uint64_t exit_thunk = reinterpret_cast<uint64_t>(remote) + exit_rva;

    uint8_t* stack = static_cast<uint8_t*>(
        VirtualAllocEx(ph, nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!stack) { printf("[!] host stack alloc failed %lu\n", GetLastError()); cleanup(false, nullptr); return false; }

    uint64_t top = reinterpret_cast<uint64_t>(stack) + 0x8000;
    top &= ~0xFull;
    top -= 8;                               // RSP % 16 == 8 at function entry
    uint64_t frame[2] = { gadget, exit_thunk };
    WriteProcessMemory(ph, reinterpret_cast<void*>(top), frame, sizeof(frame), nullptr);

    using NtCTE = NTSTATUS_(__stdcall*)(HANDLE*, uint32_t, void*, HANDLE, void*,
                                        void*, uint32_t, uintptr_t, uintptr_t,
                                        uintptr_t, void*);
    auto cte = reinterpret_cast<NtCTE>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"));
    if (!cte) { cleanup(true, stack); return false; }

    // Let the normal thread startup run the payload: LdrInitializeThunk ->
    // RtlUserThreadStart -> StartRoutine(Argument). Hijacking the context of a
    // brand-new thread breaks the startup context NtContinue restores.
    uint64_t entry = reinterpret_cast<uint64_t>(remote) + start_rva;
    HANDLE th = nullptr;
    NTSTATUS_ st = cte(&th, 0x1FFFFF, nullptr, ph,
                       reinterpret_cast<void*>(entry),
                       reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(remote)),
                       1 /* CREATE_SUSPENDED */, 0, 0, 0, nullptr);
    if (st < 0 || !th) {
        printf("[!] host thread create failed 0x%08lX\n", static_cast<unsigned>(st));
        cleanup(true, stack);
        return false;
    }
    printf("[*] mm: thread=%p status=0x%08lX stack=%p entry=0x%llX\n",
           th, static_cast<unsigned>(st), stack,
           static_cast<unsigned long long>(entry));

    ResumeThread(th);
    WaitForSingleObject(th, wait_ms);

    DWORD ec = 0;
    GetExitCodeThread(th, &ec);
    bool exited = WaitForSingleObject(th, 0) == WAIT_OBJECT_0;
    if (out_exit) *out_exit = ec;
    printf("[*] mm: thread exit=%lu (0x%08lX) exited=%d\n",
           static_cast<unsigned long>(ec), static_cast<unsigned>(ec), exited ? 1 : 0);

    uint64_t tr_rva = find_export(nt, local.data(), "g_trace");
    if (tr_rva) {
        uint32_t tr[16]{};
        if (ReadProcessMemory(ph, remote + tr_rva, tr, sizeof(tr), nullptr)) {
            printf("[*] mm: trace");
            for (int i = 0; i < 16; ++i)
                if (tr[i]) printf(" %d=%08lX", i, static_cast<unsigned long>(tr[i]));
            printf("\n");
        } else {
            printf("[!] mm: trace read failed %lu (rva=0x%llX)\n",
                   GetLastError(), static_cast<unsigned long long>(tr_rva));
        }
    } else {
        printf("[!] mm: g_trace export missing\n");
    }
    CloseHandle(th);

    if (exited) {
        VirtualFreeEx(ph, stack, 0, MEM_RELEASE);
        VirtualFreeEx(ph, remote, 0, MEM_RELEASE);
    }
    return exited;
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

void drain_debug_events(DWORD pid, int quiet_ms) {
    DEBUG_EVENT de{};
    while (WaitForDebugEvent(&de, quiet_ms))
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
}

void dump_debug_events(DWORD pid, HANDLE ph, int quiet_ms) {
    std::vector<ModRange> mods;
    collect_modules(pid, mods);

    DEBUG_EVENT de{};
    int printed = 0;
    while (WaitForDebugEvent(&de, quiet_ms)) {
        bool stop = false;

        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            auto& er = de.u.Exception.ExceptionRecord;
            if (er.ExceptionCode != 0x80000003L) {
                printf("[dbg] exception code=0x%08lX addr=0x%llX first=%d params=%lu\n",
                       static_cast<unsigned>(er.ExceptionCode),
                       static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(er.ExceptionAddress)),
                       de.u.Exception.dwFirstChance,
                       static_cast<unsigned long>(er.NumberParameters));
                for (DWORD i = 0; i < er.NumberParameters && i < 15; ++i)
                    printf("[dbg]   param[%lu]=0x%llX\n", static_cast<unsigned long>(i),
                           static_cast<unsigned long long>(er.ExceptionInformation[i]));

                HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                       FALSE, de.dwThreadId);
                if (th) {
                    CONTEXT c{};
                    c.ContextFlags = CONTEXT_ALL;
                    if (GetThreadContext(th, &c)) {
                        printf("[dbg]   rip=0x%llX rsp=0x%llX rbp=0x%llX\n",
                               static_cast<unsigned long long>(c.Rip),
                               static_cast<unsigned long long>(c.Rsp),
                               static_cast<unsigned long long>(c.Rbp));
                        uint64_t stack[256]{};
                        SIZE_T got = 0;
                        if (ReadProcessMemory(ph, reinterpret_cast<void*>(c.Rsp),
                                              stack, sizeof(stack), &got)) {
                            for (size_t i = 0; i < got / sizeof(uint64_t); ++i) {
                                uint64_t v = stack[i];
                                if (!v) continue;
                                printf("[dbg]   stk[%03u] 0x%llX ", static_cast<unsigned>(i),
                                       static_cast<unsigned long long>(v));
                                print_addr(mods, v);
                                printf("\n");
                            }
                        }
                    }
                    CloseHandle(th);
                }
                fflush(stdout);
                if (++printed >= 2) stop = true;
            }
        } else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            stop = true;
        }

        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
        if (stop) break;
    }
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
        if (!slurp(dll, &img, &size) || size < 0x100) {
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
        wchar_t cmdline[] = L"cmd.exe /c ping -n 300 127.0.0.1 >nul";
        DWORD host_flags = CREATE_NEW_CONSOLE;
        if (!CreateProcessW(nullptr, cmdline, nullptr, nullptr, FALSE,
                            host_flags, nullptr, nullptr, &si, &pi)) {
            printf("[!] host spawn failed %lu\n", GetLastError());
            delete[] img;
            return 1;
        }
        printf("[*] test host cmd.exe pid %lu\n", static_cast<unsigned long>(pi.dwProcessId));

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
        bool dbg = maptest_dbg && DebugActiveProcess(pi.dwProcessId) != FALSE;
        printf("[*] debugger attached=%d\n", dbg ? 1 : 0);
        if (dbg) drain_debug_events(pi.dwProcessId, 300);

        DWORD mexit = 0;
        bool ran = manual_map_host(ph, img, size, full, exp, &mexit, 15000);
        printf("[*] maptest ran=%d exit=%lu (0x%08lX)\n",
               ran ? 1 : 0, static_cast<unsigned long>(mexit),
               static_cast<unsigned>(mexit));

        if (dbg) {
            dump_debug_events(pi.dwProcessId, ph, 1500);
            DebugActiveProcessStop(pi.dwProcessId);
        }

        CloseHandle(ph);
        TerminateProcess(pi.hProcess, 0);
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
        if (!slurp(dll, &img, &size) || size < 0x100) {
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
        bool ran = manual_map_host(ph, img, size, full, exp, &mexit, 15000);
        printf("[*] hosttest ran=%d exit=%lu (0x%08lX)\n",
               ran ? 1 : 0, static_cast<unsigned long>(mexit),
               static_cast<unsigned>(mexit));

        CloseHandle(ph);
        delete[] img;
        return ran ? 0 : 1;
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

        HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hp);
        printf("open host=%p err=%lu\n", ph, GetLastError());
        // Continue even if PROCESS_ALL_ACCESS fails — the probe gathers
        // granted-mask and open-path data even without full rights.
        if (!ph) ph = nullptr;

        BOOL wow = FALSE;
        IsWow64Process(ph, &wow);
        printf("wow64=%d\n", wow ? 1 : 0);

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
        if (!k32) { CloseHandle(ph); return 1; }

        uint32_t p_open = wow_export32(ph, k32, "OpenProcess");
        uint32_t p_alloc = wow_export32(ph, k32, "VirtualAllocEx");
        uint32_t p_gle = wow_export32(ph, k32, "GetLastError");
        printf("OpenProcess=0x%X VirtualAllocEx=0x%X GetLastError=0x%X\n", p_open, p_alloc, p_gle);

        // --- Granted mask via NtQueryObject on the game process ---
        DWORD game = pid_by_name(L"FortniteClient-Win64-Shipping.exe");
        printf("game pid=%lu\n", static_cast<unsigned long>(game));

        HANDLE gh = nullptr;
        ULONG granted_mask = 0;
        if (game) {
            gh = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, game);
            if (gh) {
                // NtQueryObject with ObjectBasicInformation (info class 0)
                // on a 0x40-byte buffer; this works on a valid handle regardless of mask
                UCHAR basic_buf[0x40]{};
                NTSTATUS_ qst = NtQueryObject(gh, 0, basic_buf, sizeof(basic_buf), nullptr);
                if (qst >= 0) {
                    // Parse OBJECT_BASIC_INFORMATION at the start of the buffer
                    auto* basic = reinterpret_cast<OBJECT_BASIC_INFORMATION_*>(basic_buf);
                    granted_mask = basic->GrantedAccess;
                    printf("granted_mask=0x%08lX (via NtQueryObject ObjectBasicInformation)\n",
                           static_cast<unsigned long>(granted_mask));
                } else {
                    printf("NtQueryObject failed 0x%08lX\n", static_cast<unsigned long>(qst));
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
            printf("--- %s mitigations ---\n", label);
            // Policy indices: 0=MitigationPolicies, 2=ControlFlowGuardPolicy, 7=SignaturePolicy
            const int ps[] = { 0, 2, 7 };
            for (int i = 0; i < 3; ++i) {
                DWORD v = 0;
                BOOL ok = gpm(h, ps[i], &v, sizeof(v));
                printf("policy[%2d] = 0x%08lX%s\n", ps[i], static_cast<unsigned long>(v),
                       ok ? "" : " (query failed)");
            }
        };
        query_policies(ph, "EAC");
        if (game) {
            HANDLE gh2 = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, game);
            if (gh2) { query_policies(gh2, "GAME"); CloseHandle(gh2); }
        }

        // --- Both open paths: NtOpenProcess with PROCESS_ALL_ACCESS and 0x11F145 ---
        // We use the NtApi variant since OpenProcess wraps NtOpenProcess
        NTSTATUS_ nt_all = STATUS_SUCCESS, nt_11f145 = STATUS_SUCCESS;
        HANDLE h_all = nullptr, h_11f145 = nullptr;

        // Path 1: PROCESS_ALL_ACCESS
        {
            using QIP2 = NTSTATUS_(__stdcall*)(HANDLE, ACCESS_MASK, ULONG, ACCESS_MASK*, ULONG, HANDLE*, ACCESS_MASK);
            // Simpler: just try OpenProcess and capture NTSTATUS via RtlNtStatus
            h_all = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hp);
            nt_all = (h_all ? STATUS_SUCCESS : GetLastError());
            printf("open_path ALL_ACCESS=%p ntstatus=0x%08lX err=%lu\n",
                   h_all, static_cast<unsigned long>(nt_all), GetLastError());
        }

        // Path 2: exact 0x11F145
        {
            h_11f145 = OpenProcess(0x11F145, FALSE, hp);
            nt_11f145 = (h_11f145 ? STATUS_SUCCESS : GetLastError());
            printf("open_path 0x11F145=%p ntstatus=0x%08lX err=%lu\n",
                   h_11f145, static_cast<unsigned long>(nt_11f145), GetLastError());
        }

        // If ALL_ACCESS succeeded, also check the granted mask on that handle
        ULONG granted_all = 0, granted_11f145 = 0;
        if (h_all) {
            // NtQueryObject on the ALL_ACCESS handle to get actual granted mask
            struct { ULONG Attributes; ACCESS_MASK GrantedAccess; ULONG HandleCount;
                     ULONG PointerCount; } basic{};
            NTSTATUS_ qst = NtQueryObject(h_all, 0, &basic, sizeof(basic), nullptr);
            if (qst >= 0) {
                granted_all = basic.GrantedAccess;
                printf("granted_mask ALL_ACCESS handle=0x%08lX\n", static_cast<unsigned long>(granted_all));
            }
            CloseHandle(h_all);
        }
        if (h_11f145) {
            struct { ULONG Attributes; ACCESS_MASK GrantedAccess; ULONG HandleCount;
                     ULONG PointerCount; } basic{};
            NTSTATUS_ qst = NtQueryObject(h_11f145, 0, &basic, sizeof(basic), nullptr);
            if (qst >= 0) {
                granted_11f145 = basic.GrantedAccess;
                printf("granted_mask 0x11F145 handle=0x%08lX\n", static_cast<unsigned long>(granted_11f145));
            }
            CloseHandle(h_11f145);
        }

        // --- Build and run the stub (existing logic continues below) ---
        uint8_t* code = static_cast<uint8_t*>(
            VirtualAllocEx(ph, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        printf("stub alloc=%p err=%lu\n", code, GetLastError());
        if (!code) { CloseHandle(ph); return 1; }

        uint32_t buf = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(code)) + 0x100;
        std::vector<uint8_t> b;
        auto imm32 = [&](uint32_t v) {
            b.push_back(v & 0xFF);
            b.push_back((v >> 8) & 0xFF);
            b.push_back((v >> 16) & 0xFF);
            b.push_back((v >> 24) & 0xFF);
        };

        b.push_back(0x68); imm32(game);        // push game pid
        b.push_back(0x6A); b.push_back(0x00);  // push 0
        b.push_back(0x68); imm32(0x1FFFFF);    // push PROCESS_ALL_ACCESS
        b.push_back(0xB8); imm32(p_open);      // mov eax, OpenProcess
        b.push_back(0xFF); b.push_back(0xD0);  // call eax
        b.push_back(0xA3); imm32(buf + 0);     // mov [buf], eax

        b.push_back(0x6A); b.push_back(0x04);  // PAGE_READWRITE
        b.push_back(0x68); imm32(0x3000);      // MEM_COMMIT|MEM_RESERVE
        b.push_back(0x68); imm32(0x1000);      // 4 KB
        b.push_back(0x6A); b.push_back(0x00);  // lpAddress = 0
        b.push_back(0xFF); b.push_back(0x35); imm32(buf + 0);  // push [buf]
        b.push_back(0xB8); imm32(p_alloc);     // mov eax, VirtualAllocEx
        b.push_back(0xFF); b.push_back(0xD0);  // call eax
        b.push_back(0xA3); imm32(buf + 4);     // mov [buf+4], eax

        b.push_back(0xB8); imm32(p_gle);       // mov eax, GetLastError
        b.push_back(0xFF); b.push_back(0xD0);  // call eax
        b.push_back(0xA3); imm32(buf + 8);     // mov [buf+8], eax

        b.push_back(0x33); b.push_back(0xC0);  // xor eax, eax
        b.push_back(0xC3);                     // ret

        printf("stub len=%u\n", static_cast<unsigned>(b.size()));
        WriteProcessMemory(ph, code, b.data(), b.size(), nullptr);

        using SPVCT = BOOL(__stdcall*)(HANDLE, void*, SIZE_T, ULONG, void*);
        auto spv = reinterpret_cast<SPVCT>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetProcessValidCallTargets"));
        if (spv) {
            CFG_CALL_TARGET_INFO info{};
            BOOL ok = spv(ph, code, 0x1000, 1, &info);
            printf("cfg mark=%d err=%lu\n", ok ? 1 : 0, GetLastError());
        } else {
            printf("no SetProcessValidCallTargets\n");
        }

        HANDLE th = CreateRemoteThread(ph, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(code),
                                       nullptr, 0, nullptr);
        printf("thread=%p err=%lu\n", th, GetLastError());
        if (th) {
            WaitForSingleObject(th, 10000);
            DWORD ec = 0;
            GetExitCodeThread(th, &ec);

            uint32_t res[3]{};
            ReadProcessMemory(ph, reinterpret_cast<void*>(static_cast<uintptr_t>(buf)), res, sizeof(res), nullptr);
            printf("thread exit=0x%08lX handle=0x%X alloc=0x%X lasterr=%lu\n",
                   static_cast<unsigned>(ec), res[0], res[1], static_cast<unsigned long>(res[2]));
            CloseHandle(th);
        }

        VirtualFreeEx(ph, code, 0, MEM_RELEASE);
        CloseHandle(ph);
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
    if (!slurp(path, &g_local, &size)) { printf("[!] cannot read %ls\n", path); return 1; }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER_*>(g_local);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(g_local + dos->e_lfanew);
    if (dos->e_magic != 0x5A4D || nt->Signature != 0x4550 || nt->FileHeader.Machine != 0x8664) {
        printf("[!] bad image\n");
        return 1;
    }

    DWORD pid = pid_by_name(L"FortniteClient-Win64-Shipping.exe");
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
            bool ran = manual_map_host(ph, g_local, size, full, "start", &mexit, 30000);
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

    g_remote = static_cast<uint8_t*>(VirtualAllocEx(g_proc, nullptr, nt->OptionalHeader.SizeOfImage,
                                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!g_remote) {
        printf("[!] alloc failed %lu (size 0x%llX)\n", GetLastError(),
               static_cast<unsigned long long>(nt->OptionalHeader.SizeOfImage));
        return 1;
    }

    g_delta = reinterpret_cast<uint64_t>(g_remote) - nt->OptionalHeader.ImageBase;

    flush(nt, g_local);
    do_relocs(nt, g_local);

    if (!do_imports(nt, g_local)) return 1;
    flush(nt, g_local);

    // Flip section protections: code RX, data RW
    auto* sec = IMAGE_FIRST_SECTION_(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData) continue;
        DWORD prot = PAGE_READONLY;
        if (sec->Characteristics & SCN_EXECUTE_) prot = PAGE_EXECUTE_READ;
        else if (sec->Characteristics & SCN_WRITE_) prot = PAGE_READWRITE;

        DWORD old = 0;
        VirtualProtectEx(g_proc, g_remote + sec->VirtualAddress, sec->SizeOfRawData, prot, &old);
    }

    uint64_t entry_rva = find_export(nt, g_local, "start");
    if (!entry_rva) { printf("[!] start not found\n"); return 1; }

    HANDLE t = CreateRemoteThread(g_proc, nullptr, 0,
                                  reinterpret_cast<LPTHREAD_START_ROUTINE>(g_remote + entry_rva),
                                  g_remote, 0, nullptr);
    if (!t) { printf("[!] thread failed %lu\n", GetLastError()); return 1; }

    WaitForSingleObject(t, 15000);
    printf("[+] mapped at %p, log C:\\fortesp.log\n", g_remote);
    return 0;
}