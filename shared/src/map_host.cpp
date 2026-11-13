// Manual mapper shared by the loader EXE and the proxy DLL.
//
// The image is rebuilt section by section, relocated against the new base,
// its imports are resolved against the *target* process (so the loader's own
// module addresses are never used), TLS callbacks are executed and finally
// the entry point is started on a thread with a hand-built stack.
#include "map_host.hpp"
#include "hash.hpp"

#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <vector>

namespace {

void emit(map_log_fn log, const char* fmt, ...) {
    char buf[1024]{};
    va_list a;
    va_start(a, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, a);
    va_end(a);
    if (log) {
        log("%s", buf);
    } else {
        printf("%s\n", buf);
    }
}

// --- target process module walking -----------------------------------------

uint8_t* remote_module(HANDLE ph, uint32_t hash) {
    using QIP = NTSTATUS_(__stdcall*)(HANDLE, uint32_t, void*, uint32_t, uint32_t*);
    auto qip = reinterpret_cast<QIP>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!qip) return nullptr;

    PROCESS_BASIC_INFORMATION_ pbi{};
    if (qip(ph, 0, &pbi, sizeof(pbi), nullptr) < 0 || !pbi.PebBaseAddress) return nullptr;

    uint64_t ldr = 0;
    if (!ReadProcessMemory(ph, reinterpret_cast<uint8_t*>(pbi.PebBaseAddress) + 0x18, &ldr, 8, nullptr))
        return nullptr;
    if (!ldr) return nullptr;

    uint64_t head = ldr + 0x10, cur = 0;
    if (!ReadProcessMemory(ph, reinterpret_cast<void*>(head), &cur, 8, nullptr)) return nullptr;

    for (int guard = 0; cur && cur != head && guard < 512; ++guard) {
        LDR_DATA_TABLE_ENTRY_ e{};
        if (!ReadProcessMemory(ph, reinterpret_cast<void*>(cur), &e, sizeof(e), nullptr)) break;

        if (e.BaseDllName.Buffer) {
            wchar_t name[64]{};
            ReadProcessMemory(ph, e.BaseDllName.Buffer, name, sizeof(name) - 2, nullptr);
            if (h::fnv1a_w(name) == hash) return static_cast<uint8_t*>(e.DllBase);
        }
        ReadProcessMemory(ph, reinterpret_cast<void*>(cur), &cur, 8, nullptr);
    }
    return nullptr;
}

uint64_t remote_proc(HANDLE ph, uint32_t mod_hash, uint32_t fn_hash) {
    auto* base = remote_module(ph, mod_hash);
    if (!base) return 0;

    IMAGE_DOS_HEADER_ dos{};
    ReadProcessMemory(ph, base, &dos, sizeof(dos), nullptr);

    IMAGE_NT_HEADERS64_ nt{};
    ReadProcessMemory(ph, base + dos.e_lfanew, &nt, sizeof(nt), nullptr);

    auto& dir = nt.OptionalHeader.DataDirectory[DIR_EXPORT_];
    if (!dir.VirtualAddress) return 0;

    IMAGE_EXPORT_DIRECTORY_ ed{};
    ReadProcessMemory(ph, base + dir.VirtualAddress, &ed, sizeof(ed), nullptr);

    for (uint32_t i = 0; i < ed.NumberOfNames; ++i) {
        uint32_t rva = 0;
        ReadProcessMemory(ph, base + ed.AddressOfNames + i * 4, &rva, 4, nullptr);

        char name[128]{};
        ReadProcessMemory(ph, base + rva, name, sizeof(name) - 1, nullptr);
        if (h::fnv1a(name) != fn_hash) continue;

        uint16_t ord = 0;
        ReadProcessMemory(ph, base + ed.AddressOfNameOrdinals + i * 2, &ord, 2, nullptr);

        uint32_t fn = 0;
        ReadProcessMemory(ph, base + ed.AddressOfFunctions + ord * 4, &fn, 4, nullptr);
        return reinterpret_cast<uint64_t>(base + fn);
    }
    return 0;
}

// Fill the image's import table with addresses taken from the target process.
bool resolve_imports(HANDLE ph, IMAGE_NT_HEADERS64_* nt, uint8_t* img, map_log_fn log) {
    auto& dir = nt->OptionalHeader.DataDirectory[DIR_IMPORT_];
    if (!dir.VirtualAddress) return true;

    bool self = (ph == GetCurrentProcess());

    auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR_*>(img + dir.VirtualAddress);
    for (; imp->Name; ++imp) {
        char dll[128]{};
        memcpy(dll, img + imp->Name, sizeof(dll) - 1);

        for (auto* thunk = reinterpret_cast<uint64_t*>(img + imp->FirstThunk); *thunk; ++thunk) {
            if (*thunk & 0x8000000000000000ull) continue;   // import by ordinal

            char fn[128]{};
            memcpy(fn, img + *thunk + 2, sizeof(fn) - 1);

            uint64_t addr = remote_proc(ph, h::fnv1a(dll), h::fnv1a(fn));
            if (!addr && self) {
                // The target does not have the module loaded. When the mapper
                // runs inside the target (the proxy case) a local load is
                // exactly that - the game runs D3D12 but the payload wants
                // d3d11, which is not in its module list.
                wchar_t wdll[160]{};
                MultiByteToWideChar(CP_ACP, 0, dll, -1, wdll, 160);
                if (LoadLibraryW(wdll)) {
                    addr = remote_proc(ph, h::fnv1a(dll), h::fnv1a(fn));
                    if (addr) emit(log, "[*] mm: loaded %s for the target", dll);
                }
            }
            if (!addr) {
                emit(log, "[!] unresolved %s!%s", dll, fn);
                return false;
            }
            *thunk = addr;
        }
    }
    return true;
}

// Relocate the image in place for `delta`.
void apply_relocs(IMAGE_NT_HEADERS64_* nt, uint8_t* img, uint64_t delta) {
    auto& dir = nt->OptionalHeader.DataDirectory[DIR_BASERELOC_];
    if (!dir.VirtualAddress || !dir.Size || !delta) return;

    auto* blk = reinterpret_cast<IMAGE_BASE_RELOCATION_*>(img + dir.VirtualAddress);
    uint32_t left = dir.Size;
    while (left > sizeof(IMAGE_BASE_RELOCATION_)) {
        if (!blk->SizeOfBlock) break;
        uint32_t n = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION_)) / 2;
        auto* ent = reinterpret_cast<uint16_t*>(blk + 1);
        for (uint32_t i = 0; i < n; ++i) {
            if ((ent[i] >> 12) != REL_DIR64_) continue;
            auto* p = reinterpret_cast<uint64_t*>(img + blk->VirtualAddress + (ent[i] & 0xFFF));
            *p += delta;
        }
        left -= blk->SizeOfBlock;
        blk = reinterpret_cast<IMAGE_BASE_RELOCATION_*>(
            reinterpret_cast<uint8_t*>(blk) + blk->SizeOfBlock);
    }
}

// Find a `ret` in an executable section so the mapped thread can return into
// the image's own exit thunk.
uint64_t find_ret_gadget(IMAGE_NT_HEADERS64_* nt, uint8_t* local, uint8_t* remote) {
    auto* sec = IMAGE_FIRST_SECTION_(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & SCN_EXECUTE_)) continue;
        auto* p = local + sec->VirtualAddress;
        uint32_t n = sec->VirtualSize ? sec->VirtualSize : sec->SizeOfRawData;
        for (uint32_t b = 0; b < n; ++b) {
            if (p[b] == 0xC3) {
                return reinterpret_cast<uint64_t>(remote) + sec->VirtualAddress + b;
            }
        }
    }
    return 0;
}

// NtCreateThreadEx returns a handle that the context calls refuse: the entry
// exists for the caller's process while NtCreate/NtSetContextThread still go
// through the target's own conversion and answer STATUS_ACCESS_VIOLATION. A
// DUP_HANDLE duplicate of the same entry is accepted. This walks this
// process's handle table to find the entry with that numeric value.
HANDLE dup_local_handle(HANDLE h) {
    using NtQSI = NTSTATUS_(__stdcall*)(ULONG, void*, ULONG, ULONG*);
    static auto qsi = reinterpret_cast<NtQSI>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!qsi) return nullptr;

    struct E {
        uintptr_t object, pid, handle;
        uint32_t  access;
        uint16_t  bt, type;
        uint32_t  attrs, reserved;
    };

    std::vector<uint8_t> buf(1 << 20);
    ULONG ret = 0;
    NTSTATUS_ st = static_cast<NTSTATUS_>(-1);
    for (int i = 0; i < 8; ++i) {
        st = qsi(0x40, buf.data(), static_cast<ULONG>(buf.size()), &ret);
        if (st >= 0) break;
        if (st != static_cast<NTSTATUS_>(0xC0000004)) return nullptr;
        buf.resize(buf.size() * 2);
    }
    if (st < 0) return nullptr;

    uintptr_t count = *reinterpret_cast<uintptr_t*>(buf.data());
    auto* ent = reinterpret_cast<E*>(buf.data() + 0x10);
    uintptr_t me = GetCurrentProcessId();

    for (uintptr_t i = 0; i < count; ++i) {
        if (ent[i].pid != me) continue;
        if (reinterpret_cast<HANDLE>(ent[i].handle) != h) continue;

        HANDLE dup = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dup,
                             0, FALSE, DUPLICATE_SAME_ACCESS))
            return nullptr;
        return dup;
    }
    return nullptr;
}

// TLS callbacks are invoked with (DllHandle, DLL_PROCESS_ATTACH, 0). They run
// on their own threads so a callback that blocks cannot stall the mapper.
void run_tls_callbacks(HANDLE ph, uint8_t* remote, IMAGE_NT_HEADERS64_* nt, map_log_fn log) {
    auto& dir = nt->OptionalHeader.DataDirectory[DIR_TLS_];
    if (!dir.VirtualAddress) {
        emit(log, "[*] mm: no tls directory");
        return;
    }

    // A manually mapped image is not registered with the loader, so its TLS
    // directory is not there for the kernel to fill in: the callbacks array
    // lives at a static VA, and what the kernel writes to it at thread start
    // (the new thread's TLS slots) never happens here. Every TLS read then
    // lands on a null or stale pointer - which is why a body that reads one
    // static can end the thread with STATUS_PENDING and no exception.
    emit(log, "[*] mm: tls at rva 0x%llX (manually mapped images get no TLS slots)",
         static_cast<unsigned long long>(dir.VirtualAddress));

    IMAGE_TLS_DIRECTORY64_ tls{};
    if (!ReadProcessMemory(ph, remote + dir.VirtualAddress, &tls, sizeof(tls), nullptr)) {
        emit(log, "[!] mm: tls directory read failed %lu", GetLastError());
        return;
    }
    if (!tls.AddressOfCallBacks) {
        emit(log, "[*] mm: tls without callbacks");
        return;
    }

    for (int i = 0; i < 64; ++i) {
        uint64_t cb = 0;
        if (!ReadProcessMemory(ph, reinterpret_cast<void*>(tls.AddressOfCallBacks + i * 8), &cb, 8, nullptr) || !cb)
            break;

        // 0x2 = THREAD_CREATE_FLAGS_SUSPENDED: the context has to be fixed up
        // before the callback runs.
        HANDLE th = nullptr;
        if (nt_create_thread(ph, reinterpret_cast<void*>(cb), nullptr, 0x2, &th) < 0 || !th) {
            emit(log, "[!] mm: tls thread %d failed", i);
            continue;
        }

        // The handle has to be a duplicate before any context call.
        if (HANDLE dup = dup_local_handle(th)) { CloseHandle(th); th = dup; }

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (GetThreadContext(th, &ctx)) {
            ctx.Rcx = reinterpret_cast<DWORD64>(remote);   // hDll
            ctx.Rdx = 1;                                  // DLL_PROCESS_ATTACH
            ctx.R8 = 0;
            SetThreadContext(th, &ctx);
        } else {
            emit(log, "[!] mm: tls ctx read failed %lu", GetLastError());
        }

        ResumeThread(th);
        WaitForSingleObject(th, 10000);
        DWORD ec = 0;
        GetExitCodeThread(th, &ec);
        CloseHandle(th);
        emit(log, "[*] mm: tls cb %d ok (exit 0x%08lX)", i, static_cast<unsigned long>(ec));
    }
}

} // namespace

bool slurp_file(const wchar_t* path, uint8_t** out, size_t* size) {
    if (!path || !out || !size) return false;

    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER li{};
    GetFileSizeEx(f, &li);
    *size = static_cast<size_t>(li.QuadPart);
    *out = new uint8_t[*size];

    DWORD got = 0;
    bool ok = ReadFile(f, *out, static_cast<DWORD>(*size), &got, nullptr) && got == *size;
    CloseHandle(f);
    if (!ok) { delete[] *out; *out = nullptr; *size = 0; }
    return ok;
}

uint64_t find_export(IMAGE_NT_HEADERS64_* nt, uint8_t* img, const char* name) {
    if (!nt || !img || !name || !*name) return 0;

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

NTSTATUS_ nt_create_thread(HANDLE proc, void* start, void* arg, uint32_t flags, HANDLE* out) {
    using NtCTE = NTSTATUS_(__stdcall*)(HANDLE*, uint32_t, void*, HANDLE, void*,
                                        void*, uint32_t, uintptr_t, uintptr_t,
                                        uintptr_t, void*);
    static NtCTE cte = reinterpret_cast<NtCTE>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"));
    if (!cte) return static_cast<NTSTATUS_>(-1);
    // StackSize stays 0 (the process default). Passing an explicit size is
    // rejected by this kernel with STATUS_INVALID_PARAMETER.
    return cte(out, 0x1FFFFF, nullptr, proc, start, arg, flags, 0, 0, 0, nullptr);
}

static int g_probe_mode = -1;

void manual_map_set_probe(int mode) { g_probe_mode = mode; }

bool manual_map_host(HANDLE ph, const uint8_t* img, size_t img_size,
                     const wchar_t* self_path, const char* start_export,
                     bool keep_mapped, map_result* out, DWORD wait_ms,
                     map_log_fn log) {
    uint64_t trace_rva_hint = 0;
    if (out) { out->started = false; out->exit_code = 0; out->remote = 0; }
    if (!ph || !img || img_size < 0x100) return false;
    // A run that produced a hard fault leaves a crashed thread behind; calling
    // the same code again with the previous run's image still mapped makes
    // every measurement ambiguous. Say so loudly instead of guessing.
    emit(log, "[*] mm: mapper entry (previous run: started=%d exit=0x%lX remote=%p)",
         out ? static_cast<int>(out->started) : -1,
         out ? static_cast<unsigned long>(out->exit_code) : 0UL,
         out ? reinterpret_cast<void*>(out->remote) : nullptr);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER_*>(const_cast<uint8_t*>(img));
    if (dos->e_magic != 0x5A4D) { emit(log, "[!] mm: not an image"); return false; }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64_*>(const_cast<uint8_t*>(img) + dos->e_lfanew);

    SIZE_T image_size = nt->OptionalHeader.SizeOfImage;

    // Keep the image low: the stub-style code in this project addresses
    // things with absolute imm32, and a 32-bit host cannot use a base above
    // 4 GB anyway.
    static const ULONG_PTR kHint[] = { 0x10000000, 0x18000000, 0x20000000,
                                       0x30000000, 0x40000000, 0x50000000 };
    uint8_t* remote = nullptr;
    for (size_t i = 0; i < _countof(kHint) && !remote; ++i) {
        remote = static_cast<uint8_t*>(
            VirtualAllocEx(ph, reinterpret_cast<LPVOID>(kHint[i]), image_size,
                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    }
    if (!remote) {
        remote = static_cast<uint8_t*>(
            VirtualAllocEx(ph, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    }
    if (!remote) {
        // The error has to be captured *before* anything else runs: a printf
        // between the failing call and GetLastError resets it, and that is how
        // this line printed 5 for a call that failed for a different reason on
        // a child process we own ourselves.
        DWORD e = GetLastError();
        emit(log, "[!] mm: host image alloc failed %lu (hint %d, size 0x%llX)",
             static_cast<unsigned long>(e), (int)_countof(kHint),
             static_cast<unsigned long long>(image_size));
        return false;
    }
    emit(log, "[*] mm: remote=%p image=0x%llX", remote, static_cast<unsigned long long>(image_size));

    uint8_t* stack = nullptr;
    auto cleanup = [&](bool free_stack) {
        if (free_stack && stack) VirtualFreeEx(ph, stack, 0, MEM_RELEASE);
        VirtualFreeEx(ph, remote, 0, MEM_RELEASE);
    };

    // Rebuild the image in memory.
    std::vector<uint8_t> local(image_size, 0);
    size_t hdr = nt->OptionalHeader.SizeOfHeaders;
    if (hdr > img_size) hdr = img_size;
    memcpy(local.data(), img, hdr);

    auto* sec = IMAGE_FIRST_SECTION_(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData) continue;
        if (static_cast<uint64_t>(sec->PointerToRawData) + sec->SizeOfRawData > img_size) {
            emit(log, "[!] mm: bad section %u", static_cast<unsigned>(i));
            cleanup(false);
            return false;
        }
        memcpy(local.data() + sec->VirtualAddress, img + sec->PointerToRawData, sec->SizeOfRawData);
    }

    uint64_t delta = reinterpret_cast<uint64_t>(remote) - nt->OptionalHeader.ImageBase;
    apply_relocs(nt, local.data(), delta);

    // Imports must point at the target's modules, not at ours.
    if (!resolve_imports(ph, nt, local.data(), log)) {
        cleanup(false);
        return false;
    }

    // The export directory is NOT written by the section loop above when the
    // linker has put it in a section of its own (.edata at 0x18E000, past
    // .bss): a manually mapped image has no export table at runtime, so
    // find_export() returned 0 for every name and the mapper silently fell
    // back to the entry point. Copy the directory here, by RVA, before any
    // export is looked up.
    emit(log, "[*] mm: export dir va=0x%llX size=0x%llX img_size=0x%llX image_size=0x%llX",
         static_cast<unsigned long long>(nt->OptionalHeader.DataDirectory[DIR_EXPORT_].VirtualAddress),
         static_cast<unsigned long long>(nt->OptionalHeader.DataDirectory[DIR_EXPORT_].Size),
         static_cast<unsigned long long>(img_size),
         static_cast<unsigned long long>(image_size));
    {
        auto& ed = nt->OptionalHeader.DataDirectory[DIR_EXPORT_];
        // The export directory lives at a VirtualAddress, not a file offset:
        // for this image 0x18E000 is past the end of the file (0xB91D), so
        // comparing it against the file size skips the copy and every export
        // lookup comes back empty.
        if (ed.VirtualAddress && ed.Size &&
            static_cast<uint64_t>(ed.VirtualAddress) + ed.Size <= image_size) {
            // From the section's FILE offset, not from the RVA: the .edata
            // section has VirtualAddress 0x18E000 but PointerToRawData 0x8A00,
            // so `img + 0x18E000` is past the end of the file.
            const uint8_t* src = nullptr;
            {
                auto* s2 = IMAGE_FIRST_SECTION_(nt);
                for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++s2) {
                    if (ed.VirtualAddress < s2->VirtualAddress) continue;
                    uint32_t off = ed.VirtualAddress - s2->VirtualAddress;
                    if (off + ed.Size > s2->SizeOfRawData) continue;
                    src = img + s2->PointerToRawData + off;
                    break;
                }
            }
            if (src) {
                memcpy(local.data() + ed.VirtualAddress, src, ed.Size);
                emit(log, "[*] mm: export directory copied to rva 0x%llX (%lu bytes)",
                     static_cast<unsigned long long>(ed.VirtualAddress),
                     static_cast<unsigned long>(ed.Size));
            } else {
                emit(log, "[!] mm: export directory not in any file-backed section");
            }
        }
    }

    // g_trace is where the payload keeps its phase markers, and it lives in
    // .data. Take its address from the image itself so a moved section cannot
    // make the loader read .bss.
    {
        auto* s4 = IMAGE_FIRST_SECTION_(nt);
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++s4) {
            const char* nm = reinterpret_cast<const char*>(s4->Name);
            if (nm[0] == '.' && nm[1] == 'd' && nm[2] == 'a' && nm[3] == 't' && nm[4] == 'a')
                emit(log, "[*] mm: .data at rva 0x%llX",
                     static_cast<unsigned long long>(s4->VirtualAddress));
        }
    }

    // Bake the payload path into g_host_path when the image exports it.
    uint64_t path_rva = find_export(nt, local.data(), "g_host_path");
    if (path_rva && self_path) {
        lstrcpynW(reinterpret_cast<wchar_t*>(local.data() + path_rva), self_path, 260);
    }

    // A probe request is a single number the image exports; the host writes it
    // before the thread exists, so the payload sees it on its first instruction
    // instead of racing with a thread that is already running.
    if (g_probe_mode >= 0) {
        uint64_t probe_rva = find_export(nt, local.data(), "g_probe_mode");
        if (probe_rva) {
            *reinterpret_cast<int32_t*>(local.data() + probe_rva) = g_probe_mode;
            emit(log, "[*] mm: probe mode %d", g_probe_mode);
        } else {
            emit(log, "[!] mm: probe mode requested, g_probe_mode not exported");
        }
    }

    // Entry point: an explicit export, otherwise the image's own entry
    // (_DllMainCRTStartup for a real CRT image).
    uint64_t start_rva = 0;
    if (start_export && *start_export) {
        start_rva = find_export(nt, local.data(), start_export);
        if (!start_rva) {
            emit(log, "[*] mm: export %s missing, using entry point", start_export);
        }
    }
    if (!start_rva) start_rva = nt->OptionalHeader.AddressOfEntryPoint;

    uint64_t exit_rva = find_export(nt, local.data(), "exit_thunk");
    if (!exit_rva) { emit(log, "[!] mm: exit_thunk export missing"); cleanup(false); return false; }

    // Report where the payload actually exported from. A stale payload.dll
    // with an older .text layout and the loader's own idea of "the entry" must
    // never be confused again: the RVAs below are read from the file the
    // mapper is mapping right now, and a payload that reaches only half of its
    // own start routine shows up here as a mismatch against a fresh build.
    // What the mapping looks like where execution is about to start: the
    // loader's own read of .data at +0x8000 showed a value the payload never
    // writes, so the mapping and the RVAs may disagree. Report the bytes the
    // mapper wrote at the entry RVA and at .data[0].
    if (static_cast<uint64_t>(start_rva) + 16 <= image_size) {
        const uint8_t* e = local.data() + start_rva;
        emit(log, "[*] mm: local[entry] = %02X %02X %02X %02X %02X %02X %02X %02X",
             e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7]);
    }
    {
        const uint8_t* d = local.data() + 0x8000;
        emit(log, "[*] mm: local[.data] = %02X %02X %02X %02X %02X %02X %02X %02X",
             d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
    }
    emit(log, "[*] mm: find_export(g_trace)=0x%llX find_export(start)=0x%llX",
         static_cast<unsigned long long>(find_export(nt, local.data(), "g_trace")),
         static_cast<unsigned long long>(find_export(nt, local.data(), "start")));
    emit(log, "[*] mm: entry=0x%llX path=0x%llX exit=0x%llX (image rva base)",
         static_cast<unsigned long long>(start_rva),
         static_cast<unsigned long long>(path_rva),
         static_cast<unsigned long long>(exit_rva));

    emit(log, "[*] mm: entry rva=0x%llX path_rva=0x%llX exit_rva=0x%llX delta=0x%llX",
         static_cast<unsigned long long>(start_rva),
         static_cast<unsigned long long>(path_rva),
         static_cast<unsigned long long>(exit_rva),
         static_cast<unsigned long long>(delta));

    // Only the parts that exist on disk: the .bss gap has no file bytes and is
    // delivered separately below. Writing the whole SizeOfImage here is what
    // made the .bss delivery pointless - the zeros arrived afterwards.
    uint64_t copy_end = 0;
    for (auto* cs = IMAGE_FIRST_SECTION_(nt), *e = cs + nt->FileHeader.NumberOfSections; cs < e; ++cs)
        if (cs->SizeOfRawData)
            copy_end = std::max<uint64_t>(copy_end, static_cast<uint64_t>(cs->VirtualAddress) + cs->SizeOfRawData);
    if (!copy_end) copy_end = nt->OptionalHeader.SizeOfHeaders;
    // one write per contiguous file-backed run would be tidier, but a single
    // sized write over [0, copy_end) leaves out exactly the .bss gap only when
    // .bss is the last section, which it is for this payload
    if (!WriteProcessMemory(ph, remote, local.data(),
                            static_cast<SIZE_T>(copy_end), nullptr)) {
        emit(log, "[!] mm: host image write failed %lu", GetLastError());
        cleanup(false);
        return false;
    }

    DWORD old = 0;
    VirtualProtectEx(ph, remote, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old);
    sec = IMAGE_FIRST_SECTION_(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData) {
            // .bss is reserve-only on disk but real memory in the mapped image:
            // if it is not delivered the payload's own statics, its runtime
            // allocation and the page the section promises all land on fresh
            // zero pages *per process* - two processes would each write their
            // own copy and read back nothing the other wrote. Hand over one
            // zero-filled delivery that both can see.
            uint32_t sz = sec->VirtualSize;
            if (!sz) continue;
            HANDLE dmap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                            0, sz, nullptr);
            if (dmap) {
                void* dsrc = MapViewOfFile(dmap, FILE_MAP_ALL_ACCESS, 0, 0, sz);
                if (dsrc) {
                    if (!WriteProcessMemory(ph, remote + sec->VirtualAddress, dsrc, sz, nullptr))
                        emit(log, "[!] mm: bss write failed %lu", GetLastError());
                    else
                        emit(log, "[*] mm: bss section delivered as one shared mapping (%lu bytes)",
                             static_cast<unsigned long>(sz));
                    UnmapViewOfFile(dsrc);
                }
                CloseHandle(dmap);
            }
            continue;
        }
        // The payload rewrites its own statics after it starts (the phase
        // trace, the worker's flags), so a .data page mapped read-only here is
        // an access violation waiting for the first store. Executable sections
        // get RX; everything else stays writable, exactly like the loader does
        // for a real DLL. Read-only is only safe for .rdata, and the section
        // header cannot tell .data from .rdata reliably enough to risk it.
        DWORD prot = PAGE_READWRITE;
        if (sec->Characteristics & SCN_EXECUTE_) prot = PAGE_EXECUTE_READ;
        // The region to protect is the one that was written, and it is not
        // always SizeOfRawData: .data is 0x50 bytes of VirtualSize with a
        // 0x200-byte raw size, so protecting SizeOfRawData both over-runs into
        // the next section and, when the two disagree the other way, leaves
        // the tail of the section on the wrong protection.
        SIZE_T prot_size = sec->SizeOfRawData;
        if (sec->VirtualSize && sec->VirtualSize < prot_size) prot_size = sec->VirtualSize;
        if (!prot_size) continue;
        if (!VirtualProtectEx(ph, remote + sec->VirtualAddress, prot_size, prot, &old))
            emit(log, "[!] mm: protect sec %u (0x%lX) failed %lu",
                 static_cast<unsigned>(i), prot, GetLastError());
    }

    // TLS callbacks run before the entry point.
    run_tls_callbacks(ph, remote, nt, log);

    // Return chain: start -> ret gadget -> exit thunk.
    uint64_t gadget = find_ret_gadget(nt, local.data(), remote);
    if (!gadget) { emit(log, "[!] mm: no ret gadget"); cleanup(false); return false; }

    uint64_t exit_thunk = reinterpret_cast<uint64_t>(remote) + exit_rva;

    stack = static_cast<uint8_t*>(
        VirtualAllocEx(ph, nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!stack) { emit(log, "[!] mm: host stack alloc failed %lu", GetLastError()); cleanup(false); return false; }

    uint64_t top = reinterpret_cast<uint64_t>(stack) + 0x8000;
    top &= ~0xFull;
    top -= 8;                               // RSP % 16 == 8 at function entry
    uint64_t frame[2] = { gadget, exit_thunk };
    WriteProcessMemory(ph, reinterpret_cast<void*>(top), frame, sizeof(frame), nullptr);

    // Let the normal thread startup run the payload: LdrInitializeThunk ->
    // RtlUserThreadStart -> StartRoutine(Argument). Hijacking the context of a
    // brand-new thread breaks the startup context NtContinue restores.
    uint64_t entry = reinterpret_cast<uint64_t>(remote) + start_rva;
    HANDLE th = nullptr;
    // Created suspended (0x2), never run-synchronous (0x1): the start context
    // has to be installed before the thread executes a single instruction.
    NTSTATUS_ st = nt_create_thread(ph, reinterpret_cast<void*>(entry),
                                     reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(remote)),
                                     2, &th);
    if (st < 0 || !th) {
        emit(log, "[!] mm: host thread create failed 0x%08lX", static_cast<unsigned>(st));
        cleanup(true);
        return false;
    }
    emit(log, "[*] mm: thread=%p status=0x%08lX stack=%p entry=0x%llX",
         th, static_cast<unsigned>(st), stack, static_cast<unsigned long long>(entry));

    // The start routine and its argument are installed through the context of
    // the suspended thread (the same calls the TLS path uses), so the image's
    // entry point is reached even when the kernel's own start context is not
    // usable across a 32/64 bit boundary.
    uint32_t start_flag = 1;
    bool ctx_installed = false;
    HANDLE ctx_th = nullptr;
    {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        // A duplicated thread handle stops SuspendThread/ResumeThread from
        // touching the real thread (count stays 0, resume reports 0, the thread
        // never runs and exits with STATUS_PENDING). Only the context calls
        // needed the duplicate, so use it for them and keep the original for
        // the scheduling calls.
        ctx_th = dup_local_handle(th);
        emit(log, "[*] mm: ctx handle dup=%d", ctx_th ? 1 : 0);

        HANDLE use = ctx_th ? ctx_th : th;
        if (GetThreadContext(use, &ctx)) {
            ctx.Rip = entry;
            ctx.Rsp = top;
            ctx.Rcx = reinterpret_cast<uint64_t>(remote);
            ctx.Rdx = start_flag;
            ctx.R8 = 0;
            if (SetThreadContext(use, &ctx)) {
                ctx_installed = true;
            } else {
                emit(log, "[!] mm: SetThreadContext failed %lu (keep the created start context)",
                     GetLastError());
            }
        } else {
            emit(log, "[!] mm: GetThreadContext failed %lu (keep the created start context)",
                 GetLastError());
        }
    }
    if (ctx_th) CloseHandle(ctx_th);
    (void)ctx_installed;

    // A suspended thread reports suspend count 0 when it is already
    // terminated, and ResumeThread then returns 0 and does nothing - which is
    // the "thread exits 0x103 with no exception" signature. Probe, then resume
    // exactly once.
    {
        DWORD sc = SuspendThread(th);
        DWORD err = (sc == static_cast<DWORD>(-1)) ? GetLastError() : 0;
        emit(log, "[*] mm: suspend probe=%ld err=%lu thread=%p entry=0x%llX rsp=0x%llX",
             static_cast<long>(sc), static_cast<unsigned long>(err), th,
             static_cast<unsigned long long>(entry),
             static_cast<unsigned long long>(top));
        if (sc != static_cast<DWORD>(-1)) ResumeThread(th);
    }

    DWORD resume_ret = ResumeThread(th);
    emit(log, "[*] mm: resume ret=%ld (0xFFFFFFFF means already terminated)",
         static_cast<long>(resume_ret));
    fflush(stdout);
    // The image's own protections are installed *before* the thread is
    // resumed. If they are applied after the thread has started, the payload's
    // entry point runs against the PAGE_READWRITE pages the copy left behind
    // and its very first write to a .data static is a read-only fault - which
    // is what the log showed: every stage up to launch_worker ran, and the
    // thread then died inside it without any further line.
    WaitForSingleObject(th, wait_ms);

    DWORD ec = 0;
    GetExitCodeThread(th, &ec);
    bool exited = WaitForSingleObject(th, 0) == WAIT_OBJECT_0;
    if (out) { out->started = true; out->exit_code = ec; out->remote = reinterpret_cast<uintptr_t>(remote); }
    emit(log, "[*] mm: thread exit=%lu (0x%08lX) exited=%d",
         static_cast<unsigned long>(ec), static_cast<unsigned>(ec), exited ? 1 : 0);

    // Trace base: the loader used to read g_trace at 0xD000, which is where
    // the *loader's own* find_export lands - and 0xD000 is .bss. The payload's
    // g_trace is in .data (exports and variables are different sections), so
    // ask the image itself instead of guessing.
    // The mapper cannot find g_trace by export (the loader-side resolver is
    // not the one the payload uses), and the loader used to read the trace at
    // 0xD000 - which is .bss, not .data. The linker script puts every exported
    // object in .data, so the trace lives at .data's RVA; report that as the
    // trace base and let the loader read it from there.
    uint64_t tr_rva = 0;
    {
        auto* s3 = IMAGE_FIRST_SECTION_(nt);
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++s3) {
            const char* nm = reinterpret_cast<const char*>(s3->Name);
            if (nm[0] == '.' && nm[1] == 'd' && nm[2] == 'a' && nm[3] == 't' && nm[4] == 'a') {
                tr_rva = s3->VirtualAddress;
                break;
            }
        }
    }
    (void)find_export(nt, local.data(), "g_trace");
    trace_rva_hint = tr_rva;
    {
        auto* s3 = IMAGE_FIRST_SECTION_(nt);
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++s3) {
            const char* nm = reinterpret_cast<const char*>(s3->Name);
            if (nm[0] == '.' && nm[1] == 'd' && nm[2] == 'a' && nm[3] == 't' && nm[4] == 'a') {
                emit(log, "[*] mm: .data rva=0x%llX size=0x%llX (g_trace=0x%llX)",
                     static_cast<unsigned long long>(s3->VirtualAddress),
                     static_cast<unsigned long long>(s3->VirtualSize),
                     static_cast<unsigned long long>(tr_rva));
                break;
            }
        }
    }
    if (tr_rva) {
        uint32_t tr[16]{};
        if (ReadProcessMemory(ph, remote + tr_rva, tr, sizeof(tr), nullptr)) {
            char line[512]{};
            int n = 0;
            n += _snprintf_s(line + n, sizeof(line) - n, _TRUNCATE, "[*] mm: trace");
            for (int i = 0; i < 16; ++i)
                if (tr[i]) n += _snprintf_s(line + n, sizeof(line) - n, _TRUNCATE, " %d=%08X", i, tr[i]);
            emit(log, "%s", line);
        } else {
            emit(log, "[!] mm: trace read failed %lu", GetLastError());
        }
    }

    CloseHandle(th);

    // The entry thread is gone; the mapping is not. Say whether the page the
    // trace lives on is still readable before handing control back, so a later
    // "trace read failed 299" cannot be mistaken for a payload bug.
    {
        MEMORY_BASIC_INFORMATION mbi{};
        uint64_t tr = reinterpret_cast<uint64_t>(remote) + trace_rva_hint;
        if (VirtualQueryEx(ph, reinterpret_cast<LPCVOID>(tr), &mbi, sizeof(mbi))) {
            emit(log, "[*] mm: post-run trace page state=0x%lX protect=0x%lX base=%p",
                 static_cast<unsigned long>(mbi.State),
                 static_cast<unsigned long>(mbi.Protect),
                 mbi.BaseAddress);
        } else {
            emit(log, "[!] mm: post-run VirtualQueryEx failed %lu", GetLastError());
        }
        uint8_t probe[4]{};
        SIZE_T got = 0;
        if (!ReadProcessMemory(ph, reinterpret_cast<LPCVOID>(tr), probe, 4, &got))
            emit(log, "[!] mm: post-run trace read failed %lu (got=%llu)", GetLastError(),
                 static_cast<unsigned long long>(got));
    }

    if (exited && !keep_mapped) {
        VirtualFreeEx(ph, stack, 0, MEM_RELEASE);
        VirtualFreeEx(ph, remote, 0, MEM_RELEASE);
    }
    return exited;
}
