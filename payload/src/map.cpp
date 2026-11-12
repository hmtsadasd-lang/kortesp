#include "map.hpp"
#include "log.hpp"
#include "../../shared/include/syscall.hpp"
#include "../../shared/include/hash.hpp"
#include "../../shared/include/mem.hpp"
#include <intrin.h>

namespace {

struct CID { void* proc; void* thread; };
struct OA  { uint32_t len; void* root; void* obj; uint32_t attr; void* sd; };

void copy_(void* d, const void* s, size_t n) {
    auto* a = static_cast<uint8_t*>(d);
    auto* b = static_cast<const uint8_t*>(s);
    while (n--) *a++ = *b++;
}

bool readm(void* p, uint64_t a, void* d, size_t n) {
    uint64_t got = 0;
    return NT_SUCCESS(sc5(UPTR(p), UPTR(&a), UPTR(d), n, UPTR(&got), sys::num("NtReadVirtualMemory")));
}

bool writem(void* p, uint64_t a, const void* s, size_t n) {
    uint64_t put = 0;
    return NT_SUCCESS(sc5(UPTR(p), UPTR(&a), UPTR(s), n, UPTR(&put), sys::num("NtWriteVirtualMemory")));
}

uint64_t remote_proc(void* p, uint32_t mod_hash, uint32_t fn_hash) {
    uint64_t ldr = 0;
    // PEB of the target: resolve through NtQueryInformationProcess
    struct PBI { NTSTATUS_ st; void* peb; uintptr_t a; int32_t b; uintptr_t c, d; };
    PBI pbi{};
    uint32_t ret = 0;
    if (!NT_SUCCESS(sc5(UPTR(p), 0, UPTR(&pbi), sizeof(pbi), UPTR(&ret),
                        sys::num("NtQueryInformationProcess")))) return 0;
    if (!pbi.peb) return 0;

    if (!readm(p, UPTR(pbi.peb) + 0x18, &ldr, 8) || !ldr) return 0;

    uint64_t head = ldr + 0x10, cur = 0;
    readm(p, head, &cur, 8);

    for (int g = 0; cur && cur != head && g < 512; ++g) {
        LDR_DATA_TABLE_ENTRY_ e{};
        if (!readm(p, cur, &e, sizeof(e))) break;

        if (e.BaseDllName.Buffer) {
            wchar_t nm[64]{};
            readm(p, UPTR(e.BaseDllName.Buffer), nm, sizeof(nm) - 2);
            if (h::fnv1a_w(nm) == mod_hash) {
                auto* b = static_cast<uint8_t*>(e.DllBase);
                IMAGE_DOS_HEADER_ dos{};
                IMAGE_NT_HEADERS64_ nt{};
                readm(p, UPTR(b), &dos, sizeof(dos));
                readm(p, UPTR(b) + dos.e_lfanew, &nt, sizeof(nt));

                auto& dir = nt.OptionalHeader.DataDirectory[DIR_EXPORT_];
                if (!dir.VirtualAddress) return 0;

                IMAGE_EXPORT_DIRECTORY_ ed{};
                readm(p, UPTR(b) + dir.VirtualAddress, &ed, sizeof(ed));

                for (uint32_t i = 0; i < ed.NumberOfNames; ++i) {
                    uint32_t rva = 0;
                    readm(p, UPTR(b) + ed.AddressOfNames + i * 4, &rva, 4);
                    char fn[128]{};
                    readm(p, UPTR(b) + rva, fn, sizeof(fn) - 1);
                    if (h::fnv1a(fn) != fn_hash) continue;

                    uint16_t ord = 0;
                    readm(p, UPTR(b) + ed.AddressOfNameOrdinals + i * 2, &ord, 2);
                    uint32_t frva = 0;
                    readm(p, UPTR(b) + ed.AddressOfFunctions + ord * 4, &frva, 4);
                    return UPTR(b) + frva;
                }
                return 0;
            }
        }
        readm(p, cur, &cur, 8);
    }
    return 0;
}

} // namespace

bool map::into(uint32_t pid, const uint8_t* img, size_t, void** out) {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER_*>(const_cast<uint8_t*>(img));
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(const_cast<uint8_t*>(img) + dos->e_lfanew);

    uint64_t h = 0;
    CID cid{ reinterpret_cast<void*>(static_cast<uintptr_t>(pid)), nullptr };
    OA oa{ sizeof(oa), nullptr, nullptr, 0, nullptr };

    if (!NT_SUCCESS(sc4(UPTR(&h), 0x1FFFFF, UPTR(&oa), UPTR(&cid), sys::num("NtOpenProcess")))) {
        log::w(L"open game failed");
        return false;
    }
    auto* p = reinterpret_cast<void*>(h);
    log::w(L"open game ok, handle:");
    log::hex(h);

    // granted access carried by the handle (OBJECT_BASIC_INFORMATION.GrantedAccess)
    uint8_t obi[0x40]{};
    uint64_t qret = 0;
    if (NT_SUCCESS(sc5(UPTR(p), 0, UPTR(obi), sizeof(obi), UPTR(&qret), sys::num("NtQueryObject")))) {
        uint32_t ga = 0;
        copy_(&ga, obi + 4, sizeof(ga));
        log::w(L"granted access:");
        log::hex(ga);
    } else {
        log::w(L"granted access query failed");
    }

    uint64_t base = 0, sz = nt->OptionalHeader.SizeOfImage;
    NTSTATUS_ st = sc6(UPTR(p), UPTR(&base), 0, UPTR(&sz), MEM_COMMIT_ | MEM_RESERVE_,
                       PAGE_RW_, sys::num("NtAllocateVirtualMemory"));
    if (!NT_SUCCESS(st)) {
        log::w(L"remote alloc failed status:");
        log::hex(static_cast<uint32_t>(st));
        sys::close(p);
        return false;
    }

    uint64_t delta = base - nt->OptionalHeader.ImageBase;

    writem(p, base, img, nt->OptionalHeader.SizeOfHeaders);

    auto* sec = IMAGE_FIRST_SECTION_(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
        if (sec->SizeOfRawData)
            writem(p, base + sec->VirtualAddress, img + sec->PointerToRawData, sec->SizeOfRawData);

    // relocs
    auto& rd = nt->OptionalHeader.DataDirectory[DIR_BASERELOC_];
    if (rd.VirtualAddress) {
        auto* blk = reinterpret_cast<IMAGE_BASE_RELOCATION_*>(const_cast<uint8_t*>(img) + rd.VirtualAddress);
        uint32_t left = rd.Size;
        while (left > sizeof(IMAGE_BASE_RELOCATION_)) {
            uint32_t n = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION_)) / 2;
            auto* ent = reinterpret_cast<uint16_t*>(blk + 1);
            for (uint32_t i = 0; i < n; ++i) {
                if ((ent[i] >> 12) != REL_DIR64_) continue;
                uint64_t at = base + blk->VirtualAddress + (ent[i] & 0xFFF);
                uint64_t v = 0;
                readm(p, at, &v, 8);
                v += delta;
                writem(p, at, &v, 8);
            }
            left -= blk->SizeOfBlock;
            blk = reinterpret_cast<IMAGE_BASE_RELOCATION_*>(reinterpret_cast<uint8_t*>(blk) + blk->SizeOfBlock);
        }
    }

    // imports
    auto& id = nt->OptionalHeader.DataDirectory[DIR_IMPORT_];
    if (id.VirtualAddress) {
        auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR_*>(const_cast<uint8_t*>(img) + id.VirtualAddress);
        for (; imp->Name; ++imp) {
            char dll[128]{};
            copy_(dll, img + imp->Name, sizeof(dll) - 1);

            for (uint64_t k = 0;; ++k) {
                uint64_t at = base + imp->FirstThunk + k * 8, thunk = 0;
                if (!readm(p, at, &thunk, 8) || !thunk) break;
                if (thunk & 0x8000000000000000ull) continue;

                char fn[128]{};
                copy_(fn, img + (thunk - base) + 2, sizeof(fn) - 1);

                uint64_t addr = remote_proc(p, h::fnv1a(dll), h::fnv1a(fn));
                if (!addr) { log::w(L"unresolved import"); sys::close(p); return false; }
                writem(p, at, &addr, 8);
            }
        }
    }

    sec = IMAGE_FIRST_SECTION_(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData) continue;
        uint32_t prot = PAGE_R_;
        if (sec->Characteristics & SCN_EXECUTE_) prot = PAGE_RX_;
        else if (sec->Characteristics & SCN_WRITE_) prot = PAGE_RW_;
        uint64_t a = base + sec->VirtualAddress, s = sec->SizeOfRawData;
        sc5(UPTR(p), UPTR(&a), UPTR(&s), prot, 0, sys::num("NtProtectVirtualMemory"));
    }

    // entry
    uint64_t entry = base + nt->OptionalHeader.AddressOfEntryPoint;
    uint64_t th = 0;
    sc11(UPTR(&th), 0x1FFFFF, 0, UPTR(p), entry, base, 0, 0, 0, 0, 0, sys::num("NtCreateThreadEx"));

    log::w(L"mapped into game from host");
    sys::close(p);
    if (out) *out = reinterpret_cast<void*>(base);
    return true;
}