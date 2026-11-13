// Delivery probe: which module names does this process ask for at runtime?
//
// The proxy problem measured on 13.11.2026 is not "can the payload run in the
// client" (it does) but "how does it get there without breaking the boot".
// Replacing version.dll is refused outright - a byte-identical copy of the
// signed system DLL is refused too, so the check is on the file, not on the
// code. The remaining option is a name the client resolves *late*, after the
// anti-cheat has finished, through the normal loader path.
//
// This file answers "which names" by instrumentation instead of guessing:
//
//   1. hook ntdll!LdrRegisterDllNotification and collect every name any module
//      asks the loader for, plain or as a full path;
//   2. hook LdrpLoadDll (the loader's own load worker) the same way, for the
//      loads nothing notifies about - delay-loads and direct LdrLoadDll calls;
//   3. poll the set of loaded modules once a second and log whatever appeared.
//
// Mode A (no payload): the prober is the only thing in the process and its own
// hooks describe the whole load sequence. That is the measurement that matters,
// because it is taken before anything of ours is next to the client.
//
// Mode B (after injection): `clientbase` prints, as data, what the payload
// needs and what a hand-written probe tool can read from outside - the client's
// base, the object bases of ULdrData, ntdll's LdrpLoadDll, ntdll's
// LdrRegisterDllNotification, and the addresses of UEngine / UWorld, which are
// the two values that decide whether the offsets in game.cpp are still right.
//
// Everything here is read-only with respect to the client: no memory is
// written in mode A except the four hotpatch bytes of the two loader
// functions, and mode A never runs inside the client.

#include "log.hpp"
#include "../../shared/include/peb.hpp"
#include "../../shared/include/ntapi.hpp"
#include "../../shared/include/hash.hpp"

// The freestanding payload links without a CRT, so GCC's stack-probe helper has
// to exist here. Two names are in play depending on the target: ___chkstk_ms is
// what the MinGW caller side references, __chkstk_ms is what GCC's own codegen
// uses. Both are defined, with the same body: touch every page the frame will
// span so a big stack allocation cannot skip a guard page.
extern "C" void __chkstk_ms(void);
extern "C" void ___chkstk_ms(void);

extern "C" void __chkstk_ms_impl(void) {
    __asm__ volatile(
        "pushq %rcx\n"
        "pushq %rax\n"
        "leaq 24(%rsp), %rcx\n"
        "subq %rax, %rcx\n"
        "movq %rsp, %rax\n"
        "1: cmpq %rcx, %rax\n"
        "jbe 2f\n"
        "subq $4096, %rax\n"
        "testb %al, (%rax)\n"
        "jmp 1b\n"
        "2: popq %rax\n"
        "popq %rcx\n"
        "ret\n");
}
extern "C" void __chkstk_ms(void) { __chkstk_ms_impl(); }
extern "C" void ___chkstk_ms(void) { __chkstk_ms_impl(); }

namespace {

// One line per event, nothing buffered: a probe that dies mid-sequence must
// still leave the sequence it saw.
constexpr int kMaxEvents = 96;
static volatile long g_events = 0;

struct Rec {
    int kind;           // 0 notification, 1 load worker, 2 appeared in LDR
    uint32_t hash;      // name hash, so two records can be matched later
    wchar_t name[128];  // empty when the hook could not read it (long paths are
                        // cut to the file name: the tail is what matters)
};
static Rec g_rec[kMaxEvents]{};

inline uintptr_t ctx_rsp() {
    uintptr_t v;
    __asm__ volatile("movq %%rsp, %0" : "=r"(v));
    return v;
}

// The loader calls its notify-args on the stack on the x64 ABI. Nothing here
// trusts that blindly: every candidate argument is range-checked before it is
// read, because reading a bad pointer inside the loader is what ends the
// process.
bool maybe_wstr(uintptr_t p, wchar_t* dst, size_t cap) {
    if (p < 0x10000 || p > 0x7FFFFFFFFFFF || (p & 1)) return false;
    auto* s = reinterpret_cast<const wchar_t*>(p);
    int n = 0;
    for (; n < static_cast<int>(cap) - 1; ++n) {
        wchar_t c = s[n];
        if (!c) break;
        // A DLL name never contains control characters; this catches the case
        // where the "string" is really a length or a pointer.
        if (c < 0x20 || c > 0x7e) return false;
        dst[n] = c;
    }
    if (!n) return false;
    dst[n] = 0;
    return true;
}

void scan_for_name(uintptr_t lo, uintptr_t hi, wchar_t* dst, size_t cap) {
    // Walks stack slots looking for the first thing that reads as a file name.
    // Slots that are themselves pointers to strings are followed one hop only.
    for (uintptr_t a = lo; a + 8 <= hi; a += 8) {
        uintptr_t v = *reinterpret_cast<uintptr_t*>(a);
        if (maybe_wstr(v, dst, cap)) {
            for (int i = 0; dst[i]; ++i)
                if (dst[i] == L'.') return;
        }
    }
    dst[0] = 0;
}

void record(int kind, const wchar_t* name) {
    long i = g_events;
    if (i >= kMaxEvents) return;
    g_events = i + 1;
    Rec& r = g_rec[i];
    r.kind = kind;
    r.hash = name ? h::fnv1a_w(name) : 0;
    int k = 0;
    if (name)
        for (; name[k] && k < 127; ++k) r.name[k] = name[k];
    r.name[k] = 0;
}

// --- hook 1: LdrRegisterDllNotification --------------------------------
// BOOLEAN (ULONG Flags, PLDR_DLL_NOTIFICATION_FUNCTION Function,
//          PVOID Context, PVOID *Cookie)
using NotifyFn = void(__stdcall*)(uint32_t reason, const void* data, void* ctx);

struct NotifyData_ {
    uint32_t Flags;
    const UNICODE_STRING_* FullDllName;
    const UNICODE_STRING_* BaseDllName;
};

static void __stdcall on_dll_notify(uint32_t reason, const void* data, void* ctx) {
    (void)ctx;
    auto* d = static_cast<const NotifyData_*>(data);
    wchar_t buf[208]{};
    const wchar_t* nm = nullptr;
    if (d && d->BaseDllName && d->BaseDllName->Buffer && d->BaseDllName->Length) {
        int n = d->BaseDllName->Length / 2;
        if (n > 200) n = 200;
        for (int i = 0; i < n; ++i) buf[i] = d->BaseDllName->Buffer[i];
        buf[n] = 0;
        nm = buf;
    }
    record(0, nm);
    // reason: 1 loaded, 2 unloaded, 4 unload pending. The task wants the whole
    // sequence, so every reason is kept and the count carries the order.
}

// --- hook 2: ntdll!LdrpLoadDll ----------------------------------------
// The internal worker every load goes through, plain or path. Its second
// argument is the full DLL name (a counted UNICODE_STRING), which is exactly
// the "\\?\globalroot\\Device\\HarddiskVolume2\\..." form the client's own
// loader produces - the form in the error dialog.
using LoadFn = int(__stdcall*)(void* dll, const UNICODE_STRING_* name, void* path,
                               uint32_t flags, void** base, int* status);

static LoadFn g_orig_load = nullptr;

static int __stdcall on_load(void* dll, const UNICODE_STRING_* name, void* path,
                             uint32_t flags, void** base, int* status) {
    wchar_t buf[208]{};
    const wchar_t* nm = nullptr;
    if (name && name->Buffer && name->Length) {
        int n = name->Length / 2;
        if (n > 200) n = 200;
        for (int i = 0; i < n; ++i) buf[i] = name->Buffer[i];
        buf[n] = 0;
        nm = buf;
    }
    if (!nm) {
        // Some builds pass the string directly; find it on the frame.
        wchar_t tmp[208]{};
        scan_for_name(ctx_rsp() + 0x28, ctx_rsp() + 0x400, tmp, 208);
        if (tmp[0]) nm = tmp;
    }
    record(1, nm);
    return g_orig_load(dll, name, path, flags, base, status);
}

// --- trampoline ------------------------------------------------------
// The three hotpatch bytes at entry-2 are enough for a hooked call: an
// absolute jmp is 14 bytes and would overwrite the prologue the trampoline is
// about to copy. The trampoline is therefore [copied 14 bytes][abs jmp back],
// and the entry gets a 5-byte rel-tic jmp into it, written with the first
// instruction's length taken from a table of the two forms ntdll uses today.
uint8_t* build_hook(void* target, void* replacement) {
    auto* src = static_cast<uint8_t*>(target);
    void* raw = nullptr;
    if (!NT_SUCCESS(sys::alloc(&raw, 64, 0x40 /*EXECUTE_READWRITE*/)) || !raw) return nullptr;
    uint8_t* tr = static_cast<uint8_t*>(raw);
    if (!tr) return nullptr;

    // Length of the instructions a 5-byte rel32 jmp overwrites, for the small
    // prologue shapes ntdll actually uses (mov r10 / mov eax / push / nop).
    int need = 5, taken = 0;
    while (taken < need) {
        int l = 1;
        if (src[taken] == 0x4C && src[taken + 1] == 0x8B) l = 3;          // mov r10, rcx
        else if (src[taken] == 0x48 && src[taken + 1] == 0x8B) l = 3;     // mov r?, r?
        else if (src[taken] == 0xB8 || (src[taken] >= 0xB8 && src[taken] <= 0xBF)) l = 5;
        else if (src[taken] == 0xE9 || src[taken] == 0xE8) l = 5;
        else if (src[taken] == 0x49 && src[taken + 1] == 0xBA) l = 10;
        else if (src[taken] == 0x66) l = 2;
        else if (src[taken] >= 0x50 && src[taken] <= 0x5F) l = 1;
        taken += l;
        if (taken > 16) return nullptr;
    }
    for (int i = 0; i < taken; ++i) tr[i] = src[i];
    // absolute jmp back to the rest of the original function
    tr[taken + 0] = 0xFF; tr[taken + 1] = 0x25;
    *reinterpret_cast<uint32_t*>(tr + taken + 2) = 0;
    *reinterpret_cast<uint64_t*>(tr + taken + 6) =
        reinterpret_cast<uint64_t>(src + taken);

    // Make the prologue writable for the patch only, then put the page back to
    // execute-read: ntdll's .text is read+execute on every Windows, and leaving
    // it writable is a bigger change than the hook itself.
    if (!NT_SUCCESS(sys::protect(src, static_cast<size_t>(taken), 0x40 /*EXECUTE_READWRITE*/)))
        return nullptr;

    src[0] = 0xE9;
    *reinterpret_cast<int32_t*>(src + 1) =
        static_cast<int32_t>(reinterpret_cast<uint8_t*>(replacement) - (src + 5));
    for (int i = 5; i < taken; ++i) src[i] = 0x90;

    sys::protect(src, static_cast<size_t>(taken), 0x20 /*EXECUTE_READ*/);
    return tr;
}

} // namespace

// Called from the payload's entry before anything else when the host put a
// probe request in g_host_path. Never returns by itself: the probe lives as
// long as the process it is measuring.
void probe_delivery(int mode) {
    log::w(L"probe: start");
    if (!sys::init()) { log::w(L"probe: sys init failed"); return; }

    void* nt = peb::module_base(HHW(L"ntdll.dll"));
    if (!nt) { log::w(L"probe: no ntdll"); return; }

    // The addresses the outside tool needs. They are logged, not computed, so a
    // reader does not have to reproduce the export walk.
    void* load = peb::export_proc(nt, HH("LdrpLoadDll"));
    void* reg = peb::export_proc(nt, HH("LdrRegisterDllNotification"));
    log::w(L"probe: ntdll:"); log::hex(reinterpret_cast<uint64_t>(nt));
    log::w(L"probe: LdrpLoadDll:"); log::hex(reinterpret_cast<uint64_t>(load));
    log::w(L"probe: LdrRegisterDllNotification:"); log::hex(reinterpret_cast<uint64_t>(reg));

    if (mode == 0) {          // 0 = keep the loader hooks
        if (load) {
            g_orig_load = reinterpret_cast<LoadFn>(build_hook(load, reinterpret_cast<void*>(&on_load)));
            log::w(g_orig_load ? L"probe: LdrpLoadDll hooked (events below are load-worker calls)"
                               : L"probe: LdrpLoadDll hook refused");
        } else {
            log::w(L"probe: LdrpLoadDll not exported - no load-worker events");
        }

        if (reg) {
            using Reg = unsigned long(__stdcall*)(uint32_t, NotifyFn, void*, void**);
            void* cookie = nullptr;
            auto r = reinterpret_cast<Reg>(reg)(0, &on_dll_notify, nullptr, &cookie);
            log::w(r == 0 ? L"probe: notification registered"
                          : L"probe: notification refused");
        } else {
            log::w(L"probe: LdrRegisterDllNotification not exported");
        }
    } else {
        log::w(L"probe: events only (no hooks in this process)");
    }

    // Baseline: what is already loaded is not news. Everything that appears
    // after this line is.
    uintptr_t known[1024]{};
    int nknown = 0;
    for (auto* e = peb::first_module(); e && nknown < 1024; e = peb::next_module(e))
        known[nknown++] = reinterpret_cast<uintptr_t>(e->DllBase);
    log::w(L"probe: baseline modules:");
    log::hex(static_cast<uint64_t>(nknown));

    long shown = 0;
    for (int tick = 0; tick < 900; ++tick) {   // ~15 min at 1 s per tick
        sys::sleep(1000);
        for (auto* e = peb::first_module(); e; e = peb::next_module(e)) {
            uintptr_t b = reinterpret_cast<uintptr_t>(e->DllBase);
            bool seen = false;
            for (int i = 0; i < nknown; ++i)
                if (known[i] == b) { seen = true; break; }
            if (seen) continue;
            if (nknown < 1024) known[nknown++] = b;
            record(2, e->BaseDllName.Buffer);
        }

        long have = g_events;
        for (long i = shown; i < have; ++i) {
            if (g_rec[i].kind == 0) log::w(L"notify:");
            else if (g_rec[i].kind == 1) log::w(L"loaddll:");
            else log::w(L"appeared:");
            if (g_rec[i].name[0]) log::w(g_rec[i].name);
            else log::hex(g_rec[i].hash);
        }
        shown = have;
    }
    log::w(L"probe: done");
}

// ---------------------------------------------------------------------------
// Command channel: the client's own log files, read back.
//
// Measured (tools/log_channel.cpp): any process may open a fort* log for append
// because the file object is shared - including the client's own log. That makes
// an invisible, ACL-free channel into the process we cannot reach by handle. The
// missing half was a reader *inside*. This is it, kept deliberately small so it
// fits the same freestanding constraints as the rest of the payload: no CRT, one
// thread, a tail offset and a fixed command line buffer.
//
// Protocol, one command per line, ASCII, no quoting:
//
//   PING                     -> answer line on the payload log
//   BASE                     -> answer with the client base address
//   READ <hex addr> <n>      -> answer with n bytes as hex
//   U32 <hex addr>           -> answer with the dword there
//   MOD <name>               -> answer with the module base, or 0
//   EXIT                     -> stop reading
//
// Answers go to fort_channel.out next to the log, one line each, prefixed ACK so
// a human tailing the file can see the round trip.
// ---------------------------------------------------------------------------

namespace ch {

// Freestanding payload: no CRT, so no strcmp. Three helpers of our own.
static int str_eq(const char* a, const char* b) {
    while (*a && *b) { if (*a != *b) return 0; ++a; ++b; }
    return *a == *b;
}
static int str_pre(const char* a, const char* b) {
    while (*b) { if (*a != *b) return 0; ++a; ++b; }
    return 1;
}

static const wchar_t* kIn  = L"C:\\Users\\Public\\fortesp2.log";
static const wchar_t* kOut = L"C:\\Users\\Public\\fort_channel.out";
static unsigned long long g_off = 0;

static unsigned long long file_size(const wchar_t* p) {
    HANDLE h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER li{};
    li.LowPart = GetFileSize(h, (LPDWORD)&li.HighPart);
    CloseHandle(h);
    return static_cast<unsigned long long>(li.QuadPart);
}

static void reply(const char* s) {
    HANDLE h = CreateFileW(kOut, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    DWORD n = 0;
    while (s[n]) ++n;
    WriteFile(h, s, n, &w, nullptr);
    WriteFile(h, "\r\n", 2, &w, nullptr);
    CloseHandle(h);
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned long long parse_hex(const char* s, int* used) {
    unsigned long long v = 0;
    int n = 0;
    while (s[n]) {
        int d = hexval(s[n]);
        if (d < 0) break;
        v = (v << 4) | static_cast<unsigned long long>(d);
        ++n;
    }
    if (used) *used = n;
    return v;
}

static unsigned long to_dec(unsigned long v, char* out) {
    char tmp[16];
    int n = 0;
    if (!v) { out[0] = '0'; out[1] = 0; return 1; }
    while (v && n < 16) { tmp[n++] = static_cast<char>('0' + v % 10); v /= 10; }
    for (int i = 0; i < n; ++i) out[i] = tmp[n - 1 - i];
    out[n] = 0;
    return static_cast<unsigned long>(n);
}

static void append_hex(char* dst, unsigned long long v, int digits) {
    const char* d = "0123456789ABCDEF";
    for (int i = digits - 1; i >= 0; --i) {
        dst[i] = d[v & 0xF];
        v >>= 4;
    }
}

static void exec(char* line) {
    while (*line == ' ' || *line == '\t') ++line;
    int len = 0; while (line[len] && line[len] != '\r' && line[len] != '\n') ++len;
    line[len] = 0;
    if (!len) return;

    char out[512];

    if (!str_pre(line, "PING")) {
        reply("ACK PING");
        return;
    }
    if (!str_pre(line, "BASE")) {
        unsigned long long b = 0;
        // The module list is the only trustworthy source for the client base:
        // ImageBaseAddress is not it on this build.
        // The base, found the same way game.cpp does: the module list, never
        // ImageBaseAddress (measured wrong on this build).
        b = 0;
        for (auto* e = peb::first_module(); e; e = peb::next_module(e)) {
            const wchar_t* n = e->BaseDllName.Buffer;
            if (!n || !e->DllBase) continue;
            const wchar_t* want = L"FortniteClient-Win64-Shipping.exe";
            const wchar_t* a = n; const wchar_t* c = want;
            while (*a && *c && *a == *c) { ++a; ++c; }
            if (!*a && !*c) { b = reinterpret_cast<unsigned long long>(e->DllBase); break; }
        }
        out[0] = 'A'; out[1] = 'C'; out[2] = 'K'; out[3] = ' ';
        out[4] = 'B'; out[5] = 'A'; out[6] = 'S'; out[7] = 'E';
        out[8] = ' ';
        out[9] = '0'; out[10] = 'x';
        append_hex(out + 11, b, 16);
        out[27] = 0;
        reply(out);
        return;
    }
    if (!str_pre(line, "READ ")) {
        int used = 0;
        unsigned long long a = parse_hex(line + 5, &used);
        unsigned long long n = parse_hex(line + 5 + used + (line[5 + used] == ' ' ? 1 : 0), nullptr);
        if (n > 32) n = 32;
        if (n == 0) n = 1;
        const unsigned char* p = reinterpret_cast<const unsigned char*>(a);
        out[0] = 'A'; out[1] = 'C'; out[2] = 'K'; out[3] = ' ';
        out[4] = 'R'; out[5] = 'E'; out[6] = 'A'; out[7] = 'D'; out[8] = ' ';
        append_hex(out + 9, a, 12);
        out[21] = ' ';
        for (unsigned long long i = 0; i < n; ++i) {
            append_hex(out + 22 + static_cast<int>(i) * 2, p[i], 2);
        }
        out[22 + static_cast<int>(n) * 2] = 0;
        reply(out);
        return;
    }
    if (!str_pre(line, "U32 ")) {
        unsigned long long a = parse_hex(line + 4, nullptr);
        unsigned long v = *reinterpret_cast<unsigned long*>(a);
        out[0] = 'A'; out[1] = 'C'; out[2] = 'K'; out[3] = ' ';
        out[4] = 'U'; out[5] = '3'; out[6] = '2'; out[7] = ' ';
        append_hex(out + 8, a, 12);
        out[20] = ' ';
        out[21] = '0'; out[22] = 'x';
        append_hex(out + 23, v, 8);
        out[31] = 0;
        reply(out);
        return;
    }
    if (!str_pre(line, "MOD ")) {
        HMODULE m = nullptr;
        wchar_t wn[64];
        int i = 0;
        for (; line[4 + i] && i < 63; ++i) wn[i] = static_cast<wchar_t>(line[4 + i]);
        wn[i] = 0;
        m = GetModuleHandleW(wn);
        out[0] = 'A'; out[1] = 'C'; out[2] = 'K'; out[3] = ' ';
        out[4] = 'M'; out[5] = 'O'; out[6] = 'D'; out[7] = ' ';
        append_hex(out + 8, reinterpret_cast<unsigned long long>(m), 16);
        out[24] = 0;
        reply(out);
        return;
    }
    reply("ERR unknown command");
}

// Tail loop. Deliberately not a message loop and not COM: the thread only ever
// does CreateFile/ReadFile on a shared file object, so it cannot deadlock against
// the loader the way an in-DllMain path would.
static DWORD WINAPI thread_proc(void*) {
    g_off = file_size(kIn);
    reply("ACK channel up");
    for (;;) {
        unsigned long long now = file_size(kIn);
        if (now > g_off) {
            HANDLE h = CreateFileW(kIn, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER li;
                li.QuadPart = static_cast<LONGLONG>(g_off);
                if (SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) {
                    char buf[512];
                    DWORD got = 0;
                    if (ReadFile(h, buf, sizeof(buf) - 1, &got, nullptr) && got) {
                        buf[got] = 0;
                        char* p = buf;
                        while (*p) {
                            char* nl = p;
                            while (*nl && *nl != '\n') ++nl;
                            char save = *nl;
                            *nl = 0;
                            exec(p);
                            if (!save) break;
                            p = nl + 1;
                        }
                    }
                }
                CloseHandle(h);
            }
            g_off = now;
        }
        Sleep(250);
    }
    return 0;
}

}  // namespace ch

extern "C" __declspec(dllexport) void channel_start() {
    HANDLE t = CreateThread(nullptr, 0, ch::thread_proc, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
}

