#include "map.hpp"
#include "game.hpp"
#include "render.hpp"
#include "hide.hpp"
#include "log.hpp"
#include "../../shared/include/syscall.hpp"
#include "../../shared/include/ntapi.hpp"
#include "../../shared/include/peb.hpp"
#include "../../shared/include/hash.hpp"
#include "../../shared/include/mem.hpp"

// progress markers for the manual-map host (the loader reads these after exit)
extern "C" __declspec(dllexport) volatile uint32_t g_trace[16];

namespace {

void* g_stack{};
volatile bool g_run{ true };

constexpr int K_ESP = VK_F1;

bool pressed(int vk, bool& last) {
    bool cur = (ntapi::GetAsyncKeyState_(vk) & 0x8000) != 0;
    bool hit = cur && !last;
    last = cur;
    return hit;
}

DWORD __stdcall worker(void*) {
    // Instrumentation is kept to one line per decision. Every log::w() is a
    // separate open/write/close on a literal path from inside a mapped image,
    // and the worker thread has been lost inside those calls before.
    log::w(L"worker up");
    // g_trace survives the frame: whatever start() wrote disappears with the
    // stack, so the worker leaves its own mark.
    g_trace[12] = 0xC1;

    bool l1{};  // ESP toggle

    // One attempt, then report. A mapped host that is not the client will never
    // satisfy game::init(), and an endless retry loop is exactly what a thread
    // that "never exits" looks like from the loader. Off-client the payload has
    // to degrade, not spin.
    if (!game::init()) {
        log::w(L"worker: game::init failed, degraded exit");
        return 0;
    }
    log::w(L"worker: game ready");

    if (!render::init()) { log::w(L"render failed"); return 1; }

    while (g_run) {
        if (pressed(K_ESP, l1)) {
            render::enabled = !render::enabled;
            log::w(render::enabled ? L"esp on" : L"esp off");
        }

        sys::sleep(160000);   // ~16ms
    }

    render::shutdown();
    game::shutdown();
    log::w(L"worker exit");
    return 0;
}

bool in_ldr(void* base) {
    auto* p = peb::self();
    if (!p || !p->Ldr) return false;

    auto* head = reinterpret_cast<uint8_t*>(p->Ldr) + 0x10;
    auto* cur = *reinterpret_cast<uint8_t**>(head);
    for (int g = 0; cur && cur != head && g < 512; ++g) {
        auto* e = reinterpret_cast<LDR_DATA_TABLE_ENTRY_*>(cur);
        if (e->DllBase == base) return true;
        cur = *reinterpret_cast<uint8_t**>(cur);
    }
    return false;
}

// The proxy maps the payload straight into the game process. Without this
// check the payload would see g_host_path, take the relay branch and try to
// map itself into the game again - which fails, because the game handle is
// capped at 0x11F145.
static wchar_t g_exe[MAX_PATH];

// GetModuleFileNameW out of the *host's* kernel32, through the PEB export
// walk. The import table is not usable here: a manually mapped image has one,
// but the mapped copy is not in the loader's module list, so a lazily bound
// thunk would fault the first time it is called. g_trace[7]/[8] say whether
// the export walk came back with a real address.
static uint32_t exe_name(wchar_t* out, uint32_t cap) {
    void* k = peb::module_base(HHW(L"kernel32.dll"));
    g_trace[7] = 0xB6;
    if (!k) return 0;
    void* p = peb::export_proc(k, HH("GetModuleFileNameW"));
    g_trace[8] = 0xB7;
    if (!p) return 0;
    using F = uint32_t(__stdcall*)(void*, wchar_t*, uint32_t);
    return reinterpret_cast<F>(p)(nullptr, out, cap);
}

static bool already_in_target() {
    g_trace[5] = 0xB0;
    g_trace[6] = 0xB5;
    uint32_t n = exe_name(g_exe, MAX_PATH);
    g_trace[9] = 0xB8;
    if (!n) return false;
    const wchar_t needle[] = L"FortniteClient-Win64-Shipping.exe";
    for (uint32_t i = 0; g_exe[i]; ++i) {
        uint32_t j = 0;
        while (needle[j] && g_exe[i + j] == needle[j]) ++j;
        if (!needle[j]) { g_trace[10] = 0xB3; return true; }
    }
    g_trace[10] = 0xB4;
    return false;
}

// Read this image from disk into a fresh buffer.
bool load_self(const wchar_t* self_path, uint8_t** out_img, uint32_t* out_size) {
    *out_img = nullptr; *out_size = 0;
    void* f = ntapi::CreateFileW_(self_path, 0x80000000, 1, nullptr, 3, 0, nullptr);
    if (!f || f == reinterpret_cast<void*>(-1)) { log::w(L"self read failed"); return false; }

    uint32_t size = static_cast<uint32_t>(ntapi::GetFileSize_(f));
    log::w(size ? L"relay: size ok" : L"relay: size zero");
    if (!size) { ntapi::CloseHandle_(f); return false; }

    void* buf = nullptr;
    if (!NT_SUCCESS(sys::alloc(&buf, size, PAGE_RW_))) { log::w(L"relay: alloc failed"); return false; }

    uint32_t got = 0;
    ntapi::ReadFile_(f, buf, size, &got, nullptr);
    ntapi::CloseHandle_(f);
    log::w(got ? L"relay: read ok" : L"relay: read empty");
    if (!got) { sys::release(buf); return false; }

    *out_img = static_cast<uint8_t*>(buf);
    *out_size = got;
    return true;
}

// host mode: read ourselves from disk, then map into the game
bool relay(const wchar_t* self_path) {
    log::w(L"relay: open self");
    void* f = ntapi::CreateFileW_(self_path, 0x80000000, 1, nullptr, 3, 0, nullptr);
    if (!f || f == reinterpret_cast<void*>(-1)) { log::w(L"self read failed"); return false; }

    uint32_t size = static_cast<uint32_t>(ntapi::GetFileSize_(f));
    log::w(size ? L"relay: size ok" : L"relay: size zero");

    void* buf = nullptr;
    if (!NT_SUCCESS(sys::alloc(&buf, size, PAGE_RW_))) { log::w(L"relay: alloc failed"); return false; }

    uint32_t got = 0;
    ntapi::ReadFile_(f, buf, size, &got, nullptr);
    ntapi::CloseHandle_(f);
    log::w(got ? L"relay: read ok" : L"relay: read empty");

    auto* dos = static_cast<IMAGE_DOS_HEADER_*>(buf);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(static_cast<uint8_t*>(buf) + dos->e_lfanew);

    log::w(L"relay: find game");
    DWORD pid = ntapi::pid_by_name_(L"FortniteClient-Win64-Shipping.exe");
    if (!pid) { log::w(L"game not running"); sys::release(buf); return false; }

    log::w(L"relay: map into game");
    bool ok = map::into(pid, static_cast<uint8_t*>(buf), got, nullptr);
    sys::release(buf);
    return ok;
}

} // namespace

// filled by the loader when the payload is manually mapped into a host process
extern "C" __declspec(dllexport) wchar_t g_host_path[260] = { 0 };

// >= 0 when the host asked for a delivery probe instead of the normal body.
// -1 is the default and means "run the payload as usual"; 0 keeps the loader
// hooks in this process, 1 only reports what it sees. The host sets it before
// the thread starts, so the value is in place on the first instruction of
// start() rather than racing with it.
extern "C" __declspec(dllexport) int g_probe_mode = -1;

// progress markers for the manual-map host (loader reads these after exit)
extern "C" __declspec(dllexport) volatile uint32_t g_trace[16] = { 0 };

// start()'s result, kept alongside the guard
static bool g_result = false;

// Re-entry guard for start(): 0 = untouched, 1 = running, 2 = done.
//
// It has to be memory every call sees, and exported data of a manually mapped
// copy is not: this image's .data carries no base relocations, so each process
// can end up looking at a different copy, and in the mapper's test host both
// entries into the payload (the thread's startup call and the mapper's own
// ret-gadget call) read the guard back as 0. A runtime allocation reached
// through a pointer the *code* sets is shared by both callers, because there
// is only one allocation.
static uint32_t* g_state_ptr = nullptr;

static uint32_t* state_ptr() {
    if (!g_state_ptr) {
        void* p = nullptr;
        if (!sys::init() || !NT_SUCCESS(sys::alloc(&p, 0x1000, PAGE_RW_))) return nullptr;
        *static_cast<uint32_t*>(p) = 0;
        g_state_ptr = static_cast<uint32_t*>(p);
    }
    return g_state_ptr;
}

// return target for manually mapped threads: the loader cannot use its own
// module addresses (ASLR differs per process), so terminate from inside the
// mapped image with a direct syscall.
extern "C" __declspec(dllexport) void __stdcall exit_thunk() {
    sys::init();
    // NtTerminateThread(ThreadHandle, ExitStatus). ThreadHandle = -2 means the
    // calling thread; -1 (and anything else that is not a thread) means the
    // whole process. The thread is parked if the syscall returns, so a wrong
    // number here shows up as "the thread is still alive" rather than as a
    // dead host.
    sc2(static_cast<uint64_t>(-2), 0, sys::num("NtTerminateThread"));
    for (;;) sys::sleep(10000000);
}

extern "C" __declspec(dllexport) uint32_t __stdcall probe0() {
    g_trace[0] = 0x1234;
    return 0x1234;
}

extern "C" __declspec(dllexport) uint32_t __stdcall probe1() {
    g_trace[0] = 0x11;
    log::open();
    g_trace[1] = 0x12;
    log::w(L"probe1");
    g_trace[2] = 0x13;
    log::close();
    g_trace[3] = 0x14;
    return 0x1235;
}

extern "C" __declspec(dllexport) uint32_t __stdcall probe2() {
    g_trace[0] = 0x21;
    bool ok = sys::init();
    g_trace[1] = ok ? 0x22 : 0x2F;
    g_trace[2] = sys::num("NtClose");
    return 0x1236;
}

void probe_delivery(int mode);
extern "C" void channel_start();

extern "C" __declspec(dllexport) bool __stdcall start(void* arg1, uint32_t reason, void* arg3) {
    (void)reason; (void)arg3;
    // The payload is entered more than once on purpose (TLS callback, DllMain,
    // then the mapper's own call); only the first entry runs the body.
    uint32_t* st = state_ptr();
    if (!st) return false;
    // Re-entry guard, measured: the loader calls the image once, and the
    // mapper's thread runs that call once. There is no second entry to guard
    // against, and the file-counter version of this guard cost two file opens
    // per entry for nothing - and its first file call was the statement the
    // entry thread died on (STATUS_PENDING, no exception). One word in .data
    // is enough, and it is not needed at all for the first entry.
    log::w(L"stage A0");
    log::open();   // log::open() reads the PEB and opens a file: with the
                   // images sharing .bss, this is the most likely fault point
    log::w(L"stage A1");
    log::w(L"entered E0/M4");
    log::w(L"stage A2");

    if (!sys::init()) { log::w(L"sys init failed"); log::close(); *st = 2; g_result = false; return false; }
    log::w(L"stage A3");

    // Probe mode comes first: it exists to describe the load sequence, and it
    // has to run before anything else this payload does leaves a mark.
    if (g_probe_mode >= 0) { probe_delivery(g_probe_mode); return true; }

    // The log-file command channel: the only surface the client leaves open to
    // an outside process. Started before anything else so a request that arrives
    // during start-up is not lost.
    channel_start();

    // Already inside the game: the proxy mapped us straight into the target,
    // so skip the relay and run the target-mode body.
    //
    // arg1 is *not* the image base: the mapper passes the mapped image as the
    // thread argument, which for this manual-map host is the page at
    // 0x10000000, not `remote`. Both branches below used to read a DOS header
    // out of that argument, and the proxy's call (arg1 = hDll) did the same,
    // which is why target mode died with 0xC0000005 right after this point.
    if (already_in_target()) {
        g_trace[4] = 0xA7;
        // Inside the client. The image is mapped here, and the offsets in
        // game.cpp are absolute RVAs from the *client's* base - so the chain is
        // started from the client module, which game::init() finds itself.
        //
        // This branch used to log the client's headers and stop, which crashed:
        // reading an IMAGE_NT_HEADERS64 requires SizeOfOptionalHeader, and an
        // image whose NT header is not what a PE parser expects faults on the
        // first field past e_lfanew. Nothing here needs the header, so it is
        // not read.
        log::w(L"target mode (in process)");

        // Hand the work to the worker the same way the host path does: this
        // thread was started by the client's loader and may still be inside
        // its lock, while hide::launch_worker installs its own gadget and
        // resumes a fresh thread - which is the path that ran in the client on
        // every earlier build.
        void* self_base = peb::self()->ImageBaseAddress;
        auto* dos = static_cast<IMAGE_DOS_HEADER_*>(self_base);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64_*>(
            static_cast<uint8_t*>(self_base) + dos->e_lfanew);
        if (dos->e_magic != 0x5A4D || nt->Signature != 0x4550) {
            log::w(L"target mode: image base is not an image");
            *st = 2; g_result = false;
            return false;
        }
        if (!hide::alloc_rx(self_base, nt->OptionalHeader.SizeOfImage)) {
            log::w(L"target mode: rx failed");
            *st = 2; g_result = false;
            return false;
        }
        g_result = hide::launch_worker(reinterpret_cast<void*>(&worker));
        *st = 2;
        return g_result;
    }

    if (in_ldr(arg1)) {
        g_trace[4] = 0xA4;
        log::w(L"host mode");
        wchar_t path[260]{};
        exe_name(path, 260);
        bool ok = relay(path);
        log::w(ok ? L"relay ok" : L"relay failed");
        log::close();
        *st = 2; g_result = ok;
        return ok;
    }

    if (g_host_path[0]) {
        g_trace[4] = 0xA5;
        log::w(L"manual host mode");
        bool ok = relay(g_host_path);
        log::w(ok ? L"relay ok" : L"relay failed");
        log::close();
        *st = 2; g_result = ok;
        return ok;
    }
    g_trace[4] = 0xA6;

    log::w(L"target mode");
    void* self_base = peb::self()->ImageBaseAddress;
    auto* dos = static_cast<IMAGE_DOS_HEADER_*>(self_base);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64_*>(static_cast<uint8_t*>(self_base) + dos->e_lfanew);
    if (dos->e_magic != 0x5A4D || nt->Signature != 0x4550) {
        log::w(L"image base is not an image");
        log::close();
        *st = 2; g_result = false;
        return false;
    }

    if (!hide::alloc_rx(self_base, nt->OptionalHeader.SizeOfImage)) { log::w(L"rx failed"); log::close(); *st = 2; g_result = false; return false; }
    g_result = hide::launch_worker(reinterpret_cast<void*>(&worker));
    log::close();
    *st = 2;
    return g_result;
}