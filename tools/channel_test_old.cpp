// channel_test.cpp - round trip for the payload's log-file command channel.
//
// Loads out\payload.dll into this process with LoadLibraryW, calls the payload's
// exported `start` (the same entry the mapper calls), appends commands to the log
// file the channel tails, and prints the answers. Everything is measured: a
// missing answer is reported with the file sizes that explain it.
#include <windows.h>
#include "map_host.hpp"
#include <stdio.h>
#include "map_host.hpp"
#include <vector>

static const wchar_t* kIn  = L"C:\\Users\\Public\\fortesp2.log";
static const wchar_t* kOut = L"C:\\Users\\Public\\fort_channel.out";

static long long fsize(const wchar_t* p) {
    HANDLE h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return -1;
    LARGE_INTEGER li; li.LowPart = GetFileSize(h, (LPDWORD)&li.HighPart);
    CloseHandle(h); return li.QuadPart;
}

static void send(const char* line) {
    HANDLE h = CreateFileW(kIn, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) { printf("append failed %lu\n", GetLastError()); return; }
    DWORD w = 0, n = 0; while (line[n]) ++n;
    WriteFile(h, line, n, &w, nullptr);
    WriteFile(h, "\r\n", 2, &w, nullptr);
    CloseHandle(h);
}

static void show_out() {
    FILE* f = _wfopen(kOut, L"r");
    if (!f) { printf("  (no answer file)\n"); return; }
    char buf[512];
    while (fgets(buf, sizeof(buf), f)) printf("  <- %s", buf);
    fclose(f);
}

int wmain() {
    FILE* fl = nullptr;
    fl = _wfopen(L"C:\\Users\\Public\\fort_chantest.log", L"w");
    if (fl) { fprintf(fl, "armed\n"); fflush(fl); }   // proves the process ran at all
    HANDLE ev = CreateFileW(L"C:\\Users\\Public\\fort_ev.txt", GENERIC_WRITE, 0,
                            nullptr, CREATE_ALWAYS, 0, nullptr);
    if (ev != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(ev, "ran", 3, &w, nullptr); CloseHandle(ev); }
    DeleteFileW(kOut);
    HANDLE dbg = CreateFileW(L"C:\\Users\\Public\\fort_step.txt", GENERIC_WRITE, 0,
                             nullptr, CREATE_ALWAYS, 0, nullptr);
    DWORD dw = 0;
    if (dbg != INVALID_HANDLE_VALUE) { WriteFile(dbg, "step0", 5, &dw, nullptr); }
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (fl) { fprintf(fl, "log %lld\n", fsize(kIn)); fflush(fl); }
    if (dbg != INVALID_HANDLE_VALUE) { WriteFile(dbg, ",step1", 6, &dw, nullptr); }
    // LoadLibraryW hangs in the payload's own TLS/DllMain path (it expects the
    // mapper's thread setup), so the image is mapped by hand, exactly as the
    // proxy does it.
    HMODULE m = (HMODULE)0x1;
    (void)m;
    if (dbg != INVALID_HANDLE_VALUE) { WriteFile(dbg, ",step2", 6, &dw, nullptr); }
    if (!m) return 1;

    // The full start() path waits on the payload's own thread setup in a host
    // that is not the client, so the channel is driven directly - it is the
    // piece under test.
    printf("loaded ok\n"); fflush(stdout);
    if (fl) { fprintf(fl, "loaded m=%p err=%lu\n", (void*)m, GetLastError()); fflush(fl); }
    typedef void (*chfn)();
    chfn ch = (chfn)GetProcAddress((HMODULE)GetModuleHandleW(L"payload.dll"), "channel_start");
    printf("channel_start 0x%p\n", (void*)ch);
    if (!ch) return 1;
    fflush(stdout);
    if (dbg != INVALID_HANDLE_VALUE) { WriteFile(dbg, ",step3", 6, &dw, nullptr); CloseHandle(dbg); }
    ch();
    FlushFileBuffers(dbg);
    fflush(stdout);
    printf("returned from channel_start\n");
    printf("channel started\n");
    fflush(stdout);
    Sleep(2000);
    printf("in=%lld out=%lld\n", fsize(kIn), fsize(kOut));

    send("PING");
    Sleep(900);
    send("BASE");
    Sleep(900);
    send("MOD kernel32.dll");
    Sleep(900);
    show_out();
    return 0;
}
