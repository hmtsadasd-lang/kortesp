// channel_test.cpp - round trip for the payload's log-file command channel.
//
// The channel lives inside the payload, so it has to be exercised where the
// payload really runs: in a separate process, mapped by the project's own
// mapper. Mapping into this process hangs (the mapper waits for an entry thread
// in its target) and LoadLibraryW hangs too (the payload's TLS/DllMain path
// expects the mapper's thread setup) - both measured, so neither is used here.
//
//   1. start out\lab\FortniteClient-Win64-Shipping.exe (the mock target)
//   2. manual_map_host the payload into it
//   3. find the payload's own `channel_start` in the mapped image's export table
//   4. call it, append commands to the log file, print the answers
#include <windows.h>
#include <stdio.h>
#include <vector>
#include "map_host.hpp"

static const wchar_t* kIn  = L"C:\\Users\\Public\\fortesp2.log";
static const wchar_t* kOut = L"C:\\Users\\Public\\fort_channel.out";

static long long fsize(const wchar_t* p) {
    HANDLE h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return -1;
    LARGE_INTEGER li; li.LowPart = GetFileSize(h, (LPDWORD)&li.HighPart);
    CloseHandle(h); return li.QuadPart;
}

static void send_line(const char* line) {
    HANDLE h = CreateFileW(kIn, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) { printf("append failed %lu\n", GetLastError()); return; }
    DWORD w = 0, n = 0; while (line[n]) ++n;
    WriteFile(h, line, n, &w, nullptr);
    WriteFile(h, "\r\n", 2, &w, nullptr);
    CloseHandle(h);
}

static void show_answers() {
    FILE* f = _wfopen(kOut, L"r");
    if (!f) { printf("  (no answer file)\n"); return; }
    char buf[512];
    while (fgets(buf, sizeof(buf), f)) printf("  <- %s", buf);
    fclose(f);
}

// Resolve an export of the *mapped* image by walking its export directory: the
// mapper places the image at an arbitrary base, so GetProcAddress cannot be
// used. The image lives in the target's address space, so it has to be read
// with ReadProcessMemory - a plain read here faults.
static void* mapped_export(HANDLE proc, uint64_t base, const char* want) {
    UCHAR dos[64] = { 0 };
    if (!ReadProcessMemory(proc, (void*)(uintptr_t)base, dos, sizeof(dos), nullptr)) return nullptr;

    DWORD lfanew = *(DWORD*)(dos + 0x3C);
    UCHAR ntbuf[0x200] = { 0 };
    if (!ReadProcessMemory(proc, (void*)(uintptr_t)(base + lfanew), ntbuf, sizeof(ntbuf), nullptr)) return nullptr;

    auto* nt = (IMAGE_NT_HEADERS64*)ntbuf;
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return nullptr;

    UCHAR edbuf[1024] = { 0 };
    if (!ReadProcessMemory(proc, (void*)(uintptr_t)(base + dir.VirtualAddress), edbuf, sizeof(edbuf), nullptr))
        return nullptr;
    auto* exp = (IMAGE_EXPORT_DIRECTORY*)edbuf;

    UCHAR nbuf[4096] = { 0 };
    if (!ReadProcessMemory(proc, (void*)(uintptr_t)(base + exp->AddressOfNames), nbuf, sizeof(nbuf), nullptr))
        return nullptr;
    auto* names = (DWORD*)nbuf;

    UCHAR obuf[2048] = { 0 };
    if (!ReadProcessMemory(proc, (void*)(uintptr_t)(base + exp->AddressOfNameOrdinals), obuf, sizeof(obuf), nullptr))
        return nullptr;
    auto* ords = (WORD*)obuf;

    UCHAR fbuf[4096] = { 0 };
    if (!ReadProcessMemory(proc, (void*)(uintptr_t)(base + exp->AddressOfFunctions), fbuf, sizeof(fbuf), nullptr))
        return nullptr;
    auto* funcs = (DWORD*)fbuf;

    printf("mapped image exports: %lu\n", (unsigned long)exp->NumberOfNames);
    for (DWORD i = 0; i < exp->NumberOfNames && i < 1024; ++i) {
        char nm[128] = { 0 };
        if (!ReadProcessMemory(proc, (void*)(uintptr_t)(base + names[i]), nm, sizeof(nm) - 1, nullptr)) break;
        const char* a = nm; const char* b = want;
        while (*a && *b && *a == *b) { ++a; ++b; }
        if (!*a && !*b) return (void*)(uintptr_t)(base + funcs[ords[i]]);
    }
    return nullptr;
}

int wmain() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    DeleteFileW(kOut);

    FILE* f = _wfopen(L"C:\\dev\\fortesp\\out\\payload.dll", L"rb");
    if (!f) { printf("no payload.dll\n"); return 1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    std::vector<unsigned char> img(static_cast<size_t>(sz));
    if (fread(img.data(), 1, static_cast<size_t>(sz), f) != static_cast<size_t>(sz)) { fclose(f); return 1; }
    fclose(f);
    printf("payload %ld bytes\n", sz);

    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    wchar_t cmd[] = L"out\\lab\\FortniteClient-Win64-Shipping.exe";
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE,
                        nullptr, nullptr, &si, &pi)) {
        printf("mock target start failed %lu\n", GetLastError());
        return 1;
    }
    printf("mock target pid %lu\n", (unsigned long)pi.dwProcessId);
    Sleep(600);

    map_result mr; ZeroMemory(&mr, sizeof(mr));
    // keep_mapped: the test reads the mapped image's export table below, so
    // the image has to survive the entry thread.
    bool ran = manual_map_host(pi.hProcess, img.data(), static_cast<size_t>(sz),
                               L"C:\\dev\\fortesp\\out\\payload.dll", "channel_start",
                               true, &mr, 20000, nullptr);
    printf("map ran=%d exit=0x%08lX remote=%p\n", ran ? 1 : 0,
           (unsigned long)mr.exit_code, (void*)mr.remote);
    if (!ran) return 1;

    Sleep(1500);
    printf("log %lld answers %lld\n", fsize(kIn), fsize(kOut));
    void* ch = mapped_export(pi.hProcess, mr.remote, "channel_start");
    printf("channel_start in image: %p\n", ch);

    send_line("PING");
    Sleep(800);
    send_line("BASE");
    Sleep(800);
    send_line("MOD kernel32.dll");
    Sleep(800);
    show_answers();
    return 0;
}
