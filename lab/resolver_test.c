/* Local harness for the mapper's export resolver.
 *
 * The resolver is pure logic over readable memory, so it can be checked
 * without a target process: load a module locally, walk its export table the
 * same way the mapper does, and compare every answer with GetProcAddress.
 *
 * This is what caught the case-sensitivity bug: the import table writes
 * "KERNEL32.dll", the loader's module list says "kernel32.dll", and the two
 * only hash the same when the module hash folds case.
 *
 * Self contained on purpose: the WinSDK's winternl.h does not carry the full
 * LDR structures on every toolchain.
 *
 * Build: gcc -m64 -O2 -o resolver_test.exe resolver_test.c
 * Usage: resolver_test.exe [module ...]
 */
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint16_t Length, MaximumLength;
    PWSTR   Buffer;
} USTR;

typedef struct _LDR_ENTRY {
    void  *InLoadOrderLinks[2];
    void  *InMemoryOrderLinks[2];
    void  *InInitOrderLinks[2];
    void  *DllBase, *EntryPoint;
    uint32_t SizeOfImage;
    USTR   FullDllName, BaseDllName;
} LDR_ENTRY;

typedef struct {
    uint32_t Length;
    uint8_t  Initialized;
    void    *SsHandle;
    void    *InLoadOrder[2], *InMemoryOrder[2], *InInitOrder[2];
} LDR_DATA;

typedef struct {
    uint8_t  pad[0x18];
    LDR_DATA *Ldr;
} MY_PEB;

typedef struct {
    uint32_t Characteristics, TimeDateStamp;
    uint16_t MajorVersion, MinorVersion;
    uint32_t Name, Base, NumberOfFunctions, NumberOfNames;
    uint32_t AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
} EXPORT_DIR;

/* the same hash the mapper uses, case insensitive for module names */
static unsigned fnv1a_ci(const char *s) {
    unsigned v = 0x811C9DC5u;
    while (*s) {
        unsigned char c = (unsigned char)*s;
        if (c >= 'A' && c <= 'Z') c += 32;
        v = (v ^ c) * 0x01000193u;
        s++;
    }
    return v;
}

static unsigned fnv1a(const char *s) {
    unsigned v = 0x811C9DC5u;
    while (*s) {
        v = (v ^ (unsigned char)*s) * 0x01000193u;
        s++;
    }
    return v;
}

/* ASCII-folded hash of a wide string.
 *
 * fnv1a_w folds case but hashes the 16 bit code unit while fnv1a hashes
 * bytes, so a wide name can never match the same narrow name. The mapper
 * walks module names out of the LDR list (wide) and compares them against
 * names from an import table (narrow), so both sides have to hash the
 * lowercase ASCII byte. */
static unsigned fnv1a_ci_w(const wchar_t *s) {
    unsigned v = 0x811C9DC5u;
    while (*s) {
        unsigned c = (unsigned)(unsigned short)*s;
        if (c >= L'A' && c <= L'Z') c += 32;
        if (c > 0x7F) c = '?';
        v = (v ^ (unsigned char)c) * 0x01000193u;
        s++;
    }
    return v;
}

/* the mapper's module lookup, against our own module list */
static uint8_t *module_base_ci(const char *want) {
    unsigned want_hash = fnv1a_ci(want);
    MY_PEB *peb = (MY_PEB *)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return NULL;
    uint8_t *head = (uint8_t *)&peb->Ldr->InMemoryOrder[0];
    uint8_t *cur = *(uint8_t **)head;
    for (int guard = 0; cur && cur != head && guard < 512; guard++) {
        LDR_ENTRY *e = (LDR_ENTRY *)(cur - offsetof(LDR_ENTRY, InMemoryOrderLinks));
        if (e->BaseDllName.Buffer) {
            /* the wide name is hashed as folded ASCII bytes, exactly like the
             * import side - a wide/narrow mismatch here is invisible to a
             * harness that converts to ASCII first */
            if (fnv1a_ci_w(e->BaseDllName.Buffer) == want_hash) return (uint8_t *)e->DllBase;
        }
        cur = *(uint8_t **)cur;
    }
    return NULL;
}

/* the mapper's export lookup, forwarders included */
static uint64_t export_by_name(uint8_t *base, const char *name, int depth);

static uint64_t resolve_forwarder(uint8_t *base, uint32_t fwd_rva,
                                  uint32_t dir_rva, uint32_t dir_size, int depth) {
    if (depth >= 2) return 0;
    if (fwd_rva < dir_rva || fwd_rva >= dir_rva + dir_size) return 0;

    char text[160] = { 0 };
    memcpy(text, base + fwd_rva, sizeof(text) - 1);

    char *dot = strrchr(text, '.');
    if (!dot) return 0;
    *dot = 0;

    uint8_t *tbase = module_base_ci(text);
    if (!tbase) return 0;

    IMAGE_DOS_HEADER *tdos = (IMAGE_DOS_HEADER *)tbase;
    IMAGE_NT_HEADERS64 *tnt = (IMAGE_NT_HEADERS64 *)(tbase + tdos->e_lfanew);
    IMAGE_DATA_DIRECTORY *tdd = &tnt->OptionalHeader.DataDirectory[0];
    if (!tdd->VirtualAddress) return 0;
    EXPORT_DIR *ted = (EXPORT_DIR *)(tbase + tdd->VirtualAddress);

    if (dot[1] == '#') {
        uint16_t ord = (uint16_t)atoi(dot + 2);
        if (ord < ted->Base) return 0;
        uint32_t idx = (uint32_t)ord - ted->Base;
        if (idx >= ted->NumberOfFunctions) return 0;
        uint32_t fn = ((uint32_t *)(tbase + ted->AddressOfFunctions))[idx];
        if (fn & 0x80000000u) return 0;
        uint64_t f = resolve_forwarder(tbase, fn, tdd->VirtualAddress, tdd->Size, depth + 1);
        return f ? f : (uint64_t)(tbase + fn);
    }
    return export_by_name(tbase, dot + 1, depth + 1);
}

static uint64_t export_by_name(uint8_t *base, const char *name, int depth) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[0];
    if (!dd->VirtualAddress) return 0;
    EXPORT_DIR *ed = (EXPORT_DIR *)(base + dd->VirtualAddress);

    uint32_t *names = (uint32_t *)(base + ed->AddressOfNames);
    uint16_t *ords = (uint16_t *)(base + ed->AddressOfNameOrdinals);
    uint32_t *funcs = (uint32_t *)(base + ed->AddressOfFunctions);

    unsigned want = fnv1a(name);
    for (DWORD i = 0; i < ed->NumberOfNames; i++) {
        const char *ename = (const char *)(base + names[i]);
        if (fnv1a(ename) != want) continue;
        DWORD fn = funcs[ords[i]];
        if (fn & 0x80000000u) continue;
        uint64_t f = resolve_forwarder(base, fn, dd->VirtualAddress, dd->Size, depth);
        return f ? f : (uint64_t)(base + fn);
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *mods[] = { "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
                           "gdi32.dll", "shell32.dll", "bcrypt.dll", "winhttp.dll",
                           "version.dll", "crypt32.dll" };
    int nmods = (int)(sizeof(mods) / sizeof(mods[0]));
    if (argc > 1) { nmods = argc - 1; for (int i = 0; i < nmods; i++) mods[i] = argv[i + 1]; }

    int checked = 0, missed = 0, fwd = 0;

    for (int m = 0; m < nmods; m++) {
        HMODULE h = LoadLibraryA(mods[m]);
        if (!h) { printf("%-16s not loadable here\n", mods[m]); continue; }

        uint8_t *base = module_base_ci(mods[m]);
        if (!base) {
            printf("%-16s MODULE LOOKUP FAILED (hash mismatch)\n", mods[m]);
            missed++;
            continue;
        }

        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
        IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
        IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[0];
        if (!dd->VirtualAddress) continue;
        EXPORT_DIR *ed = (EXPORT_DIR *)(base + dd->VirtualAddress);
        uint32_t *names = (uint32_t *)(base + ed->AddressOfNames);
        uint16_t *ords = (uint16_t *)(base + ed->AddressOfNameOrdinals);
        uint32_t *funcs = (uint32_t *)(base + ed->AddressOfFunctions);

        int local_missed = 0, local_fwd = 0;
        for (DWORD i = 0; i < ed->NumberOfNames; i++) {
            const char *ename = (const char *)(base + names[i]);
            uint64_t got = export_by_name(base, ename, 0);
            FARPROC want = GetProcAddress(h, ename);
            checked++;
            if (!got) {
                local_missed++;
                printf("    miss %-16s %-40s got=0x%llX want=0x%llX\n",
                       mods[m], ename, (unsigned long long)got,
                       (unsigned long long)(uintptr_t)want);
                continue;
            }
            if (!want) {
                /* GetProcAddress cannot resolve it (the forward target is not
                 * loaded here) but the resolver can - that is a win, not a
                 * miss. */
                local_fwd++;
                continue;
            }
            if (got != (uint64_t)want) {
                /* a forwarder resolves to the real target, not to this module */
                DWORD fn = funcs[ords[i]];
                if (fn >= dd->VirtualAddress && fn < dd->VirtualAddress + dd->Size) local_fwd++;
                else {
                    local_missed++;
                    printf("    miss %-16s %-40s got=0x%llX want=0x%llX fwd_rva=0x%X\n",
                           mods[m], ename, (unsigned long long)got,
                           (unsigned long long)(uintptr_t)want, fn);
                }
            }
        }
        fwd += local_fwd;
        missed += local_missed;
        printf("%-16s base=%p exports=%u missed=%d forwarders=%d\n",
               mods[m], base, ed->NumberOfNames, local_missed, local_fwd);
    }

    printf("checked=%d missed=%d forwarders=%d\n", checked, missed, fwd);
    printf(missed ? "RESOLVER: FAIL\n" : "RESOLVER: OK\n");
    return missed ? 1 : 0;
}
