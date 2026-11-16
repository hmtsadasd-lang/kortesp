with open('C:\\dev\\fortesp\\ring0\\src\\main.cpp', 'r') as f:
    lines = f.readlines()

# Find start and end of CmdFlags struct
start = None
end = None
for i, line in enumerate(lines):
    if 'struct CmdFlags {' in line:
        start = i
    if start is not None and 'CmdFlags parse_cmd() {' in line:
        end = i
        break

print(f'Found struct at lines {start+1} to {end}')

new_block = '''    bool mock{ false };
    // Granular stages. Each one stops after its own step, so a hang can be
    // attributed to a layer instead of to the whole pipeline.
    bool raw{ false };          // one physical read, nothing else
    bool only_ntos{ false };    // SystemModuleInformation only
    bool only_cr3{ false };     // the heavy physical CR3 scan, on purpose
    bool only_eproc{ false };   // PsInitialSystemProcess only
    bool esp_mode{ false };     // overlay overlay
    bool actors{ false };       // PersistentLevel.Actors instead of PlayerArray
    uint64_t raw_pa{ 0 };
    size_t   raw_len{ 16 };
    std::wstring driver_name;   // --driver-name <name.sys>
};
CmdFlags parse_cmd() {
    CmdFlags f;
    int argc;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            if (wcscmp(argv[i], L"--probe") == 0) f.probe = true;
            if (wcscmp(argv[i], L"--kwtest") == 0) f.kwtest = true;
            if (wcscmp(argv[i], L"--cloak") == 0) f.cloak = true;
            if (wcscmp(argv[i], L"--cloak-commit") == 0) { f.cloak = true; f.cloak_commit = true; }
            if (wcscmp(argv[i], L"--cloak-restore") == 0) f.cloak_restore = true;
            if (wcscmp(argv[i], L"--hide-symlink") == 0) f.hide_symlink = true;
            if (wcscmp(argv[i], L"--mock")  == 0) f.mock  = true;
            if (wcscmp(argv[i], L"--esp")    == 0) f.esp_mode = true;
            if (wcscmp(argv[i], L"--actors") == 0) f.actors  = true;
            if (wcscmp(argv[i], L"--ntos")  == 0) f.only_ntos = true;
            if (wcscmp(argv[i], L"--cr3scan") == 0) f.only_cr3 = true;
            if (wcscmp(argv[i], L"--eproc") == 0) f.only_eproc = true;
            if (wcscmp(argv[i], L"--driver-name") == 0 && i + 1 < argc)
                f.driver_name = argv[++i];
            if (wcscmp(argv[i], L"--raw") == 0) {
                f.raw = true;
                if (i + 1 < argc) {
                    f.raw_pa = wcstoull(argv[++i], nullptr, 0);
                    if (i + 1 < argc && argv[i + 1][0] != L'-') {
                        const unsigned long long l = wcstoull(argv[++i], nullptr, 0);
                        if (l && l <= 0x1000) f.raw_len = static_cast<size_t>(l);
                        else if (l) printf("[!] len %llu capped to 4096\n", l);
                    }
                }
            }
        }
        LocalFree(argv);
    }
    return f;
}'''

new_lines = lines[:start] + [new_block + '\n'] + lines[end:]
with open('C:\\dev\\fortesp\\ring0\\src\\main.cpp', 'w') as f:
    f.writelines(new_lines)
print('SUCCESS')