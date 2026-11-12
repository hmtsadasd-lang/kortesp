#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID reserved) {
    (void)self; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE f = CreateFileW(L"C:\\Users\\Public\\eac_dll_test.txt",
                               GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD pid = GetCurrentProcessId();
            static const char hex[] = "0123456789ABCDEF";
            char buf[13];
            buf[0] = 'p'; buf[1] = 'i'; buf[2] = 'd'; buf[3] = '=';
            for (int i = 0; i < 8; ++i) buf[4 + i] = hex[(pid >> (28 - i * 4)) & 0xF];
            buf[12] = '\n';
            DWORD put = 0;
            WriteFile(f, buf, 13, &put, NULL);
            CloseHandle(f);
        }
    }
    return TRUE;
}
