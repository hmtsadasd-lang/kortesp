/* Mock client: a target that copies the *real* client's I/O design.
 *
 * The hook matrix measured on the live game found six hook families that
 * install with err=0 and then never fire. Two very different explanations fit
 * that silence:
 *
 *   1. the client's message/input design never drives those hooks, or
 *   2. the injection itself is vetoed inside the client (EAC hooks
 *      LdrpLoadDll / LdrRegisterDllNotification), so no hook can run there.
 *
 * To tell them apart we need a target that we *know* does what the client
 * does, and that we can watch directly. This program is that target. It has
 * three loops, selected on the command line:
 *
 *   get   - the textbook GetMessage loop. Everything that can fire, fires.
 *   peek  - PeekMessage(PM_REMOVE) loop, legacy input still on. Isolates
 *           "does PeekMessage alone suppress WH_GETMESSAGE?".
 *   raw   - PeekMessage loop + RegisterRawInputDevices(RIDEV_NOLEGACY): the
 *           real client's design. No legacy key or mouse message is ever
 *           queued and the game reads WM_INPUT instead.
 *
 * The window class is MockClientWindow and the window is visible, so the
 * harness can find it the same way the real probes find the game's
 * UnrealWindow. Nothing here is an anti-cheat evasion: it is a fixture that
 * demonstrates which hook families a PeekMessage/raw-input program can drive,
 * so a hook that never fires in the game can be classified as "design" or
 * "refused" by comparison.
 *
 * Build (lab\run_all.ps1 does this):
 *   gcc -m64 -O2 -static -o mock_client.exe mock_client.c -luser32
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static const char* g_mode = "raw";
static volatile LONG g_input = 0;   /* WM_INPUT deliveries seen            */
static volatile LONG g_legacy = 0;  /* legacy key and mouse messages seen  */
static volatile LONG g_ticks = 0;   /* loop iterations                     */

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_INPUT:
        InterlockedIncrement(&g_input);
        break;
    case WM_KEYDOWN: case WM_KEYUP: case WM_SYSKEYDOWN: case WM_SYSKEYUP:
    case WM_MOUSEMOVE: case WM_LBUTTONDOWN: case WM_LBUTTONUP:
    case WM_RBUTTONDOWN: case WM_RBUTTONUP: case WM_MOUSEWHEEL:
        InterlockedIncrement(&g_legacy);
        break;
    case WM_CLOSE:
        DestroyWindow(h);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        break;
    }
    return DefWindowProcW(h, m, w, l);
}

/* A desktop key tap and a click, so the input stack has something to deliver
 * even when the harness is not sending anything. */
static void poke_input(void) {
    INPUT in[2];
    ZeroMemory(in, sizeof(in));
    in[0].type = INPUT_KEYBOARD;
    in[0].ki.wVk = VK_F13;                 /* silent, non-typing */
    in[1] = in[0];
    in[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, in, sizeof(INPUT));
}

int WINAPI WinMain(HINSTANCE h, HINSTANCE, LPSTR cmd, int) {
    (void)cmd;
    /* The mode may arrive as "raw", "--raw" or "-raw". */
    {
        LPSTR cl = GetCommandLineA();
        if (cl) {
            if (strstr(cl, "legacypump") || strstr(cl, "--legacypump")) g_mode = "legacypump";
            else if (strstr(cl, "peek") && !strstr(cl, "raw")) g_mode = "peek";
            else if (strstr(cl, "get")) g_mode = "get";
        }
    }

    WNDCLASSW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = wndproc;
    wc.hInstance = h;
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.lpszClassName = L"MockClientWindow";
    if (!RegisterClassW(&wc)) {
        printf("[!] RegisterClass failed %lu\n", GetLastError());
        return 1;
    }

    HWND w = CreateWindowExW(0, L"MockClientWindow", L"mock client", 
                             WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                             120, 120, 640, 400, NULL, NULL, h, NULL);
    if (!w) { printf("[!] CreateWindow failed %lu\n", GetLastError()); return 1; }

    printf("[*] mock client pid %lu tid %lu mode %s window %p\n",
           (unsigned long)GetCurrentProcessId(),
           (unsigned long)GetCurrentThreadId(), g_mode, (void*)w);
    fflush(stdout);

    /* The raw-input fingerprint. RIDEV_NOLEGACY turns off the keyboard and
     * mouse *legacy* messages for this window: the system posts WM_INPUT and
     * nothing else. This is what the real client does. */
    if (strcmp(g_mode, "raw") == 0) {
        RAWINPUTDEVICE rid[2];
        ZeroMemory(rid, sizeof(rid));
        rid[0].usUsagePage = 0x01; rid[0].usUsage = 0x06;   /* keyboard */
        rid[0].dwFlags = RIDEV_NOLEGACY; rid[0].hwndTarget = w;
        rid[1].usUsagePage = 0x01; rid[1].usUsage = 0x02;   /* mouse    */
        rid[1].dwFlags = RIDEV_NOLEGACY; rid[1].hwndTarget = w;
        if (!RegisterRawInputDevices(rid, 2, sizeof(RAWINPUTDEVICE)))
            printf("[!] RegisterRawInputDevices failed %lu\n", GetLastError());
        else
            printf("[*] raw input registered (RIDEV_NOLEGACY)\n");
        fflush(stdout);
    }

    MSG msg;
    ULONGLONG t0 = GetTickCount64();
    for (;;) {
        /* Every 2 s nudge the input stack, so a run with no harness keystrokes
         * still gives the input hooks a reason to be called. */
        if ((GetTickCount64() - t0) % 2000 < 20) poke_input();

        if (strcmp(g_mode, "get") == 0) {
            if (GetMessageW(&msg, NULL, 0, 0) <= 0) break;
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        } else {
            /* peek and raw: the client's loop shape. */
            while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) return 0;
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            Sleep(1);
        }
        InterlockedIncrement(&g_ticks);

        if ((GetTickCount64() - t0) % 10000 < 20) {
            printf("[*] ticks=%ld input=%ld legacy=%ld\n",
                   (long)g_ticks, (long)g_input, (long)g_legacy);
            fflush(stdout);
        }
    }
    return 0;
}
