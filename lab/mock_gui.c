/* A plain Win32 GUI target: a visible window, so EVENT_OBJECT_SHOW is
 * guaranteed. The console mock is not enough - its window belongs to
 * conhost. */
#include <windows.h>

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_DESTROY) PostQuitMessage(0);
    return DefWindowProcW(h, m, w, l);
}

int WINAPI WinMain(HINSTANCE h, HINSTANCE, LPSTR, int) {
    WNDCLASSA wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = wndproc;
    wc.hInstance = h;
    wc.lpszClassName = "MockGuiTarget";
    RegisterClassA(&wc);
    HWND w = CreateWindowExA(0, "MockGuiTarget", "mock gui", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                             100, 100, 420, 300, NULL, NULL, h, NULL);
    if (!w) return 1;
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}
