#include "vmm.hpp"
#include "esp.hpp"
#include "ov.hpp"
#include "r0.hpp"
#include <windows.h>
#include <cstdio>

namespace { constexpr wchar_t kImage[] = L"FortniteClient-Win64-Shipping.exe"; }

// Simple toggle state – no boollast / staticULONGLAST_try cruft.
struct Toggle { int vk; bool* flag; };

bool key_pressed_once(int vk) {
    static bool was_down[256]{};
    bool cur = (GetAsyncKeyState(vk) & 0x8000) != 0;
    bool ret = cur && !was_down[vk];
    was_down[vk] = cur;
    return ret;
}

int wmain() {
    if (!r0::init()) {
        printf("driver missing - run run_r0.bat as admin\n");
        return 1;
    }
    printf("driver ok; scanning\n");
    if (!vmm::init()) {
        printf("kernel discovery failed\n");
        return 1;
    }

    HWND game = nullptr;
    for (int i = 0; i < 240 && !game; ++i) {
        game = FindWindowW(L"UnrealWindow", nullptr);
        Sleep(500);
    }
    if (!game) { printf("no UnrealWindow\n"); return 1; }

    if (!vmm::attach(kImage)) {
        printf("process not found\n");
        return 1;
    }
    printf("attached pid %u\n", vmm::pid());

    if (!ov::init(game)) {
        printf("overlay failed\n");
        return 1;
    }

    // Init ESP – throttled: try once per second if not ready.
    static ULONGLONG last_try{}; 
    if (!esp::ready() && GetTickCount64() - last_try > 1000) {
        last_try = GetTickCount64();
        esp::init();
    }

    // Toggle table – one entry per config flag.
    Toggle t[] = {
        { VK_F1, &esp::cfg.on },
        { VK_F2, &esp::cfg.boxes },
        { VK_F3, &esp::cfg.names },
        { VK_F4, &esp::cfg.health },
        { VK_F5, &esp::cfg.dist },
        { VK_F6, &esp::cfg.lines },
        { VK_F7, &esp::cfg.team_colors },
        { VK_F8, &esp::cfg.bots }
    };

    for (;;) {
        if (!ov::pump()) break;
        if (key_pressed_once(VK_END)) break;

        // Handle toggles.
        for (auto& x : t) {
            if (key_pressed_once(x.vk)) *x.flag = !*x.flag;
        }

        ov::tick();
        ov::begin();
        esp::draw();
        ov::end();
        Sleep(1);
    }

    esp::shutdown();
    ov::shutdown();
    vmm::shutdown();
    return 0;
}