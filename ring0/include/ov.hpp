#pragma once
#include <windows.h>
#include <cstdint>

namespace ov {
struct Color { float r, g, b, a; };

// Layered window over the game; its own D3D11 swapchain.
// No Present hook, no D3D12 — just a transparent window that follows
// UnrealWindow each frame.
bool init(HWND game);
void shutdown();
void tick();                     // follow the game window each frame

bool pump();                     // false when the game window is gone
void begin();                    // reset command list
void end();                      // close command list / present

void fill(float l, float t, float r, float b, Color c);
void box(float l, float t, float r, float b, Color c, float th);
void line(float x0, float y0, float x1, float y1, float th, Color c);
void text(float x, float y, const wchar_t* s, Color c, float scale = 1.f);
float textw(const wchar_t* s, float scale = 1.f);
int width();
int height();
} // namespace ov