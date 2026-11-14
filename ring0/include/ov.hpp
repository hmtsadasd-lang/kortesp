#pragma once
#include <windows.h>
#include <cstdint>

namespace ov {
struct Color{float r,g,b,a;};
bool init(HWND game); void shutdown(); void tick(); bool pump(); void begin(); void end();
void fill(float l,float t,float r,float b,Color c); void box(float l,float t,float r,float b,Color c,float th); void line(float x0,float y0,float x1,float y1,float th,Color c); void text(float x,float y,const wchar_t*s,Color c,float scale=1.f); float textw(const wchar_t*s,float scale=1.f); int width(); int height();
} // namespace ov