#pragma once
#include <cstdint>
#include <windows.h>

namespace ov {

struct Color { float r, g, b, a; };
struct Vec3  { double x, y, z; };
struct Pov   { Vec3 loc{}; Vec3 fwd{}; Vec3 right{}; Vec3 up{}; double focal{}; int w{}; int h{}; };

// Overlay subsystem - D3D11 layered window
bool   init(HWND game);
void   shutdown();
bool   attached();
bool   pump();            // pump messages, returns false if overlay closed
void   begin();           // begin frame (clear vertex buffer)
void   end();             // end frame (draw + present)
void   tick();            // update window position/size

// Drawing primitives
void fill(float l, float t, float r, float b, Color c);
void box(float l, float t, float r, float b, Color c, float th = 1.0f);
void line(float x0, float y0, float x1, float y1, float th, Color c);
void text(float x, float y, const wchar_t* s, Color c, float sc = 1.0f);
float textw(const wchar_t* s, float sc);

int  width();
int  height();
int  pending();          // pending vertex count (for debugging)

void set_surface(int w, int h);

} // namespace ov