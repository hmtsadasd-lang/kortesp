#pragma once
#include <windows.h>
#include <cstdint>

namespace render {

struct Color { float r, g, b, a; };

bool init();
void shutdown();

void begin();
void end();

void rect(float l, float t, float r, float b, Color c);
void line(float x0, float y0, float x1, float y1, float th, Color c);
void text(float x, float y, const wchar_t* s, Color c, float scale = 1.f);
float text_width(const wchar_t* s, float scale = 1.f);

int width();
int height();

extern bool enabled;

} // namespace render