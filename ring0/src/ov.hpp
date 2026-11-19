#pragma once
#include "font.hpp"
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <cstdint>
#include <cstring>
#include <cmath>

// Layered, click-through, topmost D3D11 overlay. Flip-model swapchain with
// DXGI_ALPHA_MODE_PREMULTIPLIED and premultiplied blending (ONE /
// INV_SRC_ALPHA).
namespace ov {

struct Color { float r, g, b, a; };

namespace detail {

constexpr wchar_t kClass[] = L"FortespOverlayHost";
constexpr int kMaxVerts = 1 << 19;

struct Vert { float x, y, r, g, b, a; };

inline HWND g_wnd{};
inline HWND g_game{};
inline ID3D11Device* g_dev{};
inline ID3D11DeviceContext* g_ctx{};
inline IDXGISwapChain1* g_sc{};
inline ID3D11RenderTargetView* g_rtv{};
inline ID3D11VertexShader* g_vs{};
inline ID3D11PixelShader* g_ps{};
inline ID3D11InputLayout* g_il{};
inline ID3D11Buffer* g_vb{};
inline ID3D11Buffer* g_cb{};
inline ID3D11BlendState* g_bl{};
inline ID3D11RasterizerState* g_rs{};
inline ID3D11DepthStencilState* g_ds{};
inline int g_w{}, g_h{};
inline Vert g_stage[kMaxVerts]{};
inline int g_n{};

inline const char* kSrc =
    "cbuffer C:register(b0){float2 sz;};"
    "struct I{float2 p:POS;float4 c:COL;};"
    "struct O{float4 p:SV_POSITION;float4 c:COL;};"
    "O vs(I i){O o;o.p=float4(i.p.x/sz.x*2-1,1-i.p.y/sz.y*2,0,1);o.c=i.c;return o;}"
    "float4 ps(O i):SV_TARGET{return float4(i.c.rgb*i.c.a,i.c.a);}";

inline LRESULT CALLBACK proc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, msg, w, l);
}

using CompileFn = HRESULT(__stdcall*)(const void*, SIZE_T, const char*, const void*,
    const void*, const char*, const char*, UINT, UINT, ID3DBlob**, ID3DBlob**);

inline bool build_pipeline() {
    HMODULE c = LoadLibraryW(L"d3dcompiler_47.dll");
    if (!c) return false;
    auto fn = reinterpret_cast<CompileFn>(
        reinterpret_cast<void*>(GetProcAddress(c, "D3DCompile")));
    if (!fn) return false;

    ID3DBlob* vs{}; ID3DBlob* ps{}; ID3DBlob* err{};
    const SIZE_T len = strlen(kSrc);
    if (fn(kSrc, len, "o", nullptr, nullptr, "vs", "vs_5_0", 0, 0, &vs, &err) < 0) return false;
    if (fn(kSrc, len, "o", nullptr, nullptr, "ps", "ps_5_0", 0, 0, &ps, &err) < 0) return false;
    if (g_dev->CreateVertexShader(vs->GetBufferPointer(), vs->GetBufferSize(), nullptr, &g_vs) < 0) return false;
    if (g_dev->CreatePixelShader(ps->GetBufferPointer(), ps->GetBufferSize(), nullptr, &g_ps) < 0) return false;

    D3D11_INPUT_ELEMENT_DESC ie[] = {
        { "POS", 0, DXGI_FORMAT_R32G32_FLOAT,       0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "COL", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 8, D3D11_INPUT_PER_VERTEX_DATA, 0 },
    };
    if (g_dev->CreateInputLayout(ie, 2, vs->GetBufferPointer(), vs->GetBufferSize(), &g_il) < 0) return false;

    D3D11_BUFFER_DESC bd{};
    bd.ByteWidth = sizeof(Vert) * kMaxVerts;
    bd.Usage = D3D11_USAGE_DYNAMIC;
    bd.BindFlags = D3D11_BIND_VERTEX_BUFFER;
    bd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    if (g_dev->CreateBuffer(&bd, nullptr, &g_vb) < 0) return false;

    D3D11_BUFFER_DESC cd{};
    cd.ByteWidth = 16;
    cd.Usage = D3D11_USAGE_DEFAULT;
    cd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
    if (g_dev->CreateBuffer(&cd, nullptr, &g_cb) < 0) return false;

    D3D11_BLEND_DESC bl{};
    bl.RenderTarget[0].BlendEnable = TRUE;
    bl.RenderTarget[0].SrcBlend = D3D11_BLEND_ONE;
    bl.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
    bl.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
    bl.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
    bl.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_INV_SRC_ALPHA;
    bl.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    if (g_dev->CreateBlendState(&bl, &g_bl) < 0) return false;

    D3D11_RASTERIZER_DESC rd{};
    rd.FillMode = D3D11_FILL_SOLID;
    rd.CullMode = D3D11_CULL_NONE;
    rd.DepthClipEnable = TRUE;
    if (g_dev->CreateRasterizerState(&rd, &g_rs) < 0) return false;

    D3D11_DEPTH_STENCIL_DESC dd{};
    dd.DepthEnable = FALSE;
    dd.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;
    if (g_dev->CreateDepthStencilState(&dd, &g_ds) < 0) return false;
    return true;
}

inline bool make_rtv() {
    ID3D11Texture2D* buf{};
    if (g_sc->GetBuffer(0, __uuidof(ID3D11Texture2D), reinterpret_cast<void**>(&buf)) < 0)
        return false;
    const HRESULT hr = g_dev->CreateRenderTargetView(buf, nullptr, &g_rtv);
    buf->Release();
    return hr >= 0;
}

inline void push(float x, float y, Color c) {
    if (g_n >= kMaxVerts) return;
    g_stage[g_n++] = { x, y, c.r, c.g, c.b, c.a };
}

inline void quad(float l, float t, float r, float b, Color c) {
    push(l, t, c); push(r, t, c); push(r, b, c);
    push(l, t, c); push(r, b, c); push(l, b, c);
}

} // namespace detail

inline void tick_impl();

inline bool init(HWND game) {
    using namespace detail;
    g_game = game;

    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc = proc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = kClass;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;

    g_wnd = CreateWindowExW(WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST |
                            WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
        kClass, L"", WS_POPUP, 0, 0, 8, 8, nullptr, nullptr, wc.hInstance, nullptr);
    if (!g_wnd) return false;
    ShowWindow(g_wnd, SW_SHOWNOACTIVATE);

    const D3D_FEATURE_LEVEL want[] = { D3D_FEATURE_LEVEL_11_0 };
    D3D_FEATURE_LEVEL got{};
    if (D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT, want, 1, D3D11_SDK_VERSION,
        &g_dev, &got, &g_ctx) < 0) return false;

    IDXGIDevice* dxdev{};
    if (g_dev->QueryInterface(__uuidof(IDXGIDevice), reinterpret_cast<void**>(&dxdev)) < 0)
        return false;
    IDXGIAdapter* adap{};
    dxdev->GetAdapter(&adap);
    dxdev->Release();
    if (!adap) return false;

    IDXGIFactory2* fact{};
    if (adap->GetParent(__uuidof(IDXGIFactory2), reinterpret_cast<void**>(&fact)) < 0) {
        adap->Release();
        return false;
    }
    adap->Release();

    DXGI_SWAP_CHAIN_DESC1 sd{};
    sd.Width = 8; sd.Height = 8;
    sd.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.SampleDesc.Count = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount = 2;
    sd.Scaling = DXGI_SCALING_STRETCH;
    sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
    sd.AlphaMode = DXGI_ALPHA_MODE_PREMULTIPLIED;

    const HRESULT hr = fact->CreateSwapChainForHwnd(g_dev, g_wnd, &sd, nullptr, nullptr, &g_sc);
    fact->Release();
    if (hr < 0) return false;

    if (!build_pipeline() || !make_rtv()) return false;
    tick_impl();
    return true;
}

inline void tick_impl() {
    using namespace detail;
    if (!g_wnd || !IsWindow(g_game)) return;

    RECT r{};
    if (!GetClientRect(g_game, &r)) return;
    POINT tl{ 0, 0 };
    ClientToScreen(g_game, &tl);

    const int w = r.right - r.left, h = r.bottom - r.top;
    if (w < 8 || h < 8) return;

    RECT cur{};
    GetWindowRect(g_wnd, &cur);
    if (cur.left != tl.x || cur.top != tl.y ||
        cur.right - cur.left != w || cur.bottom - cur.top != h)
        SetWindowPos(g_wnd, HWND_TOPMOST, tl.x, tl.y, w, h,
            SWP_NOACTIVATE | SWP_SHOWWINDOW);

    if (w == g_w && h == g_h) return;
    g_w = w; g_h = h;

    if (g_sc) {
        if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; }
        g_sc->ResizeBuffers(0, static_cast<UINT>(w), static_cast<UINT>(h), DXGI_FORMAT_UNKNOWN, 0);
        make_rtv();
    }
}

inline void shutdown() {
    using namespace detail;
    if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; }
    if (g_vb) { g_vb->Release(); g_vb = nullptr; }
    if (g_cb) { g_cb->Release(); g_cb = nullptr; }
    if (g_il) { g_il->Release(); g_il = nullptr; }
    if (g_vs) { g_vs->Release(); g_vs = nullptr; }
    if (g_ps) { g_ps->Release(); g_ps = nullptr; }
    if (g_bl) { g_bl->Release(); g_bl = nullptr; }
    if (g_rs) { g_rs->Release(); g_rs = nullptr; }
    if (g_ds) { g_ds->Release(); g_ds = nullptr; }
    if (g_sc) { g_sc->Release(); g_sc = nullptr; }
    if (g_ctx) { g_ctx->Release(); g_ctx = nullptr; }
    if (g_dev) { g_dev->Release(); g_dev = nullptr; }
    if (g_wnd) { DestroyWindow(g_wnd); g_wnd = nullptr; }
    g_w = g_h = 0;
}

inline bool pump() {
    using namespace detail;
    MSG m{};
    while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return g_wnd && IsWindow(g_game) && IsWindow(g_wnd);
}

inline void tick() { tick_impl(); }
inline void begin() { detail::g_n = 0; }

inline void end() {
    using namespace detail;
    if (!g_ctx || g_w < 1 || g_h < 1) {
        if (g_sc) g_sc->Present(0, 0);
        return;
    }
    const float clear[4]{ 0.f, 0.f, 0.f, 0.f };
    g_ctx->ClearRenderTargetView(g_rtv, clear);

    if (g_n && g_rtv) {
        D3D11_MAPPED_SUBRESOURCE m{};
        if (g_ctx->Map(g_vb, 0, D3D11_MAP_WRITE_DISCARD, 0, &m) >= 0) {
            memcpy(m.pData, g_stage, sizeof(Vert) * static_cast<size_t>(g_n));
            g_ctx->Unmap(g_vb, 0);

            float sz[4]{ static_cast<float>(g_w), static_cast<float>(g_h), 0.f, 0.f };
            g_ctx->UpdateSubresource(g_cb, 0, nullptr, sz, 0, 0);

            UINT stride = sizeof(Vert), offset = 0;
            g_ctx->IASetVertexBuffers(0, 1, &g_vb, &stride, &offset);
            g_ctx->IASetInputLayout(g_il);
            g_ctx->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
            g_ctx->VSSetShader(g_vs, nullptr, 0);
            g_ctx->VSSetConstantBuffers(0, 1, &g_cb);
            g_ctx->PSSetShader(g_ps, nullptr, 0);
            g_ctx->OMSetRenderTargets(1, &g_rtv, nullptr);
            g_ctx->OMSetBlendState(g_bl, nullptr, 0xFFFFFFFF);
            g_ctx->OMSetDepthStencilState(g_ds, 0);
            g_ctx->RSSetState(g_rs);

            D3D11_VIEWPORT vp{ 0.f, 0.f, static_cast<float>(g_w), static_cast<float>(g_h), 0.f, 1.f };
            g_ctx->RSSetViewports(1, &vp);
            g_ctx->Draw(static_cast<UINT>(g_n), 0);
            g_ctx->OMSetRenderTargets(0, nullptr, nullptr);
        }
    }
    g_sc->Present(0, 0);
}

inline void fill(float l, float t, float r, float b, Color c) { detail::quad(l, t, r, b, c); }

inline void box(float l, float t, float r, float b, Color c, float th = 1.0f) {
    detail::quad(l, t, r, t + th, c);
    detail::quad(l, b - th, r, b, c);
    detail::quad(l, t, l + th, b, c);
    detail::quad(r - th, t, r, b, c);
}

inline void line(float x0, float y0, float x1, float y1, float th, Color c) {
    const float dx = x1 - x0, dy = y1 - y0;
    const float len = sqrtf(dx * dx + dy * dy);
    if (len < 0.01f) return;
    const float nx = -dy / len * th * 0.5f, ny = dx / len * th * 0.5f;
    detail::push(x0 + nx, y0 + ny, c); detail::push(x1 + nx, y1 + ny, c);
    detail::push(x1 - nx, y1 - ny, c);
    detail::push(x0 + nx, y0 + ny, c); detail::push(x1 - nx, y1 - ny, c);
    detail::push(x0 - nx, y0 - ny, c);
}

inline void text(float x, float y, const wchar_t* s, Color c, float sc = 1.0f) {
    for (; *s; ++s) {
        const int gi = font::index(*s);
        for (int row = 0; row < 7; ++row) {
            const uint8_t bits = font::kGlyphs[gi][row];
            for (int col = 0; col < 5; ++col)
                if (bits & (1 << (4 - col)))
                    detail::quad(x + col * sc, y + row * sc,
                                 x + (col + 1) * sc, y + (row + 1) * sc, c);
        }
        x += 6 * sc;
    }
}

inline float textw(const wchar_t* s, float sc = 1.0f) {
    return static_cast<float>(wcslen(s)) * 6.f * sc;
}

inline void tick_impl();

inline bool init(HWND game);
inline void shutdown();
inline bool pump();
inline void tick();
inline void begin();
inline void end();
inline void fill(float l, float t, float r, float b, Color c);
inline void box(float l, float t, float r, float b, Color c);
inline void line(float x0, float y0, float x1, float y1, float th, Color c);
inline void text(float x, float y, const wchar_t* s, Color c, float sc);
inline float textw(const wchar_t* s, float sc);
inline int width() { return detail::g_w; }
inline int height() { return detail::g_h; }
inline int pending() { return detail::g_n; }

} // namespace ov
