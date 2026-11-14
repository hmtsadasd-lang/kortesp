#include "ov.hpp"
#include "../../payload/include/font.hpp"
#include <d3d11.h>
#include <dxgi1_2.h>
#include <d3dcompiler.h>
#include <cwchar>
#include <cmath>

namespace { constexpr wchar_t kClass[] = L"fortesp_r0_overlay"; }

HWND g_wnd{}; HWND g_game{}; ID3D11Device* g_dev{}; ID3D11DeviceContext* g_ctx{}; IDXGISwapChain* g_sc{}; ID3D11RenderTargetView* g_rtv{}; ID3D11VertexShader* g_vs{}; ID3D11PixelShader* g_ps{}; ID3D11InputLayout* g_il{}; ID3D11Buffer* g_vb{}; ID3D11Buffer* g_cb{}; ID3D11BlendState* g_bl{}; ID3D11RasterizerState* g_rs{}; ID3D11DepthStencilState* g_ds{}; int g_w{}, g_h{}; struct Vert { float x, y, r, g, b, a; }; constexpr int kMax = 1 << 16; Vert g_stage[kMax]{}; int g_n{}; const char* kSrc =
    "cbuffer C:register(b0){float2 sz;};"
    "struct I{float2 p:POS;float4 c:COL;};"
    "struct O{float4 p:SV_POSITION;float4 c:COL;};"
    "O vs(I i){O o;o.p=float4(i.p.x/sz.x*2-1,1-i.p.y/sz.y*2,0,1);o.c=i.c;return o;}"
    "float4 ps(O i):SV_TARGET{return i.c;}";

LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}

using CompileFn = HRESULT(__stdcall*)(const void*, SIZE_T, const char*, const void*, const void*, const char*, const char*, UINT, UINT, ID3DBlob**, ID3DBlob**);

bool build_pipeline() {
    HMODULE c = LoadLibraryW(L"d3dcompiler_47.dll");
    if (!c) return false;
    auto fn = reinterpret_cast<CompileFn>(GetProcAddress(c, "D3DCompile"));
    if (!fn) return false;

    ID3DBlob* vs{}; ID3DBlob* ps{}; ID3DBlob* err{};
    const SIZE_T len = strlen(kSrc);
    if (fn(kSrc, len, "o", nullptr, nullptr, "vs", "vs_5_0", 0, 0, &vs, &err) < 0) return false;
    if (fn(kSrc, len, "o", nullptr, nullptr, "ps", "ps_5_0", 0, 0, &ps, &err) < 0) return false;

    if (g_dev->CreateVertexShader(vs->GetBufferPointer(), vs->GetBufferSize(), nullptr, &g_vs) < 0) return false;
    if (g_dev->CreatePixelShader(ps->GetBufferPointer(), ps->GetBufferSize(), nullptr, &g_ps) < 0) return false;

    D3D11_INPUT_ELEMENT_DESC ie[] = {
        { "POS", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "COL", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 8, D3D11_INPUT_PER_VERTEX_DATA, 0 },
    };
    if (g_dev->CreateInputLayout(ie, 2, vs->GetBufferPointer(), vs->GetBufferSize(), &g_il) < 0) return false;

    D3D11_BUFFER_DESC bd{};
    bd.ByteWidth = sizeof(Vert) * kMax;
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
    bl.RenderTarget[0].SrcBlend = D3D11_BLEND_SRC_ALPHA;
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

bool make_rtv() {
    ID3D11Texture2D* buf{};
    if (g_sc->GetBuffer(0, __uuidof(ID3D11Texture2D), reinterpret_cast<void**>(&buf)) < 0) return false;
    const HRESULT hr = g_dev->CreateRenderTargetView(buf, nullptr, &g_rtv);
    buf->Release();
    return hr >= 0;
}

void push(float x, float y, ov::Color c) {
    if (g_n >= kMax) return;
    g_stage[g_n++] = { x, y, c.r, c.g, c.b, c.a };
}

void quad(float l, float t, float r, float b, ov::Color c) {
    push(l, t, c); push(r, t, c); push(r, b, c);
    push(l, t, c); push(r, b, c); push(l, b, c);
} // namespace

namespace ov {

bool init(HWND game) {
    g_game = game;

    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc = proc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = kClass;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;

    g_wnd = CreateWindowExW(WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        kClass, L"", WS_POPUP, 0, 0, 8, 8,
        nullptr, nullptr, wc.hInstance, nullptr);
    if (!g_wnd) return false;

    SetLayeredWindowAttributes(g_wnd, 0, 255, LWA_ALPHA);
    ShowWindow(g_wnd, SW_SHOWNOACTIVATE);

    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 8;
    sd.BufferDesc.Height = 8;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = g_wnd;
    sd.SampleDesc.Count = 1;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    sd.Windowed = TRUE;

    const D3D_FEATURE_LEVEL want[] = { D3D_FEATURE_LEVEL_11_0 };
    D3D_FEATURE_LEVEL got{};
    if (D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT, want, 1, D3D11_SDK_VERSION,
        &sd, &g_sc, &g_dev, &got, &g_ctx) < 0) return false;

    if (!build_pipeline() || !make_rtv()) return false;
    tick();
    return true;
}

void shutdown() {
    if (g_rtv) g_rtv->Release();
    if (g_vb) g_vb->Release();
    if (g_cb) g_cb->Release();
    if (g_il) g_il->Release();
    if (g_vs) g_vs->Release();
    if (g_ps) g_ps->Release();
    if (g_bl) g_bl->Release();
    if (g_rs) g_rs->Release();
    if (g_ds) g_ds->Release();
    if (g_ctx) g_ctx->Release();
    if (g_dev) g_dev->Release();
    if (g_sc) g_sc->Release();
    if (g_wnd) DestroyWindow(g_wnd);
    g_rtv = nullptr; g_vb = nullptr; g_cb = nullptr; g_il = nullptr;
    g_vs = nullptr; g_ps = nullptr; g_bl = nullptr; g_rs = nullptr; g_ds = nullptr;
    g_ctx = nullptr; g_dev = nullptr; g_sc = nullptr; g_wnd = nullptr;
}

void tick() {
    if (!g_wnd || !IsWindow(g_game)) return;

    RECT r{};
    if (!GetClientRect(g_game, &r)) return;
    POINT tl{ 0, 0 };
    ClientToScreen(g_game, &tl);

    int w = r.right - r.left, h = r.bottom - r.top;
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
        g_sc->ResizeBuffers(0, static_cast<UINT>(w), static_cast<UINT>(h),
            DXGI_FORMAT_UNKNOWN, 0);
        make_rtv();
    }
}

bool pump() {
    MSG m{};
    while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return g_wnd && IsWindow(g_game) && IsWindow(g_wnd);
}

void begin() { g_n = 0; }

void end() {
    if (!g_ctx || !g_rtv) return;
    const float clear[4]{ 0.f, 0.f, 0.f, 0.f };
    g_ctx->ClearRenderTargetView(g_rtv, clear);

    if (g_n) {
        D3D11_MAPPED_SUBRESOURCE m{};
        if (g_ctx->Map(g_vb, 0, D3D11_MAP_WRITE_DISCARD, 0, &m) >= 0) {
            memcpy(m.pData, g_stage, sizeof(Vert) * g_n);
            g_ctx->Unmap(g_vb, 0);

            float sz[2]{ static_cast<float>(g_w), static_cast<float>(g_h) };
            g_ctx->UpdateSubresource(g_cb, 0, nullptr, sz, 0, 0);

            UINT stride = sizeof(Vert), off = 0;
            g_ctx->IASetVertexBuffers(0, 1, &g_vb, &stride, &off);
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

void fill(float l, float t, float r, float b, Color c) { quad(l, t, r, b, c); }

void box(float l, float t, float r, float b, Color c, float th) {
    quad(l, t, r, t + th, c);
    quad(l, b - th, r, b, c);
    quad(l, t, l + th, b, c);
    quad(r - th, t, r, b, c);
}

void line(float x0, float y0, float x1, float y1, float th, Color c) {
    float dx = x1 - x0, dy = y1 - y0;
    float len = sqrtf(dx * dx + dy * dy);
    if (len < 0.01f) return;
    float nx = -dy / len * th * 0.5f, ny = dx / len * th * 0.5f;
    push(x0 + nx, y0 + ny, c); push(x1 + nx, y1 + ny, c); push(x1 - nx, y1 - ny, c);
    push(x0 + nx, y0 + ny, c); push(x1 - nx, y1 - ny, c); push(x0 - nx, y0 - ny, c);
}

void text(float x, float y, const wchar_t* s, Color c, float sc) {
    for (; *s; ++s) {
        int gi = font::index(*s);
        for (int row = 0; row < 7; ++row) {
            uint8_t bits = font::kGlyphs[gi][row];
            for (int col = 0; col < 5; ++col)
                if (bits & (1 << (4 - col)))
                    quad(x + col * sc, y + row * sc, x + (col + 1) * sc, y + (row + 1) * sc, c);
        }
        x += 6 * sc;
    }
}

float textw(const wchar_t* s, float sc) { return static_cast<float>(wcslen(s)) * 6.f * sc; }
int width() { return g_w; }
int height() { return g_h; }

} // namespace