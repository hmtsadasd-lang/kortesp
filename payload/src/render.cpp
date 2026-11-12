#include "render.hpp"
#include "font.hpp"
#include "log.hpp"
#include "../../shared/include/syscall.hpp"
#include "../../shared/include/mem.hpp"
#include "../../shared/include/ntapi.hpp"
#include <d3d11.h>
#include <dxgi1_2.h>
#include <d3dcompiler.h>

namespace render { bool enabled = true; }

// Bridge defined in game.cpp
extern void esp_draw();

namespace {

using PresentFn = HRESULT(__stdcall*)(IDXGISwapChain*, UINT, UINT);
using CompileFn = HRESULT(__stdcall*)(const void*, size_t, const char*, const void*,
                                      const void*, const char*, const char*, uint32_t,
                                      uint32_t, void**, void**);

PresentFn g_orig{};
void**    g_shared_vt{};
void**    g_clone{};
bool      g_restored{};

ID3D11Device*            g_dev{};
ID3D11DeviceContext*     g_ctx{};
IDXGISwapChain*          g_swap{};
ID3D11RenderTargetView*  g_rtv{};
ID3D11VertexShader*      g_vs{};
ID3D11PixelShader*       g_ps{};
ID3D11InputLayout*       g_il{};
ID3D11Buffer*            g_cb{};
ID3D11Buffer*            g_vb{};
ID3D11BlendState*        g_blend{};
ID3D11RasterizerState*   g_rast{};
ID3D11DepthStencilState* g_dss{};
int g_w{}, g_h{};

struct Vert { float x, y, r, g, b, a; };
constexpr int kMaxVerts = 65536;
Vert g_stage[kMaxVerts];
int  g_count{};

const char* kSrc =
    "cbuffer C:register(b0){float2 sz;float2 p;};"
    "struct I{float2 p:POS;float4 c:COL;};"
    "struct O{float4 p:SV_POSITION;float4 c:COL;};"
    "O vs(I i){O o;o.p=float4(i.p.x/sz.x*2-1,1-i.p.y/sz.y*2,0,1);o.c=i.c;return o;}"
    "float4 ps(O i):SV_TARGET{return i.c;}";

bool compile() {
    void* lib = ntapi::LoadLibraryW_(L"d3dcompiler_47.dll");
    if (!lib) { log::w(L"d3dcompiler missing"); return false; }

    auto fn = reinterpret_cast<CompileFn>(ntapi::GetProcAddress_(lib, "D3DCompile"));
    if (!fn) return false;

    ID3DBlob* vs = nullptr;
    ID3DBlob* ps = nullptr;
    ID3DBlob* err = nullptr;

    if (fn(kSrc, strlen_(kSrc), "s", nullptr, nullptr, "vs", "vs_5_0",
           static_cast<uint32_t>(D3DCOMPILE_OPTIMIZATION_LEVEL3), 0,
           reinterpret_cast<void**>(&vs), reinterpret_cast<void**>(&err)) < 0) {
        log::w(L"vs compile failed"); return false;
    }
    if (fn(kSrc, strlen_(kSrc), "s", nullptr, nullptr, "ps", "ps_5_0",
           static_cast<uint32_t>(D3DCOMPILE_OPTIMIZATION_LEVEL3), 0,
           reinterpret_cast<void**>(&ps), reinterpret_cast<void**>(&err)) < 0) {
        log::w(L"ps compile failed"); return false;
    }

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
    bl.RenderTarget[0].SrcBlend = D3D11_BLEND_SRC_ALPHA;
    bl.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
    bl.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
    bl.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
    bl.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_INV_SRC_ALPHA;
    bl.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
    bl.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    if (g_dev->CreateBlendState(&bl, &g_blend) < 0) return false;

    D3D11_RASTERIZER_DESC rd{};
    rd.FillMode = D3D11_FILL_SOLID;
    rd.CullMode = D3D11_CULL_NONE;
    rd.DepthClipEnable = TRUE;
    if (g_dev->CreateRasterizerState(&rd, &g_rast) < 0) return false;

    D3D11_DEPTH_STENCIL_DESC ds{};
    ds.DepthEnable = FALSE;
    ds.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;
    if (g_dev->CreateDepthStencilState(&ds, &g_dss) < 0) return false;

    return true;
}

bool make_targets(IDXGISwapChain* s) {
    DXGI_SWAP_CHAIN_DESC d{};
    if (s->GetDesc(&d) < 0) return false;
    g_w = static_cast<int>(d.BufferDesc.Width);
    g_h = static_cast<int>(d.BufferDesc.Height);

    ID3D11Texture2D* buf = nullptr;
    if (s->GetBuffer(0, __uuidof(ID3D11Texture2D), reinterpret_cast<void**>(&buf)) < 0) return false;

    HRESULT hr = g_dev->CreateRenderTargetView(buf, nullptr, &g_rtv);
    buf->Release();
    return hr >= 0;
}

HRESULT __stdcall present_hook(IDXGISwapChain* s, UINT sync, UINT flags) {
    if (!g_restored) {
        *reinterpret_cast<void***>(s) = g_clone;
        sys::protect(g_shared_vt, 8 * 32, PAGE_RW_);
        g_shared_vt[8] = reinterpret_cast<void*>(g_orig);
        sys::protect(g_shared_vt, 8 * 32, PAGE_RX_);
        g_restored = true;
    }

    if (!g_dev && s->GetDevice(__uuidof(ID3D11Device), reinterpret_cast<void**>(&g_dev)) >= 0) {
        g_dev->GetImmediateContext(&g_ctx);
        if (make_targets(s) && compile()) { g_swap = s; log::w(L"pipeline live"); }
        else render::shutdown();
    }

    if (g_swap == s && render::enabled && g_rtv) {
        render::begin();
        esp_draw();
        render::end();
    }

    return g_orig(s, sync, flags);
}

void push(float x, float y, render::Color c) {
    if (g_count >= kMaxVerts) return;
    g_stage[g_count++] = { x, y, c.r, c.g, c.b, c.a };
}

void quad(float l, float t, float r, float b, render::Color c) {
    push(l, t, c); push(r, t, c); push(r, b, c);
    push(l, t, c); push(r, b, c); push(l, b, c);
}

} // namespace

bool render::init() {
    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc = reinterpret_cast<WNDPROC>(&ntapi::DefWindowProcW_);
    wc.lpszClassName = L"fortesp_dummy";
    if (!ntapi::RegisterClassExW_(&wc)) { log::w(L"class failed"); return false; }

    void* w = ntapi::CreateWindowExW_(0, L"fortesp_dummy", L"", WS_POPUP,
                                      0, 0, 8, 8, nullptr, nullptr, nullptr, nullptr);
    if (!w) { log::w(L"window failed"); return false; }

    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferDesc.Width = 8;
    sd.BufferDesc.Height = 8;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.SampleDesc.Count = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount = 2;
    sd.OutputWindow = static_cast<HWND>(w);
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    void* lib = ntapi::LoadLibraryW_(L"d3d11.dll");
    if (!lib) return false;

    using CreateFn = HRESULT(__stdcall*)(IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT,
                                         const D3D_FEATURE_LEVEL*, UINT, UINT,
                                         const DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**,
                                         ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
    auto create = reinterpret_cast<CreateFn>(ntapi::GetProcAddress_(lib, "D3D11CreateDeviceAndSwapChain"));
    if (!create) return false;

    IDXGISwapChain* tmp = nullptr;
    ID3D11Device* d = nullptr;
    ID3D11DeviceContext* c = nullptr;
    D3D_FEATURE_LEVEL fl{};

    if (create(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0, D3D11_SDK_VERSION,
               &sd, &tmp, &d, &fl, &c) < 0) { log::w(L"dummy swapchain failed"); return false; }

    g_shared_vt = *reinterpret_cast<void***>(tmp);
    g_orig = reinterpret_cast<PresentFn>(g_shared_vt[8]);

    if (!NT_SUCCESS(sys::alloc(reinterpret_cast<void**>(&g_clone), 8 * 32, PAGE_RW_))) return false;
    memcpy(g_clone, g_shared_vt, 8 * 32);
    g_clone[8] = reinterpret_cast<void*>(&present_hook);
    sys::protect(g_clone, 8 * 32, PAGE_RX_);

    sys::protect(g_shared_vt, 8 * 32, PAGE_RW_);
    g_shared_vt[8] = reinterpret_cast<void*>(&present_hook);
    sys::protect(g_shared_vt, 8 * 32, PAGE_RX_);

    c->Release();
    d->Release();
    tmp->Release();
    ntapi::DestroyWindow_(w);
    log::w(L"hook armed");
    return true;
}

void render::shutdown() {
    ID3D11DeviceChild* list[] = {
        reinterpret_cast<ID3D11DeviceChild*>(g_rtv),
        reinterpret_cast<ID3D11DeviceChild*>(g_vb),
        reinterpret_cast<ID3D11DeviceChild*>(g_cb),
        reinterpret_cast<ID3D11DeviceChild*>(g_il),
        reinterpret_cast<ID3D11DeviceChild*>(g_vs),
        reinterpret_cast<ID3D11DeviceChild*>(g_ps),
        reinterpret_cast<ID3D11DeviceChild*>(g_blend),
        reinterpret_cast<ID3D11DeviceChild*>(g_rast),
        reinterpret_cast<ID3D11DeviceChild*>(g_dss),
    };
    for (auto* o : list) if (o) o->Release();
    g_rtv = nullptr; g_vb = nullptr; g_cb = nullptr; g_il = nullptr;
    g_vs = nullptr; g_ps = nullptr; g_blend = nullptr; g_rast = nullptr; g_dss = nullptr;

    if (g_ctx) { g_ctx->Release(); g_ctx = nullptr; }
    if (g_dev) { g_dev->Release(); g_dev = nullptr; }
    g_swap = nullptr;
}

void render::begin() {
    g_count = 0;
    float clear[4]{};
    g_ctx->ClearRenderTargetView(g_rtv, clear);
}

void render::end() {
    if (!g_count) return;

    D3D11_MAPPED_SUBRESOURCE m{};
    if (g_ctx->Map(g_vb, 0, D3D11_MAP_WRITE_DISCARD, 0, &m) < 0) return;
    memcpy(m.pData, g_stage, sizeof(Vert) * g_count);
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
    g_ctx->OMSetBlendState(g_blend, nullptr, 0xFFFFFFFF);
    g_ctx->OMSetDepthStencilState(g_dss, 0);
    g_ctx->RSSetState(g_rast);

    D3D11_VIEWPORT vp{ 0, 0, static_cast<float>(g_w), static_cast<float>(g_h), 0, 1 };
    g_ctx->RSSetViewports(1, &vp);
    g_ctx->Draw(g_count, 0);

    g_ctx->OMSetRenderTargets(0, nullptr, nullptr);
}

void render::rect(float l, float t, float r, float b, render::Color c) { quad(l, t, r, b, c); }

void render::line(float x0, float y0, float x1, float y1, float th, render::Color c) {
    float dx = x1 - x0, dy = y1 - y0;
    float len = sqrtf_(dx * dx + dy * dy);
    if (len < 0.01f) return;
    float nx = -dy / len * th * 0.5f, ny = dx / len * th * 0.5f;
    push(x0 + nx, y0 + ny, c); push(x1 + nx, y1 + ny, c); push(x1 - nx, y1 - ny, c);
    push(x0 + nx, y0 + ny, c); push(x1 - nx, y1 - ny, c); push(x0 - nx, y0 - ny, c);
}

void render::text(float x, float y, const wchar_t* s, render::Color c, float sc) {
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

float render::text_width(const wchar_t* s, float sc) { return wcslen_(s) * 6.f * sc; }

int render::width() { return g_w; }
int render::height() { return g_h; }