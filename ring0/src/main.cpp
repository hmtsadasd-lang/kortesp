#include "vmm.hpp"
#include "esp.hpp"
#include "ov.hpp"
#include "r0.hpp"
#include <windows.h>
#include <cstdio>

namespace { constexpr wchar_t kImage[]=L"FortniteClient-Win64-Shipping.exe"; bool down(int vk){return(GetAsyncState(vk)&0x8000)!=0;} struct Toggle{int vk;bool*flag;boollast;}; }

int wmain(){ if(!r0::init()){printf("driver missing - run run_r0.bat as admin\n");return 1;}printf("driver ok; scanning\n"); if(!vmm::init()){printf("kernel discovery failed\n");return 1;}HWND game=nullptr;for(inti=0;i<240&&!game;++i){game=FindWindowW(L"UnrealWindow",nullptr);Sleep(500);}if(!game){printf("no UnrealWindow\n");return 1;}if(!vmm::attach(kImage)){printf("process not found\n");return 1;}printf("attached pid %u\n",vmm::pid());if(!ov::init(game)){printf("overlay failed\n");return 1;}if(!esp::init())printf("waiting for a match\n");staticULONGLAST_try{};Toggle t[]={{VK_F1,&esp::cfg.on,true},{VK_F2,&esp::cfg.boxes,true},{VK_F3,&esp::cfg.names,true},{VK_F4,&esp::cfg.health,true},{VK_F5,&esp::cfg.dist,true},{VK_F6,&esp::cfg.lines,true},{VK_F7,&esp::cfg.team_colors,true},{VK_F8,&esp::cfg.bots,false}};for(;;){if(!ov::pump())break;for(auto&x:t){boold=down(x.vk);if(d&&!x.last)*x.flag=!*x.flag;x.last=d;}if(down(VK_END))break;if(!esp::ready()&&GetTickCount64()-last_try>1000){last_try=GetTickCount64();esp::init();}ov::tick();ov::begin();esp::draw();ov::end();Sleep(1);}esp::shutdown();ov::shutdown();vmm::shutdown();return0; }