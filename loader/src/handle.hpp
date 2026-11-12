#pragma once
#include <windows.h>

DWORD  pid_by_name(const wchar_t* exe);
ULONG  granted_access(DWORD pid, HANDLE h);
HANDLE open_game(DWORD pid, DWORD need);
void   dump_game_handles(DWORD game_pid);