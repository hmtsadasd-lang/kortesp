#pragma once
#include <cstdint>

// Fortnite, dump hash 6b77eceb. Member offsets are from that dump; INFER marks the two values to verify with a watch before trusting.
namespace off {

constexpr uintptr_t GEngine  = 0x1C9DC1D8;   // OFFSET_GENGINE
constexpr uintptr_t GObjects = 0x1C966F18;   // OFFSET_GOBJECTS
// OFFSET_GWORLD is 0x0 in this dump -> world comes from GEngine.

constexpr uintptr_t Engine_GameViewportClient = 0xC0;
constexpr uintptr_t Viewport_World            = 0x78;

constexpr uintptr_t World_GameState          = 0x1C0;
constexpr uintptr_t World_OwningGameInstance = 0x238;

constexpr uintptr_t GameInstance_LocalPlayers      = 0x38;
constexpr uintptr_t Player_PlayerController        = 0x30;
constexpr uintptr_t Controller_PlayerState         = 0x280;
constexpr uintptr_t Controller_PlayerCameraManager = 0x330;

constexpr uintptr_t Camera_CameraCachePrivate = 0x15A0;
constexpr uintptr_t CacheEntry_POV            = 0x10;
constexpr uintptr_t POV_Location              = 0x00;   // FVector, 3x double
constexpr uintptr_t POV_Rotation              = 0x18;   // FRotator, 3x double
constexpr uintptr_t POV_FOV                   = 0x30;   // float, degrees

constexpr uintptr_t GameState_PlayerArray = 0x290;

constexpr uintptr_t State_Pawn  = 0x2F0;
constexpr uintptr_t State_Name  = 0x310;   // FString {wchar_t*; int len; int max;}
constexpr uintptr_t State_Flags = 0x282;   // bit1 spectator, bit3 bot, bit5 inactive
constexpr uintptr_t State_Team  = 0xF81;   // INFER - verify

constexpr uintptr_t Pawn_Mesh        = 0x2F8;
constexpr uintptr_t Pawn_Dying       = 0x738;   // bit 5
constexpr uintptr_t Pawn_HealthSet   = 0x1430;
constexpr uintptr_t Pawn_CapsuleHalf = 0x1E8C;  // float

constexpr uintptr_t Comp_C2W          = 0x100;  // INFER - gap before RelativeLocation
constexpr uintptr_t Xform_Translation = 0x10;

constexpr uintptr_t Health_Current = 0x48 + 0x4;
constexpr uintptr_t Health_Base    = 0x48;
constexpr uintptr_t Health_Max     = 0x70 + 0x4;

constexpr int kMaxPlayers = 128;

} // namespace off