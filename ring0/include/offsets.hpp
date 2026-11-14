#pragma once
#include <cstdint>

// Fortnite dump hash 6b77eceb. Every entry below is VERIFIED against the dump
// or marked UNVERIFIED (needs a watch or a re‑dump). No INFER remain.
namespace off {

// ---- absolute RVAs from the client's module base -------------------------
// Verified: these RVAs plus the client base give valid kernel addresses.
constexpr uintptr_t GEngine  = 0x1C9DC1D8;   // VERIFIED
constexpr uintptr_t GObjects = 0x1C966F18;   // VERIFIED
// OFFSET_GWORLD is 0x0 in this dump -> world comes from GEngine lookup.

// ---- UEngine -> world ---------------------------------------------------
constexpr uintptr_t Engine_GameViewportClient = 0xC0;   // VERIFIED
constexpr uintptr_t Viewport_World            = 0x78;   // VERIFIED

// ---- UWorld -------------------------------------------------------------
constexpr uintptr_t World_GameState        = 0x1C0;   // VERIFIED
constexpr uintptr_t World_OwningGameInstance = 0x238;   // VERIFIED

// ---- UGameInstance / Uplayer / AController ------------------------------
constexpr uintptr_t GameInstance_LocalPlayers = 0x38;   // VERIFIED
constexpr uintptr_t Player_PlayerController   = 0x30;   // VERIFIED
constexpr uintptr_t Controller_PlayerState    = 0x280;  // VERIFIED
// Controller_PlayerCameraManager at 0x2C8 is UNVERIFIED (verify with watch);
constexpr uintptr_t Controller_PlayerCameraManager = 0x2C8;

// ---- camera chain -------------------------------------------------------
// All offsets below are from the camera object returned by the chain above.
// Verified: POV_Location, POV_Rotation, POV_FOV are float[3/4].
constexpr uintptr_t Camera_CameraCachePrivate = 0x15A0;   // VERIFIED
constexpr uintptr_t CacheEntry_POV            = 0x10;    // VERIFIED
// POV_Location is float[3] stored as double[3] in our code.
constexpr uintptr_t POV_Location              = 0x00;    // VERIFIED (float[3] -> double[3])
constexpr uintptr_t POV_Rotation              = 0x18;    // VERIFIED (float[3] -> double[3])
constexpr uintptr_t POV_FOV                   = 0x30;    // VERIFIED (float, degrees)

// ---- AGameStateBase -----------------------------------------------------
constexpr uintptr_t GameState_PlayerArray = 0x290;   // VERIFIED

// ---- APlayerState -------------------------------------------------------
constexpr uintptr_t State_Pawn      = 0x2F0;   // VERIFIED
constexpr uintptr_t State_Name      = 0x310;   // FString {wchar_t*; int len; int max;}
// State_Flags at 0x2F8 is UNVERIFIED; verify with watch before trusting bots filter.
constexpr uintptr_t State_Flags     = 0x2F8;   // UNVERIFIED - bit3 bIsABot, bit1 bIsSpectator, bit5 bIsInactive
// State_Team at 0xF81 is UNVERIFIED; verify with watch.
constexpr uintptr_t State_Team      = 0xF81;   // UNVERIFIED - AFortPlayerStateAthena::TeamIndex

// ---- ACharacter / AFortPawn --------------------------------------------
constexpr uintptr_t Pawn_Mesh        = 0x2F8;   // VERIFIED - USkeletalMeshComponent*
constexpr uintptr_t Pawn_Dying       = 0x738;   // VERIFIED - bit 5 = bIsDying
constexpr uintptr_t Pawn_HealthSet   = 0x1430;  // VERIFIED - UFortHealthSet*
constexpr uintptr_t Pawn_CapsuleHalf = 0x1E8C;  // VERIFIED - float

// ---- USceneComponent ----------------------------------------------------
constexpr uintptr_t Comp_C2W         = 0x100;   // VERIFIED - FTransform, sits in the 0x100..0x140 gap
// ComponentTransform (RelativeTransform) is at 0x0; Comp_C2W + 0x10 gives Translation.
constexpr uintptr_t Xform_Translation = 0x10;   // VERIFIED - FTransform.Translation (3x double)

// ---- UFortHealthSet (FFortGameplayAttributeData) ------------------------
constexpr uintptr_t Health_Current = 0x48 + 0x4;  // VERIFIED - CurrentValue
constexpr uintptr_t Health_Base    = 0x48;        // VERIFIED - BaseValue (fallback)
constexpr uintptr_t Health_Max     = 0x70 + 0x4;  // VERIFIED

constexpr int kMaxPlayers = 128;

} // namespace off