#pragma once
#include <cstdint>

// Fortnite, UE5 LWC. FVector is FVector3d, FRotator is FRotator3d, FQuat is
// FQuat4d (32 bytes) - 24/24/32, not 12/12/16. Reading float[3] returns the
// low mantissa halves of the doubles.
//
// VERIFIED  = confirmed against a dump or a live run.
// UNVERIFIED = needs a watch before it is trusted.
namespace off {

// ---- absolute RVAs from the client module base --------------------------
constexpr uintptr_t GEngine  = 0x1C9DC1D8;   // VERIFIED
constexpr uintptr_t GObjects = 0x1C966F18;   // VERIFIED

// ---- UEngine -> world ---------------------------------------------------
constexpr uintptr_t Engine_GameViewportClient = 0xC0;   // VERIFIED
constexpr uintptr_t Viewport_World            = 0x78;   // VERIFIED

// ---- UWorld -------------------------------------------------------------
constexpr uintptr_t World_GameState          = 0x1C0;   // VERIFIED
constexpr uintptr_t World_OwningGameInstance = 0x238;   // VERIFIED
constexpr uintptr_t World_PersistentLevel    = 0x100;   // UNVERIFIED - actors path
constexpr uintptr_t Level_Actors             = 0xA0;    // UNVERIFIED - TArray<AActor*>

// ---- UGameInstance / ULocalPlayer / APlayerController -------------------
constexpr uintptr_t GameInstance_LocalPlayers = 0x38;   // VERIFIED
constexpr uintptr_t Player_PlayerController   = 0x30;   // VERIFIED
constexpr uintptr_t Controller_PlayerState    = 0x280;  // VERIFIED
constexpr uintptr_t Controller_PlayerCameraManager = 0x2C8;  // UNVERIFIED

// ---- camera chain -------------------------------------------------------
constexpr uintptr_t Camera_CameraCachePrivate = 0x15A0;   // VERIFIED
constexpr uintptr_t CacheEntry_POV            = 0x10;     // VERIFIED
// POV = { FVector3d Location; FRotator3d Rotation; double FOV; }
constexpr uintptr_t POV_Location = 0x00;   // VERIFIED (3x double)
constexpr uintptr_t POV_Rotation = 0x18;   // VERIFIED (3x double)
constexpr uintptr_t POV_FOV      = 0x30;   // VERIFIED (double, degrees)

// ---- AGameStateBase -----------------------------------------------------
constexpr uintptr_t GameState_PlayerArray = 0x290;   // VERIFIED

// ---- APlayerState -------------------------------------------------------
constexpr uintptr_t State_Pawn  = 0x2F0;   // VERIFIED
constexpr uintptr_t State_Name  = 0x310;   // VERIFIED - FString
constexpr uintptr_t State_Flags = 0x2F8;   // UNVERIFIED - bit3 bot, bit1 spec, bit5 inactive
constexpr uintptr_t State_Team  = 0xF81;   // UNVERIFIED - uint8, not 4-aligned

// ---- APawn / ACharacter -------------------------------------------------
constexpr uintptr_t Pawn_PlayerState = 0x2C8;   // UNVERIFIED
constexpr uintptr_t Pawn_Mesh        = 0x2F8;   // VERIFIED - USkeletalMeshComponent*
constexpr uintptr_t Pawn_Dying       = 0x738;   // VERIFIED - bit 5 bIsDying
constexpr uintptr_t Pawn_HealthSet   = 0x1430;  // VERIFIED - UFortHealthSet*
constexpr uintptr_t Pawn_CapsuleHalf = 0x1E8C;  // VERIFIED - float

// ---- AActor / USceneComponent ------------------------------------------
constexpr uintptr_t Actor_RootComponent = 0x1B8;   // UNVERIFIED
constexpr uintptr_t Comp_RelativeLoc    = 0x128;   // UNVERIFIED
constexpr uintptr_t Comp_C2W            = 0x100;   // VERIFIED - FTransform
// FTransform = { FQuat4d 32; FVector3d 24; FVector3d 24 } = 0x50
constexpr uintptr_t Xform_Translation = 0x20;   // VERIFIED
constexpr uintptr_t Xform_Stride      = 0x50;   // VERIFIED

// ---- USkeletalMeshComponent bone array ---------------------------------
constexpr uintptr_t Mesh_BoneArray = 0x5C8;   // UNVERIFIED - FTransform array*

// ---- UFortHealthSet -----------------------------------------------------
constexpr uintptr_t Health_Current = 0x48 + 0x4;   // VERIFIED float
constexpr uintptr_t Health_Base    = 0x48;         // VERIFIED float
constexpr uintptr_t Health_Max     = 0x70 + 0x4;   // VERIFIED float

// ---- UObject ------------------------------------------------------------
constexpr uintptr_t Obj_Class = 0x10;   // UNVERIFIED - UClass*
constexpr uintptr_t Class_Name = 0x18;  // UNVERIFIED - FName (NamePrivate, not ClassPrivate at 0x10)

// ---- bones (SK_Male / SK_Female) ---------------------------------------
// Per-skeleton; verify each before trusting the skeleton overlay.
constexpr int Bone_Pelvis    = 2;    // UNVERIFIED
constexpr int Bone_Chest     = 5;    // UNVERIFIED
constexpr int Bone_LShoulder = 8;    // UNVERIFIED
constexpr int Bone_LElbow    = 9;    // UNVERIFIED
constexpr int Bone_LHand     = 10;   // UNVERIFIED
constexpr int Bone_RShoulder = 38;   // UNVERIFIED
constexpr int Bone_RElbow    = 39;   // UNVERIFIED
constexpr int Bone_RHand     = 40;   // UNVERIFIED
constexpr int Bone_Neck      = 66;   // UNVERIFIED
constexpr int Bone_LThigh    = 71;   // UNVERIFIED
constexpr int Bone_LKnee     = 72;   // UNVERIFIED
constexpr int Bone_LFoot     = 75;   // UNVERIFIED
constexpr int Bone_RThigh    = 78;   // UNVERIFIED
constexpr int Bone_RKnee     = 79;   // UNVERIFIED
constexpr int Bone_RFoot     = 82;   // UNVERIFIED
constexpr int Bone_Head      = 110;  // UNVERIFIED

// ---- EPROCESS, 26200. Mirror of vmm.cpp kCand[0]; documentation only ----
constexpr uintptr_t Eproc_Pid   = 0x1D0;   // VERIFIED
constexpr uintptr_t Eproc_Links = 0x1D8;   // VERIFIED
constexpr uintptr_t Eproc_Name  = 0x338;   // VERIFIED - char[15]
constexpr uintptr_t Eproc_Dtb   = 0x28;    // VERIFIED
constexpr uintptr_t Eproc_Peb   = 0x2E0;   // VERIFIED
constexpr uintptr_t Eproc_Token = 0x248;   // UNVERIFIED, unused (read-only)

// ---- PEB / LDR ---------------------------------------------------------
constexpr uintptr_t Peb_Ldr  = 0x18;   // VERIFIED - PEB_LDR_DATA*
constexpr uintptr_t Peb_Params = 0x20; // VERIFIED - RTL_USER_PROCESS_PARAMETERS*
constexpr uintptr_t Ldr_InLoadOrder = 0x10;   // VERIFIED
constexpr uintptr_t Ldr_DllBase     = 0x30;   // VERIFIED
constexpr uintptr_t Ldr_SizeOfImage = 0x40;   // VERIFIED
constexpr uintptr_t Ldr_BaseDllNameLen = 0x58;  // VERIFIED
constexpr uintptr_t Ldr_BaseDllNameBuf = 0x60;  // VERIFIED

constexpr int kMaxPlayers = 128;
constexpr int kMaxActors  = 4096;

} // namespace off