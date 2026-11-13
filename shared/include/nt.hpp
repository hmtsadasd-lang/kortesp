#pragma once
#include <windows.h>
#include <cstdint>
#include <cstddef>

using NTSTATUS_ = int32_t;
using UPTR = uintptr_t;

#define NT_SUCCESS(s) ((NTSTATUS_)(s) >= 0)

struct UNICODE_STRING_ { uint16_t Length, MaxLength; wchar_t* Buffer; };

// The 56 byte OBJECT_BASIC_INFORMATION every Windows since Vista returns for
// NtQueryObject(ObjectBasicInformation). The four-field version that older
// headers declare is refused with STATUS_INFO_LENGTH_MISMATCH, so
// GrantedAccess always read back as 0.
struct OBJECT_BASIC_INFORMATION_ {
    ULONG       Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG       HandleCount;
    ULONG       PointerCount;
    ULONG       PagedPoolUsage;
    ULONG       NonPagedPoolUsage;
    ULONG       Reserved[3];
    ULONG       NameInformationLength;
    ULONG       TypeInformationLength;
    ULONG       SecurityDescriptorLength;
    LARGE_INTEGER CreateTime;
};
static_assert(sizeof(OBJECT_BASIC_INFORMATION_) == 56, "OBJECT_BASIC_INFORMATION is 56 bytes");

// A WOW64 (32 bit) thread context, as Wow64GetThreadContext and
// NtGetContextThread on a WOW64 thread take it. Layout is fixed by the
// kernel, the float area is 112 bytes and the extended area 512.
struct WOW64_CONTEXT_ {
    uint32_t ContextFlags;
    uint32_t Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    uint8_t  FloatSave[112];
    uint32_t SegGs, SegFs, SegEs, SegDs;
    uint32_t Edi, Esi, Ebx, Edx, Ecx, Eax;
    uint32_t Ebp, Eip, SegCs, EFlags, Esp, SegSs;
    uint8_t  ExtendedRegisters[512];
};
static_assert(sizeof(WOW64_CONTEXT_) == 0x2CC, "WOW64_CONTEXT is 716 bytes");
static_assert(offsetof(WOW64_CONTEXT_, Eip) == 0xB8, "Eip at 0xB8");
static_assert(offsetof(WOW64_CONTEXT_, Esp) == 0xC4, "Esp at 0xC4");

constexpr uint32_t WOW64_CONTEXT_i386_    = 0x00010000;
constexpr uint32_t WOW64_CONTEXT_CONTROL_ = WOW64_CONTEXT_i386_ | 0x1;

struct CLIENT_ID_ { UPTR UniqueProcess, UniqueThread; };

struct OBJECT_ATTRIBUTES_ {
    ULONG       Length;
    HANDLE      RootDirectory;
    UNICODE_STRING_* ObjectName;
    ULONG       Attributes;
    PVOID       SecurityDescriptor;
    PVOID       SecurityQualityOfService;
};

// STATUS_SUCCESS is not declared by every toolchain's headers.
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS_)0)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS_)0xC0000022)
#endif

struct LDR_DATA_TABLE_ENTRY_ {
    void*    InLoadOrderLinks[2];
    void*    InMemoryOrderLinks[2];
    void*    InInitOrderLinks[2];
    void*    DllBase;
    void*    EntryPoint;
    uint32_t SizeOfImage;
    // Flags (uint32) sits here in the real entry: dropping it shifted
    // FullDllName/BaseDllName by 4 and the name hashes compared fragments of a
    // path against a module name. That is why every hash lookup missed while
    // the raw list walk worked.
    uint32_t Flags;
    UNICODE_STRING_ FullDllName;
    UNICODE_STRING_ BaseDllName;
};

// layout checked against winternl.h by hand: without an explicit pad the
// void* after a uint32_t is 4-byte aligned, the whole struct shifts by 4, and
// every list head read through it lands on the wrong field. That misread is
// what made every module walk in a mapped image miss, and the null base it
// returned was then called (`call *%r11` with r11 = 0) - the 0xC0000005.
struct PEB_LDR_DATA_ {
    uint32_t Length;
    uint8_t  Initialized;
    uint8_t  pad_low[3];
    void*    SsHandle;
    void*    InLoadOrderModuleList[2];
    void*    InMemoryOrderModuleList[2];
    void*    InInitOrderModuleList[2];
};

static_assert(sizeof(PEB_LDR_DATA_) == 0x40, "PEB_LDR_DATA_ layout");
static_assert(sizeof(LDR_DATA_TABLE_ENTRY_) == 0x68, "LDR_DATA_TABLE_ENTRY_ layout");
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_, DllBase) == 0x30, "DllBase at 0x30");
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_, BaseDllName) == 0x58, "BaseDllName at 0x58");
static_assert(offsetof(PEB_LDR_DATA_, InLoadOrderModuleList) == 0x10, "InLoadOrder at 0x10");

struct PEB_ {
    uint8_t  InheritedAddressSpace;
    uint8_t  ReadImageFileExecOptions;
    uint8_t  BeingDebugged;
    uint8_t  pad0;
    void*    Mutant;
    void*    ImageBaseAddress;
    PEB_LDR_DATA_* Ldr;
    // The handle table's owner id (this process's id) follows ProcessParameters.
    void*    ProcessParameters;
    void*    SubSystemData;
    void*    ProcessHeap;
    void*    FastPebLock;
    uint64_t FastPebLockRoutine;   // RTL_CRITICAL_SECTION section, x64
    uint64_t FastPebUnlockRoutine;
    uint32_t EnvironmentUpdateCount;
    uint32_t pad1;
    void**   KernelCallbackTable;
    uint32_t SystemReserved;
    uint32_t AtlThunkSListPtr32;
    void*    FreeList;
    uint32_t TlsExpansionCounter;
    uint32_t pad2;
    void*    TlsBitmap;
    uint64_t TlsBitmapBits[2];
    void*    ReadOnlySharedMemoryBase;
    void*    HotpatchInformation;
    void**   ReadOnlyStaticServerData;
    void*    AnsiCodePageData;
    void*    OemCodePageData;
    void*    UnicodeCaseTableData;
    uint32_t NumberOfProcessors;
    uint32_t NtGlobalFlag;
    uint64_t pad3;
    uint64_t CriticalSectionTimeout;
    uintptr_t HeapSegmentReserve;
    uintptr_t HeapSegmentCommit;
    uintptr_t HeapDeCommitTotalFreeThreshold;
    uintptr_t HeapDeCommitFreeBlockThreshold;
    uint32_t NumberOfHeaps;
    uint32_t MaximumNumberOfHeaps;
    void**   ProcessHeaps;
    void*    GdiSharedHandleTable;
    void*    ProcessStarterHelper;
    uint32_t GdiDCAttributeList;
    uint32_t pad4;
    uint64_t LoaderLock;           // RTL_CRITICAL_SECTION section, x64
    uint32_t OSMajorVersion;
    uint32_t OSMinorVersion;
    uint16_t OSBuildNumber;
    uint16_t OSCSDVersion;
    uint32_t OSPlatformId;
    uint32_t ImageSubsystem;
    uint32_t ImageSubsystemMajorVersion;
    uint32_t ImageSubsystemMinorVersion;
    uint32_t pad5;
    uintptr_t ActiveProcessAffinityMask;
    uint32_t GdiHandleBuffer[60];
    // 0x3C8 on x86; on x64 the buffer is wider and this lands at the value
    // used below. Only used to read the process id back.
};

struct PROCESS_BASIC_INFORMATION_ {
    NTSTATUS_ ExitStatus;
    PEB_*     PebBaseAddress;
    UPTR      AffinityMask;
    int32_t   BasePriority;
    UPTR      UniqueProcessId;
    UPTR      InheritedFromUniqueProcessId;
};

// The real x64 CONTEXT. The layout matters: NtGetContextThread and
// NtSetContextThread write/read the whole 0x430 byte block, so a shortened
// struct corrupts the thread's context.
struct CONTEXT_ {
    uint64_t P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
    uint32_t ContextFlags;
    uint32_t MxCsr;
    uint16_t SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
    uint32_t EFlags;
    uint64_t Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    uint8_t  FloatSave[512];
    uint8_t  Header[32];      // M128A Header[2]
    uint8_t  Legacy[16];
    uint8_t  Xmm[256];        // Xmm0..Xmm15
    uint64_t Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    uint64_t R8, R9, R10, R11, R12, R13, R14, R15;
    uint64_t Rip;
};

#define CONTEXT_AMD64_   0x00100000
#define CONTEXT_CONTROL_ (CONTEXT_AMD64_ | 0x1)

struct IMAGE_DOS_HEADER_ {
    uint16_t e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    uint16_t e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    uint16_t e_res[4], e_oemid, e_oeminfo, e_res2[10];
    int32_t  e_lfanew;
};

struct IMAGE_FILE_HEADER_ {
    uint16_t Machine, NumberOfSections;
    uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    uint16_t SizeOfOptionalHeader, Characteristics;
};

struct IMAGE_DATA_DIRECTORY_ { uint32_t VirtualAddress, Size; };

struct IMAGE_OPTIONAL_HEADER64_ {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOSVersion, MinorOSVersion, MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint64_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_ DataDirectory[16];
};

struct IMAGE_NT_HEADERS64_ {
    uint32_t Signature;
    IMAGE_FILE_HEADER_ FileHeader;
    IMAGE_OPTIONAL_HEADER64_ OptionalHeader;
};

struct IMAGE_SECTION_HEADER_ {
    char     Name[8];
    uint32_t VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData;
    uint32_t PointerToRelocations, PointerToLinenumbers;
    uint16_t NumberOfRelocations, NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct IMAGE_IMPORT_DESCRIPTOR_ {
    uint32_t OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk;
};

struct IMAGE_EXPORT_DIRECTORY_ {
    uint32_t Characteristics, TimeDateStamp;
    uint16_t MajorVersion, MinorVersion;
    uint32_t Name, Base, NumberOfFunctions, NumberOfNames;
    uint32_t AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
};

struct IMAGE_BASE_RELOCATION_ { uint32_t VirtualAddress, SizeOfBlock; };

constexpr uint32_t DIR_EXPORT_   = 0;
constexpr uint32_t DIR_IMPORT_   = 1;
constexpr uint32_t DIR_BASERELOC_= 5;
constexpr uint32_t DIR_TLS_      = 9;

struct IMAGE_TLS_DIRECTORY64_ {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};

constexpr uint16_t REL_ABSOLUTE_ = 0;
constexpr uint16_t REL_DIR64_    = 10;

constexpr uint32_t MEM_COMMIT_  = 0x1000;
constexpr uint32_t MEM_RESERVE_ = 0x2000;
constexpr uint32_t MEM_RELEASE_ = 0x8000;

constexpr uint32_t PAGE_NA_   = 0x01;
constexpr uint32_t PAGE_R_    = 0x02;
constexpr uint32_t PAGE_RW_   = 0x04;
constexpr uint32_t PAGE_RX_   = 0x20;

constexpr uint32_t SCN_CODE_    = 0x00000020;
constexpr uint32_t SCN_EXECUTE_ = 0x20000000;
constexpr uint32_t SCN_WRITE_   = 0x80000000;
constexpr uint32_t SCN_UNINITIALIZED_DATA_ = 0x00000080;

#define IMAGE_FIRST_SECTION_(nt) \
    reinterpret_cast<IMAGE_SECTION_HEADER_*>( \
        reinterpret_cast<uint8_t*>(nt) + 4 + 20 + (nt)->FileHeader.SizeOfOptionalHeader)
