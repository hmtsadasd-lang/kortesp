#pragma once
#include <cstdint>

using NTSTATUS_ = int32_t;
using UPTR = uintptr_t;

#define NT_SUCCESS(s) ((NTSTATUS_)(s) >= 0)

struct UNICODE_STRING_ { uint16_t Length, MaxLength; wchar_t* Buffer; };

struct LDR_DATA_TABLE_ENTRY_ {
    void*    InLoadOrderLinks[2];
    void*    InMemoryOrderLinks[2];
    void*    InInitOrderLinks[2];
    void*    DllBase;
    void*    EntryPoint;
    uint32_t SizeOfImage;
    UNICODE_STRING_ FullDllName;
    UNICODE_STRING_ BaseDllName;
};

struct PEB_LDR_DATA_ {
    uint32_t Length;
    uint8_t  Initialized;
    void*    SsHandle;
    void*    InLoadOrderModuleList[2];
    void*    InMemoryOrderModuleList[2];
    void*    InInitOrderModuleList[2];
};

struct PEB_ {
    uint8_t  InheritedAddressSpace;
    uint8_t  ReadImageFileExecOptions;
    uint8_t  BeingDebugged;
    uint8_t  pad0;
    void*    Mutant;
    void*    ImageBaseAddress;
    PEB_LDR_DATA_* Ldr;
};

struct PROCESS_BASIC_INFORMATION_ {
    NTSTATUS_ ExitStatus;
    PEB_*     PebBaseAddress;
    UPTR      AffinityMask;
    int32_t   BasePriority;
    UPTR      UniqueProcessId;
    UPTR      InheritedFromUniqueProcessId;
};

struct CONTEXT_ {
    uint64_t P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
    uint32_t ContextFlags, MxCsr;
    uint16_t SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
    uint32_t EFlags;
    uint64_t Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    uint64_t Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15;
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

#define IMAGE_FIRST_SECTION_(nt) \
    reinterpret_cast<IMAGE_SECTION_HEADER_*>( \
        reinterpret_cast<uint8_t*>(nt) + 4 + 20 + (nt)->FileHeader.SizeOfOptionalHeader)