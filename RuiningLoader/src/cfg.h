#pragma once
#include <windows.h>
#include "tcg.h"

/* Forward declare PICO (defined in stomp.h) */
typedef struct _PICO PICO;

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif

#ifndef CFG_CALL_TARGET_VALID
#define CFG_CALL_TARGET_VALID 0x00000001
#endif
#define STATUS_INVALID_PAGE_PROTECTION ((NTSTATUS)0xC0000045L)

typedef struct {
    ULONG_PTR Offset;
    ULONG_PTR Flags;
} MY_CFG_CALL_TARGET_INFO;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID  VirtualAddress;
	SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, * PMEMORY_RANGE_ENTRY;

typedef struct {
    MEMORY_RANGE_ENTRY *Ranges;
    ULONG              RangeCount;
} MY_VM_RANGE_INFO;

typedef struct {
    ULONG                   dwNumberOfOffsets;
    PULONG                  plOutput;
    MY_CFG_CALL_TARGET_INFO *ptOffsets;
    PVOID                   pMustBeZero;
    PVOID                   pMoarZero;
} MY_VM_INFORMATION;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;

/* Crystal Palace imports needed by cfg.c */
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset(void *, int, size_t);
DECLSPEC_IMPORT NTSYSAPI NTSTATUS NTAPI NTDLL$NtSetInformationVirtualMemory(HANDLE, VIRTUAL_MEMORY_INFORMATION_CLASS, ULONG_PTR, PMEMORY_RANGE_ENTRY, PVOID, SIZE_T);

/* CFG primitive functions */
BOOL      _cfg_mark_region(PVOID regionBase, SIZE_T regionSize);
BOOL      _cfg_mark_single(PVOID addr);
BOOL      _cfg_mark_single_image(PVOID ImageBase, PVOID Function);
void      EnableCFG(DLLDATA *dll, char *base);
void      EnableCFGForPICO(PICO *pico_dst, char *pico_src);