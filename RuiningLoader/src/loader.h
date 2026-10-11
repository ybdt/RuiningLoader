#pragma once
#include <windows.h>
#include "tcg.h"
#include "cfg.h"

#define NtCurrentProcess()  ((HANDLE)(LONG_PTR)-1)

DECLSPEC_IMPORT void * __cdecl MSVCRT$memset ( void *, int, size_t );
DECLSPEC_IMPORT void * __cdecl MSVCRT$memcpy ( void *, const void *, size_t );
//getchar
DECLSPEC_IMPORT int __cdecl MSVCRT$getchar(void);
// Sleep
DECLSPEC_IMPORT void WINAPI KERNEL32$Sleep(DWORD);


char _DLL_ [0] __attribute__ ( ( section ( "dll" ) ) );
char _PICO_ [ 0 ] __attribute__ ( ( section ( "pico" ) ) );
char _MASK_  [0] __attribute__ ( ( section ( "mask"  ) ) );

typedef struct {
    int  len;
    char value[];
} RESOURCE;

typedef struct {
	char * picData;
	DWORD  picSize;
} PIC_CLEANUP_CTX;

int __tag_setup_hooks ( );
int __tag_set_image_info ( );

typedef void ( * SETUP_HOOKS ) ( IMPORTFUNCS * funcs );
typedef void ( * SET_IMAGE_INFO ) ( PVOID base, DWORD size );


#define GETRESOURCE(x) ( char * ) &x

#ifdef STOMP_DLL

    #ifndef PICO_STOMP_DLL
        #error "PICO_STOMP_DLL must be defined when compiling StompDLL"
    #endif

    #ifndef DLL_STOMP_DLL
        #error "DLL_STOMP_DLL must be defined when compiling StompDLL"
    #endif

    #define MODE_STOMP 1

#else
    #define MODE_STOMP 0
#endif


DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc ( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualFree ( LPVOID, SIZE_T, DWORD );
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FlushInstructionCache(HANDLE, LPCVOID, SIZE_T);
// MessageBoxA is used in the hooks to demonstrate that the hooks are working, and to show the output of the GetVersions callback
DECLSPEC_IMPORT int WINAPI USER32$MessageBoxA ( HWND, LPCSTR, LPCSTR, UINT );
DECLSPEC_IMPORT HANDLE  KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL    KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE  KERNEL32$CreateTimerQueue(VOID);
DECLSPEC_IMPORT BOOL    KERNEL32$CreateTimerQueueTimer(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
DECLSPEC_IMPORT BOOL    KERNEL32$DeleteTimerQueue(HANDLE);
DECLSPEC_IMPORT HANDLE  KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
DECLSPEC_IMPORT BOOL    KERNEL32$SetEvent(HANDLE);
DECLSPEC_IMPORT HANDLE  KERNEL32$CreateWaitableTimerA(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
DECLSPEC_IMPORT BOOL    KERNEL32$SetWaitableTimer(HANDLE, const LARGE_INTEGER*, LONG, PTIMERAPCROUTINE, LPVOID, BOOL);
// GetLastError from kernel32.dll for error handling
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError ( void );
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryExA(LPCSTR, HANDLE, DWORD);
DECLSPEC_IMPORT NTSYSAPI BOOLEAN WINAPI KERNEL32$RtlAddFunctionTable(PRUNTIME_FUNCTION, DWORD, DWORD64);
DECLSPEC_IMPORT RUNTIME_FUNCTION * WINAPI KERNEL32$RtlLookupFunctionEntry ( DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE );
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT NTSYSAPI VOID NTAPI NTDLL$RtlCaptureContext(PCONTEXT);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtContinue(PCONTEXT, BOOLEAN);
// GetProcAddress and GetModuleHandleA are used in the hooks to resolve the addresses of the original functions, so they must be imported here as well
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);

