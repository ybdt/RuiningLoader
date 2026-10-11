#pragma once
#include <windows.h>
#include "tcg.h"
#include "cfg.h"

/* ── NT types (guard against phnt/ntdef collisions) ─────────────────── */

#ifndef _PHNT_NTDEF_H
#ifndef _NTDEF_

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef LONG KPRIORITY, *PKPRIORITY;

#endif
#endif

#ifndef _NTEXAPI_H

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _KWAIT_REASON {
    Executive, FreePage, PageIn, PoolAllocation, DelayExecution,
    Suspended, UserRequest, WrExecutive, WrFreePage, WrPageIn,
    WrPoolAllocation, WrDelayExecution, WrSuspended, WrUserRequest,
    WrEventPair, WrQueue, WrLpcReceive, WrLpcReply, WrVirtualMemory,
    WrPageOut, WrRendezvous, Spare2, Spare3, Spare4, Spare5,
    WrCalloutStack, WrKernel, WrResource, WrPushLock, WrMutex,
    WrQuantumEnd, WrDispatchInt, WrPreempted, WrYieldExecution,
    WrFastMutex, WrGuardedMutex, WrRundown, MaximumWaitReason
} KWAIT_REASON, *PKWAIT_REASON;

typedef enum _KTHREAD_STATE {
    Initialized, Ready, Running, Standby, Terminated, Waiting,
    Transition, DeferredReady, GateWaitObsolete,
    WaitingForProcessInSwap, MaximumThreadState
} KTHREAD_STATE, *PKTHREAD_STATE;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    CLIENT_ID     ClientId;
    KPRIORITY     Priority;
    KPRIORITY     BasePriority;
    ULONG         ContextSwitches;
    KTHREAD_STATE ThreadState;
    KWAIT_REASON  WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

_Struct_size_bytes_(NextEntryOffset)
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG              NextEntryOffset;
    ULONG              NumberOfThreads;
    ULONGLONG          WorkingSetPrivateSize;
    ULONG              HardFaultCount;
    ULONG              NumberOfThreadsHighWatermark;
    ULONGLONG          CycleTime;
    LARGE_INTEGER      CreateTime;
    LARGE_INTEGER      UserTime;
    LARGE_INTEGER      KernelTime;
    UNICODE_STRING     ImageName;
    KPRIORITY          BasePriority;
    HANDLE             UniqueProcessId;
    HANDLE             InheritedFromUniqueProcessId;
    ULONG              HandleCount;
    ULONG              SessionId;
    ULONG_PTR          UniqueProcessKey;
    SIZE_T             PeakVirtualSize;
    SIZE_T             VirtualSize;
    ULONG              PageFaultCount;
    SIZE_T             PeakWorkingSetSize;
    SIZE_T             WorkingSetSize;
    SIZE_T             QuotaPeakPagedPoolUsage;
    SIZE_T             QuotaPagedPoolUsage;
    SIZE_T             QuotaPeakNonPagedPoolUsage;
    SIZE_T             QuotaNonPagedPoolUsage;
    SIZE_T             PagefileUsage;
    SIZE_T             PeakPagefileUsage;
    SIZE_T             PrivatePageCount;
    LARGE_INTEGER      ReadOperationCount;
    LARGE_INTEGER      WriteOperationCount;
    LARGE_INTEGER      OtherOperationCount;
    LARGE_INTEGER      ReadTransferCount;
    LARGE_INTEGER      WriteTransferCount;
    LARGE_INTEGER      OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

#endif

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeparation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformationObsolete,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    SystemThreadPriorityClientIdInformation,
    SystemProcessorIdleCycleTimeInformation,
    SystemVerifierCancellationInformation,
    SystemProcessorPowerInformationEx,
    SystemRefTraceInformation,
    SystemSpecialPoolInformation,
    SystemProcessIdInformation,
    SystemErrorPortInformation,
    SystemBootEnvironmentInformation,
    SystemHypervisorInformation,
    SystemVerifierInformationEx,
    SystemTimeZoneInformation,
    SystemImageFileExecutionOptionsInformation,
    SystemCoverageInformation,
    SystemPrefetchPatchInformation,
    SystemVerifierFaultsInformation,
    SystemSystemPartitionInformation,
    SystemSystemDiskInformation,
    SystemProcessorPerformanceDistribution,
    SystemNumaProximityNodeInformation,
    SystemDynamicTimeZoneInformation,
    SystemCodeIntegrityInformation,
    SystemProcessorMicrocodeUpdateInformation,
    SystemProcessorBrandString,
    SystemVirtualAddressInformation,
    SystemLogicalProcessorAndGroupInformation,
    SystemProcessorCycleTimeInformation,
    SystemStoreInformation,
    SystemRegistryAppendString,
    SystemAitSamplingValue,
    SystemVhdBootInformation,
    SystemCpuQuotaInformation,
    SystemNativeBasicInformation,
    SystemErrorPortTimeouts,
    SystemLowPriorityIoInformation,
    SystemTpmBootEntropyInformation,
    SystemVerifierCountersInformation,
    SystemPagedPoolInformationEx,
    SystemSystemPtesInformationEx,
    SystemNodeDistanceInformation,
    SystemAcpiAuditInformation,
    SystemBasicPerformanceInformation,
    SystemQueryPerformanceCounterInformation,
    SystemSessionBigPoolInformation,
    SystemBootGraphicsInformation,
    SystemScrubPhysicalMemoryInformation,
    SystemBadPageInformation,
    SystemProcessorProfileControlArea,
    SystemCombinePhysicalMemoryInformation,
    SystemEntropyInterruptTimingInformation,
    SystemConsoleInformation,
    SystemPlatformBinaryInformation,
    SystemPolicyInformation,
    SystemHypervisorProcessorCountInformation,
    SystemDeviceDataInformation,
    SystemDeviceDataEnumerationInformation,
    SystemMemoryTopologyInformation,
    SystemMemoryChannelInformation,
    SystemBootLogoInformation,
    SystemProcessorPerformanceInformationEx,
    SystemCriticalProcessErrorLogInformation,
    SystemSecureBootPolicyInformation,
    SystemPageFileInformationEx,
    SystemSecureBootInformation,
    SystemEntropyInterruptTimingRawInformation,
    SystemPortableWorkspaceEfiLauncherInformation,
    SystemFullProcessInformation,
    SystemKernelDebuggerInformationEx,
    SystemBootMetadataInformation,
    SystemSoftRebootInformation,
    SystemElamCertificateInformation,
    SystemOfflineDumpConfigInformation,
    SystemProcessorFeaturesInformation,
    SystemRegistryReconciliationInformation,
    SystemEdidInformation,
    SystemManufacturingInformation,
    SystemEnergyEstimationConfigInformation,
    SystemHypervisorDetailInformation,
    SystemProcessorCycleStatsInformation,
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation,
    SystemKernelDebuggerFlags,
    SystemCodeIntegrityPolicyInformation,
    SystemIsolatedUserModeInformation,
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation,
    SystemAllowedCpuSetsInformation,
    SystemVsmProtectionInformation,
    SystemInterruptCpuSetsInformation,
    SystemSecureBootPolicyFullInformation,
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation,
    SystemRootSiloInformation,
    SystemCpuSetInformation,
    SystemCpuSetTagInformation,
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation,
    SystemCodeIntegrityPlatformManifestInformation,
    SystemInterruptSteeringInformation,
    SystemSupportedProcessorArchitectures,
    SystemMemoryUsageInformation,
    SystemCodeIntegrityCertificateInformation,
    SystemPhysicalMemoryInformation,
    SystemControlFlowTransition,
    SystemKernelDebuggingAllowed,
    SystemActivityModerationExeState,
    SystemActivityModerationUserSettings,
    SystemCodeIntegrityPoliciesFullInformation,
    SystemCodeIntegrityUnlockInformation,
    SystemIntegrityQuotaInformation,
    SystemFlushInformation,
    SystemProcessorIdleMaskInformation,
    SystemSecureDumpEncryptionInformation,
    SystemWriteConstraintInformation,
    SystemKernelVaShadowInformation,
    SystemHypervisorSharedPageInformation,
    SystemFirmwareBootPerformanceInformation,
    SystemCodeIntegrityVerificationInformation,
    SystemFirmwarePartitionInformation,
    SystemSpeculationControlInformation,
    SystemDmaGuardPolicyInformation,
    SystemEnclaveLaunchControlInformation,
    SystemWorkloadAllowedCpuSetsInformation,
    SystemCodeIntegrityUnlockModeInformation,
    SystemLeapSecondInformation,
    SystemFlags2Information,
    SystemSecurityModelInformation,
    SystemCodeIntegritySyntheticCacheInformation,
    SystemFeatureConfigurationInformation,
    SystemFeatureConfigurationSectionInformation,
    SystemFeatureUsageSubscriptionInformation,
    SystemSecureSpeculationControlInformation,
    SystemSpacesBootInformation,
    SystemFwRamdiskInformation,
    SystemWheaIpmiHardwareInformation,
    SystemDifSetRuleClassInformation,
    SystemDifClearRuleClassInformation,
    SystemDifApplyPluginVerificationOnDriver,
    SystemDifRemovePluginVerificationOnDriver,
    SystemShadowStackInformation,
    SystemBuildVersionInformation,
    SystemPoolLimitInformation,
    SystemCodeIntegrityAddDynamicStore,
    SystemCodeIntegrityClearDynamicStores,
    SystemDifPoolTrackingInformation,
    SystemPoolZeroingInformation,
    SystemDpcWatchdogInformation,
    SystemDpcWatchdogInformation2,
    SystemSupportedProcessorArchitectures2,
    SystemSingleProcessorRelationshipInformation,
    SystemXfgCheckFailureInformation,
    SystemIommuStateInformation,
    SystemHypervisorMinrootInformation,
    SystemHypervisorBootPagesInformation,
    SystemPointerAuthInformation,
    SystemSecureKernelDebuggerInformation,
    SystemOriginalImageFeatureInformation,
    SystemMemoryNumaInformation,
    SystemMemoryNumaPerformanceInformation,
    SystemCodeIntegritySignedPoliciesFullInformation,
    SystemSecureCoreInformation,
    SystemTrustedAppsRuntimeInformation,
    SystemBadPageInformationEx,
    SystemResourceDeadlockTimeout,
    SystemBreakOnContextUnwindFailureInformation,
    SystemOslRamdiskInformation,
    SystemCodeIntegrityPolicyManagementInformation,
    SystemMemoryNumaCacheInformation,
    SystemProcessorFeaturesBitMapInformation,
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

/* ── Hook types and argument structs ────────────────────────────────── */

typedef DWORD (WINAPI *fnWaitForSingleObjectEx)(HANDLE, DWORD, BOOL);
typedef DWORD (WINAPI *fnWaitForMultipleObjects)(DWORD, const HANDLE *, BOOL, DWORD);
typedef BOOL  (WINAPI *fnConnectNamedPipe)(HANDLE, LPOVERLAPPED);

typedef enum _HOOK_FUNCTION {
    WAIT_FOR_SINGLE_OBJECT_EX,
    WAIT_FOR_MULTIPLE_OBJECTS,
    CONNECT_NAMED_PIPE,
} HOOK_TYPE;

typedef struct _CONNECT_NAMED_PIPE_ARGS {
    HANDLE           hPipe;
    LPOVERLAPPED     lpOverlapped;
    fnConnectNamedPipe OriginalFunc;
} CONNECT_NAMED_PIPE_ARGS;

typedef struct _WAIT_FOR_SINGLE_OBJECT_EX_ARGS {
    HANDLE                  hObject;
    DWORD                   dwMilliseconds;
    BOOL                    bAlertable;
    fnWaitForSingleObjectEx OriginalFunc;
} WAIT_FOR_SINGLE_OBJECT_EX_ARGS;

typedef struct _WAIT_FOR_MULTIPLE_OBJECTS_ARGS {
    DWORD                    nCount;
    const HANDLE            *lpHandles;
    BOOL                     bWaitAll;
    DWORD                    dwMilliseconds;
    fnWaitForMultipleObjects OriginalFunc;
    DWORD                    returnValue;
} WAIT_FOR_MULTIPLE_OBJECTS_ARGS;

typedef struct _HOOK_ARGS {
    union {
        WAIT_FOR_SINGLE_OBJECT_EX_ARGS WaitForSingleObjectExArgs;
        WAIT_FOR_MULTIPLE_OBJECTS_ARGS WaitForMultipleObjectsArgs;
        CONNECT_NAMED_PIPE_ARGS        ConnectNamedPipeArgs;
    };
} HOOK_ARGS;

/* ── NT status / macros ─────────────────────────────────────────────── */

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SP_NT_SUCCESS(s)        (((NTSTATUS)(s)) >= 0)

/* ── Crystal Palace imports (MODULE$Function convention) ─────────────── */

DECLSPEC_IMPORT DWORD   KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT DWORD   KERNEL32$WaitForSingleObjectEx(HANDLE, DWORD, BOOL);
DECLSPEC_IMPORT HANDLE  KERNEL32$CreateEventW(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
DECLSPEC_IMPORT HANDLE  KERNEL32$CreateTimerQueue(VOID);
DECLSPEC_IMPORT BOOL    KERNEL32$CreateTimerQueueTimer(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
DECLSPEC_IMPORT BOOL    KERNEL32$DeleteTimerQueue(HANDLE);
DECLSPEC_IMPORT LPVOID  KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL    KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT BOOL    KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL    KERNEL32$SetEvent(HANDLE);
DECLSPEC_IMPORT HMODULE KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT HMODULE KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL    KERNEL32$FlushInstructionCache(HANDLE, LPCVOID, SIZE_T);
DECLSPEC_IMPORT DWORD   KERNEL32$GetCurrentProcessId(VOID);
DECLSPEC_IMPORT DWORD   KERNEL32$GetCurrentThreadId(VOID);
DECLSPEC_IMPORT DWORD   KERNEL32$DuplicateHandle(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
DECLSPEC_IMPORT HANDLE  KERNEL32$OpenThread(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    KERNEL32$GetThreadContext(HANDLE, LPCONTEXT);
DECLSPEC_IMPORT BOOL    KERNEL32$SetThreadContext(HANDLE, const CONTEXT *);
DECLSPEC_IMPORT BOOL    KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT VOID    KERNEL32$SetLastError(DWORD);
DECLSPEC_IMPORT DWORD   KERNEL32$GetTickCount(VOID);
DECLSPEC_IMPORT HANDLE  KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT DWORD   KERNEL32$ResumeThread(HANDLE);
DECLSPEC_IMPORT BOOL    KERNEL32$TerminateThread(HANDLE, DWORD);
DECLSPEC_IMPORT DWORD   KERNEL32$GetLastError(void);

DECLSPEC_IMPORT void * __cdecl MSVCRT$memcpy(void *, const void *, size_t);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset(void *, int, size_t);
DECLSPEC_IMPORT int    __cdecl MSVCRT$_strnicmp(const char *, const char *, size_t);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueueApcThread(HANDLE, PVOID, PVOID, PVOID, PVOID);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

DECLSPEC_IMPORT void * __cdecl KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT HANDLE __cdecl KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT BOOL __cdecl KERNEL32$HeapFree(HANDLE, DWORD, void *);

// NtSetContextThread
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtSetContextThread(HANDLE, PCONTEXT);
typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG      Priority;
    LONG      BasePriority;
} THREAD_BASIC_INFORMATION;

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryInformationThread(HANDLE, ULONG, PVOID, ULONG, PULONG);

void cfg_refresh_agent(void);

/* ── USTRING for SystemFunction032 (RC4 encrypt/decrypt) ────────────── */

typedef struct {
    DWORD  Length;
    DWORD  MaximumLength;
    PVOID  Buffer;
} USTRING;

typedef NTSTATUS (WINAPI *fnSystemFunction032)(USTRING *, USTRING *);
typedef VOID     (WINAPI *fnRtlCaptureContext)(PCONTEXT);
typedef NTSTATUS (NTAPI  *fnNtContinue)(PCONTEXT, BOOLEAN);

/* ── Globals ────────────────────────────────────────────────────────── */

PVOID  g_ImageBase                                  = NULL;
DWORD  g_ImageSize                                  = 0;

fnWaitForSingleObjectEx  g_pWaitForSingleObjectEx   = NULL;
fnWaitForMultipleObjects g_pWaitForMultipleObjects  = NULL;
fnConnectNamedPipe       g_pConnectNamedPipe        = NULL;

/* Ekko Functions */
typedef DWORD (WINAPI* fnWaitForSingleObject)(HANDLE, DWORD);
fnWaitForSingleObject     g_pWaitForSingleObject    = NULL;

typedef BOOL (WINAPI* fnGetThreadContext)(HANDLE, LPCONTEXT);
fnGetThreadContext        g_pGetThreadContext       = NULL;

typedef BOOL (WINAPI* fnSetThreadContext)(HANDLE, const CONTEXT *);
fnSetThreadContext        g_pSetThreadContext       = NULL;

typedef BOOL (WINAPI* fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
fnVirtualProtect          g_pVirtualProtect         = NULL;

typedef BOOL (WINAPI* fnSetEvent)(HANDLE);
fnSetEvent                g_pSetEvent               = NULL;

fnNtContinue             g_pNtContinue              = NULL;
fnSystemFunction032      g_pSysFunc032              = NULL;

typedef void (NTAPI* fnRtlMoveMemory)(PVOID, const VOID *, SIZE_T);
fnRtlMoveMemory           g_pRtlMoveMemory          = NULL;

/* kraken mask functions */
fnRtlCaptureContext      g_pRtlCaptureContext       = NULL;
PVOID g_pNtTestAlert                                = NULL;
PVOID g_pNtWaitForSingleObject                      = NULL;
PVOID g_pNtSetEvent                                 = NULL;
PVOID g_pNtSignalAndWaitForSingleObject             = NULL;
PVOID g_pNtAlertResumeThread                        = NULL;
PVOID g_pRtlExitUserThread                          = NULL;
PVOID g_pNtSuspendThread                            = NULL;
PVOID g_pNtResumeThread                             = NULL;

ULONG_PTR g_NtContinueGadget;
ULONG_PTR g_JmpGadget;        /* FF 23 = jmp [rbx] (memory indirect, timer Ekko) */
ULONG_PTR g_JmpRdiGadget;     /* FF E7 = jmp rdi  (register direct, APC Ekko) */

