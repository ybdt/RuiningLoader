#include "cfg.h"
#include "stomp.h"

BOOL _cfg_mark_region(PVOID regionBase, SIZE_T regionSize) {
    if (!regionBase || !regionSize) return FALSE;

    ULONG_PTR alignedBase = (ULONG_PTR)regionBase & ~0xFFF;
    SIZE_T    baseOffset  = (ULONG_PTR)regionBase - alignedBase;
    SIZE_T    alignedSize = (regionSize + baseOffset + 0xFFF) & ~0xFFF;

    DWORD granule = 16;
    DWORD count   = (DWORD)((regionSize + granule - 1) / granule);

    MY_CFG_CALL_TARGET_INFO *targets = (MY_CFG_CALL_TARGET_INFO *)KERNEL32$VirtualAlloc(
        NULL, count * sizeof(MY_CFG_CALL_TARGET_INFO),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (!targets) return FALSE;

    PULONG pOutput = (PULONG)KERNEL32$VirtualAlloc(
        NULL, count * sizeof(ULONG),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (!pOutput) {
        KERNEL32$VirtualFree(targets, 0, MEM_RELEASE);
        return FALSE;
    }

    for (DWORD i = 0; i < count; i++) {
        targets[i].Offset = baseOffset + (i * granule);
        targets[i].Flags  = CFG_CALL_TARGET_VALID;
    }

    MEMORY_RANGE_ENTRY range;
    range.VirtualAddress = (PVOID)alignedBase;
    range.NumberOfBytes  = alignedSize;

    MY_VM_INFORMATION vmInfo;
    MSVCRT$memset(&vmInfo, 0, sizeof(vmInfo));
    vmInfo.dwNumberOfOffsets = count;
    vmInfo.plOutput          = pOutput;
    vmInfo.ptOffsets         = targets;

    NTSTATUS status = NTDLL$NtSetInformationVirtualMemory(
        NtCurrentProcess(),
        VmCfgCallTargetInformation,
        1, &range, &vmInfo, sizeof(vmInfo)
    );

    BOOL success = TRUE;
    if (!SP_NT_SUCCESS(status) && status != STATUS_INVALID_PAGE_PROTECTION) {
        StealthDbg("CFG: NtSetInformationVirtualMemory failed: 0x%08X base=%p size=0x%zX\n",
            (unsigned)status, (PVOID)alignedBase, alignedSize);
        success = FALSE;
    }

    if (success) {
        DWORD applied = 0;
        for (DWORD i = 0; i < count; i++) {
            if (pOutput[i] & 0x1) applied++;
        }
        StealthDbg("CFG: marked %u/%u targets at %p+0x%zX (0x%zX bytes) status=0x%08X\n",
            applied, count, (PVOID)alignedBase, baseOffset, regionSize, (unsigned)status);
        if (applied == 0 && count > 0) {
            StealthDbg("CFG: WARNING - zero targets applied, pages may not be executable\n");
        }
    }

    KERNEL32$VirtualFree(targets, 0, MEM_RELEASE);
    KERNEL32$VirtualFree(pOutput, 0, MEM_RELEASE);
    return success;
}

BOOL _cfg_mark_single(PVOID addr) {
    if (!addr) return FALSE;

    ULONG_PTR alignedBase = (ULONG_PTR)addr & ~0xFFF;
    ULONG_PTR offset      = ((ULONG_PTR)addr - alignedBase) & ~0xF;

    MY_CFG_CALL_TARGET_INFO target;
    target.Offset = offset;
    target.Flags  = CFG_CALL_TARGET_VALID;

    ULONG output = 0;

    MEMORY_RANGE_ENTRY range;
    range.VirtualAddress = (PVOID)alignedBase;
    range.NumberOfBytes  = 0x1000;

    MY_VM_INFORMATION vmInfo;
    MSVCRT$memset(&vmInfo, 0, sizeof(vmInfo));
    vmInfo.dwNumberOfOffsets = 1;
    vmInfo.plOutput          = &output;
    vmInfo.ptOffsets         = &target;

    NTSTATUS status = NTDLL$NtSetInformationVirtualMemory(
        NtCurrentProcess(),
        VmCfgCallTargetInformation,
        1, &range, &vmInfo, sizeof(vmInfo)
    );

    if (!SP_NT_SUCCESS(status) && status != STATUS_INVALID_PAGE_PROTECTION) {
        StealthDbg("CFG: mark single %p failed: 0x%08X\n", addr, (unsigned)status);
        return FALSE;
    }
    StealthDbg("CFG: single target %p applied=%d\n", addr, (output & 0x1));
    return (output & 0x1) != 0;
}

BOOL _cfg_mark_single_image(PVOID ImageBase, PVOID Function) {
    if (!ImageBase || !Function)
        return FALSE;

    MY_CFG_CALL_TARGET_INFO target;
    MEMORY_RANGE_ENTRY      range;
    MY_VM_INFORMATION       vmInfo;
    PIMAGE_NT_HEADERS       ntHeader;
    ULONG                   output = 0;

    ntHeader = (PIMAGE_NT_HEADERS)(
        (PUCHAR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew
    );

    range.VirtualAddress = ImageBase;
    range.NumberOfBytes  =
        (ntHeader->OptionalHeader.SizeOfImage + 0x1000 - 1) & ~(0x1000 - 1);

    target.Offset = (ULONG_PTR)Function - (ULONG_PTR)ImageBase;
    target.Flags  = CFG_CALL_TARGET_VALID;

    MSVCRT$memset(&vmInfo, 0, sizeof(vmInfo));
    vmInfo.dwNumberOfOffsets = 1;
    vmInfo.plOutput          = &output;
    vmInfo.ptOffsets         = &target;

    NTSTATUS status = NTDLL$NtSetInformationVirtualMemory(
        NtCurrentProcess(),
        VmCfgCallTargetInformation,
        1,
        &range,
        &vmInfo,
        sizeof(vmInfo)
    );

    if (!SP_NT_SUCCESS(status)) {
        StealthDbg("CFG: image target %p failed: 0x%08X\n",
                   Function, (unsigned)status);
        return FALSE;
    }

    StealthDbg("CFG: image target %p applied=%d\n",
               Function, (output & 0x1));

    return (output & 0x1) != 0;
}

void EnableCFG(DLLDATA *dll, char *base) {
    IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)PTR_OFFSET(
        dll->OptionalHeader,
        dll->NtHeaders->FileHeader.SizeOfOptionalHeader
    );

    for (WORD i = 0; i < dll->NtHeaders->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        PVOID  secBase = base + sec->VirtualAddress;
        SIZE_T secSize = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        _cfg_mark_region(secBase, secSize);
    }
}

void EnableCFGForPICO(PICO *pico_dst, char *pico_src) {
    SIZE_T codeSize = PicoCodeSize(pico_src);
    _cfg_mark_region(pico_dst->code, codeSize);
}