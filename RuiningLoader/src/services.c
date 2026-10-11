#include <windows.h>
#include "tcg.h"

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA ( LPCSTR );

/**
 * This function is used to locate functions in
 * modules that are loaded by default (K32 & NTDLL)
 */
FARPROC resolve ( DWORD mod_hash, DWORD func_hash )
{
    HANDLE module = findModuleByHash ( mod_hash );
    return findFunctionByHash ( module, func_hash );
}

/**
 * This function is used to load and/or locate functions
 * in modules that are not loaded by default.
 */
FARPROC resolve_ext ( char * mod_name, char * func_name )
{
    HANDLE module = KERNEL32$GetModuleHandleA ( mod_name );
    
    if ( module == NULL ) {
        module = LoadLibraryA ( mod_name );
    }
 
    return GetProcAddress ( module, func_name );
}
