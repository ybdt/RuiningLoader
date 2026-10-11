#include <windows.h>
#include "tcg.h"

/* globals defined in hooks.c - shared via merge in the same PICO */
extern PVOID  g_ImageBase;
extern DWORD  g_ImageSize;
extern VOID   ResolveHookFunctions(VOID);
extern VOID   EnableCFGForGadgets(VOID);  

/*
 * Hooked GetProcAddress - Crystal Palace's attach rewrites the GetProcAddress
 * reference in go() so ProcessImports uses this function to resolve the DLL's imports.
 *
 * For each import, we check if __resolve_hook() has a registered hook for it.
 * If yes, return the hook pointer. Otherwise, call the real GetProcAddress
 * (preserved by attach within this function's context).
 */
FARPROC WINAPI _GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    /* skip ordinal imports (high bits are zero for ordinals) */
    StealthDbg("_GetProcAddress called for module=%p proc=%p\n", hModule, lpProcName);
    if ((ULONG_PTR)lpProcName > 0xFFFF) {
        FARPROC hook = __resolve_hook(ror13hash(lpProcName));
        if (hook) {
            StealthDbg("Hooked import: %s\n", lpProcName);
            return hook;
        }
    }
    /* no hook - call the real GetProcAddress (preserved by attach) */
    return GetProcAddress(hModule, lpProcName);
}


/**
 * This will overwrite the function pointer for GetProcAddress.
 */
void setup_hooks ( IMPORTFUNCS * funcs )
{
    funcs->GetProcAddress = ( __typeof__ ( GetProcAddress ) * ) _GetProcAddress;
}

/**
 * Called by the loader after the DLL is mapped into memory.
 * Sets the image base & size so EkkoObf knows what region to encrypt/decrypt.
 */
void set_image_info ( PVOID base, DWORD size )
{
    g_ImageBase = base;
    g_ImageSize = size;
    StealthDbg("set_image_info: base=%p size=0x%lx\n", base, size);
    ResolveHookFunctions();
    EnableCFGForGadgets();
}
